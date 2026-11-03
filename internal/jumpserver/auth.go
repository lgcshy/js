package jumpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"jsbridge/internal/config"
	"jsbridge/internal/errs"
)

type PasswordInitOptions struct {
	Origin    string
	CAFile    string
	ProxyURL  string
	Username  string
	Password  string
	Transport http.RoundTripper
}

type AccessKeyPair struct {
	ID       string
	Secret   string
	Username string
}

type AccessKeyRecord struct {
	ID        string `json:"id"`
	Secret    string `json:"secret,omitempty"`
	IsActive  bool   `json:"is_active"`
}

// LoginAndCreateAccessKey 使用本人账号密码登录一次并调用 API 创建本机专用的个人 Access Key，不持久化主密码。
func LoginAndCreateAccessKey(ctx context.Context, opts PasswordInitOptions) (*AccessKeyPair, error) {
	origin, _, err := config.ValidateCoreOrigin(opts.Origin)
	if err != nil {
		return nil, err
	}
	username := strings.TrimSpace(opts.Username)
	if username == "" || opts.Password == "" {
		return nil, errs.New("EMPTY_CREDENTIALS", "JumpServer 账号与密码不能为空。")
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, errs.New("LOCAL_ERROR", "初始化会话容器失败。")
	}
	hc, err := NewHTTPClient(opts.CAFile, opts.ProxyURL, jar, opts.Transport)
	if err != nil {
		return nil, err
	}
	defer hc.CloseIdleConnections()

	// 1. POST /api/v1/authentication/tokens/ 获取短期 Bearer Token
	loginPayload := map[string]string{
		"username": username,
		"password": opts.Password,
	}
	status, rawResp, err := doBearerJSON(ctx, hc, origin, "", http.MethodPost, "/api/v1/authentication/tokens/", loginPayload)
	if err != nil {
		return nil, err
	}

	var tokenResp struct {
		Token       string   `json:"token"`
		Error       string   `json:"error"`
		Msg         string   `json:"msg"`
		Code        string   `json:"code"`
		MFAChoices  []string `json:"mfa_choices"`
		Data        struct {
			Choices []string `json:"choices"`
		} `json:"data"`
		User struct {
			Username string `json:"username"`
		} `json:"user"`
	}
	if len(bytes.TrimSpace(rawResp)) > 0 {
		_ = json.Unmarshal(rawResp, &tokenResp)
	}

	lowerErr := strings.ToLower(tokenResp.Error + " " + tokenResp.Code + " " + tokenResp.Msg)
	if len(tokenResp.MFAChoices) > 0 || len(tokenResp.Data.Choices) > 0 || strings.Contains(lowerErr, "mfa") {
		return nil, errs.Action(
			"MFA_UNSUPPORTED",
			"当前版本不支持 MFA 账号自动初始化。",
			"请在网页“个人信息 → API Key”手动创建 Access Key 后使用 js init --access-key",
		)
	}
	if strings.Contains(lowerErr, "confirm") || strings.Contains(lowerErr, "ticket") || strings.Contains(lowerErr, "review") {
		return nil, errs.Action(
			"APPROVAL_REQUIRED",
			"当前账号登录需要审批，暂不支持自动等待工单。",
			"请在网页手动创建 Access Key 后使用 js init --access-key",
		)
	}
	if status >= 300 || strings.TrimSpace(tokenResp.Token) == "" {
		return nil, errs.New("LOGIN_FAILED", "JumpServer 账号密码认证失败；未保存任何信息，也不会自动重试。")
	}

	bearer := strings.TrimSpace(tokenResp.Token)
	resolvedUser := username
	if tokenResp.User.Username != "" {
		resolvedUser = tokenResp.User.Username
	}

	// 2. POST /api/v1/authentication/access-keys/ 创建个人 Access Key
	akStatus, akRaw, err := doBearerJSON(ctx, hc, origin, bearer, http.MethodPost, "/api/v1/authentication/access-keys/", map[string]any{})
	if err != nil {
		return nil, err
	}

	// JumpServer v4.10.19 在启用 SECURITY_VIEW_AUTH_NEED_MFA 时会要求同一会话先完成 ConfirmType.PASSWORD 二次确认
	if akStatus == http.StatusForbidden || akStatus == http.StatusBadRequest || akStatus == http.StatusUnauthorized {
		var confirmProbe struct {
			Code   string `json:"code"`
			Detail string `json:"detail"`
		}
		_ = json.Unmarshal(akRaw, &confirmProbe)
		probeText := strings.ToLower(confirmProbe.Code + " " + confirmProbe.Detail)
		if strings.Contains(probeText, "confirm") || strings.Contains(probeText, "password") || strings.Contains(probeText, "relogin") {
			confirmPayload := map[string]string{
				"confirm_type": "password",
				"secret_key":   opts.Password,
			}
			cStatus, _, cErr := doBearerJSON(ctx, hc, origin, bearer, http.MethodPost, "/api/v1/authentication/confirm/", confirmPayload)
			if cErr == nil && cStatus < 300 {
				akStatus, akRaw, err = doBearerJSON(ctx, hc, origin, bearer, http.MethodPost, "/api/v1/authentication/access-keys/", map[string]any{})
				if err != nil {
					return nil, err
				}
			}
		}
	}

	if akStatus >= 300 {
		return nil, errs.Action(
			"AK_CREATE_UNAVAILABLE",
			"登录成功，但服务端不允许通过 API 创建个人 Access Key（可能受平台策略或最多 10 把密钥限制）。",
			"请在 JumpServer 网页“个人信息 → API Key”手动创建后运行 js init --access-key",
		)
	}

	var created AccessKeyRecord
	if err := json.Unmarshal(akRaw, &created); err != nil || !IsValidUUID(created.ID) || strings.TrimSpace(created.Secret) == "" {
		return nil, errs.Action(
			"AK_CREATE_UNAVAILABLE",
			"服务端未返回有效的 Access Key ID 和 Secret。",
			"请在 JumpServer 网页“个人信息 → API Key”手动创建后运行 js init --access-key",
		)
	}

	return &AccessKeyPair{
		ID:       strings.TrimSpace(created.ID),
		Secret:   strings.TrimSpace(created.Secret),
		Username: resolvedUser,
	}, nil
}

// ListAccessKeys 查询本人已有的 Access Key 元数据（不含 secret），用于 P0 权限核验和诊断。
func (c *Client) ListAccessKeys(ctx context.Context) ([]AccessKeyRecord, error) {
	var raw json.RawMessage
	if _, err := c.Request(ctx, http.MethodGet, "/api/v1/authentication/access-keys/", nil, &raw); err != nil {
		return nil, err
	}
	var list []AccessKeyRecord
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	var paged struct {
		Results []AccessKeyRecord `json:"results"`
	}
	if err := json.Unmarshal(raw, &paged); err != nil {
		return nil, errs.New("API_RESPONSE", "解析 Access Key 列表失败。")
	}
	return paged.Results, nil
}

// RevokeAccessKey 在服务端吊销本机创建的个人 Access Key（用于 js logout）。
func (c *Client) RevokeAccessKey(ctx context.Context, keyID string) error {
	keyID = strings.TrimSpace(keyID)
	if !IsValidUUID(keyID) {
		return errs.New("ACCESS_KEY_ID", "无效的 Access Key UUID。")
	}
	_, err := c.Request(ctx, http.MethodDelete, "/api/v1/authentication/access-keys/"+keyID+"/", nil, nil)
	return err
}

func doBearerJSON(
	ctx context.Context,
	hc *http.Client,
	origin, bearer, method, path string,
	payload any,
) (int, []byte, error) {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, errs.New("API_REQUEST", "序列化认证请求失败。")
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, origin+path, body)
	if err != nil {
		return 0, nil, errs.New("API_REQUEST", "构造认证请求失败。")
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if hc.Jar != nil {
		if u, parseErr := url.Parse(origin); parseErr == nil {
			for _, ck := range hc.Jar.Cookies(u) {
				if strings.Contains(strings.ToLower(ck.Name), "csrftoken") && ck.Value != "" {
					req.Header.Set("X-CSRFToken", ck.Value)
					req.Header.Set("Referer", origin+"/")
					break
				}
			}
		}
	}

	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, errs.New("API_NETWORK", "连接 JumpServer HTTPS 入口失败，请检查网络或证书配置。")
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponseBytes+1))
	if err != nil {
		return resp.StatusCode, nil, errs.New("API_NETWORK", "读取 JumpServer 认证响应失败。")
	}
	if len(raw) > maxAPIResponseBytes {
		return resp.StatusCode, nil, errs.New("API_RESPONSE_LIMIT", "JumpServer 响应超过上限。")
	}
	return resp.StatusCode, raw, nil
}
