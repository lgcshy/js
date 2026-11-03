package jumpserver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"jsbridge/internal/config"
	"jsbridge/internal/errs"
)

const maxAPIResponseBytes = 4 * 1024 * 1024

var uuidRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func IsValidUUID(s string) bool {
	return uuidRegex.MatchString(strings.TrimSpace(s))
}

type ClientOptions struct {
	Origin       string
	Username     string
	KeyID        string
	Secret       string
	OrgID        string
	CAFile       string
	ProxyURL     string
	AllowMFA     bool
	Transport    http.RoundTripper
}

type Client struct {
	origin          string
	username        string
	keyID           string
	secret          string
	orgID           string
	allowMFA        bool
	httpClient      *http.Client

	mu              sync.Mutex
	failedAuth      bool
	profileVerified bool
}

func NewHTTPClient(caFile, proxyURL string, jar http.CookieJar, customTransport http.RoundTripper) (*http.Client, error) {
	rt := customTransport
	if rt == nil {
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		if strings.TrimSpace(caFile) != "" {
			pemBytes, err := os.ReadFile(config.ExpandHome(caFile))
			if err != nil {
				return nil, errs.New("TLS_CA", "无法读取配置的受信任 CA 证书文件。")
			}
			pool, err := x509.SystemCertPool()
			if err != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM(pemBytes) {
				return nil, errs.New("TLS_CA", "CA 证书文件中未找到有效 PEM 证书。")
			}
			tlsCfg.RootCAs = pool
		}

		var proxyFunc func(*http.Request) (*url.URL, error) // 默认 nil：绝不隐式继承环境代理
		if strings.TrimSpace(proxyURL) != "" {
			pu, err := url.Parse(strings.TrimSpace(proxyURL))
			if err != nil || (pu.Scheme != "http" && pu.Scheme != "https" && pu.Scheme != "socks5") || pu.Host == "" {
				return nil, errs.New("CONFIG_PROXY", "proxy_url 代理配置格式无效。")
			}
			proxyFunc = http.ProxyURL(pu)
		}

		rt = &http.Transport{
			Proxy: proxyFunc,
			DialContext: (&net.Dialer{
				Timeout:   8 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSClientConfig:       tlsCfg,
			TLSHandshakeTimeout:   8 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			MaxIdleConns:          8,
			IdleConnTimeout:       30 * time.Second,
		}
	}

	return &http.Client{
		Transport: rt,
		Jar:       jar,
		Timeout:   15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			// 禁止跟随重定向，防止签名头或令牌泄露到第三方地址
			return http.ErrUseLastResponse
		},
	}, nil
}

func NewClient(opts ClientOptions) (*Client, error) {
	origin, _, err := config.ValidateCoreOrigin(opts.Origin)
	if err != nil {
		return nil, err
	}
	keyID := strings.TrimSpace(opts.KeyID)
	secret := strings.TrimSpace(opts.Secret)
	if !IsValidUUID(keyID) || secret == "" {
		return nil, errs.New("ACCESS_KEY_FORMAT", "Access Key 需包含合法的 UUID ID 与非空 Secret。")
	}
	hc, err := NewHTTPClient(opts.CAFile, opts.ProxyURL, nil, opts.Transport)
	if err != nil {
		return nil, err
	}
	return &Client{
		origin:     origin,
		username:   strings.TrimSpace(opts.Username),
		keyID:      keyID,
		secret:     secret,
		orgID:      strings.TrimSpace(opts.OrgID),
		allowMFA:   opts.AllowMFA,
		httpClient: hc,
	}, nil
}

func (c *Client) Close() {
	c.mu.Lock()
	c.secret = ""
	c.mu.Unlock()
	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}
}

func (c *Client) Request(ctx context.Context, method, path string, payload any, out any) (int, error) {
	c.mu.Lock()
	if c.failedAuth {
		c.mu.Unlock()
		return 0, errs.New("AUTH_FAILED", "本次客户端认证已失败，不再自动重试。")
	}
	secret := c.secret
	keyID := c.keyID
	c.mu.Unlock()

	if !strings.HasPrefix(path, "/api/v1/") || strings.ContainsAny(path, "\r\n") {
		return 0, errs.New("API_PATH", "API 路径不允许。")
	}

	var bodyReader io.Reader
	if payload != nil {
		rawBody, err := json.Marshal(payload)
		if err != nil {
			return 0, errs.New("API_REQUEST", "序列化 API 请求失败。")
		}
		bodyReader = bytes.NewReader(rawBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.origin+path, bodyReader)
	if err != nil {
		return 0, errs.New("API_REQUEST", "构造 API 请求失败。")
	}

	dateStr := time.Now().UTC().Format(http.TimeFormat)
	signingText := fmt.Sprintf("(request-target): %s %s\ndate: %s", strings.ToLower(method), path, dateStr)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signingText))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	req.Header.Set("Date", dateStr)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", fmt.Sprintf(
		`Signature keyId="%s",algorithm="hmac-sha256",headers="(request-target) date",signature="%s"`,
		keyID, sig,
	))
	if c.orgID != "" {
		req.Header.Set("X-JMS-ORG", c.orgID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, errs.New("API_NETWORK", "JumpServer HTTPS 请求失败（可能是网络或证书校验问题）；不自动重放。")
	}
	defer resp.Body.Close()

	rawResp, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponseBytes+1))
	if err != nil {
		return resp.StatusCode, errs.New("API_NETWORK", "读取 JumpServer API 响应失败；不自动重放。")
	}
	if len(rawResp) > maxAPIResponseBytes {
		return resp.StatusCode, errs.New("API_RESPONSE_LIMIT", "JumpServer API 响应超过 4 MiB 安全上限。")
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		c.mu.Lock()
		c.failedAuth = true
		c.mu.Unlock()
	}

	if resp.StatusCode >= 300 {
		var errProbe struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(rawResp, &errProbe)
		switch errProbe.Code {
		case "acl_review", "acl_face_verify", "acl_face_online", "acl_face_online_not_supported":
			return resp.StatusCode, errs.New("APPROVAL_REQUIRED", "该资产要求登录审批或人脸验证，当前版本暂不支持自动等待审批。")
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return resp.StatusCode, errs.Action("API_HTTP_401", "JumpServer API 凭据无效或已被吊销；未自动重试。", "请运行 js init 重新初始化")
		}
		return resp.StatusCode, errs.New(
			fmt.Sprintf("API_HTTP_%d", resp.StatusCode),
			"JumpServer API 拒绝请求；原始响应已隐藏，不自动重试。",
		)
	}

	if len(bytes.TrimSpace(rawResp)) > 0 {
		if out != nil {
			if err := json.Unmarshal(rawResp, out); err != nil {
				return resp.StatusCode, errs.New("API_RESPONSE", "JumpServer API 未返回预期的 JSON 结构。")
			}
		} else {
			var check any
			if err := json.Unmarshal(rawResp, &check); err != nil {
				return resp.StatusCode, errs.New("API_RESPONSE", "JumpServer API 未返回有效 JSON。")
			}
		}
	}
	return resp.StatusCode, nil
}
