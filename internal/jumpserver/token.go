package jumpserver

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"jsbridge/internal/errs"
)

var tzOffsetNoColon = regexp.MustCompile(`([+-]\d{2})(\d{2})$`)

type TokenRequest struct {
	AssetID         string
	AccountAlias    string // "@INPUT" 或托管账号 alias
	InputUsername   string
	InputSecret     string
	InputSecretType string // "password" 或 "ssh_key"
	Protocol        string // "ssh" 或 "sftp"
}

type ConnectionToken struct {
	ID          string `json:"id"`
	Value       string `json:"value"`
	IsActive    *bool  `json:"is_active"`
	IsReusable  bool   `json:"is_reusable"`
	IsExpired   bool   `json:"is_expired"`
	DateExpired string `json:"date_expired"`
}

func (c *Client) CreateConnectionToken(ctx context.Context, req TokenRequest) (*ConnectionToken, error) {
	if req.Protocol != "ssh" && req.Protocol != "sftp" {
		return nil, errs.New("PROTOCOL", "只支持 ssh 与 sftp 协议令牌。")
	}
	connectMethod := "ssh"
	if req.Protocol == "sftp" {
		connectMethod = "sftp"
	}
	account := req.AccountAlias
	if account == "" {
		account = "@INPUT"
	}

	payload := map[string]any{
		"asset":          req.AssetID,
		"account":        account,
		"protocol":       req.Protocol,
		"connect_method": connectMethod,
		"is_reusable":    false,
	}
	if account == "@INPUT" {
		payload["input_username"] = req.InputUsername
		payload["input_secret"] = req.InputSecret
		payload["input_secret_type"] = req.InputSecretType
	}

	var tok ConnectionToken
	_, err := c.Request(ctx, http.MethodPost, "/api/v1/authentication/connection-token/", payload, &tok)
	if err != nil {
		return nil, err
	}
	if tok.IsActive == nil || !*tok.IsActive {
		return nil, errs.New("APPROVAL_REQUIRED", "连接令牌处于未激活状态（需要登录审批），当前版本暂不支持等待审批。")
	}
	if !IsValidUUID(tok.ID) || strings.TrimSpace(tok.Value) == "" {
		return nil, errs.New("TOKEN_RESPONSE", "服务端返回的连接令牌不完整。")
	}
	if tok.IsReusable || tok.IsExpired {
		return nil, errs.New("TOKEN_RESPONSE", "连接令牌被标记为可复用或已过期，已拒绝使用。")
	}
	if strings.TrimSpace(tok.DateExpired) != "" {
		exp, parseErr := ParseJumpServerTime(tok.DateExpired)
		if parseErr != nil || !exp.After(time.Now().UTC()) {
			return nil, errs.New("TOKEN_RESPONSE", "连接令牌过期时间无效或已过期。")
		}
	}
	return &tok, nil
}

// ParseJumpServerTime 兼容标准 RFC3339/ISO8601 与JumpServer Core 返回的 "YYYY/MM/DD HH:MM:SS +0800" 格式。
func ParseJumpServerTime(raw string) (time.Time, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return time.Time{}, errs.New("TIME_FORMAT", "时间字符串为空。")
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006/01/02 15:04:05 -0700",
		"2006/01/02 15:04:05 -07:00",
		"2006-01-02 15:04:05 -0700",
		"2006-01-02 15:04:05 -07:00",
		"2006-01-02T15:04:05-0700",
		"2006-01-02T15:04:05.999999999-0700",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	normalized := tzOffsetNoColon.ReplaceAllString(strings.ReplaceAll(s, "Z", "+00:00"), "$1:$2")
	if t, err := time.Parse(time.RFC3339Nano, normalized); err == nil {
		return t, nil
	}
	return time.Time{}, errs.New("TIME_FORMAT", "无法解析服务端时间格式。")
}
