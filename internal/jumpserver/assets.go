package jumpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"jsbridge/internal/errs"
)

type UserProfile struct {
	ID              string `json:"id"`
	Username        string `json:"username"`
	Name            string `json:"name"`
	IsActive        bool   `json:"is_active"`
	IsValid         bool   `json:"is_valid"`
	IsSuperuser     bool   `json:"is_superuser"`
	IsOrgAdmin      bool   `json:"is_org_admin"`
	IsServiceAcct   bool   `json:"is_service_account"`
	MFAEnabled      bool   `json:"mfa_enabled"`
	MFAForceEnabled bool   `json:"mfa_force_enabled"`
}

type PermProtocol struct {
	Name string `json:"name"`
	Port int    `json:"port"`
}

type PermAction struct {
	Value string `json:"value"`
	Label string `json:"label,omitempty"`
}

type PermAccount struct {
	Alias     string       `json:"alias"`
	Name      string       `json:"name"`
	Username  string       `json:"username"`
	HasSecret *bool        `json:"has_secret,omitempty"`
	Actions   []PermAction `json:"actions"`
}

func (a PermAccount) HasAction(act string) bool {
	for _, x := range a.Actions {
		if x.Value == act {
			return true
		}
	}
	return false
}

type AssetSummary struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Address  string `json:"address"`
	IsActive bool   `json:"is_active"`
}

type AssetDetail struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Address         string         `json:"address"`
	IsActive        bool           `json:"is_active"`
	PermedProtocols []PermProtocol `json:"permed_protocols"`
	PermedAccounts  []PermAccount  `json:"permed_accounts"`
}

func (a AssetDetail) SupportsProtocol(proto string) bool {
	for _, p := range a.PermedProtocols {
		if p.Name == proto {
			return true
		}
	}
	return false
}

func (c *Client) VerifyIdentity(ctx context.Context) (*UserProfile, error) {
	var profile UserProfile
	if _, err := c.Request(ctx, http.MethodGet, "/api/v1/users/profile/", nil, &profile); err != nil {
		return nil, err
	}
	if (c.username != "" && profile.Username != c.username) ||
		profile.IsSuperuser || profile.IsOrgAdmin || profile.IsServiceAcct {
		return nil, errs.New("IDENTITY", "API 身份必须属于配置指定的本人普通用户账号（禁止管理员或服务账号令牌）。")
	}
	if !profile.IsActive || !profile.IsValid {
		return nil, errs.New("IDENTITY", "本人 JumpServer 账号当前未启用或已失效。")
	}
	if !c.allowMFA && (profile.MFAEnabled || profile.MFAForceEnabled) {
		return nil, errs.New("MFA_REQUIRED", "账号已启用 MFA；当前版本暂不支持 MFA 挑战流程。")
	}
	c.mu.Lock()
	c.profileVerified = true
	if c.username == "" {
		c.username = profile.Username
	}
	c.mu.Unlock()
	return &profile, nil
}

func (c *Client) ensureIdentityVerified(ctx context.Context) error {
	c.mu.Lock()
	verified := c.profileVerified
	c.mu.Unlock()
	if verified {
		return nil
	}
	_, err := c.VerifyIdentity(ctx)
	return err
}

func (c *Client) ListAssets(ctx context.Context) ([]AssetSummary, error) {
	if err := c.ensureIdentityVerified(ctx); err != nil {
		return nil, err
	}
	var all []AssetSummary
	for offset := 0; offset < 5000; offset += 100 {
		path := fmt.Sprintf("/api/v1/perms/users/self/assets/?limit=100&offset=%d", offset)
		var raw json.RawMessage
		if _, err := c.Request(ctx, http.MethodGet, path, nil, &raw); err != nil {
			return nil, err
		}
		var direct []AssetSummary
		if err := json.Unmarshal(raw, &direct); err == nil {
			all = append(all, direct...)
			return all, nil
		}
		var paged struct {
			Results []AssetSummary `json:"results"`
			Next    any            `json:"next"`
		}
		if err := json.Unmarshal(raw, &paged); err != nil {
			return nil, errs.New("API_RESPONSE", "解析授权资产列表失败。")
		}
		all = append(all, paged.Results...)
		if paged.Next == nil || paged.Next == "" {
			return all, nil
		}
	}
	return nil, errs.New("ASSET_LIMIT", "授权资产超过 5000 条限制，请通过 org_id 缩小组织范围。")
}

func (c *Client) GetAsset(ctx context.Context, assetID string) (*AssetDetail, error) {
	assetID = strings.TrimSpace(assetID)
	if !IsValidUUID(assetID) {
		return nil, errs.New("ASSET_ID", "资产 UUID 格式无效。")
	}
	var detail AssetDetail
	_, err := c.Request(ctx, http.MethodGet, "/api/v1/perms/users/self/assets/"+assetID+"/", nil, &detail)
	if err != nil {
		return nil, err
	}
	return &detail, nil
}

type ResolveAssetRequest struct {
	Address        string
	CachedAssetID  string
	Protocol       string
	Username       string
	ManagedAccount string // 若指定则强制使用该托管账号
	AllowManaged   bool   // 若为 true 且资产存在同名已托管秘密账号，优先免密使用托管账号
	RequiredAction string // 可选动作要求，如 "upload" 或 "download"
}

type ResolvedAsset struct {
	Asset        AssetDetail
	AccountAlias string // "@INPUT" 或托管账号 alias
	Account      PermAccount
	IsManaged    bool
	CacheHit     bool
}

func (c *Client) ResolveAsset(ctx context.Context, req ResolveAssetRequest) (*ResolvedAsset, error) {
	if err := c.ensureIdentityVerified(ctx); err != nil {
		return nil, err
	}

	// 快速路径：命中本地缓存的 asset_id 时只需 1 次资产详情请求
	if IsValidUUID(req.CachedAssetID) {
		detail, err := c.GetAsset(ctx, req.CachedAssetID)
		if err == nil && detail != nil && detail.IsActive &&
			detail.Address == req.Address && detail.SupportsProtocol(req.Protocol) {
			if resolved, accErr := selectAssetAccount(*detail, req); accErr == nil {
				resolved.CacheHit = true
				return resolved, nil
			}
		}
		// 若缓存资产已重建/失效（如 404），重置 auth latch 之外继续列表回退（注意 404 不会触发 failedAuth）
	}

	items, err := c.ListAssets(ctx)
	if err != nil {
		return nil, err
	}
	var matches []AssetDetail
	for _, item := range items {
		if item.Address != req.Address {
			continue
		}
		detail, dErr := c.GetAsset(ctx, item.ID)
		if dErr != nil {
			return nil, dErr
		}
		if detail.IsActive && detail.SupportsProtocol(req.Protocol) {
			matches = append(matches, *detail)
		}
	}
	if len(matches) == 0 {
		return nil, errs.New("ASSET_PERMISSION", "当前组织范围内找不到该 IP 的已授权 "+strings.ToUpper(req.Protocol)+" 资产。")
	}
	if len(matches) > 1 {
		// 若已配置明确 asset_id 且匹配其中一个，直接选中
		if req.CachedAssetID != "" {
			for _, m := range matches {
				if m.ID == req.CachedAssetID {
					return selectAssetAccount(m, req)
				}
			}
		}
		return nil, errs.New("AMBIGUOUS_ASSET", "同一 IP 匹配到多个已授权资产；请在配置中明确指定 asset_id。")
	}
	return selectAssetAccount(matches[0], req)
}

func selectAssetAccount(asset AssetDetail, req ResolveAssetRequest) (*ResolvedAsset, error) {
	checkAction := func(acc PermAccount) error {
		if req.RequiredAction == "" {
			return nil
		}
		if acc.HasAction(req.RequiredAction) || acc.HasAction("all") {
			return nil
		}
		return errs.New("ACTION_PERMISSION", fmt.Sprintf("该资产账号未授权 %s 文件传输动作。", req.RequiredAction))
	}

	// 1. 显式指定托管账号
	if strings.TrimSpace(req.ManagedAccount) != "" {
		want := strings.TrimSpace(req.ManagedAccount)
		for _, acc := range asset.PermedAccounts {
			if acc.Alias != "@INPUT" && (acc.Alias == want || acc.Username == want || acc.Name == want) && acc.HasAction("connect") {
				if err := checkAction(acc); err != nil {
					return nil, err
				}
				alias := acc.Alias
				if alias == "" {
					alias = acc.Username
				}
				return &ResolvedAsset{
					Asset:        asset,
					AccountAlias: alias,
					Account:      acc,
					IsManaged:    true,
				}, nil
			}
		}
		return nil, errs.New("ACCOUNT_PERMISSION", "该资产未授权指定的托管账号连接。")
	}

	// 2. 自动发现同名且已托管秘密的账号（仅当用户尚未手动绑定本机密码/私钥/gopass 时）
	if req.AllowManaged && req.Username != "" {
		for _, acc := range asset.PermedAccounts {
			if acc.Alias != "@INPUT" && !strings.HasPrefix(acc.Alias, "@") &&
				acc.Username == req.Username && acc.HasAction("connect") {
				if acc.HasSecret == nil || *acc.HasSecret {
					if err := checkAction(acc); err != nil {
						return nil, err
					}
					alias := acc.Alias
					if alias == "" {
						alias = acc.Username
					}
					return &ResolvedAsset{
						Asset:        asset,
						AccountAlias: alias,
						Account:      acc,
						IsManaged:    true,
					}, nil
				}
			}
		}
	}

	// 3. 标准 @INPUT 路线
	for _, acc := range asset.PermedAccounts {
		if acc.Alias == "@INPUT" && acc.HasAction("connect") {
			if err := checkAction(acc); err != nil {
				return nil, err
			}
			return &ResolvedAsset{
				Asset:        asset,
				AccountAlias: "@INPUT",
				Account:      acc,
				IsManaged:    false,
			}, nil
		}
	}

	return nil, errs.New("ACCOUNT_PERMISSION", "该资产未授权 @INPUT 或对应托管账号连接；不会尝试其他账号。")
}
