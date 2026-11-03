package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"jsbridge/internal/app"
	"jsbridge/internal/jumpserver"
	"jsbridge/internal/transport"
)

type P0Report struct {
	Timestamp             string                    `json:"timestamp"`
	Origin                string                    `json:"origin"`
	KoKo                  string                    `json:"koko"`
	KoKoHandshakeMs       int64                     `json:"koko_handshake_ms"`
	KoKoFingerprintMatch  bool                      `json:"koko_fingerprint_match"`
	Identity              map[string]any            `json:"identity,omitempty"`
	TokensEndpointStatus  int                       `json:"tokens_endpoint_options_status"`
	AccessKeysReadAllowed bool                      `json:"access_keys_list_allowed"`
	ExistingAccessKeys    int                       `json:"existing_access_key_count"`
	AssetListCount        int                       `json:"asset_list_count"`
	AssetListMs           int64                     `json:"asset_list_ms"`
	SingleAssetQueryMs    int64                     `json:"single_asset_query_ms,omitempty"`
	SingleAssetProtocols  []string                  `json:"single_asset_protocols,omitempty"`
	SingleAssetAccounts   []map[string]any          `json:"single_asset_accounts,omitempty"`
	ExecBaseline          map[string]any            `json:"exec_baseline,omitempty"`
	SFTPProbe             *transport.SFTPProbeResult `json:"sftp_probe,omitempty"`
	SFTPTimings           *app.StageTimings         `json:"sftp_timings,omitempty"`
	SFTPError             string                    `json:"sftp_error,omitempty"`
}

// runP0Probe 执行只读 P0 服务端契约核验，不写入远端文件、不修改凭据、不输出任何秘密值。
func runP0Probe(ctx context.Context, svc *app.Service, target string) (*P0Report, error) {
	rep := &P0Report{
		Timestamp: time.Now().Format(time.RFC3339),
		Origin:    svc.Config.Origin,
		KoKo:      fmt.Sprintf("%s:%d", svc.Config.Data.KoKoHost, svc.Config.Data.KoKoPort),
	}

	// 1. KoKo 握手与指纹核验耗时
	t0 := time.Now()
	observed, err := transport.ObserveHostFingerprint(ctx, svc.Config.Data.KoKoHost, svc.Config.Data.KoKoPort)
	if err != nil {
		return nil, err
	}
	rep.KoKoHandshakeMs = time.Since(t0).Milliseconds()
	rep.KoKoFingerprintMatch = (svc.Config.Data.KoKoHostFingerprint == "" || observed == svc.Config.Data.KoKoHostFingerprint)

	// 2. OPTIONS /api/v1/authentication/tokens/ 可达性核查
	hc, err := jumpserver.NewHTTPClient(svc.Config.Data.CAFile, svc.Config.Data.ProxyURL, nil, svc.HTTPTransport)
	if err == nil {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodOptions, svc.Config.Origin+"/api/v1/authentication/tokens/", nil)
		if reqErr == nil {
			req.Header.Set("Accept", "application/json")
			if resp, doErr := hc.Do(req); doErr == nil {
				rep.TokensEndpointStatus = resp.StatusCode
				_ = resp.Body.Close()
			}
		}
		hc.CloseIdleConnections()
	}

	// 3. 本人 API 身份、Access Key 接口权限与资产查询耗时对比
	api, err := svc.NewCoreClient(ctx, false)
	if err != nil {
		return nil, err
	}
	defer api.Close()

	prof, err := api.VerifyIdentity(ctx)
	if err != nil {
		return nil, err
	}
	rep.Identity = map[string]any{
		"username":          prof.Username,
		"is_active":         prof.IsActive,
		"mfa_enabled":       prof.MFAEnabled,
		"mfa_force_enabled": prof.MFAForceEnabled,
	}

	if aks, akErr := api.ListAccessKeys(ctx); akErr == nil {
		rep.AccessKeysReadAllowed = true
		rep.ExistingAccessKeys = len(aks)
	}

	tList := time.Now()
	assets, err := api.ListAssets(ctx)
	if err != nil {
		return nil, err
	}
	rep.AssetListMs = time.Since(tList).Milliseconds()
	rep.AssetListCount = len(assets)

	if target == "" {
		return rep, nil
	}

	// 4. 指定目标的单次资产详情查询、只读命令耗时基线与只读 SFTP 根目录探测
	rt, _, err := svc.Config.ResolveTarget(target)
	if err != nil {
		return nil, err
	}

	var targetAssetID string
	for _, a := range assets {
		if a.Address == rt.Address {
			targetAssetID = a.ID
			break
		}
	}
	if targetAssetID != "" {
		tSingle := time.Now()
		detail, dErr := api.GetAsset(ctx, targetAssetID)
		rep.SingleAssetQueryMs = time.Since(tSingle).Milliseconds()
		if dErr == nil && detail != nil {
			for _, p := range detail.PermedProtocols {
				rep.SingleAssetProtocols = append(rep.SingleAssetProtocols, p.Name)
			}
			for _, acc := range detail.PermedAccounts {
				var acts []string
				for _, act := range acc.Actions {
					acts = append(acts, act.Value)
				}
				entry := map[string]any{
					"alias":    acc.Alias,
					"username": acc.Username,
					"actions":  acts,
				}
				if acc.HasSecret != nil {
					entry["has_secret"] = *acc.HasSecret
				}
				rep.SingleAssetAccounts = append(rep.SingleAssetAccounts, entry)
			}
		}
	}

	// 只读 exec 基线（hostname）
	execStart := time.Now()
	execRes, timings, execErr := svc.ExecuteCommand(ctx, rt.Canonical, "hostname", 15*time.Second, "", false)
	if execErr == nil && execRes != nil {
		rep.ExecBaseline = map[string]any{
			"status":             execRes.Status,
			"exit_code":          execRes.ExitCode,
			"end_to_end_ms":      time.Since(execStart).Milliseconds(),
			"connect_timings":    timings,
			"command_execute_ms": execRes.DurationMs,
		}
	} else if execErr != nil {
		rep.ExecBaseline = map[string]any{
			"error": execErr.Error(),
		}
	}

	// 只读 SFTP 令牌与根目录映射探测
	sftpSess, sftpErr := svc.OpenConnection(ctx, rt.Canonical, "sftp", false, "")
	if sftpErr != nil {
		rep.SFTPError = sftpErr.Error()
	} else {
		defer sftpSess.Conn.Close()
		rep.SFTPTimings = &sftpSess.Timings
		probe, pErr := sftpSess.Conn.ProbeSFTP("/home/" + rt.Username)
		if pErr != nil {
			rep.SFTPError = pErr.Error()
		} else {
			rep.SFTPProbe = probe
		}
	}

	return rep, nil
}
