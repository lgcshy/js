package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"jsbridge/internal/config"
	"jsbridge/internal/credentials"
	"jsbridge/internal/errs"
	"jsbridge/internal/jumpserver"
	"jsbridge/internal/transport"
)

type InitOptions struct {
	ConfigPath    string
	CoreURL       string
	KoKoHost      string
	KoKoPort      int
	Fingerprint   string
	CAFile        string
	ProxyURL      string
	OrgID         string
	StoreMode     string // "", "keyring", "file"
	Username      string
	UseAccessKey  bool
	AccessKeyFile string
	KeyID         string // 仅供测试注入，CLI 不通过参数传 secret
	KeySecret     string // 仅供测试注入，CLI 不通过参数传 secret
	CustomStore   credentials.Store
	HTTPTransport http.RoundTripper
	PromptPass    func(string) (string, error)
	PromptText    func(string) (string, error)
	Out           io.Writer
	SkipHostCheck bool // 仅供无 SSH 的纯 API 单元测试使用
}

type InitResult struct {
	ConfigPath      string `json:"config_path"`
	Origin          string `json:"core_url"`
	Username        string `json:"jumpserver_user"`
	CredentialStore string `json:"credential_store"`
	CreatedAK       bool   `json:"created_ak"`
	KoKoFingerprint string `json:"koko_host_fingerprint"`
}

func Initialize(ctx context.Context, opts InitOptions) (*InitResult, error) {
	promptPass := opts.PromptPass
	if promptPass == nil {
		promptPass = credentials.PromptPassword
	}
	promptText := opts.PromptText
	if promptText == nil {
		promptText = credentials.PromptLine
	}
	out := opts.Out
	if out == nil {
		out = os.Stderr
	}

	cfgPath := strings.TrimSpace(opts.ConfigPath)
	if cfgPath == "" {
		var err error
		cfgPath, err = config.DefaultConfigPath()
		if err != nil {
			return nil, err
		}
	}
	cfgPath, err := filepath.Abs(config.ExpandHome(cfgPath))
	if err != nil {
		return nil, errs.New("CONFIG", "配置路径无效。")
	}

	// 若已有旧配置，保留原有的 targets / aliases / generation，只在验证通过后原子更新
	var existing config.Data
	if raw, readErr := os.ReadFile(cfgPath); readErr == nil {
		_ = json.Unmarshal(raw, &existing)
	}

	coreURL := firstNonEmpty(opts.CoreURL, existing.CoreURL)
	if coreURL == "" {
		ans, pErr := promptText("请输入 JumpServer 地址（例如 https://jumpserver.example.com）：")
		if pErr != nil {
			return nil, pErr
		}
		coreURL = strings.TrimSpace(ans)
	}
	origin, parsedHost, err := config.ValidateCoreOrigin(coreURL)
	if err != nil {
		return nil, err
	}
	kokoHost := firstNonEmpty(opts.KoKoHost, existing.KoKoHost, parsedHost)
	kokoPort := opts.KoKoPort
	if kokoPort <= 0 {
		if existing.KoKoPort > 0 {
			kokoPort = existing.KoKoPort
		} else {
			kokoPort = 2222
		}
	}
	expectedFP := firstNonEmpty(opts.Fingerprint, existing.KoKoHostFingerprint)
	caFile := firstNonEmpty(opts.CAFile, existing.CAFile)
	proxyURL := firstNonEmpty(opts.ProxyURL, existing.ProxyURL)
	orgID := firstNonEmpty(opts.OrgID, existing.OrgID)

	// 1. 先核验 KoKo SSH 主机身份（主机不受信时不读取或提交任何秘密）
	if !opts.SkipHostCheck {
		if strings.TrimSpace(expectedFP) == "" {
			observed, obsErr := transport.ObserveHostFingerprint(ctx, kokoHost, kokoPort)
			if obsErr != nil {
				return nil, obsErr
			}
			_, _ = fmt.Fprintf(out, "观察到 KoKo (%s:%d) 主机指纹：%s\n", kokoHost, kokoPort, observed)
			ans, pErr := promptText("请与管理员提供的可信记录核对，确认信任该指纹吗？[y/N]：")
			if pErr != nil {
				return nil, pErr
			}
			if a := strings.ToLower(strings.TrimSpace(ans)); a != "y" && a != "yes" {
				return nil, errs.New("HOST_KEY_UNTRUSTED", "未确认 KoKo 主机指纹，已取消初始化。")
			}
			expectedFP = observed
		} else {
			cb, cbErr := transport.BuildHostKeyCallback(expectedFP, nil)
			if cbErr != nil {
				return nil, cbErr
			}
			if vErr := transport.VerifyHostPrecheck(ctx, kokoHost, kokoPort, cb); vErr != nil {
				return nil, vErr
			}
		}
	}

	// 2. 选择并确认凭据存储后端（系统凭据库 vs 显式开启的 0600 文件存储）
	cfgDir := filepath.Dir(cfgPath)
	storeMode := strings.ToLower(strings.TrimSpace(opts.StoreMode))
	if storeMode == "" && existing.CredentialStore != "" {
		storeMode = existing.CredentialStore
	}

	var store credentials.Store = opts.CustomStore
	if store == nil {
		switch storeMode {
		case "file":
			if runtime.GOOS == "windows" {
				return nil, errs.New("STORE_UNSUPPORTED", "0600 文件存储仅在 Linux/Unix 提供；Windows 请使用系统凭据管理器。")
			}
			store = credentials.NewFileStore(cfgDir)
			printFileStoreNotice(out, cfgDir)
		case "", "keyring":
			kr := credentials.NewKeyringStore()
			if availErr := kr.Available(ctx, true); availErr != nil {
				if storeMode == "keyring" || runtime.GOOS == "windows" {
					return nil, availErr
				}
				_, _ = fmt.Fprintf(out, "! %s\n", availErr.Error())
				ans, pErr := promptText("是否显式开启 0600 权限文件存储（保存于 " + filepath.Join(cfgDir, "secrets.json") + "）？[y/N]：")
				if pErr != nil {
					return nil, pErr
				}
				if a := strings.ToLower(strings.TrimSpace(ans)); a == "y" || a == "yes" {
					storeMode = "file"
					store = credentials.NewFileStore(cfgDir)
					printFileStoreNotice(out, cfgDir)
				} else {
					return nil, errs.Action("KEYRING_UNAVAILABLE", "未启用凭据存储，已取消初始化。", "如需在无桌面 Linux 使用文件存储，请运行 js init --store file")
				}
			} else {
				storeMode = "keyring"
				store = kr
			}
		default:
			return nil, errs.New("CONFIG", "store 只支持 keyring 或 file。")
		}
	} else if storeMode == "" {
		storeMode = "keyring"
		if store.Name() == "file" {
			storeMode = "file"
		}
	}

	if availErr := store.Available(ctx, true); availErr != nil {
		return nil, availErr
	}

	// 3. 完成本人 JumpServer 认证并获得个人 Access Key
	var keyID, keySecret, resolvedUser, createdAKID string
	useAKMode := opts.UseAccessKey || strings.TrimSpace(opts.AccessKeyFile) != "" || (opts.KeyID != "" && opts.KeySecret != "")

	if strings.TrimSpace(opts.AccessKeyFile) != "" {
		rawBytes, rErr := credentials.ReadProtectedFile(config.ExpandHome(opts.AccessKeyFile), 65536)
		if rErr != nil {
			return nil, rErr
		}
		keyID, keySecret, err = credentials.ParseAccessKeySecret(string(rawBytes))
		if err != nil {
			return nil, err
		}
		resolvedUser = strings.TrimSpace(opts.Username)
	} else if opts.KeyID != "" && opts.KeySecret != "" {
		keyID = strings.TrimSpace(opts.KeyID)
		keySecret = strings.TrimSpace(opts.KeySecret)
		resolvedUser = strings.TrimSpace(opts.Username)
	} else if useAKMode {
		resolvedUser = strings.TrimSpace(opts.Username)
		keyID, err = promptText("个人 Access Key ID：")
		if err != nil {
			return nil, err
		}
		keySecret, err = promptPass("个人 Access Key Secret：")
		if err != nil {
			return nil, err
		}
	} else {
		username := strings.TrimSpace(opts.Username)
		if username == "" {
			defaultHint := ""
			if existing.JumpServerUser != "" {
				defaultHint = " [" + existing.JumpServerUser + "]"
			}
			username, err = promptText("JumpServer 账号" + defaultHint + "：")
			if err != nil {
				return nil, err
			}
			if username == "" {
				username = existing.JumpServerUser
			}
		}
		if username == "" {
			return nil, errs.New("EMPTY_CREDENTIALS", "JumpServer 账号不能为空。")
		}
		password, pErr := promptPass("JumpServer 密码：")
		if pErr != nil {
			return nil, pErr
		}
		pair, loginErr := jumpserver.LoginAndCreateAccessKey(ctx, jumpserver.PasswordInitOptions{
			Origin:    origin,
			CAFile:    caFile,
			ProxyURL:  proxyURL,
			Username:  username,
			Password:  password,
			Transport: opts.HTTPTransport,
		})
		password = ""
		if loginErr != nil {
			be, ok := errs.As(loginErr)
			if ok && (be.Code == "AK_CREATE_UNAVAILABLE" || be.Code == "MFA_UNSUPPORTED" || be.Code == "APPROVAL_REQUIRED") {
				_, _ = fmt.Fprintf(out, "! %s\n", be.Message)
				ans, askErr := promptText("是否现在粘贴在网页“个人信息 → API Key”创建的 Access Key？[Y/n]：")
				if askErr != nil {
					return nil, loginErr
				}
				if a := strings.ToLower(strings.TrimSpace(ans)); a == "n" || a == "no" {
					return nil, loginErr
				}
				keyID, err = promptText("个人 Access Key ID：")
				if err != nil {
					return nil, err
				}
				keySecret, err = promptPass("个人 Access Key Secret：")
				if err != nil {
					return nil, err
				}
				resolvedUser = username
			} else {
				return nil, loginErr
			}
		} else {
			_, _ = fmt.Fprintln(out, "✓ 登录成功")
			keyID = pair.ID
			keySecret = pair.Secret
			resolvedUser = pair.Username
			createdAKID = pair.ID
		}
	}

	// 4. 用该 Access Key 向 Core 核验本人身份（验证通过后才落盘和写入凭据库）
	client, err := jumpserver.NewClient(jumpserver.ClientOptions{
		Origin:    origin,
		Username:  resolvedUser,
		KeyID:     keyID,
		Secret:    keySecret,
		OrgID:     orgID,
		CAFile:    caFile,
		ProxyURL:  proxyURL,
		AllowMFA:  useAKMode || createdAKID == "",
		Transport: opts.HTTPTransport,
	})
	if err != nil {
		return nil, err
	}
	defer client.Close()

	profile, err := client.VerifyIdentity(ctx)
	if err != nil {
		return nil, err
	}
	resolvedUser = profile.Username

	// 5. 写入凭据库并原子保存配置
	svcName := credentials.ServiceName(origin)
	akEntry := credentials.AccessKeyEntry(resolvedUser)
	if err := store.Set(ctx, svcName, akEntry, credentials.FormatAccessKeySecret(keyID, keySecret), true); err != nil {
		return nil, err
	}
	keySecret = ""

	newCfg := &config.Config{
		Path:   cfgPath,
		Origin: origin,
		Data:   existing,
	}
	newCfg.Data.CoreURL = origin
	newCfg.Data.JumpServerUser = resolvedUser
	newCfg.Data.OrgID = orgID
	newCfg.Data.CAFile = caFile
	newCfg.Data.ProxyURL = proxyURL
	newCfg.Data.KoKoHost = kokoHost
	newCfg.Data.KoKoPort = kokoPort
	newCfg.Data.KoKoHostFingerprint = expectedFP
	newCfg.Data.CredentialStore = storeMode
	newCfg.Data.AccessKeyFile = ""
	if createdAKID != "" {
		newCfg.Data.CreatedAKID = createdAKID
	}
	if newCfg.Data.SavePasswordPolicy == "" {
		newCfg.Data.SavePasswordPolicy = "always"
	}
	if newCfg.Data.Aliases == nil {
		newCfg.Data.Aliases = map[string]string{}
	}
	if newCfg.Data.Targets == nil {
		newCfg.Data.Targets = map[string]config.TargetConfig{}
	}
	newCfg.RecordStoredCredential(akEntry)
	newCfg.BumpGeneration()

	if err := newCfg.Save(); err != nil {
		return nil, err
	}

	storeDesc := "系统凭据库"
	if storeMode == "file" {
		storeDesc = "0600 凭据文件 (" + filepath.Join(cfgDir, "secrets.json") + ")"
	}
	if createdAKID != "" {
		_, _ = fmt.Fprintf(out, "✓ 已为本机创建个人 Access Key，保存到%s（你的密码不会被保存）\n", storeDesc)
	} else {
		_, _ = fmt.Fprintf(out, "✓ 已验证个人 Access Key（账号 %s），保存到%s\n", resolvedUser, storeDesc)
	}
	if !opts.SkipHostCheck && expectedFP != "" {
		_, _ = fmt.Fprintf(out, "✓ KoKo 主机指纹已核验 (%s)\n", expectedFP)
	}
	_, _ = fmt.Fprintln(out, "完成。试试：js hosts")

	return &InitResult{
		ConfigPath:      cfgPath,
		Origin:          origin,
		Username:        resolvedUser,
		CredentialStore: storeMode,
		CreatedAK:       createdAKID != "",
		KoKoFingerprint: expectedFP,
	}, nil
}

func printFileStoreNotice(out io.Writer, cfgDir string) {
	_, _ = fmt.Fprintln(out, "提示：0600 文件存储不加密，依靠操作系统文件权限保护；本机 root、同账号进程或家目录备份可读取，切勿在多人共享账号上启用。")
	if isNet, fsType := config.IsNetworkFilesystem(cfgDir); isNet {
		_, _ = fmt.Fprintf(out, "警告：检测到配置目录位于网络文件系统 (%s)，凭据文件可能暴露于网络存储服务端！\n", fsType)
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func (s *Service) SetTargetPassword(ctx context.Context, targetInput string, interactive bool) (string, error) {
	rt, _, err := s.Config.ResolveTarget(targetInput)
	if err != nil {
		return "", err
	}
	if s.Store == nil {
		return "", errs.New("KEYRING_UNAVAILABLE", "未初始化凭据存储。")
	}
	pw, err := s.PromptPass(fmt.Sprintf("保存 %s 的目标密码：", rt.Canonical))
	if err != nil {
		return "", err
	}
	if pw == "" {
		return "", errs.New("EMPTY_SECRET", "密码不能为空。")
	}
	entryKey := credentials.TargetEntry(rt.Entry.AssetID, rt.Username, rt.Canonical)
	if err := s.Store.Set(ctx, s.ServiceKey(), entryKey, pw, interactive); err != nil {
		return "", err
	}
	pw = ""
	fallbackKey := credentials.TargetFallbackEntry(rt.Canonical)
	if fallbackKey != entryKey {
		_ = s.Store.Delete(ctx, s.ServiceKey(), fallbackKey, interactive)
	}

	err = s.Config.Update(true, func(d *config.Data) error {
		if d.Targets == nil {
			d.Targets = map[string]config.TargetConfig{}
		}
		tc := d.Targets[rt.Canonical]
		tc.Credential = config.CredentialConfig{Type: "store"}
		d.Targets[rt.Canonical] = tc
		s.Config.RecordStoredCredential(entryKey)
		if fallbackKey != entryKey {
			s.Config.RemoveStoredCredential(fallbackKey)
		}
		d.StoredCredentials = s.Config.Data.StoredCredentials
		return nil
	})
	return rt.Canonical, err
}

func (s *Service) ForgetTarget(ctx context.Context, targetInput string, interactive bool) (string, error) {
	rt, _, err := s.Config.ResolveTarget(targetInput)
	if err != nil {
		return "", err
	}
	keysToDelete := []string{
		credentials.TargetEntry(rt.Entry.AssetID, rt.Username, rt.Canonical),
		credentials.TargetFallbackEntry(rt.Canonical),
		credentials.KeyPassphraseEntry(rt.Canonical),
	}
	if s.Store != nil {
		for _, k := range keysToDelete {
			if k != "" {
				_ = s.Store.Delete(ctx, s.ServiceKey(), k, interactive)
			}
		}
		_ = s.Store.Delete(ctx, "jumpserver-adapter:"+s.Config.Origin, rt.Canonical, interactive)
	}

	err = s.Config.Update(true, func(d *config.Data) error {
		if tc, exists := d.Targets[rt.Canonical]; exists {
			// 只清除本工具保存的凭据引用，不删除用户的私钥文件或外部 gopass 条目
			tc.Credential = config.CredentialConfig{Type: "prompt"}
			d.Targets[rt.Canonical] = tc
		}
		for _, k := range keysToDelete {
			s.Config.RemoveStoredCredential(k)
		}
		d.StoredCredentials = s.Config.Data.StoredCredentials
		return nil
	})
	return rt.Canonical, err
}

func (s *Service) BindGopass(targetInput, ref string) (string, error) {
	rt, _, err := s.Config.ResolveTarget(targetInput)
	if err != nil {
		return "", err
	}
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "-") || strings.ContainsAny(ref, "\r\n\x00") {
		return "", errs.New("CREDENTIAL_REF", "gopass 条目名无效。")
	}
	err = s.Config.Update(true, func(d *config.Data) error {
		if d.Targets == nil {
			d.Targets = map[string]config.TargetConfig{}
		}
		tc := d.Targets[rt.Canonical]
		tc.Credential = config.CredentialConfig{
			Type: "gopass",
			Ref:  ref,
		}
		d.Targets[rt.Canonical] = tc
		return nil
	})
	return rt.Canonical, err
}

func (s *Service) BindSSHKey(targetInput, identityPath string, allowSubmission bool, passphraseGopassRef string) (string, error) {
	rt, _, err := s.Config.ResolveTarget(targetInput)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(identityPath) == "" {
		return "", errs.New("PRIVATE_KEY", "必须指定具体的私钥文件路径。")
	}
	absKeyPath, err := filepath.Abs(s.Config.LocalPath(identityPath))
	if err != nil {
		return "", errs.New("PRIVATE_KEY", "私钥路径无效。")
	}
	info, err := os.Lstat(absKeyPath)
	if err != nil || !info.Mode().IsRegular() {
		return "", errs.New("PRIVATE_KEY", "指定的私钥文件不存在或不是常规文件（拒绝软链接）。")
	}
	if strings.TrimSpace(passphraseGopassRef) != "" {
		if strings.HasPrefix(passphraseGopassRef, "-") || strings.ContainsAny(passphraseGopassRef, "\r\n\x00") {
			return "", errs.New("CREDENTIAL_REF", "passphrase gopass 条目名无效。")
		}
	}

	err = s.Config.Update(true, func(d *config.Data) error {
		if d.Targets == nil {
			d.Targets = map[string]config.TargetConfig{}
		}
		tc := d.Targets[rt.Canonical]
		tc.Credential = config.CredentialConfig{
			Type:                "ssh_key",
			Path:                absKeyPath,
			SubmitToJumpServer:  allowSubmission,
			PassphraseGopassRef: strings.TrimSpace(passphraseGopassRef),
		}
		d.Targets[rt.Canonical] = tc
		return nil
	})
	return rt.Canonical, err
}

type LogoutResult struct {
	ServerAKRevoked bool   `json:"server_ak_revoked"`
	LocalAKDeleted  bool   `json:"local_ak_deleted"`
	Warning         string `json:"warning,omitempty"`
}

func (s *Service) Logout(ctx context.Context, interactive bool) (*LogoutResult, error) {
	res := &LogoutResult{}
	createdID := strings.TrimSpace(s.Config.Data.CreatedAKID)
	if createdID != "" {
		if api, err := s.NewCoreClient(ctx, interactive); err == nil {
			if revErr := api.RevokeAccessKey(ctx, createdID); revErr == nil {
				res.ServerAKRevoked = true
			} else {
				res.Warning = "本地登录凭据已清除，但未能在线吊销服务端 Access Key（请必要时在网页“个人信息 → API Key”确认）。"
			}
			api.Close()
		}
	}

	akEntry := credentials.AccessKeyEntry(s.Config.Data.JumpServerUser)
	if s.Store != nil {
		if err := s.Store.Delete(ctx, s.ServiceKey(), akEntry, interactive); err == nil {
			res.LocalAKDeleted = true
		}
	}

	err := s.Config.Update(true, func(d *config.Data) error {
		d.CreatedAKID = ""
		d.AccessKeyFile = ""
		s.Config.RemoveStoredCredential(akEntry)
		d.StoredCredentials = s.Config.Data.StoredCredentials
		return nil
	})
	return res, err
}

func (s *Service) MigrateStore(ctx context.Context, targetMode string, interactive bool) (int, error) {
	targetMode = strings.ToLower(strings.TrimSpace(targetMode))
	if targetMode != "keyring" && targetMode != "file" {
		return 0, errs.New("CONFIG", "目标存储类型只支持 keyring 或 file。")
	}
	if targetMode == "file" && runtime.GOOS == "windows" {
		return 0, errs.New("STORE_UNSUPPORTED", "0600 文件存储仅在 Linux/Unix 提供。")
	}
	if s.Config.Data.CredentialStore == targetMode {
		return 0, nil
	}

	var dst credentials.Store
	if targetMode == "file" {
		dst = credentials.NewFileStore(s.Config.Dir())
	} else {
		dst = credentials.NewKeyringStore()
	}

	keys := append([]string(nil), s.Config.Data.StoredCredentials...)
	akKey := credentials.AccessKeyEntry(s.Config.Data.JumpServerUser)
	hasAK := false
	for _, k := range keys {
		if k == akKey {
			hasAK = true
			break
		}
	}
	if !hasAK && s.Config.Data.JumpServerUser != "" {
		keys = append(keys, akKey)
	}

	count, err := credentials.MigrateStore(ctx, s.Store, dst, s.ServiceKey(), keys, interactive)
	if err != nil {
		return 0, err
	}
	err = s.Config.Update(true, func(d *config.Data) error {
		d.CredentialStore = targetMode
		return nil
	})
	if err != nil {
		return 0, err
	}
	s.Store = dst
	return count, nil
}

type ImportSummary struct {
	FromPath               string   `json:"from_path"`
	DryRun                 bool     `json:"dry_run"`
	ImportedTargets        []string `json:"imported_targets"`
	ImportedAliases        []string `json:"imported_aliases"`
	MigratedKeyringTargets []string `json:"migrated_keyring_targets,omitempty"`
	Skipped                []string `json:"skipped,omitempty"`
}

// ImportLegacyConfig 从 Python 原型 config.json 导入目标映射和别名（不复制明文文件秘密、不自动继承未经确认的私钥上传许可）。
func (s *Service) ImportLegacyConfig(fromPath string, dryRun bool) (*ImportSummary, error) {
	absFrom, err := filepath.Abs(config.ExpandHome(fromPath))
	if err != nil {
		return nil, errs.New("IMPORT_PATH", "导入源路径无效。")
	}
	raw, err := os.ReadFile(absFrom)
	if err != nil {
		return nil, errs.New("IMPORT_READ", "无法读取旧配置文件。")
	}
	var legacy config.Data
	if err := json.Unmarshal(raw, &legacy); err != nil {
		return nil, errs.New("IMPORT_PARSE", "旧配置文件不是有效的 JSON。")
	}

	summary := &ImportSummary{
		FromPath: absFrom,
		DryRun:   dryRun,
	}

	newTargets := map[string]config.TargetConfig{}
	var newStoredKeys []string
	var targetKeys []string
	for k := range legacy.Targets {
		targetKeys = append(targetKeys, k)
	}
	sort.Strings(targetKeys)

	for _, k := range targetKeys {
		src := legacy.Targets[k]
		rt, _, tErr := s.Config.ResolveTarget(k)
		if tErr != nil {
			summary.Skipped = append(summary.Skipped, k+" (格式不兼容)")
			continue
		}
		if _, exists := s.Config.Data.Targets[rt.Canonical]; exists {
			summary.Skipped = append(summary.Skipped, rt.Canonical+" (本地已存在，跳过覆盖)")
			continue
		}
		tc := config.TargetConfig{
			AssetID:   src.AssetID,
			FileRoots: src.FileRoots,
		}
		switch src.Credential.Type {
		case "gopass":
			tc.Credential = config.CredentialConfig{Type: "gopass", Ref: src.Credential.Ref}
		case "ssh_key":
			// 安全门禁：不自动继承 submit_to_jumpserver=true，需用户显式确认
			var resolvedPath string
			if strings.TrimSpace(src.Credential.Path) != "" {
				p := config.ExpandHome(src.Credential.Path)
				if !filepath.IsAbs(p) {
					p = filepath.Join(filepath.Dir(absFrom), p)
				}
				resolvedPath = p
			}
			tc.Credential = config.CredentialConfig{
				Type:                "ssh_key",
				Path:                resolvedPath,
				SubmitToJumpServer:  false,
				PassphraseGopassRef: src.Credential.PassphraseGopassRef,
			}
		case "keyring", "store":
			tc.Credential = config.CredentialConfig{Type: "store"}
			if s.Store != nil {
				legacySvc := "jumpserver-adapter:" + s.Config.Origin
				if val, gErr := s.Store.Get(context.Background(), legacySvc, rt.Canonical, false); gErr == nil && val != "" {
					summary.MigratedKeyringTargets = append(summary.MigratedKeyringTargets, rt.Canonical)
					if !dryRun {
						entryKey := credentials.TargetEntry(src.AssetID, rt.Username, rt.Canonical)
						if sErr := s.Store.Set(context.Background(), s.ServiceKey(), entryKey, val, false); sErr == nil {
							newStoredKeys = append(newStoredKeys, entryKey)
						}
					}
				}
			}
		default:
			tc.Credential = config.CredentialConfig{Type: "prompt"}
		}
		newTargets[rt.Canonical] = tc
		summary.ImportedTargets = append(summary.ImportedTargets, rt.Canonical)
	}

	newAliases := map[string]string{}
	var aliasKeys []string
	for a := range legacy.Aliases {
		aliasKeys = append(aliasKeys, a)
	}
	sort.Strings(aliasKeys)
	for _, a := range aliasKeys {
		dest := legacy.Aliases[a]
		if config.IsReservedCommand(a) {
			summary.Skipped = append(summary.Skipped, "alias:"+a+" (与保留子命令冲突)")
			continue
		}
		if _, exists := s.Config.Data.Aliases[a]; exists {
			summary.Skipped = append(summary.Skipped, "alias:"+a+" (已存在)")
			continue
		}
		if rt, _, aErr := s.Config.ResolveTarget(dest); aErr == nil {
			newAliases[a] = rt.Canonical
			summary.ImportedAliases = append(summary.ImportedAliases, a+" -> "+rt.Canonical)
		} else {
			summary.Skipped = append(summary.Skipped, "alias:"+a+" (目标无效)")
		}
	}

	if !dryRun && (len(newTargets) > 0 || len(newAliases) > 0 || len(newStoredKeys) > 0) {
		err = s.Config.Update(true, func(d *config.Data) error {
			if d.Targets == nil {
				d.Targets = map[string]config.TargetConfig{}
			}
			for k, v := range newTargets {
				d.Targets[k] = v
			}
			if d.Aliases == nil {
				d.Aliases = map[string]string{}
			}
			for k, v := range newAliases {
				d.Aliases[k] = v
			}
			for _, sk := range newStoredKeys {
				s.Config.RecordStoredCredential(sk)
			}
			d.StoredCredentials = s.Config.Data.StoredCredentials
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return summary, nil
}
