package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lgcshy/js/internal/config"
	"github.com/lgcshy/js/internal/credentials"
	"github.com/lgcshy/js/internal/errs"
	"github.com/lgcshy/js/internal/jumpserver"
	"github.com/lgcshy/js/internal/transport"
)

type StageTimings struct {
	HostVerifyMs     int64 `json:"host_verify_ms"`
	AssetResolveMs   int64 `json:"asset_resolve_ms"`
	CredentialReadMs int64 `json:"credential_read_ms"`
	TokenCreateMs    int64 `json:"token_create_ms"`
	KoKoAuthMs       int64 `json:"koko_auth_ms"`
	TotalMs          int64 `json:"total_ms"`
	AssetCacheHit    bool  `json:"asset_cache_hit"`
}

type Service struct {
	Config        *config.Config
	Store         credentials.Store
	HTTPTransport http.RoundTripper
	PromptPass    func(prompt string) (string, error)
	PromptText    func(prompt string) (string, error)
	Stderr        io.Writer
}

func NewService(cfg *config.Config, customStore credentials.Store) *Service {
	var store credentials.Store = customStore
	if store == nil && cfg != nil {
		store = StoreForConfig(cfg)
	}
	return &Service{
		Config:     cfg,
		Store:      store,
		PromptPass: credentials.PromptPassword,
		PromptText: credentials.PromptLine,
		Stderr:     os.Stderr,
	}
}

func StoreForConfig(cfg *config.Config) credentials.Store {
	if cfg != nil && cfg.Data.CredentialStore == "file" {
		return credentials.NewFileStore(cfg.Dir())
	}
	return credentials.NewKeyringStore()
}

func (s *Service) ServiceKey() string {
	return credentials.ServiceName(s.Config.Origin)
}

func (s *Service) LoadAccessKey(ctx context.Context, interactive bool) (string, string, error) {
	// 1. 优先从配置的凭据存储（系统凭据库或显式开启的 0600 secrets.json）读取本机 AK
	if s.Store != nil {
		akKey := credentials.AccessKeyEntry(s.Config.Data.JumpServerUser)
		raw, err := s.Store.Get(ctx, s.ServiceKey(), akKey, interactive)
		if err == nil && strings.TrimSpace(raw) != "" {
			return credentials.ParseAccessKeySecret(raw)
		}
		if err != nil && !errors.Is(err, credentials.ErrNotFound) {
			// 若未配置备用 access_key_file，直接返回凭据库锁定/权限错误
			if strings.TrimSpace(s.Config.Data.AccessKeyFile) == "" {
				return "", "", err
			}
		}
	}

	// 2. 兼容显式配置的 0600 access_key_file（如测试夹具或手动指定的文件）
	if strings.TrimSpace(s.Config.Data.AccessKeyFile) != "" {
		akPath := s.Config.LocalPath(s.Config.Data.AccessKeyFile)
		rawBytes, err := credentials.ReadProtectedFile(akPath, 65536)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return "", "", errs.Action("NOT_LOGGED_IN", "未找到本机 Access Key 凭据。", "请运行 js init 完成初始化")
			}
			return "", "", err
		}
		return credentials.ParseAccessKeySecret(string(rawBytes))
	}

	return "", "", errs.Action("NOT_LOGGED_IN", "本机尚未保存 JumpServer 登录凭据。", "请运行 js init 完成初始化")
}

func (s *Service) NewCoreClient(ctx context.Context, interactive bool) (*jumpserver.Client, error) {
	keyID, secret, err := s.LoadAccessKey(ctx, interactive)
	if err != nil {
		return nil, err
	}
	return jumpserver.NewClient(jumpserver.ClientOptions{
		Origin:    s.Config.Origin,
		Username:  s.Config.Data.JumpServerUser,
		KeyID:     keyID,
		Secret:    secret,
		OrgID:     s.Config.Data.OrgID,
		CAFile:    s.Config.Data.CAFile,
		ProxyURL:  s.Config.Data.ProxyURL,
		Transport: s.HTTPTransport,
	})
}

type preparedCred struct {
	secret          string
	secretType      string // "password" 或 "ssh_key"
	freshlyPrompted bool
	fromSavedStore  bool
}

func (s *Service) resolveTargetCredential(
	ctx context.Context,
	rt config.ResolvedTarget,
	assetID string,
	isManaged bool,
	interactive bool,
	overridePassword string,
) (*preparedCred, error) {
	if isManaged {
		return &preparedCred{}, nil
	}
	if overridePassword != "" {
		return &preparedCred{
			secret:          overridePassword,
			secretType:      "password",
			freshlyPrompted: true,
		}, nil
	}

	credCfg := rt.Entry.Credential
	switch credCfg.Type {
	case "gopass":
		pw, err := credentials.ReadGopassPassword(ctx, credCfg.Ref)
		if err != nil {
			return nil, err
		}
		return &preparedCred{secret: pw, secretType: "password"}, nil

	case "ssh_key":
		var keyPath string
		if strings.TrimSpace(credCfg.Path) != "" {
			keyPath = s.Config.LocalPath(credCfg.Path)
		}
		var pass string
		var hasPass bool
		if strings.TrimSpace(credCfg.PassphraseGopassRef) != "" {
			pw, err := credentials.ReadGopassPassword(ctx, credCfg.PassphraseGopassRef)
			if err != nil {
				return nil, err
			}
			pass, hasPass = pw, true
		} else if credCfg.PassphraseStored && s.Store != nil {
			pw, err := s.Store.Get(ctx, s.ServiceKey(), credentials.KeyPassphraseEntry(rt.Canonical), interactive)
			if err != nil && !errors.Is(err, credentials.ErrNotFound) {
				return nil, err
			}
			if err == nil && pw != "" {
				pass, hasPass = pw, true
			}
		}
		pemKey, err := credentials.LoadTargetSSHPrivateKey(
			keyPath,
			credCfg.SubmitToJumpServer,
			pass,
			hasPass,
			interactive,
			s.PromptPass,
		)
		if err != nil {
			return nil, err
		}
		return &preparedCred{secret: pemKey, secretType: "ssh_key"}, nil

	case "store", "keyring", "file":
		if s.Store == nil {
			return nil, errs.Action("KEYRING_UNAVAILABLE", "未配置可用的凭据存储。", "请运行 js init")
		}
		primaryKey := credentials.TargetEntry(assetID, rt.Username, rt.Canonical)
		fallbackKey := credentials.TargetFallbackEntry(rt.Canonical)

		for _, key := range []string{primaryKey, fallbackKey} {
			if key == "" {
				continue
			}
			val, err := s.Store.Get(ctx, s.ServiceKey(), key, interactive)
			if err == nil && val != "" {
				return &preparedCred{
					secret:         val,
					secretType:     "password",
					fromSavedStore: true,
				}, nil
			}
			if err != nil && !errors.Is(err, credentials.ErrNotFound) {
				return nil, err
			}
		}
		if !interactive {
			return nil, errs.Action(
				"LOCAL_INPUT_REQUIRED",
				fmt.Sprintf("尚未找到 %s 的已保存密码。", rt.Canonical),
				fmt.Sprintf("请先在终端运行 js passwd %s", rt.Canonical),
			)
		}
		return s.promptTargetPassword(rt.Canonical)

	case "prompt", "":
		if !interactive {
			return nil, errs.Action(
				"LOCAL_INPUT_REQUIRED",
				fmt.Sprintf("目标 %s 需要本机输入密码后才能供自动化或 Agent 使用。", rt.Canonical),
				fmt.Sprintf("请先在终端连接一次 js %s 或运行 js passwd %s", rt.Canonical, rt.Canonical),
			)
		}
		return s.promptTargetPassword(rt.Canonical)

	case "managed":
		return nil, errs.New("ACCOUNT_PERMISSION", "该资产未匹配到可用的托管账号。")

	default:
		return nil, errs.New("CREDENTIAL_TYPE", "不支持的目标凭据类型："+credCfg.Type)
	}
}

func (s *Service) promptTargetPassword(canonical string) (*preparedCred, error) {
	if s.PromptPass == nil {
		return nil, errs.Action("LOCAL_INPUT_REQUIRED", "当前环境不支持交互输入密码。", "请在终端直接运行 js")
	}
	pw, err := s.PromptPass(fmt.Sprintf("%s 的密码：", canonical))
	if err != nil {
		return nil, err
	}
	if pw == "" {
		return nil, errs.New("EMPTY_SECRET", "目标密码不能为空。")
	}
	return &preparedCred{
		secret:          pw,
		secretType:      "password",
		freshlyPrompted: true,
	}, nil
}

func (s *Service) maybeSaveTargetPassword(
	ctx context.Context,
	rt config.ResolvedTarget,
	asset jumpserver.AssetDetail,
	password string,
	interactive bool,
) {
	if password == "" || s.Store == nil {
		return
	}
	policy := s.Config.Data.SavePasswordPolicy
	if policy == "never" {
		return
	}
	if policy == "ask" {
		if !interactive || s.PromptText == nil {
			return
		}
		ans, err := s.PromptText("是否保存该服务器密码供下次免输入登录？[Y/n]：")
		if err != nil {
			return
		}
		ans = strings.ToLower(strings.TrimSpace(ans))
		if ans == "n" || ans == "no" {
			return
		}
	}

	entryKey := credentials.TargetEntry(asset.ID, rt.Username, rt.Canonical)
	if err := s.Store.Set(ctx, s.ServiceKey(), entryKey, password, interactive); err != nil {
		if s.Stderr != nil {
			_, _ = fmt.Fprintf(s.Stderr, "! 登录成功，但保存密码到凭据存储失败：%v\n", err)
		}
		return
	}
	// 清理可能存在的未解析资产前的 fallback 条目
	fallbackKey := credentials.TargetFallbackEntry(rt.Canonical)
	if fallbackKey != entryKey {
		_ = s.Store.Delete(ctx, s.ServiceKey(), fallbackKey, interactive)
	}

	_ = s.Config.Update(true, func(d *config.Data) error {
		if d.Targets == nil {
			d.Targets = map[string]config.TargetConfig{}
		}
		tc := d.Targets[rt.Canonical]
		tc.AssetID = asset.ID
		tc.AssetName = asset.Name
		tc.Credential = config.CredentialConfig{Type: "store"}
		d.Targets[rt.Canonical] = tc
		return nil
	})
	_ = s.Config.Update(false, func(d *config.Data) error {
		s.Config.RecordStoredCredential(entryKey)
		s.Config.RemoveStoredCredential(fallbackKey)
		d.StoredCredentials = s.Config.Data.StoredCredentials
		return nil
	})

	if s.Stderr != nil {
		storeLabel := "系统凭据库"
		if s.Store.Name() == "file" {
			storeLabel = "0600 凭据文件"
		}
		_, _ = fmt.Fprintf(s.Stderr, "✓ 已登录，密码已保存到%s，下次无需输入\n", storeLabel)
	}
}

func (s *Service) cacheResolvedAsset(canonical string, asset jumpserver.AssetDetail) {
	cur, ok := s.Config.Data.Targets[canonical]
	if ok && cur.AssetID == asset.ID && cur.AssetName == asset.Name {
		return
	}
	_ = s.Config.Update(false, func(d *config.Data) error {
		if d.Targets == nil {
			d.Targets = map[string]config.TargetConfig{}
		}
		tc, exists := d.Targets[canonical]
		if !exists {
			tc = config.TargetConfig{
				Credential: config.CredentialConfig{Type: "prompt"},
			}
		}
		tc.AssetID = asset.ID
		tc.AssetName = asset.Name
		d.Targets[canonical] = tc
		return nil
	})
}

type OpenedSession struct {
	Conn            *transport.Connection
	ResolvedTarget  config.ResolvedTarget
	ResolvedAsset   *jumpserver.ResolvedAsset
	Timings         StageTimings
	freshPassword   string
	fromSavedStore  bool
}

// OpenConnection 执行完整安全连接流水线：
// 1. KoKo 主机密钥验证（失败时绝不读取 AK 或目标凭据）
// 2. 本人 API 身份与资产授权解析（优先命中本地 asset_id 缓存）
// 3. 读取或终端提示目标凭据
// 4. 创建一次性普通连接令牌并登录 KoKo
func (s *Service) OpenConnection(
	ctx context.Context,
	targetInput string,
	protocol string,
	interactive bool,
	overridePassword string,
) (*OpenedSession, error) {
	return s.OpenConnectionWithAction(ctx, targetInput, protocol, "", interactive, overridePassword)
}

func (s *Service) OpenConnectionWithAction(
	ctx context.Context,
	targetInput string,
	protocol string,
	requiredAction string,
	interactive bool,
	overridePassword string,
) (*OpenedSession, error) {
	totalStart := time.Now()

	rt, candidates, err := s.Config.ResolveTarget(targetInput)
	if err != nil {
		if len(candidates) > 1 && interactive && s.PromptText != nil {
			chosen, pickErr := s.pickCandidateTarget(candidates)
			if pickErr != nil {
				return nil, pickErr
			}
			rt, _, err = s.Config.ResolveTarget(chosen)
		}
		if err != nil {
			return nil, err
		}
	}

	if protocol != "ssh" && protocol != "sftp" {
		return nil, errs.New("PROTOCOL", "只支持 ssh 与 sftp 协议。")
	}

	var khPaths []string
	khList := s.Config.Data.KnownHostsFiles
	if len(khList) == 0 && strings.TrimSpace(s.Config.Data.KoKoHostFingerprint) == "" {
		khList = []string{"~/.ssh/known_hosts"}
	}
	for _, p := range khList {
		khPaths = append(khPaths, s.Config.LocalPath(p))
	}
	hostKeyCb, err := transport.BuildHostKeyCallback(s.Config.Data.KoKoHostFingerprint, khPaths)
	if err != nil {
		return nil, err
	}

	var timings StageTimings

	// 第 1 步：验证 KoKo 主机身份（必须在读取任何秘密或请求令牌之前通过）
	t0 := time.Now()
	if err := transport.VerifyHostPrecheck(ctx, s.Config.Data.KoKoHost, s.Config.Data.KoKoPort, hostKeyCb); err != nil {
		return nil, err
	}
	timings.HostVerifyMs = time.Since(t0).Milliseconds()

	// 第 2 步：加载本机 AK 并查询本人资产授权
	t1 := time.Now()
	api, err := s.NewCoreClient(ctx, interactive)
	if err != nil {
		return nil, err
	}
	defer api.Close()

	allowAutoManaged := rt.Entry.Credential.Type == "" || rt.Entry.Credential.Type == "prompt" || rt.Entry.Credential.Type == "managed"
	resolvedAsset, err := api.ResolveAsset(ctx, jumpserver.ResolveAssetRequest{
		Address:        rt.Address,
		CachedAssetID:  rt.Entry.AssetID,
		Protocol:       protocol,
		Username:       rt.Username,
		ManagedAccount: rt.Entry.Credential.ManagedAccount,
		AllowManaged:   allowAutoManaged,
		RequiredAction: requiredAction,
	})
	if err != nil {
		return nil, err
	}
	timings.AssetResolveMs = time.Since(t1).Milliseconds()
	timings.AssetCacheHit = resolvedAsset.CacheHit
	s.cacheResolvedAsset(rt.Canonical, resolvedAsset.Asset)

	// 第 3 步：读取或输入目标凭据
	t2 := time.Now()
	cred, err := s.resolveTargetCredential(ctx, rt, resolvedAsset.Asset.ID, resolvedAsset.IsManaged, interactive, overridePassword)
	if err != nil {
		return nil, err
	}
	timings.CredentialReadMs = time.Since(t2).Milliseconds()

	// 第 4 步：申请一次性普通连接令牌
	t3 := time.Now()
	tok, err := api.CreateConnectionToken(ctx, jumpserver.TokenRequest{
		AssetID:         resolvedAsset.Asset.ID,
		AccountAlias:    resolvedAsset.AccountAlias,
		InputUsername:   rt.Username,
		InputSecret:     cred.secret,
		InputSecretType: cred.secretType,
		Protocol:        protocol,
	})
	freshPw := ""
	if cred.freshlyPrompted && cred.secretType == "password" {
		freshPw = cred.secret
	}
	cred.secret = ""
	if err != nil {
		return nil, err
	}
	timings.TokenCreateMs = time.Since(t3).Milliseconds()

	// 第 5 步：用 JMS-<token.ID> 登录 KoKo，并再次强制校验主机密钥
	t4 := time.Now()
	conn, err := transport.DialKoKo(ctx, s.Config.Data.KoKoHost, s.Config.Data.KoKoPort, hostKeyCb, tok.ID, tok.Value)
	tok.Value = ""
	if err != nil {
		return nil, err
	}
	timings.KoKoAuthMs = time.Since(t4).Milliseconds()
	timings.TotalMs = time.Since(totalStart).Milliseconds()

	conn.Target = rt.Canonical
	conn.AssetID = resolvedAsset.Asset.ID
	conn.FileRoots = rt.Entry.FileRoots

	return &OpenedSession{
		Conn:           conn,
		ResolvedTarget: rt,
		ResolvedAsset:  resolvedAsset,
		Timings:        timings,
		freshPassword:  freshPw,
		fromSavedStore: cred.fromSavedStore,
	}, nil
}

func (s *Service) pickCandidateTarget(candidates []string) (string, error) {
	if s.Stderr != nil {
		_, _ = fmt.Fprintln(s.Stderr, "该 IP 有多个已配置账号，请选择：")
		for i, c := range candidates {
			_, _ = fmt.Fprintf(s.Stderr, "  [%d] %s\n", i+1, c)
		}
	}
	ans, err := s.PromptText(fmt.Sprintf("输入序号 [1-%d]：", len(candidates)))
	if err != nil {
		return "", err
	}
	var idx int
	if _, scanErr := fmt.Sscanf(ans, "%d", &idx); scanErr != nil || idx < 1 || idx > len(candidates) {
		return "", errs.New("TARGET_USER", "未选择有效序号，已取消。")
	}
	return candidates[idx-1], nil
}

// ConnectInteractive 打开交互终端；实现“目标登录成功后才保存密码”，并在密码错误或失效时允许重新输入一次（不循环重试）。
func (s *Service) ConnectInteractive(ctx context.Context, targetInput string) error {
	sess, err := s.OpenConnection(ctx, targetInput, "ssh", true, "")
	if err != nil {
		return err
	}

	err = sess.Conn.RunInteractiveShell(ctx, func() {
		if sess.freshPassword != "" {
			pw := sess.freshPassword
			sess.freshPassword = ""
			s.maybeSaveTargetPassword(ctx, sess.ResolvedTarget, sess.ResolvedAsset.Asset, pw, true)
		}
	})
	sess.Conn.Close()
	if err == nil {
		return nil
	}

	be, ok := errs.As(err)
	if !ok || be.Code != "TARGET_AUTH_FAILED" {
		return err
	}
	// 仅在密码来源（首次输入或已保存的密码失效）时允许重新输入一次，绝不循环重试
	if sess.freshPassword == "" && !sess.fromSavedStore {
		return err
	}
	if s.Stderr != nil {
		_, _ = fmt.Fprintf(s.Stderr, "✗ %s 密码被目标服务器拒绝（未保存错误密码），请重新输入一次：\n", sess.ResolvedTarget.Canonical)
	}
	retryCred, promptErr := s.promptTargetPassword(sess.ResolvedTarget.Canonical)
	if promptErr != nil {
		return promptErr
	}

	sess2, err2 := s.OpenConnection(ctx, sess.ResolvedTarget.Canonical, "ssh", true, retryCred.secret)
	retryCred.secret = ""
	if err2 != nil {
		return err2
	}
	defer sess2.Conn.Close()

	return sess2.Conn.RunInteractiveShell(ctx, func() {
		if sess2.freshPassword != "" {
			pw := sess2.freshPassword
			sess2.freshPassword = ""
			s.maybeSaveTargetPassword(ctx, sess2.ResolvedTarget, sess2.ResolvedAsset.Asset, pw, true)
		}
	})
}

// ExecuteCommand 执行单条远端命令；在交互终端首次输入密码且执行成功时自动保存，错误时不保存。
func (s *Service) ExecuteCommand(
	ctx context.Context,
	targetInput string,
	command string,
	timeout time.Duration,
	cwd string,
	interactive bool,
) (*transport.ExecResult, *StageTimings, error) {
	sess, err := s.OpenConnection(ctx, targetInput, "ssh", interactive, "")
	if err != nil {
		return nil, nil, err
	}
	defer sess.Conn.Close()

	res, execErr := sess.Conn.Execute(ctx, command, timeout, cwd, transport.DefaultOutputLimit)
	if execErr != nil {
		return nil, &sess.Timings, execErr
	}

	if res.Status == "target_auth_failed" {
		// 人工终端下若首次输错或旧密码失效，允许重输一次；非交互直接返回明确修复提示
		if interactive && (sess.freshPassword != "" || sess.fromSavedStore) {
			if s.Stderr != nil {
				_, _ = fmt.Fprintf(s.Stderr, "✗ %s 密码被目标服务器拒绝（未保存），请重新输入一次：\n", sess.ResolvedTarget.Canonical)
			}
			retryCred, promptErr := s.promptTargetPassword(sess.ResolvedTarget.Canonical)
			if promptErr != nil {
				return res, &sess.Timings, nil
			}
			sess2, err2 := s.OpenConnection(ctx, sess.ResolvedTarget.Canonical, "ssh", true, retryCred.secret)
			retryCred.secret = ""
			if err2 != nil {
				return nil, nil, err2
			}
			defer sess2.Conn.Close()

			res2, execErr2 := sess2.Conn.Execute(ctx, command, timeout, cwd, transport.DefaultOutputLimit)
			if execErr2 != nil {
				return nil, &sess2.Timings, execErr2
			}
			if res2.Status != "target_auth_failed" && sess2.freshPassword != "" {
				s.maybeSaveTargetPassword(ctx, sess2.ResolvedTarget, sess2.ResolvedAsset.Asset, sess2.freshPassword, true)
			}
			return res2, &sess2.Timings, nil
		}
		return res, &sess.Timings, nil
	}

	if sess.freshPassword != "" {
		s.maybeSaveTargetPassword(ctx, sess.ResolvedTarget, sess.ResolvedAsset.Asset, sess.freshPassword, interactive)
	}
	return res, &sess.Timings, nil
}

// StreamCommand 打开连接并以透传方式运行远端命令（供 js rsh / rsync -e 使用）。
// 非交互：不提示输入，凭据必须已保存；所有诊断信息只写 stderr，stdout 保持协议纯净。
func (s *Service) StreamCommand(ctx context.Context, targetInput, command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	sess, err := s.OpenConnection(ctx, targetInput, "ssh", false, "")
	if err != nil {
		return 125, err
	}
	defer sess.Conn.Close()
	return sess.Conn.ExecStream(ctx, command, stdin, stdout, stderr)
}
