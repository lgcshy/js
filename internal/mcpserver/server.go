package mcpserver

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pkg/sftp"

	"github.com/lgcshy/js/internal/app"
	"github.com/lgcshy/js/internal/config"
	"github.com/lgcshy/js/internal/errs"
	"github.com/lgcshy/js/internal/transport"
)

const (
	MaxPooledConnections  = 8
	DefaultIdleTTL        = 15 * time.Minute
	DefaultQueueWait      = 60 * time.Second
	ModelStreamHeadBytes  = 32 * 1024 // 32 KiB
	ModelStreamTailBytes  = 32 * 1024 // 32 KiB
	ModelStreamTotalLimit = ModelStreamHeadBytes + ModelStreamTailBytes
)

type poolKey struct {
	Target   string
	Protocol string // "ssh" or "sftp"
}

type failKey struct {
	Target     string
	Generation int64
}

type pooledConn struct {
	key        poolKey
	generation int64
	session    *app.OpenedSession
	sftpClient *sftp.Client
	rootCtx    *transport.SFTPRootContext
	lastUsed   time.Time
	inUse      bool
}

func (p *pooledConn) close() {
	if p == nil {
		return
	}
	if p.sftpClient != nil {
		_ = p.sftpClient.Close()
	}
	if p.session != nil && p.session.Conn != nil {
		p.session.Conn.Close()
	}
}

func (p *pooledConn) isAlive() bool {
	if p == nil || p.session == nil || p.session.Conn == nil || p.session.Conn.IsClosed() {
		return false
	}
	return true
}

type targetLock struct {
	ch chan struct{}
}

func newTargetLock() *targetLock {
	tl := &targetLock{ch: make(chan struct{}, 1)}
	tl.ch <- struct{}{}
	return tl
}

func (l *targetLock) acquire(ctx context.Context, wait time.Duration) (func(), error) {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-l.ch:
		return func() {
			l.ch <- struct{}{}
		}, nil
	case <-ctx.Done():
		return nil, errs.New("CANCELED", "等待目标连接锁时请求已取消。")
	case <-timer.C:
		return nil, errs.New("SESSION_BUSY", "同一目标服务器的前序操作仍在执行，排队等待超时。")
	}
}

type Manager struct {
	Service        *app.Service
	MaxConns       int
	IdleTTL        time.Duration
	QueueWait      time.Duration
	ModelHeadBytes int
	ModelTailBytes int

	mu             sync.Mutex
	pool           map[poolKey]*pooledConn
	locks          map[poolKey]*targetLock
	failedTargets  map[failKey]string
	lastGeneration int64
}

func NewManager(svc *app.Service) *Manager {
	var gen int64
	if svc != nil && svc.Config != nil {
		gen = svc.Config.Data.Generation
	}
	return &Manager{
		Service:        svc,
		MaxConns:       MaxPooledConnections,
		IdleTTL:        DefaultIdleTTL,
		QueueWait:      DefaultQueueWait,
		ModelHeadBytes: ModelStreamHeadBytes,
		ModelTailBytes: ModelStreamTailBytes,
		pool:           map[poolKey]*pooledConn{},
		locks:          map[poolKey]*targetLock{},
		failedTargets:  map[failKey]string{},
		lastGeneration: gen,
	}
}

func (m *Manager) CloseAll() int {
	m.mu.Lock()
	var toClose []*pooledConn
	for k, pc := range m.pool {
		toClose = append(toClose, pc)
		delete(m.pool, k)
	}
	m.mu.Unlock()

	for _, pc := range toClose {
		pc.close()
	}
	return len(toClose)
}

// syncConfigAndCleanup 在每次工具调用前同步磁盘配置的 generation，并清理闲置超过 15 分钟或已断开的连接。
func (m *Manager) syncConfigAndCleanup() int64 {
	var stale []*pooledConn
	now := time.Now()

	m.mu.Lock()
	if m.Service != nil && m.Service.Config != nil && m.Service.Config.Path != "" {
		if latest, err := config.Load(m.Service.Config.Path); err == nil {
			prevStore := m.Service.Config.Data.CredentialStore
			m.Service.Config.Data = latest.Data
			m.Service.Config.Origin = latest.Origin
			// 仅当未注入自定义内存测试 Store 且存储后端类型变化时切换 Store
			if m.Service.Store != nil && m.Service.Store.Name() != "memory" && prevStore != latest.Data.CredentialStore {
				m.Service.Store = app.StoreForConfig(m.Service.Config)
			}
			if latest.Data.Generation != m.lastGeneration {
				m.lastGeneration = latest.Data.Generation
				// 配置或凭据代次已更新：废弃旧代次的空闲连接，清除旧代次的失败锁定
				for k, pc := range m.pool {
					if !pc.inUse {
						stale = append(stale, pc)
						delete(m.pool, k)
					}
				}
				for fk := range m.failedTargets {
					if fk.Generation != m.lastGeneration {
						delete(m.failedTargets, fk)
					}
				}
			}
		}
	}

	idleTTL := m.IdleTTL
	if idleTTL <= 0 {
		idleTTL = DefaultIdleTTL
	}
	for k, pc := range m.pool {
		if !pc.inUse && (!pc.isAlive() || now.Sub(pc.lastUsed) > idleTTL) {
			stale = append(stale, pc)
			delete(m.pool, k)
		}
	}
	gen := m.lastGeneration
	m.mu.Unlock()

	for _, pc := range stale {
		pc.close()
	}
	return gen
}

func (m *Manager) getTargetLock(key poolKey) *targetLock {
	m.mu.Lock()
	defer m.mu.Unlock()
	tl, ok := m.locks[key]
	if !ok {
		tl = newTargetLock()
		m.locks[key] = tl
	}
	return tl
}

func (m *Manager) latchFailure(target string, gen int64, code string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failedTargets[failKey{Target: target, Generation: gen}] = code
}

func (m *Manager) checkLatchedFailure(target string, gen int64) error {
	m.mu.Lock()
	code, latched := m.failedTargets[failKey{Target: target, Generation: gen}]
	m.mu.Unlock()
	if !latched {
		return nil
	}
	return errs.Action(
		"AUTH_FAILURE_LATCHED",
		fmt.Sprintf("目标 %s 在当前凭据代次中已发生认证失败 (%s)，已锁定自动重试以防锁号。", target, code),
		fmt.Sprintf("请在本机终端运行 js passwd %s（或 js init）更新凭据后再试", target),
	)
}

func shouldLatchAuthError(code string) bool {
	switch code {
	case "SSH_AUTH", "API_HTTP_401", "API_HTTP_403", "AUTH_FAILED", "TARGET_AUTH_FAILED":
		return true
	default:
		return false
	}
}

func (m *Manager) withPooledConnection(
	ctx context.Context,
	targetInput string,
	protocol string,
	requiredAction string,
	fn func(pc *pooledConn) (map[string]any, error),
) map[string]any {
	gen := m.syncConfigAndCleanup()

	rt, _, err := m.Service.Config.ResolveTarget(targetInput)
	if err != nil {
		return errorToResult(err, targetInput)
	}
	canonical := rt.Canonical
	if lErr := m.checkLatchedFailure(canonical, gen); lErr != nil {
		return errorToResult(lErr, canonical)
	}

	key := poolKey{Target: canonical, Protocol: protocol}
	tl := m.getTargetLock(key)
	waitDur := m.QueueWait
	if waitDur <= 0 {
		waitDur = DefaultQueueWait
	}
	release, err := tl.acquire(ctx, waitDur)
	if err != nil {
		return errorToResult(err, canonical)
	}
	defer release()

	// 获得该 (target, protocol) 的串行锁后再次检查代次与锁定状态
	gen = m.syncConfigAndCleanup()
	if lErr := m.checkLatchedFailure(canonical, gen); lErr != nil {
		return errorToResult(lErr, canonical)
	}

	pc, err := m.acquireOrConnect(ctx, key, requiredAction, gen)
	if err != nil {
		if be, ok := errs.As(err); ok && shouldLatchAuthError(be.Code) {
			m.latchFailure(canonical, gen, be.Code)
		}
		return errorToResult(err, canonical)
	}

	var shouldEvict bool
	defer func() {
		m.mu.Lock()
		pc.inUse = false
		pc.lastUsed = time.Now()
		if shouldEvict || !pc.isAlive() || pc.generation != m.lastGeneration {
			delete(m.pool, key)
			m.mu.Unlock()
			pc.close()
			return
		}
		m.mu.Unlock()
	}()

	out, callErr := fn(pc)
	if callErr != nil {
		if be, ok := errs.As(callErr); ok {
			if shouldLatchAuthError(be.Code) {
				m.latchFailure(canonical, gen, be.Code)
				shouldEvict = true
			}
		} else {
			shouldEvict = true
		}
		return errorToResult(callErr, canonical)
	}
	return out
}

func (m *Manager) acquireOrConnect(
	ctx context.Context,
	key poolKey,
	requiredAction string,
	gen int64,
) (*pooledConn, error) {
	m.mu.Lock()
	if existing, ok := m.pool[key]; ok {
		if existing.isAlive() && existing.generation == gen {
			// 若是 SFTP 连接且本次需要特定动作（如 upload/download），检查已缓存资产账号是否具备该动作权限
			if key.Protocol == "sftp" && requiredAction != "" && existing.session != nil && existing.session.ResolvedAsset != nil {
				acc := existing.session.ResolvedAsset.Account
				if !acc.HasAction(requiredAction) && !acc.HasAction("all") {
					m.mu.Unlock()
					return nil, errs.New("ACTION_PERMISSION", fmt.Sprintf("该资产账号未授权 %s 文件传输动作。", requiredAction))
				}
			}
			existing.inUse = true
			existing.lastUsed = time.Now()
			m.mu.Unlock()
			return existing, nil
		}
		delete(m.pool, key)
		m.mu.Unlock()
		existing.close()
	} else {
		// 检查连接池上限（最多 8 个连接）
		maxConns := m.MaxConns
		if maxConns <= 0 {
			maxConns = MaxPooledConnections
		}
		if len(m.pool) >= maxConns {
			// 尝试淘汰一个最早未使用的空闲连接
			var oldestKey poolKey
			var oldestConn *pooledConn
			for k, cand := range m.pool {
				if !cand.inUse {
					if oldestConn == nil || cand.lastUsed.Before(oldestConn.lastUsed) {
						oldestKey = k
						oldestConn = cand
					}
				}
			}
			if oldestConn == nil {
				m.mu.Unlock()
				return nil, errs.New("SESSION_LIMIT", fmt.Sprintf("已达到并发连接上限 (%d)，所有连接均在使用中。", maxConns))
			}
			delete(m.pool, oldestKey)
			m.mu.Unlock()
			oldestConn.close()
		} else {
			m.mu.Unlock()
		}
	}

	// 建立新连接（非交互模式）
	sess, err := m.Service.OpenConnectionWithAction(ctx, key.Target, key.Protocol, requiredAction, false, "")
	if err != nil {
		return nil, err
	}

	pc := &pooledConn{
		key:        key,
		generation: gen,
		session:    sess,
		lastUsed:   time.Now(),
		inUse:      true,
	}

	if key.Protocol == "sftp" {
		sc, sErr := sess.Conn.OpenSFTP()
		if sErr != nil {
			sess.Conn.Close()
			return nil, sErr
		}
		rootCtx, rErr := transport.DetectSFTPRoot(sc, sess.ResolvedTarget.Username)
		if rErr != nil {
			_ = sc.Close()
			sess.Conn.Close()
			return nil, rErr
		}
		pc.sftpClient = sc
		pc.rootCtx = rootCtx
	}

	m.mu.Lock()
	m.pool[key] = pc
	m.mu.Unlock()
	return pc, nil
}

func errorToResult(err error, target string) map[string]any {
	if be, ok := errs.As(err); ok {
		res := be.Result()
		if be.Code == "TARGET_AUTH_FAILED" {
			res["action_required"] = true
			if target != "" {
				res["hint"] = fmt.Sprintf("请在本机终端运行 js passwd %s 重新输入并保存密码", target)
			}
		}
		return res
	}
	return map[string]any{
		"ok":      false,
		"error":   "OPERATION_FAILED",
		"message": "操作失败，原始异常已隐藏，不自动重试。",
	}
}

// TruncateForModel 限制返回给大模型的单路文本长度（默认头 32 KiB + 尾 32 KiB），保证合法 UTF-8 边界。
func TruncateForModel(s string, headBytes, tailBytes int) (out string, totalBytes int, truncated bool) {
	totalBytes = len(s)
	if headBytes <= 0 {
		headBytes = ModelStreamHeadBytes
	}
	if tailBytes <= 0 {
		tailBytes = ModelStreamTailBytes
	}
	limit := headBytes + tailBytes
	if totalBytes <= limit {
		return s, totalBytes, false
	}

	headEnd := headBytes
	for headEnd > 0 && !utf8.RuneStart(s[headEnd]) {
		headEnd--
	}
	tailStart := totalBytes - tailBytes
	for tailStart < totalBytes && !utf8.RuneStart(s[tailStart]) {
		tailStart++
	}
	omitted := tailStart - headEnd
	if omitted <= 0 {
		return s, totalBytes, false
	}
	marker := fmt.Sprintf("\n...[MCP 模型上下文保护：中间省略 %d 字节，总计 %d 字节]...\n", omitted, totalBytes)
	return s[:headEnd] + marker + s[tailStart:], totalBytes, true
}

// --- MCP 工具入参结构体（严禁包含任何密码、令牌或私钥字段） ---

type ListHostsInput struct{}

type RunCommandInput struct {
	Target  string  `json:"target" jsonschema:"目标服务器（支持 用户@IP、已配置单账号的 IP 或别名）"`
	Command string  `json:"command" jsonschema:"要执行的单条非交互远程命令"`
	Cwd     string  `json:"cwd,omitempty" jsonschema:"可选的远端工作目录绝对路径（如 /var/log）"`
	Timeout float64 `json:"timeout,omitempty" jsonschema:"超时秒数 (0, 3600]，默认 30 秒"`
}

type UploadInput struct {
	LocalPath  string `json:"local_path" jsonschema:"本机源文件或目录路径"`
	Target     string `json:"target" jsonschema:"目标服务器（用户@IP、单账号 IP 或别名）"`
	RemotePath string `json:"remote_path" jsonschema:"远端目标路径（支持 ~/路径、相对家目录路径或平台允许的绝对路径）"`
	Overwrite  bool   `json:"overwrite,omitempty" jsonschema:"若远端文件已存在是否允许覆盖（默认 false）"`
	Recursive  bool   `json:"recursive,omitempty" jsonschema:"若本机源路径是目录是否递归上传（默认 false）"`
}

type DownloadInput struct {
	Target     string `json:"target" jsonschema:"目标服务器（用户@IP、单账号 IP 或别名）"`
	RemotePath string `json:"remote_path" jsonschema:"远端源文件或目录路径"`
	LocalPath  string `json:"local_path" jsonschema:"本机保存目标路径"`
	Overwrite  bool   `json:"overwrite,omitempty" jsonschema:"若本机目标文件已存在是否允许覆盖（默认 false）"`
	Recursive  bool   `json:"recursive,omitempty" jsonschema:"若远端源路径是目录是否递归下载（默认 false）"`
}

type CloseConnectionInput struct {
	Target   string `json:"target,omitempty" jsonschema:"可选目标服务器（用户@IP 或别名）；为空或 * 时关闭所有缓存连接"`
	Protocol string `json:"protocol,omitempty" jsonschema:"可选协议过滤（ssh 或 sftp）；为空时关闭该目标的全部协议连接"`
}

func (m *Manager) HandleListHosts(ctx context.Context) map[string]any {
	gen := m.syncConfigAndCleanup()
	cfg := m.Service.Config

	reverseAliases := map[string][]string{}
	for a, dest := range cfg.Data.Aliases {
		reverseAliases[dest] = append(reverseAliases[dest], a)
	}
	for k := range reverseAliases {
		sort.Strings(reverseAliases[k])
	}

	var keys []string
	for k := range cfg.Data.Targets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	storeReady := false
	if m.Service.Store != nil {
		storeReady = m.Service.Store.Available(ctx, false) == nil
	}

	hosts := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		tc := cfg.Data.Targets[k]
		credType := tc.Credential.Type
		if credType == "" {
			credType = "prompt"
		}
		ready := false
		switch credType {
		case "store", "keyring", "file":
			ready = storeReady
		case "gopass", "managed":
			ready = true
		case "ssh_key":
			ready = tc.Credential.Path != "" && tc.Credential.SubmitToJumpServer
		}
		hosts = append(hosts, map[string]any{
			"target":          k,
			"asset_id":        tc.AssetID,
			"asset_name":      tc.AssetName,
			"credential_type": credType,
			"key_bound":       tc.Credential.Path != "",
			"aliases":         reverseAliases[k],
			"ready_for_agent": ready,
		})
	}

	return map[string]any{
		"ok":               true,
		"credential_store": cfg.Data.CredentialStore,
		"store_ready":      storeReady,
		"generation":       gen,
		"hosts":            hosts,
		"aliases":          cfg.Data.Aliases,
	}
}

func (m *Manager) HandleRunCommand(ctx context.Context, in RunCommandInput) map[string]any {
	timeoutSec := in.Timeout
	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	timeout := time.Duration(timeoutSec * float64(time.Second))

	return m.withPooledConnection(ctx, in.Target, "ssh", "", func(pc *pooledConn) (map[string]any, error) {
		res, err := pc.session.Conn.Execute(ctx, in.Command, timeout, in.Cwd, transport.DefaultOutputLimit)
		if err != nil {
			return nil, err
		}
		if res.Status == "target_auth_failed" {
			return nil, errs.Action(
				"TARGET_AUTH_FAILED",
				fmt.Sprintf("目标服务器 %s 拒绝了已保存的凭据（认证失败）。", pc.key.Target),
				fmt.Sprintf("请在本机终端运行 js passwd %s 更新密码", pc.key.Target),
			)
		}

		stdoutModel, stdoutTotal, outTrunc := TruncateForModel(res.Stdout, m.ModelHeadBytes, m.ModelTailBytes)
		stderrModel, stderrTotal, errTrunc := TruncateForModel(res.Stderr, m.ModelHeadBytes, m.ModelTailBytes)

		out := map[string]any{
			"ok":                        res.Status == "ssh_completed",
			"target":                    pc.key.Target,
			"status":                    res.Status,
			"stdout":                    stdoutModel,
			"stderr":                    stderrModel,
			"stdout_bytes":              stdoutTotal,
			"stderr_bytes":              stderrTotal,
			"exit_code":                 res.ExitCode,
			"stdout_stderr_merged":      res.StdoutStderrMerged,
			"exit_status_source":        res.ExitStatusSource,
			"target_execution_verified": res.TargetExecutionVerified,
			"duration_seconds":          res.DurationSeconds,
			"duration_ms":               res.DurationMs,
			"truncated":                 res.Truncated || outTrunc || errTrunc,
			"transport_truncated":       res.Truncated,
			"model_truncated":           outTrunc || errTrunc,
		}
		if res.RemoteProcessMayStillRun {
			out["remote_process_may_still_run"] = true
		}
		if res.Status == "approval_required" {
			out["action_required"] = true
			out["hint"] = "该命令触发 JumpServer 命令审批策略，请使用已获授权的命令"
		}
		return out, nil
	})
}

func (m *Manager) HandleUpload(ctx context.Context, in UploadInput) map[string]any {
	if strings.TrimSpace(in.LocalPath) == "" || strings.TrimSpace(in.RemotePath) == "" {
		return errorToResult(errs.New("USAGE", "local_path 与 remote_path 不能为空。"), in.Target)
	}
	return m.withPooledConnection(ctx, in.Target, "sftp", "upload", func(pc *pooledConn) (map[string]any, error) {
		res, err := m.Service.UploadOnSession(
			ctx,
			pc.sftpClient,
			pc.rootCtx,
			pc.session.Conn.FileRoots,
			pc.key.Target,
			[]string{in.LocalPath},
			in.RemotePath,
			app.CopyOptions{
				Recursive:   in.Recursive,
				Overwrite:   in.Overwrite,
				Interactive: false,
				Quiet:       true,
			},
		)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"ok":               true,
			"status":           "uploaded",
			"target":           pc.key.Target,
			"files_count":      res.FilesCount,
			"dirs_count":       res.DirsCount,
			"total_bytes":      res.TotalBytes,
			"duration_seconds": res.DurationSeconds,
			"duration_ms":      res.DurationMs,
			"items":            res.Items,
			"skipped_symlinks": res.SkippedSymlinks,
		}, nil
	})
}

func (m *Manager) HandleDownload(ctx context.Context, in DownloadInput) map[string]any {
	if strings.TrimSpace(in.RemotePath) == "" || strings.TrimSpace(in.LocalPath) == "" {
		return errorToResult(errs.New("USAGE", "remote_path 与 local_path 不能为空。"), in.Target)
	}
	return m.withPooledConnection(ctx, in.Target, "sftp", "download", func(pc *pooledConn) (map[string]any, error) {
		res, err := m.Service.DownloadOnSession(
			ctx,
			pc.sftpClient,
			pc.rootCtx,
			pc.session.Conn.FileRoots,
			pc.key.Target,
			[]string{in.RemotePath},
			in.LocalPath,
			app.CopyOptions{
				Recursive:   in.Recursive,
				Overwrite:   in.Overwrite,
				Interactive: false,
				Quiet:       true,
			},
		)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"ok":               true,
			"status":           "downloaded",
			"target":           pc.key.Target,
			"files_count":      res.FilesCount,
			"dirs_count":       res.DirsCount,
			"total_bytes":      res.TotalBytes,
			"duration_seconds": res.DurationSeconds,
			"duration_ms":      res.DurationMs,
			"items":            res.Items,
			"skipped_symlinks": res.SkippedSymlinks,
		}, nil
	})
}

func (m *Manager) HandleCloseConnection(in CloseConnectionInput) map[string]any {
	targetFilter := strings.TrimSpace(in.Target)
	protoFilter := strings.ToLower(strings.TrimSpace(in.Protocol))
	if protoFilter != "" && protoFilter != "ssh" && protoFilter != "sftp" {
		return errorToResult(errs.New("PROTOCOL", "protocol 只支持 ssh 或 sftp。"), targetFilter)
	}

	if targetFilter == "" || targetFilter == "*" || targetFilter == "all" {
		var toClose []*pooledConn
		m.mu.Lock()
		for k, pc := range m.pool {
			if protoFilter == "" || k.Protocol == protoFilter {
				toClose = append(toClose, pc)
				delete(m.pool, k)
			}
		}
		m.mu.Unlock()
		for _, pc := range toClose {
			pc.close()
		}
		return map[string]any{
			"ok":           true,
			"status":       "closed",
			"closed_count": len(toClose),
		}
	}

	canonical := targetFilter
	if rt, _, err := m.Service.Config.ResolveTarget(targetFilter); err == nil {
		canonical = rt.Canonical
	}

	var toClose []*pooledConn
	m.mu.Lock()
	for k, pc := range m.pool {
		if k.Target == canonical && (protoFilter == "" || k.Protocol == protoFilter) {
			toClose = append(toClose, pc)
			delete(m.pool, k)
		}
	}
	m.mu.Unlock()

	for _, pc := range toClose {
		pc.close()
	}
	status := "closed"
	if len(toClose) == 0 {
		status = "already_closed"
	}
	return map[string]any{
		"ok":           true,
		"status":       status,
		"target":       canonical,
		"closed_count": len(toClose),
	}
}

func NewServer(svc *app.Service, version string) (*mcp.Server, *Manager) {
	if version == "" {
		version = "0.2.0"
	}
	mgr := NewManager(svc)

	// 诊断日志静默，确保不向 stdio 泄漏任何内部状态或异常正文
	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))

	srv := mcp.NewServer(
		&mcp.Implementation{
			Name:    "jumpserver-js",
			Version: version,
		},
		&mcp.ServerOptions{
			Instructions: "所有连接均经由 JumpServer 审计并复用本机已保存的本人凭据。严禁在任何工具参数中传入密码、令牌或私钥。run_command 自动建连并复用连接，每次调用为独立命令（cwd 需显式指定）；超时或断线不自动重放。遇到 action_required=true 时请提示用户在终端执行 hint 给出的命令。",
			Logger:       discardLogger,
			Capabilities: &mcp.ServerCapabilities{
				Tools: &mcp.ToolCapabilities{},
			},
		},
	)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_hosts",
		Description: "列出本地已配置或已缓存的目标服务器、别名及凭据就绪状态；不读取秘密，不发起远程连接。",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ ListHostsInput) (*mcp.CallToolResult, any, error) {
		return nil, mgr.HandleListHosts(ctx), nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "run_command",
		Description: "在目标服务器上执行单条非交互命令并分别返回 stdout/stderr；内部自动建立并复用 SSH 连接（无需管理会话 ID）。每次调用是独立命令，cwd 需显式指定；超时或断线立即关闭连接且不自动重放。",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in RunCommandInput) (*mcp.CallToolResult, any, error) {
		return nil, mgr.HandleRunCommand(ctx, in), nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "upload",
		Description: "经 JumpServer SFTP 将本机文件或目录上传到目标服务器（先写 .js-partial 再改名；默认不覆盖已有文件，失败不自动重试）。",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in UploadInput) (*mcp.CallToolResult, any, error) {
		return nil, mgr.HandleUpload(ctx, in), nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "download",
		Description: "经 JumpServer SFTP 将目标服务器上的文件或目录下载到本机（先写 .js-partial 再改名；默认不覆盖已有文件，失败不自动重试）。",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in DownloadInput) (*mcp.CallToolResult, any, error) {
		return nil, mgr.HandleDownload(ctx, in), nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "close_connection",
		Description: "主动关闭 MCP 缓存的目标连接（不指定 target 时关闭全部缓存连接；关闭连接不保证远端已启动的进程必然终止）。",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in CloseConnectionInput) (*mcp.CallToolResult, any, error) {
		return nil, mgr.HandleCloseConnection(in), nil
	})

	return srv, mgr
}

// ServeStdio 启动 stdio MCP 服务，在连接结束或进程退出时关闭全部缓存的 SSH/SFTP 会话。
func ServeStdio(ctx context.Context, svc *app.Service, version string) error {
	// MCP 模式下禁止向 stderr 输出交互提示
	svc.Stderr = io.Discard
	srv, mgr := NewServer(svc, version)
	defer mgr.CloseAll()

	t := &mcp.StdioTransport{
		MaxLineLength: 4 * 1024 * 1024, // 限制单帧 JSON-RPC 输入上限为 4 MiB
	}
	return srv.Run(ctx, t)
}
