package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"jsbridge/internal/errs"
)

const DefaultOutputLimit = 1024 * 1024 // 1 MiB

type Connection struct {
	Client    *ssh.Client
	Target    string
	AssetID   string
	FileRoots []string

	closeOnce sync.Once
	closed    atomic.Bool
	done      chan struct{}
}

type ExecResult struct {
	Status                   string  `json:"status"`
	Stdout                   string  `json:"stdout"`
	Stderr                   string  `json:"stderr"`
	ExitCode                 *int    `json:"exit_code"`
	StdoutStderrMerged       bool    `json:"stdout_stderr_merged"`
	ExitStatusSource         string  `json:"exit_status_source"`
	TargetExecutionVerified  bool    `json:"target_execution_verified"`
	DurationSeconds          float64 `json:"duration_seconds"`
	DurationMs               int64   `json:"duration_ms"`
	Truncated                bool    `json:"truncated"`
	RemoteProcessMayStillRun bool    `json:"remote_process_may_still_run,omitempty"`
}

func DialKoKo(
	ctx context.Context,
	host string,
	port int,
	hostKeyCb ssh.HostKeyCallback,
	tokenID, tokenValue string,
) (*Connection, error) {
	if hostKeyCb == nil {
		return nil, errs.New("HOST_KEY_UNKNOWN", "缺少主机密钥校验器。")
	}
	if strings.TrimSpace(tokenID) == "" || tokenValue == "" {
		return nil, errs.New("SSH_AUTH", "连接令牌为空。")
	}

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, errs.New("SSH_HANDSHAKE", "KoKo 网络连接失败。")
	}

	deadline := time.Now().Add(15 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = rawConn.SetDeadline(deadline)

	sshCfg := &ssh.ClientConfig{
		User: "JMS-" + strings.TrimSpace(tokenID),
		// 仅使用单次密码令牌认证，不退回 keyboard-interactive 或本机私钥
		Auth:            []ssh.AuthMethod{ssh.Password(tokenValue)},
		HostKeyCallback: hostKeyCb,
		Timeout:         15 * time.Second,
	}

	c, chans, reqs, err := ssh.NewClientConn(rawConn, addr, sshCfg)
	if err != nil {
		_ = rawConn.Close()
		if be, ok := errs.As(err); ok {
			return nil, be
		}
		return nil, errs.New("SSH_AUTH", "KoKo 令牌认证失败；停止连接且不自动重试。")
	}
	// 握手与认证完成后清除底层套接字固定截止时间
	_ = rawConn.SetDeadline(time.Time{})

	client := ssh.NewClient(c, chans, reqs)
	conn := &Connection{
		Client: client,
		done:   make(chan struct{}),
	}
	go conn.keepAliveLoop(30 * time.Second)
	return conn, nil
}

func (c *Connection) keepAliveLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			if c.IsClosed() || c.Client == nil {
				return
			}
			_, _, err := c.Client.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				c.Close()
				return
			}
		}
	}
}

func (c *Connection) IsClosed() bool {
	return c.closed.Load()
}

func (c *Connection) Close() {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		if c.done != nil {
			close(c.done)
		}
		if c.Client != nil {
			_ = c.Client.Close()
		}
	})
}

func IsKoKoTargetAuthFailure(output string) bool {
	return strings.Contains(output, "ssh: unable to authenticate") ||
		strings.Contains(output, "error: Authentication failed") ||
		strings.Contains(output, "错误: 认证失败") ||
		strings.Contains(output, "Authentication failed (username or password incorrect)")
}

func shellQuotePOSIX(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (c *Connection) Execute(
	ctx context.Context,
	command string,
	timeout time.Duration,
	cwd string,
	maxBytes int,
) (*ExecResult, error) {
	if command == "" || len(command) > 32768 || strings.ContainsRune(command, '\x00') {
		return nil, errs.New("COMMAND", "命令为空、超过 32 KiB 或包含 NUL 字符。")
	}
	if timeout <= 0 || timeout > time.Hour {
		return nil, errs.New("TIMEOUT", "timeout 必须在 (0, 3600s] 范围内。")
	}
	if cwd != "" {
		if !strings.HasPrefix(cwd, "/") || strings.ContainsRune(cwd, '\x00') {
			return nil, errs.New("CWD", "cwd 必须是不含 NUL 的绝对路径。")
		}
		command = "cd -- " + shellQuotePOSIX(cwd) + " && " + command
	}
	if maxBytes <= 0 {
		maxBytes = DefaultOutputLimit
	}
	if c.IsClosed() || c.Client == nil {
		return &ExecResult{
			Status:                   "disconnected",
			ExitStatusSource:         "koko",
			TargetExecutionVerified:  false,
			RemoteProcessMayStillRun: true,
		}, nil
	}

	started := time.Now()
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var timedOut atomic.Bool
	var limitExceeded atomic.Bool
	finished := make(chan struct{})

	// 监控总期限：涵盖打开通道、exec 确认、流读取和退出状态等待；一旦超时立即关闭整个 SSH 传输唤醒阻塞调用
	go func() {
		select {
		case <-finished:
			return
		case <-execCtx.Done():
			timedOut.Store(true)
			c.Close()
		}
	}()

	sess, err := c.Client.NewSession()
	if err != nil {
		close(finished)
		state := "transport_error"
		if timedOut.Load() || time.Since(started) >= timeout {
			state = "timeout"
		}
		c.Close()
		dur := time.Since(started)
		return &ExecResult{
			Status:                   state,
			ExitStatusSource:         "koko",
			TargetExecutionVerified:  false,
			DurationSeconds:          math.Round(dur.Seconds()*1000) / 1000,
			DurationMs:               dur.Milliseconds(),
			RemoteProcessMayStillRun: true,
		}, nil
	}
	defer sess.Close()

	stdoutPipe, err := sess.StdoutPipe()
	if err != nil {
		close(finished)
		c.Close()
		return nil, errs.New("SSH_CHANNEL", "无法打开远端标准输出流。")
	}
	stderrPipe, err := sess.StderrPipe()
	if err != nil {
		close(finished)
		c.Close()
		return nil, errs.New("SSH_CHANNEL", "无法打开远端标准错误流。")
	}

	if err := sess.Start(command); err != nil {
		close(finished)
		state := "transport_error"
		if timedOut.Load() || time.Since(started) >= timeout {
			state = "timeout"
		}
		c.Close()
		dur := time.Since(started)
		return &ExecResult{
			Status:                   state,
			ExitStatusSource:         "koko",
			TargetExecutionVerified:  false,
			DurationSeconds:          math.Round(dur.Seconds()*1000) / 1000,
			DurationMs:               dur.Milliseconds(),
			RemoteProcessMayStillRun: true,
		}, nil
	}

	var bufMu sync.Mutex
	var outBuf, errBuf bytes.Buffer
	totalRead := 0

	readStream := func(r io.Reader, dst *bytes.Buffer) {
		chunk := make([]byte, 32*1024)
		for {
			n, rErr := r.Read(chunk)
			if n > 0 {
				bufMu.Lock()
				remaining := maxBytes - totalRead
				totalRead += n
				if remaining > 0 {
					take := n
					if take > remaining {
						take = remaining
					}
					dst.Write(chunk[:take])
				}
				over := totalRead > maxBytes
				bufMu.Unlock()
				if over {
					limitExceeded.Store(true)
					c.Close()
					return
				}
			}
			if rErr != nil {
				return
			}
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		readStream(stdoutPipe, &outBuf)
	}()
	go func() {
		defer wg.Done()
		readStream(stderrPipe, &errBuf)
	}()

	wg.Wait()
	waitErr := sess.Wait()
	close(finished)

	state := "ssh_completed"
	var exitCode *int

	switch {
	case limitExceeded.Load():
		state = "output_limit"
		c.Close()
	case timedOut.Load() || time.Since(started) >= timeout:
		state = "timeout"
		c.Close()
	case waitErr == nil:
		zero := 0
		exitCode = &zero
	default:
		var exitErr *ssh.ExitError
		var missingErr *ssh.ExitMissingError
		if errors.As(waitErr, &exitErr) {
			code := exitErr.ExitStatus()
			exitCode = &code
		} else if errors.As(waitErr, &missingErr) {
			state = "exit_status_unknown"
		} else {
			if c.IsClosed() {
				state = "disconnected"
			} else {
				state = "transport_error"
				c.Close()
			}
		}
	}

	stdoutStr := strings.ToValidUTF8(outBuf.String(), "\uFFFD")
	stderrStr := strings.ToValidUTF8(errBuf.String(), "\uFFFD")
	combined := stdoutStr + stderrStr

	// KoKo 的前置拒绝或目标认证失败分支可能正常发送 exit-status 0，必须显式识别并隔离连接
	if strings.Contains(combined, "SSH Command not support ACL review ticket") {
		state = "approval_required"
	}
	if IsKoKoTargetAuthFailure(combined) {
		state = "target_auth_failed"
		c.Close()
	}

	dur := time.Since(started)
	res := &ExecResult{
		Status:                  state,
		Stdout:                  stdoutStr,
		Stderr:                  stderrStr,
		ExitCode:                exitCode,
		StdoutStderrMerged:      false,
		ExitStatusSource:        "koko",
		TargetExecutionVerified: false,
		DurationSeconds:         math.Round(dur.Seconds()*1000) / 1000,
		DurationMs:              dur.Milliseconds(),
		Truncated:               limitExceeded.Load(),
	}
	if state != "ssh_completed" {
		res.RemoteProcessMayStillRun = true
	}
	return res, nil
}

// ExecStream 在不分配 PTY 的 exec 通道上运行命令，并把 stdin/stdout/stderr 原样透传，
// 用于 rsync -e 这类需要二进制安全管道的场景。返回远端退出码。
func (c *Connection) ExecStream(ctx context.Context, command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if command == "" || strings.ContainsRune(command, '\x00') {
		return 125, errs.New("COMMAND", "命令为空或包含 NUL 字符。")
	}
	if c.IsClosed() || c.Client == nil {
		return 125, errs.New("DISCONNECTED", "连接已断开。")
	}
	sess, err := c.Client.NewSession()
	if err != nil {
		return 125, errs.New("SSH_CHANNEL", "无法打开 SSH exec 通道。")
	}
	defer sess.Close()
	sess.Stdout = stdout
	sess.Stderr = stderr
	w, err := sess.StdinPipe()
	if err != nil {
		return 125, errs.New("SSH_CHANNEL", "无法打开远端标准输入流。")
	}
	if err := sess.Start(command); err != nil {
		return 125, errs.New("SSH_CHANNEL", "远端命令启动失败。")
	}
	go func() {
		_, _ = io.Copy(w, stdin)
		_ = w.Close() // 向远端发送 EOF（half-close）
	}()
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case <-ctx.Done():
		c.Close()
		return 130, ctx.Err()
	case waitErr := <-done:
		if waitErr == nil {
			return 0, nil
		}
		var exitErr *ssh.ExitError
		if errors.As(waitErr, &exitErr) {
			return exitErr.ExitStatus(), nil
		}
		return 125, errs.New("SSH_EXEC", "远端命令异常结束，退出码未知。")
	}
}
