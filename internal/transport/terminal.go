package transport

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"jsbridge/internal/errs"
)

// RunInteractiveShell 启动远端 PTY + Shell。
// onTargetConnected 在确认 KoKo 已成功连上目标服务器（而非目标认证失败立即断开）后调用一次，用于实现“登录成功后才保存密码”。
func (c *Connection) RunInteractiveShell(ctx context.Context, onTargetConnected func()) error {
	stdinFd := int(os.Stdin.Fd())
	stdoutFd := int(os.Stdout.Fd())
	if !term.IsTerminal(stdinFd) || !term.IsTerminal(stdoutFd) {
		return errs.New("LOCAL_TERMINAL", "交互连接需要真实终端（TTY）；脚本或 Agent 请使用 js 用户@IP 命令 或 js mcp。")
	}

	sess, err := c.Client.NewSession()
	if err != nil {
		return errs.New("SSH_CHANNEL", "无法打开远端交互会话。")
	}
	defer sess.Close()

	width, height, err := term.GetSize(stdoutFd)
	if err != nil || width <= 0 || height <= 0 {
		width, height = 80, 24
	}
	termType := os.Getenv("TERM")
	if strings.TrimSpace(termType) == "" {
		termType = "xterm-256color"
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := sess.RequestPty(termType, height, width, modes); err != nil {
		return errs.New("SSH_PTY", "请求远端 PTY 失败。")
	}

	remoteIn, err := sess.StdinPipe()
	if err != nil {
		return errs.New("SSH_CHANNEL", "无法打开远端输入通道。")
	}
	remoteOut, err := sess.StdoutPipe()
	if err != nil {
		return errs.New("SSH_CHANNEL", "无法打开远端输出通道。")
	}
	remoteErr, err := sess.StderrPipe()
	if err != nil {
		return errs.New("SSH_CHANNEL", "无法打开远端错误输出通道。")
	}

	if err := sess.Shell(); err != nil {
		return errs.New("SSH_SHELL", "启动远端 Shell 失败。")
	}

	// 首帧探测：识别 KoKo 是否因目标用户名/密码错误而直接报错断开，确保错误密码绝不被保存
	initialBytes, probeErr := probeTargetShellStart(remoteOut)
	if probeErr != nil {
		return probeErr
	}
	if onTargetConnected != nil {
		onTargetConnected()
	}

	restoreConsole, err := prepareInteractiveTerminal(stdinFd, stdoutFd)
	if err != nil {
		return err
	}
	defer restoreConsole()

	stopWatch := watchWindowResize(ctx, stdoutFd, sess)
	defer stopWatch()

	if len(initialBytes) > 0 {
		_, _ = os.Stdout.Write(initialBytes)
	}

	outDone := make(chan struct{})
	go func() {
		defer close(outDone)
		_, _ = io.Copy(os.Stdout, remoteOut)
	}()
	go func() {
		_, _ = io.Copy(os.Stderr, remoteErr)
	}()
	go func() {
		_, _ = io.Copy(remoteIn, os.Stdin)
		_ = remoteIn.Close()
	}()

	_ = sess.Wait()
	<-outDone
	return nil
}

type readChunk struct {
	data []byte
	err  error
}

// probeTargetShellStart 等待 KoKo 完成到目标资产的连接握手：
// - KoKo 成功连接目标后会先写出终端标题序列 (\x1b]2;...) 并进入桥接；
// - KoKo 连接目标认证失败时会写出错误提示并立即关闭通道（EOF）。
func probeTargetShellStart(remoteOut io.Reader) ([]byte, error) {
	var collected bytes.Buffer
	ch := make(chan readChunk, 1)

	readNext := func() {
		buf := make([]byte, 4096)
		n, err := remoteOut.Read(buf)
		var copied []byte
		if n > 0 {
			copied = append([]byte(nil), buf[:n]...)
		}
		ch <- readChunk{data: copied, err: err}
	}

	deadline := time.NewTimer(6 * time.Second)
	defer deadline.Stop()

	for {
		go readNext()
		select {
		case res := <-ch:
			if len(res.data) > 0 {
				collected.Write(res.data)
			}
			text := collected.String()
			if IsKoKoTargetAuthFailure(text) {
				return nil, errs.New("TARGET_AUTH_FAILED", "目标服务器拒绝了该用户名或密码（认证失败）。")
			}
			// KoKo 在 proxy/server.go 创建目标连接成功后会立即发送窗口标题序列 \x1b]2;
			if strings.Contains(text, "\x1b]2;") {
				// 再短暂等待 80ms 确认通道没有紧接着报错关闭
				settle := time.NewTimer(80 * time.Millisecond)
				select {
				case <-settle.C:
					return collected.Bytes(), nil
				}
			}
			if res.err != nil {
				// 通道在进入交互前就已关闭
				if IsKoKoTargetAuthFailure(text) {
					return nil, errs.New("TARGET_AUTH_FAILED", "目标服务器拒绝了该用户名或密码（认证失败）。")
				}
				trimmed := strings.TrimSpace(text)
				if strings.Contains(trimmed, "error:") || strings.Contains(trimmed, "错误:") {
					return nil, errs.New("TARGET_CONNECT_FAILED", "KoKo 无法连接目标服务器（请检查目标是否在线或权限状态）。")
				}
				return collected.Bytes(), nil
			}
			// 若最新数据块已是远端主机输出（非 KoKo "开始连接到... 0.1" 进度帧），也可确认进入交互
			chunkStr := strings.TrimSpace(string(res.data))
			isSpinner := strings.Contains(chunkStr, "开始连接") ||
				strings.Contains(chunkStr, "Connecting") ||
				isProgressTickOnly(chunkStr)
			if len(chunkStr) > 0 && !isSpinner &&
				!strings.Contains(chunkStr, "error:") && !strings.Contains(chunkStr, "错误:") {
				return collected.Bytes(), nil
			}
		case <-deadline.C:
			return collected.Bytes(), nil
		}
	}
}

func isProgressTickOnly(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r == '.' || r == ' ' || r == '\r' || r == '\n' || r == '\b':
		default:
			return false
		}
	}
	return len(s) > 0
}
