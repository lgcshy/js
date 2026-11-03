//go:build !windows

package transport

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"jsbridge/internal/errs"
)

func prepareInteractiveTerminal(stdinFd, _ int) (func(), error) {
	oldState, err := term.MakeRaw(stdinFd)
	if err != nil {
		return nil, errs.New("LOCAL_TERMINAL", "无法将本机终端切换为 Raw 模式。")
	}
	return func() {
		_ = term.Restore(stdinFd, oldState)
	}, nil
}

func watchWindowResize(ctx context.Context, stdoutFd int, sess *ssh.Session) func() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH)
	stopCh := make(chan struct{})

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-stopCh:
				return
			case <-sigCh:
				if w, h, err := term.GetSize(stdoutFd); err == nil && w > 0 && h > 0 {
					_ = sess.WindowChange(h, w)
				}
			}
		}
	}()

	return func() {
		signal.Stop(sigCh)
		close(stopCh)
	}
}
