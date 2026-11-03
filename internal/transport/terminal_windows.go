//go:build windows

package transport

import (
	"context"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
	"golang.org/x/term"

	"jsbridge/internal/errs"
)

func prepareInteractiveTerminal(stdinFd, stdoutFd int) (func(), error) {
	oldInState, err := term.MakeRaw(stdinFd)
	if err != nil {
		return nil, errs.New("LOCAL_TERMINAL", "无法设置 Windows 控制台输入模式。")
	}

	outHandle := windows.Handle(stdoutFd)
	var oldOutMode uint32
	hasOutMode := windows.GetConsoleMode(outHandle, &oldOutMode) == nil
	if hasOutMode {
		vtMode := oldOutMode | windows.ENABLE_PROCESSED_OUTPUT | windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
		if err := windows.SetConsoleMode(outHandle, vtMode|windows.DISABLE_NEWLINE_AUTO_RETURN); err != nil {
			_ = windows.SetConsoleMode(outHandle, vtMode)
		}
	}

	return func() {
		_ = term.Restore(stdinFd, oldInState)
		if hasOutMode {
			_ = windows.SetConsoleMode(outHandle, oldOutMode)
		}
	}, nil
}

func watchWindowResize(ctx context.Context, stdoutFd int, sess *ssh.Session) func() {
	stopCh := make(chan struct{})
	lastW, lastH, _ := term.GetSize(stdoutFd)

	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stopCh:
				return
			case <-ticker.C:
				if w, h, err := term.GetSize(stdoutFd); err == nil && w > 0 && h > 0 {
					if w != lastW || h != lastH {
						lastW, lastH = w, h
						_ = sess.WindowChange(h, w)
					}
				}
			}
		}
	}()

	return func() {
		close(stopCh)
	}
}
