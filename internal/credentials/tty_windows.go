//go:build windows

package credentials

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/lgcshy/js/internal/errs"
)

func IsInteractiveTTY() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

func PromptPassword(prompt string) (string, error) {
	in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return "", errs.Action("LOCAL_INPUT_REQUIRED", "需要本机交互控制台输入凭据。", "请在 Windows Terminal 或 PowerShell 直接运行 js 命令")
	}
	defer in.Close()

	out, err := os.OpenFile("CONOUT$", os.O_RDWR, 0)
	if err != nil {
		return "", errs.Action("LOCAL_INPUT_REQUIRED", "需要本机交互控制台。", "请在 Windows Terminal 或 PowerShell 直接运行 js 命令")
	}
	defer out.Close()

	if !term.IsTerminal(int(in.Fd())) {
		return "", errs.Action("LOCAL_INPUT_REQUIRED", "当前会话没有交互控制台。", "请在 Windows Terminal 或 PowerShell 直接运行 js 命令")
	}
	_, _ = fmt.Fprint(out, prompt)
	raw, err := term.ReadPassword(int(in.Fd()))
	_, _ = fmt.Fprintln(out)
	if err != nil {
		return "", errs.New("LOCAL_INPUT_ABORTED", "凭据输入已取消或读取失败。")
	}
	return string(raw), nil
}

func PromptLine(prompt string) (string, error) {
	in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return "", errs.Action("LOCAL_INPUT_REQUIRED", "需要本机交互控制台完成输入。", "请在 Windows Terminal 或 PowerShell 直接运行 js 命令")
	}
	defer in.Close()

	out, err := os.OpenFile("CONOUT$", os.O_RDWR, 0)
	if err != nil {
		return "", errs.Action("LOCAL_INPUT_REQUIRED", "需要本机交互控制台。", "请在 Windows Terminal 或 PowerShell 直接运行 js 命令")
	}
	defer out.Close()

	_, _ = fmt.Fprint(out, prompt)
	reader := bufio.NewReader(in)
	line, err := reader.ReadString('\n')
	if err != nil && len(line) == 0 {
		return "", errs.New("LOCAL_INPUT_ABORTED", "终端输入已取消。")
	}
	return strings.TrimSpace(line), nil
}
