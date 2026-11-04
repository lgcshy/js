//go:build !windows

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

// PromptPassword 只从本机控制终端 /dev/tty 无回显读取秘密，绝不从管道 stdin 或 MCP 通道读取。
func PromptPassword(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errs.Action("LOCAL_INPUT_REQUIRED", "请在本机交互终端输入凭据，不能通过非交互管道或 Agent 发送。", "请在终端直接运行 js 命令")
	}
	defer tty.Close()

	if !term.IsTerminal(int(tty.Fd())) {
		return "", errs.Action("LOCAL_INPUT_REQUIRED", "当前会话没有交互控制终端。", "请在终端直接运行 js 命令")
	}
	_, _ = fmt.Fprint(tty, prompt)
	raw, err := term.ReadPassword(int(tty.Fd()))
	_, _ = fmt.Fprintln(tty)
	if err != nil {
		return "", errs.New("LOCAL_INPUT_ABORTED", "凭据输入已取消或读取失败。")
	}
	return string(raw), nil
}

// PromptLine 从本机控制终端 /dev/tty 读取单行普通文本（如账号、序号、确认项）。
func PromptLine(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errs.Action("LOCAL_INPUT_REQUIRED", "需要本机交互终端完成输入。", "请在终端直接运行 js 命令")
	}
	defer tty.Close()

	_, _ = fmt.Fprint(tty, prompt)
	reader := bufio.NewReader(tty)
	line, err := reader.ReadString('\n')
	if err != nil && len(line) == 0 {
		return "", errs.New("LOCAL_INPUT_ABORTED", "终端输入已取消。")
	}
	return strings.TrimSpace(line), nil
}
