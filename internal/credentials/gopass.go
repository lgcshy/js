package credentials

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"time"

	"jsbridge/internal/errs"
)

var GopassCommandRunner = defaultGopassRunner

func defaultGopassRunner(ctx context.Context, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "gopass", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	// 丢弃 stderr，防止凭据子进程输出外泄
	stderr.Reset()
	return stdout.Bytes(), err
}

func GopassAvailable() bool {
	_, err := exec.LookPath("gopass")
	return err == nil
}

func ReadGopassPassword(ctx context.Context, reference string) (string, error) {
	reference = strings.TrimSpace(reference)
	if reference == "" || strings.HasPrefix(reference, "-") || strings.ContainsAny(reference, "\r\n\x00") {
		return "", errs.New("CREDENTIAL_REF", "gopass 条目名无效。")
	}
	tctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	args := []string{"show", "--password", "--nosync", "--nofuzzysearch", "--alsoclip=false", reference}
	out, err := GopassCommandRunner(tctx, args)
	if err != nil {
		if tctx.Err() != nil {
			return "", errs.Action("GOPASS", "gopass 读取超时（可能等待 GPG 解锁）。", "请先在终端解锁 GPG/gopass")
		}
		return "", errs.New("GOPASS", "无法读取指定 gopass 条目；原始输出已隐藏。")
	}
	val := strings.TrimRight(string(out), "\r\n")
	if val == "" || strings.ContainsAny(val, "\r\n\x00") {
		return "", errs.New("GOPASS_FORMAT", "gopass 密码必须是单行非空值。")
	}
	return val, nil
}
