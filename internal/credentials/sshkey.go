package credentials

import (
	"encoding/pem"
	"errors"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/lgcshy/js/internal/errs"
)

const maxPrivateKeyFileBytes = 65536

// LoadTargetSSHPrivateKey 仅在显式允许提交给 JumpServer 时读取、解锁并序列化目标私钥（内存导出 OpenSSH PEM，不落盘）。
func LoadTargetSSHPrivateKey(
	path string,
	submitAllowed bool,
	passphrase string,
	hasExplicitPassphrase bool,
	interactive bool,
	promptPassphrase func(prompt string) (string, error),
) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errs.Action("KEY_NOT_BOUND", "尚未绑定目标私钥路径。", "请运行 js bind-key user@IP 私钥路径 --allow-key-submission")
	}
	if !submitAllowed {
		return "", errs.Action(
			"KEY_SUBMISSION_REQUIRED",
			"此路线需要把目标私钥通过 HTTPS 提交给 JumpServer，尚未明确允许。",
			"确认接受后请运行 js bind-key user@IP 私钥路径 --allow-key-submission",
		)
	}
	raw, err := ReadProtectedFile(path, maxPrivateKeyFileBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", errs.New("PRIVATE_KEY", "指定的目标私钥文件不存在。")
		}
		return "", err
	}

	var parsedKey any
	if hasExplicitPassphrase {
		parsedKey, err = ssh.ParseRawPrivateKeyWithPassphrase(raw, []byte(passphrase))
	} else {
		parsedKey, err = ssh.ParseRawPrivateKey(raw)
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			if !interactive || promptPassphrase == nil {
				return "", errs.Action(
					"KEY_PASSPHRASE_REQUIRED",
					"目标私钥已加密，非交互模式无法输入口令。",
					"请在交互终端连接，或绑定口令引用",
				)
			}
			pw, promptErr := promptPassphrase("目标私钥解锁口令：")
			if promptErr != nil {
				return "", promptErr
			}
			parsedKey, err = ssh.ParseRawPrivateKeyWithPassphrase(raw, []byte(pw))
		}
	}
	if err != nil {
		return "", errs.New("PRIVATE_KEY", "私钥格式不支持或解锁失败；不会尝试其他密钥。")
	}

	block, err := ssh.MarshalPrivateKey(parsedKey, "")
	if err != nil {
		return "", errs.New("PRIVATE_KEY", "无法序列化目标私钥为 OpenSSH 格式。")
	}
	encoded := pem.EncodeToMemory(block)
	if len(encoded) == 0 {
		return "", errs.New("PRIVATE_KEY", "目标私钥编码为空。")
	}
	return string(encoded), nil
}
