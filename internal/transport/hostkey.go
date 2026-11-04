package transport

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/lgcshy/js/internal/errs"
)

var errStopAfterHostKey = errors.New("stop handshake after host key check")

func FingerprintSHA256(key ssh.PublicKey) string {
	return ssh.FingerprintSHA256(key)
}

func BuildHostKeyCallback(pinnedFingerprint string, knownHostsPaths []string) (ssh.HostKeyCallback, error) {
	pinned := strings.TrimSpace(pinnedFingerprint)
	if pinned != "" {
		return func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got := FingerprintSHA256(key)
			if subtle.ConstantTimeCompare([]byte(got), []byte(pinned)) != 1 {
				return errs.New("HOST_KEY_CHANGED", "KoKo 主机指纹与可信配置不一致；已停止连接。")
			}
			return nil
		}, nil
	}

	var existing []string
	for _, p := range knownHostsPaths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			existing = append(existing, p)
		}
	}
	if len(existing) == 0 {
		return func(_ string, _ net.Addr, _ ssh.PublicKey) error {
			return errs.Action("HOST_KEY_UNKNOWN", "尚无可信 KoKo 主机密钥记录。", "请核对指纹后运行 js trust --fingerprint SHA256:...")
		}, nil
	}

	khCb, err := knownhosts.New(existing...)
	if err != nil {
		return nil, errs.New("KNOWN_HOSTS", "无法解析 known_hosts 文件。")
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := khCb(hostname, remote, key)
		if err == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) {
			if len(keyErr.Want) > 0 {
				return errs.New("HOST_KEY_CHANGED", "KoKo 主机密钥与 known_hosts 记录不一致；已停止连接。")
			}
			return errs.Action("HOST_KEY_UNKNOWN", "known_hosts 中尚无此 KoKo 主机密钥。", "请核对指纹后运行 js trust --fingerprint SHA256:...")
		}
		return errs.New("HOST_KEY_CHANGED", "KoKo 主机密钥校验未通过；已停止连接。")
	}, nil
}

// ObserveHostFingerprint 仅完成 SSH 密钥交换并提取服务端公钥指纹，不发起任何用户认证。
func ObserveHostFingerprint(ctx context.Context, host string, port int) (string, error) {
	var observed string
	cb := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		observed = FingerprintSHA256(key)
		return errStopAfterHostKey
	}
	err := handshakeOnly(ctx, host, port, cb)
	if err != nil {
		return "", err
	}
	if observed == "" {
		return "", errs.New("SSH_HANDSHAKE", "未能读取 KoKo 主机公钥。")
	}
	return observed, nil
}

// VerifyHostPrecheck 在读取任何秘密或创建令牌之前，对 KoKo 进行真实 SSH 握手与主机密钥验证。
func VerifyHostPrecheck(ctx context.Context, host string, port int, verifyCb ssh.HostKeyCallback) error {
	if verifyCb == nil {
		return errs.New("HOST_KEY_UNKNOWN", "缺少主机密钥校验器。")
	}
	cb := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if err := verifyCb(hostname, remote, key); err != nil {
			return err
		}
		return errStopAfterHostKey
	}
	return handshakeOnly(ctx, host, port, cb)
}

func handshakeOnly(ctx context.Context, host string, port int, cb ssh.HostKeyCallback) error {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	d := net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return errs.New("SSH_HANDSHAKE", "KoKo 网络连接失败。")
	}
	defer rawConn.Close()

	deadline := time.Now().Add(10 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = rawConn.SetDeadline(deadline)

	cfg := &ssh.ClientConfig{
		User:            "hostkey-probe",
		Auth:            nil,
		HostKeyCallback: cb,
		Timeout:         10 * time.Second,
	}
	sc, _, _, err := ssh.NewClientConn(rawConn, addr, cfg)
	if sc != nil {
		_ = sc.Close()
	}
	if err != nil {
		if errors.Is(err, errStopAfterHostKey) || strings.Contains(err.Error(), errStopAfterHostKey.Error()) {
			return nil
		}
		if be, ok := errs.As(err); ok {
			return be
		}
		return errs.New("SSH_HANDSHAKE", "KoKo SSH 握手失败。")
	}
	return nil
}
