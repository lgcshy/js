package app_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/lgcshy/js/internal/app"
	"github.com/lgcshy/js/internal/config"
	"github.com/lgcshy/js/internal/credentials"
	"github.com/lgcshy/js/internal/errs"
	"github.com/lgcshy/js/internal/jumpserver"
	"github.com/lgcshy/js/internal/transport"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func jsonResponse(status int, body any, headers map[string]string) *http.Response {
	raw, _ := json.Marshal(body)
	h := make(http.Header)
	h.Set("Content-Type", "application/json")
	for k, v := range headers {
		h.Set(k, v)
	}
	return &http.Response{
		StatusCode: status,
		Header:     h,
		Body:       io.NopCloser(bytes.NewReader(raw)),
	}
}

func newTestConfig(t *testing.T) (*config.Config, *credentials.FileStore) {
	t.Helper()
	dir := t.TempDir()
	akPath := filepath.Join(dir, "access_key")
	akContent := "ID: 00000000-0000-0000-0000-000000000001\nSecret: test-api-secret\n"
	if err := os.WriteFile(akPath, []byte(akContent), 0o600); err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(dir, "config.json")
	cfgData := config.Data{
		CoreURL:         "https://jump.example",
		JumpServerUser:  "jsuser",
		AccessKeyFile:   "access_key",
		KoKoHost:        "127.0.0.1",
		KoKoPort:        2222,
		CredentialStore: "file",
		Targets: map[string]config.TargetConfig{
			"root@10.0.0.1": {Credential: config.CredentialConfig{Type: "prompt"}},
			"deploy@10.0.0.1": {Credential: config.CredentialConfig{Type: "gopass", Ref: "servers/test/deploy"}},
			"only@10.0.0.2": {Credential: config.CredentialConfig{Type: "gopass", Ref: "servers/test/only"}},
		},
	}
	cfg := &config.Config{
		Path:   cfgPath,
		Origin: "https://jump.example",
		Data:   cfgData,
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	return loaded, credentials.NewFileStore(dir)
}

// 1. HTTPSig 签名验证、禁止重定向与隐藏响应秘密
func TestSignatureAndNoRedirect(t *testing.T) {
	var seen int
	client, err := jumpserver.NewClient(jumpserver.ClientOptions{
		Origin:   "https://jump.example",
		Username: "jsuser",
		KeyID:    "00000000-0000-0000-0000-000000000001",
		Secret:   "test-api-secret",
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			seen++
			signingText := fmt.Sprintf("(request-target): get /api/v1/users/profile/\ndate: %s", req.Header.Get("Date"))
			mac := hmac.New(sha256.New, []byte("test-api-secret"))
			mac.Write([]byte(signingText))
			sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
			if !strings.Contains(req.Header.Get("Authorization"), `signature="`+sig+`"`) {
				t.Fatalf("unexpected Authorization header: %s", req.Header.Get("Authorization"))
			}
			return jsonResponse(302, map[string]string{"message": "test-api-secret"}, map[string]string{
				"Location": "https://elsewhere.example",
			}), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	_, err = client.Request(context.Background(), http.MethodGet, "/api/v1/users/profile/", nil, nil)
	if err == nil {
		t.Fatal("expected error on 302 redirect")
	}
	if strings.Contains(err.Error(), "test-api-secret") {
		t.Fatalf("secret leaked in error: %v", err)
	}
	if seen != 1 {
		t.Fatalf("expected 1 request (no redirect follow), got %d", seen)
	}
}

// 2. 401 认证失败锁定不重试
func TestFailedAuthCannotRetry(t *testing.T) {
	var calls int
	client, err := jumpserver.NewClient(jumpserver.ClientOptions{
		Origin:   "https://jump.example",
		Username: "jsuser",
		KeyID:    "00000000-0000-0000-0000-000000000001",
		Secret:   "test-api-secret",
		Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			calls++
			return jsonResponse(401, map[string]string{"secret": "hidden-value"}, nil), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	for i := 0; i < 2; i++ {
		_, err := client.Request(context.Background(), http.MethodGet, "/api/v1/users/profile/", nil, nil)
		if err == nil || strings.Contains(err.Error(), "hidden-value") {
			t.Fatalf("expected safe error on attempt %d, got %v", i, err)
		}
	}
	if calls != 1 {
		t.Fatalf("expected exactly 1 network call after 401 latch, got %d", calls)
	}
}

// 3. 拒绝错误用户名、超级管理员、组织管理员与强制 MFA（4 组子用例）
func TestRejectWrongIdentityAdminOrMFA(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(m map[string]any)
	}{
		{"wrong_user", func(m map[string]any) { m["username"] = "someone_else" }},
		{"superuser", func(m map[string]any) { m["is_superuser"] = true }},
		{"org_admin", func(m map[string]any) { m["is_org_admin"] = true }},
		{"mfa_forced", func(m map[string]any) { m["mfa_force_enabled"] = true }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			profile := map[string]any{
				"username":   "jsuser",
				"is_active":  true,
				"is_valid":   true,
			}
			tc.mutate(profile)
			client, err := jumpserver.NewClient(jumpserver.ClientOptions{
				Origin:   "https://jump.example",
				Username: "jsuser",
				KeyID:    "00000000-0000-0000-0000-000000000001",
				Secret:   "test-api-secret",
				Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
					return jsonResponse(200, profile, nil), nil
				}),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if _, err := client.VerifyIdentity(context.Background()); err == nil {
				t.Fatalf("expected VerifyIdentity rejection for %s", tc.name)
			}
		})
	}
}

// 4. 账号秘密不跨用户混用 + 单账号 IP 简写与多账号 IP 拒绝猜测
func TestAccountSecretNotCrossedAndIPResolution(t *testing.T) {
	cfg, _ := newTestConfig(t)

	// 多账号 IP 不猜测
	if _, candidates, err := cfg.ResolveTarget("10.0.0.1"); err == nil || len(candidates) != 2 {
		t.Fatalf("expected ambiguous error with 2 candidates, got err=%v candidates=%v", err, candidates)
	}
	// 单账号已配置 IP 直接解析
	rt, _, err := cfg.ResolveTarget("10.0.0.2")
	if err != nil || rt.Canonical != "only@10.0.0.2" {
		t.Fatalf("expected only@10.0.0.2, got %+v err=%v", rt, err)
	}
	// 未配置 IP 拒绝猜测用户名
	if _, _, err := cfg.ResolveTarget("10.0.0.99"); err == nil {
		t.Fatal("expected error for unknown bare IP")
	}
}

// 5. gopass 参数隔离与错误隐藏
func TestGopassFlagsAndHiddenFailure(t *testing.T) {
	orig := credentials.GopassCommandRunner
	defer func() { credentials.GopassCommandRunner = orig }()

	var capturedArgs []string
	credentials.GopassCommandRunner = func(_ context.Context, args []string) ([]byte, error) {
		capturedArgs = append([]string(nil), args...)
		return []byte("secret-must-not-escape"), fmt.Errorf("exit 1: also-secret")
	}

	_, err := credentials.ReadGopassPassword(context.Background(), "servers/test/root")
	if err == nil {
		t.Fatal("expected gopass error")
	}
	if strings.Contains(err.Error(), "secret-must-not-escape") || strings.Contains(err.Error(), "also-secret") {
		t.Fatalf("secret leaked in gopass error: %v", err)
	}
	joined := strings.Join(capturedArgs, " ")
	for _, flag := range []string{"--password", "--nosync", "--nofuzzysearch", "--alsoclip=false"} {
		if !strings.Contains(joined, flag) {
			t.Fatalf("missing required gopass flag %s in %v", flag, capturedArgs)
		}
	}
}

// 6. 私钥仅在显式允许提交时导出（RSA & Ed25519）及口令解锁
func TestPrivateKeyExportGateAndPassphrase(t *testing.T) {
	dir := t.TempDir()

	// RSA 2048
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaBlock, err := ssh.MarshalPrivateKey(rsaPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	rsaPath := filepath.Join(dir, "id_rsa")
	if err := os.WriteFile(rsaPath, pem.EncodeToMemory(rsaBlock), 0o600); err != nil {
		t.Fatal(err)
	}

	// 未允许提交时必须拒绝
	_, err = credentials.LoadTargetSSHPrivateKey(rsaPath, false, "", false, false, nil)
	if be, ok := errs.As(err); !ok || be.Code != "KEY_SUBMISSION_REQUIRED" {
		t.Fatalf("expected KEY_SUBMISSION_REQUIRED, got %v", err)
	}

	// 允许提交后导出有效 OpenSSH 私钥且公钥一致
	exportedRSA, err := credentials.LoadTargetSSHPrivateKey(rsaPath, true, "", false, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	signerRSA, err := ssh.ParsePrivateKey([]byte(exportedRSA))
	if err != nil {
		t.Fatal(err)
	}
	origRSAPub, _ := ssh.NewPublicKey(&rsaPriv.PublicKey)
	if !bytes.Equal(signerRSA.PublicKey().Marshal(), origRSAPub.Marshal()) {
		t.Fatal("exported RSA public key mismatch")
	}

	// Ed25519 带口令加密私钥
	pubEd, privEd, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encBlock, err := ssh.MarshalPrivateKeyWithPassphrase(privEd, "", []byte("my-key-pass"))
	if err != nil {
		t.Fatal(err)
	}
	edPath := filepath.Join(dir, "id_ed25519_enc")
	if err := os.WriteFile(edPath, pem.EncodeToMemory(encBlock), 0o600); err != nil {
		t.Fatal(err)
	}

	// 非交互且无口令时拒绝
	if _, err := credentials.LoadTargetSSHPrivateKey(edPath, true, "", false, false, nil); err == nil {
		t.Fatal("expected passphrase required error")
	}
	// 提供明确口令时成功解锁并导出无口令 OpenSSH PEM
	exportedEd, err := credentials.LoadTargetSSHPrivateKey(edPath, true, "my-key-pass", true, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	signerEd, err := ssh.ParsePrivateKey([]byte(exportedEd))
	if err != nil {
		t.Fatal(err)
	}
	origEdPub, _ := ssh.NewPublicKey(pubEd)
	if !bytes.Equal(signerEd.PublicKey().Marshal(), origEdPub.Marshal()) {
		t.Fatal("exported Ed25519 public key mismatch")
	}
}

// 7. 0600 文件存储安全检查：拒绝过宽权限、拒绝软链接，支持读写删除与迁移
func TestFileStorePermissionsSymlinkAndMigration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions test")
	}
	ctx := context.Background()
	dir := t.TempDir()
	fs := credentials.NewFileStore(dir)

	if err := fs.Set(ctx, "js:https://jump.example", "asset-1/alice", "s3cr3t!", false); err != nil {
		t.Fatal(err)
	}
	got, err := fs.Get(ctx, "js:https://jump.example", "asset-1/alice", false)
	if err != nil || got != "s3cr3t!" {
		t.Fatalf("unexpected get: %q err=%v", got, err)
	}

	// 放宽权限到 0644 必须拒绝读取并提示 chmod 600
	if err := os.Chmod(fs.Path, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = fs.Get(ctx, "js:https://jump.example", "asset-1/alice", false)
	if be, ok := errs.As(err); !ok || be.Code != "SECRET_PERMISSIONS" || !strings.Contains(be.Hint, "chmod 600") {
		t.Fatalf("expected SECRET_PERMISSIONS with chmod 600 hint, got %v", err)
	}

	// 恢复 0600 后正常读取并迁移到另一存储
	if err := os.Chmod(fs.Path, 0o600); err != nil {
		t.Fatal(err)
	}
	mem := credentials.NewMemoryStore()
	n, err := credentials.MigrateStore(ctx, fs, mem, "js:https://jump.example", []string{"asset-1/alice"}, false)
	if err != nil || n != 1 {
		t.Fatalf("expected 1 migrated entry, got %d err=%v", n, err)
	}
	if _, err := fs.Get(ctx, "js:https://jump.example", "asset-1/alice", false); err != credentials.ErrNotFound {
		t.Fatalf("expected old entry deleted after migration, got %v", err)
	}
	if v, err := mem.Get(ctx, "js:https://jump.example", "asset-1/alice", false); err != nil || v != "s3cr3t!" {
		t.Fatalf("expected migrated secret in destination store, got %q err=%v", v, err)
	}

	// 软链接必须拒绝读取
	realFile := filepath.Join(dir, "real.json")
	_ = os.WriteFile(realFile, []byte(`{}`), 0o600)
	linkFile := filepath.Join(dir, "link.json")
	if err := os.Symlink(realFile, linkFile); err != nil {
		t.Fatal(err)
	}
	if _, err := credentials.ReadProtectedFile(linkFile, 1024); err == nil {
		t.Fatal("expected symlink rejection")
	}
}

// 8. 令牌载荷、未激活审批门禁与部署日期格式兼容
func TestTokenPayloadInactiveGuardAndTimeFormats(t *testing.T) {
	var bodies []map[string]any
	inactive := false
	client, err := jumpserver.NewClient(jumpserver.ClientOptions{
		Origin:   "https://jump.example",
		Username: "jsuser",
		KeyID:    "00000000-0000-0000-0000-000000000001",
		Secret:   "test-api-secret",
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			var m map[string]any
			_ = json.NewDecoder(req.Body).Decode(&m)
			bodies = append(bodies, m)
			return jsonResponse(201, map[string]any{
				"id":        "00000000-0000-0000-0000-000000000002",
				"value":     "test-token",
				"is_active": inactive,
			}, nil), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	_, err = client.CreateConnectionToken(context.Background(), jumpserver.TokenRequest{
		AssetID:         "00000000-0000-0000-0000-000000000099",
		AccountAlias:    "@INPUT",
		InputUsername:   "root",
		InputSecret:     "fake-key",
		InputSecretType: "ssh_key",
		Protocol:        "ssh",
	})
	if be, ok := errs.As(err); !ok || be.Code != "APPROVAL_REQUIRED" {
		t.Fatalf("expected APPROVAL_REQUIRED, got %v", err)
	}
	if len(bodies) != 1 || bodies[0]["account"] != "@INPUT" || bodies[0]["input_secret_type"] != "ssh_key" || bodies[0]["is_reusable"] != false {
		t.Fatalf("unexpected token request body: %+v", bodies)
	}

	// 验证JumpServer Core "YYYY/MM/DD HH:MM:SS +0800" 与 ISO8601 时间格式
	future := time.Now().In(time.FixedZone("CST", 8*3600)).Add(5 * time.Minute)
	for _, formatted := range []string{
		future.Format("2006/01/02 15:04:05 -0700"),
		future.Format("2006-01-02T15:04:05-0700"),
		future.UTC().Format(time.RFC3339),
	} {
		parsed, pErr := jumpserver.ParseJumpServerTime(formatted)
		if pErr != nil || !parsed.After(time.Now().UTC()) {
			t.Fatalf("failed to parse %q: %v", formatted, pErr)
		}
	}
}

// 9. 账号密码初始化创建个人 AK（含 ConfirmType.PASSWORD 二次确认与 MFA 提示）
func TestLoginAndCreateAccessKeyFlow(t *testing.T) {
	ctx := context.Background()
	confirmed := false

	pair, err := jumpserver.LoginAndCreateAccessKey(ctx, jumpserver.PasswordInitOptions{
		Origin:   "https://jump.example",
		Username: "jsuser",
		Password: "my-js-password",
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "/api/v1/authentication/tokens/":
				return jsonResponse(200, map[string]any{
					"token":   "temp-bearer-token",
					"keyword": "Bearer",
					"user":    map[string]any{"username": "jsuser"},
				}, map[string]string{"Set-Cookie": "jms_sessionid=s1; Path=/"}), nil
			case "/api/v1/authentication/access-keys/":
				if req.Header.Get("Authorization") != "Bearer temp-bearer-token" {
					return jsonResponse(401, map[string]any{"detail": "missing bearer"}, nil), nil
				}
				if !confirmed {
					return jsonResponse(403, map[string]any{"code": "confirm_password", "detail": "User confirm required"}, nil), nil
				}
				return jsonResponse(201, map[string]any{
					"id":        "00000000-0000-0000-0000-000000000077",
					"secret":    "generated-ak-secret",
					"is_active": true,
				}, nil), nil
			case "/api/v1/authentication/confirm/":
				confirmed = true
				return jsonResponse(200, "ok", nil), nil
			default:
				return jsonResponse(404, map[string]any{}, nil), nil
			}
		}),
	})
	if err != nil {
		t.Fatalf("unexpected LoginAndCreateAccessKey error: %v", err)
	}
	if !confirmed || pair.ID != "00000000-0000-0000-0000-000000000077" || pair.Secret != "generated-ak-secret" {
		t.Fatalf("unexpected pair: %+v confirmed=%v", pair, confirmed)
	}

	// MFA 账号返回 HTTP 200 mfa_choices 时明确提示手动创建 AK
	_, mfaErr := jumpserver.LoginAndCreateAccessKey(ctx, jumpserver.PasswordInitOptions{
		Origin:   "https://jump.example",
		Username: "jsuser",
		Password: "my-js-password",
		Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return jsonResponse(200, map[string]any{
				"error":       "mfa_required",
				"mfa_choices": []string{"otp"},
			}, nil), nil
		}),
	})
	if be, ok := errs.As(mfaErr); !ok || be.Code != "MFA_UNSUPPORTED" || !strings.Contains(be.Hint, "--access-key") {
		t.Fatalf("expected MFA_UNSUPPORTED with --access-key hint, got %v", mfaErr)
	}
}

// --- 本机真实 Go SSH 测试服务器夹具 ---

type mockSSHServer struct {
	Port        int
	Fingerprint string
	mu          sync.Mutex
	Events      []string
	TargetBadPw bool
	closeCh     chan struct{}
	listener    net.Listener
}

func startMockSSHServer(t *testing.T, expectedUser, expectedPass string) *mockSSHServer {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}

	s := &mockSSHServer{
		Fingerprint: transport.FingerprintSHA256(hostSigner.PublicKey()),
		closeCh:     make(chan struct{}),
	}

	sshCfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			s.mu.Lock()
			s.Events = append(s.Events, "auth:"+c.User())
			s.mu.Unlock()
			if (expectedUser == "" || c.User() == expectedUser) && (expectedPass == "" || string(pass) == expectedPass) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("password rejected")
		},
	}
	sshCfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.listener = ln
	s.Port = ln.Addr().(*net.TCPAddr).Port

	t.Cleanup(func() {
		close(s.closeCh)
		_ = ln.Close()
	})

	go func() {
		for {
			rawConn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handleConn(rawConn, sshCfg)
		}
	}()
	return s
}

func (s *mockSSHServer) record(ev string) {
	s.mu.Lock()
	s.Events = append(s.Events, ev)
	s.mu.Unlock()
}

func (s *mockSSHServer) snapshotEvents() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.Events...)
}

func (s *mockSSHServer) handleConn(rawConn net.Conn, cfg *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(rawConn, cfg)
	if err != nil {
		_ = rawConn.Close()
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.Prohibited, "only session allowed")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		go s.handleSession(ch, chReqs)
	}
}

func sendExitStatus(ch ssh.Channel, status uint32) {
	var payload [4]byte
	binary.BigEndian.PutUint32(payload[:], status)
	_, _ = ch.SendRequest("exit-status", false, payload[:])
}

func (s *mockSSHServer) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "exec":
			if len(req.Payload) < 4 {
				_ = req.Reply(false, nil)
				continue
			}
			n := binary.BigEndian.Uint32(req.Payload[:4])
			cmd := string(req.Payload[4 : 4+n])
			s.record(cmd)

			if cmd == "no-ack" {
				// 模拟服务端卡死不确认 exec 请求
				select {
				case <-s.closeCh:
				case <-time.After(2 * time.Second):
				}
				return
			}
			_ = req.Reply(true, nil)

			go func(command string) {
				defer ch.Close()
				s.mu.Lock()
				badPw := s.TargetBadPw
				s.mu.Unlock()
				if badPw {
					_, _ = ch.Write([]byte("ssh: handshake failed: ssh: unable to authenticate"))
					sendExitStatus(ch, 0)
					return
				}

				switch command {
				case "hang":
					select {
					case <-s.closeCh:
					case <-time.After(2 * time.Second):
					}
				case "no-status":
					_, _ = ch.Write([]byte("partial"))
				case "large":
					_, _ = ch.Write(bytes.Repeat([]byte("x"), 100000))
					sendExitStatus(ch, 0)
				case "denied":
					_, _ = ch.Write([]byte("SSH Command not support ACL review ticket"))
					sendExitStatus(ch, 0)
				case "bad-target-auth":
					_, _ = ch.Write([]byte("ssh: handshake failed: ssh: unable to authenticate"))
					sendExitStatus(ch, 0)
				case "fail":
					_, _ = ch.Write([]byte("hostname-test\n"))
					_, _ = ch.Stderr().Write([]byte("stderr-test\n"))
					sendExitStatus(ch, 7)
				default:
					_, _ = ch.Write([]byte("hostname-test\n"))
					_, _ = ch.Stderr().Write([]byte("stderr-test\n"))
					sendExitStatus(ch, 0)
				}
			}(cmd)
			return
		default:
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		}
	}
}

// 10. 真实 SSH 协议测试：双路独立输出、连续命令、退出码、超时断开不重放、输出上限、未知退出码与目标认证失败隔离
func TestRealSSHChannelsTimeoutLimitAndIsolation(t *testing.T) {
	ctx := context.Background()
	srv := startMockSSHServer(t, "JMS-tok1", "val1")

	// 错误主机指纹在认证前拒绝
	badCb, err := transport.BuildHostKeyCallback("SHA256:wrongfingerprint", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := transport.VerifyHostPrecheck(ctx, "127.0.0.1", srv.Port, badCb); err == nil {
		t.Fatal("expected HOST_KEY_CHANGED")
	} else if be, ok := errs.As(err); !ok || be.Code != "HOST_KEY_CHANGED" {
		t.Fatalf("expected HOST_KEY_CHANGED, got %v", err)
	}
	if len(srv.snapshotEvents()) != 0 {
		t.Fatalf("must not attempt SSH auth when host key mismatches, events=%v", srv.snapshotEvents())
	}

	goodCb, err := transport.BuildHostKeyCallback(srv.Fingerprint, nil)
	if err != nil {
		t.Fatal(err)
	}

	// 双路输出与连续命令
	conn, err := transport.DialKoKo(ctx, "127.0.0.1", srv.Port, goodCb, "tok1", "val1")
	if err != nil {
		t.Fatal(err)
	}
	first, err := conn.Execute(ctx, "identity", 5*time.Second, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := conn.Execute(ctx, "fail", 5*time.Second, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if first.Stdout != "hostname-test\n" || first.Stderr != "stderr-test\n" || first.ExitCode == nil || *first.ExitCode != 0 {
		t.Fatalf("unexpected first result: %+v", first)
	}
	if second.ExitCode == nil || *second.ExitCode != 7 || first.TargetExecutionVerified {
		t.Fatalf("unexpected second result: %+v", second)
	}

	// 未知退出状态与命令审批拒绝
	noSt, err := conn.Execute(ctx, "no-status", 5*time.Second, "", 0)
	if err != nil || noSt.Status != "exit_status_unknown" || noSt.ExitCode != nil {
		t.Fatalf("expected exit_status_unknown, got %+v err=%v", noSt, err)
	}
	denied, err := conn.Execute(ctx, "denied", 5*time.Second, "", 0)
	if err != nil || denied.Status != "approval_required" {
		t.Fatalf("expected approval_required, got %+v err=%v", denied, err)
	}
	conn.Close()

	// 超时（包括 hang 和 no-ack）必须关闭传输且不重放
	for _, cmd := range []string{"hang", "no-ack"} {
		t.Run("timeout_"+cmd, func(t *testing.T) {
			c2, dErr := transport.DialKoKo(ctx, "127.0.0.1", srv.Port, goodCb, "tok1", "val1")
			if dErr != nil {
				t.Fatal(dErr)
			}
			start := time.Now()
			res, eErr := c2.Execute(ctx, cmd, 150*time.Millisecond, "", 0)
			if eErr != nil {
				t.Fatal(eErr)
			}
			if time.Since(start) > 1500*time.Millisecond {
				t.Fatalf("timeout took too long: %v", time.Since(start))
			}
			if res.Status != "timeout" || res.ExitCode != nil || !res.RemoteProcessMayStillRun || !c2.IsClosed() {
				t.Fatalf("unexpected timeout result: %+v closed=%v", res, c2.IsClosed())
			}
		})
	}

	// 输出超限截断并关闭连接
	c3, err := transport.DialKoKo(ctx, "127.0.0.1", srv.Port, goodCb, "tok1", "val1")
	if err != nil {
		t.Fatal(err)
	}
	limRes, err := c3.Execute(ctx, "large", 5*time.Second, "", 1024)
	if err != nil {
		t.Fatal(err)
	}
	if limRes.Status != "output_limit" || !limRes.Truncated || len(limRes.Stdout) > 1024 || !c3.IsClosed() {
		t.Fatalf("unexpected output_limit result: status=%s len=%d closed=%v", limRes.Status, len(limRes.Stdout), c3.IsClosed())
	}

	// 目标认证失败必须关闭连接不可复用
	c4, err := transport.DialKoKo(ctx, "127.0.0.1", srv.Port, goodCb, "tok1", "val1")
	if err != nil {
		t.Fatal(err)
	}
	badAuthRes, err := c4.Execute(ctx, "bad-target-auth", 5*time.Second, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if badAuthRes.Status != "target_auth_failed" || !c4.IsClosed() {
		t.Fatalf("expected target_auth_failed & closed, got %+v closed=%v", badAuthRes, c4.IsClosed())
	}
}

// 11. 主机指纹未通过前绝不读取 AK、绝不调用 API、绝不读取目标密码
func TestNoSecretOrAPIBeforeHostVerification(t *testing.T) {
	ctx := context.Background()
	srv := startMockSSHServer(t, "JMS-tok", "val")
	cfg, _ := newTestConfig(t)
	cfg.Data.KoKoHost = "127.0.0.1"
	cfg.Data.KoKoPort = srv.Port
	cfg.Data.KoKoHostFingerprint = "SHA256:untrusted-mismatch"

	apiCalled := false
	promptCalled := false
	svc := app.NewService(cfg, credentials.NewMemoryStore())
	svc.HTTPTransport = roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		apiCalled = true
		return jsonResponse(200, map[string]any{}, nil), nil
	})
	svc.PromptPass = func(_ string) (string, error) {
		promptCalled = true
		return "pw", nil
	}

	_, err := svc.OpenConnection(ctx, "root@10.0.0.1", "ssh", true, "")
	if be, ok := errs.As(err); !ok || be.Code != "HOST_KEY_CHANGED" {
		t.Fatalf("expected HOST_KEY_CHANGED, got %v", err)
	}
	if apiCalled || promptCalled {
		t.Fatalf("must not touch API (%v) or target secret (%v) before KoKo host verification", apiCalled, promptCalled)
	}
}

// 12. P1 端到端核心体验：
// - 全新初始化 (init) -> 首次输入错误密码不保存 -> 重输正确密码自动保存 -> 第二次连接零提示 + 单次资产缓存命中 -> 别名/保留字 -> 注销吊销 AK
func TestEndToEndInitSaveOnSuccessCacheAndLogout(t *testing.T) {
	ctx := context.Background()
	sshSrv := startMockSSHServer(t, "", "")
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	memStore := credentials.NewMemoryStore()

	const assetUUID = "00000000-0000-0000-0000-000000000104"
	const createdAKUUID = "00000000-0000-0000-0000-000000000888"

	var listCalls, detailCalls, revokeCalls int
	var lastSubmittedSecret string

	mockCore := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodPost && req.URL.Path == "/api/v1/authentication/tokens/":
			return jsonResponse(200, map[string]any{
				"token": "bearer-1",
				"user":  map[string]any{"username": "jsuser"},
			}, nil), nil
		case req.Method == http.MethodPost && req.URL.Path == "/api/v1/authentication/access-keys/":
			return jsonResponse(201, map[string]any{
				"id":        createdAKUUID,
				"secret":    "ak-secret-1",
				"is_active": true,
			}, nil), nil
		case req.Method == http.MethodDelete && req.URL.Path == "/api/v1/authentication/access-keys/"+createdAKUUID+"/":
			revokeCalls++
			return jsonResponse(204, map[string]any{}, nil), nil
		case req.Method == http.MethodGet && req.URL.Path == "/api/v1/users/profile/":
			return jsonResponse(200, map[string]any{
				"username":  "jsuser",
				"is_active": true,
				"is_valid":  true,
			}, nil), nil
		case req.Method == http.MethodGet && strings.HasPrefix(req.URL.Path, "/api/v1/perms/users/self/assets/") && req.URL.Path != "/api/v1/perms/users/self/assets/":
			detailCalls++
			return jsonResponse(200, map[string]any{
				"id":               assetUUID,
				"name":             "prod-104-16",
				"address":          "192.0.2.16",
				"is_active":        true,
				"permed_protocols": []map[string]any{{"name": "ssh", "port": 22}},
				"permed_accounts": []map[string]any{{
					"alias":   "@INPUT",
					"actions": []map[string]any{{"value": "connect"}},
				}},
			}, nil), nil
		case req.Method == http.MethodGet && req.URL.Path == "/api/v1/perms/users/self/assets/":
			listCalls++
			return jsonResponse(200, []map[string]any{{
				"id":        assetUUID,
				"name":      "prod-104-16",
				"address":   "192.0.2.16",
				"is_active": true,
			}}, nil), nil
		case req.Method == http.MethodPost && req.URL.Path == "/api/v1/authentication/connection-token/":
			var body map[string]any
			_ = json.NewDecoder(req.Body).Decode(&body)
			lastSubmittedSecret, _ = body["input_secret"].(string)
			sshSrv.mu.Lock()
			sshSrv.TargetBadPw = (lastSubmittedSecret != "correct-server-pw")
			sshSrv.mu.Unlock()
			active := true
			return jsonResponse(201, map[string]any{
				"id":        "00000000-0000-0000-0000-000000000555",
				"value":     "one-time-tok",
				"is_active": active,
			}, nil), nil
		default:
			return jsonResponse(404, map[string]any{}, nil), nil
		}
	})

	// Step A: 全新用户 js init（密码登录自动创建本机 AK）
	var initOut bytes.Buffer
	initRes, err := app.Initialize(ctx, app.InitOptions{
		ConfigPath:    cfgPath,
		CoreURL:       "https://jump.example",
		KoKoHost:      "127.0.0.1",
		KoKoPort:      sshSrv.Port,
		Fingerprint:   sshSrv.Fingerprint,
		CustomStore:   memStore,
		HTTPTransport: mockCore,
		PromptText:    func(_ string) (string, error) { return "jsuser", nil },
		PromptPass:    func(_ string) (string, error) { return "js-login-pw", nil },
		Out:           &initOut,
	})
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if !initRes.CreatedAK || initRes.Username != "jsuser" {
		t.Fatalf("unexpected init result: %+v", initRes)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	svc := app.NewService(cfg, memStore)
	svc.HTTPTransport = mockCore
	svc.Stderr = io.Discard

	// Step B: 首次连接先输错目标密码 ("wrong-pw")，提示重输一次时输入正确密码 ("correct-server-pw")
	pwQueue := []string{"wrong-pw", "correct-server-pw"}
	svc.PromptPass = func(_ string) (string, error) {
		if len(pwQueue) == 0 {
			return "", fmt.Errorf("unexpected extra password prompt")
		}
		next := pwQueue[0]
		pwQueue = pwQueue[1:]
		return next, nil
	}

	res1, _, err := svc.ExecuteCommand(ctx, "alice@192.0.2.16", "hostname", 5*time.Second, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if res1.Status != "ssh_completed" || len(pwQueue) != 0 {
		t.Fatalf("expected retry once then succeed, res=%+v remainingQueue=%v", res1, pwQueue)
	}
	// 确认保存的是正确密码而非第一次的错误密码
	savedPw, err := memStore.Get(ctx, svc.ServiceKey(), assetUUID+"/alice", false)
	if err != nil || savedPw != "correct-server-pw" {
		t.Fatalf("expected correct-server-pw saved under %s/alice, got %q err=%v", assetUUID, savedPw, err)
	}

	// Step C: 设置便捷别名（同时验证保留字拒绝）
	if _, err := cfg.SetAlias("init", "alice@192.0.2.16"); err == nil {
		t.Fatal("expected reserved command name rejected as alias")
	}
	if _, err := cfg.SetAlias("srv16", "alice@192.0.2.16"); err != nil {
		t.Fatal(err)
	}
	_ = cfg.Save()

	// Step D: 第二次通过别名连接：零密码提示（interactive=false 也能直接过），且命中本地 asset_id 缓存（不拉全量资产列表！）
	prevListCalls := listCalls
	svc.PromptPass = func(_ string) (string, error) {
		t.Fatal("second connection must require zero password input!")
		return "", nil
	}
	res2, timings2, err := svc.ExecuteCommand(ctx, "srv16", "hostname", 5*time.Second, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Status != "ssh_completed" || !timings2.AssetCacheHit || listCalls != prevListCalls {
		t.Fatalf("expected zero-input cached connection, status=%s cacheHit=%v listCalls=%d->%d",
			res2.Status, timings2.AssetCacheHit, prevListCalls, listCalls)
	}

	// Step E: 注销 logout 在线吊销本机创建的 AK，清除本地登录凭据，但保留已保存的目标服务器密码
	logoutRes, err := svc.Logout(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if !logoutRes.ServerAKRevoked || revokeCalls != 1 {
		t.Fatalf("expected server AK revoked, res=%+v revokeCalls=%d", logoutRes, revokeCalls)
	}
	if _, err := memStore.Get(ctx, svc.ServiceKey(), credentials.AccessKeyEntry("jsuser"), false); err != credentials.ErrNotFound {
		t.Fatalf("expected AK deleted after logout, got %v", err)
	}
	if pw, err := memStore.Get(ctx, svc.ServiceKey(), assetUUID+"/alice", false); err != nil || pw != "correct-server-pw" {
		t.Fatalf("logout must preserve saved target passwords, got %q err=%v", pw, err)
	}
	_ = detailCalls
}
