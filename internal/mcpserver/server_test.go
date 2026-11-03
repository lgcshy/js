package mcpserver_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"jsbridge/internal/app"
	"jsbridge/internal/config"
	"jsbridge/internal/credentials"
	"jsbridge/internal/mcpserver"
	"jsbridge/internal/transport"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func jsonResp(status int, body any) *http.Response {
	raw, _ := json.Marshal(body)
	h := make(http.Header)
	h.Set("Content-Type", "application/json")
	return &http.Response{
		StatusCode: status,
		Header:     h,
		Body:       io.NopCloser(bytes.NewReader(raw)),
	}
}

type testSSHSFTPServer struct {
	Port        int
	Fingerprint string
	FailAuthFor map[string]bool
	mu          sync.Mutex
	listener    net.Listener
	closeCh     chan struct{}
}

func startTestSSHSFTPServer(t *testing.T) *testSSHSFTPServer {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}

	s := &testSSHSFTPServer{
		Fingerprint: transport.FingerprintSHA256(hostSigner.PublicKey()),
		FailAuthFor: map[string]bool{},
		closeCh:     make(chan struct{}),
	}

	sshCfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if strings.HasPrefix(c.User(), "JMS-") && string(pass) != "" {
				return &ssh.Permissions{
					Extensions: map[string]string{"jms_user": c.User()},
				}, nil
			}
			return nil, fmt.Errorf("rejected")
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

func (s *testSSHSFTPServer) handleConn(rawConn net.Conn, cfg *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(rawConn, cfg)
	if err != nil {
		_ = rawConn.Close()
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)

	jmsUser := sc.User()
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.Prohibited, "only session")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		go s.handleSession(jmsUser, ch, chReqs)
	}
}

func sendExit(ch ssh.Channel, code uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], code)
	_, _ = ch.SendRequest("exit-status", false, b[:])
}

func (s *testSSHSFTPServer) handleSession(jmsUser string, ch ssh.Channel, reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "exec":
			if len(req.Payload) < 4 {
				_ = req.Reply(false, nil)
				continue
			}
			n := binary.BigEndian.Uint32(req.Payload[:4])
			cmd := string(req.Payload[4 : 4+n])
			_ = req.Reply(true, nil)

			go func(command string) {
				defer ch.Close()
				s.mu.Lock()
				badTarget := s.FailAuthFor[jmsUser]
				s.mu.Unlock()
				if badTarget {
					_, _ = ch.Write([]byte("Connect asset error: Authentication failed (username or password incorrect)\r\n"))
					sendExit(ch, 0)
					return
				}

				switch {
				case command == "large-100k":
					chunk := bytes.Repeat([]byte("A"), 50000)
					chunk2 := bytes.Repeat([]byte("Z"), 50000)
					_, _ = ch.Write(chunk)
					_, _ = ch.Write(chunk2)
					sendExit(ch, 0)
				case command == "slow-200ms":
					time.Sleep(200 * time.Millisecond)
					_, _ = ch.Write([]byte("slow-done\n"))
					sendExit(ch, 0)
				case strings.Contains(command, "echo-ok"):
					_, _ = ch.Write([]byte("ok-output\n"))
					sendExit(ch, 0)
				default:
					_, _ = ch.Write([]byte("ran:" + command + "\n"))
					sendExit(ch, 0)
				}
			}(cmd)
			return

		case "subsystem":
			if len(req.Payload) < 4 {
				_ = req.Reply(false, nil)
				continue
			}
			n := binary.BigEndian.Uint32(req.Payload[:4])
			sub := string(req.Payload[4 : 4+n])
			if sub != "sftp" {
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, nil)
			go func() {
				defer ch.Close()
				srv, err := sftp.NewServer(ch)
				if err != nil {
					return
				}
				_ = srv.Serve()
			}()
			return

		default:
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		}
	}
}

func TestMCPToolsSchemaAndFullWorkflow(t *testing.T) {
	ctx := context.Background()
	sshSrv := startTestSSHSFTPServer(t)
	dir := t.TempDir()

	cfgPath := filepath.Join(dir, "config.json")
	memStore := credentials.NewMemoryStore()

	const assetUUID = "00000000-0000-0000-0000-000000000104"
	cfg := &config.Config{
		Path:   cfgPath,
		Origin: "https://jump.example",
		Data: config.Data{
			CoreURL:             "https://jump.example",
			JumpServerUser:      "jsuser",
			KoKoHost:            "127.0.0.1",
			KoKoPort:            sshSrv.Port,
			KoKoHostFingerprint: sshSrv.Fingerprint,
			CredentialStore:     "file",
			Generation:          1,
			Aliases: map[string]string{
				"s104": "alice@192.0.2.16",
			},
			Targets: map[string]config.TargetConfig{
				"alice@192.0.2.16": {
					AssetID:    assetUUID,
					AssetName:  "prod-104-16",
					Credential: config.CredentialConfig{Type: "store"},
				},
				"bad@192.0.2.16": {
					AssetID:    assetUUID,
					AssetName:  "prod-104-16",
					Credential: config.CredentialConfig{Type: "store"},
				},
			},
		},
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	svc := app.NewService(cfg, memStore)
	svc.Stderr = io.Discard

	// 写入 AK 与目标密码到内存凭据库
	_ = memStore.Set(ctx, svc.ServiceKey(), credentials.AccessKeyEntry("jsuser"),
		credentials.FormatAccessKeySecret("00000000-0000-0000-0000-000000000001", "ak-secret"), false)
	_ = memStore.Set(ctx, svc.ServiceKey(), credentials.TargetEntry(assetUUID, "alice", "alice@192.0.2.16"), "good-pw", false)
	_ = memStore.Set(ctx, svc.ServiceKey(), credentials.TargetEntry(assetUUID, "bad", "bad@192.0.2.16"), "bad-pw", false)

	var sshTokenCount atomic.Int32
	var sftpTokenCount atomic.Int32
	var badTokenCount atomic.Int32
	var tokSeq atomic.Int32

	svc.HTTPTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/api/v1/users/profile/":
			return jsonResp(200, map[string]any{
				"username":  "jsuser",
				"is_active": true,
				"is_valid":  true,
			}), nil
		case req.Method == http.MethodGet && strings.HasPrefix(req.URL.Path, "/api/v1/perms/users/self/assets/"):
			return jsonResp(200, map[string]any{
				"id":        assetUUID,
				"name":      "prod-104-16",
				"address":   "192.0.2.16",
				"is_active": true,
				"permed_protocols": []map[string]any{
					{"name": "ssh", "port": 22},
					{"name": "sftp", "port": 22},
				},
				"permed_accounts": []map[string]any{{
					"alias": "@INPUT",
					"actions": []map[string]any{
						{"value": "connect"},
						{"value": "upload"},
						{"value": "download"},
					},
				}},
			}), nil
		case req.Method == http.MethodPost && req.URL.Path == "/api/v1/authentication/connection-token/":
			var body map[string]any
			_ = json.NewDecoder(req.Body).Decode(&body)
			proto, _ := body["protocol"].(string)
			user, _ := body["input_username"].(string)
			sec, _ := body["input_secret"].(string)

			seq := tokSeq.Add(1)
			tokID := fmt.Sprintf("00000000-0000-0000-0000-%012d", seq)

			if user == "bad" {
				badTokenCount.Add(1)
				sshSrv.mu.Lock()
				sshSrv.FailAuthFor["JMS-"+tokID] = (sec != "fixed-pw")
				sshSrv.mu.Unlock()
			} else if proto == "ssh" {
				sshTokenCount.Add(1)
			} else if proto == "sftp" {
				sftpTokenCount.Add(1)
			}

			return jsonResp(201, map[string]any{
				"id":        tokID,
				"value":     "tok-val",
				"is_active": true,
			}), nil
		default:
			return jsonResp(404, map[string]any{}), nil
		}
	})

	server, mgr := mcpserver.NewServer(svc, "0.3.0-test")
	defer mgr.CloseAll()

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverCtx, cancelServer := context.WithCancel(ctx)
	defer cancelServer()
	go func() {
		_ = server.Run(serverCtx, serverTransport)
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("MCP client connect failed: %v", err)
	}
	defer session.Close()

	// 1. 验证工具集合及参数 Schema 不含任何秘密字段
	toolsRes, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}
	wantTools := map[string]bool{
		"list_hosts":       true,
		"run_command":      true,
		"upload":           true,
		"download":         true,
		"close_connection": true,
	}
	if len(toolsRes.Tools) != len(wantTools) {
		t.Fatalf("unexpected tool count: %d", len(toolsRes.Tools))
	}
	forbidden := []string{"password", "token", "private_key", "secret", "passphrase", "access_key"}
	for _, tool := range toolsRes.Tools {
		if !wantTools[tool.Name] {
			t.Fatalf("unexpected tool name: %s", tool.Name)
		}
		rawSchema, _ := json.Marshal(tool.InputSchema)
		schemaLower := strings.ToLower(string(rawSchema))
		for _, bad := range forbidden {
			if strings.Contains(schemaLower, `"`+bad+`"`) {
				t.Fatalf("tool %s schema contains forbidden secret property %q: %s", tool.Name, bad, string(rawSchema))
			}
		}
	}

	callJSON := func(name string, args map[string]any) map[string]any {
		t.Helper()
		res, cErr := session.CallTool(ctx, &mcp.CallToolParams{
			Name:      name,
			Arguments: args,
		})
		if cErr != nil {
			t.Fatalf("CallTool(%s) failed: %v", name, cErr)
		}
		if len(res.Content) == 0 {
			t.Fatalf("CallTool(%s) returned empty content", name)
		}
		tc, ok := res.Content[0].(*mcp.TextContent)
		if !ok {
			t.Fatalf("CallTool(%s) unexpected content type %T", name, res.Content[0])
		}
		var parsed map[string]any
		if uErr := json.Unmarshal([]byte(tc.Text), &parsed); uErr != nil {
			t.Fatalf("CallTool(%s) invalid JSON %q: %v", name, tc.Text, uErr)
		}
		return parsed
	}

	// 2. list_hosts
	hostsOut := callJSON("list_hosts", map[string]any{})
	if hostsOut["ok"] != true {
		t.Fatalf("list_hosts failed: %+v", hostsOut)
	}

	// 3. run_command 自动建连 + 第二次调用复用同一 SSH 连接（sshTokenCount 仍为 1）
	cmd1 := callJSON("run_command", map[string]any{
		"target":  "s104",
		"command": "echo-ok",
		"cwd":     "/tmp",
	})
	if cmd1["ok"] != true || cmd1["stdout"] != "ok-output\n" {
		t.Fatalf("unexpected cmd1 result: %+v", cmd1)
	}
	cmd2 := callJSON("run_command", map[string]any{
		"target":  "alice@192.0.2.16",
		"command": "hostname",
	})
	if cmd2["ok"] != true || sshTokenCount.Load() != 1 {
		t.Fatalf("expected SSH connection reused (1 token), got sshTokenCount=%d res=%+v", sshTokenCount.Load(), cmd2)
	}

	// 4. 大输出模型上下文保护截断（100 KiB > 64 KiB 头尾上限，保持连接不断开）
	largeOut := callJSON("run_command", map[string]any{
		"target":  "s104",
		"command": "large-100k",
	})
	if largeOut["ok"] != true || largeOut["model_truncated"] != true || largeOut["transport_truncated"] != false {
		t.Fatalf("expected model_truncated=true and transport_truncated=false, got %+v", largeOut)
	}
	stdoutText, _ := largeOut["stdout"].(string)
	if !strings.HasPrefix(stdoutText, "AAAA") || !strings.HasSuffix(stdoutText, "ZZZZ") || !strings.Contains(stdoutText, "MCP 模型上下文保护") {
		t.Fatalf("unexpected truncated stdout structure, len=%d", len(stdoutText))
	}

	// 5. upload 与 download（独立复用 SFTP 连接 + 默认拒绝覆盖 + overwrite=true 允许覆盖 + SHA256 一致）
	srcFile := filepath.Join(dir, "upload_src.bin")
	payload := bytes.Repeat([]byte("JumpServer-MCP-SFTP-Test-Payload-"), 1024)
	if err := os.WriteFile(srcFile, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	remoteDir := filepath.Join(dir, "remote_sftp")
	if err := os.MkdirAll(remoteDir, 0o700); err != nil {
		t.Fatal(err)
	}
	remoteDst := filepath.Join(remoteDir, "uploaded.bin")

	up1 := callJSON("upload", map[string]any{
		"local_path":  srcFile,
		"target":      "s104",
		"remote_path": remoteDst,
	})
	if up1["ok"] != true || up1["status"] != "uploaded" {
		t.Fatalf("upload failed: %+v", up1)
	}

	// 默认 overwrite=false 再次上传同名文件必须拒绝
	upConflict := callJSON("upload", map[string]any{
		"local_path":  srcFile,
		"target":      "s104",
		"remote_path": remoteDst,
	})
	if upConflict["ok"] != false || upConflict["error"] != "FILE_EXISTS" {
		t.Fatalf("expected FILE_EXISTS when overwrite=false, got %+v", upConflict)
	}

	// overwrite=true 覆盖成功，且全程复用同一个 SFTP 会话（sftpTokenCount == 1）
	upOverwrite := callJSON("upload", map[string]any{
		"local_path":  srcFile,
		"target":      "s104",
		"remote_path": remoteDst,
		"overwrite":   true,
	})
	if upOverwrite["ok"] != true || sftpTokenCount.Load() != 1 {
		t.Fatalf("expected overwrite upload success & SFTP session reuse (1 token), got count=%d res=%+v", sftpTokenCount.Load(), upOverwrite)
	}

	// download 回本地并核验 SHA-256
	dlDst := filepath.Join(dir, "downloaded.bin")
	dl1 := callJSON("download", map[string]any{
		"target":      "s104",
		"remote_path": remoteDst,
		"local_path":  dlDst,
	})
	if dl1["ok"] != true || dl1["status"] != "downloaded" || sftpTokenCount.Load() != 1 {
		t.Fatalf("download failed or did not reuse SFTP session: %+v", dl1)
	}
	gotBytes, err := os.ReadFile(dlDst)
	if err != nil || sha256.Sum256(gotBytes) != sha256.Sum256(payload) {
		t.Fatalf("downloaded file SHA256 mismatch")
	}

	// 6. 目标认证失败锁定 (AUTH_FAILURE_LATCHED) 与 CLI 更新 generation 后自动解锁
	bad1 := callJSON("run_command", map[string]any{
		"target":  "bad@192.0.2.16",
		"command": "hostname",
	})
	if bad1["ok"] != false || bad1["error"] != "TARGET_AUTH_FAILED" || bad1["action_required"] != true {
		t.Fatalf("expected TARGET_AUTH_FAILED with action_required=true, got %+v", bad1)
	}
	bad2 := callJSON("run_command", map[string]any{
		"target":  "bad@192.0.2.16",
		"command": "hostname",
	})
	if bad2["ok"] != false || bad2["error"] != "AUTH_FAILURE_LATCHED" || badTokenCount.Load() != 1 {
		t.Fatalf("expected AUTH_FAILURE_LATCHED without extra token call, got count=%d res=%+v", badTokenCount.Load(), bad2)
	}

	// 模拟用户在终端执行 js passwd 修复密码并递增 config.json 的 generation
	_ = memStore.Set(ctx, svc.ServiceKey(), credentials.TargetEntry(assetUUID, "bad", "bad@192.0.2.16"), "fixed-pw", false)
	if err := cfg.Update(true, func(_ *config.Data) error { return nil }); err != nil {
		t.Fatal(err)
	}

	badRecovered := callJSON("run_command", map[string]any{
		"target":  "bad@192.0.2.16",
		"command": "echo-ok",
	})
	if badRecovered["ok"] != true || badRecovered["stdout"] != "ok-output\n" {
		t.Fatalf("expected generation bump to unlatch target and succeed, got %+v", badRecovered)
	}

	// 7. close_connection
	closeOut := callJSON("close_connection", map[string]any{"target": "*"})
	if closeOut["ok"] != true {
		t.Fatalf("close_connection failed: %+v", closeOut)
	}
}
