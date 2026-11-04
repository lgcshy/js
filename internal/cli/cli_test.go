package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/lgcshy/js/internal/app"
	"github.com/lgcshy/js/internal/config"
)

func TestCLIDoctorBindAliasAndStoreCommands(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfg := &config.Config{
		Path:   cfgPath,
		Origin: "https://jump.example",
		Data: config.Data{
			CoreURL:             "https://jump.example",
			JumpServerUser:      "jsuser",
			KoKoHost:            "127.0.0.1",
			KoKoPort:            2222,
			KoKoHostFingerprint: "SHA256:testfp",
			CredentialStore:     "file",
			Targets:             map[string]config.TargetConfig{},
			Aliases:             map[string]string{},
		},
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	// 1. doctor 默认不触发网络或认证
	if code := runMain([]string{"--config", cfgPath, "doctor"}); code != 0 {
		t.Fatalf("doctor exited with %d", code)
	}

	// 2. bind-gopass（位置参数和 --ref 两种写法）
	if code := runMain([]string{"--config", cfgPath, "bind-gopass", "root@10.0.0.2", "servers/test/root"}); code != 0 {
		t.Fatalf("bind-gopass positional failed with %d", code)
	}
	if code := runMain([]string{"--config", cfgPath, "bind-gopass", "alice@10.0.0.3", "--ref", "servers/test/alice"}); code != 0 {
		t.Fatalf("bind-gopass --ref failed with %d", code)
	}

	// 3. bind-key（验证默认 submit_to_jumpserver=false）
	keyFile := filepath.Join(dir, "dummy_key")
	_ = os.WriteFile(keyFile, []byte("dummy"), 0o600)
	if code := runMain([]string{"--config", cfgPath, "bind-key", "root@10.0.0.4", keyFile}); code != 0 {
		t.Fatalf("bind-key failed with %d", code)
	}

	// 4. alias 与保留字拒绝
	if code := runMain([]string{"--config", cfgPath, "alias", "hosts", "root@10.0.0.2"}); code == 0 {
		t.Fatal("alias 'hosts' must be rejected as reserved subcommand")
	}
	if code := runMain([]string{"--config", cfgPath, "alias", "app2", "root@10.0.0.2"}); code != 0 {
		t.Fatalf("alias app2 failed with %d", code)
	}

	// 5. completion 脚本生成与动态补全模式
	for _, sh := range []string{"bash", "zsh", "powershell"} {
		var compBuf bytes.Buffer
		if err := writeCompletion(&compBuf, sh); err != nil || !strings.Contains(compBuf.String(), "__complete") {
			t.Fatalf("unexpected %s completion: %v %s", sh, err, compBuf.String())
		}
	}
	var epBuf bytes.Buffer
	printDynamicCompletions(&epBuf, cfgPath, "cp-endpoints")
	if !strings.Contains(epBuf.String(), "app2:") || !strings.Contains(epBuf.String(), "root@10.0.0.2:") {
		t.Fatalf("expected cp-endpoints completion with trailing colon, got: %s", epBuf.String())
	}

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Data.Targets["root@10.0.0.2"].Credential.Ref != "servers/test/root" {
		t.Fatalf("unexpected gopass ref: %+v", loaded.Data.Targets["root@10.0.0.2"])
	}
	if loaded.Data.Targets["root@10.0.0.4"].Credential.SubmitToJumpServer {
		t.Fatal("bind-key without --allow-key-submission must keep submit_to_jumpserver=false")
	}
	if loaded.Data.Aliases["app2"] != "root@10.0.0.2" {
		t.Fatalf("unexpected alias map: %+v", loaded.Data.Aliases)
	}

	// 6. forget 不删除磁盘上的用户私钥文件
	if code := runMain([]string{"--config", cfgPath, "forget", "root@10.0.0.4"}); code != 0 {
		t.Fatalf("forget failed with %d", code)
	}
	if _, err := os.Stat(keyFile); err != nil {
		t.Fatalf("forget must NEVER delete user's private key file: %v", err)
	}

	if runtime.GOOS != "windows" {
		raw, _ := os.ReadFile(cfgPath)
		var check map[string]any
		if err := json.Unmarshal(raw, &check); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseCopyEndpointCrossPlatform(t *testing.T) {
	cases := []struct {
		in         string
		wantTarget string
		wantPath   string
		wantRemote bool
	}{
		{`C:\Users\alice\build.tgz`, "", `C:\Users\alice\build.tgz`, false},
		{`D:/work/app.zip`, "", `D:/work/app.zip`, false},
		{`./local:file.txt`, "", `./local:file.txt`, false},
		{`/var/log/syslog`, "", `/var/log/syslog`, false},
		{`~/downloads/a.tgz`, "", `~/downloads/a.tgz`, false},
		{`alice@192.0.2.16:~/tmp/a.tgz`, "alice@192.0.2.16", "~/tmp/a.tgz", true},
		{`web1:/opt/app/conf`, "web1", "/opt/app/conf", true},
		{`alice@192.0.2.16:`, "alice@192.0.2.16", "", true},
	}
	for _, tc := range cases {
		target, p, isRem := app.ParseCopyEndpoint(tc.in)
		if target != tc.wantTarget || p != tc.wantPath || isRem != tc.wantRemote {
			t.Fatalf("ParseCopyEndpoint(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.in, target, p, isRem, tc.wantTarget, tc.wantPath, tc.wantRemote)
		}
	}
}
