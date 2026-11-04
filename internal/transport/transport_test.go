package transport

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"

	"github.com/lgcshy/js/internal/errs"
)

func TestProbeTargetShellStartDetectsSuccessAndAuthFailure(t *testing.T) {
	// 1. KoKo 目标连接成功后写出窗口标题序列 \x1b]2;... 及提示符
	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write([]byte("\x1b]2;JumpServer-prod\x07alice@host:~$ "))
		time.Sleep(200 * time.Millisecond)
		_ = pw.Close()
	}()
	buf, err := probeTargetShellStart(pr)
	if err != nil {
		t.Fatalf("expected success probe, got err=%v", err)
	}
	if !strings.Contains(string(buf), "alice@host") {
		t.Fatalf("expected buffered prompt bytes, got %q", string(buf))
	}

	// 2. KoKo 目标认证失败写出错误并断开：必须返回 TARGET_AUTH_FAILED，阻止保存错误密码
	failText := "Connect asset 192.0.2.16 error: Authentication failed (username or password incorrect)\r\n"
	_, err = probeTargetShellStart(strings.NewReader(failText))
	if be, ok := errs.As(err); !ok || be.Code != "TARGET_AUTH_FAILED" {
		t.Fatalf("expected TARGET_AUTH_FAILED, got %v", err)
	}

	// 3. 中文 KoKo 认证失败提示同样必须识别
	cnFailText := "连接资产 192.0.2.16 错误: 认证失败（用户名或密码错误）\r\n"
	_, err = probeTargetShellStart(strings.NewReader(cnFailText))
	if be, ok := errs.As(err); !ok || be.Code != "TARGET_AUTH_FAILED" {
		t.Fatalf("expected TARGET_AUTH_FAILED for Chinese message, got %v", err)
	}

	// 4. KoKo 实测进度帧 ("开始连接到 ... 0.0  0.1") 后跟认证失败，必须等待进度结束并拦截错误密码
	pr2, pw2 := io.Pipe()
	go func() {
		_, _ = pw2.Write([]byte("开始连接到 手动输入(alice)@192.0.2.16  0.0"))
		time.Sleep(30 * time.Millisecond)
		_, _ = pw2.Write([]byte("   0.1   0.2\r\n"))
		time.Sleep(30 * time.Millisecond)
		_, _ = pw2.Write([]byte("连接资产 192.0.2.16 错误: 认证失败（用户名或密码错误）\r\n"))
		_ = pw2.Close()
	}()
	_, err = probeTargetShellStart(pr2)
	if be, ok := errs.As(err); !ok || be.Code != "TARGET_AUTH_FAILED" {
		t.Fatalf("expected TARGET_AUTH_FAILED after enterprise progress spinner, got %v", err)
	}
}

func TestCheckedScopedPathBlocksTraversalAndSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX path layout test")
	}
	root := t.TempDir()
	allowed := filepath.Join(root, "allowed")
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(allowed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	outsideSecret := filepath.Join(outside, "secret.txt")
	_ = os.WriteFile(outsideSecret, []byte("top-secret"), 0o600)
	escapeLink := filepath.Join(allowed, "escape")
	if err := os.Symlink(outsideSecret, escapeLink); err != nil {
		t.Fatal(err)
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	srv, err := sftp.NewServer(serverConn)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = srv.Serve()
		_ = serverConn.Close()
	}()

	client, err := sftp.NewClientPipe(clientConn, clientConn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
		_ = client.Close()
	}()

	// 未配置 file_roots 必须拒绝
	if _, err := CheckedScopedPath(client, nil, filepath.Join(allowed, "a.txt"), false); err == nil {
		t.Fatal("expected error when roots is empty")
	}
	// 允许目录内新建文件路径通过
	got, err := CheckedScopedPath(client, []string{allowed}, filepath.Join(allowed, "new.txt"), true)
	if err != nil || got != filepath.Join(allowed, "new.txt") {
		t.Fatalf("expected allowed path, got %q err=%v", got, err)
	}
	// .. 穿越、目录外路径、指向外部的软链接均必须拒绝
	for _, bad := range []string{
		allowed + "/../outside/secret.txt",
		outsideSecret,
		escapeLink,
	} {
		if _, err := CheckedScopedPath(client, []string{allowed}, bad, false); err == nil {
			t.Fatalf("expected escape blocked for %s", bad)
		}
	}
}

func TestSFTPUploadDownloadRecursiveOverwriteSymlinkAndHomeRootGuard(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX path layout test")
	}
	ctx := t.Context()
	tmp := t.TempDir()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	srv, err := sftp.NewServer(serverConn)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = srv.Serve()
		_ = serverConn.Close()
	}()

	client, err := sftp.NewClientPipe(clientConn, clientConn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
		_ = client.Close()
	}()

	// 1. 验证平台 SFTP 家目录根限制检测与越界绝对路径拦截
	homeRoot := &SFTPRootContext{
		Username:     "alice",
		HomeDir:      filepath.Join(tmp, "remote_home"),
		IsHomeRooted: true,
	}
	if err := os.MkdirAll(homeRoot.HomeDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// ~/sub/a.txt 正常映射到 <HomeDir>/sub/a.txt
	mapped, err := ResolveRemotePath(client, homeRoot, nil, "~/sub/a.txt", true)
	if err != nil || mapped != filepath.Join(homeRoot.HomeDir, "sub/a.txt") {
		t.Fatalf("expected mapped home path, got %q err=%v", mapped, err)
	}
	// /tmp/a.txt 越出家目录根，必须主动返回 SFTP_ROOT_RESTRICTED 防止静默写到 ~/tmp
	if _, err := ResolveRemotePath(client, homeRoot, nil, "/tmp/a.txt", true); err == nil {
		t.Fatal("expected SFTP_ROOT_RESTRICTED for /tmp/a.txt when IsHomeRooted=true")
	} else if be, ok := errs.As(err); !ok || be.Code != "SFTP_ROOT_RESTRICTED" || !be.ActionRequired {
		t.Fatalf("expected SFTP_ROOT_RESTRICTED with action_required, got %v", err)
	}

	// 2. 递归目录上传与下载（含跳过软链接、禁止未带 -r 传目录、禁止隐式覆盖、支持交互确认与 -f 覆盖）
	srcDir := filepath.Join(tmp, "local_src")
	if err := os.MkdirAll(filepath.Join(srcDir, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "file1.txt"), []byte("hello-1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "nested", "file2.txt"), []byte("hello-2-nested"), 0o600); err != nil {
		t.Fatal(err)
	}
	// 在目录内放入一个软链接，验证默认跳过不跟随
	_ = os.Symlink(filepath.Join(srcDir, "file1.txt"), filepath.Join(srcDir, "link_ignored"))

	// 未带 Recursive=true 上传目录必须报错 IS_DIRECTORY
	if _, err := UploadPath(ctx, client, homeRoot, nil, srcDir, "~/uploaded_dir", TransferOptions{Recursive: false}); err == nil {
		t.Fatal("expected IS_DIRECTORY when uploading directory without -r")
	}

	// 带 Recursive=true 上传目录
	upRes, err := UploadPath(ctx, client, homeRoot, nil, srcDir, "~/uploaded_dir", TransferOptions{
		Recursive: true,
		Quiet:     true,
	})
	if err != nil {
		t.Fatalf("UploadPath recursive failed: %v", err)
	}
	if upRes.FilesCount != 2 || len(upRes.SkippedSymlinks) != 1 {
		t.Fatalf("expected 2 uploaded files and 1 skipped symlink, got %+v", upRes)
	}

	// 确认无残留 .js-partial 文件
	if _, err := os.Stat(filepath.Join(homeRoot.HomeDir, "uploaded_dir", "file1.txt.js-partial")); !os.IsNotExist(err) {
		t.Fatal("unexpected .js-partial file left behind")
	}

	// 3. 覆盖保护：非交互且无 Overwrite 时报错 FILE_EXISTS；交互确认拒绝时报错；交互确认同意或 Overwrite=true 时成功
	singleSrc := filepath.Join(srcDir, "file1.txt")
	if _, err := UploadPath(ctx, client, homeRoot, nil, singleSrc, "~/uploaded_dir/file1.txt", TransferOptions{
		Overwrite:   false,
		Interactive: false,
		Quiet:       true,
	}); err == nil {
		t.Fatal("expected FILE_EXISTS when Overwrite=false and Interactive=false")
	}

	prompted := false
	if _, err := UploadPath(ctx, client, homeRoot, nil, singleSrc, "~/uploaded_dir/file1.txt", TransferOptions{
		Overwrite:   false,
		Interactive: true,
		Quiet:       true,
		ConfirmOverwrite: func(_ string) (bool, error) {
			prompted = true
			return true, nil
		},
	}); err != nil || !prompted {
		t.Fatalf("expected interactive overwrite confirmation to succeed, prompted=%v err=%v", prompted, err)
	}

	// 4. 递归下载回本地新目录并对比内容
	dlDir := filepath.Join(tmp, "local_dl")
	dlRes, err := DownloadPath(ctx, client, homeRoot, nil, "~/uploaded_dir", dlDir, TransferOptions{
		Recursive: true,
		Quiet:     true,
	})
	if err != nil {
		t.Fatalf("DownloadPath recursive failed: %v", err)
	}
	if dlRes.FilesCount != 2 {
		t.Fatalf("expected 2 downloaded files, got %+v", dlRes)
	}
	b2, err := os.ReadFile(filepath.Join(dlDir, "nested", "file2.txt"))
	if err != nil || string(b2) != "hello-2-nested" {
		t.Fatalf("unexpected downloaded nested file content: %q err=%v", string(b2), err)
	}
}


