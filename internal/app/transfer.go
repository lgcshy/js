package app

import (
	"context"
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"github.com/pkg/sftp"

	"jsbridge/internal/config"
	"jsbridge/internal/errs"
	"jsbridge/internal/transport"
)

type CopyOptions struct {
	Recursive   bool
	Overwrite   bool
	Interactive bool
	Quiet       bool
	MaxBytes    int64
}

type OpenedSFTPSession struct {
	Session *OpenedSession
	Client  *sftp.Client
	RootCtx *transport.SFTPRootContext
}

func (o *OpenedSFTPSession) Close() {
	if o == nil {
		return
	}
	if o.Client != nil {
		_ = o.Client.Close()
	}
	if o.Session != nil && o.Session.Conn != nil {
		o.Session.Conn.Close()
	}
}

// ParseCopyEndpoint 区分本地路径与远端 `目标:路径` 规格（兼容 Windows 盘符路径如 `C:\...` 或 `D:/...`）。
func ParseCopyEndpoint(raw string) (targetPart string, pathPart string, isRemote bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", false
	}
	// 显式本地路径前缀
	if strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") ||
		strings.HasPrefix(s, `.\`) || strings.HasPrefix(s, `..\`) ||
		strings.HasPrefix(s, "/") || strings.HasPrefix(s, `\`) ||
		strings.HasPrefix(s, "~") {
		return "", s, false
	}
	// Windows 盘符路径（例如 C:\dir\file 或 C:/dir/file）
	if len(s) >= 3 && isAlphaASCII(s[0]) && s[1] == ':' && (s[2] == '\\' || s[2] == '/') {
		return "", s, false
	}
	idx := strings.IndexByte(s, ':')
	if idx <= 0 {
		return "", s, false
	}
	host := s[:idx]
	// 若冒号前包含路径分隔符，说明是含冒号的本地文件名而非目标主机
	if strings.ContainsAny(host, `/\`) {
		return "", s, false
	}
	return host, s[idx+1:], true
}

func isAlphaASCII(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// OpenSFTPSession 建立经 JumpServer 的 SFTP 会话并探测目标根目录映射；
// 支持“目标服务器登录成功后才保存密码”，在密码错误时最多允许交互重输一次。
func (s *Service) OpenSFTPSession(
	ctx context.Context,
	targetInput string,
	requiredAction string,
	interactive bool,
) (*OpenedSFTPSession, error) {
	sess, err := s.OpenConnectionWithAction(ctx, targetInput, "sftp", requiredAction, interactive, "")
	if err != nil {
		return nil, err
	}

	sc, rootCtx, sftpErr := openAndVerifySFTP(sess.Conn, sess.ResolvedTarget.Username)
	if sftpErr == nil {
		if sess.freshPassword != "" {
			pw := sess.freshPassword
			sess.freshPassword = ""
			s.maybeSaveTargetPassword(ctx, sess.ResolvedTarget, sess.ResolvedAsset.Asset, pw, interactive)
		}
		return &OpenedSFTPSession{
			Session: sess,
			Client:  sc,
			RootCtx: rootCtx,
		}, nil
	}

	sess.Conn.Close()
	be, ok := errs.As(sftpErr)
	if !ok || be.Code != "TARGET_AUTH_FAILED" || !interactive || (sess.freshPassword == "" && !sess.fromSavedStore) {
		return nil, sftpErr
	}

	if s.Stderr != nil {
		_, _ = fmt.Fprintf(s.Stderr, "✗ %s 密码被目标服务器拒绝（未保存），请重新输入一次：\n", sess.ResolvedTarget.Canonical)
	}
	retryCred, promptErr := s.promptTargetPassword(sess.ResolvedTarget.Canonical)
	if promptErr != nil {
		return nil, promptErr
	}

	sess2, err2 := s.OpenConnectionWithAction(ctx, sess.ResolvedTarget.Canonical, "sftp", requiredAction, true, retryCred.secret)
	retryCred.secret = ""
	if err2 != nil {
		return nil, err2
	}
	sc2, rootCtx2, sftpErr2 := openAndVerifySFTP(sess2.Conn, sess2.ResolvedTarget.Username)
	if sftpErr2 != nil {
		sess2.Conn.Close()
		return nil, sftpErr2
	}
	if sess2.freshPassword != "" {
		pw := sess2.freshPassword
		sess2.freshPassword = ""
		s.maybeSaveTargetPassword(ctx, sess2.ResolvedTarget, sess2.ResolvedAsset.Asset, pw, true)
	}
	return &OpenedSFTPSession{
		Session: sess2,
		Client:  sc2,
		RootCtx: rootCtx2,
	}, nil
}

func openAndVerifySFTP(conn *transport.Connection, username string) (*sftp.Client, *transport.SFTPRootContext, error) {
	sc, err := conn.OpenSFTP()
	if err != nil {
		return nil, nil, err
	}
	rootCtx, err := transport.DetectSFTPRoot(sc, username)
	if err != nil {
		_ = sc.Close()
		return nil, nil, err
	}
	return sc, rootCtx, nil
}

func (s *Service) buildTransferOptions(opts CopyOptions) transport.TransferOptions {
	return transport.TransferOptions{
		Recursive:   opts.Recursive,
		Overwrite:   opts.Overwrite,
		Interactive: opts.Interactive,
		Quiet:       opts.Quiet,
		MaxBytes:    opts.MaxBytes,
		ProgressOut: s.Stderr,
		ConfirmOverwrite: func(prompt string) (bool, error) {
			if s.PromptText == nil {
				return false, nil
			}
			ans, err := s.PromptText(prompt)
			if err != nil {
				return false, err
			}
			a := strings.ToLower(strings.TrimSpace(ans))
			return a == "y" || a == "yes", nil
		},
	}
}

func (s *Service) Upload(
	ctx context.Context,
	targetInput string,
	localSources []string,
	rawRemoteDst string,
	opts CopyOptions,
) (*transport.TransferResult, error) {
	if len(localSources) == 0 {
		return nil, errs.New("USAGE", "请指定要上传的本地源路径。")
	}
	sftpSess, err := s.OpenSFTPSession(ctx, targetInput, "upload", opts.Interactive)
	if err != nil {
		return nil, err
	}
	defer sftpSess.Close()

	return s.UploadOnSession(ctx, sftpSess.Client, sftpSess.RootCtx, sftpSess.Session.Conn.FileRoots, sftpSess.Session.ResolvedTarget.Canonical, localSources, rawRemoteDst, opts)
}

func (s *Service) UploadOnSession(
	ctx context.Context,
	sc *sftp.Client,
	rootCtx *transport.SFTPRootContext,
	fileRoots []string,
	canonicalTarget string,
	localSources []string,
	rawRemoteDst string,
	opts CopyOptions,
) (*transport.TransferResult, error) {
	started := time.Now()
	tOpts := s.buildTransferOptions(opts)

	if len(localSources) > 1 {
		resolvedDst, err := transport.ResolveRemotePath(sc, rootCtx, fileRoots, rawRemoteDst, true)
		if err != nil {
			return nil, err
		}
		fi, stErr := sc.Stat(resolvedDst)
		if stErr != nil || !fi.IsDir() {
			return nil, errs.New("NOT_A_DIRECTORY", fmt.Sprintf("同时上传多个源时，远端目标 %s 必须是已存在的目录。", resolvedDst))
		}
	}

	combined := &transport.TransferResult{
		Direction: "upload",
		Target:    canonicalTarget,
	}
	for _, src := range localSources {
		expandedSrc := config.ExpandHome(src)
		partRes, err := transport.UploadPath(ctx, sc, rootCtx, fileRoots, expandedSrc, rawRemoteDst, tOpts)
		if partRes != nil {
			combined.FilesCount += partRes.FilesCount
			combined.DirsCount += partRes.DirsCount
			combined.TotalBytes += partRes.TotalBytes
			combined.Items = append(combined.Items, partRes.Items...)
			combined.SkippedSymlinks = append(combined.SkippedSymlinks, partRes.SkippedSymlinks...)
		}
		if err != nil {
			return combined, err
		}
	}
	dur := time.Since(started)
	combined.DurationSeconds = math.Round(dur.Seconds()*1000) / 1000
	combined.DurationMs = dur.Milliseconds()
	return combined, nil
}

func (s *Service) Download(
	ctx context.Context,
	targetInput string,
	remoteSources []string,
	localDst string,
	opts CopyOptions,
) (*transport.TransferResult, error) {
	if len(remoteSources) == 0 {
		return nil, errs.New("USAGE", "请指定要下载的远端源路径。")
	}
	sftpSess, err := s.OpenSFTPSession(ctx, targetInput, "download", opts.Interactive)
	if err != nil {
		return nil, err
	}
	defer sftpSess.Close()

	return s.DownloadOnSession(ctx, sftpSess.Client, sftpSess.RootCtx, sftpSess.Session.Conn.FileRoots, sftpSess.Session.ResolvedTarget.Canonical, remoteSources, localDst, opts)
}

func (s *Service) DownloadOnSession(
	ctx context.Context,
	sc *sftp.Client,
	rootCtx *transport.SFTPRootContext,
	fileRoots []string,
	canonicalTarget string,
	remoteSources []string,
	localDst string,
	opts CopyOptions,
) (*transport.TransferResult, error) {
	started := time.Now()
	tOpts := s.buildTransferOptions(opts)
	expandedDst := config.ExpandHome(localDst)

	if len(remoteSources) > 1 {
		fi, stErr := os.Stat(expandedDst)
		if stErr != nil || !fi.IsDir() {
			return nil, errs.New("NOT_A_DIRECTORY", fmt.Sprintf("同时下载多个远端源时，本地目标 %s 必须是已存在的目录。", localDst))
		}
	}

	combined := &transport.TransferResult{
		Direction: "download",
		Target:    canonicalTarget,
	}
	for _, rSrc := range remoteSources {
		partRes, err := transport.DownloadPath(ctx, sc, rootCtx, fileRoots, rSrc, expandedDst, tOpts)
		if partRes != nil {
			combined.FilesCount += partRes.FilesCount
			combined.DirsCount += partRes.DirsCount
			combined.TotalBytes += partRes.TotalBytes
			combined.Items = append(combined.Items, partRes.Items...)
			combined.SkippedSymlinks = append(combined.SkippedSymlinks, partRes.SkippedSymlinks...)
		}
		if err != nil {
			return combined, err
		}
	}
	dur := time.Since(started)
	combined.DurationSeconds = math.Round(dur.Seconds()*1000) / 1000
	combined.DurationMs = dur.Milliseconds()
	return combined, nil
}

// Copy 解析 scp 风格的 `源... 目标` 参数并执行上传或下载。
func (s *Service) Copy(ctx context.Context, operands []string, opts CopyOptions) (*transport.TransferResult, error) {
	if len(operands) < 2 {
		return nil, errs.New("USAGE", "用法：js cp [-r] [-f] <源...> <目标>")
	}
	sources := operands[:len(operands)-1]
	dest := operands[len(operands)-1]

	dstTarget, dstPath, dstIsRemote := ParseCopyEndpoint(dest)

	if dstIsRemote {
		// 上传模式：所有源必须是本地路径
		var localSrcs []string
		for _, src := range sources {
			_, _, srcIsRemote := ParseCopyEndpoint(src)
			if srcIsRemote {
				return nil, errs.New("USAGE", "不支持从远端直接复制到另一个远端；请先下载到本地。")
			}
			localSrcs = append(localSrcs, src)
		}
		return s.Upload(ctx, dstTarget, localSrcs, dstPath, opts)
	}

	// 下载模式：所有源必须是远端路径，且属于同一目标服务器
	var remoteSrcs []string
	var commonTarget string
	var commonCanonical string

	for _, src := range sources {
		srcTarget, srcPath, srcIsRemote := ParseCopyEndpoint(src)
		if !srcIsRemote {
			return nil, errs.New("USAGE", "源和目标必须有一端为远端（格式：用户@IP:路径 或 别名:路径）。")
		}
		rt, _, err := s.Config.ResolveTarget(srcTarget)
		if err != nil {
			if commonTarget == "" {
				commonTarget = srcTarget
			} else if commonTarget != srcTarget {
				return nil, errs.New("USAGE", "单次下载的多个远端路径必须属于同一台目标服务器。")
			}
		} else {
			if commonCanonical == "" {
				commonCanonical = rt.Canonical
				commonTarget = rt.Canonical
			} else if commonCanonical != rt.Canonical {
				return nil, errs.New("USAGE", "单次下载的多个远端路径必须属于同一台目标服务器。")
			}
		}
		remoteSrcs = append(remoteSrcs, srcPath)
	}

	return s.Download(ctx, commonTarget, remoteSrcs, dstPath, opts)
}
