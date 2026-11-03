package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"

	"jsbridge/internal/errs"
)

const (
	MaxSmallFileBytes  = 1024 * 1024 // 1 MiB（兼容小文件限长接口）
	transferChunkBytes = 128 * 1024  // 128 KiB 流式传输块
)

type SFTPProbeResult struct {
	WorkingDir       string   `json:"working_dir"`
	RootRealPath     string   `json:"root_realpath"`
	RootEntriesCount int      `json:"root_entries_count"`
	SampleEntries    []string `json:"sample_entries,omitempty"`
	TmpAccessible    bool     `json:"tmp_accessible"`
	HomeAccessible   bool     `json:"home_accessible"`
}

// SFTPRootContext 描述 KoKo 在令牌登录下对目标资产的 SFTP 根目录映射上下文。
type SFTPRootContext struct {
	Username     string `json:"username"`
	HomeDir      string `json:"home_dir"`
	IsHomeRooted bool   `json:"is_home_rooted"`
}

type TransferItemResult struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Bytes       int64  `json:"bytes"`
	Overwritten bool   `json:"overwritten"`
}

type TransferResult struct {
	Direction       string               `json:"direction"` // "upload" or "download"
	Target          string               `json:"target,omitempty"`
	FilesCount      int                  `json:"files_count"`
	DirsCount       int                  `json:"dirs_count"`
	TotalBytes      int64                `json:"total_bytes"`
	DurationSeconds float64              `json:"duration_seconds"`
	DurationMs      int64                `json:"duration_ms"`
	Items           []TransferItemResult `json:"items,omitempty"`
	SkippedSymlinks []string             `json:"skipped_symlinks,omitempty"`
}

type TransferOptions struct {
	Recursive        bool
	Overwrite        bool
	Interactive      bool
	Quiet            bool
	MaxBytes         int64
	ProgressOut      io.Writer
	ConfirmOverwrite func(prompt string) (bool, error)
}

func (c *Connection) OpenSFTP() (*sftp.Client, error) {
	if c == nil || c.Client == nil || c.IsClosed() {
		return nil, errs.New("SFTP", "SSH 连接未就绪，无法启动 SFTP 子系统。")
	}
	sc, err := sftp.NewClient(c.Client, sftp.MaxPacket(32768))
	if err != nil {
		return nil, errs.New("SFTP", "SFTP 子系统连接失败；不回退到 Shell 传输。")
	}
	return sc, nil
}

// ProbeSFTP 只读探测 KoKo 令牌登录下的 SFTP 虚拟目录与根目录映射（P0 契约验证使用，不写入任何远端文件）。
func (c *Connection) ProbeSFTP(homeCandidate string) (*SFTPProbeResult, error) {
	sc, err := c.OpenSFTP()
	if err != nil {
		return nil, err
	}
	defer sc.Close()

	wd, _ := sc.Getwd()
	rp, _ := sc.RealPath("/")
	entries, err := sc.ReadDir("/")
	if err != nil {
		return nil, errs.New("SFTP_READ", "SFTP 根目录只读列举失败（请确认资产已授权下载/浏览或目标凭据正确）。")
	}
	var sample []string
	for i, e := range entries {
		if i >= 8 {
			break
		}
		name := e.Name()
		if e.IsDir() {
			name += "/"
		}
		sample = append(sample, name)
	}

	_, tmpErr := sc.Stat("/tmp")
	homeOK := false
	if strings.TrimSpace(homeCandidate) != "" {
		_, hErr := sc.Stat(homeCandidate)
		homeOK = hErr == nil
	}

	return &SFTPProbeResult{
		WorkingDir:       wd,
		RootRealPath:     rp,
		RootEntriesCount: len(entries),
		SampleEntries:    sample,
		TmpAccessible:    tmpErr == nil,
		HomeAccessible:   homeOK,
	}, nil
}

// DetectSFTPRoot 验证目标 SFTP 会话已成功连上目标服务器，并探测平台 SFTP 根目录是否锁定在用户家目录。
func DetectSFTPRoot(sc *sftp.Client, username string) (*SFTPRootContext, error) {
	if sc == nil {
		return nil, errs.New("SFTP", "SFTP 客户端为空。")
	}
	// 触发首次目标资产 SFTP 操作，确认目标服务器认证是否通过
	_, statErr := sc.Stat("/")
	if statErr != nil {
		_, rdErr := sc.ReadDir("/")
		if rdErr != nil {
			msg := strings.ToLower(statErr.Error() + " " + rdErr.Error())
			if strings.Contains(msg, "authenticate") || strings.Contains(msg, "permission denied") || strings.Contains(msg, "eof") || strings.Contains(msg, "connection lost") {
				return nil, errs.New("TARGET_AUTH_FAILED", "SFTP 连接目标服务器失败（目标密码可能错误或该账号无 SFTP 权限）。")
			}
			return nil, errs.New("SFTP", "无法访问远端 SFTP 根目录；请检查资产 SFTP 协议与账号权限。")
		}
	}

	username = strings.TrimSpace(username)
	var homeCandidate string
	if username == "root" {
		homeCandidate = "/root"
	} else if username != "" {
		homeCandidate = "/home/" + username
	}

	ctx := &SFTPRootContext{
		Username: username,
		HomeDir:  homeCandidate,
	}
	if homeCandidate == "" {
		return ctx, nil
	}

	homeFi, homeErr := sc.Stat(homeCandidate)
	if homeErr != nil || homeFi == nil || !homeFi.IsDir() {
		// 若 /home/<user> 不可见，说明 SFTP 根目录可能本身是某特定目录或非标准家目录，退回以 "/" 为基准
		ctx.HomeDir = "/"
		return ctx, nil
	}

	// 判断 KoKo 是否将 SFTP 根目录限制为 homeCandidate（如 /home/alice）：
	// 在 KoKo GetRealPath 中，若 rootDirPath == "/home/alice"，则：
	// - Stat("/home/alice") 会命中前缀并成功；
	// - Stat("/etc") 与 Stat("/home") 不含 "/home/alice" 前缀，会被拼成 "/home/alice/etc" 与 "/home/alice/home" 而失败。
	_, etcErr := sc.Stat("/etc")
	_, usrErr := sc.Stat("/usr")
	if etcErr != nil && usrErr != nil {
		ctx.IsHomeRooted = true
	}
	return ctx, nil
}

// ResolveRemotePath 将用户输入的远端路径（支持 `~/...`、相对路径、绝对路径）解析为 KoKo SFTP 路径，
// 并在平台将 SFTP 根目录限制为家目录时拦截越界绝对路径（如 `/tmp`），防止被静默写到 `~/tmp`。
func ResolveRemotePath(
	sc *sftp.Client,
	rootCtx *SFTPRootContext,
	fileRoots []string,
	rawRemotePath string,
	forWrite bool,
) (string, error) {
	if strings.ContainsRune(rawRemotePath, '\x00') {
		return "", errs.New("FILE_PATH", "远端路径不能包含 NUL 字符。")
	}
	p := strings.TrimSpace(strings.ReplaceAll(rawRemotePath, `\`, "/"))

	homeDir := "/"
	isHomeRooted := false
	if rootCtx != nil {
		if rootCtx.HomeDir != "" {
			homeDir = rootCtx.HomeDir
		}
		isHomeRooted = rootCtx.IsHomeRooted
	}

	var candidate string
	switch {
	case p == "" || p == "." || p == "~" || p == "~/":
		candidate = homeDir

	case strings.HasPrefix(p, "~/"):
		sub := strings.TrimPrefix(p, "~/")
		if hasDotDotSegment(sub) {
			return "", errs.New("FILE_SCOPE", "远端路径不允许包含 '..'。")
		}
		candidate = path.Join(homeDir, sub)

	case !strings.HasPrefix(p, "/"):
		if hasDotDotSegment(p) {
			return "", errs.New("FILE_SCOPE", "远端路径不允许包含 '..'。")
		}
		candidate = path.Join(homeDir, p)

	default:
		if hasDotDotSegment(p) {
			return "", errs.New("FILE_SCOPE", "远端路径不允许包含 '..'。")
		}
		candidate = path.Clean(p)
		if isHomeRooted && homeDir != "/" {
			if candidate != homeDir && !strings.HasPrefix(candidate, homeDir+"/") {
				relSuggest := strings.TrimPrefix(candidate, "/")
				return "", errs.Action(
					"SFTP_ROOT_RESTRICTED",
					fmt.Sprintf("当前 JumpServer 平台将 SFTP 根目录限制为登录用户家目录 (%s)，无法直接通过 SFTP 访问 %s（否则会被 KoKo 静默映射到 %s%s）。",
						homeDir, candidate, homeDir, candidate),
					fmt.Sprintf("请改用家目录路径（如 ~/%s），或联系 管理员 将平台 SFTP 根目录调整为 /", relSuggest),
				)
			}
		}
	}

	candidate = path.Clean(candidate)
	if len(fileRoots) > 0 && sc != nil {
		return CheckedScopedPath(sc, fileRoots, candidate, forWrite)
	}
	return candidate, nil
}

func hasDotDotSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// CheckedScopedPath 校验受控目录范围（用于兼容 file_roots 沙箱检查，防 `..` 与软链接逃逸）。
func CheckedScopedPath(sc *sftp.Client, roots []string, remotePath string, forWrite bool) (string, error) {
	if len(roots) == 0 || !strings.HasPrefix(remotePath, "/") || strings.ContainsRune(remotePath, '\x00') {
		return "", errs.New("FILE_SCOPE", "需先设置允许的 file_roots，并使用绝对路径。")
	}
	if hasDotDotSegment(remotePath) {
		return "", errs.New("FILE_SCOPE", "文件路径不允许包含 '..'。")
	}
	cleanTarget := path.Clean(remotePath)
	checkTarget := cleanTarget
	if forWrite {
		checkTarget = path.Dir(cleanTarget)
	}

	resolved, err := resolveSFTPSymlinks(sc, checkTarget)
	if err != nil {
		return "", errs.New("FILE_PATH", "无法在服务端解析远端路径。")
	}
	resolved = path.Clean(resolved)
	if forWrite {
		resolved = path.Join(resolved, path.Base(cleanTarget))
	}

	for _, r := range roots {
		if !strings.HasPrefix(r, "/") {
			continue
		}
		nr, rErr := resolveSFTPSymlinks(sc, path.Clean(r))
		if rErr != nil {
			continue
		}
		nr = path.Clean(nr)
		if resolved == nr || (nr == "/" && strings.HasPrefix(resolved, "/")) || strings.HasPrefix(resolved, nr+"/") {
			return resolved, nil
		}
	}
	return "", errs.New("FILE_SCOPE", "文件路径不在允许的目录范围内。")
}

// resolveSFTPSymlinks 同时结合 RealPath 与逐级 Lstat/ReadLink，避免纯 Go pkg/sftp 服务端 RealPath 仅做词法清理而不展开软链接。
func resolveSFTPSymlinks(sc *sftp.Client, target string) (string, error) {
	cur, err := sc.RealPath(target)
	if err != nil {
		return "", err
	}
	cur = path.Clean(cur)
	for depth := 0; depth < 16; depth++ {
		parts := strings.Split(strings.TrimPrefix(cur, "/"), "/")
		built := "/"
		changed := false
		for i, part := range parts {
			if part == "" {
				continue
			}
			next := path.Join(built, part)
			fi, lErr := sc.Lstat(next)
			if lErr != nil {
				return "", lErr
			}
			if fi.Mode()&os.ModeSymlink != 0 {
				linkDest, rlErr := sc.ReadLink(next)
				if rlErr != nil {
					return "", rlErr
				}
				if !strings.HasPrefix(linkDest, "/") {
					linkDest = path.Join(built, linkDest)
				}
				rest := strings.Join(parts[i+1:], "/")
				if rest != "" {
					cur = path.Clean(path.Join(linkDest, rest))
				} else {
					cur = path.Clean(linkDest)
				}
				changed = true
				break
			}
			built = next
		}
		if !changed {
			return cur, nil
		}
	}
	return "", errs.New("FILE_PATH", "软链接嵌套层级过深。")
}

// UploadPath 执行本地文件或目录（-r）到远端 SFTP 的流式上传。
// 遵循约定：
// - 默认不跟随软链接；
// - 先写 `<目标>.js-partial`，完整关闭后再重命名为最终文件名；
// - 目标已存在时：-f 直接先删旧文件再改名，交互模式询问确认，非交互且无 -f 报错；
// - 失败不自动重试，明确提示残留 `.js-partial` 位置。
func UploadPath(
	ctx context.Context,
	sc *sftp.Client,
	rootCtx *SFTPRootContext,
	fileRoots []string,
	localSrc string,
	rawRemoteDst string,
	opts TransferOptions,
) (*TransferResult, error) {
	started := time.Now()
	absSrc, err := filepath.Abs(localSrc)
	if err != nil {
		return nil, errs.New("FILE_PATH", "本地源路径无效："+localSrc)
	}
	srcFi, err := os.Lstat(absSrc)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errs.New("FILE_NOT_FOUND", "本地源文件或目录不存在："+localSrc)
		}
		return nil, errs.New("FILE_READ", "无法读取本地源路径属性："+localSrc)
	}
	if srcFi.Mode()&os.ModeSymlink != 0 {
		return nil, errs.New("SYMLINK_SKIPPED", "默认不跟随软链接："+localSrc)
	}

	resolvedDst, err := ResolveRemotePath(sc, rootCtx, fileRoots, rawRemoteDst, true)
	if err != nil {
		return nil, err
	}

	res := &TransferResult{
		Direction: "upload",
	}

	if srcFi.IsDir() {
		if !opts.Recursive {
			return nil, errs.New("IS_DIRECTORY", fmt.Sprintf("本地源路径 %s 是目录，请使用 -r 递归上传。", localSrc))
		}
		targetDir := resolvedDst
		if dstFi, stErr := sc.Stat(resolvedDst); stErr == nil && dstFi.IsDir() {
			srcBase := filepath.Base(absSrc)
			trimmedRaw := strings.TrimSpace(rawRemoteDst)
			if trimmedRaw == "" || trimmedRaw == "." || trimmedRaw == "~" ||
				strings.HasSuffix(trimmedRaw, "/") || path.Base(resolvedDst) != srcBase {
				targetDir = path.Join(resolvedDst, srcBase)
			}
		}
		if err := uploadDirRecursive(ctx, sc, fileRoots, absSrc, targetDir, opts, res); err != nil {
			return res, err
		}
	} else {
		if !srcFi.Mode().IsRegular() {
			return nil, errs.New("FILE_TYPE", "仅支持上传常规文件或目录："+localSrc)
		}
		targetFile := resolvedDst
		trimmedRaw := strings.TrimSpace(rawRemoteDst)
		isDirHint := trimmedRaw == "" || trimmedRaw == "." || trimmedRaw == "~" || strings.HasSuffix(trimmedRaw, "/")
		if dstFi, stErr := sc.Stat(resolvedDst); stErr == nil && dstFi.IsDir() {
			targetFile = path.Join(resolvedDst, filepath.Base(absSrc))
		} else if isDirHint {
			targetFile = path.Join(resolvedDst, filepath.Base(absSrc))
		}
		if err := uploadSingleFile(ctx, sc, fileRoots, absSrc, srcFi, targetFile, opts, res); err != nil {
			return res, err
		}
	}

	dur := time.Since(started)
	res.DurationSeconds = math.Round(dur.Seconds()*1000) / 1000
	res.DurationMs = dur.Milliseconds()
	return res, nil
}

func uploadDirRecursive(
	ctx context.Context,
	sc *sftp.Client,
	fileRoots []string,
	localDir string,
	remoteDir string,
	opts TransferOptions,
	res *TransferResult,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(fileRoots) > 0 {
		if _, err := CheckedScopedPath(sc, fileRoots, remoteDir, true); err != nil {
			return err
		}
	}
	if err := sc.MkdirAll(remoteDir); err != nil {
		return errs.New("SFTP_MKDIR", "无法创建远端目录："+remoteDir)
	}
	res.DirsCount++

	entries, err := os.ReadDir(localDir)
	if err != nil {
		return errs.New("FILE_READ", "无法读取本地目录："+localDir)
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		localChild := filepath.Join(localDir, name)
		remoteChild := path.Join(remoteDir, name)

		fi, lErr := os.Lstat(localChild)
		if lErr != nil {
			return errs.New("FILE_READ", "无法读取本地路径状态："+localChild)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			res.SkippedSymlinks = append(res.SkippedSymlinks, localChild)
			if opts.ProgressOut != nil && !opts.Quiet {
				_, _ = fmt.Fprintf(opts.ProgressOut, "! 跳过软链接：%s\n", localChild)
			}
			continue
		}
		if fi.IsDir() {
			if err := uploadDirRecursive(ctx, sc, fileRoots, localChild, remoteChild, opts, res); err != nil {
				return err
			}
			continue
		}
		if fi.Mode().IsRegular() {
			if err := uploadSingleFile(ctx, sc, fileRoots, localChild, fi, remoteChild, opts, res); err != nil {
				return err
			}
		}
	}
	return nil
}

func uploadSingleFile(
	ctx context.Context,
	sc *sftp.Client,
	fileRoots []string,
	localFile string,
	srcFi os.FileInfo,
	remoteFile string,
	opts TransferOptions,
	res *TransferResult,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if opts.MaxBytes > 0 && srcFi.Size() > opts.MaxBytes {
		return errs.New("FILE_LIMIT", fmt.Sprintf("文件 %s (%s) 超过单次大小限制 (%s)。",
			filepath.Base(localFile), FormatBytes(srcFi.Size()), FormatBytes(opts.MaxBytes)))
	}
	if len(fileRoots) > 0 {
		checked, err := CheckedScopedPath(sc, fileRoots, remoteFile, true)
		if err != nil {
			return err
		}
		remoteFile = checked
	}

	overwriting := false
	if existingFi, lErr := sc.Lstat(remoteFile); lErr == nil && existingFi != nil {
		if existingFi.IsDir() {
			return errs.New("IS_DIRECTORY", fmt.Sprintf("远端目标 %s 是已存在的目录，无法覆盖为文件。", remoteFile))
		}
		if !opts.Overwrite {
			if !opts.Interactive || opts.ConfirmOverwrite == nil {
				return errs.New("FILE_EXISTS", fmt.Sprintf("远端文件 %s 已存在；请使用 -f（或 overwrite=true）显式覆盖。", remoteFile))
			}
			ok, cErr := opts.ConfirmOverwrite(fmt.Sprintf("远端文件 %s (%s) 已存在，是否覆盖？[y/N]：", remoteFile, FormatBytes(existingFi.Size())))
			if cErr != nil {
				return cErr
			}
			if !ok {
				return errs.New("FILE_EXISTS", "已取消覆盖远端文件："+remoteFile)
			}
		}
		overwriting = true
	}

	srcHandle, err := os.Open(localFile)
	if err != nil {
		return errs.New("FILE_READ", "无法打开本地文件："+localFile)
	}
	defer srcHandle.Close()

	partPath := remoteFile + ".js-partial"
	// 若存在上次中断遗留的同名 .js-partial，先移除以避免 KoKo SFTP_IS_OVERWRITE_FILE=false 静默改名
	_ = sc.Remove(partPath)

	dstHandle, err := sc.OpenFile(partPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return errs.New("SFTP_WRITE", fmt.Sprintf("无法在远端创建临时文件 %s（请检查目录是否存在及上传权限）。", partPath))
	}

	prog := newProgressTracker("上传", filepath.Base(localFile), srcFi.Size(), opts.ProgressOut, opts.Quiet)
	written, copyErr := streamWithContext(ctx, srcHandle, dstHandle, opts.MaxBytes, prog)
	closeErr := dstHandle.Close()
	if copyErr != nil || closeErr != nil {
		if errors.Is(copyErr, context.Canceled) {
			return errs.New("SFTP_WRITE_UNCERTAIN", fmt.Sprintf("上传已取消，未自动重试；远端可能留有残留文件：%s", partPath))
		}
		if be, ok := errs.As(copyErr); ok {
			return be
		}
		return errs.New("SFTP_WRITE_UNCERTAIN", fmt.Sprintf("上传写入中断或失败，未自动重试；远端残留文件位置：%s", partPath))
	}

	// 若覆盖已有目标文件，先删除原目标文件再将 .js-partial 重命名过去（兼容标准 SFTP v3 与 KoKo）
	if overwriting {
		if rmErr := sc.Remove(remoteFile); rmErr != nil {
			return errs.New("SFTP_WRITE_UNCERTAIN", fmt.Sprintf("无法移除待覆盖的远端旧文件 %s（新内容保存在 %s，未自动重试）。", remoteFile, partPath))
		}
	}
	if renErr := sc.Rename(partPath, remoteFile); renErr != nil {
		if posErr := sc.PosixRename(partPath, remoteFile); posErr != nil {
			return errs.New("SFTP_WRITE_UNCERTAIN", fmt.Sprintf("临时文件已写入 %s，但重命名为 %s 失败；未自动重试。", partPath, remoteFile))
		}
	}

	prog.finish(written)
	res.FilesCount++
	res.TotalBytes += written
	res.Items = append(res.Items, TransferItemResult{
		Source:      localFile,
		Destination: remoteFile,
		Bytes:       written,
		Overwritten: overwriting,
	})
	return nil
}

// DownloadPath 执行远端 SFTP 文件或目录（-r）到本地的流式下载。
// 遵循约定：
// - 默认不跟随远端软链接；
// - 先写本地 `<目标>.js-partial`（0600 权限），完整落盘后再原子重命名为最终文件名；
// - 本地目标已存在时：-f 直接覆盖，交互模式询问确认，非交互且无 -f 报错；
// - 失败不自动重试，提示本地 `.js-partial` 残留位置。
func DownloadPath(
	ctx context.Context,
	sc *sftp.Client,
	rootCtx *SFTPRootContext,
	fileRoots []string,
	rawRemoteSrc string,
	localDst string,
	opts TransferOptions,
) (*TransferResult, error) {
	started := time.Now()
	resolvedSrc, err := ResolveRemotePath(sc, rootCtx, fileRoots, rawRemoteSrc, false)
	if err != nil {
		return nil, err
	}

	srcFi, err := sc.Lstat(resolvedSrc)
	if err != nil {
		return nil, errs.New("FILE_NOT_FOUND", "远端源文件或目录不存在或无权访问："+resolvedSrc)
	}
	if srcFi.Mode()&os.ModeSymlink != 0 {
		return nil, errs.New("SYMLINK_SKIPPED", "默认不跟随远端软链接："+resolvedSrc)
	}

	absDst, err := filepath.Abs(localDst)
	if err != nil {
		return nil, errs.New("FILE_PATH", "本地目标路径无效："+localDst)
	}

	res := &TransferResult{
		Direction: "download",
	}

	if srcFi.IsDir() {
		if !opts.Recursive {
			return nil, errs.New("IS_DIRECTORY", fmt.Sprintf("远端源路径 %s 是目录，请使用 -r 递归下载。", resolvedSrc))
		}
		targetLocalDir := absDst
		if dstFi, stErr := os.Stat(absDst); stErr == nil && dstFi.IsDir() {
			srcBase := path.Base(resolvedSrc)
			trimmedRaw := strings.TrimSpace(localDst)
			if trimmedRaw == "." || trimmedRaw == "./" || trimmedRaw == `.\` ||
				strings.HasSuffix(trimmedRaw, "/") || strings.HasSuffix(trimmedRaw, `\`) ||
				filepath.Base(absDst) != srcBase {
				targetLocalDir = filepath.Join(absDst, srcBase)
			}
		}
		if err := downloadDirRecursive(ctx, sc, fileRoots, resolvedSrc, targetLocalDir, opts, res); err != nil {
			return res, err
		}
	} else {
		if !srcFi.Mode().IsRegular() {
			return nil, errs.New("FILE_TYPE", "仅支持下载远端常规文件或目录："+resolvedSrc)
		}
		targetLocalFile := absDst
		trimmedRaw := strings.TrimSpace(localDst)
		isDirHint := trimmedRaw == "." || trimmedRaw == "./" || trimmedRaw == `.\` ||
			strings.HasSuffix(trimmedRaw, "/") || strings.HasSuffix(trimmedRaw, `\`)
		if dstFi, stErr := os.Stat(absDst); stErr == nil && dstFi.IsDir() {
			targetLocalFile = filepath.Join(absDst, path.Base(resolvedSrc))
		} else if isDirHint {
			targetLocalFile = filepath.Join(absDst, path.Base(resolvedSrc))
		}
		if err := downloadSingleFile(ctx, sc, fileRoots, resolvedSrc, srcFi, targetLocalFile, opts, res); err != nil {
			return res, err
		}
	}

	dur := time.Since(started)
	res.DurationSeconds = math.Round(dur.Seconds()*1000) / 1000
	res.DurationMs = dur.Milliseconds()
	return res, nil
}

func downloadDirRecursive(
	ctx context.Context,
	sc *sftp.Client,
	fileRoots []string,
	remoteDir string,
	localDir string,
	opts TransferOptions,
	res *TransferResult,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(fileRoots) > 0 {
		if _, err := CheckedScopedPath(sc, fileRoots, remoteDir, false); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(localDir, 0o700); err != nil {
		return errs.New("FILE_WRITE", "无法创建本地目录："+localDir)
	}
	res.DirsCount++

	entries, err := sc.ReadDir(remoteDir)
	if err != nil {
		return errs.New("SFTP_READ", "无法列举远端目录："+remoteDir)
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
			continue
		}
		remoteChild := path.Join(remoteDir, name)
		localChild := filepath.Join(localDir, name)

		// 使用 Lstat 准确识别软链接，不跟随软链接
		fi, lErr := sc.Lstat(remoteChild)
		if lErr != nil {
			fi = entry
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			res.SkippedSymlinks = append(res.SkippedSymlinks, remoteChild)
			if opts.ProgressOut != nil && !opts.Quiet {
				_, _ = fmt.Fprintf(opts.ProgressOut, "! 跳过远端软链接：%s\n", remoteChild)
			}
			continue
		}
		if fi.IsDir() {
			if err := downloadDirRecursive(ctx, sc, fileRoots, remoteChild, localChild, opts, res); err != nil {
				return err
			}
			continue
		}
		if fi.Mode().IsRegular() {
			if err := downloadSingleFile(ctx, sc, fileRoots, remoteChild, fi, localChild, opts, res); err != nil {
				return err
			}
		}
	}
	return nil
}

func downloadSingleFile(
	ctx context.Context,
	sc *sftp.Client,
	fileRoots []string,
	remoteFile string,
	srcFi os.FileInfo,
	localFile string,
	opts TransferOptions,
	res *TransferResult,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if opts.MaxBytes > 0 && srcFi.Size() > opts.MaxBytes {
		return errs.New("FILE_LIMIT", fmt.Sprintf("远端文件 %s (%s) 超过单次大小限制 (%s)。",
			path.Base(remoteFile), FormatBytes(srcFi.Size()), FormatBytes(opts.MaxBytes)))
	}
	if len(fileRoots) > 0 {
		checked, err := CheckedScopedPath(sc, fileRoots, remoteFile, false)
		if err != nil {
			return err
		}
		remoteFile = checked
	}

	overwriting := false
	if existingFi, lErr := os.Lstat(localFile); lErr == nil && existingFi != nil {
		if existingFi.IsDir() {
			return errs.New("IS_DIRECTORY", fmt.Sprintf("本地目标 %s 是已存在的目录，无法覆盖为文件。", localFile))
		}
		if !opts.Overwrite {
			if !opts.Interactive || opts.ConfirmOverwrite == nil {
				return errs.New("FILE_EXISTS", fmt.Sprintf("本地文件 %s 已存在；请使用 -f（或 overwrite=true）显式覆盖。", localFile))
			}
			ok, cErr := opts.ConfirmOverwrite(fmt.Sprintf("本地文件 %s (%s) 已存在，是否覆盖？[y/N]：", localFile, FormatBytes(existingFi.Size())))
			if cErr != nil {
				return cErr
			}
			if !ok {
				return errs.New("FILE_EXISTS", "已取消覆盖本地文件："+localFile)
			}
		}
		overwriting = true
	}

	parentDir := filepath.Dir(localFile)
	if _, pErr := os.Stat(parentDir); pErr != nil {
		return errs.New("FILE_PATH", "本地目标父目录不存在："+parentDir)
	}

	remoteHandle, err := sc.Open(remoteFile)
	if err != nil {
		return errs.New("SFTP_READ", "无法打开远端文件："+remoteFile)
	}
	defer remoteHandle.Close()

	partPath := localFile + ".js-partial"
	localHandle, err := os.OpenFile(partPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return errs.New("FILE_WRITE", "无法创建本地临时文件："+partPath)
	}

	prog := newProgressTracker("下载", path.Base(remoteFile), srcFi.Size(), opts.ProgressOut, opts.Quiet)
	written, copyErr := streamWithContext(ctx, remoteHandle, localHandle, opts.MaxBytes, prog)
	syncErr := localHandle.Sync()
	closeErr := localHandle.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		if errors.Is(copyErr, context.Canceled) {
			return errs.New("SFTP_READ", fmt.Sprintf("下载已取消，未自动重试；本地残留文件：%s", partPath))
		}
		if be, ok := errs.As(copyErr); ok {
			return be
		}
		return errs.New("SFTP_READ", fmt.Sprintf("下载读取中断或失败，未自动重试；本地残留文件：%s", partPath))
	}

	if err := os.Rename(partPath, localFile); err != nil {
		return errs.New("FILE_WRITE", fmt.Sprintf("下载已完成临时文件 %s，但重命名为 %s 失败。", partPath, localFile))
	}

	prog.finish(written)
	res.FilesCount++
	res.TotalBytes += written
	res.Items = append(res.Items, TransferItemResult{
		Source:      remoteFile,
		Destination: localFile,
		Bytes:       written,
		Overwritten: overwriting,
	})
	return nil
}

func streamWithContext(
	ctx context.Context,
	r io.Reader,
	w io.Writer,
	maxBytes int64,
	prog *progressTracker,
) (int64, error) {
	buf := make([]byte, transferChunkBytes)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, rErr := r.Read(buf)
		if n > 0 {
			total += int64(n)
			if maxBytes > 0 && total > maxBytes {
				return total, errs.New("FILE_LIMIT", fmt.Sprintf("文件大小超过限制 (%s)。", FormatBytes(maxBytes)))
			}
			written := 0
			for written < n {
				wn, wErr := w.Write(buf[written:n])
				if wn > 0 {
					written += wn
				}
				if wErr != nil {
					return total, wErr
				}
			}
			prog.update(total)
		}
		if rErr != nil {
			if errors.Is(rErr, io.EOF) {
				return total, nil
			}
			return total, rErr
		}
	}
}

type progressTracker struct {
	action     string
	name       string
	total      int64
	out        io.Writer
	quiet      bool
	start      time.Time
	lastRender time.Time
}

func newProgressTracker(action, name string, total int64, out io.Writer, quiet bool) *progressTracker {
	now := time.Now()
	return &progressTracker{
		action: action,
		name:   name,
		total:  total,
		out:    out,
		quiet:  quiet || out == nil,
		start:  now,
	}
}

func (p *progressTracker) update(current int64) {
	if p.quiet {
		return
	}
	now := time.Now()
	if !p.lastRender.IsZero() && now.Sub(p.lastRender) < 120*time.Millisecond {
		return
	}
	p.lastRender = now
	p.render(current, false)
}

func (p *progressTracker) finish(current int64) {
	if p.quiet {
		return
	}
	p.render(current, true)
}

func (p *progressTracker) render(current int64, done bool) {
	elapsed := time.Since(p.start).Seconds()
	if elapsed <= 0 {
		elapsed = 0.001
	}
	speed := float64(current) / elapsed
	var pct float64 = 100
	var etaStr string
	if p.total > 0 {
		pct = float64(current) * 100 / float64(p.total)
		if pct > 100 {
			pct = 100
		}
		if !done && speed > 0 && current < p.total {
			remSec := int(math.Ceil(float64(p.total-current) / speed))
			etaStr = fmt.Sprintf("  ETA %02d:%02d", remSec/60, remSec%60)
		}
	}
	suffix := "\r"
	if done {
		suffix = "\n"
	}
	_, _ = fmt.Fprintf(
		p.out,
		"\r%s %-24s %10s / %-10s (%5.1f%%)  %10s/s%s%s",
		p.action,
		truncateMiddle(p.name, 24),
		FormatBytes(current),
		FormatBytes(p.total),
		pct,
		FormatBytes(int64(speed)),
		etaStr,
		suffix,
	)
}

func truncateMiddle(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen || maxLen < 6 {
		return s
	}
	head := (maxLen - 3) / 2
	tail := maxLen - 3 - head
	return string(runes[:head]) + "..." + string(runes[len(runes)-tail:])
}

func FormatBytes(b int64) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	val := float64(b)
	for _, u := range units {
		val /= 1024
		if val < 1024 || u == "TiB" {
			return fmt.Sprintf("%.1f %s", val, u)
		}
	}
	return fmt.Sprintf("%d B", b)
}
