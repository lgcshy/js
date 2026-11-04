//go:build !windows

package credentials

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/lgcshy/js/internal/errs"
)

// ReadProtectedFile 只读取当前用户持有、权限不超过 0600 的常规文件，拒绝软链接与过宽权限。
func ReadProtectedFile(path string, maxBytes int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, os.ErrNotExist
		}
		return nil, errs.New("SECRET_FILE", "无法读取指定凭据文件。")
	}
	if !info.Mode().IsRegular() {
		return nil, errs.New("SECRET_FILE", "凭据路径必须是常规文件，不能是软链接。")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if ok && int(st.Uid) != os.Getuid() {
		return nil, errs.New("SECRET_OWNER", "凭据文件必须归当前操作系统用户所有。")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errs.Action(
			"SECRET_PERMISSIONS",
			"凭据文件权限过宽，已拒绝读取。",
			fmt.Sprintf("请执行 chmod 600 %s", path),
		)
	}
	if info.Size() > maxBytes {
		return nil, errs.New("SECRET_FILE", "凭据文件过大。")
	}

	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errs.New("SECRET_FILE", "无法安全打开凭据文件（可能存在软链接）。")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()

	fInfo, err := f.Stat()
	if err != nil || !fInfo.Mode().IsRegular() {
		return nil, errs.New("SECRET_FILE", "凭据路径必须是常规文件。")
	}
	if fSt, ok := fInfo.Sys().(*syscall.Stat_t); ok && int(fSt.Uid) != os.Getuid() {
		return nil, errs.New("SECRET_OWNER", "凭据文件必须归当前操作系统用户所有。")
	}
	if fInfo.Mode().Perm()&0o077 != 0 {
		return nil, errs.Action(
			"SECRET_PERMISSIONS",
			"凭据文件权限过宽，已拒绝读取。",
			fmt.Sprintf("请执行 chmod 600 %s", path),
		)
	}
	if fInfo.Size() > maxBytes {
		return nil, errs.New("SECRET_FILE", "凭据文件过大。")
	}

	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, errs.New("SECRET_FILE", "读取凭据文件失败。")
	}
	if int64(len(data)) > maxBytes {
		return nil, errs.New("SECRET_FILE", "凭据文件过大。")
	}
	return data, nil
}
