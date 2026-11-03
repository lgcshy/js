//go:build windows

package credentials

import (
	"io"
	"os"

	"jsbridge/internal/errs"
)

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
	if info.Size() > maxBytes {
		return nil, errs.New("SECRET_FILE", "凭据文件过大。")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errs.New("SECRET_FILE", "无法打开指定凭据文件。")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, errs.New("SECRET_FILE", "读取凭据文件失败。")
	}
	if int64(len(data)) > maxBytes {
		return nil, errs.New("SECRET_FILE", "凭据文件过大。")
	}
	return data, nil
}
