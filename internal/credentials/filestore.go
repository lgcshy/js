package credentials

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/lgcshy/js/internal/config"
	"github.com/lgcshy/js/internal/errs"
)

const maxSecretsFileSize = 256 * 1024

// FileStore 在 Linux/Unix 上以 0700 目录 + 0600 常规文件保存秘密，需用户显式启用。
type FileStore struct {
	Path          string
	allowAnyOS    bool // 仅供跨平台单元测试显式打开
}

func NewFileStore(configDir string) *FileStore {
	return &FileStore{
		Path: filepath.Join(configDir, "secrets.json"),
	}
}

func (s *FileStore) Name() string {
	return "file"
}

func (s *FileStore) Available(_ context.Context, _ bool) error {
	if runtime.GOOS == "windows" && !s.allowAnyOS {
		return errs.New("STORE_UNSUPPORTED", "0600 文件存储仅支持 Linux/Unix；Windows 请使用系统凭据管理器。")
	}
	if _, err := os.Lstat(s.Path); err == nil {
		if _, readErr := ReadProtectedFile(s.Path, maxSecretsFileSize); readErr != nil {
			return readErr
		}
	}
	return nil
}

func (s *FileStore) Get(ctx context.Context, service, key string, interactive bool) (string, error) {
	if err := s.Available(ctx, interactive); err != nil {
		return "", err
	}
	var secret string
	var found bool
	err := config.WithFileLock(s.Path+".lock", func() error {
		all, err := s.loadUnlocked()
		if err != nil {
			return err
		}
		if svcMap, ok := all[service]; ok {
			secret, found = svcMap[key]
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if !found || secret == "" {
		return "", ErrNotFound
	}
	return secret, nil
}

func (s *FileStore) Set(ctx context.Context, service, key, secret string, interactive bool) error {
	if runtime.GOOS == "windows" && !s.allowAnyOS {
		return errs.New("STORE_UNSUPPORTED", "0600 文件存储仅支持 Linux/Unix；Windows 请使用系统凭据管理器。")
	}
	if secret == "" {
		return errs.New("EMPTY_SECRET", "不能保存空凭据。")
	}
	if len(secret) > 8192 {
		return errs.New("SECRET_TOO_LARGE", "凭据长度超出限制。")
	}
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errs.New("SECRET_WRITE", "无法创建凭据目录。")
	}
	_ = os.Chmod(dir, 0o700)

	return config.WithFileLock(s.Path+".lock", func() error {
		all, err := s.loadUnlocked()
		if err != nil {
			return err
		}
		if all[service] == nil {
			all[service] = map[string]string{}
		}
		all[service][key] = secret
		return s.saveUnlocked(all)
	})
}

func (s *FileStore) Delete(ctx context.Context, service, key string, interactive bool) error {
	if runtime.GOOS == "windows" && !s.allowAnyOS {
		return errs.New("STORE_UNSUPPORTED", "0600 文件存储仅支持 Linux/Unix；Windows 请使用系统凭据管理器。")
	}
	if _, err := os.Lstat(s.Path); os.IsNotExist(err) {
		return nil
	}
	return config.WithFileLock(s.Path+".lock", func() error {
		all, err := s.loadUnlocked()
		if err != nil {
			return err
		}
		if svcMap, ok := all[service]; ok {
			delete(svcMap, key)
			if len(svcMap) == 0 {
				delete(all, service)
			}
		}
		return s.saveUnlocked(all)
	})
}

func (s *FileStore) loadUnlocked() (map[string]map[string]string, error) {
	raw, err := ReadProtectedFile(s.Path, maxSecretsFileSize)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]map[string]string{}, nil
		}
		return nil, err
	}
	if len(raw) == 0 {
		return map[string]map[string]string{}, nil
	}
	var all map[string]map[string]string
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil, errs.New("SECRET_FILE_CORRUPT", "secrets.json 格式损坏，无法解析。")
	}
	if all == nil {
		all = map[string]map[string]string{}
	}
	return all, nil
}

func (s *FileStore) saveUnlocked(all map[string]map[string]string) error {
	var randBuf [8]byte
	_, _ = rand.Read(randBuf[:])
	tmpPath := fmt.Sprintf("%s.%s.tmp", s.Path, hex.EncodeToString(randBuf[:]))

	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errs.New("SECRET_WRITE", "无法创建临时凭据文件。")
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	_ = f.Chmod(0o600)

	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(all); err != nil {
		_ = f.Close()
		return errs.New("SECRET_WRITE", "写入凭据文件失败。")
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return errs.New("SECRET_WRITE", "同步凭据文件失败。")
	}
	if err := f.Close(); err != nil {
		return errs.New("SECRET_WRITE", "关闭凭据文件失败。")
	}
	if err := os.Rename(tmpPath, s.Path); err != nil {
		return errs.New("SECRET_WRITE", "原子更新凭据文件失败。")
	}
	cleanup = false
	return nil
}
