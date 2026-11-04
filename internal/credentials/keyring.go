package credentials

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/lgcshy/js/internal/errs"
)

const (
	maxKeyringSecretBytes     = 2048 // 低于 Windows Credential Manager 2560 字节及 macOS 4096 字节上限
	interactiveKeyringTimeout = 30 * time.Second
	nonInteractiveTimeout     = 5 * time.Second
)

type KeyringStore struct {
	InteractiveTimeout    time.Duration
	NonInteractiveTimeout time.Duration
}

func NewKeyringStore() *KeyringStore {
	return &KeyringStore{
		InteractiveTimeout:    interactiveKeyringTimeout,
		NonInteractiveTimeout: nonInteractiveTimeout,
	}
}

func (k *KeyringStore) Name() string {
	return "keyring"
}

func (k *KeyringStore) timeout(interactive bool) time.Duration {
	if interactive {
		if k.InteractiveTimeout > 0 {
			return k.InteractiveTimeout
		}
		return interactiveKeyringTimeout
	}
	if k.NonInteractiveTimeout > 0 {
		return k.NonInteractiveTimeout
	}
	return nonInteractiveTimeout
}

func (k *KeyringStore) Available(ctx context.Context, interactive bool) error {
	return checkPlatformKeyring(ctx, interactive)
}

func (k *KeyringStore) Get(ctx context.Context, service, key string, interactive bool) (string, error) {
	if err := k.Available(ctx, interactive); err != nil {
		return "", err
	}
	type res struct {
		val string
		err error
	}
	ch := make(chan res, 1)
	go func() {
		v, err := keyring.Get(service, key)
		ch <- res{val: v, err: err}
	}()

	tctx, cancel := context.WithTimeout(ctx, k.timeout(interactive))
	defer cancel()

	select {
	case r := <-ch:
		if r.err != nil {
			if errors.Is(r.err, keyring.ErrNotFound) {
				return "", ErrNotFound
			}
			return "", errs.Action("KEYRING", "无法从系统凭据库读取凭据（可能未解锁或已拒绝授权）。", "请确认凭据库已解锁，或在无桌面 Linux 使用 --store file")
		}
		return r.val, nil
	case <-tctx.Done():
		return "", errs.Action("KEYRING_TIMEOUT", "等待系统凭据库响应或解锁超时。", "请先在桌面环境中解锁系统凭据库")
	}
}

func (k *KeyringStore) Set(ctx context.Context, service, key, secret string, interactive bool) error {
	if secret == "" {
		return errs.New("EMPTY_SECRET", "不能保存空凭据。")
	}
	if len(secret) > maxKeyringSecretBytes {
		return errs.New("SECRET_TOO_LARGE", "凭据超过系统凭据库单条长度上限，请勿存入完整私钥。")
	}
	if err := k.Available(ctx, interactive); err != nil {
		return err
	}
	ch := make(chan error, 1)
	go func() {
		ch <- keyring.Set(service, key, secret)
	}()

	tctx, cancel := context.WithTimeout(ctx, k.timeout(interactive))
	defer cancel()

	select {
	case err := <-ch:
		if err != nil {
			return errs.Action("KEYRING", "写入系统凭据库失败。", "若当前为无桌面 Linux，可使用 js init --store file")
		}
		return nil
	case <-tctx.Done():
		return errs.Action("KEYRING_TIMEOUT", "等待系统凭据库写入或解锁超时。", "请先解锁系统凭据库，或使用 js init --store file")
	}
}

func (k *KeyringStore) Delete(ctx context.Context, service, key string, interactive bool) error {
	if err := k.Available(ctx, interactive); err != nil {
		return err
	}
	ch := make(chan error, 1)
	go func() {
		ch <- keyring.Delete(service, key)
	}()

	tctx, cancel := context.WithTimeout(ctx, k.timeout(interactive))
	defer cancel()

	select {
	case err := <-ch:
		if err != nil && !errors.Is(err, keyring.ErrNotFound) {
			return errs.New("KEYRING", "从系统凭据库删除条目失败。")
		}
		return nil
	case <-tctx.Done():
		return errs.Action("KEYRING_TIMEOUT", "等待系统凭据库删除响应超时。", "请确认系统凭据库已解锁")
	}
}

// MemoryStore 用于单元测试和会话内临时存储，不落盘、不依赖桌面凭据服务。
type MemoryStore struct {
	mu   sync.RWMutex
	data map[string]map[string]string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{data: map[string]map[string]string{}}
}

func (m *MemoryStore) Name() string                               { return "memory" }
func (m *MemoryStore) Available(_ context.Context, _ bool) error  { return nil }

func (m *MemoryStore) Get(_ context.Context, service, key string, _ bool) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if svc, ok := m.data[service]; ok {
		if v, exists := svc[key]; exists && v != "" {
			return v, nil
		}
	}
	return "", ErrNotFound
}

func (m *MemoryStore) Set(_ context.Context, service, key, secret string, _ bool) error {
	if secret == "" {
		return errs.New("EMPTY_SECRET", "不能保存空凭据。")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data[service] == nil {
		m.data[service] = map[string]string{}
	}
	m.data[service][key] = secret
	return nil
}

func (m *MemoryStore) Delete(_ context.Context, service, key string, _ bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if svc, ok := m.data[service]; ok {
		delete(svc, key)
	}
	return nil
}
