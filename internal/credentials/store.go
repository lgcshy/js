package credentials

import (
	"context"
	"errors"
	"strings"

	"github.com/lgcshy/js/internal/errs"
)

var ErrNotFound = errors.New("credential not found")

type Store interface {
	Name() string
	Available(ctx context.Context, interactive bool) error
	Get(ctx context.Context, service, key string, interactive bool) (string, error)
	Set(ctx context.Context, service, key, secret string, interactive bool) error
	Delete(ctx context.Context, service, key string, interactive bool) error
}

func ServiceName(origin string) string {
	return "js:" + strings.TrimRight(strings.TrimSpace(origin), "/")
}

func AccessKeyEntry(username string) string {
	return "ak:" + strings.TrimSpace(username)
}

func TargetEntry(assetID, username, canonicalTarget string) string {
	if strings.TrimSpace(assetID) != "" && strings.TrimSpace(username) != "" {
		return strings.TrimSpace(assetID) + "/" + strings.TrimSpace(username)
	}
	return "target:" + strings.TrimSpace(canonicalTarget)
}

func TargetFallbackEntry(canonicalTarget string) string {
	return "target:" + strings.TrimSpace(canonicalTarget)
}

func KeyPassphraseEntry(canonicalTarget string) string {
	return "keypass:" + strings.TrimSpace(canonicalTarget)
}

func FormatAccessKeySecret(id, secret string) string {
	return strings.TrimSpace(id) + ":" + strings.TrimSpace(secret)
}

func ParseAccessKeySecret(raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if idx := strings.IndexByte(raw, ':'); idx > 0 && idx < len(raw)-1 && !strings.ContainsAny(raw, "\r\n") {
		id := strings.TrimSpace(raw[:idx])
		sec := strings.TrimSpace(raw[idx+1:])
		if id != "" && sec != "" {
			return id, sec, nil
		}
	}
	// 兼容两行 ID: xxx / Secret: yyy 文件格式
	var id, sec string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		sep := strings.IndexAny(line, ":=")
		if sep <= 0 {
			return "", "", errs.New("ACCESS_KEY_FORMAT", "Access Key 格式无效，需包含 ID 和 Secret。")
		}
		k := strings.ToLower(strings.TrimSpace(line[:sep]))
		v := strings.TrimSpace(line[sep+1:])
		switch k {
		case "id", "access_key_id", "key_id":
			id = v
		case "secret", "access_key_secret", "key_secret":
			sec = v
		}
	}
	if id == "" || sec == "" {
		return "", "", errs.New("ACCESS_KEY_FORMAT", "Access Key 需同时提供 ID 和 Secret。")
	}
	return id, sec, nil
}

// MigrateStore 将已知条目从旧存储复制到新存储，全部写入成功后再删除旧副本。
func MigrateStore(ctx context.Context, src, dst Store, service string, keys []string, interactive bool) (int, error) {
	if src.Name() == dst.Name() {
		return 0, nil
	}
	if err := dst.Available(ctx, interactive); err != nil {
		return 0, err
	}
	copied := make([]string, 0, len(keys))
	for _, k := range keys {
		val, err := src.Get(ctx, service, k, interactive)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}
			return 0, err
		}
		if err := dst.Set(ctx, service, k, val, interactive); err != nil {
			return 0, err
		}
		copied = append(copied, k)
	}
	for _, k := range copied {
		_ = src.Delete(ctx, service, k, interactive)
	}
	return len(copied), nil
}
