package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"jsbridge/internal/errs"
)

const AppDirName = "jsbridge"

var (
	targetUserRegex = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}\$?$`)

	ReservedCommands = map[string]struct{}{
		"init":        {},
		"login":       {},
		"logout":      {},
		"status":      {},
		"hosts":       {},
		"connect":     {},
		"exec":        {},
		"rsh":         {},
		"cp":          {},
		"scp":         {},
		"passwd":      {},
		"credential":  {},
		"forget":      {},
		"bind-gopass": {},
		"bind-key":    {},
		"alias":       {},
		"unalias":     {},
		"doctor":      {},
		"fingerprint": {},
		"trust":       {},
		"inspect":     {},
		"store":       {},
		"completion":  {},
		"mcp":         {},
		"version":     {},
		"help":        {},
	}
)

type CredentialConfig struct {
	Type                string `json:"type"` // "store", "keyring", "file", "gopass", "ssh_key", "managed", "prompt"
	Ref                 string `json:"ref,omitempty"`
	Path                string `json:"path,omitempty"`
	SubmitToJumpServer  bool   `json:"submit_to_jumpserver,omitempty"`
	PassphraseGopassRef string `json:"passphrase_gopass_ref,omitempty"`
	PassphraseStored    bool   `json:"passphrase_stored,omitempty"`
	ManagedAccount      string `json:"managed_account,omitempty"`
}

type TargetConfig struct {
	AssetID    string           `json:"asset_id,omitempty"`
	AssetName  string           `json:"asset_name,omitempty"`
	Credential CredentialConfig `json:"credential"`
	FileRoots  []string         `json:"file_roots,omitempty"`
}

type Data struct {
	CoreURL             string                  `json:"core_url"`
	JumpServerUser      string                  `json:"jumpserver_user"`
	OrgID               string                  `json:"org_id,omitempty"`
	CAFile              string                  `json:"ca_file,omitempty"`
	ProxyURL            string                  `json:"proxy_url,omitempty"`
	KoKoHost            string                  `json:"koko_host"`
	KoKoPort            int                     `json:"koko_port"`
	KoKoHostFingerprint string                  `json:"koko_host_fingerprint,omitempty"`
	KnownHostsFiles     []string                `json:"known_hosts_files,omitempty"`
	CredentialStore     string                  `json:"credential_store,omitempty"` // "keyring" (default) or "file"
	AccessKeyFile       string                  `json:"access_key_file,omitempty"`
	CreatedAKID         string                  `json:"created_ak_id,omitempty"`
	SavePasswordPolicy  string                  `json:"save_password_policy,omitempty"` // "always" (default), "ask", "never"
	Generation          int64                   `json:"generation"`
	Aliases             map[string]string       `json:"aliases,omitempty"`
	Targets             map[string]TargetConfig `json:"targets,omitempty"`
	StoredCredentials   []string                `json:"stored_credentials,omitempty"`
}

type Config struct {
	Path   string
	Origin string
	Data   Data
}

type ResolvedTarget struct {
	Canonical string
	Username  string
	Address   string
	Entry     TargetConfig
}

func DefaultConfigDir() (string, error) {
	if env := strings.TrimSpace(os.Getenv("JSBRIDGE_CONFIG_DIR")); env != "" {
		return filepath.Abs(ExpandHome(env))
	}
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		return "", errs.New("CONFIG_DIR", "无法确定当前用户的配置目录。")
	}
	return filepath.Join(base, AppDirName), nil
}

func DefaultConfigPath() (string, error) {
	dir, err := DefaultConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

func ExpandHome(p string) string {
	if p == "~" {
		if h, err := os.UserHomeDir(); err == nil {
			return h
		}
		return p
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, p[2:])
		}
	}
	return p
}

func ValidateCoreOrigin(raw string) (string, string, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(raw), "/")
	if trimmed == "" {
		return "", "", errs.New("CONFIG", "core_url 不能为空。")
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", "", errs.New("CONFIG", "core_url 必须是没有路径及凭据的 HTTPS 源站。")
	}
	return trimmed, u.Hostname(), nil
}

func Load(path string) (*Config, error) {
	if strings.TrimSpace(path) == "" {
		var err error
		path, err = DefaultConfigPath()
		if err != nil {
			return nil, err
		}
	}
	absPath, err := filepath.Abs(ExpandHome(path))
	if err != nil {
		return nil, errs.New("CONFIG", "配置路径无效。")
	}
	raw, err := os.ReadFile(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errs.Action("NOT_INITIALIZED", "尚未初始化配置。", "请先在本机终端运行 js init")
		}
		return nil, errs.New("CONFIG", "无法读取 JSON 配置。")
	}
	return Parse(absPath, raw)
}

func Parse(absPath string, raw []byte) (*Config, error) {
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil || probe == nil {
		return nil, errs.New("CONFIG", "配置必须是合法的 JSON 对象。")
	}
	var data Data
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, errs.New("CONFIG", "无法解析配置字段。")
	}
	origin, host, err := ValidateCoreOrigin(data.CoreURL)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(data.JumpServerUser) == "" {
		return nil, errs.New("CONFIG", "必须指定本人 JumpServer 用户名。")
	}
	if strings.TrimSpace(data.KoKoHost) == "" {
		data.KoKoHost = host
	}
	if data.KoKoPort <= 0 || data.KoKoPort > 65535 {
		if data.KoKoPort == 0 {
			data.KoKoPort = 2222
		} else {
			return nil, errs.New("CONFIG", "koko_port 端口范围无效。")
		}
	}
	if data.CredentialStore == "" {
		data.CredentialStore = "keyring"
	}
	if data.CredentialStore != "keyring" && data.CredentialStore != "file" {
		return nil, errs.New("CONFIG", "credential_store 只支持 keyring 或 file。")
	}
	if data.SavePasswordPolicy == "" {
		data.SavePasswordPolicy = "always"
	}
	switch data.SavePasswordPolicy {
	case "always", "ask", "never":
	default:
		return nil, errs.New("CONFIG", "save_password_policy 只支持 always、ask 或 never。")
	}
	if data.Aliases == nil {
		data.Aliases = map[string]string{}
	}
	if data.Targets == nil {
		data.Targets = map[string]TargetConfig{}
	}
	return &Config{
		Path:   absPath,
		Origin: origin,
		Data:   data,
	}, nil
}

func (c *Config) Dir() string {
	return filepath.Dir(c.Path)
}

func (c *Config) LocalPath(value string) string {
	expanded := ExpandHome(value)
	if filepath.IsAbs(expanded) {
		return expanded
	}
	return filepath.Join(c.Dir(), expanded)
}

func IsReservedCommand(name string) bool {
	_, ok := ReservedCommands[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

func (c *Config) SetAlias(alias, target string) (string, error) {
	alias = strings.TrimSpace(alias)
	if alias == "" || strings.ContainsAny(alias, " \t\r\n@:/\\") || strings.HasPrefix(alias, "-") {
		return "", errs.New("ALIAS_NAME", "别名格式无效，不能包含空白、@、:、/ 或以 - 开头。")
	}
	if IsReservedCommand(alias) {
		return "", errs.New("ALIAS_RESERVED", fmt.Sprintf("%q 是保留子命令名，不能用作别名。", alias))
	}
	if _, err := netip.ParseAddr(alias); err == nil {
		return "", errs.New("ALIAS_NAME", "别名不能直接写成 IP 地址。")
	}
	rt, _, err := c.ResolveTarget(target)
	if err != nil {
		return "", err
	}
	if c.Data.Aliases == nil {
		c.Data.Aliases = map[string]string{}
	}
	c.Data.Aliases[alias] = rt.Canonical
	return rt.Canonical, nil
}

// ResolveTarget 解析 `user@IP`、`别名` 或 `IP`。
// 当输入仅为 IP 且本地配置存在多个候选账号时，返回 candidates 供交互端选择，非交互直接返回错误。
func (c *Config) ResolveTarget(input string) (ResolvedTarget, []string, error) {
	value := strings.TrimSpace(input)
	if value == "" {
		return ResolvedTarget{}, nil, errs.New("TARGET_ADDRESS", "目标不能为空。")
	}
	if mapped, ok := c.Data.Aliases[value]; ok {
		value = mapped
	}
	if !strings.Contains(value, "@") {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return ResolvedTarget{}, nil, errs.New("TARGET_ADDRESS", "目标必须使用 user@IP、准确 IP 或已配置的别名。")
		}
		canonicalIP := addr.String()
		suffix := "@" + canonicalIP
		var matches []string
		for k := range c.Data.Targets {
			if strings.HasSuffix(k, suffix) {
				matches = append(matches, k)
			}
		}
		sort.Strings(matches)
		if len(matches) == 1 {
			value = matches[0]
		} else if len(matches) > 1 {
			return ResolvedTarget{}, matches, errs.New("TARGET_USER_AMBIGUOUS", "该 IP 存在多个已配置账号，请明确选择 user@IP。")
		} else {
			return ResolvedTarget{}, nil, errs.New("TARGET_USER", "请指定 user@IP；不能猜测目标用户名。")
		}
	}

	idx := strings.LastIndex(value, "@")
	user := value[:idx]
	rawAddr := value[idx+1:]
	if !targetUserRegex.MatchString(user) {
		return ResolvedTarget{}, nil, errs.New("TARGET_USER", "目标用户名格式不支持。")
	}
	addr, err := netip.ParseAddr(rawAddr)
	if err != nil {
		return ResolvedTarget{}, nil, errs.New("TARGET_ADDRESS", "目标必须使用资产的准确 IP，或配置中的别名。")
	}
	canonicalIP := addr.String()
	canonical := user + "@" + canonicalIP
	entry, ok := c.Data.Targets[canonical]
	if !ok {
		entry = TargetConfig{
			Credential: CredentialConfig{Type: "prompt"},
		}
	}
	if entry.Credential.Type == "" {
		entry.Credential.Type = "prompt"
	}
	return ResolvedTarget{
		Canonical: canonical,
		Username:  user,
		Address:   canonicalIP,
		Entry:     entry,
	}, nil, nil
}

func (c *Config) RecordStoredCredential(key string) {
	if key == "" {
		return
	}
	if !slices.Contains(c.Data.StoredCredentials, key) {
		c.Data.StoredCredentials = append(c.Data.StoredCredentials, key)
		sort.Strings(c.Data.StoredCredentials)
	}
}

func (c *Config) RemoveStoredCredential(key string) {
	if key == "" || len(c.Data.StoredCredentials) == 0 {
		return
	}
	out := c.Data.StoredCredentials[:0]
	for _, existing := range c.Data.StoredCredentials {
		if existing != key {
			out = append(out, existing)
		}
	}
	c.Data.StoredCredentials = out
}

func (c *Config) BumpGeneration() {
	c.Data.Generation++
}

func (c *Config) Save() error {
	origin, host, err := ValidateCoreOrigin(c.Data.CoreURL)
	if err != nil {
		return err
	}
	c.Origin = origin
	c.Data.CoreURL = origin
	if strings.TrimSpace(c.Data.KoKoHost) == "" {
		c.Data.KoKoHost = host
	}
	dir := filepath.Dir(c.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errs.New("CONFIG_WRITE", "无法创建配置目录。")
	}
	lockPath := c.Path + ".lock"
	return WithFileLock(lockPath, func() error {
		return writeAtomicJSON(c.Path, &c.Data)
	})
}

// Update 在排他文件锁内重新加载最新磁盘配置（若存在）、执行变更并原子写回，避免多进程并发更新丢失。
func (c *Config) Update(bumpGen bool, mutator func(d *Data) error) error {
	dir := filepath.Dir(c.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errs.New("CONFIG_WRITE", "无法创建配置目录。")
	}
	lockPath := c.Path + ".lock"
	return WithFileLock(lockPath, func() error {
		if raw, err := os.ReadFile(c.Path); err == nil {
			if latest, parseErr := Parse(c.Path, raw); parseErr == nil {
				c.Data = latest.Data
				c.Origin = latest.Origin
			}
		}
		if err := mutator(&c.Data); err != nil {
			return err
		}
		if bumpGen {
			c.Data.Generation++
		}
		origin, host, err := ValidateCoreOrigin(c.Data.CoreURL)
		if err != nil {
			return err
		}
		c.Origin = origin
		c.Data.CoreURL = origin
		if strings.TrimSpace(c.Data.KoKoHost) == "" {
			c.Data.KoKoHost = host
		}
		return writeAtomicJSON(c.Path, &c.Data)
	})
}

func writeAtomicJSON(targetPath string, value any) error {
	var randBuf [8]byte
	_, _ = rand.Read(randBuf[:])
	tmpPath := fmt.Sprintf("%s.%s.tmp", targetPath, hex.EncodeToString(randBuf[:]))

	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errs.New("CONFIG_WRITE", "无法创建临时配置文件。")
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		_ = f.Close()
		return errs.New("CONFIG_WRITE", "序列化配置失败。")
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return errs.New("CONFIG_WRITE", "同步配置文件失败。")
	}
	if err := f.Close(); err != nil {
		return errs.New("CONFIG_WRITE", "关闭临时配置文件失败。")
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		return errs.New("CONFIG_WRITE", "替换配置文件失败。")
	}
	cleanup = false
	return nil
}
