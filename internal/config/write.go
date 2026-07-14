package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"time"

	"github.com/BurntSushi/toml"
)

type diskConfig struct {
	Settings Settings                    `toml:"settings"`
	Servers  map[string]diskServerConfig `toml:"servers,omitempty"`
	Proxies  map[string]diskProxyConfig  `toml:"proxies,omitempty"`
}

type diskServerConfig struct {
	Host          string   `toml:"host"`
	Port          int      `toml:"port,omitempty"`
	User          string   `toml:"user"`
	Auth          string   `toml:"auth"`
	KeyPath       string   `toml:"key_path,omitempty"`
	KeyPassphrase CredRef  `toml:"key_passphrase,omitempty"`
	Password      CredRef  `toml:"password,omitempty"`
	DefaultDir    string   `toml:"default_dir,omitempty"`
	Description   string   `toml:"description,omitempty"`
	ProxyJump     string   `toml:"proxy_jump,omitempty"`
	ProxyChain    []string `toml:"proxy_chain,omitempty"`
	AllowedPaths  []string `toml:"allowed_paths,omitempty"`
	Tags          []string `toml:"tags,omitempty"`
	Mode          string   `toml:"mode,omitempty"`
	AllowPatterns []string `toml:"allow_patterns,omitempty"`
	DenyPatterns  []string `toml:"deny_patterns,omitempty"`
}

type diskProxyConfig struct {
	Type               string  `toml:"type"`
	Host               string  `toml:"host,omitempty"`
	Port               int     `toml:"port,omitempty"`
	User               string  `toml:"user,omitempty"`
	Password           CredRef `toml:"password,omitempty"`
	Server             string  `toml:"server,omitempty"`
	Auth               string  `toml:"auth,omitempty"`
	KeyPath            string  `toml:"key_path,omitempty"`
	InsecureSkipVerify bool    `toml:"insecure_skip_verify,omitempty"`
}

var (
	replaceConfigFile     = os.Rename
	acquireConfigSaveLock = acquireSaveLock
)

// SaveCommittedError reports a post-commit cleanup failure. The target file
// has already been atomically replaced when this error is returned.
type SaveCommittedError struct {
	Err error
}

func (e *SaveCommittedError) Error() string { return e.Err.Error() }
func (e *SaveCommittedError) Unwrap() error { return e.Err }

func IsSaveCommitted(err error) bool {
	var committedErr *SaveCommittedError
	return errors.As(err, &committedErr)
}

func NewConfig() *Config {
	return &Config{
		Settings: defaultSettings(),
		Servers:  make(map[string]ServerConfig),
		Proxies:  make(map[string]ProxyConfig),
	}
}

func ValidateServerName(name string) error {
	if len(name) == 0 || len(name) > 64 || !serverNameRe.MatchString(name) {
		return fmt.Errorf("config: server name %q must match ^[a-z0-9][a-z0-9_-]*$ and be 1-64 chars", name)
	}
	return nil
}

func AddServer(cfg *Config, name string, server ServerConfig) error {
	if err := validateMutationTarget(cfg, name); err != nil {
		return err
	}
	if _, ok := cfg.Servers[name]; ok {
		return fmt.Errorf("config: server %q already exists", name)
	}
	return replaceServer(cfg, name, server)
}

func UpsertServer(cfg *Config, name string, server ServerConfig) error {
	if err := validateMutationTarget(cfg, name); err != nil {
		return err
	}
	return replaceServer(cfg, name, server)
}

func RemoveServer(cfg *Config, name string) error {
	if err := validateMutationTarget(cfg, name); err != nil {
		return err
	}
	if _, ok := cfg.Servers[name]; !ok {
		return fmt.Errorf("config: server %q not found", name)
	}
	candidate := cloneConfig(cfg)
	delete(candidate.Servers, name)
	if err := validate(candidate); err != nil {
		return err
	}
	cfg.Servers = candidate.Servers
	return nil
}

func SetServerPolicy(cfg *Config, name, mode string, allowPatterns, denyPatterns []string) error {
	if err := validateMutationTarget(cfg, name); err != nil {
		return err
	}
	server, ok := cfg.Servers[name]
	if !ok {
		return fmt.Errorf("config: server %q not found", name)
	}
	server.Mode = mode
	server.AllowPatterns = append([]string(nil), allowPatterns...)
	server.DenyPatterns = append([]string(nil), denyPatterns...)
	return replaceServer(cfg, name, server)
}

func Save(path string, cfg *Config) error {
	return saveWithPreCommit(path, cfg, nil, nil)
}

// SaveWithPreCommit is Save with an operation that runs after the target is
// locked and confirmed unchanged, but before the prepared config replaces it.
// A pre-commit error leaves the target file untouched.
func SaveWithPreCommit(path string, cfg *Config, preCommit, rollback func() error) error {
	if preCommit == nil || rollback == nil {
		return fmt.Errorf("config: pre-commit and rollback operations are required")
	}
	return saveWithPreCommit(path, cfg, preCommit, rollback)
}

func saveWithPreCommit(path string, cfg *Config, preCommit, rollback func() error) (saveErr error) {
	if path == "" {
		return fmt.Errorf("config: save path is required")
	}
	if cfg == nil {
		return fmt.Errorf("config: cannot save nil config")
	}

	encoded, err := encodeForSave(cfg)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("config: create directory %q: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("config: create temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("config: set temporary file permissions: %w", err)
	}
	if _, err := tmp.Write(encoded); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("config: write temporary file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("config: sync temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("config: close temporary file: %w", err)
	}
	if _, err := Load(tmpPath); err != nil {
		return fmt.Errorf("config: validate temporary file: %w", err)
	}
	releaseLock, err := acquireConfigSaveLock(path)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if err := releaseLock(); err != nil {
			unlockErr := fmt.Errorf("config: release save lock for %q: %w", path, err)
			if committed && saveErr == nil {
				saveErr = &SaveCommittedError{Err: unlockErr}
			} else if saveErr == nil {
				saveErr = unlockErr
			} else {
				saveErr = fmt.Errorf("%w; %v", saveErr, unlockErr)
			}
		}
	}()
	if err := ensureSaveTargetUnchanged(path, cfg); err != nil {
		return err
	}
	if preCommit != nil {
		if err := preCommit(); err != nil {
			return fmt.Errorf("config: pre-commit operation: %w", err)
		}
	}
	if err := replaceConfigFile(tmpPath, path); err != nil {
		if preCommit != nil {
			if rollbackErr := rollback(); rollbackErr != nil {
				return fmt.Errorf("config: replace %q: %w; pre-commit rollback failed: %v", path, err, rollbackErr)
			}
		}
		return fmt.Errorf("config: replace %q: %w", path, err)
	}
	committed = true
	cleanup = false
	cfg.Path = path
	cfg.source = append(cfg.source[:0], encoded...)
	cfg.snapshot = cloneDiskConfig(encodeConfig(cfg))
	return nil
}

func ensureSaveTargetUnchanged(path string, cfg *Config) error {
	sameSource := cfg.Path != "" && filepath.Clean(cfg.Path) == filepath.Clean(path)
	current, err := os.ReadFile(path)
	if sameSource {
		if err != nil {
			return fmt.Errorf("config: %q changed on disk since it was loaded: %w", path, err)
		}
		if !bytes.Equal(current, cfg.source) {
			return fmt.Errorf("config: %q changed on disk since it was loaded", path)
		}
		return nil
	}

	if err == nil {
		return fmt.Errorf("config: %q changed on disk before the new configuration was saved", path)
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("config: inspect save target %q: %w", path, err)
	}
	return nil
}

// Backup creates a timestamped, durable copy of a configuration file.
func Backup(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("config: backup path is required")
	}

	source, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("config: open backup source %q: %w", path, err)
	}
	defer source.Close()

	backupPath := path + ".backup-" + time.Now().UTC().Format("20060102-150405")
	backup, err := os.OpenFile(backupPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", fmt.Errorf("config: create backup %q: %w", backupPath, err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = backup.Close()
			_ = os.Remove(backupPath)
		}
	}()
	if _, err := io.Copy(backup, source); err != nil {
		return "", fmt.Errorf("config: copy backup: %w", err)
	}
	if err := backup.Sync(); err != nil {
		return "", fmt.Errorf("config: sync backup: %w", err)
	}
	if err := backup.Close(); err != nil {
		return "", fmt.Errorf("config: close backup: %w", err)
	}
	cleanup = false
	return backupPath, nil
}

func encodeForSave(cfg *Config) ([]byte, error) {
	current := encodeConfig(cfg)
	if names, ok := appendedServerNames(current, cfg.snapshot); ok && len(names) > 0 {
		return appendServerBlocks(cfg.source, current.Servers, names)
	}

	var encoded bytes.Buffer
	if err := toml.NewEncoder(&encoded).Encode(current); err != nil {
		return nil, fmt.Errorf("config: encode: %w", err)
	}
	return encoded.Bytes(), nil
}

func appendedServerNames(current diskConfig, snapshot *diskConfig) ([]string, bool) {
	if snapshot == nil || len(snapshot.Servers) >= len(current.Servers) ||
		!reflect.DeepEqual(current.Settings, snapshot.Settings) ||
		!reflect.DeepEqual(current.Proxies, snapshot.Proxies) {
		return nil, false
	}

	for name, server := range snapshot.Servers {
		if currentServer, ok := current.Servers[name]; !ok || !reflect.DeepEqual(currentServer, server) {
			return nil, false
		}
	}

	names := make([]string, 0, len(current.Servers)-len(snapshot.Servers))
	for name := range current.Servers {
		if _, exists := snapshot.Servers[name]; !exists {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, true
}

func appendServerBlocks(source []byte, servers map[string]diskServerConfig, names []string) ([]byte, error) {
	encoded := append([]byte(nil), source...)
	if len(encoded) > 0 && encoded[len(encoded)-1] != '\n' {
		encoded = append(encoded, '\n')
	}

	for _, name := range names {
		var server bytes.Buffer
		if err := toml.NewEncoder(&server).Encode(servers[name]); err != nil {
			return nil, fmt.Errorf("config: encode server %q: %w", name, err)
		}
		encoded = append(encoded, '\n')
		encoded = append(encoded, "[servers."+name+"]\n"...)
		encoded = append(encoded, server.Bytes()...)
	}
	return encoded, nil
}

func defaultSettings() Settings {
	return Settings{
		AllowConfigPlaintextPassword: false,
		AllowInlineCredentials:       true,
		DefaultTimeoutMs:             120_000,
		MaxTimeoutMs:                 1_800_000,
		OutputMaxBytes:               65_536,
		SftpProgressThresholdBytes:   10 * 1024 * 1024,
		SessionIdleSeconds:           3_600,
		MaxSessions:                  16,
		ConnIdleSeconds:              600,
		AuditRetentionDays:           90,
		AuditRecordOutput:            true,
		AuditOutputMaxBytes:          32 * 1024,
	}
}

func validateMutationTarget(cfg *Config, name string) error {
	if cfg == nil {
		return fmt.Errorf("config: cannot modify nil config")
	}
	if err := ValidateServerName(name); err != nil {
		return err
	}
	if cfg.Servers == nil {
		cfg.Servers = make(map[string]ServerConfig)
	}
	return nil
}

func replaceServer(cfg *Config, name string, server ServerConfig) error {
	candidate := cloneConfig(cfg)
	server.Name = name
	candidate.Servers[name] = server
	if err := validate(candidate); err != nil {
		return err
	}
	cfg.Servers = candidate.Servers
	return nil
}

func cloneConfig(cfg *Config) *Config {
	clone := *cfg
	clone.Servers = make(map[string]ServerConfig, len(cfg.Servers))
	for name, server := range cfg.Servers {
		clone.Servers[name] = server
	}
	clone.Proxies = make(map[string]ProxyConfig, len(cfg.Proxies))
	for name, proxy := range cfg.Proxies {
		clone.Proxies[name] = proxy
	}
	return &clone
}

func encodeConfig(cfg *Config) diskConfig {
	servers := make(map[string]diskServerConfig, len(cfg.Servers))
	for name, server := range cfg.Servers {
		servers[name] = diskServerConfig{
			Host:          server.Host,
			Port:          server.Port,
			User:          server.User,
			Auth:          server.Auth,
			KeyPath:       server.KeyPath,
			KeyPassphrase: server.KeyPassphrase,
			Password:      server.Password,
			DefaultDir:    server.DefaultDir,
			Description:   server.Description,
			ProxyJump:     server.ProxyJump,
			ProxyChain:    server.ProxyChain,
			AllowedPaths:  server.AllowedPaths,
			Tags:          server.Tags,
			Mode:          server.Mode,
			AllowPatterns: server.AllowPatterns,
			DenyPatterns:  server.DenyPatterns,
		}
	}
	proxies := make(map[string]diskProxyConfig, len(cfg.Proxies))
	for name, proxy := range cfg.Proxies {
		proxies[name] = diskProxyConfig{
			Type:               proxy.Type,
			Host:               proxy.Host,
			Port:               proxy.Port,
			User:               proxy.User,
			Password:           proxy.Password,
			Server:             proxy.Server,
			Auth:               proxy.Auth,
			KeyPath:            proxy.KeyPath,
			InsecureSkipVerify: proxy.InsecureSkipVerify,
		}
	}
	return diskConfig{Settings: cfg.Settings, Servers: servers, Proxies: proxies}
}

func cloneDiskConfig(cfg diskConfig) *diskConfig {
	clone := cfg
	clone.Settings.WeakAlgorithmsOptIn = append([]string(nil), cfg.Settings.WeakAlgorithmsOptIn...)
	clone.Settings.UploadLocalAllowedPaths = append([]string(nil), cfg.Settings.UploadLocalAllowedPaths...)
	clone.Servers = make(map[string]diskServerConfig, len(cfg.Servers))
	for name, server := range cfg.Servers {
		server.ProxyChain = append([]string(nil), server.ProxyChain...)
		server.AllowedPaths = append([]string(nil), server.AllowedPaths...)
		server.Tags = append([]string(nil), server.Tags...)
		server.AllowPatterns = append([]string(nil), server.AllowPatterns...)
		server.DenyPatterns = append([]string(nil), server.DenyPatterns...)
		clone.Servers[name] = server
	}
	clone.Proxies = make(map[string]diskProxyConfig, len(cfg.Proxies))
	for name, proxy := range cfg.Proxies {
		clone.Proxies[name] = proxy
	}
	return &clone
}
