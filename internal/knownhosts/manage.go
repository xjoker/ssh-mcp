package knownhosts

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	gossh "golang.org/x/crypto/ssh"
	sshknownhosts "golang.org/x/crypto/ssh/knownhosts"
)

// Status describes whether a scanned key is trusted by known_hosts.
type Status string

const (
	StatusTrusted  Status = "trusted"
	StatusUnknown  Status = "unknown"
	StatusMismatch Status = "mismatch"
)

var fileMu sync.Mutex

// Check compares key with the entry for addr in path without modifying it.
// A missing file means no key has been trusted yet. Malformed files and read
// failures are returned so callers never mistake an unreadable trust store for
// an unknown host.
func Check(path, addr string, key gossh.PublicKey) (Status, error) {
	if path == "" {
		return "", errors.New("known_hosts path is required")
	}
	if addr == "" {
		return "", errors.New("host address is required")
	}
	if key == nil {
		return "", errors.New("host key is required")
	}

	fileMu.Lock()
	defer fileMu.Unlock()
	return check(path, addr, key)
}

func check(path, addr string, key gossh.PublicKey) (Status, error) {
	callbackAddr, err := callbackAddress(addr)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return StatusUnknown, nil
	} else if err != nil {
		return "", fmt.Errorf("stat known_hosts: %w", err)
	}

	callback, err := sshknownhosts.New(path)
	if err != nil {
		return "", fmt.Errorf("parse known_hosts: %w", err)
	}
	err = callback(callbackAddr, &net.TCPAddr{}, key)
	if err == nil {
		return StatusTrusted, nil
	}
	var revokedErr *sshknownhosts.RevokedError
	if errors.As(err, &revokedErr) {
		return StatusMismatch, nil
	}
	var keyErr *sshknownhosts.KeyError
	if errors.As(err, &keyErr) {
		if len(keyErr.Want) == 0 {
			return StatusUnknown, nil
		}
		return StatusMismatch, nil
	}
	return "", fmt.Errorf("check known_hosts: %w", err)
}

func callbackAddress(addr string) (string, error) {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr, nil
	}
	ipText := addr
	if strings.HasPrefix(ipText, "[") && strings.HasSuffix(ipText, "]") {
		ipText = strings.TrimSuffix(strings.TrimPrefix(ipText, "["), "]")
	}
	if ip, err := netip.ParseAddr(ipText); err == nil {
		return net.JoinHostPort(ip.String(), "22"), nil
	}
	if strings.Contains(addr, ":") {
		return "", fmt.Errorf("invalid host address %q", addr)
	}
	return net.JoinHostPort(addr, "22"), nil
}

// Entry is a safe summary of one known_hosts entry.
type Entry struct {
	Hosts       []string
	KeyType     string
	Fingerprint string
	Revoked     bool

	marker string
	raw    string
}

// List returns the host keys recorded in path. Hashed host names are not
// exposed and are represented by "[hashed]".
func List(path string) ([]Entry, error) {
	fileMu.Lock()
	defer fileMu.Unlock()
	return list(path)
}

func list(path string) ([]Entry, error) {
	contents, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read known_hosts: %w", err)
	}

	var entries []Entry
	for _, line := range strings.Split(string(contents), "\n") {
		raw := strings.TrimSuffix(line, "\r")
		fields := strings.Fields(raw)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		marker := ""
		revoked := fields[0] == "@revoked"
		if strings.HasPrefix(fields[0], "@") {
			marker = fields[0]
			fields = fields[1:]
		}
		if len(fields) < 3 {
			continue
		}
		key, _, _, _, err := gossh.ParseAuthorizedKey([]byte(fields[1] + " " + fields[2]))
		if err != nil {
			continue
		}

		hosts := strings.Split(fields[0], ",")
		if strings.HasPrefix(fields[0], "|") {
			hosts = []string{"[hashed]"}
		}
		entries = append(entries, Entry{
			Hosts:       hosts,
			KeyType:     key.Type(),
			Fingerprint: gossh.FingerprintSHA256(key),
			Revoked:     revoked,
			marker:      marker,
			raw:         raw,
		})
	}
	return entries, nil
}

// Append records a confirmed host key in path.
func Append(path, host string, key gossh.PublicKey) (appendErr error) {
	if path == "" {
		return errors.New("known_hosts path is required")
	}
	if host == "" {
		return errors.New("host is required")
	}
	if key == nil {
		return errors.New("host key is required")
	}

	fileMu.Lock()
	defer fileMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create known_hosts directory: %w", err)
	}
	releaseLock, err := acquireKnownHostsFileLock(path)
	if err != nil {
		return err
	}
	defer func() {
		if err := releaseLock(); err != nil {
			appendErr = errors.Join(appendErr, fmt.Errorf("release known_hosts lock: %w", err))
		}
	}()
	status, err := check(path, host, key)
	if err != nil {
		return err
	}
	switch status {
	case StatusTrusted:
		return nil
	case StatusMismatch:
		return fmt.Errorf("host key mismatch for %s: known_hosts already contains a different key", host)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open known_hosts: %w", err)
	}
	defer file.Close()
	if _, err := file.WriteString(sshknownhosts.Line([]string{host}, key) + "\n"); err != nil {
		return fmt.Errorf("append known_hosts: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync known_hosts: %w", err)
	}
	return nil
}

// Revoke replaces one exact entry with an @revoked entry.
func Revoke(path string, entry Entry) (revokeErr error) {
	if entry.raw == "" {
		return errors.New("known_hosts entry is required")
	}
	if entry.Revoked {
		return errors.New("known_hosts entry is already revoked")
	}
	if entry.marker != "" {
		return errors.New("known_hosts marked entries cannot be revoked")
	}

	fileMu.Lock()
	defer fileMu.Unlock()
	releaseLock, err := acquireKnownHostsFileLock(path)
	if err != nil {
		return err
	}
	defer func() {
		if err := releaseLock(); err != nil {
			revokeErr = errors.Join(revokeErr, fmt.Errorf("release known_hosts lock: %w", err))
		}
	}()
	contents, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read known_hosts: %w", err)
	}

	lines := strings.Split(string(contents), "\n")
	revoked := false
	for index, line := range lines {
		if !revoked && strings.TrimSuffix(line, "\r") == entry.raw {
			lines[index] = "@revoked " + entry.raw
			revoked = true
		}
	}
	if !revoked {
		return errors.New("known_hosts entry no longer exists")
	}
	if err := writeAtomic(path, []byte(strings.Join(lines, "\n"))); err != nil {
		return err
	}
	return nil
}

// Remove deletes one exact entry while preserving every other line.
func Remove(path string, entry Entry) (removeErr error) {
	if entry.raw == "" {
		return errors.New("known_hosts entry is required")
	}

	fileMu.Lock()
	defer fileMu.Unlock()
	releaseLock, err := acquireKnownHostsFileLock(path)
	if err != nil {
		return err
	}
	defer func() {
		if err := releaseLock(); err != nil {
			removeErr = errors.Join(removeErr, fmt.Errorf("release known_hosts lock: %w", err))
		}
	}()
	contents, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read known_hosts: %w", err)
	}

	lines := strings.Split(string(contents), "\n")
	filtered := make([]string, 0, len(lines))
	removed := false
	for _, line := range lines {
		if !removed && strings.TrimSuffix(line, "\r") == entry.raw {
			removed = true
			continue
		}
		filtered = append(filtered, line)
	}
	if !removed {
		return errors.New("known_hosts entry no longer exists")
	}

	newContents := strings.Join(filtered, "\n")
	if err := writeAtomic(path, []byte(newContents)); err != nil {
		return err
	}
	return nil
}

func writeAtomic(path string, contents []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".known_hosts-*")
	if err != nil {
		return fmt.Errorf("create known_hosts temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return fmt.Errorf("set known_hosts temporary permissions: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return fmt.Errorf("write known_hosts temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync known_hosts temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close known_hosts temporary file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace known_hosts: %w", err)
	}
	return nil
}
