package knownhosts

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	gossh "golang.org/x/crypto/ssh"
	sshknownhosts "golang.org/x/crypto/ssh/knownhosts"
)

var fileMu sync.Mutex

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
func Append(path, host string, key gossh.PublicKey) error {
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
func Revoke(path string, entry Entry) error {
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
func Remove(path string, entry Entry) error {
	if entry.raw == "" {
		return errors.New("known_hosts entry is required")
	}

	fileMu.Lock()
	defer fileMu.Unlock()
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
