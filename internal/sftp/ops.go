package sftp

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/xjoker/ssh-mcp/internal/safety"
)

const (
	// readChunkSize is the size of each read chunk in Read.
	readChunkSize = 32 * 1024 // 32 KiB

	// progressChunkSize is the interval at which progressCb is called.
	progressChunkSize = 256 * 1024 // 256 KiB
)

// List returns the directory entries of path.
// Each Entry's Path is parent/child.
func (c *Client) List(dirPath safety.RemotePath) ([]Entry, error) {
	infos, err := c.b.ReadDir(dirPath.String())
	if err != nil {
		return nil, fmt.Errorf("sftp: List %q: %w", dirPath, err)
	}
	entries := make([]Entry, 0, len(infos))
	for _, fi := range infos {
		var linkTo string
		if fi.Mode()&os.ModeSymlink != 0 {
			target, lerr := c.b.ReadLink(path.Join(dirPath.String(), fi.Name()))
			if lerr == nil {
				linkTo = target
			}
		}
		entries = append(entries, fileInfoToEntry(fi, dirPath.String(), linkTo))
	}
	return entries, nil
}

// Stat returns metadata for a single file or directory.
// It follows symlinks (uses Stat, not Lstat). If the entry is a symlink,
// IsLink is set and LinkTo is populated via an additional Lstat+ReadLink.
func (c *Client) Stat(p safety.RemotePath) (Entry, error) {
	// Stat follows symlinks — use for main metadata.
	fi, err := c.b.Stat(p.String())
	if err != nil {
		return Entry{}, fmt.Errorf("sftp: Stat %q: %w", p, err)
	}

	// Detect symlink via Lstat.
	var linkTo string
	lfi, lerr := c.b.Lstat(p.String())
	if lerr == nil && lfi.Mode()&os.ModeSymlink != 0 {
		target, rlerr := c.b.ReadLink(p.String())
		if rlerr == nil {
			linkTo = target
		}
		// Build entry from lstat (preserves ModeSymlink bit) but size/modtime from stat.
		e := fileInfoToEntry(lfi, path.Dir(p.String()), linkTo)
		// Override IsDir with the followed stat result.
		e.IsDir = fi.IsDir()
		e.Size = fi.Size()
		e.ModTime = fi.ModTime()
		return e, nil
	}

	return fileInfoToEntry(fi, path.Dir(p.String()), linkTo), nil
}

// Read reads [offset, offset+length) bytes from path.
// Negative offset is interpreted as "from EOF": e.g. -4096 means the last 4 KiB.
// If progressCb is non-nil it is called periodically with (bytesRead, total).
func (c *Client) Read(p safety.RemotePath, offset, length int64,
	progressCb func(read, total int64)) ([]byte, error) {

	if length < 0 {
		return nil, fmt.Errorf("sftp: Read: length must be non-negative, got %d", length)
	}

	// Resolve negative offset.
	if offset < 0 {
		fi, err := c.b.Stat(p.String())
		if err != nil {
			return nil, fmt.Errorf("sftp: Read: stat for negative offset: %w", err)
		}
		fileSize := fi.Size()
		offset = fileSize + offset
		if offset < 0 {
			offset = 0
		}
	}

	f, err := c.b.OpenFile(p.String(), os.O_RDONLY)
	if err != nil {
		return nil, fmt.Errorf("sftp: Read: open %q: %w", p, err)
	}
	defer f.Close()

	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return nil, fmt.Errorf("sftp: Read: seek: %w", err)
		}
	}

	if length == 0 {
		return []byte{}, nil
	}

	buf := make([]byte, 0, length)
	tmp := make([]byte, readChunkSize)
	var totalRead int64
	var sinceLastProgress int64

	for totalRead < length {
		remaining := length - totalRead
		chunkSize := int64(readChunkSize)
		if remaining < chunkSize {
			chunkSize = remaining
		}

		n, rerr := f.Read(tmp[:chunkSize])
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			totalRead += int64(n)
			sinceLastProgress += int64(n)

			if progressCb != nil && sinceLastProgress >= progressChunkSize {
				progressCb(totalRead, length)
				sinceLastProgress = 0
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return nil, fmt.Errorf("sftp: Read: read error: %w", rerr)
		}
	}

	if progressCb != nil && totalRead > 0 {
		progressCb(totalRead, length)
	}

	return buf, nil
}

// Write writes data to path with the given mode.
// If atomic is true, data is written to a temp file in the same directory
// and then renamed over the target. On rename failure the temp file is removed.
// If progressCb is non-nil it is called periodically with (written, total).
func (c *Client) Write(p safety.RemotePath, data []byte, mode os.FileMode,
	atomic bool, progressCb func(written, total int64)) error {

	if atomic {
		return c.writeAtomic(p, data, mode, progressCb)
	}
	return c.writeDirect(p, data, mode, progressCb)
}

func (c *Client) writeDirect(p safety.RemotePath, data []byte, mode os.FileMode,
	progressCb func(written, total int64)) error {

	f, err := c.b.OpenFile(p.String(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return fmt.Errorf("sftp: Write: open %q: %w", p, err)
	}

	werr := writeWithProgress(f, data, progressCb)
	cerr := f.Close()
	if werr != nil {
		return fmt.Errorf("sftp: Write: %w", werr)
	}
	if cerr != nil {
		return fmt.Errorf("sftp: Write: close: %w", cerr)
	}

	// Apply mode explicitly since OpenFile may not honor the mode on all servers.
	if err := c.b.Chmod(p.String(), mode); err != nil {
		return fmt.Errorf("sftp: Write: chmod: %w", err)
	}
	return nil
}

// atomicTmpMaxRetries is the number of times writeAtomic will retry generating
// a unique temp-file name when O_EXCL creation fails.
const atomicTmpMaxRetries = 3

// randHex8 returns 8 random hex characters sourced from crypto/rand.
func randHex8() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func (c *Client) writeAtomic(p safety.RemotePath, data []byte, mode os.FileMode,
	progressCb func(written, total int64)) error {

	dir := path.Dir(p.String())
	base := path.Base(p.String())

	// Try up to atomicTmpMaxRetries times to create a uniquely-named temp file
	// with O_EXCL (exclusive create). This prevents concurrent writes to the
	// same target from clobbering each other's temp files (SDD §5.6).
	//
	// Note: pkg/sftp passes OpenFile flags directly to the SFTP server's
	// SSH_FXP_OPEN request. O_EXCL (0x0004) is part of the sftp-v3 open flags
	// and is supported by OpenSSH/sftp-server. If the server does not support
	// O_EXCL the open will either succeed (treating it as O_CREAT) or return an
	// error; in the latter case we retry with a fresh random name, which by
	// itself provides sufficient uniqueness protection.
	var tmpPath string
	var f sftpFile
	for attempt := 0; attempt < atomicTmpMaxRetries; attempt++ {
		suffix, err := randHex8()
		if err != nil {
			return fmt.Errorf("sftp: Write(atomic): rand: %w", err)
		}
		candidate := path.Join(dir, "."+base+".msb-tmp."+suffix)
		fh, openErr := c.b.OpenFile(candidate, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
		if openErr == nil {
			tmpPath = candidate
			f = fh
			break
		}
		// If this was the last attempt, return the error.
		if attempt == atomicTmpMaxRetries-1 {
			return fmt.Errorf("sftp: Write(atomic): open tmp (attempt %d): %w", attempt+1, openErr)
		}
		// Otherwise retry with a different random name.
	}

	werr := writeWithProgress(f, data, progressCb)
	cerr := f.Close()
	if werr != nil {
		_ = c.b.Remove(tmpPath)
		return fmt.Errorf("sftp: Write(atomic): write: %w", werr)
	}
	if cerr != nil {
		_ = c.b.Remove(tmpPath)
		return fmt.Errorf("sftp: Write(atomic): close: %w", cerr)
	}

	// Apply mode to temp file before rename.
	if err := c.b.Chmod(tmpPath, mode); err != nil {
		_ = c.b.Remove(tmpPath)
		return fmt.Errorf("sftp: Write(atomic): chmod tmp: %w", err)
	}

	if err := c.b.PosixRename(tmpPath, p.String()); err != nil {
		// PosixRename failed; try plain Rename as fallback.
		if err2 := c.b.Rename(tmpPath, p.String()); err2 != nil {
			_ = c.b.Remove(tmpPath)
			return fmt.Errorf("sftp: Write(atomic): rename %q → %q: %w (posix: %v)", tmpPath, p, err2, err)
		}
	}
	return nil
}

// writeWithProgress writes data to f, calling progressCb every progressChunkSize bytes.
func writeWithProgress(f sftpFile, data []byte, progressCb func(written, total int64)) error {
	total := int64(len(data))
	var written int64
	var sinceLastProgress int64

	for len(data) > 0 {
		chunk := data
		if int64(len(chunk)) > readChunkSize {
			chunk = data[:readChunkSize]
		}
		n, err := f.Write(chunk)
		written += int64(n)
		sinceLastProgress += int64(n)
		data = data[n:]

		if progressCb != nil && sinceLastProgress >= progressChunkSize {
			progressCb(written, total)
			sinceLastProgress = 0
		}
		if err != nil {
			return err
		}
	}

	if progressCb != nil && written > 0 {
		progressCb(written, total)
	}
	return nil
}

// Mkdir creates a directory at path with the given mode.
// If recursive is true, all missing parent directories are created.
func (c *Client) Mkdir(p safety.RemotePath, mode os.FileMode, recursive bool) error {
	var err error
	if recursive {
		err = c.b.MkdirAll(p.String())
	} else {
		err = c.b.Mkdir(p.String())
	}
	if err != nil {
		return fmt.Errorf("sftp: Mkdir %q: %w", p, err)
	}
	// pkg/sftp Mkdir does not accept a mode parameter; set it explicitly.
	if err := c.b.Chmod(p.String(), mode); err != nil {
		return fmt.Errorf("sftp: Mkdir: chmod %q: %w", p, err)
	}
	return nil
}

// Remove removes a file or directory.
// If recursive is true, a non-empty directory is removed with all its contents.
// Otherwise only a single file or empty directory is removed.
func (c *Client) Remove(p safety.RemotePath, recursive bool) error {
	if recursive {
		if err := c.b.RemoveAll(p.String()); err != nil {
			return fmt.Errorf("sftp: Remove(recursive) %q: %w", p, err)
		}
		return nil
	}

	// Non-recursive: try file remove first, then directory remove.
	err := c.b.Remove(p.String())
	if err == nil {
		return nil
	}
	// If Remove failed, it might be a directory.
	if dirErr := c.b.RemoveDirectory(p.String()); dirErr != nil {
		return fmt.Errorf("sftp: Remove %q: %w", p, err)
	}
	return nil
}

// Rename renames (moves) from to to.
// PosixRename is attempted first (atomic overwrite); plain Rename is used as fallback.
func (c *Client) Rename(from, to safety.RemotePath) error {
	err := c.b.PosixRename(from.String(), to.String())
	if err == nil {
		return nil
	}
	if err2 := c.b.Rename(from.String(), to.String()); err2 != nil {
		return fmt.Errorf("sftp: Rename %q → %q: %w (posix: %v)", from, to, err2, err)
	}
	return nil
}

// Chmod changes the mode of path.
func (c *Client) Chmod(p safety.RemotePath, mode os.FileMode) error {
	if err := c.b.Chmod(p.String(), mode); err != nil {
		return fmt.Errorf("sftp: Chmod %q: %w", p, err)
	}
	return nil
}

// Symlink creates a symbolic link at linkPath pointing to target.
func (c *Client) Symlink(target, linkPath safety.RemotePath) error {
	// OpenSSH reverses linkpath/targetpath relative to the SFTP draft spec.
	// pkg/sftp follows the spec (Symlink(oldname, newname) creates newname→oldname),
	// but OpenSSH expects the args swapped, so we pass (linkPath, target) here.
	if err := c.b.Symlink(linkPath.String(), target.String()); err != nil {
		return fmt.Errorf("sftp: Symlink %q → %q: %w", target, linkPath, err)
	}
	return nil
}

// Realpath resolves path to an absolute path on the remote host.
// It expands a leading '~' to the remote home directory, resolves relative
// paths against the remote working directory, then calls the SFTP server's
// realpath to canonicalize. The server's response is re-validated through
// safety.ValidateRemotePath (S-1 / Codex L02): a malicious or buggy SFTP
// server cannot smuggle in NUL bytes, oversized paths, or non-absolute
// strings even though we are usually willing to trust it.
func (c *Client) Realpath(p string) (safety.RemotePath, error) {
	resolved, err := c.resolveRelative(p)
	if err != nil {
		return safety.RemotePath{}, err
	}

	abs, err := c.b.RealPath(resolved)
	if err != nil {
		return safety.RemotePath{}, fmt.Errorf("sftp: Realpath %q: %w", p, err)
	}
	rp, err := safety.ValidateRemotePath(abs)
	if err != nil {
		return safety.RemotePath{}, fmt.Errorf("sftp: Realpath %q: server returned invalid path %q: %w", p, abs, err)
	}
	return rp, nil
}

// resolveRelative expands '~' and resolves relative paths to absolute ones
// before passing to the server's RealPath.
func (c *Client) resolveRelative(p string) (string, error) {
	if strings.HasPrefix(p, "~/") || p == "~" {
		home, err := c.b.Getwd()
		if err != nil {
			return "", fmt.Errorf("sftp: Realpath: getwd for ~ expansion: %w", err)
		}
		if p == "~" {
			return home, nil
		}
		return path.Join(home, p[2:]), nil
	}
	if !strings.HasPrefix(p, "/") {
		// Relative path — resolve against working directory.
		cwd, err := c.b.Getwd()
		if err != nil {
			return "", fmt.Errorf("sftp: Realpath: getwd for relative path: %w", err)
		}
		return path.Join(cwd, p), nil
	}
	return p, nil
}
