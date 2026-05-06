package sftp

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xjoker/ssh-mcp/internal/safety"
)

// ---------------------------------------------------------------------------
// Fake FileInfo
// ---------------------------------------------------------------------------

type fakeFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
	isDir   bool
}

func (f *fakeFileInfo) Name() string      { return f.name }
func (f *fakeFileInfo) Size() int64       { return f.size }
func (f *fakeFileInfo) Mode() os.FileMode { return f.mode }
func (f *fakeFileInfo) ModTime() time.Time { return f.modTime }
func (f *fakeFileInfo) IsDir() bool       { return f.isDir }
func (f *fakeFileInfo) Sys() interface{}  { return nil }

// ---------------------------------------------------------------------------
// Fake sftpFile (in-memory read/write buffer)
// ---------------------------------------------------------------------------

type fakeFile struct {
	buf    []byte
	pos    int
	closed bool
	// record calls
	writes [][]byte
}

func newFakeFileWithContent(content []byte) *fakeFile {
	return &fakeFile{buf: append([]byte(nil), content...)}
}

func (f *fakeFile) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		f.pos = int(offset)
	case io.SeekCurrent:
		f.pos += int(offset)
	case io.SeekEnd:
		f.pos = len(f.buf) + int(offset)
	}
	if f.pos < 0 {
		f.pos = 0
	}
	return int64(f.pos), nil
}

func (f *fakeFile) Read(b []byte) (int, error) {
	if f.pos >= len(f.buf) {
		return 0, io.EOF
	}
	n := copy(b, f.buf[f.pos:])
	f.pos += n
	return n, nil
}

func (f *fakeFile) Write(b []byte) (int, error) {
	chunk := make([]byte, len(b))
	copy(chunk, b)
	f.writes = append(f.writes, chunk)
	f.buf = append(f.buf, chunk...)
	return len(b), nil
}

func (f *fakeFile) Close() error {
	f.closed = true
	return nil
}

// ---------------------------------------------------------------------------
// Fake sftpBackend
// ---------------------------------------------------------------------------

type fakeBackend struct {
	// stubbed responses
	getwdResult  string
	getwdErr     error
	realPathFunc func(p string) (string, error)
	statFunc     func(p string) (os.FileInfo, error)
	lstatFunc    func(p string) (os.FileInfo, error)
	readLinkFunc func(p string) (string, error)
	openFileFunc func(path string, f int) (sftpFile, error)
	readDirFunc  func(p string) ([]os.FileInfo, error)

	// posixRename behaviour
	posixRenameErr  error
	renameCallCount int
	removeCallCount int
	removedPaths    []string

	// chmod record
	chmodCalls []string

	// mkdir
	mkdirErr    error
	mkdirAllErr error
}

func (fb *fakeBackend) Getwd() (string, error) { return fb.getwdResult, fb.getwdErr }

func (fb *fakeBackend) RealPath(p string) (string, error) {
	if fb.realPathFunc != nil {
		return fb.realPathFunc(p)
	}
	return p, nil
}

func (fb *fakeBackend) Stat(p string) (os.FileInfo, error) {
	if fb.statFunc != nil {
		return fb.statFunc(p)
	}
	return nil, fs.ErrNotExist
}

func (fb *fakeBackend) Lstat(p string) (os.FileInfo, error) {
	if fb.lstatFunc != nil {
		return fb.lstatFunc(p)
	}
	return nil, fs.ErrNotExist
}

func (fb *fakeBackend) ReadLink(p string) (string, error) {
	if fb.readLinkFunc != nil {
		return fb.readLinkFunc(p)
	}
	return "", fs.ErrNotExist
}

func (fb *fakeBackend) OpenFile(path string, f int) (sftpFile, error) {
	if fb.openFileFunc != nil {
		return fb.openFileFunc(path, f)
	}
	return nil, errors.New("fakeBackend: OpenFile not configured")
}

func (fb *fakeBackend) ReadDir(p string) ([]os.FileInfo, error) {
	if fb.readDirFunc != nil {
		return fb.readDirFunc(p)
	}
	return nil, errors.New("fakeBackend: ReadDir not configured")
}

func (fb *fakeBackend) Mkdir(path string) error    { return fb.mkdirErr }
func (fb *fakeBackend) MkdirAll(path string) error { return fb.mkdirAllErr }

func (fb *fakeBackend) Remove(path string) error {
	fb.removeCallCount++
	fb.removedPaths = append(fb.removedPaths, path)
	return nil
}

func (fb *fakeBackend) RemoveAll(path string) error {
	fb.removeCallCount++
	fb.removedPaths = append(fb.removedPaths, path)
	return nil
}

func (fb *fakeBackend) RemoveDirectory(path string) error { return nil }

func (fb *fakeBackend) PosixRename(oldname, newname string) error {
	fb.renameCallCount++
	return fb.posixRenameErr
}

func (fb *fakeBackend) Rename(oldname, newname string) error {
	fb.renameCallCount++
	return nil
}

func (fb *fakeBackend) Chmod(path string, mode os.FileMode) error {
	fb.chmodCalls = append(fb.chmodCalls, path)
	return nil
}

func (fb *fakeBackend) Symlink(oldname, newname string) error { return nil }
func (fb *fakeBackend) Close() error                          { return nil }

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func mustRemotePath(t *testing.T, p string) safety.RemotePath {
	t.Helper()
	rp, err := safety.ValidateRemotePath(p)
	if err != nil {
		t.Fatalf("ValidateRemotePath(%q): %v", p, err)
	}
	return rp
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// Test 1: Read negative offset is converted to a valid positive offset.
func TestRead_NegativeOffsetConverted(t *testing.T) {
	content := []byte("0123456789") // 10 bytes

	var seekedOffset int64 = -1 // sentinel: not yet set

	fb := &fakeBackend{
		statFunc: func(p string) (os.FileInfo, error) {
			return &fakeFileInfo{name: "test.txt", size: int64(len(content))}, nil
		},
		openFileFunc: func(path string, f int) (sftpFile, error) {
			ff := newFakeFileWithContent(content)
			// Wrap to capture seek call.
			return &seekCapturingFile{fakeFile: ff, onSeek: func(off int64) {
				seekedOffset = off
			}}, nil
		},
	}

	c := &Client{b: fb}
	p := mustRemotePath(t, "/tmp/test.txt")

	got, err := c.Read(p, -4, 4, nil)
	if err != nil {
		t.Fatalf("Read: unexpected error: %v", err)
	}
	// offset=-4 on a 10-byte file → seek to position 6, read 4 bytes "6789"
	if want := []byte("6789"); string(got) != string(want) {
		t.Errorf("Read content: got %q, want %q", got, want)
	}
	if seekedOffset != 6 {
		t.Errorf("Seek offset: got %d, want 6", seekedOffset)
	}
}

// seekCapturingFile wraps fakeFile and records the first Seek call.
type seekCapturingFile struct {
	*fakeFile
	onSeek func(int64)
}

func (s *seekCapturingFile) Seek(offset int64, whence int) (int64, error) {
	if s.onSeek != nil {
		s.onSeek(offset)
		s.onSeek = nil // only record first call
	}
	return s.fakeFile.Seek(offset, whence)
}

// Test 2: Write atomic calls OpenFile(tmp) → Write → PosixRename.
// The temp path must match the pattern ".<base>.msb-tmp.<8 hex chars>".
func TestWrite_AtomicCallOrder(t *testing.T) {
	var openedPath string
	var openedFlags int
	var ff *fakeFile

	fb := &fakeBackend{
		openFileFunc: func(p string, f int) (sftpFile, error) {
			openedPath = p
			openedFlags = f
			ff = &fakeFile{}
			return ff, nil
		},
	}

	c := &Client{b: fb}
	p := mustRemotePath(t, "/tmp/hello.txt")
	data := []byte("hello world")

	if err := c.Write(p, data, 0644, true, nil); err != nil {
		t.Fatalf("Write(atomic): unexpected error: %v", err)
	}

	// The opened path must be the temp file, not the target, with the new
	// random-suffix pattern: /tmp/.hello.txt.msb-tmp.<8 hex chars>
	wantPrefix := "/tmp/.hello.txt.msb-tmp."
	if !strings.HasPrefix(openedPath, wantPrefix) {
		t.Errorf("OpenFile path: got %q, want prefix %q", openedPath, wantPrefix)
	}
	suffix := openedPath[len(wantPrefix):]
	if len(suffix) != 8 {
		t.Errorf("temp suffix len: got %d, want 8 hex chars (got %q)", len(suffix), suffix)
	}
	for _, ch := range suffix {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			t.Errorf("temp suffix contains non-hex char %q in %q", ch, suffix)
		}
	}

	// O_EXCL must be set on the open flags.
	if openedFlags&os.O_EXCL == 0 {
		t.Errorf("OpenFile flags: O_EXCL not set (flags=0x%x)", openedFlags)
	}

	// Data must have been written to the temp file.
	if ff == nil || len(ff.writes) == 0 {
		t.Fatal("no writes recorded on temp file")
	}

	// PosixRename must have been called once.
	if fb.renameCallCount != 1 {
		t.Errorf("Rename call count: got %d, want 1", fb.renameCallCount)
	}

	// No temp file removal on success.
	if fb.removeCallCount != 0 {
		t.Errorf("Remove call count: got %d, want 0 (success path)", fb.removeCallCount)
	}
}

// Test 3: Write atomic — PosixRename failure falls back to Rename, and on
// total rename failure, temp file is removed.
func TestWrite_AtomicRenameFailureRemovesTemp(t *testing.T) {
	fb := &fakeBackend{
		openFileFunc: func(path string, f int) (sftpFile, error) {
			return &fakeFile{}, nil
		},
		posixRenameErr: errors.New("posix rename not supported"),
	}

	// Build a backend where both PosixRename and Rename fail.
	fb2 := &bothRenameFail{fakeBackend: fb}

	c := &Client{b: fb2}
	p := mustRemotePath(t, "/var/app/config.yaml")

	err := c.Write(p, []byte("data"), 0600, true, nil)
	if err == nil {
		t.Fatal("expected error when both renames fail, got nil")
	}

	// The temp file must have been removed. The path matches the pattern
	// /var/app/.config.yaml.msb-tmp.<8 hex chars>.
	if fb.removeCallCount == 0 {
		t.Error("Remove not called after rename failure")
	}
	wantTmpPrefix := "/var/app/.config.yaml.msb-tmp."
	found := false
	for _, rp := range fb.removedPaths {
		if strings.HasPrefix(rp, wantTmpPrefix) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Remove not called with temp path matching prefix %q; removed: %v",
			wantTmpPrefix, fb.removedPaths)
	}
}

// bothRenameFail wraps fakeBackend making both PosixRename and Rename fail.
type bothRenameFail struct {
	*fakeBackend
}

func (b *bothRenameFail) PosixRename(oldname, newname string) error {
	b.fakeBackend.renameCallCount++
	return errors.New("posix rename failed")
}

func (b *bothRenameFail) Rename(oldname, newname string) error {
	b.fakeBackend.renameCallCount++
	return errors.New("plain rename failed")
}

// Test 4: Realpath expands "~/foo" to home+"/foo".
func TestRealpath_TildeExpansion(t *testing.T) {
	fb := &fakeBackend{
		getwdResult: "/home/alice",
		realPathFunc: func(p string) (string, error) {
			// Echo back the resolved path as-is (server considers it canonical).
			return p, nil
		},
	}
	c := &Client{b: fb}

	rp, err := c.Realpath("~/documents")
	if err != nil {
		t.Fatalf("Realpath(~/documents): %v", err)
	}
	if got, want := rp.String(), "/home/alice/documents"; got != want {
		t.Errorf("Realpath: got %q, want %q", got, want)
	}
}

// Test 5: Realpath resolves a relative path using Getwd.
func TestRealpath_RelativePath(t *testing.T) {
	fb := &fakeBackend{
		getwdResult: "/srv/www",
		realPathFunc: func(p string) (string, error) {
			return p, nil
		},
	}
	c := &Client{b: fb}

	rp, err := c.Realpath("logs/access.log")
	if err != nil {
		t.Fatalf("Realpath(relative): %v", err)
	}
	if got, want := rp.String(), "/srv/www/logs/access.log"; got != want {
		t.Errorf("Realpath: got %q, want %q", got, want)
	}
}

// Test 6: List → Entry field mapping is correct.
func TestList_EntryFieldMapping(t *testing.T) {
	modTime := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)
	fb := &fakeBackend{
		readDirFunc: func(p string) ([]os.FileInfo, error) {
			return []os.FileInfo{
				&fakeFileInfo{
					name:    "file.txt",
					size:    42,
					mode:    0644,
					modTime: modTime,
					isDir:   false,
				},
				&fakeFileInfo{
					name:    "subdir",
					size:    0,
					mode:    os.ModeDir | 0755,
					modTime: modTime,
					isDir:   true,
				},
			}, nil
		},
	}
	c := &Client{b: fb}
	p := mustRemotePath(t, "/home/user")

	entries, err := c.List(p)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries): got %d, want 2", len(entries))
	}

	// Check regular file entry.
	e := entries[0]
	if e.Name != "file.txt" {
		t.Errorf("Name: got %q, want %q", e.Name, "file.txt")
	}
	if e.Path != "/home/user/file.txt" {
		t.Errorf("Path: got %q, want %q", e.Path, "/home/user/file.txt")
	}
	if e.Size != 42 {
		t.Errorf("Size: got %d, want 42", e.Size)
	}
	if e.IsDir {
		t.Error("IsDir: got true, want false")
	}
	if !e.ModTime.Equal(modTime) {
		t.Errorf("ModTime: got %v, want %v", e.ModTime, modTime)
	}

	// Check directory entry.
	d := entries[1]
	if !d.IsDir {
		t.Error("directory IsDir: got false, want true")
	}
	if d.Path != "/home/user/subdir" {
		t.Errorf("directory Path: got %q, want %q", d.Path, "/home/user/subdir")
	}
}

// Test 7: Mode string format — regular file with 0644.
func TestEntry_ModeStringFormat(t *testing.T) {
	fi := &fakeFileInfo{
		name: "example.sh",
		mode: 0755,
	}
	e := fileInfoToEntry(fi, "/usr/local/bin", "")
	// os.FileMode(0755).String() = "-rwxr-xr-x"
	if e.Mode != "-rwxr-xr-x" {
		t.Errorf("Mode string: got %q, want %q", e.Mode, "-rwxr-xr-x")
	}
	if e.ModeBits != 0755 {
		t.Errorf("ModeBits: got %04o, want 0755", e.ModeBits)
	}
}

// Test 8: Mode string for directory — "drwxr-xr-x".
func TestEntry_DirModeStringFormat(t *testing.T) {
	fi := &fakeFileInfo{
		name:  "mydir",
		mode:  os.ModeDir | 0755,
		isDir: true,
	}
	e := fileInfoToEntry(fi, "/var", "")
	if e.Mode != "drwxr-xr-x" {
		t.Errorf("Mode string: got %q, want %q", e.Mode, "drwxr-xr-x")
	}
	if !e.IsDir {
		t.Error("IsDir: got false, want true")
	}
}

// Test 9: Read progress callback is called when reading large content.
func TestRead_ProgressCallback(t *testing.T) {
	// Create content larger than progressChunkSize (256 KiB).
	contentSize := int(progressChunkSize) + 1
	content := make([]byte, contentSize)
	for i := range content {
		content[i] = byte(i & 0xff)
	}

	fb := &fakeBackend{
		openFileFunc: func(path string, f int) (sftpFile, error) {
			return newFakeFileWithContent(content), nil
		},
	}
	c := &Client{b: fb}
	p := mustRemotePath(t, "/data/large.bin")

	var progressCalls int
	cb := func(read, total int64) {
		progressCalls++
		if read > total {
			t.Errorf("progress: read (%d) > total (%d)", read, total)
		}
	}

	_, err := c.Read(p, 0, int64(contentSize), cb)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if progressCalls == 0 {
		t.Error("progressCb was never called")
	}
}

// Test 10: Realpath with bare "~" returns home directory.
func TestRealpath_TildeAlone(t *testing.T) {
	fb := &fakeBackend{
		getwdResult: "/root",
		realPathFunc: func(p string) (string, error) {
			return p, nil
		},
	}
	c := &Client{b: fb}

	rp, err := c.Realpath("~")
	if err != nil {
		t.Fatalf("Realpath(~): %v", err)
	}
	if got, want := rp.String(), "/root"; got != want {
		t.Errorf("Realpath(~): got %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// M02 — atomic write: random temp name + O_EXCL retry
// ---------------------------------------------------------------------------

// Test 11 (M02): O_EXCL failure on first attempt triggers retry with a
// different random name.
func TestWrite_AtomicExclRetry(t *testing.T) {
	callCount := 0
	var openedPaths []string

	fb := &fakeBackend{
		openFileFunc: func(p string, f int) (sftpFile, error) {
			callCount++
			openedPaths = append(openedPaths, p)
			if callCount == 1 {
				// Simulate O_EXCL failure (file already exists).
				return nil, errors.New("file already exists")
			}
			// Second attempt succeeds.
			return &fakeFile{}, nil
		},
	}

	c := &Client{b: fb}
	p := mustRemotePath(t, "/srv/data/report.txt")

	if err := c.Write(p, []byte("content"), 0644, true, nil); err != nil {
		t.Fatalf("Write(atomic): unexpected error on retry: %v", err)
	}

	if callCount < 2 {
		t.Errorf("expected at least 2 OpenFile calls (retry), got %d", callCount)
	}

	// Both paths must match the expected prefix.
	wantPrefix := "/srv/data/.report.txt.msb-tmp."
	for _, op := range openedPaths {
		if !strings.HasPrefix(op, wantPrefix) {
			t.Errorf("opened path %q does not match prefix %q", op, wantPrefix)
		}
	}

	// The two attempted paths must be different (different random suffixes).
	if len(openedPaths) >= 2 && openedPaths[0] == openedPaths[1] {
		t.Errorf("retry used the same temp path %q instead of a new random name", openedPaths[0])
	}
}

// Test 12 (M02): Temp path format is ".<base>.msb-tmp.<8 hex chars>".
func TestWrite_AtomicTmpNameFormat(t *testing.T) {
	var openedPath string

	fb := &fakeBackend{
		openFileFunc: func(p string, f int) (sftpFile, error) {
			openedPath = p
			return &fakeFile{}, nil
		},
	}

	c := &Client{b: fb}
	p := mustRemotePath(t, "/opt/app/settings.json")

	if err := c.Write(p, []byte("{}"), 0644, true, nil); err != nil {
		t.Fatalf("Write(atomic): %v", err)
	}

	wantPrefix := "/opt/app/.settings.json.msb-tmp."
	if !strings.HasPrefix(openedPath, wantPrefix) {
		t.Fatalf("tmp path %q does not start with %q", openedPath, wantPrefix)
	}
	hexSuffix := openedPath[len(wantPrefix):]
	if len(hexSuffix) != 8 {
		t.Errorf("hex suffix len: got %d, want 8 (got %q)", len(hexSuffix), hexSuffix)
	}
	for _, ch := range hexSuffix {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			t.Errorf("non-hex char %q in suffix %q", ch, hexSuffix)
		}
	}
}

// Test 13 (M02): Multiple concurrent atomic writes to the same target produce
// unique temp names.
func TestWrite_AtomicTmpNamesUnique(t *testing.T) {
	const iterations = 20
	seen := make(map[string]bool, iterations)

	for i := 0; i < iterations; i++ {
		var openedPath string
		fb := &fakeBackend{
			openFileFunc: func(p string, f int) (sftpFile, error) {
				openedPath = p
				return &fakeFile{}, nil
			},
		}
		c := &Client{b: fb}
		p := mustRemotePath(t, "/tmp/target.bin")
		if err := c.Write(p, []byte("x"), 0600, true, nil); err != nil {
			t.Fatalf("Write(atomic) iter %d: %v", i, err)
		}
		if seen[openedPath] {
			t.Errorf("duplicate temp path on iteration %d: %q", i, openedPath)
		}
		seen[openedPath] = true
	}
}

// SDD §13 / Codex L02: Realpath must re-validate the server's response
// through safety.ValidateRemotePath. A malicious server returning a NUL
// byte / oversized / non-absolute path must be rejected.
func TestRealpath_RejectsNULFromServer(t *testing.T) {
	c := &Client{b: &fakeBackend{
		getwdResult: "/home/u",
		realPathFunc: func(p string) (string, error) {
			return "/tmp/evil\x00path", nil
		},
	}}
	_, err := c.Realpath("foo")
	if err == nil {
		t.Fatal("expected error for NUL byte in server response")
	}
}

func TestRealpath_RejectsRelativeFromServer(t *testing.T) {
	c := &Client{b: &fakeBackend{
		getwdResult: "/home/u",
		realPathFunc: func(p string) (string, error) {
			return "relative/path", nil
		},
	}}
	_, err := c.Realpath("foo")
	if err == nil {
		t.Fatal("expected error for relative path from server")
	}
}

func TestRealpath_AcceptsValidAbsolute(t *testing.T) {
	c := &Client{b: &fakeBackend{
		getwdResult: "/home/u",
		realPathFunc: func(p string) (string, error) {
			return "/etc/hosts", nil
		},
	}}
	rp, err := c.Realpath("foo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rp.String() != "/etc/hosts" {
		t.Errorf("got %q, want /etc/hosts", rp.String())
	}
}
