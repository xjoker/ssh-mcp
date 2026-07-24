package sftp

// Tests for WriteFrom (io.Reader-based write path added for sftp_upload,
// see docs/design/sftp-upload-tool.md §4 step 1). Write() itself is now a
// thin bytes.Reader wrapper around WriteFrom — sftp_test.go's existing
// byte-exact Write() tests already cover that indirection, so this file
// focuses on the io.Reader entry point directly: an os.File-backed source
// (closest analogue to sftp_upload's real usage) streamed through
// WriteFrom, verified both byte-for-byte and via sha256 digest comparison
// against the local source, mirroring what the sftp_upload handler will
// compute via io.TeeReader.
import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type readerFromFile struct {
	fakeFile
	readFromCalls int
	sizeSeen      int64
}

func (f *readerFromFile) ReadFrom(r io.Reader) (int64, error) {
	f.readFromCalls++
	f.sizeSeen = -1
	if sized, ok := r.(interface{ Size() int64 }); ok {
		f.sizeSeen = sized.Size()
	}
	// Hide ReaderFrom from io.Copy so this test double consumes the wrapped
	// reader exactly once instead of recursively selecting ReadFrom again.
	return io.Copy(struct{ io.Writer }{Writer: &f.fakeFile}, r)
}

// writeFromAndCapture streams data (via a real os.File, not an in-memory
// reader) through Client.WriteFrom and returns the bytes the fake backend
// captured.
func writeFromAndCapture(t *testing.T, data []byte, atomic bool) []byte {
	t.Helper()

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "upload-src.bin")
	if err := os.WriteFile(srcPath, data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	src, err := os.Open(srcPath) // #nosec G304 -- test-only, path built from t.TempDir()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer src.Close()

	var captured *fakeFile
	fb := &fakeBackend{
		openFileFunc: func(p string, f int) (sftpFile, error) {
			ff := &fakeFile{}
			captured = ff
			return ff, nil
		},
	}
	c := &Client{b: fb}
	p := mustRemotePath(t, "/srv/app/upload-dst.bin")

	if err := c.WriteFrom(p, src, int64(len(data)), 0644, atomic, nil); err != nil {
		t.Fatalf("WriteFrom: unexpected error: %v", err)
	}
	return captured.buf
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return buf
}

// TestWriteFrom_ByteExact_100KiB verifies a 100 KiB source streamed through
// WriteFrom (io.Reader, os.File-backed) lands byte-for-byte identical on the
// "remote" side, for both atomic and direct writes.
func TestWriteFrom_ByteExact_100KiB(t *testing.T) {
	data := randomBytes(t, 100*1024)
	for _, atomic := range []bool{true, false} {
		got := writeFromAndCapture(t, data, atomic)
		if !bytes.Equal(got, data) {
			t.Fatalf("atomic=%v: byte mismatch, len got=%d want=%d", atomic, len(got), len(data))
		}
	}
}

// TestWriteFrom_Sha256_100KiB verifies the sha256 of what actually reached
// the "remote" side matches the sha256 computed over the local source —
// this is the same invariant the sftp_upload handler relies on when it
// wraps the source file in an io.TeeReader to compute the response's
// "sha256" field without buffering the whole upload in memory.
func TestWriteFrom_Sha256_100KiB(t *testing.T) {
	data := randomBytes(t, 100*1024)
	want := sha256.Sum256(data)

	got := writeFromAndCapture(t, data, true)
	gotSum := sha256.Sum256(got)

	if hex.EncodeToString(gotSum[:]) != hex.EncodeToString(want[:]) {
		t.Fatalf("sha256 mismatch: got %x want %x", gotSum, want)
	}
}

// TestWriteFrom_PartialWrites_ChunkBoundary: force the backend to accept
// only 4096 bytes per Write() call across a source whose length is not a
// multiple of readChunkSize, exercising copyWithProgress's inner retry loop
// exactly as sftp_op's writeAndCapture already does for the []byte path.
func TestWriteFrom_PartialWrites_ChunkBoundary(t *testing.T) {
	data := randomBytes(t, readChunkSize+4097)

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "upload-src.bin")
	if err := os.WriteFile(srcPath, data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	src, err := os.Open(srcPath) // #nosec G304 -- test-only, path built from t.TempDir()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer src.Close()

	var captured *fakeFile
	fb := &fakeBackend{
		openFileFunc: func(p string, f int) (sftpFile, error) {
			pf := &partialWriteFile{maxPerCall: 4096}
			captured = &pf.fakeFile
			return pf, nil
		},
	}
	c := &Client{b: fb}
	p := mustRemotePath(t, "/srv/app/upload-dst.bin")

	if err := c.WriteFrom(p, src, int64(len(data)), 0644, true, nil); err != nil {
		t.Fatalf("WriteFrom: unexpected error: %v", err)
	}
	if !bytes.Equal(captured.buf, data) {
		t.Fatalf("byte mismatch: len got=%d want=%d", len(captured.buf), len(data))
	}
}

// TestWriteFrom_ProgressCallback_TotalIsSize verifies progressCb receives
// the caller-supplied size as "total" on every call, matching Write's
// len(data) semantics.
func TestWriteFrom_ProgressCallback_TotalIsSize(t *testing.T) {
	data := randomBytes(t, 2*progressChunkSize+1)

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "upload-src.bin")
	if err := os.WriteFile(srcPath, data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	src, err := os.Open(srcPath) // #nosec G304 -- test-only, path built from t.TempDir()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer src.Close()

	fb := &fakeBackend{
		openFileFunc: func(p string, f int) (sftpFile, error) {
			return &fakeFile{}, nil
		},
	}
	c := &Client{b: fb}
	p := mustRemotePath(t, "/srv/app/upload-dst.bin")

	var calls int
	var lastWritten, lastTotal int64
	cb := func(written, total int64) {
		calls++
		lastWritten = written
		lastTotal = total
	}

	if err := c.WriteFrom(p, src, int64(len(data)), 0644, true, cb); err != nil {
		t.Fatalf("WriteFrom: unexpected error: %v", err)
	}
	if calls == 0 {
		t.Fatal("expected at least one progress callback")
	}
	if lastTotal != int64(len(data)) {
		t.Errorf("last total: got %d want %d", lastTotal, len(data))
	}
	if lastWritten != int64(len(data)) {
		t.Errorf("last written: got %d want %d (final callback should report full completion)", lastWritten, len(data))
	}
}

func TestWriteFrom_ReaderFromPath_ByteExactSizeAndProgress(t *testing.T) {
	data := randomBytes(t, 2*progressChunkSize+1)
	wantSHA := sha256.Sum256(data)

	dst := &readerFromFile{}
	fb := &fakeBackend{
		openFileFunc: func(string, int) (sftpFile, error) {
			return dst, nil
		},
	}
	c := &Client{b: fb}
	p := mustRemotePath(t, "/srv/app/concurrent-upload.bin")

	var progress []int64
	cb := func(written, total int64) {
		if total != int64(len(data)) {
			t.Errorf("progress total = %d, want %d", total, len(data))
		}
		if len(progress) > 0 && written < progress[len(progress)-1] {
			t.Errorf("progress regressed from %d to %d", progress[len(progress)-1], written)
		}
		progress = append(progress, written)
	}

	if err := c.WriteFrom(p, bytes.NewReader(data), int64(len(data)), 0o644, true, cb); err != nil {
		t.Fatalf("WriteFrom: %v", err)
	}
	if dst.readFromCalls != 1 {
		t.Fatalf("ReadFrom calls = %d, want 1", dst.readFromCalls)
	}
	if dst.sizeSeen != int64(len(data)) {
		t.Fatalf("Size() = %d, want %d", dst.sizeSeen, len(data))
	}
	if !bytes.Equal(dst.buf, data) {
		t.Fatalf("byte mismatch: len got=%d want=%d", len(dst.buf), len(data))
	}
	gotSHA := sha256.Sum256(dst.buf)
	if gotSHA != wantSHA {
		t.Fatalf("sha256 mismatch: got %x want %x", gotSHA, wantSHA)
	}
	if len(progress) < 2 {
		t.Fatalf("progress callbacks = %d, want periodic and final callbacks", len(progress))
	}
	var sawIntermediate bool
	for _, written := range progress {
		if written > 0 && written < int64(len(data)) {
			sawIntermediate = true
			break
		}
	}
	if !sawIntermediate {
		t.Fatalf("progress = %v, want at least one value between 0 and %d", progress, len(data))
	}
	if got := progress[len(progress)-1]; got != int64(len(data)) {
		t.Fatalf("final progress = %d, want %d", got, len(data))
	}
}
