package sftp

// Investigation test file for the 2026-07-01 unverified report: "uploading a
// ~20KB shell script via sftp_op write produced a corrupted/misaligned
// remote file". These tests exercise Client.Write's chunking loop
// (writeWithProgress in ops.go, readChunkSize=32KiB) with byte-exact
// comparisons, including a short-write backend to stress the loop's
// resume-after-partial-write logic, which is the only place in this codebase
// that splits a single write() call into multiple wire writes. There is no
// append/offset write path in sftp_op — "write" always does one full-file
// atomic (or direct) write per MCP call.

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"os"
	"testing"
)

// partialWriteFile wraps fakeFile but truncates every Write() call to at
// most maxPerCall bytes, forcing writeWithProgress's `for len(data) > 0`
// loop to run many more iterations than the 32KiB chunk size alone would
// produce. This is the closest local analogue to a real SFTP connection
// returning short writes under packet-size / congestion pressure.
type partialWriteFile struct {
	fakeFile
	maxPerCall int
}

func (f *partialWriteFile) Write(b []byte) (int, error) {
	n := len(b)
	if n > f.maxPerCall {
		n = f.maxPerCall
	}
	return f.fakeFile.Write(b[:n])
}

// randomShellLikeContent builds n bytes of pseudo-random content sprinkled
// with shell metacharacters ($, `, ", ', \, |, ;, &, newlines, tabs) — the
// kind of content a ~20KB shell script would contain — using crypto/rand so
// results aren't affected by any package-level PRNG seeding elsewhere in the suite.
func randomShellLikeContent(t *testing.T, n int) []byte {
	t.Helper()
	special := []byte("$`\"'\\|;&(){}[]<>*?~#!\n\t ")
	buf := make([]byte, n)
	for i := 0; i < n; i++ {
		// ~1 in 6 bytes is a shell metacharacter; rest is printable ASCII.
		useSpecial, err := rand.Int(rand.Reader, big.NewInt(6))
		if err != nil {
			t.Fatalf("rand: %v", err)
		}
		if useSpecial.Int64() == 0 {
			idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(special))))
			if err != nil {
				t.Fatalf("rand: %v", err)
			}
			buf[i] = special[idx.Int64()]
			continue
		}
		v, err := rand.Int(rand.Reader, big.NewInt(95)) // printable ASCII 0x20-0x7e
		if err != nil {
			t.Fatalf("rand: %v", err)
		}
		buf[i] = byte(0x20 + v.Int64())
	}
	return buf
}

func writeAndCapture(t *testing.T, data []byte, atomic bool, perCallCap int) []byte {
	t.Helper()
	var captured *fakeFile
	fb := &fakeBackend{
		openFileFunc: func(p string, f int) (sftpFile, error) {
			if perCallCap > 0 {
				pf := &partialWriteFile{maxPerCall: perCallCap}
				captured = &pf.fakeFile
				return pf, nil
			}
			ff := &fakeFile{}
			captured = ff
			return ff, nil
		},
	}
	c := &Client{b: fb}
	p := mustRemotePath(t, "/srv/app/deploy.sh")
	if err := c.Write(p, data, 0644, atomic, nil); err != nil {
		t.Fatalf("Write: unexpected error: %v", err)
	}
	return captured.buf
}

// TestWrite_ByteExact_20KiB_ShellContent: single-call write of ~20KB of
// shell-script-like content (random + metacharacters) must land byte-for-byte
// identical on the "remote" file, both in atomic and direct mode.
func TestWrite_ByteExact_20KiB_ShellContent(t *testing.T) {
	data := randomShellLikeContent(t, 20*1024)
	for _, atomic := range []bool{true, false} {
		got := writeAndCapture(t, data, atomic, 0)
		if !bytes.Equal(got, data) {
			t.Fatalf("atomic=%v: byte mismatch, len got=%d want=%d", atomic, len(got), len(data))
		}
	}
}

// TestWrite_ByteExact_100KiB_ShellContent: same at 100KB — spans multiple
// 32KiB writeWithProgress chunks (100KB / 32KiB ≈ 3.2 chunks).
func TestWrite_ByteExact_100KiB_ShellContent(t *testing.T) {
	data := randomShellLikeContent(t, 100*1024)
	for _, atomic := range []bool{true, false} {
		got := writeAndCapture(t, data, atomic, 0)
		if !bytes.Equal(got, data) {
			t.Fatalf("atomic=%v: byte mismatch, len got=%d want=%d", atomic, len(got), len(data))
		}
	}
}

// TestWrite_ByteExact_PartialWrites: force the backend to accept only 4096
// bytes per Write() call (well below the 32KiB chunk size), so
// writeWithProgress's inner loop must resume correctly many times within a
// single 32KiB chunk. This is the scenario most likely to reveal an
// off-by-one / dropped-bytes bug in the chunking logic if one exists.
func TestWrite_ByteExact_PartialWrites(t *testing.T) {
	data := randomShellLikeContent(t, 100*1024)
	got := writeAndCapture(t, data, true, 4096)
	if !bytes.Equal(got, data) {
		// Find first mismatch for a useful failure message.
		n := len(got)
		if len(data) < n {
			n = len(data)
		}
		idx := -1
		for i := 0; i < n; i++ {
			if got[i] != data[i] {
				idx = i
				break
			}
		}
		t.Fatalf("byte mismatch: len got=%d want=%d, first diff at index %d", len(got), len(data), idx)
	}
}

// TestWrite_ByteExact_NewlineBoundaries: content ending with \n, content NOT
// ending with \n, and CRLF-heavy content must all round-trip exactly with no
// injected/stripped/translated line endings.
func TestWrite_ByteExact_NewlineBoundaries(t *testing.T) {
	cases := map[string][]byte{
		"trailing_lf":    []byte("#!/bin/sh\necho hi\n"),
		"no_trailing_lf": []byte("#!/bin/sh\necho hi"),
		"crlf":           []byte("#!/bin/sh\r\necho hi\r\n"),
		"mixed_lf_crlf":  []byte("line1\nline2\r\nline3\n\r\n"),
		"only_newlines":  []byte("\n\n\n\n"),
		"embedded_nul":   append([]byte("before"), append([]byte{0x00}, []byte("after\n")...)...),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			got := writeAndCapture(t, data, true, 0)
			if !bytes.Equal(got, data) {
				t.Fatalf("%s: byte mismatch: got %q want %q", name, got, data)
			}
		})
	}
}

// TestWrite_ByteExact_ChunkBoundaryExact: content whose length is an exact
// multiple of readChunkSize (32KiB), and one byte over/under, to catch
// off-by-one errors at the chunk boundary itself.
func TestWrite_ByteExact_ChunkBoundaryExact(t *testing.T) {
	sizes := []int{
		readChunkSize - 1,
		readChunkSize,
		readChunkSize + 1,
		2 * readChunkSize,
		2*readChunkSize + 1,
	}
	for _, size := range sizes {
		data := randomShellLikeContent(t, size)
		got := writeAndCapture(t, data, true, 0)
		if !bytes.Equal(got, data) {
			t.Fatalf("size=%d: byte mismatch, len got=%d want=%d", size, len(got), len(data))
		}
	}
}

// Ensure os import stays used if future edits trim other usages (mode arg
// in Client.Write requires os.FileMode, exercised transitively above).
var _ = os.FileMode(0)
