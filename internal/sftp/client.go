// Package sftp is a thin wrapper over github.com/pkg/sftp that enforces
// safety.RemotePath on every path argument and adds progress callbacks.
// SDD §5.6.
//
// Module boundary: this package imports only internal/safety and
// golang.org/x/crypto/ssh (for New's parameter type). It MUST NOT import
// internal/ssh.
package sftp

import (
	"os"

	pkgsftp "github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// sftpBackend is the subset of *pkgsftp.Client methods used by this package.
// Production code uses a real *pkgsftp.Client; tests inject a fake.
type sftpBackend interface {
	ReadDir(p string) ([]os.FileInfo, error)
	Stat(p string) (os.FileInfo, error)
	Lstat(p string) (os.FileInfo, error)
	ReadLink(p string) (string, error)
	OpenFile(path string, f int) (sftpFile, error)
	Mkdir(path string) error
	MkdirAll(path string) error
	Remove(path string) error
	RemoveAll(path string) error
	RemoveDirectory(path string) error
	PosixRename(oldname, newname string) error
	Rename(oldname, newname string) error
	Chmod(path string, mode os.FileMode) error
	Symlink(oldname, newname string) error
	RealPath(path string) (string, error)
	Getwd() (string, error)
	Close() error
}

// sftpFile is the subset of *pkgsftp.File used by Read/Write.
type sftpFile interface {
	Seek(offset int64, whence int) (int64, error)
	Read(b []byte) (int, error)
	Write(b []byte) (int, error)
	Close() error
}

// realBackend adapts *pkgsftp.Client to sftpBackend.
type realBackend struct{ c *pkgsftp.Client }

func (r *realBackend) ReadDir(p string) ([]os.FileInfo, error) { return r.c.ReadDir(p) }
func (r *realBackend) Stat(p string) (os.FileInfo, error)      { return r.c.Stat(p) }
func (r *realBackend) Lstat(p string) (os.FileInfo, error)     { return r.c.Lstat(p) }
func (r *realBackend) ReadLink(p string) (string, error)        { return r.c.ReadLink(p) }
func (r *realBackend) OpenFile(path string, f int) (sftpFile, error) {
	return r.c.OpenFile(path, f)
}
func (r *realBackend) Mkdir(path string) error               { return r.c.Mkdir(path) }
func (r *realBackend) MkdirAll(path string) error            { return r.c.MkdirAll(path) }
func (r *realBackend) Remove(path string) error              { return r.c.Remove(path) }
func (r *realBackend) RemoveAll(path string) error           { return r.c.RemoveAll(path) }
func (r *realBackend) RemoveDirectory(path string) error     { return r.c.RemoveDirectory(path) }
func (r *realBackend) PosixRename(oldname, newname string) error { return r.c.PosixRename(oldname, newname) }
func (r *realBackend) Rename(oldname, newname string) error  { return r.c.Rename(oldname, newname) }
func (r *realBackend) Chmod(path string, mode os.FileMode) error { return r.c.Chmod(path, mode) }
func (r *realBackend) Symlink(oldname, newname string) error { return r.c.Symlink(oldname, newname) }
func (r *realBackend) RealPath(path string) (string, error)  { return r.c.RealPath(path) }
func (r *realBackend) Getwd() (string, error)                { return r.c.Getwd() }
func (r *realBackend) Close() error                          { return r.c.Close() }

// Client is the SFTP client exposed to the rest of the project.
// It wraps a sftpBackend (production: *pkgsftp.Client) and enforces
// safety.RemotePath on every path argument.
type Client struct {
	b sftpBackend
}

// New creates a new Client from an existing SSH connection.
// The caller is responsible for closing the returned Client before closing
// the SSH connection.
func New(sshClient *ssh.Client) (*Client, error) {
	c, err := pkgsftp.NewClient(sshClient)
	if err != nil {
		return nil, err
	}
	return &Client{b: &realBackend{c: c}}, nil
}

// Close releases the underlying SFTP connection.
func (c *Client) Close() error { return c.b.Close() }
