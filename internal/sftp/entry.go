package sftp

import (
	"os"
	"path"
	"time"
)

// Entry represents a single file system entry on the remote host.
// SDD §5.6.
type Entry struct {
	Name     string    `json:"name"`
	Path     string    `json:"path"`
	Size     int64     `json:"size"`
	Mode     string    `json:"mode"`
	ModeBits uint32    `json:"mode_bits"`
	ModTime  time.Time `json:"mod_time"`
	IsDir    bool      `json:"is_dir"`
	IsLink   bool      `json:"is_link"`
	LinkTo   string    `json:"link_to,omitempty"`
}

// fileInfoToEntry converts an os.FileInfo to an Entry.
// parentDir is the directory containing the entry (used to build Path).
// linkTo is non-empty when the entry is a symlink target (already resolved by caller).
func fileInfoToEntry(fi os.FileInfo, parentDir string, linkTo string) Entry {
	mode := fi.Mode()
	isLink := mode&os.ModeSymlink != 0

	e := Entry{
		Name:     fi.Name(),
		Path:     path.Join(parentDir, fi.Name()),
		Size:     fi.Size(),
		Mode:     mode.String(),
		ModeBits: uint32(mode.Perm()),
		ModTime:  fi.ModTime(),
		IsDir:    fi.IsDir(),
		IsLink:   isLink,
		LinkTo:   linkTo,
	}
	return e
}
