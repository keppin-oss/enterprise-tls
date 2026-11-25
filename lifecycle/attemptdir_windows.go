//go:build windows

package lifecycle

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// AttemptStore is <journal dir>\attempts.
// It holds every component of the journal directory and the attempts
// directory open without FILE_SHARE_DELETE until Close, so no ancestor of an
// attempt directory can be renamed or replaced while it is open.
type AttemptStore struct {
	mu       sync.Mutex
	unpin    func()
	attempts windows.Handle
	path     string
}

// OpenAttemptStore pins the journal directory, which must carry the private
// broker descriptor, and opens its attempts subdirectory, creating it with
// that descriptor when absent.
func OpenAttemptStore(journalDir string) (*AttemptStore, error) {
	dir, err := filepath.Abs(journalDir)
	if err != nil {
		return nil, err
	}
	pins, unpin, err := pinDirectory(dir)
	if err != nil {
		return nil, err
	}
	leaf := pins[len(pins)-1]
	if err := checkJournalACL(leaf, "", true); err != nil {
		unpin()
		return nil, fmt.Errorf("journal directory: %w", err)
	}
	h, err := openPrivateDir(leaf, attemptsName, windows.FILE_OPEN_IF)
	if err != nil {
		unpin()
		return nil, fmt.Errorf("attempts directory: %w", err)
	}
	return &AttemptStore{unpin: unpin, attempts: h, path: filepath.Join(dir, attemptsName)}, nil
}

// Close releases the store. Attempt directories opened from it stay valid
// until their own Close, but are no longer protected against ancestor renames.
func (s *AttemptStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unpin == nil {
		return nil
	}
	windows.CloseHandle(s.attempts)
	s.unpin()
	s.unpin = nil
	return nil
}

// Open opens attempts\<id>, creating it exclusively when create is true. The
// returned directory is held without FILE_SHARE_DELETE until its Close. A
// missing directory matches fs.ErrNotExist.
func (s *AttemptStore) Open(id string, create bool) (*AttemptDir, error) {
	if !validAttemptID(id) {
		return nil, fmt.Errorf("invalid attempt ID %q", id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unpin == nil {
		return nil, errors.New("attempt store closed")
	}
	disposition := uint32(windows.FILE_OPEN)
	if create {
		disposition = windows.FILE_CREATE
	}
	h, err := openPrivateDir(s.attempts, id, disposition)
	if err != nil {
		return nil, notExist(err, id)
	}
	return &AttemptDir{h: h, path: filepath.Join(s.path, id)}, nil
}

// openPrivateDir opens or creates a plain directory under parent and checks
// the private broker descriptor (owner SY or BA, protected DACL with exactly
// SY and BA full control).
func openPrivateDir(parent windows.Handle, name string, disposition uint32) (windows.Handle, error) {
	sd, err := windows.SecurityDescriptorFromString(attemptDirSDDL)
	if err != nil {
		return 0, err
	}
	h, err := openRelative(parent, name,
		windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, disposition, windows.FILE_DIRECTORY_FILE, sd)
	if err != nil {
		return 0, err
	}
	if err := checkPlainDirectory(h); err != nil {
		windows.CloseHandle(h)
		return 0, err
	}
	if err := checkAttemptDirACL(h); err != nil {
		windows.CloseHandle(h)
		return 0, err
	}
	return h, nil
}

// checkAttemptDirACL is the private broker descriptor with both ACEs
// inheritable by files and subdirectories (OI|CI, nothing else), so that
// every file created in it inherits SYSTEM and Administrators only.
func checkAttemptDirACL(h windows.Handle) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	return checkAttemptDescriptor(sd)
}

func checkAttemptDescriptor(sd *windows.SECURITY_DESCRIPTOR) error {
	if err := checkJournalDescriptor(sd, "", true); err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceFlags != windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE {
			return errors.New("attempt directory ACEs must be inheritable by files and directories")
		}
	}
	return nil
}

// AttemptDir is one attempt directory held open. Every file is reached
// relative to its handle; names must be single plain components.
type AttemptDir struct {
	mu   sync.Mutex
	h    windows.Handle
	path string
}

// Close releases the directory handle.
func (d *AttemptDir) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.h == 0 {
		return nil
	}
	err := windows.CloseHandle(d.h)
	d.h = 0
	return err
}

// Path returns the absolute path of name for a native tool. It designates the
// held directory only while the directory and the store are open.
func (d *AttemptDir) Path(name string) (string, error) {
	if !validFileName(name) {
		return "", fmt.Errorf("invalid attempt file name %q", name)
	}
	return filepath.Join(d.path, name), nil
}

func (d *AttemptDir) open(name string, access, share, disposition uint32) (windows.Handle, error) {
	if !validFileName(name) {
		return 0, fmt.Errorf("invalid attempt file name %q", name)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.h == 0 {
		return 0, errors.New("attempt directory closed")
	}
	h, err := openRelative(d.h, name, access, share, disposition, windows.FILE_NON_DIRECTORY_FILE, nil)
	if err != nil {
		return 0, notExist(err, name)
	}
	return h, nil
}

func notExist(err error, name string) error {
	if errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) || errors.Is(err, windows.STATUS_OBJECT_PATH_NOT_FOUND) {
		return fmt.Errorf("%s: %w (%w)", name, fs.ErrNotExist, err)
	}
	return fmt.Errorf("%s: %w", name, err)
}

// checkPlainFile requires a regular, single-link file without reparse point.
func checkPlainFile(h windows.Handle) (size int64, err error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return 0, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return 0, errors.New("not a plain file")
	}
	if info.NumberOfLinks != 1 {
		return 0, errors.New("file has more than one link")
	}
	return int64(info.FileSizeHigh)<<32 | int64(info.FileSizeLow), nil
}

// ReadFile reads a plain single-link file of at most max bytes. Writers are
// excluded while it is read.
func (d *AttemptDir) ReadFile(name string, max int64) ([]byte, error) {
	h, err := d.open(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, windows.FILE_OPEN)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), name)
	defer f.Close()
	size, err := checkPlainFile(h)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if size > max {
		return nil, fmt.Errorf("%s: %d bytes, limit %d", name, size, max)
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s: grew beyond the %d byte limit", name, max)
	}
	return data, nil
}

// Stat returns nil for a plain single-link file, an error matching
// fs.ErrNotExist when the name is absent, and another error otherwise.
func (d *AttemptDir) Stat(name string) error {
	h, err := d.open(name, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	if _, err := checkPlainFile(h); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// WriteFile creates or replaces the content of a plain single-link file and
// flushes it. An existing file is checked before it is truncated.
func (d *AttemptDir) WriteFile(name string, data []byte) error {
	h, err := d.open(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, windows.FILE_OPEN_IF)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(h), name)
	defer f.Close()
	if _, err := checkPlainFile(h); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

// List enumerates the directory by handle. Names are returned as stored;
// callers validate them before use.
func (d *AttemptDir) List() ([]DirEntry, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.h == 0 {
		return nil, errors.New("attempt directory closed")
	}
	var out []DirEntry
	buf := make([]byte, 64<<10)
	class := uint32(windows.FileFullDirectoryRestartInfo)
	for {
		err := windows.GetFileInformationByHandleEx(d.h, class, &buf[0], uint32(len(buf)))
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			break
		}
		if err != nil {
			return nil, err
		}
		class = windows.FileFullDirectoryInfo
		entries, err := parseFullDirInfo(buf)
		if err != nil {
			return nil, err
		}
		out = append(out, entries...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// parseFullDirInfo decodes FILE_FULL_DIR_INFO records, skipping "." and "..".
func parseFullDirInfo(buf []byte) ([]DirEntry, error) {
	const (
		attrOffset = 56
		lenOffset  = 60
		nameOffset = 68
	)
	var out []DirEntry
	for off := 0; ; {
		if off+nameOffset > len(buf) {
			return nil, errors.New("truncated directory record")
		}
		rec := buf[off:]
		next := binary.LittleEndian.Uint32(rec[0:])
		attrs := binary.LittleEndian.Uint32(rec[attrOffset:])
		n := int(binary.LittleEndian.Uint32(rec[lenOffset:]))
		if n%2 != 0 || nameOffset+n > len(rec) {
			return nil, errors.New("malformed directory record")
		}
		units := make([]uint16, n/2)
		for i := range units {
			units[i] = binary.LittleEndian.Uint16(rec[nameOffset+2*i:])
		}
		name := string(utf16.Decode(units))
		if name != "." && name != ".." {
			kind := EntryFile
			switch {
			case attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
				kind = EntryReparse
			case attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0:
				kind = EntryDirectory
			}
			out = append(out, DirEntry{Name: name, Kind: kind})
		}
		if next == 0 {
			return out, nil
		}
		off += int(next)
	}
}

// Remove deletes name only if it is a plain single-link file whose SHA-256 is
// hash, verified on the handle that deletes it. Writers and other deleters
// are excluded meanwhile. Absent: ErrNotFound. Any mismatch: ErrNotOwned.
func (d *AttemptDir) Remove(name, hash string) error {
	if !validHash(hash) {
		return fmt.Errorf("%w: %s has no recorded hash", ErrNotOwned, name)
	}
	h, err := d.open(name, windows.GENERIC_READ|windows.DELETE, windows.FILE_SHARE_READ, windows.FILE_OPEN)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %v", ErrNotFound, err)
	}
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(h), name)
	defer f.Close()
	if _, err := checkPlainFile(h); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrNotOwned, name, err)
	}
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return err
	}
	if hex.EncodeToString(sum.Sum(nil)) != hash {
		return fmt.Errorf("%w: %s content differs from the recorded hash", ErrNotOwned, name)
	}
	return deleteHandle(h)
}
