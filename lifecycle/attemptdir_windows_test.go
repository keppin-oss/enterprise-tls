//go:build windows

package lifecycle

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

func fullDirRecord(name string, attrs uint32, last bool) []byte {
	units := utf16.Encode([]rune(name))
	rec := make([]byte, 68+2*len(units))
	binary.LittleEndian.PutUint32(rec[56:], attrs)
	binary.LittleEndian.PutUint32(rec[60:], uint32(2*len(units)))
	for i, u := range units {
		binary.LittleEndian.PutUint16(rec[68+2*i:], u)
	}
	for len(rec)%8 != 0 {
		rec = append(rec, 0)
	}
	if !last {
		binary.LittleEndian.PutUint32(rec[0:], uint32(len(rec)))
	}
	return rec
}

func TestParseFullDirInfo(t *testing.T) {
	var buf []byte
	buf = append(buf, fullDirRecord(".", windows.FILE_ATTRIBUTE_DIRECTORY, false)...)
	buf = append(buf, fullDirRecord("request.inf", windows.FILE_ATTRIBUTE_ARCHIVE, false)...)
	buf = append(buf, fullDirRecord("sub", windows.FILE_ATTRIBUTE_DIRECTORY, false)...)
	buf = append(buf, fullDirRecord("link", windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT, true)...)
	got, err := parseFullDirInfo(buf)
	want := []DirEntry{{"request.inf", EntryFile}, {"sub", EntryDirectory}, {"link", EntryReparse}}
	if err != nil || len(got) != len(want) {
		t.Fatalf("%v %v", got, err)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%d: %v", i, got[i])
		}
	}
	bad := fullDirRecord("x", 0, true)
	binary.LittleEndian.PutUint32(bad[60:], 4096)
	if _, err := parseFullDirInfo(bad); err == nil {
		t.Fatal("overlong name accepted")
	}
	if _, err := parseFullDirInfo(make([]byte, 10)); err == nil {
		t.Fatal("truncated record accepted")
	}
}

const testAttempt = "0123456789abcdef0123456789abcdef"

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestProtectedNTFSAttemptStore(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("temporary SYSTEM/BA-owned directories require an elevated test token")
	}
	dir := protectedDir(t)
	s, err := OpenAttemptStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	attempts := filepath.Join(dir, attemptsName)
	sd, err := windows.GetNamedSecurityInfo(attempts, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || checkJournalDescriptor(sd, "", true) != nil {
		t.Fatalf("attempts descriptor: %v", err)
	}
	if _, err := s.Open("not-an-id", true); err == nil {
		t.Fatal("invalid attempt ID accepted")
	}
	if _, err := s.Open(testAttempt, false); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing attempt: %v", err)
	}
	d, err := s.Open(testAttempt, true)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if again, err := s.Open(testAttempt, true); err == nil {
		again.Close()
		t.Fatal("attempt directory created twice")
	}
	data := []byte("[Version]\n")
	if err := d.WriteFile("request.inf", data); err != nil {
		t.Fatal(err)
	}
	if got, err := d.ReadFile("request.inf", 1024); err != nil || string(got) != string(data) {
		t.Fatalf("read back: %q %v", got, err)
	}
	if _, err := d.ReadFile("request.inf", 4); err == nil {
		t.Fatal("size limit ignored")
	}
	if err := d.Stat("request.inf"); err != nil {
		t.Fatal(err)
	}
	if err := d.Stat("issued.cer"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	if _, err := d.Path(`..\journal.log`); err == nil {
		t.Fatal("path escaped the attempt directory")
	}
	path, err := d.Path("request.inf")
	if err != nil || path != filepath.Join(attempts, testAttempt, "request.inf") {
		t.Fatalf("path %s %v", path, err)
	}

	// Held directories and their ancestors cannot be renamed.
	attemptPath := filepath.Join(attempts, testAttempt)
	if err := os.Rename(attemptPath, attemptPath+"-moved"); err == nil {
		t.Fatal("held attempt directory renamed")
	}
	if err := os.Rename(attempts, attempts+"-moved"); err == nil {
		t.Fatal("attempts directory renamed while the store is open")
	}

	if err := os.Mkdir(filepath.Join(attemptPath, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := d.List()
	if err != nil || len(entries) != 2 || entries[0] != (DirEntry{"request.inf", EntryFile}) ||
		entries[1] != (DirEntry{"sub", EntryDirectory}) {
		t.Fatalf("list: %v %v", entries, err)
	}
	if err := d.Stat("sub"); err == nil {
		t.Fatal("directory reported as a plain file")
	}

	// Remove verifies the content and the link count on the deleting handle.
	if err := d.Remove("request.inf", hexSum([]byte("other"))); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("wrong hash: %v", err)
	}
	alias := filepath.Join(attemptPath, "alias.inf")
	if err := os.Link(filepath.Join(attemptPath, "request.inf"), alias); err != nil {
		t.Fatal(err)
	}
	if err := d.Remove("request.inf", hexSum(data)); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("hard link: %v", err)
	}
	if _, err := d.ReadFile("request.inf", 1024); err == nil {
		t.Fatal("multi-link file read")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := d.Remove("request.inf", hexSum(data)); err != nil {
		t.Fatal(err)
	}
	if err := d.Remove("request.inf", hexSum(data)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second remove: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := s.Open(testAttempt, false); err != nil {
		t.Fatal(err)
	} else {
		reopened.Close()
	}
}

func TestProtectedNTFSAttemptStoreRefusals(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("temporary SYSTEM/BA-owned directories require an elevated test token")
	}
	// A journal directory without the private descriptor.
	if s, err := OpenAttemptStore(t.TempDir()); err == nil {
		s.Close()
		t.Fatal("unprotected journal directory accepted")
	}
	// An attempts directory that inherits instead of carrying its own
	// protected descriptor.
	dir := protectedDir(t)
	if err := os.Mkdir(filepath.Join(dir, attemptsName), 0o700); err != nil {
		t.Fatal(err)
	}
	if s, err := OpenAttemptStore(dir); err == nil {
		s.Close()
		t.Fatal("inherited attempts descriptor accepted")
	}
	// Protected directories whose ACEs files would not inherit.
	dir = protectedDir(t)
	mkdirSDDL(t, filepath.Join(dir, attemptsName), "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if s, err := OpenAttemptStore(dir); err == nil {
		s.Close()
		t.Fatal("non-inheritable attempts descriptor accepted")
	}
	dir = protectedDir(t)
	s, err := OpenAttemptStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	mkdirSDDL(t, filepath.Join(dir, attemptsName, testAttempt), "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if d, err := s.Open(testAttempt, false); err == nil {
		d.Close()
		t.Fatal("non-inheritable attempt directory accepted")
	}
	s.Close()
	// An attempts reparse point.
	dir = protectedDir(t)
	if err := os.Symlink(t.TempDir(), filepath.Join(dir, attemptsName)); err != nil {
		t.Skipf("directory symlink: %v", err)
	}
	if s, err := OpenAttemptStore(dir); err == nil {
		s.Close()
		t.Fatal("attempts reparse point accepted")
	}
}

func TestAttemptDirDescriptor(t *testing.T) {
	for sddl, ok := range map[string]bool{
		"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)":   true,
		"O:SYG:SYD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)":   true,
		"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)":           false,
		"O:BAG:BAD:P(A;OI;FA;;;SY)(A;OICI;FA;;;BA)":     false,
		"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;CI;FA;;;BA)":     false,
		"O:BAG:BAD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)":    false,
		"O:BAG:BAD:P(A;OICIIO;FA;;;SY)(A;OICI;FA;;;BA)": false,
	} {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		if got := checkAttemptDescriptor(sd) == nil; got != ok {
			t.Errorf("%s: accepted=%t", sddl, got)
		}
	}
}

func mkdirSDDL(t *testing.T, path, sddl string) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := windows.CreateDirectory(name, &sa); err != nil {
		t.Fatal(err)
	}
}
