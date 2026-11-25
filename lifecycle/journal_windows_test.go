//go:build windows

package lifecycle

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestProtectedNTFSJournalLeaseAndReopen(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("temporary SYSTEM/BA-owned journal requires an elevated test token")
	}
	dir := filepath.Join(t.TempDir(), "protected")
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := windows.CreateDirectory(name, &sa); err != nil {
		t.Fatal(err)
	}
	j, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if other, err := OpenJournal(dir); err == nil {
		other.Close()
		t.Fatal("second journal acquired an exclusive lease")
	}
	a := Activator{Journal: j, Consumer: &testConsumer{}}
	g, err := a.Reserve(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(ctx, Activation{g, hashA}); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dir, dir+"-moved"); err == nil {
		t.Fatal("pinned directory was renamed")
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	g2, err := (Activator{Journal: reopened}).Reserve(ctx)
	if err != nil || g2 <= g {
		t.Fatalf("counter lost: %d %v", g2, err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(dir, "journal.log"), filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	if linked, err := OpenJournal(dir); err == nil {
		linked.Close()
		t.Fatal("multi-link journal accepted")
	}
}

func TestPrivateJournalDescriptor(t *testing.T) {
	cases := []struct {
		sddl  string
		valid bool
	}{
		{"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)", true},
		{"O:SYG:SYD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)", true},
		{"O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)", false},
		{"O:LSG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)", false},
		{"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;WD)", false},
		{"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;SY)", false},
		{"O:BAG:BAD:P(A;;FR;;;SY)(A;;FA;;;BA)", false},
		{"O:BAG:BAD:P(A;IO;FA;;;SY)(A;;FA;;;BA)", false},
		{"O:BAG:BAD:P(A;ID;FA;;;SY)(A;;FA;;;BA)", false},
		{"O:BAG:BAD:P(D;;FA;;;SY)(A;;FA;;;BA)", false},
		{"O:BAG:BAD:P", false},
	}
	for _, tc := range cases {
		t.Run(tc.sddl, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tc.sddl)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkPrivateDescriptor(sd); (err == nil) != tc.valid {
				t.Fatalf("valid=%t err=%v", tc.valid, err)
			}
		})
	}
}

func TestConsumerJournalCannotAuthorizeBrokerWrites(t *testing.T) {
	sid := "S-1-5-80-1-2-3-4-5"
	for _, tc := range []struct {
		mask             string
		directory, valid bool
	}{
		{"0x1200a9", true, true},
		{"0x12019f", false, true},
		{"FA", false, false},
		{"0x12019f", true, false},
		{"0x1200a9", false, false},
	} {
		sddl := "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;" + tc.mask + ";;;" + sid + ")"
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkJournalDescriptor(sd, sid, tc.directory); (err == nil) != tc.valid {
			t.Fatalf("mask=%s directory=%v err=%v", tc.mask, tc.directory, err)
		}
		if err := checkPrivateDescriptor(sd); err == nil {
			t.Fatal("consumer-writable file accepted as broker authority")
		}
	}
	j := &FileJournal{state: emptyState(), activationOnly: true}
	s := emptyState()
	s.Operation = &Operation{Sequence: 1, Name: "native-op"}
	if err := (fileTransaction{j}).Save(s); err == nil {
		t.Fatal("consumer journal allowed native-operation authority")
	}
}

// protectedDir creates a SYSTEM/BA-only directory like a provisioned broker
// journal directory. It requires an elevated test token.
func protectedDir(t *testing.T) string {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("temporary SYSTEM/BA-owned journal requires an elevated test token")
	}
	dir := filepath.Join(t.TempDir(), "protected")
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := windows.CreateDirectory(name, &sa); err != nil {
		t.Fatal(err)
	}
	return dir
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// Real NTFS compaction keeps the lease, leaves only journal.log and survives
// reopen; appends continue after the checkpoint.
func TestProtectedNTFSJournalCompaction(t *testing.T) {
	dir := protectedDir(t)
	j, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	a := Activator{Journal: j, Consumer: &testConsumer{}}
	for range 5 {
		if _, err := a.Reserve(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Apply(ctx, Activation{3, hashA}); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(filepath.Join(dir, journalName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Compact(ctx, CompactOptions{}); err != nil {
		t.Fatal(err)
	}
	if names := dirNames(t, dir); len(names) != 1 || names[0] != journalName {
		t.Fatalf("directory after compaction: %v", names)
	}
	after, err := os.Stat(filepath.Join(dir, journalName))
	if err != nil || after.Size() >= before.Size() {
		t.Fatalf("journal not compacted: %d -> %d (%v)", before.Size(), after.Size(), err)
	}
	if other, err := OpenJournal(dir); err == nil {
		other.Close()
		t.Fatal("lease lost by compaction")
	}
	if g, err := a.Reserve(ctx); err != nil || g != 6 {
		t.Fatalf("append after compaction: %d %v", g, err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	s := reopened.state
	if s.Counter != 6 || s.Target != (Activation{3, hashA}) || s.Compaction == nil {
		t.Fatalf("state after reopen: %+v", s)
	}
}

// Every stop point of the replacement reopens to a consistent journal.
func TestProtectedNTFSJournalInterruptedCompaction(t *testing.T) {
	dir := protectedDir(t)
	j, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if _, err := (Activator{Journal: j}).Reserve(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Compact(ctx, CompactOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, journalName)
	tmp := filepath.Join(dir, journalTmp)
	old := filepath.Join(dir, journalOld)
	reopen := func() State {
		t.Helper()
		r, err := OpenJournal(dir)
		if err != nil {
			t.Fatalf("reopen with %v: %v", dirNames(t, dir), err)
		}
		defer r.Close()
		if names := dirNames(t, dir); len(names) != 1 || names[0] != journalName {
			t.Fatalf("leftovers after reopen: %v", names)
		}
		return r.state
	}

	// Stop before the first rename: a partial journal.tmp is discarded.
	if err := os.WriteFile(tmp, []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if s := reopen(); s.Counter != 1 {
		t.Fatalf("state: %+v", s)
	}
	// Stop after the second rename: journal.old is removed.
	if err := os.WriteFile(old, []byte("previous log"), 0600); err != nil {
		t.Fatal(err)
	}
	if s := reopen(); s.Counter != 1 {
		t.Fatalf("state: %+v", s)
	}
	// Stop between the renames: the flushed journal.tmp becomes journal.log.
	// Renaming keeps the explicit protected descriptor of the file.
	if err := os.Rename(log, tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(old, []byte("previous log"), 0600); err != nil {
		t.Fatal(err)
	}
	if s := reopen(); s.Counter != 1 {
		t.Fatalf("state: %+v", s)
	}
	// journal.old alone is never adopted or replaced by an empty journal.
	if err := os.Rename(log, old); err != nil {
		t.Fatal(err)
	}
	if r, err := OpenJournal(dir); err == nil {
		r.Close()
		t.Fatal("journal.old alone silently replaced")
	}
	if _, err := os.Stat(old); err != nil {
		t.Fatalf("journal.old touched: %v", err)
	}
}

// Recovery validates before it deletes. Ambiguous or invalid
// candidates fail closed and every file is kept for inspection.
func TestProtectedNTFSJournalRecoveryKeepsFilesWhenInvalid(t *testing.T) {
	dir := protectedDir(t)
	j, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if _, err := (Activator{Journal: j}).Reserve(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Compact(ctx, CompactOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, journalName)
	tmp := filepath.Join(dir, journalTmp)
	old := filepath.Join(dir, journalOld)
	checkpoint, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	mustFail := func(want ...string) {
		t.Helper()
		if r, err := OpenJournal(dir); err == nil {
			r.Close()
			t.Fatalf("opened with %v", dirNames(t, dir))
		}
		if got := dirNames(t, dir); !slices.Equal(got, want) {
			t.Fatalf("files after refused open: %v, want %v", got, want)
		}
	}
	// A truncated journal.tmp is never promoted, and journal.old is kept.
	if err := os.Rename(log, old); err != nil {
		t.Fatal(err)
	}
	writeProtected(t, tmp, checkpoint[:len(checkpoint)-1])
	mustFail(journalOld, journalTmp)
	// Neither is a journal.tmp holding ordinary frames instead of a checkpoint.
	plain := emptyState()
	plain.Revision = 1
	frame, _ := encodeFrame(plain)
	writeProtected(t, tmp, frame)
	mustFail(journalOld, journalTmp)
	// An empty journal.log next to leftovers is not adopted as a new journal.
	if err := os.Remove(tmp); err != nil {
		t.Fatal(err)
	}
	writeProtected(t, tmp, checkpoint)
	writeProtected(t, log, nil)
	mustFail(journalName, journalOld, journalTmp)
	// A corrupt journal.log keeps both leftovers.
	writeProtected(t, log, checkpoint[:10])
	mustFail(journalName, journalOld, journalTmp)
}

// writeProtected writes a file with the broker journal descriptor, owner
// included, so that recovery reaches the frame checks instead of failing on
// inherited ACEs or on the default owner the creating token assigns.
func writeProtected(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString(brokerSDDL)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if err := withHandle(path, func(h windows.Handle) error { return checkJournalFile(h, "") }); err != nil {
		t.Fatalf("test file not accepted as a protected journal file: %v", err)
	}
}

func withHandle(path string, fn func(windows.Handle) error) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return fn(h)
}
