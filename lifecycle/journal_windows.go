//go:build windows

package lifecycle

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// pinDirectory opens every component of dir, from the volume root, without
// FILE_SHARE_DELETE and without following reparse points: while the handles
// are held no component can be renamed or replaced. dir must be on a fixed
// local NTFS volume. The last handle is the leaf; unpin closes them all.
func pinDirectory(dir string) (pins []windows.Handle, unpin func(), err error) {
	dir, err = filepath.Abs(dir)
	if err != nil {
		return nil, nil, err
	}
	volume := filepath.VolumeName(dir)
	if len(volume) != 2 || volume[1] != ':' {
		return nil, nil, errors.New("local drive required")
	}
	root, err := windows.UTF16PtrFromString(volume + `\`)
	if err != nil {
		return nil, nil, err
	}
	if windows.GetDriveType(root) != windows.DRIVE_FIXED {
		return nil, nil, errors.New("fixed local volume required")
	}
	unpin = func() {
		for i := len(pins) - 1; i >= 0; i-- {
			windows.CloseHandle(pins[i])
		}
	}
	fail := func(err error) ([]windows.Handle, func(), error) { unpin(); return nil, nil, err }
	parts := strings.Split(strings.TrimPrefix(dir[len(volume):], `\`), `\`)
	for i := -1; i < len(parts); i++ {
		var h windows.Handle
		var err error
		if i < 0 {
			h, err = windows.CreateFile(root, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
				windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
				windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		} else {
			if parts[i] == "" {
				continue
			}
			h, err = openRelative(pins[len(pins)-1], parts[i],
				windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
				windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.FILE_OPEN,
				windows.FILE_DIRECTORY_FILE, nil)
		}
		if err != nil {
			return fail(err)
		}
		pins = append(pins, h)
		if err := checkPlainDirectory(h); err != nil {
			return fail(err)
		}
	}
	var fs [32]uint16
	if err := windows.GetVolumeInformationByHandle(pins[len(pins)-1], nil, 0, nil, nil, nil, &fs[0], uint32(len(fs))); err != nil {
		return fail(err)
	}
	if windows.UTF16ToString(fs[:]) != "NTFS" {
		return fail(errors.New("NTFS required"))
	}
	return pins, unpin, nil
}

func checkPlainDirectory(h windows.Handle) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return errors.New("directory component is not a plain directory")
	}
	return nil
}

// Hold every directory component open without FILE_SHARE_DELETE. Subsequent
// opens cannot be redirected by renaming/replacing an ancestor. Reparse points
// and remote volumes are outside this adapter's supported storage contract.
func openJournalFile(dir, consumerSID string) (*os.File, func(), journalReplacer, error) {
	if consumerSID != "" {
		sid, err := windows.StringToSid(consumerSID)
		if err != nil || !strings.HasPrefix(consumerSID, "S-1-5-80-") ||
			len(strings.Split(consumerSID, "-")) != 9 || sid.String() != consumerSID {
			return nil, nil, nil, errors.New("dedicated canonical service SID required")
		}
	}
	pins, unpin, err := pinDirectory(dir)
	if err != nil {
		return nil, nil, nil, err
	}
	fail := func(err error) (*os.File, func(), journalReplacer, error) { unpin(); return nil, nil, nil, err }
	leaf := pins[len(pins)-1]
	if err := checkJournalACL(leaf, consumerSID, true); err != nil {
		return fail(err)
	}
	if consumerSID != "" {
		// The privileged installer owns provisioning; no create, no delete.
		h, err := openRelative(leaf, journalName, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL,
			0, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE, nil)
		if err != nil {
			return fail(err)
		}
		if err := checkJournalFile(h, consumerSID); err != nil {
			windows.CloseHandle(h)
			return fail(err)
		}
		return os.NewFile(uintptr(h), journalName), unpin, nil, nil
	}
	h, err := openBrokerJournal(leaf)
	if err != nil {
		return fail(err)
	}
	replace := func(current *os.File, frame []byte) (*os.File, bool, error) {
		return replaceJournal(leaf, current, frame)
	}
	return os.NewFile(uintptr(h), journalName), unpin, replace, nil
}

const (
	journalName = "journal.log"
	// journalTmp holds a complete, flushed checkpoint during Compact.
	journalTmp = "journal.tmp"
	// journalOld is the previous file, renamed aside through its own handle.
	journalOld = "journal.old"
	// The broker handle needs DELETE to rename itself aside during Compact.
	// Share mode stays 0: holding any of these handles is the lease.
	brokerAccess = windows.GENERIC_READ | windows.GENERIC_WRITE | windows.READ_CONTROL | windows.DELETE
	brokerSDDL   = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
)

// openBrokerJournal opens journal.log exclusively, finishing or discarding an
// interrupted compaction:
//   - journal.log present: it is authoritative; a leftover journal.tmp (stop
//     before the first rename) or journal.old (stop after the second) is removed;
//   - journal.log absent, journal.tmp present: Compact stopped between its two
//     renames after flushing journal.tmp, which becomes journal.log;
//   - only journal.old present: fail closed for administrator inspection;
//   - nothing present: create an empty journal.
//
// Another process cannot interleave: during the window without journal.log the
// compacting process holds journal.tmp with share mode 0.
func openBrokerJournal(leaf windows.Handle) (windows.Handle, error) {
	h, err := openRelative(leaf, journalName, brokerAccess, 0, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE, nil)
	switch {
	case err == nil:
		if err := checkJournalFile(h, ""); err != nil {
			windows.CloseHandle(h)
			return 0, err
		}
		var stale []string
		for _, name := range []string{journalTmp, journalOld} {
			ok, err := existsRelative(leaf, name)
			if err != nil {
				windows.CloseHandle(h)
				return 0, err
			}
			if ok {
				stale = append(stale, name)
			}
		}
		if len(stale) == 0 {
			return h, nil
		}
		// Leftovers go only after the live journal proves complete and
		// non-empty under the lease; otherwise every file stays for inspection.
		_, n, err := scanFrames(handleReader(h))
		if err == nil && n == 0 {
			err = errors.New("empty")
		}
		if err == nil {
			err = rewind(h)
		}
		if err != nil {
			windows.CloseHandle(h)
			return 0, fmt.Errorf("journal.log with %v is not a valid journal (%w): files kept for administrator inspection", stale, err)
		}
		for _, name := range stale {
			if err := removeRelative(leaf, name); err != nil {
				windows.CloseHandle(h)
				return 0, fmt.Errorf("remove stale %s: %w", name, err)
			}
		}
		return h, nil
	case !errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND):
		return 0, err
	}
	t, err := openRelative(leaf, journalTmp, brokerAccess, 0, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE, nil)
	switch {
	case err == nil:
		if err := checkJournalFile(t, ""); err != nil {
			windows.CloseHandle(t)
			return 0, err
		}
		// Compact flushes exactly one checkpoint before the first rename;
		// anything else is not that file, and journal.old is kept.
		err := isCheckpointFile(handleReader(t))
		if err == nil {
			err = rewind(t)
		}
		if err != nil {
			windows.CloseHandle(t)
			return 0, fmt.Errorf("journal.tmp without journal.log is not a complete checkpoint (%w): files kept for administrator inspection", err)
		}
		if err := renameHandle(t, leaf, journalName, false); err != nil {
			windows.CloseHandle(t)
			return 0, fmt.Errorf("complete interrupted compaction: %w", err)
		}
		if err := windows.FlushFileBuffers(t); err != nil {
			windows.CloseHandle(t)
			return 0, err
		}
		if err := removeRelative(leaf, journalOld); err != nil {
			windows.CloseHandle(t)
			return 0, fmt.Errorf("remove stale %s: %w", journalOld, err)
		}
		return t, nil
	case !errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND):
		return 0, err
	}
	if o, err := openRelative(leaf, journalOld, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE, nil); err == nil {
		windows.CloseHandle(o)
		return 0, errors.New("journal.old without journal.log or journal.tmp: administrator inspection required")
	} else if !errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) {
		return 0, err
	}
	sd, err := windows.SecurityDescriptorFromString(brokerSDDL)
	if err != nil {
		return 0, err
	}
	h, err = openRelative(leaf, journalName, brokerAccess, 0, windows.FILE_CREATE, windows.FILE_NON_DIRECTORY_FILE, sd)
	if err != nil {
		return 0, err
	}
	if err := checkJournalFile(h, ""); err != nil {
		windows.CloseHandle(h)
		return 0, err
	}
	return h, nil
}

// replaceJournal implements FileJournal.replace for the broker journal. It
// closes current only when it returns a new file.
func replaceJournal(leaf windows.Handle, current *os.File, frame []byte) (*os.File, bool, error) {
	if err := removeRelative(leaf, journalTmp); err != nil {
		return nil, false, err
	}
	sd, err := windows.SecurityDescriptorFromString(brokerSDDL)
	if err != nil {
		return nil, false, err
	}
	t, err := openRelative(leaf, journalTmp, brokerAccess, 0, windows.FILE_CREATE, windows.FILE_NON_DIRECTORY_FILE, sd)
	if err != nil {
		return nil, false, err
	}
	next := os.NewFile(uintptr(t), journalName)
	discard := func(err error) (*os.File, bool, error) {
		next.Close()
		return nil, false, errors.Join(err, removeRelative(leaf, journalTmp))
	}
	if err := checkJournalFile(t, ""); err != nil {
		return discard(err)
	}
	if _, err := next.Write(frame); err != nil {
		return discard(err)
	}
	if err := next.Sync(); err != nil {
		return discard(err)
	}
	// 1. The live file moves aside. From here until step 2, reopening
	// completes the replacement from the flushed journal.tmp.
	if err := renameHandle(windows.Handle(current.Fd()), leaf, journalOld, true); err != nil {
		return discard(err)
	}
	// 2. The checkpoint takes the journal name.
	if err := renameHandle(t, leaf, journalName, false); err != nil {
		next.Close()
		return nil, true, err
	}
	// Flushing the renamed file commits the NTFS log records of both renames.
	if err := next.Sync(); err != nil {
		current.Close()
		return next, true, err
	}
	// 3. Delete the previous file through its own handle. A failure leaves a
	// journal.old that the next open removes; the new journal is complete.
	derr := deleteHandle(windows.Handle(current.Fd()))
	current.Close()
	if derr != nil {
		return next, true, fmt.Errorf("delete %s: %w", journalOld, derr)
	}
	return next, true, nil
}

// fileRenameInformationEx is FILE_INFORMATION_CLASS FileRenameInformationEx.
const fileRenameInformationEx = 65

// fileRenameInfo mirrors FILE_RENAME_INFORMATION (Flags variant).
type fileRenameInfo struct {
	Flags          uint32
	RootDirectory  windows.Handle
	FileNameLength uint32
	FileName       [1]uint16
}

// renameHandle renames the open file to name inside the pinned directory dir.
// The root must be explicit: with a NULL root, Win32 resolves even a simple
// name against the process current directory, not the file's directory
// (observed on NTFS, Windows 11 26200), and SetFileInformationByHandle rejects
// an explicit root, so the NT call is used: it resolves name literally.
func renameHandle(h, dir windows.Handle, name string, replace bool) error {
	if strings.ContainsAny(name, `\/:`) {
		return errors.New("simple name required")
	}
	u, err := windows.UTF16FromString(name)
	if err != nil {
		return err
	}
	u = u[:len(u)-1]
	offset := unsafe.Offsetof(fileRenameInfo{}.FileName)
	size := offset + uintptr(len(u)+1)*2
	buf := make([]uint64, (size+7)/8)
	info := (*fileRenameInfo)(unsafe.Pointer(&buf[0]))
	info.Flags = windows.FILE_RENAME_POSIX_SEMANTICS
	if replace {
		info.Flags |= windows.FILE_RENAME_REPLACE_IF_EXISTS
	}
	info.RootDirectory = dir
	info.FileNameLength = uint32(len(u) * 2)
	copy(unsafe.Slice(&info.FileName[0], len(u)), u)
	var iosb windows.IO_STATUS_BLOCK
	return windows.NtSetInformationFile(h, &iosb, (*byte)(unsafe.Pointer(&buf[0])), uint32(size), fileRenameInformationEx)
}

func deleteHandle(h windows.Handle) error {
	flags := uint32(windows.FILE_DISPOSITION_DELETE | windows.FILE_DISPOSITION_POSIX_SEMANTICS)
	return windows.SetFileInformationByHandle(h, windows.FileDispositionInfoEx, (*byte)(unsafe.Pointer(&flags)), 4)
}

// handleReader reads a synchronous file handle from its current position.
type handleReader windows.Handle

func (h handleReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	var n uint32
	if err := windows.ReadFile(windows.Handle(h), p, &n, nil); err != nil {
		return int(n), err
	}
	if n == 0 {
		return 0, io.EOF
	}
	return int(n), nil
}

func rewind(h windows.Handle) error {
	_, err := windows.Seek(h, 0, io.SeekStart)
	return err
}

// existsRelative reports whether a plain file exists in the pinned directory.
func existsRelative(leaf windows.Handle, name string) (bool, error) {
	h, err := openRelative(leaf, name, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE, nil)
	if errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	windows.CloseHandle(h)
	return true, nil
}

// removeRelative deletes a leftover plain file in the pinned directory; a
// missing file is not an error.
func removeRelative(leaf windows.Handle, name string) error {
	h, err := openRelative(leaf, name, windows.DELETE|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE, nil)
	if errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return deleteHandle(h)
}

// checkJournalFile verifies a journal file handle: a plain single-link file
// with the expected owner and protected DACL.
func checkJournalFile(h windows.Handle, consumerSID string) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks != 1 {
		return errors.New("journal must be a plain single-link file")
	}
	return checkJournalACL(h, consumerSID, false)
}

func checkJournalACL(h windows.Handle, consumerSID string, directory bool) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	return checkJournalDescriptor(sd, consumerSID, directory)
}

func checkPrivateDescriptor(sd *windows.SECURITY_DESCRIPTOR) error {
	return checkJournalDescriptor(sd, "", false)
}

func checkJournalDescriptor(sd *windows.SECURITY_DESCRIPTOR, consumerSID string, directory bool) error {
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if owner == nil || (!owner.IsWellKnown(windows.WinLocalSystemSid) && !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)) {
		return errors.New("journal owner must be SYSTEM or Administrators")
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("journal DACL must be protected")
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	count := uint16(2)
	if consumerSID != "" {
		count++
	}
	if acl == nil || acl.AceCount != count {
		return errors.New("journal has an unexpected ACE count")
	}
	seen := map[string]bool{}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		// OI/CI are allowed on the provisioned directory, never inherit-only.
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags & ^byte(3) != 0 {
			return errors.New("unsupported journal ACE")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case sid.IsWellKnown(windows.WinLocalSystemSid), sid.IsWellKnown(windows.WinBuiltinAdministratorsSid):
			if ace.Mask != 0x1f01ff {
				return errors.New("administrators require full control")
			}
		case consumerSID != "" && sid.String() == consumerSID:
			mask := windows.ACCESS_MASK(0x12019f)
			if directory {
				mask = 0x1200a9
			}
			if ace.Mask != mask || ace.Header.AceFlags != 0 {
				return errors.New("invalid consumer journal rights")
			}
		default:
			return errors.New("untrusted journal principal")
		}
		if seen[sid.String()] {
			return fmt.Errorf("duplicate journal principal")
		}
		seen[sid.String()] = true
	}
	return nil
}

func openRelative(parent windows.Handle, name string, access, share, disposition, options uint32,
	sd *windows.SECURITY_DESCRIPTOR) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	oa := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: parent, ObjectName: objectName,
		Attributes:         windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
		SecurityDescriptor: sd,
	}
	var h windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&h, access|windows.SYNCHRONIZE, &oa, &status, nil,
		windows.FILE_ATTRIBUTE_NORMAL, share, disposition,
		options|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT, 0, 0)
	return h, err
}
