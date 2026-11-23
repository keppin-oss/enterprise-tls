package lifecycle

import (
	"errors"
	"strings"
)

// EntryKind classifies an entry of an attempt directory listing.
type EntryKind int

const (
	EntryFile EntryKind = iota + 1
	EntryDirectory
	// EntryReparse is any entry carrying a reparse point, whatever its type.
	EntryReparse
)

// DirEntry is one entry of an attempt directory, as enumerated by handle.
type DirEntry struct {
	Name string
	Kind EntryKind
}

// ErrAttemptDirUnsupported is returned where the protected NTFS attempt
// directory is not available.
var ErrAttemptDirUnsupported = errors.New("the protected attempt directory requires Windows")

const (
	attemptsName = "attempts"
	// attemptDirSDDL is the private broker descriptor, inheritable so that
	// files certreq creates get SYSTEM and Administrators full control only.
	attemptDirSDDL = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
)

// validAttemptID accepts only the attempt IDs Enrollment generates: 32
// lowercase hex characters.
func validAttemptID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// validFileName accepts a single path component made of ASCII letters,
// digits, '.', '-' and '_', not "." or "..", with no trailing dot and no
// Win32 reserved device base name: no separators, streams, devices or Win32
// name normalization, so the Win32 path given to certreq and the NT name
// opened relative to the held directory designate the same file.
func validFileName(name string) bool {
	if name == "" || len(name) > 128 || name == "." || name == ".." || strings.HasSuffix(name, ".") {
		return false
	}
	if reservedDeviceName(name) {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// reservedDeviceName reports whether Win32 maps name to a device: CON, PRN,
// AUX, NUL, CONIN$, CONOUT$, COM0-9 or LPT0-9, in any case, alone or
// followed by any extension. Win32 also ignores trailing spaces and dots,
// which validFileName rejects separately.
func reservedDeviceName(name string) bool {
	base := strings.ToUpper(name)
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) {
		return base[3] >= '0' && base[3] <= '9'
	}
	return false
}
