//go:build windows

package enterprise

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// TestResolveTool_SystemDirectory verifies that certreq.exe resolves to an
// absolute path inside the OS-reported system directory, not via PATH.
func TestResolveTool_SystemDirectory(t *testing.T) {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "certreq.exe")); err != nil {
		t.Skipf("certreq.exe not present in %s: %v", dir, err)
	}
	got, err := resolveTool("certreq.exe")
	if err != nil {
		t.Fatalf("resolveTool: %v", err)
	}
	if !filepath.IsAbs(got) || !strings.EqualFold(got, filepath.Join(dir, "certreq.exe")) {
		t.Fatalf("got %q, want %q", got, filepath.Join(dir, "certreq.exe"))
	}
}

// TestResolveTool_IgnoresPATH verifies that a certreq.exe placed earlier in
// PATH is never selected.
func TestResolveTool_IgnoresPATH(t *testing.T) {
	sys := t.TempDir()
	if err := os.WriteFile(filepath.Join(sys, "certreq.exe"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	decoy := t.TempDir()
	if err := os.WriteFile(filepath.Join(decoy, "certreq.exe"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", decoy+string(os.PathListSeparator)+os.Getenv("PATH"))
	withSystemDirectory(t, sys)

	got, err := resolveTool("certreq.exe")
	if err != nil {
		t.Fatalf("resolveTool: %v", err)
	}
	if !strings.EqualFold(got, filepath.Join(sys, "certreq.exe")) {
		t.Fatalf("got %q, want system-directory path", got)
	}
}

// TestResolveTool_MissingIsNotFound verifies that a missing tool wraps
// exec.ErrNotFound, so Enroll classifies it as unavailable.
func TestResolveTool_MissingIsNotFound(t *testing.T) {
	withSystemDirectory(t, t.TempDir())
	_, err := resolveTool("certreq.exe")
	if !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("expected exec.ErrNotFound, got %v", err)
	}
	if got := classifyToolError(phaseNew, -1, err); got != StatusUnavailable {
		t.Fatalf("expected unavailable, got %s", got)
	}
	// The real runner surfaces the same error without spawning anything.
	if _, _, code, err := (execRunner{}).Run(context.Background(), "certreq.exe", "-?"); code != -1 || !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("execRunner: code=%d err=%v", code, err)
	}
}

// TestResolveTool_RejectsPaths verifies that only bare names are accepted.
func TestResolveTool_RejectsPaths(t *testing.T) {
	for _, name := range []string{"", `..\certreq.exe`, `C:\tmp\certreq.exe`, "sub/certreq.exe"} {
		if _, err := resolveTool(name); err == nil {
			t.Errorf("resolveTool(%q): expected error", name)
		}
	}
}

func withSystemDirectory(t *testing.T, dir string) {
	t.Helper()
	prev := systemDirectory
	systemDirectory = func() (string, error) { return dir, nil }
	t.Cleanup(func() { systemDirectory = prev })
}

// TestResolveTool_Classification verifies that only absence and a directory in
// place of the tool are "unavailable"; every other resolution failure keeps its
// cause and is classified enrollment-failed in every certreq phase.
func TestResolveTool_Classification(t *testing.T) {
	sysErr := errors.New("GetSystemDirectory failed")
	cases := []struct {
		name     string
		setup    func(t *testing.T)
		want     Status
		wantRoot error
	}{
		{"missing", func(t *testing.T) { withSystemDirectory(t, t.TempDir()) }, StatusUnavailable, exec.ErrNotFound},
		{"directory", func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "certreq.exe"), 0o700); err != nil {
				t.Fatal(err)
			}
			withSystemDirectory(t, dir)
		}, StatusUnavailable, exec.ErrNotFound},
		{"access denied", func(t *testing.T) {
			withSystemDirectory(t, t.TempDir())
			withStat(t, fs.ErrPermission)
		}, StatusEnrollmentFailed, fs.ErrPermission},
		{"io error", func(t *testing.T) {
			withSystemDirectory(t, t.TempDir())
			withStat(t, windows.ERROR_IO_DEVICE)
		}, StatusEnrollmentFailed, windows.ERROR_IO_DEVICE},
		{"system directory error", func(t *testing.T) {
			prev := systemDirectory
			systemDirectory = func() (string, error) { return "", sysErr }
			t.Cleanup(func() { systemDirectory = prev })
		}, StatusEnrollmentFailed, sysErr},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup(t)
			_, err := resolveTool("certreq.exe")
			if !errors.Is(err, tc.wantRoot) {
				t.Fatalf("expected cause %v, got %v", tc.wantRoot, err)
			}
			if tc.want != StatusUnavailable && errors.Is(err, exec.ErrNotFound) {
				t.Fatalf("non-absence error must not wrap exec.ErrNotFound: %v", err)
			}
			for _, ph := range []certreqPhase{phaseNew, phaseSubmit, phaseAccept} {
				if got := classifyToolError(ph, -1, err); got != tc.want {
					t.Errorf("phase %d: got %s, want %s", ph, got, tc.want)
				}
			}
		})
	}
}

// TestResolveTool_RejectsDotNames verifies "." and ".." are not bare names.
func TestResolveTool_RejectsDotNames(t *testing.T) {
	for _, name := range []string{".", ".."} {
		if _, err := resolveTool(name); err == nil || errors.Is(err, exec.ErrNotFound) {
			t.Errorf("resolveTool(%q): expected non-not-found error, got %v", name, err)
		}
	}
}

func withStat(t *testing.T, statErr error) {
	t.Helper()
	prev := statTool
	statTool = func(name string) (os.FileInfo, error) {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: statErr}
	}
	t.Cleanup(func() { statTool = prev })
}
