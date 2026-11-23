//go:build windows

package enterprise

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// systemDirectory returns the Windows system directory (normally
// C:\Windows\System32) from the OS, not from environment variables that the
// caller's environment could override. It is a variable so tests can inject a
// directory.
var systemDirectory = windows.GetSystemDirectory

// statTool is os.Stat, a variable so tests can inject stat failures.
var statTool = os.Stat

// resolveTool maps a bare tool name such as "certreq.exe" to its absolute path
// in the Windows system directory, so the tool is never looked up through PATH
// or the current directory.
//
// Only a tool that is genuinely absent (fs.ErrNotExist) or that is a directory
// is reported as wrapping exec.ErrNotFound, which classifyToolError treats as
// "unavailable". Any other failure (access denied, I/O error, system directory
// lookup) is returned with its cause and without exec.ErrNotFound, so it is
// classified fail-closed as enrollment-failed rather than fallback-safe.
func resolveTool(name string) (string, error) {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return "", fmt.Errorf("tool name %q must be a bare file name", name)
	}
	dir, err := systemDirectory()
	if err != nil {
		return "", fmt.Errorf("resolve system directory for %s: %w", name, err)
	}
	path := filepath.Join(dir, name)
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("resolved path for %s is not absolute: %q", name, path)
	}
	info, err := statTool(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", fmt.Errorf("%s not found in system directory %q: %w", name, dir, exec.ErrNotFound)
	case err != nil:
		return "", fmt.Errorf("stat %s in system directory %q: %w", name, dir, err)
	case info.IsDir():
		return "", fmt.Errorf("%s in system directory %q is a directory: %w", name, dir, exec.ErrNotFound)
	}
	return path, nil
}
