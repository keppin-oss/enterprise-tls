//go:build !windows

package enterprise

import (
	"fmt"
	"os/exec"
)

// resolveTool reports that Windows tools such as certreq.exe are not available
// on non-Windows platforms. The error wraps exec.ErrNotFound so the outcome is
// classified as "unavailable".
func resolveTool(name string) (string, error) {
	return "", fmt.Errorf("%s is only available on Windows: %w", name, exec.ErrNotFound)
}
