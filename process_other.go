//go:build !windows

package enterprise

import (
	"context"
	"errors"
)

func runCommandTree(context.Context, string, ...string) (string, string, int, error) {
	return "", "", -1, errors.New("native process execution is only supported on Windows")
}
