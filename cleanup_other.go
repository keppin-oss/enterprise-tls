//go:build !windows

package enterprise

import "errors"

var errNotWindows = errors.New("enterprise cleanup is only supported on Windows")

// winStore and winKeyRemover are no-op stubs that allow the package to compile
// on non-Windows platforms. The cleanup contract itself is Windows-only.
type winStore struct{}
type winKeyRemover struct{}

func (winStore) FindLeafBySHA256([32]byte) ([]byte, error) {
	return nil, errNotWindows
}

func (winStore) KeyProvInfo([32]byte) (keyProvInfo, error) {
	return keyProvInfo{}, errNotWindows
}

func (winStore) DeleteLeafBySHA256([32]byte) error {
	return errNotWindows
}

func (winKeyRemover) DeleteCNGKey(string, string) error {
	return errNotWindows
}
