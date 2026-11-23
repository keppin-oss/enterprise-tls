//go:build !windows

package lifecycle

// AttemptStore is the protected attempt directory root (Windows only).
type AttemptStore struct{}

// AttemptDir is one held attempt directory (Windows only).
type AttemptDir struct{}

func OpenAttemptStore(string) (*AttemptStore, error)         { return nil, ErrAttemptDirUnsupported }
func (*AttemptStore) Close() error                           { return nil }
func (*AttemptStore) Open(string, bool) (*AttemptDir, error) { return nil, ErrAttemptDirUnsupported }
func (*AttemptDir) Close() error                             { return nil }
func (*AttemptDir) Path(string) (string, error)              { return "", ErrAttemptDirUnsupported }
func (*AttemptDir) ReadFile(string, int64) ([]byte, error)   { return nil, ErrAttemptDirUnsupported }
func (*AttemptDir) Stat(string) error                        { return ErrAttemptDirUnsupported }
func (*AttemptDir) WriteFile(string, []byte) error           { return ErrAttemptDirUnsupported }
func (*AttemptDir) List() ([]DirEntry, error)                { return nil, ErrAttemptDirUnsupported }
func (*AttemptDir) Remove(string, string) error              { return ErrAttemptDirUnsupported }
