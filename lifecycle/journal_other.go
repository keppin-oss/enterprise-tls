//go:build !windows

package lifecycle

import (
	"errors"
	"os"
)

func openJournalFile(string, string) (*os.File, func(), journalReplacer, error) {
	return nil, nil, nil, errors.New("the protected NTFS journal requires Windows")
}
