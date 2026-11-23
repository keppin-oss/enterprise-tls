//go:build !windows

package enterprise

import (
	"context"
	"errors"

	"github.com/keppin-oss/enterprise-tls/lifecycle"
)

var errStoreUnsupported = errors.New("the machine certificate store requires Windows")

// MachineMy implements lifecycle.CertStore on Windows only.
type MachineMy struct{}

// NewMachineMy returns the LocalMachine\My adapter.
func NewMachineMy() MachineMy { return MachineMy{} }

var _ lifecycle.CertStore = MachineMy{}

func (MachineMy) Install(context.Context, lifecycle.Attempt, []byte) error {
	return errStoreUnsupported
}

func (MachineMy) VerifyBinding(context.Context, lifecycle.Attempt) (string, error) {
	return "", errStoreUnsupported
}
