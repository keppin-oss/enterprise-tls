//go:build !windows

package enterprise

import (
	"context"
	"errors"
)

var errCAUnsupported = errors.New("the native CA client requires Windows")

type unsupportedCA struct{}

func newCOMCA(string) caClient { return unsupportedCA{} }

func (unsupportedCA) Submit(context.Context, string, string, []byte) caReply {
	return caReply{Err: errCAUnsupported}
}

func (unsupportedCA) Retrieve(context.Context, string, int) caReply {
	return caReply{Err: errCAUnsupported}
}
