package enterprise

import (
	"errors"
	"fmt"
)

// ErrCallerIdentity refuses a CA call made with an identity other than the
// expected one.
var ErrCallerIdentity = errors.New("CA call refused: caller identity not established")

// identityDecision is the caller identity guard of the CA call: any thread
// token refuses the call; only the absence of a
// thread token (ERROR_NO_TOKEN) leads to the check of the process SID; any
// other error refuses.
func identityDecision(threadToken bool, threadErr error, processSID string, processErr error, expect string) error {
	switch {
	case expect == "":
		return fmt.Errorf("%w: no expected SID", ErrCallerIdentity)
	case threadToken:
		return fmt.Errorf("%w: the thread is impersonating", ErrCallerIdentity)
	case threadErr != nil:
		return fmt.Errorf("%w: thread token: %v", ErrCallerIdentity, threadErr)
	case processErr != nil:
		return fmt.Errorf("%w: process token: %v", ErrCallerIdentity, processErr)
	case processSID != expect:
		return fmt.Errorf("%w: process SID %s, expected %s", ErrCallerIdentity, processSID, expect)
	}
	return nil
}
