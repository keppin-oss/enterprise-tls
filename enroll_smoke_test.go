//go:build windows && enterprise_tls_smoke

package enterprise

import (
	"context"
	"errors"
	"strings"
	"testing"
	"unsafe"

	"github.com/keppin-oss/cng/windowscng"
	"golang.org/x/sys/windows"
)

// isElevated reports whether the current process token is elevated, which is
// required for machine-scoped enrollment and key operations.
func isElevated() bool {
	token := windows.GetCurrentProcessToken()
	defer token.Close()
	var elevated uint32
	var returned uint32
	err := windows.GetTokenInformation(token, windows.TokenElevation,
		(*byte)(unsafe.Pointer(&elevated)), uint32(unsafe.Sizeof(elevated)), &returned)
	return err == nil && elevated != 0
}

// TestEnroll_Smoke_SubmitFailureCleansUpKey exercises the real Enroll()
// orchestration against real certreq.exe without a real Enterprise CA:
//
//   - -new -machine succeeds and creates the exact generated CNG key container;
//   - -submit fails because the configured CA is deliberately unreachable;
//   - the module's failure-cleanup path removes that exact key through the
//     shared Keppin-OSS CNG deletion primitive.
//
// It must be run elevated (Administrator) and with the enterprise_tls_smoke tag.
func TestEnroll_Smoke_SubmitFailureCleansUpKey(t *testing.T) {
	if !isElevated() {
		t.Skip("requires Administrator elevation")
	}

	// A reserved, non-resolvable host guarantees -submit reaches no CA while
	// -new still succeeds locally.
	p := New(Config{CA: "unreachable.invalid\\KeppinTestCA"})
	res, err := p.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected enrollment to fail against an unreachable CA")
	}
	if res == nil {
		t.Fatal("expected non-nil result")
	}

	// Safety net: ensure no residual key owned by this module remains even if a
	// later assertion fails. The deletion path is delegated to windowscng.
	t.Cleanup(func() {
		if res.KeyContainer != "" {
			_ = windowscng.Delete(res.KeyContainer)
		}
	})

	if !strings.HasPrefix(res.KeyContainer, keyContainerPrefix) {
		t.Fatalf("expected Enterprise-TLS namespaced key container, got %q", res.KeyContainer)
	}

	// The failure must have occurred at submit or later; success and
	// not-configured are not acceptable outcomes here.
	if res.Status == StatusSuccess || res.Status == StatusNotConfigured {
		t.Fatalf("expected failure status, got %s", res.Status)
	}

	if res.KeyState != KeyStateRemoved {
		t.Fatalf("expected KeyStateRemoved, got %s (cleanupErr=%v)", res.KeyState, res.KeyCleanupErr)
	}

	// Prove the shared deletion removed the exact key: reopening the exact name
	// for deletion reports not-found through the shared primitive, and a
	// repeated cleanup is therefore safely idempotent.
	if err := windowscng.Delete(res.KeyContainer); !errors.Is(err, windowscng.ErrKeyNotFound) {
		t.Errorf("expected key container %q to be absent after cleanup, got %v", res.KeyContainer, err)
	}
}
