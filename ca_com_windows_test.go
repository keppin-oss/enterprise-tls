//go:build windows

package enterprise

import (
	"context"
	"errors"
	"runtime"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/keppin-oss/enterprise-tls/lifecycle"
)

func processSID(t *testing.T) string {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return u.User.Sid.String()
}

// The guard runs before CoCreateInstance: with an identity other than the
// expected one nothing reaches the CA.
func TestCOMCARefusesAnotherIdentity(t *testing.T) {
	ca := comCA{expectSID: "S-1-5-80-0"} // never this test's process
	rep := ca.Submit(actx, `nohost\noca`, "t", []byte{0x30, 0x00})
	if !errors.Is(rep.Err, ErrCallerIdentity) {
		t.Fatalf("submit: %v", rep.Err)
	}
	rep = ca.Retrieve(actx, `nohost\noca`, 1)
	if !errors.Is(rep.Err, ErrCallerIdentity) {
		t.Fatalf("retrieve: %v", rep.Err)
	}
	if rep := (comCA{}).Submit(actx, "x", "t", []byte{1}); rep.Err == nil {
		t.Fatal("client without an expected SID")
	}
}

// threadIdentity reports a thread token when the thread impersonates, which
// the guard refuses; without one it reads the process SID.
func TestThreadIdentity(t *testing.T) {
	want := processSID(t)
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // the impersonating thread is discarded with the goroutine
		tok, terr, sid, perr := threadIdentity()
		if tok || terr != nil || perr != nil || sid != want {
			done <- errors.New("process identity not read")
			return
		}
		if identityDecision(tok, terr, sid, perr, want) != nil {
			done <- errors.New("guard refused the process identity")
			return
		}
		if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
			done <- err
			return
		}
		tok, terr, sid, perr = threadIdentity()
		if !tok || !errors.Is(identityDecision(tok, terr, sid, perr, want), ErrCallerIdentity) {
			done <- errors.New("impersonating thread not refused")
			return
		}
		done <- nil
	}()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Review of bd5759d, finding 2: an expired context never starts a CA call,
// and the caller reports ErrQuiescence only when the call may have started.
func TestCOMCAExpiredContextNeverStarts(t *testing.T) {
	ctx, cancel := context.WithCancel(actx)
	cancel()
	// With the test's own identity the guard would pass: the context check
	// must refuse first.
	rep := comCA{expectSID: processSID(t)}.Submit(ctx, `nohost\noca`, "t", []byte{0x30, 0x00})
	if rep.Err == nil || errors.Is(rep.Err, lifecycle.ErrQuiescence) || !errors.Is(rep.Err, context.Canceled) {
		t.Fatalf("expired context: %v", rep.Err)
	}
}

func TestCallGateOrdering(t *testing.T) {
	g := &callGate{}
	if !g.begin() || !g.abandon() {
		t.Fatal("a started call must be reported as possibly running")
	}
	g = &callGate{}
	if g.abandon() || g.begin() {
		t.Fatal("an abandoned call must never start")
	}
}
