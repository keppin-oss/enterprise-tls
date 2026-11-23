//go:build windows

package enterprise

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/keppin-oss/enterprise-tls/lifecycle"
)

// In-process ICertRequest through an explicit vtable on a locked OS thread.
// No child process and no external dependency.

var (
	modOle32    = windows.NewLazySystemDLL("ole32.dll")
	modOleAut32 = windows.NewLazySystemDLL("oleaut32.dll")

	procCoInitializeEx   = modOle32.NewProc("CoInitializeEx")
	procCoCreateInstance = modOle32.NewProc("CoCreateInstance")
	procSysAllocString   = modOleAut32.NewProc("SysAllocString")
	procSysAllocStringBL = modOleAut32.NewProc("SysAllocStringByteLen")
	procSysFreeString    = modOleAut32.NewProc("SysFreeString")
	procSysStringLen     = modOleAut32.NewProc("SysStringLen")
)

var (
	clsidCCertRequest = windows.GUID{Data1: 0x98AFF3F0, Data2: 0x5524, Data3: 0x11D0, Data4: [8]byte{0x88, 0x12, 0x00, 0xA0, 0xC9, 0x03, 0xB8, 0x3C}}
	iidICertRequest   = windows.GUID{Data1: 0x014E4840, Data2: 0x5523, Data3: 0x11D0, Data4: [8]byte{0x88, 0x12, 0x00, 0xA0, 0xC9, 0x03, 0xB8, 0x3C}}
)

const (
	coinitMultithreaded = 0x0
	clsctxInprocServer  = 0x1

	crInBinary  = 0x2
	crInPKCS10  = 0x100
	crOutBase64 = 0x1

	// ICertRequest vtable slots (IUnknown 0-2, IDispatch 3-6).
	slotRelease               = 2
	slotSubmit                = 7
	slotRetrievePending       = 8
	slotGetLastStatus         = 9
	slotGetRequestID          = 10
	slotGetDispositionMessage = 11
	slotGetCertificate        = 13
)

type comObject struct{ p unsafe.Pointer }

// call invokes a vtable slot. Callers convert pointers to uintptr in the
// argument list; uintptrescapes keeps those objects on the heap and alive
// for the whole call, as for syscall.Proc.Call (Go unsafe.Pointer rule 4).
//
//go:uintptrescapes
func (o comObject) call(slot int, args ...uintptr) int32 {
	vtbl := *(*unsafe.Pointer)(o.p)
	fn := *(*uintptr)(unsafe.Add(vtbl, uintptr(slot)*unsafe.Sizeof(uintptr(0))))
	r, _, _ := syscall.SyscallN(fn, append([]uintptr{uintptr(o.p)}, args...)...)
	return int32(uint32(r))
}

func (o comObject) release() {
	if o.p != nil {
		o.call(slotRelease)
	}
}

func allocBSTR(s string) (uintptr, error) {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return 0, err
	}
	r, _, _ := procSysAllocString.Call(uintptr(unsafe.Pointer(p)))
	if r == 0 {
		return 0, errors.New("SysAllocString failed")
	}
	return r, nil
}

func allocBSTRBytes(b []byte) (uintptr, error) {
	if len(b) == 0 {
		return 0, errors.New("empty request")
	}
	r, _, _ := procSysAllocStringBL.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	if r == 0 {
		return 0, errors.New("SysAllocStringByteLen failed")
	}
	return r, nil
}

func freeBSTR(b uintptr) {
	if b != 0 {
		procSysFreeString.Call(b)
	}
}

// takeBSTR returns the content of a BSTR received as an out parameter and
// frees it.
func takeBSTR(b unsafe.Pointer) string {
	if b == nil {
		return ""
	}
	defer procSysFreeString.Call(uintptr(b))
	n, _, _ := procSysStringLen.Call(uintptr(b))
	return windows.UTF16ToString(unsafe.Slice((*uint16)(b), n))
}

// comCA is the caClient for Windows.
type comCA struct{ expectSID string }

func newCOMCA(expectSID string) caClient { return comCA{expectSID: expectSID} }

// threadIdentity reads the identity of the calling OS thread for the guard.
func threadIdentity() (threadToken bool, threadErr error, processSID string, processErr error) {
	var t windows.Token
	switch err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &t); {
	case err == nil:
		t.Close()
		return true, nil, "", nil
	case errors.Is(err, windows.ERROR_NO_TOKEN):
	default:
		return false, err, "", nil
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false, nil, "", err
	}
	return false, nil, u.User.Sid.String(), nil
}

// checkIdentity runs the guard on the calling (locked) thread.
func (c comCA) checkIdentity() error {
	tok, terr, sid, perr := threadIdentity()
	return identityDecision(tok, terr, sid, perr, c.expectSID)
}

func (c comCA) Submit(ctx context.Context, config, template string, csr []byte) caReply {
	if strings.ContainsAny(template, "\r\n") {
		return caReply{Err: errors.New("invalid template name")}
	}
	return c.do(ctx, "Submit", func(o comObject, disp *int32, begin func() bool) (int32, error) {
		req, err := allocBSTRBytes(csr)
		if err != nil {
			return 0, err
		}
		defer freeBSTR(req)
		attr, err := allocBSTR("CertificateTemplate:" + template)
		if err != nil {
			return 0, err
		}
		defer freeBSTR(attr)
		cfg, err := allocBSTR(config)
		if err != nil {
			return 0, err
		}
		defer freeBSTR(cfg)
		if err := c.checkIdentity(); err != nil {
			return 0, err
		}
		if !begin() {
			return 0, errCallAbandoned
		}
		return o.call(slotSubmit, crInBinary|crInPKCS10, req, attr, cfg, uintptr(unsafe.Pointer(disp))), nil
	})
}

func (c comCA) Retrieve(ctx context.Context, config string, requestID int) caReply {
	if requestID <= 0 || requestID > 1<<31-1 {
		return caReply{Err: errors.New("invalid RequestId")}
	}
	return c.do(ctx, "RetrievePending", func(o comObject, disp *int32, begin func() bool) (int32, error) {
		cfg, err := allocBSTR(config)
		if err != nil {
			return 0, err
		}
		defer freeBSTR(cfg)
		if err := c.checkIdentity(); err != nil {
			return 0, err
		}
		if !begin() {
			return 0, errCallAbandoned
		}
		return o.call(slotRetrievePending, uintptr(int32(requestID)), cfg, uintptr(unsafe.Pointer(disp))), nil
	})
}

// do runs one CA call on a dedicated OS thread in the MTA. The thread stays
// locked and ends with the goroutine, so its COM state is never reused. A
// call that does not return cannot be cancelled in process: when ctx ends
// first, the reply matches lifecycle.ErrQuiescence and the call keeps running
// until the CA answers or the process ends.
func (c comCA) do(ctx context.Context, name string, call func(comObject, *int32, func() bool) (int32, error)) caReply {
	if c.expectSID == "" {
		return caReply{Err: errors.New("expected caller SID required")}
	}
	if err := ctx.Err(); err != nil {
		return caReply{Err: fmt.Errorf("ICertRequest::%s not started: %w", name, err)}
	}
	gate := &callGate{}
	done := make(chan caReply, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread exits with the goroutine
		done <- c.onThread(name, gate, call)
	}()
	select {
	case rep := <-done:
		return rep
	case <-ctx.Done():
	}
	select {
	case rep := <-done: // finished together with the cancellation
		return rep
	default:
	}
	if gate.abandon() {
		return caReply{Err: fmt.Errorf("%w: ICertRequest::%s still running: %v", lifecycle.ErrQuiescence, name, ctx.Err())}
	}
	return caReply{Err: fmt.Errorf("ICertRequest::%s not started: %w", name, ctx.Err())}
}

var errCallAbandoned = errors.New("CA call abandoned by the caller before it started")

// callGate orders the start of the CA call against the caller giving up: the
// worker starts the call only while the caller is still waiting, and the
// caller reports ErrQuiescence only when the call may have started.
type callGate struct {
	mu        sync.Mutex
	started   bool
	abandoned bool
}

// begin is called by the worker immediately before the CA call.
func (g *callGate) begin() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.abandoned {
		return false
	}
	g.started = true
	return true
}

// abandon is called by the caller when it stops waiting; it reports whether
// the call may have started.
func (g *callGate) abandon() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.abandoned = true
	return g.started
}

func (c comCA) onThread(name string, gate *callGate, call func(comObject, *int32, func() bool) (int32, error)) caReply {
	if r, _, _ := procCoInitializeEx.Call(0, coinitMultithreaded); int32(uint32(r)) < 0 {
		return caReply{Err: fmt.Errorf("CoInitializeEx: 0x%08X", uint32(r))}
	}
	// No CoUninitialize: the thread ends with this goroutine.
	if err := c.checkIdentity(); err != nil {
		return caReply{Err: err}
	}
	var p unsafe.Pointer
	if r, _, _ := procCoCreateInstance.Call(uintptr(unsafe.Pointer(&clsidCCertRequest)), 0, clsctxInprocServer,
		uintptr(unsafe.Pointer(&iidICertRequest)), uintptr(unsafe.Pointer(&p))); int32(uint32(r)) < 0 {
		return caReply{Err: fmt.Errorf("CoCreateInstance(CCertRequest): 0x%08X", uint32(r))}
	}
	o := comObject{p}
	defer o.release()

	var disp int32 = -1
	hr, err := call(o, &disp, gate.begin)
	if err != nil {
		return caReply{Err: err} // refused before the call
	}
	rep := caReply{Disposition: lifecycle.CADisposition(disp)}
	if hr < 0 {
		rep.Err = fmt.Errorf("ICertRequest::%s: HRESULT 0x%08X: %v", name, uint32(hr), windows.Errno(uint32(hr)))
	}
	var st int32
	if o.call(slotGetLastStatus, uintptr(unsafe.Pointer(&st))) >= 0 {
		rep.Status = uint32(st)
	}
	var rid int32
	if o.call(slotGetRequestID, uintptr(unsafe.Pointer(&rid))) >= 0 && rid > 0 {
		rep.RequestID = int(rid)
	}
	var msg unsafe.Pointer
	if o.call(slotGetDispositionMessage, uintptr(unsafe.Pointer(&msg))) >= 0 {
		rep.Text = takeBSTR(msg)
	}
	if rep.Err == nil && rep.Disposition == lifecycle.DispIssued {
		var cb unsafe.Pointer
		if r := o.call(slotGetCertificate, crOutBase64, uintptr(unsafe.Pointer(&cb))); r < 0 {
			rep.CertErr = fmt.Errorf("HRESULT 0x%08X", uint32(r))
		} else {
			b64 := takeBSTR(cb)
			rep.Cert, rep.CertErr = base64.StdEncoding.DecodeString(strings.Join(strings.Fields(b64), ""))
		}
	}
	return rep
}
