//go:build windows

package enterprise

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// PROC_THREAD_ATTRIBUTE_JOB_LIST (Windows 10+). Assignment happens as part of
// CreateProcess, before any user code runs; there is no create/assign gap.
const procThreadAttributeJobList = 0x0002000d

type jobAccounting struct {
	TotalUserTime, TotalKernelTime, PeriodUserTime, PeriodKernelTime int64
	PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses uint32
}

// waitJobEmpty checks the entire job, including descendants whose direct
// parent has exited. Cancellation requests termination; it never substitutes
// for observing ActiveProcesses == 0. The job handle stays open throughout.
func waitJobEmpty(ctx context.Context, job windows.Handle) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	cancel := ctx.Done()
	var cause error
	for {
		var info jobAccounting
		if err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil); err != nil {
			return errors.Join(ErrProcessQuiescence, cause, err)
		}
		if info.ActiveProcesses == 0 {
			return cause
		}
		select {
		case <-cancel:
			cause = ctx.Err()
			if err := windows.TerminateJobObject(job, 1); err != nil {
				return errors.Join(ErrProcessQuiescence, cause, err)
			}
			cancel = nil // continue waiting, without a timeout bypass
		case <-ticker.C:
		}
	}
}

func runCommandTree(ctx context.Context, path string, args ...string) (string, string, int, error) {
	if err := ctx.Err(); err != nil {
		return "", "", -1, err
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return "", "", -1, fmt.Errorf("create process job: %w", err)
	}
	defer windows.CloseHandle(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return "", "", -1, fmt.Errorf("configure process job: %w", err)
	}

	outR, outW, err := os.Pipe()
	if err != nil {
		return "", "", -1, err
	}
	defer outR.Close()
	defer outW.Close()
	errR, errW, err := os.Pipe()
	if err != nil {
		return "", "", -1, err
	}
	defer errR.Close()
	defer errW.Close()
	in, err := os.Open(os.DevNull)
	if err != nil {
		return "", "", -1, err
	}
	defer in.Close()
	handles := []windows.Handle{windows.Handle(in.Fd()), windows.Handle(outW.Fd()), windows.Handle(errW.Fd())}
	for _, h := range handles {
		if err := windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			return "", "", -1, err
		}
	}
	attrs, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return "", "", -1, err
	}
	defer attrs.Delete()
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]),
		uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		return "", "", -1, err
	}
	// The job handle is deliberately NOT in the inherited handle list.
	if err := attrs.Update(procThreadAttributeJobList, unsafe.Pointer(&job), unsafe.Sizeof(job)); err != nil {
		return "", "", -1, err
	}
	app, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", "", -1, err
	}
	escaped := []string{windows.EscapeArg(path)}
	for _, arg := range args {
		escaped = append(escaped, windows.EscapeArg(arg))
	}
	cmd, err := windows.UTF16PtrFromString(strings.Join(escaped, " "))
	if err != nil {
		return "", "", -1, err
	}
	si := windows.StartupInfoEx{}
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESTDHANDLES
	si.StdInput, si.StdOutput, si.StdErr = handles[0], handles[1], handles[2]
	si.ProcThreadAttributeList = attrs.List()
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(app, cmd, nil, nil, true,
		windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_UNICODE_ENVIRONMENT,
		nil, nil, &si.StartupInfo, &pi); err != nil {
		return "", "", -1, fmt.Errorf("create contained process: %w", err)
	}
	runtime.KeepAlive(handles)
	defer windows.CloseHandle(pi.Process)
	windows.CloseHandle(pi.Thread)
	outW.Close()
	errW.Close()

	var stdout, stderr bytes.Buffer
	var wg sync.WaitGroup
	var outErr, errErr error
	wg.Add(2)
	go func() { defer wg.Done(); _, outErr = io.Copy(&stdout, outR) }()
	go func() { defer wg.Done(); _, errErr = io.Copy(&stderr, errR) }()
	waitErr := waitJobEmpty(ctx, job)
	if errors.Is(waitErr, ErrProcessQuiescence) {
		// Stop collection even if containment could not be established. The
		// caller must preserve artifacts and avoid cleanup in this case.
		_ = windows.TerminateJobObject(job, 1)
		outR.Close()
		errR.Close()
	}
	wg.Wait()
	if !errors.Is(waitErr, ErrProcessQuiescence) {
		if _, err := windows.WaitForSingleObject(pi.Process, windows.INFINITE); err != nil {
			waitErr = errors.Join(ErrProcessQuiescence, waitErr, err)
		}
	}
	var code uint32
	codeErr := windows.GetExitCodeProcess(pi.Process, &code)
	err = errors.Join(waitErr, codeErr, outErr, errErr)
	if code != 0 && err == nil {
		err = fmt.Errorf("process exited with code %#x", code)
	}
	return stdout.String(), stderr.String(), int(code), err
}
