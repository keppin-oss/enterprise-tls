//go:build windows

package enterprise

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"github.com/keppin-oss/cng/windowscng"
	"golang.org/x/sys/windows"
)

var (
	modCrypt32 = windows.NewLazySystemDLL("crypt32.dll")

	procCertGetCertificateContextProperty = modCrypt32.NewProc("CertGetCertificateContextProperty")
	procCertDeleteCertificateFromStore    = modCrypt32.NewProc("CertDeleteCertificateFromStore")
)

const (
	certStoreProvSystem         = "System"           // CERT_STORE_PROV_SYSTEM (ANSI)
	certSystemStoreLocalMachine = uint32(0x00020000) // CERT_SYSTEM_STORE_LOCAL_MACHINE
	certKeyProvInfoPropID       = uint32(2)          // CERT_KEY_PROV_INFO_PROP_ID
)

// cryptKeyProvInfo mirrors CRYPT_KEY_PROV_INFO (64-bit). The two string fields
// point into the buffer returned by CertGetCertificateContextProperty.
type cryptKeyProvInfo struct {
	containerName uintptr
	provName      uintptr
	provType      uint32
	flags         uint32
	cProvParam    uint32
	pad           uint32
	rgProvParam   uintptr
	keySpec       uint32
}

// winStore implements certStore against LocalMachine\My.
type winStore struct{}

func openMachineMy() (syscall.Handle, error) {
	provider, err := windows.BytePtrFromString(certStoreProvSystem)
	if err != nil {
		return 0, err
	}
	name, err := windows.UTF16PtrFromString("MY")
	if err != nil {
		return 0, err
	}
	store, err := syscall.CertOpenStore(
		uintptr(unsafe.Pointer(provider)),
		0,
		0,
		certSystemStoreLocalMachine,
		uintptr(unsafe.Pointer(name)),
	)
	if err != nil {
		return 0, fmt.Errorf("CertOpenStore: %w", err)
	}
	return store, nil
}

// findContext enumerates LocalMachine\My and returns the certificate context
// whose SHA-256 equals fp. Non-matching contexts are freed as they are
// enumerated. The returned context is owned by the caller, which must free or
// delete it.
func findContext(store syscall.Handle, fp [32]byte) (*syscall.CertContext, bool, error) {
	var prev *syscall.CertContext
	for {
		// Enumeration consumes prev, even on end-of-store or error. Only a
		// matching context returned to the caller remains caller-owned.
		ctx, err := syscall.CertEnumCertificatesInStore(store, prev)
		if ctx == nil {
			if errors.Is(err, windows.Errno(windows.CRYPT_E_NOT_FOUND)) {
				return nil, false, nil
			}
			return nil, false, fmt.Errorf("CertEnumCertificatesInStore: %w", err)
		}
		der := unsafe.Slice(ctx.EncodedCert, int(ctx.Length))
		if sha256.Sum256(der) == fp {
			return ctx, true, nil
		}
		prev = ctx
	}
}

func (winStore) FindLeafBySHA256(fp [32]byte) ([]byte, error) {
	store, err := openMachineMy()
	if err != nil {
		return nil, err
	}
	defer syscall.CertCloseStore(store, 0)

	ctx, found, err := findContext(store, fp)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errCertNotFound
	}
	defer syscall.CertFreeCertificateContext(ctx)

	der := unsafe.Slice(ctx.EncodedCert, int(ctx.Length))
	out := make([]byte, len(der))
	copy(out, der)
	return out, nil
}

func (winStore) KeyProvInfo(fp [32]byte) (keyProvInfo, error) {
	store, err := openMachineMy()
	if err != nil {
		return keyProvInfo{}, err
	}
	defer syscall.CertCloseStore(store, 0)

	ctx, found, err := findContext(store, fp)
	if err != nil {
		return keyProvInfo{}, err
	}
	if !found {
		return keyProvInfo{}, errCertNotFound
	}
	defer syscall.CertFreeCertificateContext(ctx)

	return readKeyProvInfo(ctx)
}

func (winStore) DeleteLeafBySHA256(fp [32]byte) error {
	store, err := openMachineMy()
	if err != nil {
		return err
	}
	defer syscall.CertCloseStore(store, 0)

	ctx, found, err := findContext(store, fp)
	if err != nil {
		return err
	}
	if !found {
		return errCertNotFound
	}

	// CertDeleteCertificateFromStore deletes the exact context and frees it.
	r1, _, lastErr := procCertDeleteCertificateFromStore.Call(uintptr(unsafe.Pointer(ctx)))
	if r1 == 0 {
		return fmt.Errorf("CertDeleteCertificateFromStore: %w", lastErr)
	}
	return nil
}

func readKeyProvInfo(ctx *syscall.CertContext) (keyProvInfo, error) {
	var size uint32
	r1, _, lastErr := procCertGetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)), uintptr(certKeyProvInfoPropID), 0, uintptr(unsafe.Pointer(&size)))
	if r1 == 0 {
		return keyProvInfo{}, fmt.Errorf("CertGetCertificateContextProperty(size): %w", lastErr)
	}
	if size == 0 {
		return keyProvInfo{}, errors.New("certificate has no key provider info")
	}
	buf := make([]byte, size)
	r1, _, lastErr = procCertGetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)), uintptr(certKeyProvInfoPropID), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r1 == 0 {
		return keyProvInfo{}, fmt.Errorf("CertGetCertificateContextProperty: %w", lastErr)
	}

	if len(buf) < int(unsafe.Sizeof(cryptKeyProvInfo{})) {
		return keyProvInfo{}, errors.New("key provider info buffer too small")
	}
	kpi := (*cryptKeyProvInfo)(unsafe.Pointer(&buf[0]))
	return keyProvInfo{
		provider:      utf16StringAt(buf, kpi.provName),
		containerName: utf16StringAt(buf, kpi.containerName),
		providerType:  kpi.provType,
		keySpec:       kpi.keySpec,
	}, nil
}

// utf16StringAt decodes a NUL-terminated UTF-16 string stored at the given
// absolute address within buf. The address is interpreted as an offset from the
// buffer base, avoiding any uintptr-to-pointer conversion.
func utf16StringAt(buf []byte, addr uintptr) string {
	base := uintptr(unsafe.Pointer(&buf[0]))
	if addr < base {
		return ""
	}
	off := int(addr - base)
	if off < 0 || off+1 >= len(buf) {
		return ""
	}
	var units []uint16
	for i := off; i+1 < len(buf); i += 2 {
		u := uint16(buf[i]) | uint16(buf[i+1])<<8
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	return string(utf16.Decode(units))
}

// winKeyRemover implements keyRemover by delegating exact machine-scoped CNG
// key deletion to the shared Keppin-OSS CNG primitive. This module still owns
// the decision of which exact key may be deleted and the provider/container
// ownership checks; windowscng only performs the Microsoft Software KSP
// machine-scoped deletion and handle lifecycle.
type winKeyRemover struct{}

func (winKeyRemover) DeleteCNGKey(provider, container string) error {
	if provider != expectedCNGProvider {
		return fmt.Errorf("refusing to delete key under unexpected provider %q", provider)
	}
	return mapCNGError(windowscng.Delete(container))
}

// mapCNGError translates the shared windowscng missing-key sentinel into the
// Enterprise-TLS errKeyNotFound contract. Other errors (permission, provider,
// corruption, unexpected failures) are passed through unchanged and are never
// converted into not-found.
func mapCNGError(err error) error {
	if errors.Is(err, windowscng.ErrKeyNotFound) {
		return errKeyNotFound
	}
	return err
}
