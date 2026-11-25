//go:build windows

package enterprise

import (
	"errors"
	"fmt"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Reading CERT_KEY_PROV_INFO_PROP_ID from a stored certificate. MachineMy
// uses it to verify the binding it writes with CertSetCertificateContextProperty.

var (
	modCrypt32 = windows.NewLazySystemDLL("crypt32.dll")

	procCertGetCertificateContextProperty = modCrypt32.NewProc("CertGetCertificateContextProperty")
)

const certKeyProvInfoPropID = uint32(2) // CERT_KEY_PROV_INFO_PROP_ID

// keyProvInfo is the CERT_KEY_PROV_INFO_PROP_ID content read from a stored
// certificate.
type keyProvInfo struct {
	provider      string
	containerName string
	providerType  uint32
	keySpec       uint32
	flags         uint32
}

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
		flags:         kpi.flags,
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
