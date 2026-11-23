//go:build windows

package enterprise

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/keppin-oss/enterprise-tls/lifecycle"
)

var (
	modNCrypt = windows.NewLazySystemDLL("ncrypt.dll")

	procCertSetContextProperty = modCrypt32.NewProc("CertSetCertificateContextProperty")
	procNCryptExportKey        = modNCrypt.NewProc("NCryptExportKey")
	procNCryptSignHash         = modNCrypt.NewProc("NCryptSignHash")
	procNCryptFreeObject       = modNCrypt.NewProc("NCryptFreeObject")
)

const (
	certSetKeyContextProp = 0x1 // CERT_SET_KEY_CONTEXT_PROP_ID in CRYPT_KEY_PROV_INFO.dwFlags
	certStoreAddNew       = 1
	cryptEExists          = 0x80092005

	storeLocalMachine = 0x00020000
	storeCurrentUser  = 0x00010000
	storeReadOnly     = 0x00008000
	storeOpenExisting = 0x00004000

	ncryptMachineKeyFlag = 0x20
	ncryptSilentFlag     = 0x40

	acquireCompareKey = 0x00000004
	acquireNoHealing  = 0x00000008
	acquireSilent     = 0x00000040
	acquireOnlyNCrypt = 0x00040000
	certNCryptKeySpec = 0xFFFFFFFF
)

const certEncoding = windows.X509_ASN_ENCODING | windows.PKCS_7_ASN_ENCODING

// cryptKeyProvInfoIn is CRYPT_KEY_PROV_INFO as passed to
// CertSetCertificateContextProperty, with the same layout as cryptKeyProvInfo
// but Go pointers for the two strings.
type cryptKeyProvInfoIn struct {
	containerName *uint16
	provName      *uint16
	provType      uint32
	flags         uint32
	cProvParam    uint32
	pad           uint32
	rgProvParam   uintptr
	keySpec       uint32
}

// MachineMy implements lifecycle.CertStore on LocalMachine\My. The store
// ACL is the default of LocalMachine\My.
type MachineMy struct {
	location uint32 // system store location; tests use the current user
	keyFlags uint32 // CRYPT_KEY_PROV_INFO.dwFlags for the binding
}

// NewMachineMy returns the LocalMachine\My adapter.
func NewMachineMy() MachineMy {
	return MachineMy{location: storeLocalMachine, keyFlags: ncryptMachineKeyFlag}
}

var _ lifecycle.CertStore = MachineMy{}

func (m MachineMy) open(readOnly bool) (windows.Handle, error) {
	if m.location == 0 {
		return 0, errors.New("certificate store adapter not initialized")
	}
	name, err := windows.UTF16PtrFromString("MY")
	if err != nil {
		return 0, err
	}
	flags := m.location | storeOpenExisting
	if readOnly {
		flags |= storeReadOnly
	}
	return windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0, flags, uintptr(unsafe.Pointer(name)))
}

// Install adds the certificate with CERT_STORE_ADD_NEW and sets its
// CRYPT_KEY_PROV_INFO: CNG (dwProvType 0), the attempt's provider and
// container, the machine flag. A certificate already present is left as it is
// (its binding is never rewritten): only VerifyBinding decides the outcome.
func (m MachineMy) Install(_ context.Context, a lifecycle.Attempt, cert []byte) error {
	if a.Provider != expectedCNGProvider || a.Container == "" {
		return errors.New("attempt without a KSP key container")
	}
	if len(cert) == 0 || sha256Hex(cert) != a.CertHash {
		return errors.New("certificate is not the attempt's")
	}
	store, err := m.open(false)
	if err != nil {
		return fmt.Errorf("open My: %w", err)
	}
	defer windows.CertCloseStore(store, 0)
	created, err := windows.CertCreateCertificateContext(certEncoding, &cert[0], uint32(len(cert)))
	if err != nil {
		return fmt.Errorf("certificate context: %w", err)
	}
	defer windows.CertFreeCertificateContext(created)
	var stored *windows.CertContext
	if err := windows.CertAddCertificateContextToStore(store, created, certStoreAddNew, &stored); err != nil {
		if errors.Is(err, windows.Errno(cryptEExists)) {
			return nil
		}
		return fmt.Errorf("add to My: %w", err)
	}
	defer windows.CertFreeCertificateContext(stored)
	cont, err := windows.UTF16PtrFromString(a.Container)
	if err != nil {
		return err
	}
	prov, err := windows.UTF16PtrFromString(a.Provider)
	if err != nil {
		return err
	}
	// Typed pointers keep both strings reachable for the whole call; the
	// structure itself is kept alive by the argument conversion (Proc.Call).
	info := cryptKeyProvInfoIn{containerName: cont, provName: prov, flags: m.keyFlags}
	if r, _, e := procCertSetContextProperty.Call(uintptr(unsafe.Pointer(stored)), uintptr(certKeyProvInfoPropID), 0,
		uintptr(unsafe.Pointer(&info))); r == 0 {
		return fmt.Errorf("set CRYPT_KEY_PROV_INFO: %w", e)
	}
	return nil
}

// find returns the certificate of My whose DER SHA-256 is certHash.
func findBySHA256(store windows.Handle, certHash string) (*windows.CertContext, []byte, error) {
	var prev *windows.CertContext
	for {
		c, err := windows.CertEnumCertificatesInStore(store, prev)
		if err != nil {
			if errors.Is(err, windows.Errno(windows.CRYPT_E_NOT_FOUND)) {
				return nil, nil, errors.New("certificate not in My")
			}
			return nil, nil, err
		}
		der := append([]byte(nil), unsafe.Slice(c.EncodedCert, c.Length)...)
		if sha256Hex(der) == certHash {
			return c, der, nil // the enumeration stops here; the caller frees c
		}
		prev = c
	}
}

// VerifyBinding is the binding check of an installed certificate, with no repair:
//  1. re-open My and find CertHash; its CRYPT_KEY_PROV_INFO names the KSP,
//     the attempt's container, CNG and the expected key flags;
//  2. CryptAcquireCertificatePrivateKey with ONLY_NCRYPT, COMPARE_KEY,
//     NO_HEALING and SILENT, without CACHE: a cached handle (no comparison
//     made) is refused;
//  3. the acquired key's SPKI equals the certificate's, and a test signature
//     with that handle verifies with the certificate's public key.
//
// It returns the SHA-256 SPKI of the acquired key.
func (m MachineMy) VerifyBinding(_ context.Context, a lifecycle.Attempt) (string, error) {
	store, err := m.open(true)
	if err != nil {
		return "", fmt.Errorf("open My: %w", err)
	}
	defer windows.CertCloseStore(store, 0)
	c, der, err := findBySHA256(store, a.CertHash)
	if err != nil {
		return "", err
	}
	defer windows.CertFreeCertificateContext(c)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("certificate key is not ECDSA")
	}
	kpi, err := readKeyProvInfo((*syscall.CertContext)(unsafe.Pointer(c)))
	if err != nil {
		return "", err
	}
	prov, cont, provType, flags := kpi.provider, kpi.containerName, kpi.providerType, kpi.flags
	if prov != a.Provider || cont != a.Container || provType != 0 || flags&m.keyFlags != m.keyFlags ||
		flags&certSetKeyContextProp != 0 {
		return "", fmt.Errorf("CRYPT_KEY_PROV_INFO %q/%q type %d flags 0x%X is not the attempt's binding", prov, cont, provType, flags)
	}
	var h windows.Handle
	var spec uint32
	var callerFree bool
	if err := windows.CryptAcquireCertificatePrivateKey(c, acquireOnlyNCrypt|acquireCompareKey|acquireNoHealing|acquireSilent,
		nil, &h, &spec, &callerFree); err != nil {
		return "", fmt.Errorf("CryptAcquireCertificatePrivateKey: %w", err)
	}
	if callerFree {
		defer procNCryptFreeObject.Call(uintptr(h))
	} else {
		return "", errors.New("a cached key handle was returned: no comparison was made")
	}
	if spec != certNCryptKeySpec {
		return "", fmt.Errorf("key spec 0x%X is not a CNG key", spec)
	}
	pub, err := exportECCPublic(h)
	if err != nil {
		return "", err
	}
	if !pub.Equal(certPub) {
		return "", errors.New("acquired key is not the certificate's")
	}
	if err := testSignature(h, certPub); err != nil {
		return "", err
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return sha256Hex(spki), nil
}

func exportECCPublic(h windows.Handle) (*ecdsa.PublicKey, error) {
	blobType, err := windows.UTF16PtrFromString("ECCPUBLICBLOB")
	if err != nil {
		return nil, err
	}
	var cb uint32
	if r, _, _ := procNCryptExportKey.Call(uintptr(h), 0, uintptr(unsafe.Pointer(blobType)), 0, 0, 0,
		uintptr(unsafe.Pointer(&cb)), ncryptSilentFlag); r != 0 || cb == 0 {
		return nil, fmt.Errorf("NCryptExportKey size: 0x%08X", uint32(r))
	}
	buf := make([]byte, cb)
	if r, _, _ := procNCryptExportKey.Call(uintptr(h), 0, uintptr(unsafe.Pointer(blobType)), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(cb), uintptr(unsafe.Pointer(&cb)), ncryptSilentFlag); r != 0 {
		return nil, fmt.Errorf("NCryptExportKey: 0x%08X", uint32(r))
	}
	return parseECCPublicBlob(buf[:cb])
}

// testSignature signs a random SHA-256-sized digest with the acquired handle
// and verifies it with the certificate's public key.
func testSignature(h windows.Handle, pub *ecdsa.PublicKey) error {
	digest := make([]byte, 32)
	if _, err := rand.Read(digest); err != nil {
		return err
	}
	sig := make([]byte, 64)
	var cb uint32
	if r, _, _ := procNCryptSignHash.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])), uintptr(len(sig)), uintptr(unsafe.Pointer(&cb)), ncryptSilentFlag); r != 0 {
		return fmt.Errorf("NCryptSignHash: 0x%08X", uint32(r))
	}
	if cb != 64 {
		return fmt.Errorf("NCryptSignHash returned %d bytes", cb)
	}
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest, r, s) {
		return errors.New("test signature does not verify with the certificate's key")
	}
	return nil
}

// The input layout must match the output layout read by readKeyProvInfo.
var _ = [1]struct{}{}[unsafe.Sizeof(cryptKeyProvInfoIn{})-unsafe.Sizeof(cryptKeyProvInfo{})]
