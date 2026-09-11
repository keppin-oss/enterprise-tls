//go:build windows

package enterprise

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"syscall"
	"testing"
	"unsafe"

	"github.com/keppin-oss/cng/windowscng"
	"golang.org/x/sys/windows"
)

func TestMapCNGError_KeyNotFound(t *testing.T) {
	err := mapCNGError(fmt.Errorf("delete: %w", windowscng.ErrKeyNotFound))
	if !errors.Is(err, errKeyNotFound) {
		t.Fatalf("expected errKeyNotFound, got %v", err)
	}
}

func TestMapCNGError_OtherErrorPreserved(t *testing.T) {
	boom := errors.New("permission denied")
	err := mapCNGError(boom)
	if errors.Is(err, errKeyNotFound) {
		t.Fatalf("must not convert an unrelated error to not-found, got %v", err)
	}
	if !errors.Is(err, boom) {
		t.Fatalf("expected original error to be preserved, got %v", err)
	}
}

func TestFindContext_Lifetime(t *testing.T) {
	// Only public certificate bytes enter an isolated memory store. The keys
	// used to issue these fixtures remain in Go memory; no system store is used.
	root, rootKey := rootCA(t)
	leaf := issueCert(t, leafTemplate(), root, rootKey, &rootKey.PublicKey)

	for _, tt := range []struct {
		name         string
		match        bool
		retainFirst  bool
		retainResult bool
	}{
		{name: "non_match_then_match_retained", match: true, retainFirst: true},
		{name: "exhausted_retained", retainFirst: true},
		{name: "non_match_then_match_no_leak", match: true},
		{name: "exhausted_no_leak"},
		{name: "returned_context_owned_by_caller", match: true, retainResult: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store, err := syscall.CertOpenStore(syscall.CERT_STORE_PROV_MEMORY, 0, 0, windows.CERT_STORE_CREATE_NEW_FLAG, 0)
			if err != nil {
				t.Fatalf("open memory store: %v", err)
			}

			var retained *syscall.CertContext
			var retainedFP [32]byte
			t.Cleanup(func() {
				// CHECK closes the store even when it reports pending contexts.
				// A retained reference must survive both the search and close;
				// without one, a pending context is an enumeration/caller leak.
				err := syscall.CertCloseStore(store, windows.CERT_CLOSE_STORE_CHECK_FLAG)
				if retained == nil {
					if err != nil {
						t.Errorf("memory store has unreleased contexts: %v", err)
					}
					return
				}
				if !errors.Is(err, windows.Errno(windows.CRYPT_E_PENDING_CLOSE)) {
					// Do not free a reference the search may already have consumed.
					t.Errorf("search released a caller-owned context: close = %v, want CRYPT_E_PENDING_CLOSE", err)
					return
				}
				if got := sha256.Sum256(unsafe.Slice(retained.EncodedCert, int(retained.Length))); got != retainedFP {
					t.Error("caller-owned context changed after search/store close")
				}
				if err := syscall.CertFreeCertificateContext(retained); err != nil {
					t.Errorf("free caller-owned context: %v", err)
				}
			})

			for _, cert := range []*x509.Certificate{root, leaf} {
				ctx, err := syscall.CertCreateCertificateContext(syscall.X509_ASN_ENCODING, &cert.Raw[0], uint32(len(cert.Raw)))
				if err != nil {
					t.Fatalf("create certificate context: %v", err)
				}
				addErr := syscall.CertAddCertificateContextToStore(store, ctx, syscall.CERT_STORE_ADD_ALWAYS, nil)
				freeErr := syscall.CertFreeCertificateContext(ctx)
				if addErr != nil || freeErr != nil {
					t.Fatalf("populate memory store: add = %v, free = %v", addErr, freeErr)
				}
			}

			// Discover the actual order rather than assume insertion order. The
			// target is the second certificate, so findContext must advance past
			// a non-match. Only a duplicate may be retained while advancing.
			first, err := syscall.CertEnumCertificatesInStore(store, nil)
			if err != nil {
				t.Fatalf("enumerate first certificate: %v", err)
			}
			if tt.retainFirst {
				retained = (*syscall.CertContext)(unsafe.Pointer(windows.CertDuplicateCertificateContext((*windows.CertContext)(unsafe.Pointer(first)))))
				retainedFP = sha256.Sum256(unsafe.Slice(first.EncodedCert, int(first.Length)))
			}
			second, err := syscall.CertEnumCertificatesInStore(store, first)
			// first was consumed by enumeration, including on failure.
			if err != nil {
				t.Fatalf("enumerate second certificate: %v", err)
			}
			target := sha256.Sum256(unsafe.Slice(second.EncodedCert, int(second.Length)))
			if err := syscall.CertFreeCertificateContext(second); err != nil {
				t.Fatalf("free discovery context: %v", err)
			}
			if !tt.match {
				target = sha256.Sum256([]byte("not a certificate in this memory store"))
			}

			ctx, found, err := findContext(store, target)
			if err != nil || found != tt.match || (ctx != nil) != tt.match {
				t.Errorf("findContext: context = %p, found = %t, err = %v; want match = %t", ctx, found, err, tt.match)
			}
			if ctx != nil {
				if got := sha256.Sum256(unsafe.Slice(ctx.EncodedCert, int(ctx.Length))); got != target {
					t.Error("findContext returned the wrong certificate")
				}
				if tt.retainResult {
					retained, retainedFP = ctx, target
				} else if err := syscall.CertFreeCertificateContext(ctx); err != nil {
					t.Errorf("free returned context: %v", err)
				}
			}
		})
	}
}
