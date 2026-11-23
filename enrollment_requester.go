package enterprise

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io/fs"
	"net"

	"github.com/keppin-oss/enterprise-tls/lifecycle"
)

const (
	fileCSR     = "request.csr"
	maxCSRFile  = 64 << 10
	maxCertFile = 64 << 10
	maxCAText   = 2 << 10 // diagnostic CA text kept in CAResult.Text
)

// caReply is the raw result of one ICertRequest call (Submit or
// RetrievePending) with its follow-up getters, read on the same object.
type caReply struct {
	// Err is the failed HRESULT of the call, a refusal before the call, or an
	// error matching lifecycle.ErrQuiescence when the call may still be
	// running.
	Err         error
	Disposition lifecycle.CADisposition
	RequestID   int    // from GetRequestId, 0 unless positive
	Status      uint32 // GetLastStatus, diagnostic
	Text        string // disposition message, diagnostic
	Cert        []byte // DER from GetCertificate after CR_DISP_ISSUED
	CertErr     error  // GetCertificate failure after CR_DISP_ISSUED
}

// caClient calls the CA. The Windows
// implementation is the in-process ICertRequest COM object.
type caClient interface {
	Submit(ctx context.Context, config, template string, csr []byte) caReply
	Retrieve(ctx context.Context, config string, requestID int) caReply
}

// NativeRequester implements lifecycle.Requester without a child process:
// the CSR is built in Go and signed by the attempt's key, the CA is called
// through ICertRequest, and every file lives in the protected attempt
// directory.
type NativeRequester struct {
	dirs attemptDirs
	ca   caClient
}

var _ lifecycle.Requester = (*NativeRequester)(nil)

// NewNativeRequester binds the requester to an open attempt store. expectSID
// is the only process identity allowed to call the CA (for the broker
// service, S-1-5-18): any thread token, or another process identity, refuses
// the call before CoCreateInstance and again before Submit/RetrievePending.
func NewNativeRequester(store *lifecycle.AttemptStore, expectSID string) *NativeRequester {
	return &NativeRequester{dirs: storeDirs{store}, ca: newCOMCA(expectSID)}
}

// requestTemplate is the request the INF described: CN=localhost, SAN
// localhost, 127.0.0.1 and ::1, digitalSignature, serverAuth. The template
// decides what is issued; EnrollmentValidator checks the result.
func requestTemplate() (*x509.CertificateRequest, error) {
	ku, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x80}, BitLength: 1}) // digitalSignature
	if err != nil {
		return nil, err
	}
	eku, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 1}})
	if err != nil {
		return nil, err
	}
	return &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "localhost"},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: ku},
			{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: eku},
		},
	}, nil
}

func (r *NativeRequester) dir(a lifecycle.Attempt, create bool) (attemptDir, error) {
	if r == nil || r.dirs == nil || r.ca == nil {
		return nil, errors.New("native requester not initialized")
	}
	d, err := r.dirs.Open(a.ID, false)
	if create && errors.Is(err, fs.ErrNotExist) {
		d, err = r.dirs.Open(a.ID, true)
	}
	return d, err
}

// WriteCSR builds the PKCS #10 request signed by key, checks that it carries
// the attempt's public key and a valid signature, and writes it (DER) as
// request.csr, replacing an earlier one: it is called only while CSRHash is
// empty, before any submit.
func (r *NativeRequester) WriteCSR(_ context.Context, a lifecycle.Attempt, key crypto.Signer) (string, error) {
	if len(a.PublicKey) == 0 {
		return "", errors.New("attempt without a recorded public key")
	}
	tmpl, err := requestTemplate()
	if err != nil {
		return "", err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return "", fmt.Errorf("build CSR: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return "", fmt.Errorf("parse built CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return "", fmt.Errorf("CSR signature: %w", err)
	}
	if !bytes.Equal(csr.RawSubjectPublicKeyInfo, a.PublicKey) {
		return "", errors.New("CSR public key is not the attempt's")
	}
	d, err := r.dir(a, true)
	if err != nil {
		return "", err
	}
	defer d.Close()
	if err := d.WriteFile(fileCSR, der); err != nil {
		return "", err
	}
	return sha256Hex(der), nil
}

// readCSR returns the CSR bytes, checked: a well-formed request with a valid
// signature.
func (r *NativeRequester) readCSR(a lifecycle.Attempt) ([]byte, *x509.CertificateRequest, error) {
	d, err := r.dir(a, false)
	if err != nil {
		return nil, nil, err
	}
	defer d.Close()
	der, err := d.ReadFile(fileCSR, maxCSRFile)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, err
	}
	return der, csr, nil
}

// ReadCSR returns the SHA-256 of request.csr and of its SubjectPublicKeyInfo.
func (r *NativeRequester) ReadCSR(_ context.Context, a lifecycle.Attempt) (string, string, error) {
	der, csr, err := r.readCSR(a)
	if err != nil {
		return "", "", err
	}
	return sha256Hex(der), sha256Hex(csr.RawSubjectPublicKeyInfo), nil
}

// refusedCA is a refusal before any CA call. Once the launch record is
// durable the state machine treats it like a failed call (CA_UNKNOWN without
// a RequestId), which is the conservative reading.
func refusedCA(err error) lifecycle.CAResult { return lifecycle.CAResult{Err: err, Text: err.Error()} }

// Submit sends request.csr, whose hash must be the recorded one, and writes an
// issued certificate to certFile, which must not exist yet.
func (r *NativeRequester) Submit(ctx context.Context, a lifecycle.Attempt, certFile string) lifecycle.CAResult {
	der, _, err := r.readCSR(a)
	if err != nil {
		return refusedCA(fmt.Errorf("request.csr unreadable: %w", err))
	}
	if sha256Hex(der) != a.CSRHash {
		return refusedCA(errors.New("request.csr is not the recorded one"))
	}
	if err := r.requireAbsent(a, certFile); err != nil {
		return refusedCA(err)
	}
	return r.result(a, certFile, r.ca.Submit(ctx, a.CA, a.Template, der))
}

// Retrieve calls RetrievePending for the recorded RequestId.
func (r *NativeRequester) Retrieve(ctx context.Context, a lifecycle.Attempt, certFile string) lifecycle.CAResult {
	if a.RequestID <= 0 {
		return refusedCA(errors.New("retrieve without a RequestId"))
	}
	if err := r.requireAbsent(a, certFile); err != nil {
		return refusedCA(err)
	}
	return r.result(a, certFile, r.ca.Retrieve(ctx, a.CA, a.RequestID))
}

func (r *NativeRequester) requireAbsent(a lifecycle.Attempt, name string) error {
	d, err := r.dir(a, false)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Stat(name); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s already present or not checkable (%v)", name, err)
	}
	return nil
}

// result maps a CA reply. After CR_DISP_ISSUED the certificate is written to
// certFile; Stat reports that write, so a certificate that could not be kept
// is never treated as issued.
func (r *NativeRequester) result(a lifecycle.Attempt, certFile string, rep caReply) lifecycle.CAResult {
	text := rep.Text
	if len(text) > maxCAText {
		text = text[:maxCAText]
	}
	res := lifecycle.CAResult{Err: rep.Err, Disposition: rep.Disposition, Status: rep.Status, Text: text}
	if rep.RequestID > 0 {
		res.RequestID = rep.RequestID
	}
	if rep.Err != nil || rep.Disposition != lifecycle.DispIssued {
		return res
	}
	res.Stat = r.keepCert(a, certFile, rep)
	return res
}

func (r *NativeRequester) keepCert(a lifecycle.Attempt, certFile string, rep caReply) error {
	if rep.CertErr != nil {
		return fmt.Errorf("GetCertificate: %w", rep.CertErr)
	}
	if len(rep.Cert) > maxCertFile {
		// The same bound as ReadCert: a kept file is always readable back.
		return fmt.Errorf("issued certificate of %d bytes exceeds %d", len(rep.Cert), maxCertFile)
	}
	if _, err := x509.ParseCertificate(rep.Cert); err != nil {
		return fmt.Errorf("issued certificate unreadable: %w", err)
	}
	d, err := r.dir(a, false)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.WriteFile(certFile, rep.Cert)
}

// ReadCert returns the DER certificate kept in file.
func (r *NativeRequester) ReadCert(_ context.Context, a lifecycle.Attempt, file string) ([]byte, error) {
	d, err := r.dir(a, false)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	der, err := d.ReadFile(file, maxCertFile)
	if err != nil {
		return nil, err
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		return nil, err
	}
	return der, nil
}

// Files lists every file of the attempt directory.
func (r *NativeRequester) Files(_ context.Context, a lifecycle.Attempt) ([]lifecycle.AttemptFile, error) {
	if r == nil {
		return nil, errors.New("native requester not initialized")
	}
	return listAttemptFiles(r.dirs, a.ID)
}
