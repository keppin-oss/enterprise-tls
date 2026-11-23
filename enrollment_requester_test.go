package enterprise

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/keppin-oss/enterprise-tls/lifecycle"
)

// fakeCA records calls and returns a scripted reply.
type fakeCA struct {
	reply caReply
	calls []string
	csr   []byte
}

func (f *fakeCA) Submit(_ context.Context, config, template string, csr []byte) caReply {
	f.calls = append(f.calls, "submit "+config+" "+template)
	f.csr = csr
	return f.reply
}

func (f *fakeCA) Retrieve(_ context.Context, config string, id int) caReply {
	f.calls = append(f.calls, "retrieve "+config)
	return f.reply
}

type requesterRig struct {
	r    *NativeRequester
	dirs *memDirs
	ca   *fakeCA
	key  *ecdsa.PrivateKey
	a    lifecycle.Attempt
}

func newRequesterRig(t *testing.T) *requesterRig {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	dirs := &memDirs{dirs: map[string]*memDir{}}
	ca := &fakeCA{}
	a := baseAttempt()
	a.PublicKey, a.SPKI = pub, sha256Hex(pub)
	return &requesterRig{r: &NativeRequester{dirs: dirs, ca: ca}, dirs: dirs, ca: ca, key: k, a: a}
}

// ready writes the CSR and records its hash, as KEY_READY does.
func (g *requesterRig) ready(t *testing.T) {
	t.Helper()
	h, err := g.r.WriteCSR(actx, g.a, g.key)
	if err != nil {
		t.Fatal(err)
	}
	g.a.CSRHash = h
}

func TestNativeWriteCSR(t *testing.T) {
	g := newRequesterRig(t)
	g.ready(t)
	der := g.dirs.dirs[attemptID].files[fileCSR]
	if sha256Hex(der) != g.a.CSRHash {
		t.Fatal("recorded hash is not the file's")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("CSR: %v", err)
	}
	if !bytes.Equal(csr.RawSubjectPublicKeyInfo, g.a.PublicKey) || csr.Subject.CommonName != "localhost" ||
		len(csr.DNSNames) != 1 || csr.DNSNames[0] != "localhost" || len(csr.IPAddresses) != 2 ||
		csr.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Fatalf("CSR content: %+v", csr)
	}
	var ku, eku bool
	for _, e := range csr.Extensions {
		switch {
		case e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 15}):
			ku = e.Critical
		case e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 37}):
			var oids []asn1.ObjectIdentifier
			_, err := asn1.Unmarshal(e.Value, &oids)
			eku = err == nil && len(oids) == 1 && oids[0].Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1})
		}
	}
	if !ku || !eku {
		t.Fatalf("requested extensions: ku=%t eku=%t", ku, eku)
	}
	hash, spki, err := g.r.ReadCSR(actx, g.a)
	if err != nil || hash != g.a.CSRHash || spki != g.a.SPKI {
		t.Fatalf("ReadCSR: %s %s %v", hash, spki, err)
	}

	// A key that is not the attempt's never produces a CSR file.
	other := newRequesterRig(t)
	other.a.PublicKey, other.a.SPKI = g.a.PublicKey, g.a.SPKI
	if _, err := other.r.WriteCSR(actx, other.a, other.key); err == nil {
		t.Fatal("CSR written with another key")
	}
	if _, ok := other.dirs.dirs[attemptID]; ok {
		t.Fatal("attempt directory created for a refused CSR")
	}
	// A tampered CSR file is not read back.
	g.dirs.dirs[attemptID].files[fileCSR] = append(append([]byte(nil), der[:len(der)-1]...), der[len(der)-1]^1)
	if _, _, err := g.r.ReadCSR(actx, g.a); err == nil {
		t.Fatal("tampered CSR accepted")
	}
}

func issuedLeaf(t *testing.T) []byte {
	t.Helper()
	return testLeaf(t).Raw
}

func TestNativeSubmitMapping(t *testing.T) {
	leaf := issuedLeaf(t)
	for name, tc := range map[string]struct {
		reply    caReply
		wantErr  bool
		wantStat bool // Stat is an error
		wantFile bool
		wantID   int
	}{
		"issued":                        {caReply{Disposition: lifecycle.DispIssued, RequestID: 21, Cert: leaf}, false, false, true, 21},
		"issued, GetCertificate failed": {caReply{Disposition: lifecycle.DispIssued, RequestID: 21, CertErr: errors.New("0x80070057")}, false, true, false, 21},
		"issued, unreadable bytes":      {caReply{Disposition: lifecycle.DispIssued, RequestID: 21, Cert: []byte("junk")}, false, true, false, 21},
		"pending":                       {caReply{Disposition: lifecycle.DispUnderSubmission, RequestID: 22}, false, false, false, 22},
		"denied":                        {caReply{Disposition: lifecycle.DispDenied, RequestID: 23, Status: 0x80094012}, false, false, false, 23},
		"failed HRESULT":                {caReply{Err: errors.New("HRESULT 0x800706BA"), Disposition: lifecycle.DispIssued, Cert: leaf}, true, false, false, 0},
		"negative RequestId":            {caReply{Disposition: lifecycle.DispError, RequestID: -1}, false, false, false, 0},
	} {
		t.Run(name, func(t *testing.T) {
			g := newRequesterRig(t)
			g.ready(t)
			g.ca.reply = tc.reply
			res := g.r.Submit(actx, g.a, "issued.cer")
			if (res.Err != nil) != tc.wantErr || (res.Stat != nil) != tc.wantStat || res.RequestID != tc.wantID ||
				res.Disposition != tc.reply.Disposition {
				t.Fatalf("%+v", res)
			}
			_, kept := g.dirs.dirs[attemptID].files["issued.cer"]
			if kept != tc.wantFile {
				t.Fatalf("certificate file kept=%t", kept)
			}
			if len(g.ca.calls) != 1 || g.ca.calls[0] != "submit "+g.a.CA+" "+g.a.Template || !bytes.Equal(g.ca.csr, g.dirs.dirs[attemptID].files[fileCSR]) {
				t.Fatalf("calls %v", g.ca.calls)
			}
			if tc.wantFile {
				if der, err := g.r.ReadCert(actx, g.a, "issued.cer"); err != nil || !bytes.Equal(der, leaf) {
					t.Fatalf("ReadCert: %v", err)
				}
			}
		})
	}
}

// Every refusal happens before the CA is called.
func TestNativeRefusalsBeforeTheCA(t *testing.T) {
	g := newRequesterRig(t)
	g.ready(t)
	changed := g.a
	changed.CSRHash = sha256Hex([]byte("other"))
	if res := g.r.Submit(actx, changed, "issued.cer"); res.Err == nil {
		t.Fatal("submit with another CSR hash")
	}
	g.dirs.dirs[attemptID].files["issued.cer"] = []byte("left over")
	if res := g.r.Submit(actx, g.a, "issued.cer"); res.Err == nil {
		t.Fatal("submit over an existing certificate file")
	}
	if res := g.r.Retrieve(actx, g.a, "retrieve-1.cer"); res.Err == nil {
		t.Fatal("retrieve without a RequestId")
	}
	withID := g.a
	withID.RequestID = 5
	if res := g.r.Retrieve(actx, withID, "issued.cer"); res.Err == nil {
		t.Fatal("retrieve over an existing file")
	}
	if len(g.ca.calls) != 0 {
		t.Fatalf("CA called: %v", g.ca.calls)
	}
	g.ca.reply = caReply{Disposition: lifecycle.DispIssued, RequestID: 5, Cert: issuedLeaf(t)}
	if res := g.r.Retrieve(actx, withID, "retrieve-1.cer"); res.Err != nil || res.Stat != nil || g.ca.calls[0] != "retrieve "+g.a.CA {
		t.Fatalf("retrieve: %+v %v", res, g.ca.calls)
	}
	if _, err := (&NativeRequester{}).WriteCSR(actx, g.a, g.key); err == nil {
		t.Fatal("zero requester accepted")
	}
}

func TestNativeTextBounded(t *testing.T) {
	g := newRequesterRig(t)
	g.ready(t)
	g.ca.reply = caReply{Disposition: lifecycle.DispDenied, Text: strings.Repeat("x", 3*maxCAText)}
	if res := g.r.Submit(actx, g.a, "issued.cer"); len(res.Text) != maxCAText {
		t.Fatalf("text %d bytes", len(res.Text))
	}
}

func TestIdentityDecision(t *testing.T) {
	const system = "S-1-5-18"
	for name, tc := range map[string]struct {
		token      bool
		threadErr  error
		sid        string
		processErr error
		expect     string
		ok         bool
	}{
		"process SYSTEM":         {false, nil, system, nil, system, true},
		"thread token":           {true, nil, system, nil, system, false},
		"thread token error":     {false, errors.New("ACCESS_DENIED"), "", nil, system, false},
		"process token error":    {false, nil, "", errors.New("x"), system, false},
		"other process identity": {false, nil, "S-1-5-19", nil, system, false},
		"no expected SID":        {false, nil, system, nil, "", false},
	} {
		err := identityDecision(tc.token, tc.threadErr, tc.sid, tc.processErr, tc.expect)
		if (err == nil) != tc.ok || err != nil && !errors.Is(err, ErrCallerIdentity) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParseECCPublicBlob(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blob := make([]byte, 8+64)
	binary.LittleEndian.PutUint32(blob, 0x31534345)
	binary.LittleEndian.PutUint32(blob[4:], 32)
	k.X.FillBytes(blob[8:40])
	k.Y.FillBytes(blob[40:72])
	pub, err := parseECCPublicBlob(blob)
	if err != nil || !pub.Equal(&k.PublicKey) {
		t.Fatalf("blob: %v", err)
	}
	bad := func(f func(b []byte) []byte) []byte { return f(append([]byte(nil), blob...)) }
	for name, b := range map[string][]byte{
		"private magic": bad(func(b []byte) []byte { binary.LittleEndian.PutUint32(b, 0x32534345); return b }),
		"P-384 size":    bad(func(b []byte) []byte { binary.LittleEndian.PutUint32(b[4:], 48); return b }),
		"short":         blob[:40],
		"not on curve":  bad(func(b []byte) []byte { b[71] ^= 1; return b }),
	} {
		if _, err := parseECCPublicBlob(b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// Review of bd5759d, finding 3: a certificate the requester would not read
// back is never kept, so Stat never promises an unreadable file.
func TestNativeCertSizeBound(t *testing.T) {
	g := newRequesterRig(t)
	g.ready(t)
	g.ca.reply = caReply{Disposition: lifecycle.DispIssued, RequestID: 30, Cert: make([]byte, maxCertFile+1)}
	res := g.r.Submit(actx, g.a, "issued.cer")
	if res.Stat == nil {
		t.Fatal("oversized certificate reported as kept")
	}
	if _, ok := g.dirs.dirs[attemptID].files["issued.cer"]; ok {
		t.Fatal("oversized certificate written")
	}
}
