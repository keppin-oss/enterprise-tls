package enterprise

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/keppin-oss/enterprise-tls/lifecycle"
)

var actx = context.Background()

// memDir is an in-memory attempt directory.
type memDir struct {
	files   map[string][]byte
	special map[string]lifecycle.EntryKind // non-file entries
	broken  map[string]error               // ReadFile/Stat failures
	removed []string
	closed  int
}

func (d *memDir) Close() error { d.closed++; return nil }
func (d *memDir) Path(name string) (string, error) {
	if strings.ContainsAny(name, `\/:`) {
		return "", errors.New("invalid name")
	}
	return `C:\journal\attempts\a\` + name, nil
}
func (d *memDir) ReadFile(name string, max int64) ([]byte, error) {
	if err := d.broken[name]; err != nil {
		return nil, err
	}
	b, ok := d.files[name]
	if !ok {
		return nil, fmt.Errorf("%s: %w", name, fs.ErrNotExist)
	}
	if int64(len(b)) > max {
		return nil, errors.New("too large")
	}
	return append([]byte(nil), b...), nil
}
func (d *memDir) Stat(name string) error {
	if err := d.broken[name]; err != nil {
		return err
	}
	if _, ok := d.files[name]; !ok {
		return fmt.Errorf("%s: %w", name, fs.ErrNotExist)
	}
	return nil
}
func (d *memDir) WriteFile(name string, data []byte) error {
	d.files[name] = append([]byte(nil), data...)
	return nil
}
func (d *memDir) List() ([]lifecycle.DirEntry, error) {
	var out []lifecycle.DirEntry
	for n := range d.files {
		out = append(out, lifecycle.DirEntry{Name: n, Kind: lifecycle.EntryFile})
	}
	for n, k := range d.special {
		out = append(out, lifecycle.DirEntry{Name: n, Kind: k})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
func (d *memDir) Remove(name, hash string) error {
	b, ok := d.files[name]
	if !ok {
		return lifecycle.ErrNotFound
	}
	if sha256Hex(b) != hash {
		return lifecycle.ErrNotOwned
	}
	delete(d.files, name)
	d.removed = append(d.removed, name)
	return nil
}

type memDirs struct {
	dirs    map[string]*memDir
	created []string
}

func (m *memDirs) Open(id string, create bool) (attemptDir, error) {
	d, ok := m.dirs[id]
	switch {
	case ok && create:
		return nil, errors.New("exists")
	case !ok && !create:
		return nil, fmt.Errorf("%s: %w", id, fs.ErrNotExist)
	case !ok:
		d = &memDir{files: map[string][]byte{}}
		m.dirs[id] = d
		m.created = append(m.created, id)
	}
	return d, nil
}

const attemptID = "0123456789abcdef0123456789abcdef"

func baseAttempt() lifecycle.Attempt {
	return lifecycle.Attempt{ID: attemptID, CA: `ca.example.test\Example CA`, Template: "ExampleWeb",
		Provider: expectedCNGProvider, Container: "keppin-enterprise-tls-c1"}
}

func testLeaf(t *testing.T) *x509.Certificate {
	t.Helper()
	root, rootKey := rootCA(t)
	k := mustRSAKey(t)
	return issueCert(t, leafTemplate(), root, rootKey, &k.PublicKey)
}

func TestListAttemptFiles(t *testing.T) {
	dirs := &memDirs{dirs: map[string]*memDir{}}
	if files, err := listAttemptFiles(dirs, attemptID); err != nil || len(files) != 0 {
		t.Fatalf("missing directory: %v %v", files, err)
	}
	d := &memDir{files: map[string][]byte{"request.csr": []byte("csr"), "issued.cer": []byte("cert"), "locked.cer": []byte("x")}}
	d.special = map[string]lifecycle.EntryKind{"sub": lifecycle.EntryDirectory, "link": lifecycle.EntryReparse}
	d.broken = map[string]error{"locked.cer": errors.New("sharing violation")}
	dirs.dirs[attemptID] = d
	files, err := listAttemptFiles(dirs, attemptID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]lifecycle.AttemptFile{}
	for _, f := range files {
		got[f.Name] = f
	}
	if got["issued.cer"].Hash != sha256Hex([]byte("cert")) || got["issued.cer"].Err != nil ||
		got["request.csr"].Hash == "" || got["sub"].Err == nil || got["link"].Err == nil ||
		got["locked.cer"].Err == nil || got["locked.cer"].Hash != "" || len(files) != 5 {
		t.Fatalf("%+v", files)
	}
	if d.closed != 1 {
		t.Fatalf("directory handle closed %d times", d.closed)
	}
}

type validatorFixture struct {
	root, inter *x509.Certificate
	interKey    *rsa.PrivateKey
	leafKey     *rsa.PrivateKey
	attempt     lifecycle.Attempt
	v           EnrollmentValidator
}

var templateOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 8, 1, 2, 3}

func bmp(s string) []byte {
	units := utf16.Encode([]rune(s))
	b := make([]byte, 0, 2*len(units))
	for _, u := range units {
		b = append(b, byte(u>>8), byte(u))
	}
	der, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: 30, Bytes: b})
	return der
}

func v2Template(oid asn1.ObjectIdentifier) []byte {
	der, _ := asn1.Marshal(struct {
		ID    asn1.ObjectIdentifier
		Major int
		Minor int
	}{oid, 100, 3})
	return der
}

func newValidatorFixture(t *testing.T) *validatorFixture {
	root, rootKey := rootCA(t)
	interKey := mustRSAKey(t)
	inter := issueCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "Example Issuing CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}, root, rootKey, &interKey.PublicKey)
	leafKey := mustRSAKey(t)
	spki, _ := x509.MarshalPKIXPublicKey(&leafKey.PublicKey)
	return &validatorFixture{root: root, inter: inter, interKey: interKey, leafKey: leafKey,
		attempt: lifecycle.Attempt{Template: "ExampleWeb", SPKI: sha256Hex(spki)},
		v: EnrollmentValidator{Roots: rootsPool(root), Intermediates: rootsPool(inter), Issuer: inter,
			Templates: map[string]asn1.ObjectIdentifier{"ExampleWeb": templateOID}}}
}

func (f *validatorFixture) leaf(t *testing.T, mutate func(*x509.Certificate)) []byte {
	tmpl := leafTemplate()
	tmpl.ExtraExtensions = []pkix.Extension{{Id: oidTemplateV2, Value: v2Template(templateOID)}}
	if mutate != nil {
		mutate(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.inter, &f.leafKey.PublicKey, f.interKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestEnrollmentValidator(t *testing.T) {
	f := newValidatorFixture(t)
	if err := f.v.Validate(actx, f.leaf(t, nil), f.attempt); err != nil {
		t.Fatalf("valid certificate rejected: %v", err)
	}
	both := func(c *x509.Certificate) {
		c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: oidTemplateV1, Value: bmp("ExampleWeb")})
	}
	if err := f.v.Validate(actx, f.leaf(t, both), f.attempt); err != nil {
		t.Fatalf("agreeing v1 and v2 rejected: %v", err)
	}
	onlyV1 := func(c *x509.Certificate) {
		c.ExtraExtensions = []pkix.Extension{{Id: oidTemplateV1, Value: bmp("ExampleWeb")}}
	}
	if err := f.v.Validate(actx, f.leaf(t, onlyV1), f.attempt); err != nil {
		t.Fatalf("v1 template rejected: %v", err)
	}
	other := f.attempt
	other.SPKI = sha256Hex([]byte("another key"))
	unknown := f.attempt
	unknown.Template = "Other"
	noRoots, noIssuer, rootIssuer := f.v, f.v, f.v
	noRoots.Roots, noIssuer.Issuer, rootIssuer.Issuer = nil, nil, f.root
	expired := f.v
	expired.Now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	for name, c := range map[string]struct {
		v   EnrollmentValidator
		a   lifecycle.Attempt
		der []byte
	}{
		"other SPKI":       {f.v, other, f.leaf(t, nil)},
		"template unknown": {f.v, unknown, f.leaf(t, nil)},
		"no roots":         {noRoots, f.attempt, f.leaf(t, nil)},
		"no issuer":        {noIssuer, f.attempt, f.leaf(t, nil)},
		"another issuer":   {rootIssuer, f.attempt, f.leaf(t, nil)},
		"expired":          {expired, f.attempt, f.leaf(t, nil)},
		"no template":      {f.v, f.attempt, f.leaf(t, func(c *x509.Certificate) { c.ExtraExtensions = nil })},
		"v2 other OID": {f.v, f.attempt, f.leaf(t, func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: oidTemplateV2, Value: v2Template(asn1.ObjectIdentifier{1, 2, 3})}}
		})},
		"v1 disagrees": {f.v, f.attempt, f.leaf(t, func(c *x509.Certificate) {
			c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: oidTemplateV1, Value: bmp("Other")})
		})},
		"wrong SAN": {f.v, f.attempt, f.leaf(t, func(c *x509.Certificate) { c.DNSNames = []string{"host.example"} })},
		"no EKU": {f.v, f.attempt, f.leaf(t, func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		})},
		"not DER": {f.v, f.attempt, []byte("not a certificate")},
	} {
		if err := c.v.Validate(actx, c.der, c.a); !errors.Is(err, ErrInvalidCertificate) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSPKIOf(t *testing.T) {
	leaf := testLeaf(t)
	got, err := spkiOf(leaf.Raw)
	if err != nil || string(got) != string(leaf.RawSubjectPublicKeyInfo) {
		t.Fatalf("%v", err)
	}
	for _, bad := range [][]byte{nil, []byte{0x30, 0x00}, leaf.Raw[:40]} {
		if _, err := spkiOf(bad); err == nil {
			t.Fatalf("%x accepted", bad)
		}
	}
}

type fakeKeys struct {
	plans []string
}

func (f *fakeKeys) Delete(context.Context, lifecycle.Artifact) error {
	return errors.New("plan expected")
}
func (f *fakeKeys) DeletePlanned(_ context.Context, plan string, _ lifecycle.Artifact) error {
	f.plans = append(f.plans, plan)
	return nil
}

func TestAttemptDeleter(t *testing.T) {
	dirs := &memDirs{dirs: map[string]*memDir{attemptID: {files: map[string][]byte{"issued.cer": []byte("cert")}}}}
	d := AttemptDeleter{dirs: dirs}
	file := lifecycle.Artifact{Kind: lifecycle.File, Name: "issued.cer", Hash: sha256Hex([]byte("cert"))}
	if err := d.Delete(actx, file); err == nil {
		t.Fatal("file deleted without its attempt")
	}
	if err := d.DeletePlanned(actx, attemptID, lifecycle.Artifact{Kind: lifecycle.File, Name: "issued.cer", Hash: sha256Hex([]byte("x"))}); !errors.Is(err, lifecycle.ErrNotOwned) {
		t.Fatalf("hash mismatch: %v", err)
	}
	if err := d.DeletePlanned(actx, attemptID, file); err != nil || len(dirs.dirs[attemptID].removed) != 1 {
		t.Fatalf("file: %v", err)
	}
	if err := d.DeletePlanned(actx, "ffffffffffffffffffffffffffffffff", file); !errors.Is(err, lifecycle.ErrNotFound) {
		t.Fatalf("missing attempt directory: %v", err)
	}
	key := lifecycle.Artifact{Kind: lifecycle.Key, Name: "key", Provider: expectedCNGProvider, Container: "c", SPKI: "s"}
	if err := d.DeletePlanned(actx, attemptID, key); err == nil {
		t.Fatal("key deleted without the cng adapter")
	}
	keys := &fakeKeys{}
	d.Keys = keys
	if err := d.DeletePlanned(actx, attemptID, key); err != nil || len(keys.plans) != 1 || keys.plans[0] != attemptID {
		t.Fatalf("key delegation: %v %v", err, keys.plans)
	}
	for _, kind := range []lifecycle.ArtifactKind{lifecycle.Certificate, lifecycle.Request} {
		if err := d.DeletePlanned(actx, attemptID, lifecycle.Artifact{Kind: kind, Name: "x", Hash: "h"}); err == nil {
			t.Fatalf("%s artifact deleted", kind)
		}
	}
}

// Only a complete SubjectPublicKeyInfo can be compared: any other shape is
// an error, never a non-matching hash.
func TestValidSPKI(t *testing.T) {
	raw := func(der []byte) asn1.RawValue {
		var v asn1.RawValue
		if rest, err := asn1.Unmarshal(der, &v); err != nil || len(rest) != 0 {
			t.Fatalf("fixture %x: %v", der, err)
		}
		return v
	}
	leaf := testLeaf(t)
	if !validSPKI(raw(leaf.RawSubjectPublicKeyInfo)) {
		t.Fatal("real SPKI rejected")
	}
	rsaAlg := []byte{0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00}
	seq := func(parts ...[]byte) []byte {
		var body []byte
		for _, p := range parts {
			body = append(body, p...)
		}
		return append([]byte{0x30, byte(len(body))}, body...)
	}
	bits := []byte{0x03, 0x02, 0x00, 0x01}
	if !validSPKI(raw(seq(rsaAlg, bits))) {
		t.Fatal("minimal SPKI rejected")
	}
	for name, der := range map[string][]byte{
		"empty sequence":         seq(),
		"algorithm only":         seq(rsaAlg),
		"key only":               seq(bits),
		"algorithm not a seq":    seq([]byte{0x06, 0x01, 0x2a}, bits),
		"no OID":                 seq(seq(), bits),
		"empty bit string":       seq(rsaAlg, []byte{0x03, 0x01, 0x00}),
		"trailing element":       seq(rsaAlg, bits, []byte{0x05, 0x00}),
		"two parameters":         seq(seq([]byte{0x06, 0x01, 0x2a}, []byte{0x05, 0x00}, []byte{0x05, 0x00}), bits),
		"key is an OCTET STRING": seq(rsaAlg, []byte{0x04, 0x01, 0x01}),
	} {
		if validSPKI(raw(der)) {
			t.Errorf("%s accepted", name)
		}
	}
	oid := []byte{0x06, 0x01, 0x2a}
	if !validSPKI(raw(seq(seq(oid, seq([]byte{0x02, 0x01, 0x01})), bits))) {
		t.Fatal("well-formed constructed parameters rejected")
	}
	for name, param := range map[string][]byte{
		"NULL":           {0x05, 0x00},
		"named curve":    {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07},
		"PSS-like":       {0xa0, 0x03, 0x02, 0x01, 0x14},
		"specified data": seq([]byte{0x02, 0x01, 0x01}, []byte{0x04, 0x01, 0x07}, []byte{0x03, 0x02, 0x00, 0x01}, []byte{0x01, 0x01, 0xff}),
	} {
		if !validSPKI(raw(seq(seq(oid, param), bits))) {
			t.Errorf("valid %s parameter rejected", name)
		}
	}
	for name, param := range map[string][]byte{
		"NULL with content":          {0x05, 0x01, 0x00},
		"unsorted SET OF INTEGER":    {0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01},
		"sorted SET OF INTEGER":      {0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02},
		"SET nested in SEQUENCE":     seq([]byte{0x31, 0x03, 0x02, 0x01, 0x01}),
		"non-minimal INTEGER":        seq([]byte{0x02, 0x02, 0x00, 0x01}),
		"BOOLEAN 0x01":               seq([]byte{0x01, 0x01, 0x01}),
		"empty OID":                  seq([]byte{0x06, 0x00}),
		"BIT STRING padding":         seq([]byte{0x03, 0x02, 0x01, 0x01}),
		"UTF8String":                 seq([]byte{0x0c, 0x01, 0x61}),
		"context-specific primitive": {0x80, 0x01, 0x00},
		"application constructed":    {0x60, 0x02, 0x05, 0x00},
		"NULL with content, nested":  seq(seq([]byte{0x05, 0x01, 0x00})),
	} {
		if validSPKI(raw(seq(seq(oid, param), bits))) {
			t.Errorf("%s parameter accepted", name)
		}
	}
	deep := []byte{0x05, 0x00}
	for i := 0; i < 20; i++ {
		deep = seq(deep)
	}
	for name, der := range map[string][]byte{
		// The outer lengths are consistent; an inner element is truncated.
		"truncated parameter element": seq(seq(oid, seq([]byte{0x02, 0x05, 0x01})), bits),
		"truncated nested element":    seq(seq(oid, seq(seq([]byte{0x04, 0x03, 0x00}))), bits),
		"trailing byte in parameters": seq(seq(oid, seq([]byte{0x05, 0x00, 0x00})), bits),
		"nesting beyond the bound":    seq(seq(oid, deep), bits),
	} {
		if validSPKI(raw(der)) {
			t.Errorf("%s accepted", name)
		}
	}
	if validSPKI(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true}) {
		t.Fatal("SET accepted")
	}
}
