package enterprise

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"time"
	"unicode/utf16"

	"github.com/keppin-oss/enterprise-tls/lifecycle"
)

// Native adapters for lifecycle.Enrollment.
// The key adapter is CNGKeys (enrollment_keys.go), the requester is
// NativeRequester (enrollment_requester.go, ICertRequest in ca_com_windows.go)
// and the store is MachineMy (mystore_windows.go). certreq.exe is not part of
// the lifecycle path.

const maxListedFile = 1 << 20 // any file hashed for the cleanup inventory

// attemptDir is the subset of *lifecycle.AttemptDir the adapters use; tests
// substitute an in-memory directory.
type attemptDir interface {
	Close() error
	Path(name string) (string, error)
	ReadFile(name string, max int64) ([]byte, error)
	Stat(name string) error
	WriteFile(name string, data []byte) error
	List() ([]lifecycle.DirEntry, error)
	Remove(name, hash string) error
}

type attemptDirs interface {
	Open(id string, create bool) (attemptDir, error)
}

type storeDirs struct{ s *lifecycle.AttemptStore }

func (d storeDirs) Open(id string, create bool) (attemptDir, error) {
	if d.s == nil {
		return nil, errors.New("attempt store required")
	}
	dir, err := d.s.Open(id, create)
	if err != nil {
		return nil, err
	}
	return dir, nil
}

// listAttemptFiles lists the attempt directory by handle. A missing directory
// is an established absence: the attempt never wrote a file. Every entry that
// is not a readable plain file is returned with Err.
func listAttemptFiles(dirs attemptDirs, id string) ([]lifecycle.AttemptFile, error) {
	if dirs == nil {
		return nil, errors.New("attempt store required")
	}
	d, err := dirs.Open(id, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer d.Close()
	entries, err := d.List()
	if err != nil {
		return nil, err
	}
	out := make([]lifecycle.AttemptFile, 0, len(entries))
	for _, e := range entries {
		f := lifecycle.AttemptFile{Name: e.Name}
		if e.Kind != lifecycle.EntryFile {
			f.Err = errors.New("not a plain file")
		} else if data, err := d.ReadFile(e.Name, maxListedFile); err != nil {
			f.Err = err
		} else {
			f.Hash = sha256Hex(data)
		}
		out = append(out, f)
	}
	return out, nil
}

var (
	oidTemplateV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 7}
	oidTemplateV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2}
)

// EnrollmentValidator is the full validation of an issued certificate.
// Roots and Issuer are required.
type EnrollmentValidator struct {
	Roots         *x509.CertPool
	Intermediates *x509.CertPool
	// Issuer is the expected issuing CA: the leaf's direct issuer in every
	// verified chain.
	Issuer *x509.Certificate
	// Templates maps a template name to the OID its v2 extension carries.
	Templates map[string]asn1.ObjectIdentifier
	Now       func() time.Time
}

// Validate checks der for attempt a; it matches lifecycle.Enrollment.Validate.
func (v EnrollmentValidator) Validate(_ context.Context, der []byte, a lifecycle.Attempt) error {
	if v.Roots == nil || v.Issuer == nil {
		return fmt.Errorf("%w: roots and expected issuer required", ErrInvalidCertificate)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}
	if a.SPKI == "" || sha256Hex(cert.RawSubjectPublicKeyInfo) != a.SPKI {
		return fmt.Errorf("%w: public key is not the attempt's", ErrInvalidCertificate)
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	if _, err := ValidateCertificate(der, ValidateOptions{Roots: v.Roots, Intermediates: v.Intermediates, Now: now}); err != nil {
		return err
	}
	chains, err := cert.Verify(x509.VerifyOptions{Roots: v.Roots, Intermediates: v.Intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CurrentTime: now})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}
	for _, chain := range chains {
		if len(chain) < 2 || !chain[1].Equal(v.Issuer) {
			return fmt.Errorf("%w: not issued by the expected CA", ErrInvalidCertificate)
		}
	}
	return v.checkTemplate(cert, a.Template)
}

func (v EnrollmentValidator) checkTemplate(cert *x509.Certificate, name string) error {
	var v2, v1 []byte
	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(oidTemplateV2):
			if v2 != nil {
				return fmt.Errorf("%w: duplicate template extension", ErrInvalidCertificate)
			}
			v2 = ext.Value
		case ext.Id.Equal(oidTemplateV1):
			if v1 != nil {
				return fmt.Errorf("%w: duplicate template extension", ErrInvalidCertificate)
			}
			v1 = ext.Value
		}
	}
	if name == "" || v2 == nil && v1 == nil {
		return fmt.Errorf("%w: certificate template not established", ErrInvalidCertificate)
	}
	if v2 != nil {
		var t struct {
			ID    asn1.ObjectIdentifier
			Major int `asn1:"optional"`
			Minor int `asn1:"optional"`
		}
		want, ok := v.Templates[name]
		if rest, err := asn1.Unmarshal(v2, &t); err != nil || len(rest) != 0 || !ok || !t.ID.Equal(want) {
			return fmt.Errorf("%w: template extension does not name %q", ErrInvalidCertificate, name)
		}
	}
	if v1 != nil {
		got, err := bmpString(v1)
		if err != nil || got != name {
			return fmt.Errorf("%w: template name extension does not name %q", ErrInvalidCertificate, name)
		}
	}
	return nil
}

func bmpString(der []byte) (string, error) {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil || len(rest) != 0 || raw.Class != asn1.ClassUniversal || raw.Tag != 30 || len(raw.Bytes)%2 != 0 {
		return "", errors.New("not a BMPString")
	}
	units := make([]uint16, len(raw.Bytes)/2)
	for i := range units {
		units[i] = uint16(raw.Bytes[2*i])<<8 | uint16(raw.Bytes[2*i+1])
	}
	return string(utf16.Decode(units)), nil
}

// AttemptDeleter deletes enrollment cleanup artifacts
// of a terminal cleanup plan. Cleaner calls DeletePlanned with the
// attempt ID. Key artifacts go to Keys, the cng adapter (CNGKeys); without it
// they fail. An installed certificate is only ever retained.
type AttemptDeleter struct {
	Keys lifecycle.Deleter
	dirs attemptDirs
}

// NewAttemptDeleter binds the deleter to an open attempt store.
func NewAttemptDeleter(store *lifecycle.AttemptStore, keys lifecycle.Deleter) AttemptDeleter {
	return AttemptDeleter{Keys: keys, dirs: storeDirs{store}}
}

var _ lifecycle.PlanDeleter = AttemptDeleter{}

// Delete refuses file artifacts, which need their plan.
func (d AttemptDeleter) Delete(ctx context.Context, a lifecycle.Artifact) error {
	return d.DeletePlanned(ctx, "", a)
}

func (d AttemptDeleter) DeletePlanned(ctx context.Context, plan string, a lifecycle.Artifact) error {
	switch a.Kind {
	case lifecycle.File:
		if plan == "" || d.dirs == nil {
			return errors.New("file artifact without its attempt")
		}
		dir, err := d.dirs.Open(plan, false)
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: %v", lifecycle.ErrNotFound, err)
		}
		if err != nil {
			return err
		}
		defer dir.Close()
		return dir.Remove(a.Name, a.Hash)
	case lifecycle.Key:
		if d.Keys == nil {
			return errors.New("key deletion requires the cng key adapter")
		}
		if pd, ok := d.Keys.(lifecycle.PlanDeleter); ok {
			return pd.DeletePlanned(ctx, plan, a)
		}
		return d.Keys.Delete(ctx, a)
	}
	return fmt.Errorf("artifact kind %q is not an enrollment artifact", a.Kind)
}

// validSPKI checks SubjectPublicKeyInfo ::= SEQUENCE { algorithm
// AlgorithmIdentifier, subjectPublicKey BIT STRING } with AlgorithmIdentifier
// ::= SEQUENCE { OBJECT IDENTIFIER, parameters ANY OPTIONAL }, every level
// fully consumed and the key non-empty. Anything else cannot be compared.
func validSPKI(f asn1.RawValue) bool {
	if f.Class != asn1.ClassUniversal || f.Tag != asn1.TagSequence || !f.IsCompound {
		return false
	}
	var alg asn1.RawValue
	rest, err := asn1.Unmarshal(f.Bytes, &alg)
	if err != nil || alg.Class != asn1.ClassUniversal || alg.Tag != asn1.TagSequence || !alg.IsCompound || !wellFormedDER(alg, 0) {
		return false
	}
	var key asn1.BitString
	if rest, err = asn1.Unmarshal(rest, &key); err != nil || len(rest) != 0 || key.BitLength == 0 {
		return false
	}
	var oid asn1.ObjectIdentifier
	params, err := asn1.Unmarshal(alg.Bytes, &oid)
	if err != nil || len(oid) == 0 {
		return false
	}
	if len(params) != 0 {
		var p asn1.RawValue
		if rest, err := asn1.Unmarshal(params, &p); err != nil || len(rest) != 0 || !wellFormedDER(p, 0) {
			return false
		}
	}
	return true
}

// maxDERDepth bounds wellFormedDER on crafted input.
const maxDERDepth = 16

// wellFormedDER reports whether v is DER that this adapter can vouch for,
// recursively with a bounded depth. asn1.RawValue checks only tags and
// lengths, so contents are checked here against a closed list:
//   - constructed SEQUENCE and context-specific values: every element
//     nested in them, with no trailing bytes;
//   - NULL: empty; BOOLEAN: 0x00 or 0xFF; INTEGER: minimal encoding;
//     OBJECT IDENTIFIER and BIT STRING: fully decoded; OCTET STRING: any.
//
// Any other type or form is reported as not well formed, so the object is
// not comparable rather than silently different. SET is excluded: without
// the schema its DER ordering (SET OF sorted by encoding) cannot be checked,
// and no known SubjectPublicKeyInfo parameters use it.
func wellFormedDER(v asn1.RawValue, depth int) bool {
	if depth >= maxDERDepth {
		return false
	}
	if v.IsCompound {
		universal := v.Class == asn1.ClassUniversal && v.Tag == asn1.TagSequence
		if !universal && v.Class != asn1.ClassContextSpecific {
			return false
		}
		for rest := v.Bytes; len(rest) > 0; {
			var child asn1.RawValue
			var err error
			if rest, err = asn1.Unmarshal(rest, &child); err != nil || !wellFormedDER(child, depth+1) {
				return false
			}
		}
		return true
	}
	if v.Class != asn1.ClassUniversal {
		return false
	}
	decodes := func(out any) bool {
		rest, err := asn1.Unmarshal(v.FullBytes, out)
		return err == nil && len(rest) == 0
	}
	switch v.Tag {
	case asn1.TagNull:
		return len(v.Bytes) == 0
	case asn1.TagBoolean:
		return len(v.Bytes) == 1 && (v.Bytes[0] == 0x00 || v.Bytes[0] == 0xff)
	case asn1.TagInteger:
		var n *big.Int
		return decodes(&n)
	case asn1.TagOID:
		var oid asn1.ObjectIdentifier
		return decodes(&oid) && len(oid) > 0
	case asn1.TagBitString:
		var b asn1.BitString
		return decodes(&b)
	case asn1.TagOctetString:
		return true
	}
	return false
}

// spkiOf returns the SubjectPublicKeyInfo DER of a certificate by walking its
// TBSCertificate fields, without the full X.509 parser: a REQUEST store
// object that the strict parser rejects must still be compared.
func spkiOf(der []byte) ([]byte, error) {
	var cert, tbs asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &cert); err != nil || len(rest) != 0 || cert.Tag != asn1.TagSequence {
		return nil, errors.New("not a certificate")
	}
	if _, err := asn1.Unmarshal(cert.Bytes, &tbs); err != nil || tbs.Tag != asn1.TagSequence {
		return nil, errors.New("no TBSCertificate")
	}
	fields := tbs.Bytes
	// version [0] EXPLICIT (optional), serialNumber, signature, issuer,
	// validity, subject, subjectPublicKeyInfo.
	for i := 0; ; i++ {
		var f asn1.RawValue
		rest, err := asn1.Unmarshal(fields, &f)
		if err != nil {
			return nil, errors.New("malformed TBSCertificate")
		}
		fields = rest
		if i == 0 && f.Class == asn1.ClassContextSpecific && f.Tag == 0 {
			i--
			continue
		}
		if i == 5 {
			if !validSPKI(f) {
				return nil, errors.New("malformed SubjectPublicKeyInfo")
			}
			return f.FullBytes, nil
		}
	}
}
