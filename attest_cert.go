package pca

// Certificates as the reference's X.509 engine (OpenSSL through node:crypto) reads them. crypto/x509 refuses a certificate
// for many reasons OpenSSL does not (a trailing byte after a DER certificate, a non-minimal length, a duplicated or
// ill-formed extension, a second extensions block), and those are precisely the inputs on which the strict readers of the
// attestation verifiers must give their own, specific answer. So a certificate is parsed here with the structure checks of
// the OpenSSL template decoder (nothing more), the strict rules are applied afterwards by the readers of attest_der.go, and
// crypto/x509 is used only for what it is good at: public keys and signature verification.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"math/big"
	"strings"
)

const (
	osslWrongTag = "error:068000A8:asn1 encoding routines::wrong tag"
	osslNested   = "error:0688010A:asn1 encoding routines::nested asn1 error"
	osslBits     = "error:0680007D:asn1 encoding routines::invalid bit string bits left"
	osslObject   = "error:0688010A:asn1 encoding routines::invalid object encoding"
)

// attCert is a parsed certificate: the raw parts the verifiers compare, and the parameters of its signature.
type attCert struct {
	Raw        []byte // the certificate as DER (outer length in minimal form)
	RawTBS     []byte // tbsCertificate, header included
	RawIssuer  []byte
	RawSubject []byte
	RawSPKI    []byte
	Serial     []byte // the INTEGER content
	SigOID     string
	SigParams  []byte // the parameters element of the signature algorithm, header included (nil: absent)
	Signature  []byte // the signature BIT STRING content without the unused-bits octet
	exts       []lenientExt
}

type lenientExt struct {
	oid      string
	critical bool
	value    []byte
}

type certElem struct {
	tag             byte
	hdr, start, end int
}

func readCertElem(b []byte, off, limit int, tag byte) (certElem, error) {
	if off >= limit {
		return certElem{}, errors.New("error:0680007B:asn1 encoding routines::not enough data")
	}
	t, err := tlvAt(b[:limit], off)
	if err != nil {
		return certElem{}, errors.New(osslNested)
	}
	if tag != 0 && t.tag != tag {
		return certElem{}, errors.New(osslWrongTag)
	}
	return certElem{tag: t.tag, hdr: off, start: t.start, end: t.end}, nil
}

func certKids(b []byte, e certElem) ([]certElem, error) {
	var out []certElem
	for p := e.start; p < e.end; {
		k, err := readCertElem(b, p, e.end, 0)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
		p = k.end
	}
	return out, nil
}

// validOID is the OpenSSL object-identifier content check: not empty, no arc starting with 0x80, no dangling continuation.
func validOID(b []byte, e certElem) bool {
	if e.tag != 0x06 || e.end <= e.start || b[e.end-1]&0x80 != 0 {
		return false
	}
	for i := e.start; i < e.end; i++ {
		if b[i] == 0x80 && (i == e.start || b[i-1]&0x80 == 0) {
			return false
		}
	}
	return true
}

// algID reads AlgorithmIdentifier: SEQUENCE { OID, parameters ANY OPTIONAL }.
func algID(b []byte, e certElem) (oid string, params []byte, err error) {
	kids, err := certKids(b, e)
	if err != nil {
		return "", nil, err
	}
	if len(kids) == 0 || len(kids) > 2 || !validOID(b, kids[0]) {
		return "", nil, errors.New(osslNested)
	}
	dotted, err := oidToDotted(b, derTlv{tag: kids[0].tag, start: kids[0].start, end: kids[0].end})
	if err != nil {
		return "", nil, errors.New(osslObject)
	}
	if len(kids) == 2 {
		params = b[kids[1].hdr:kids[1].end]
	}
	return dotted, params, nil
}

func checkBitString(b []byte, e certElem) error {
	if e.tag != 0x03 || e.end-e.start < 1 {
		return errors.New(osslWrongTag)
	}
	if b[e.start] > 7 {
		return errors.New(osslBits)
	}
	return nil
}

var nameValueTags = map[byte]bool{0x0c: true, 0x12: true, 0x13: true, 0x14: true, 0x16: true, 0x1c: true, 0x1e: true, 0x03: true, 0x30: true}

// checkName validates a Name: SEQUENCE OF SET OF SEQUENCE { OID, string }.
func checkName(b []byte, e certElem) error {
	rdns, err := certKids(b, e)
	if err != nil {
		return err
	}
	for _, rdn := range rdns {
		if rdn.tag != 0x31 {
			return errors.New(osslWrongTag)
		}
		atvs, err := certKids(b, rdn)
		if err != nil {
			return err
		}
		for _, atv := range atvs {
			if atv.tag != 0x30 {
				return errors.New(osslWrongTag)
			}
			kv, err := certKids(b, atv)
			if err != nil {
				return err
			}
			if len(kv) != 2 || !validOID(b, kv[0]) || !nameValueTags[kv[1].tag] {
				return errors.New(osslNested)
			}
		}
	}
	return nil
}

// parseCertDER parses a DER certificate like d2i_X509: its structure is checked, trailing bytes after it are ignored.
func parseCertDER(der []byte) (*attCert, error) {
	outer, err := readCertElem(der, 0, len(der), 0x30)
	if err != nil {
		return nil, err
	}
	tbs, err := readCertElem(der, outer.start, outer.end, 0x30)
	if err != nil {
		return nil, err
	}
	alg, err := readCertElem(der, tbs.end, outer.end, 0x30)
	if err != nil {
		return nil, err
	}
	sig, err := readCertElem(der, alg.end, outer.end, 0x03)
	if err != nil {
		return nil, err
	}
	if sig.end != outer.end {
		return nil, errors.New(osslNested)
	}
	if err := checkBitString(der, sig); err != nil {
		return nil, err
	}
	c := &attCert{RawTBS: append([]byte{}, der[tbs.hdr:tbs.end]...), Signature: append([]byte{}, der[sig.start+1:sig.end]...)}
	if c.SigOID, c.SigParams, err = algID(der, alg); err != nil {
		return nil, err
	}

	p := tbs.start
	if p < tbs.end && der[p] == 0xa0 {
		v, err := readCertElem(der, p, tbs.end, 0xa0)
		if err != nil {
			return nil, err
		}
		inner, err := readCertElem(der, v.start, v.end, 0x02)
		if err != nil {
			return nil, err
		}
		if inner.end != v.end {
			return nil, errors.New(osslNested)
		}
		p = v.end
	}
	serial, err := readCertElem(der, p, tbs.end, 0x02)
	if err != nil {
		return nil, err
	}
	if serial.end == serial.start {
		return nil, errors.New("error:0688010A:asn1 encoding routines::illegal zero content")
	}
	c.Serial = append([]byte{}, der[serial.start:serial.end]...)
	p = serial.end
	inner, err := readCertElem(der, p, tbs.end, 0x30) // signature algorithm
	if err != nil {
		return nil, err
	}
	if _, _, err := algID(der, inner); err != nil {
		return nil, err
	}
	p = inner.end
	issuer, err := readCertElem(der, p, tbs.end, 0x30)
	if err != nil {
		return nil, err
	}
	if err := checkName(der, issuer); err != nil {
		return nil, err
	}
	c.RawIssuer = append([]byte{}, der[issuer.hdr:issuer.end]...)
	p = issuer.end
	validity, err := readCertElem(der, p, tbs.end, 0x30)
	if err != nil {
		return nil, err
	}
	times, err := certKids(der, validity)
	if err != nil {
		return nil, err
	}
	if len(times) != 2 || (times[0].tag != 0x17 && times[0].tag != 0x18) || (times[1].tag != 0x17 && times[1].tag != 0x18) {
		return nil, errors.New(osslNested)
	}
	p = validity.end
	subject, err := readCertElem(der, p, tbs.end, 0x30)
	if err != nil {
		return nil, err
	}
	if err := checkName(der, subject); err != nil {
		return nil, err
	}
	c.RawSubject = append([]byte{}, der[subject.hdr:subject.end]...)
	p = subject.end
	spki, err := readCertElem(der, p, tbs.end, 0x30)
	if err != nil {
		return nil, err
	}
	sk, err := certKids(der, spki)
	if err != nil {
		return nil, err
	}
	if len(sk) != 2 || sk[0].tag != 0x30 {
		return nil, errors.New(osslNested)
	}
	if _, _, err := algID(der, sk[0]); err != nil {
		return nil, err
	}
	if err := checkBitString(der, sk[1]); err != nil {
		return nil, err
	}
	c.RawSPKI = append([]byte{}, der[spki.hdr:spki.end]...)
	p = spki.end
	for _, uid := range []byte{0x81, 0x82} {
		if p < tbs.end && der[p] == uid {
			u, err := readCertElem(der, p, tbs.end, uid)
			if err != nil {
				return nil, err
			}
			p = u.end
		}
	}
	if p < tbs.end && der[p] == 0xa3 {
		wrap, err := readCertElem(der, p, tbs.end, 0xa3)
		if err != nil {
			return nil, err
		}
		seq, err := readCertElem(der, wrap.start, wrap.end, 0x30)
		if err != nil {
			return nil, err
		}
		if seq.end != wrap.end {
			return nil, errors.New(osslNested)
		}
		exts, err := certKids(der, seq)
		if err != nil {
			return nil, err
		}
		for _, e := range exts {
			if e.tag != 0x30 {
				return nil, errors.New(osslWrongTag)
			}
			parts, err := certKids(der, e)
			if err != nil {
				return nil, err
			}
			if len(parts) < 2 || len(parts) > 3 || !validOID(der, parts[0]) {
				return nil, errors.New(osslNested)
			}
			le := lenientExt{}
			if le.oid, err = oidToDotted(der, derTlv{tag: parts[0].tag, start: parts[0].start, end: parts[0].end}); err != nil {
				return nil, errors.New(osslObject)
			}
			next := 1
			if len(parts) == 3 {
				if parts[1].tag != 0x01 || parts[1].end-parts[1].start != 1 {
					return nil, errors.New(osslNested)
				}
				le.critical = der[parts[1].start] != 0
				next = 2
			}
			if parts[next].tag != 0x04 {
				return nil, errors.New(osslWrongTag)
			}
			le.value = append([]byte{}, der[parts[next].start:parts[next].end]...)
			c.exts = append(c.exts, le)
		}
		p = wrap.end
	}
	if p != tbs.end {
		return nil, errors.New(osslNested)
	}

	// the certificate as DER: the outer length in its minimal form, the content as supplied
	content := der[outer.start:outer.end]
	c.Raw = append(derLengthHeader(0x30, len(content)), content...)
	return c, nil
}

func derLengthHeader(tag byte, n int) []byte {
	switch {
	case n < 0x80:
		return []byte{tag, byte(n)}
	case n < 0x100:
		return []byte{tag, 0x81, byte(n)}
	case n < 0x10000:
		return []byte{tag, 0x82, byte(n >> 8), byte(n)}
	case n < 0x1000000:
		return []byte{tag, 0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return []byte{tag, 0x84, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

// certFromPEM parses the first certificate block of a PEM text (PEM_read_bio_X509_AUX: bytes after the certificate inside the
// block are an error).
func certFromPEM(text string) (*attCert, error) {
	m := pemCertBodyRe.FindStringSubmatch(text)
	if m == nil {
		return nil, errors.New("error:0480006C:PEM routines::no start line")
	}
	body := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, m[1])
	der, err := base64StdDecode(body)
	if err != nil {
		return nil, errors.New("error:1E08010C:DECODER routines::unsupported")
	}
	c, err := parseCertDER(der)
	if err != nil {
		return nil, err
	}
	outer, _ := readCertElem(der, 0, len(der), 0x30)
	if outer.end != len(der) {
		return nil, errors.New(osslNested)
	}
	return c, nil
}

func certSelfIssued(c *attCert) bool { return string(c.RawSubject) == string(c.RawIssuer) }

// certSerialHex is the serial number as lowercase hex without leading zeros.
func certSerialHex(c *attCert) string {
	return strings.TrimLeft(toHexLower(c.Serial), "0")
}

// ───────────────────────────────────────────────────────────── keys and signatures

var (
	oidRSAEncryption = "1.2.840.113549.1.1.1"
	oidRSAPSSKey     = "1.2.840.113549.1.1.10"
	oidECPublicKey   = "1.2.840.10045.2.1"
	oidEd25519Key    = "1.3.101.112"
)

// keyOfCert is the certificate's subject public key. An RSASSA-PSS key (which crypto/x509 does not read) is read from its
// SubjectPublicKeyInfo as the RSAPublicKey it carries.
func keyOfCert(c *attCert) (certKey, error) {
	spki, err := readCertElem(c.RawSPKI, 0, len(c.RawSPKI), 0x30)
	if err != nil {
		return certKey{}, err
	}
	kids, err := certKids(c.RawSPKI, spki)
	if err != nil || len(kids) != 2 {
		return certKey{}, errors.New(osslNested)
	}
	oid, _, err := algID(c.RawSPKI, kids[0])
	if err != nil {
		return certKey{}, err
	}
	bits := c.RawSPKI[kids[1].start+1 : kids[1].end]
	switch oid {
	case oidRSAEncryption, oidRSAPSSKey:
		rk, err := x509.ParsePKCS1PublicKey(bits)
		if err != nil {
			return certKey{}, errors.New("error:1E08010C:DECODER routines::unsupported")
		}
		k := keyInfoOf(rk, c.RawSPKI)
		if oid == oidRSAPSSKey {
			k.typ = "rsa-pss"
		}
		return k, nil
	case oidECPublicKey, oidEd25519Key:
		pub, err := x509.ParsePKIXPublicKey(c.RawSPKI)
		if err != nil {
			return certKey{}, errors.New("error:1E08010C:DECODER routines::unsupported")
		}
		return keyInfoOf(pub, c.RawSPKI), nil
	}
	return certKey{}, errors.New("error:1E08010C:DECODER routines::unsupported")
}

var sigHashes = map[string]crypto.Hash{
	"1.2.840.10045.4.3.2":   crypto.SHA256,
	"1.2.840.10045.4.3.3":   crypto.SHA384,
	"1.2.840.10045.4.3.4":   crypto.SHA512,
	"1.2.840.113549.1.1.11": crypto.SHA256,
	"1.2.840.113549.1.1.12": crypto.SHA384,
	"1.2.840.113549.1.1.13": crypto.SHA512,
}

var hashOIDs = map[string]crypto.Hash{
	"2.16.840.1.101.3.4.2.1": crypto.SHA256,
	"2.16.840.1.101.3.4.2.2": crypto.SHA384,
	"2.16.840.1.101.3.4.2.3": crypto.SHA512,
	"1.3.14.3.2.26":          crypto.SHA1,
}

// pssParams reads RSASSA-PSS-params: the hash, the salt length, and whether the profile is one this verifier checks (MGF1 over the
// same hash, trailer field 1).
func pssParams(raw []byte) (crypto.Hash, int, bool) {
	h, salt := crypto.SHA1, 20
	if len(raw) == 0 {
		return h, salt, true
	}
	seq, err := readCertElem(raw, 0, len(raw), 0x30)
	if err != nil {
		return 0, 0, false
	}
	kids, err := certKids(raw, seq)
	if err != nil {
		return 0, 0, false
	}
	mgfHash := crypto.SHA1
	for _, k := range kids {
		inner, err := certKids(raw, k)
		if err != nil || len(inner) != 1 {
			return 0, 0, false
		}
		switch k.tag {
		case 0xa0:
			oid, _, err := algID(raw, inner[0])
			if err != nil {
				return 0, 0, false
			}
			var ok bool
			if h, ok = hashOIDs[oid]; !ok {
				return 0, 0, false
			}
		case 0xa1:
			oid, params, err := algID(raw, inner[0])
			if err != nil || oid != "1.2.840.113549.1.1.8" {
				return 0, 0, false
			}
			pe, err := readCertElem(params, 0, len(params), 0x30)
			if err != nil {
				return 0, 0, false
			}
			hoid, _, err := algID(params, pe)
			if err != nil {
				return 0, 0, false
			}
			var ok bool
			if mgfHash, ok = hashOIDs[hoid]; !ok {
				return 0, 0, false
			}
		case 0xa2, 0xa3:
			if inner[0].tag != 0x02 {
				return 0, 0, false
			}
			v := new(big.Int).SetBytes(raw[inner[0].start:inner[0].end])
			if !v.IsInt64() || v.Int64() > 1<<20 {
				return 0, 0, false
			}
			if k.tag == 0xa2 {
				salt = int(v.Int64())
			} else if v.Int64() != 1 {
				return 0, 0, false
			}
		default:
			return 0, 0, false
		}
	}
	return h, salt, mgfHash == h
}

// certSigOK is X509Certificate.verify(publicKey): the certificate's signature under the key (no name or role checks).
func certSigOK(child *attCert, k certKey) bool {
	if child.SigOID == "1.3.101.112" {
		pk, ok := k.pub.(ed25519.PublicKey)
		return ok && ed25519.Verify(pk, child.RawTBS, child.Signature)
	}
	if child.SigOID == "1.2.840.113549.1.1.10" {
		pk, ok := k.pub.(*rsa.PublicKey)
		h, salt, good := pssParams(child.SigParams)
		if !ok || !good || !h.Available() {
			return false
		}
		hh := h.New()
		hh.Write(child.RawTBS)
		return rsa.VerifyPSS(pk, h, hh.Sum(nil), child.Signature, &rsa.PSSOptions{SaltLength: salt}) == nil
	}
	h, known := sigHashes[child.SigOID]
	if !known || !h.Available() {
		return false
	}
	hh := h.New()
	hh.Write(child.RawTBS)
	digest := hh.Sum(nil)
	switch pk := k.pub.(type) {
	case *ecdsa.PublicKey:
		return strings.HasPrefix(child.SigOID, "1.2.840.10045.4.3.") && ecdsa.VerifyASN1(pk, digest, child.Signature)
	case *rsa.PublicKey:
		return strings.HasPrefix(child.SigOID, "1.2.840.113549.1.1.") && rsa.VerifyPKCS1v15(pk, h, digest, child.Signature) == nil
	}
	return false
}

// certSigOKBy is certSigOK under the subject key of parent (false when that key cannot be read).
func certSigOKBy(child, parent *attCert) bool {
	k, err := keyOfCert(parent)
	if err != nil {
		return false
	}
	return certSigOK(child, k)
}

// ───────────────────────────────────────────────────────────── extensions read by helpers (lenient: the strict readers judge the table)

func (c *attCert) extValue(oid string) ([]byte, bool) {
	for _, e := range c.exts {
		if e.oid == oid {
			return e.value, true
		}
	}
	return nil, false
}

// ocspServers are the OCSP responder URLs of the Authority Information Access extension.
func (c *attCert) ocspServers() []string {
	v, ok := c.extValue("1.3.6.1.5.5.7.1.1")
	if !ok {
		return nil
	}
	seq, err := readCertElem(v, 0, len(v), 0x30)
	if err != nil {
		return nil
	}
	descs, err := certKids(v, seq)
	if err != nil {
		return nil
	}
	var out []string
	for _, d := range descs {
		parts, err := certKids(v, d)
		if err != nil || len(parts) != 2 || parts[0].tag != 0x06 {
			continue
		}
		method, err := oidToDotted(v, derTlv{tag: parts[0].tag, start: parts[0].start, end: parts[0].end})
		if err != nil || method != "1.3.6.1.5.5.7.48.1" || parts[1].tag != 0x86 {
			continue
		}
		out = append(out, string(v[parts[1].start:parts[1].end]))
	}
	return out
}

// hasOCSPSigningEKU: the extended key usage extension lists id-kp-OCSPSigning.
func (c *attCert) hasOCSPSigningEKU() bool {
	v, ok := c.extValue("2.5.29.37")
	if !ok {
		return false
	}
	seq, err := readCertElem(v, 0, len(v), 0x30)
	if err != nil {
		return false
	}
	purposes, err := certKids(v, seq)
	if err != nil {
		return false
	}
	for _, p := range purposes {
		if oid, err := oidToDotted(v, derTlv{tag: p.tag, start: p.start, end: p.end}); err == nil && oid == "1.3.6.1.5.5.7.3.9" {
			return true
		}
	}
	return false
}
