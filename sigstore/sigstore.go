// Package pcasigstore verifies a Sigstore bundle offline (track K9) and turns its SLSA v1 provenance into the facts
// pca.ProvenanceGate checks. A port of packages/pca-attest-eat/src/sigstore.ts, judging every input as the reference does.
//
// Verifies a bundle (v0.2 / v0.3, keyless, a DSSE in-toto envelope) against a pinned trusted_root.json with no network: every
// RFC 3161 timestamp must verify and a Rekor v1 SET must verify when present (the time sources); one Rekor v1 dsse 0.0.1 /
// intoto 0.0.2 or Rekor v2 hashedrekord 0.0.2 entry with an RFC 9162 inclusion proof to a checkpoint signed by the pinned log;
// the certificate path to a pinned Fulcio CA at every verified time; the embedded SCT when the root lists CT logs; the entry
// body naming this envelope; the DSSE signature; the Fulcio identity extensions; the in-toto Statement.
//
// It is a separate module so that core pca-go users do not carry it. Certificates are read as node:crypto (OpenSSL) reads
// them (pca.NodeCert). Never panics: hostile input is a refusal with the reference's code.
package pcasigstore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	_ "crypto/sha512" // SHA-384 / SHA-512 for crypto.Hash
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	pca "github.com/Atlas-Authorization/pca-go"
)

var mediaTypes = []string{
	"application/vnd.dev.sigstore.bundle+json;version=0.2",
	"application/vnd.dev.sigstore.bundle+json;version=0.3",
	"application/vnd.dev.sigstore.bundle.v0.3+json",
}

const (
	inTotoPayloadType = "application/vnd.in-toto+json"
	oidFulcio         = "1.3.6.1.4.1.57264.1."
	oidSCTList        = "1.3.6.1.4.1.11129.2.4.2"
	oidSAN            = "2.5.29.17"
	oidEKU            = "2.5.29.37"
	oidAKI            = "2.5.29.35"
	oidSKI            = "2.5.29.14"
	ekuCodeSigning    = "1.3.6.1.5.5.7.3.3"
	ekuTimeStamping   = "1.3.6.1.5.5.7.3.8"
	oidSignedData     = "1.2.840.113549.1.7.2"
	oidTSTInfo        = "1.2.840.113549.1.9.16.1.4"
	oidContentType    = "1.2.840.113549.1.9.3"
	oidMessageDigest  = "1.2.840.113549.1.9.4"
	maxSafe           = 1<<53 - 1
	forever           = math.MaxInt64 // validFor without an end
)

var digestOIDs = map[string]crypto.Hash{"2.16.840.1.101.3.4.2.1": crypto.SHA256, "2.16.840.1.101.3.4.2.2": crypto.SHA384, "2.16.840.1.101.3.4.2.3": crypto.SHA512}

// Subject is one statement subject digest.
type Subject struct {
	Alg    string `json:"alg"`
	Digest string `json:"digest"`
}

// Timestamps counts the verified time sources.
type Timestamps struct {
	TSA int  `json:"tsa"`
	Set bool `json:"set"`
}

// Core is what a verified bundle establishes before any SLSA reading (the `core` of sigstore-vectors.json). A source
// extension that is present is reported even when empty.
type Core struct {
	Identity      string     `json:"identity"`
	OIDCIssuer    string     `json:"oidc_issuer"`
	SourceRepo    *string    `json:"source_repo,omitempty"`
	SourceRef     *string    `json:"source_ref,omitempty"`
	SourceDigest  *string    `json:"source_digest,omitempty"`
	PredicateType string     `json:"predicate_type"`
	Subjects      []Subject  `json:"subjects"`
	SignedTime    int64      `json:"signed_time"`
	RekorLogIndex int64      `json:"rekor_log_index"`
	Rekor         string     `json:"rekor"`
	Timestamps    Timestamps `json:"timestamps"`
}

// CoreResult is {OK, Core, Statement} or {Code, Detail}.
type CoreResult struct {
	OK        bool
	Core      Core
	Statement map[string]any
	Code      string
	Detail    string
}

// Result is {OK, Facts} (the facts member of a pca.ProvenanceGate input) or {Code, Detail}.
type Result struct {
	OK     bool
	Facts  map[string]any
	Code   string
	Detail string
}

// ------------------------------------------------------------------------------------------------ refusals

// thrown is a reference exception: the verifier turns it into a refusal under the current stage.
type thrown string

func throw(msg string) { panic(thrown(msg)) }

// catch runs f; a throw (or any runtime fault: the reference's TypeError on a missing member) becomes an error.
func catch(f func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if t, ok := r.(thrown); ok {
				err = fmt.Errorf("%s", string(t))
			} else {
				err = fmt.Errorf("%v", r)
			}
		}
	}()
	f()
	return nil
}

// ------------------------------------------------------------------------------------------------ JSON values

func obj(v any) map[string]any { m, _ := v.(map[string]any); return m }

func arr(v any) ([]any, bool) { a, ok := v.([]any); return a, ok }

var b64Re = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)

// b64 is the reference's base64 reader: a string of the standard alphabet, padded to a multiple of 4 (else it throws).
func b64(v any) []byte {
	s, ok := v.(string)
	if !ok || !b64Re.MatchString(s) || len(s)%4 != 0 {
		throw("not base64")
	}
	b, err := b64Decode(s)
	if err != nil {
		throw("not base64")
	}
	return b
}

var rfc3339Re = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$`)

// rfc3339 is an RFC 3339 date-time (upper-case T / Z, a real calendar date, as Date.parse reads it) in epoch ms.
func rfc3339(v string) (int64, bool) {
	m := rfc3339Re.FindStringSubmatch(v)
	if m == nil {
		return 0, false
	}
	n := func(s string) int { x, _ := strconv.Atoi(s); return x }
	y, mo, d, h, mi, s := n(m[1]), n(m[2]), n(m[3]), n(m[4]), n(m[5]), n(m[6])
	// Date.UTC maps years 0-99 to 1900-1999, so such a date never reads back as itself
	if y < 100 || mo < 1 || mo > 12 || d < 1 || d != time.Date(y, time.Month(mo), d, 0, 0, 0, 0, time.UTC).Day() {
		return 0, false
	}
	ms := 0
	if m[7] != "" {
		ms = n((m[7] + "00")[:3])
	}
	if mi > 59 || s > 59 || h > 24 || (h == 24 && (mi != 0 || s != 0 || strings.Trim(m[7], "0") != "")) { // 24:00:00 exactly
		return 0, false
	}
	off := 0
	if m[8] != "Z" {
		oh, om := n(m[8][1:3]), n(m[8][4:6])
		if oh > 23 || om > 59 {
			return 0, false
		}
		off = (oh*60 + om) * 60000
		if m[8][0] == '-' {
			off = -off
		}
	}
	return time.Date(y, time.Month(mo), d, h, mi, s, ms*1e6, time.UTC).UnixMilli() - int64(off), true
}

// ------------------------------------------------------------------------------------------------ trusted root

type validity struct{ start, end int64 }

func (v validity) has(at int64) bool { return v.start <= at && at <= v.end }

func readValidity(v any) validity {
	o := obj(v)
	s, ok := o["start"].(string)
	start, good := rfc3339(s)
	if !ok || !good {
		throw("validFor.start missing")
	}
	end := int64(forever)
	if e, ok := o["end"].(string); ok {
		if end, good = rfc3339(e); !good {
			throw("validFor.end malformed")
		}
	}
	return validity{start, end}
}

// PinnedLog is a pinned transparency or CT log. v2 logs (Ed25519, C2SP signed-note checkpoints) carry their note name: the host
// of their base URL.
type PinnedLog struct {
	keyID  []byte
	key    crypto.PublicKey
	valid  validity
	v2Name string
}

// PinnedCA is a pinned certificate authority or timestamp authority: its chain (leaf first) and validity.
type PinnedCA struct {
	chain []*pca.NodeCert
	raw   [][]byte
	valid validity
}

// PinnedRoots is a parsed trusted_root.json: transparency logs, CT logs, Fulcio CAs, timestamp authorities.
type PinnedRoots struct {
	tlogs, ctlogs []PinnedLog
	cas, tsas     []PinnedCA
}

// hostname is new URL(u).hostname for the http(s) base URLs a trusted root carries ("" when u is not such a URL).
func hostname(u string) string {
	// the URL parser drops tab / newline anywhere and C0 controls / space around the input
	u = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, u)
	u = strings.TrimFunc(u, func(r rune) bool { return r <= ' ' })
	_, rest, ok := strings.Cut(u, "://")
	if !ok {
		return ""
	}
	auth := rest
	if i := strings.IndexAny(auth, "/?#"); i >= 0 {
		auth = auth[:i]
	}
	if i := strings.LastIndexByte(auth, '@'); i >= 0 {
		auth = auth[i+1:]
	}
	host := auth
	if strings.HasPrefix(auth, "[") {
		// an unclosed IPv6 literal is "" (new URL throws); auth[0] is '[', so a ']' is never at index 0
		host = auth[:strings.IndexByte(auth, ']')+1]
	} else if i := strings.IndexByte(auth, ':'); i >= 0 {
		host = auth[:i]
	}
	return strings.ToLower(host)
}

func sha256Of(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// pinnedLog reads one log. ECDSA P-256 (Rekor v1, CT): id = SHA-256(SPKI DER). RSA PKCS#1 (CT only): id = SHA-256 of the SPKI
// form. Ed25519 (Rekor v2 only): id = SHA-256(name || 0x0A || 0x01 || key), the C2SP signed-note key hash. Another key type
// is skipped (nil); a root whose id disagrees with its key is malformed.
func pinnedLog(t any, transparency bool) *PinnedLog {
	to := obj(t)
	pk, lid := obj(to["publicKey"]), obj(to["logId"])
	if to == nil || pk == nil || lid == nil {
		throw("log entry malformed")
	}
	der := b64(pk["rawBytes"])
	keyID := b64(lid["keyId"])
	valid := readValidity(pk["validFor"])
	spki := func(der []byte) crypto.PublicKey {
		k, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			throw("Failed to read asymmetric key")
		}
		return k
	}
	switch pk["keyDetails"] {
	case "PKIX_ECDSA_P256_SHA_256":
		if !bytes.Equal(sha256Of(der), keyID) {
			throw("log id is not the SHA-256 of its key")
		}
		return &PinnedLog{keyID: keyID, key: spki(der), valid: valid}
	case "PKCS1_RSA_PKCS1V5":
		if transparency {
			return nil
		}
		k, err := x509.ParsePKCS1PublicKey(der)
		if err != nil {
			throw("Failed to read asymmetric key")
		}
		form, _ := x509.MarshalPKIXPublicKey(k)
		if !bytes.Equal(sha256Of(form), keyID) {
			throw("log id is not the SHA-256 of its key")
		}
		return &PinnedLog{keyID: keyID, key: k, valid: valid}
	case "PKIX_ED25519":
		if !transparency {
			return nil
		}
		k := spki(der)
		name := ""
		if u, ok := to["baseUrl"].(string); ok {
			name = hostname(u)
		}
		if name == "" || !bytes.Equal(sha256Of([]byte(name+"\n"), []byte{1}, der[len(der)-32:]), keyID) {
			throw("log id is not the signed-note key hash of its key")
		}
		return &PinnedLog{keyID: keyID, key: k, valid: valid, v2Name: name}
	}
	return nil
}

// fullCert is a certificate that is exactly one DER certificate.
func fullCert(der []byte) *pca.NodeCert {
	c, err := pca.ParseNodeCert(der)
	if err != nil {
		throw(err.Error())
	}
	if t := tlv(der, 0, len(der)); t.end != len(der) {
		throw("trailing bytes after the certificate")
	}
	return c
}

func pinnedChain(v any) PinnedCA {
	cc := obj(obj(v)["certChain"])
	certs, ok := arr(cc["certificates"]) // a missing certChain reads as an empty map: not ok
	if !ok || len(certs) == 0 {
		throw("certificate authority entry malformed")
	}
	ca := PinnedCA{}
	for _, x := range certs {
		der := b64(obj(x)["rawBytes"])
		ca.chain = append(ca.chain, fullCert(der))
		ca.raw = append(ca.raw, der)
	}
	ca.valid = readValidity(obj(v)["validFor"])
	return ca
}

// decodeOneJSON is JSON.parse: exactly one value. Decoder.More alone would accept a trailing `}` or `]`.
func decodeOneJSON(b []byte) (any, bool) {
	var v any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if d.Decode(&v) != nil {
		return nil, false
	}
	_, err := d.Token()
	return v, err == io.EOF
}

// ParseTrustedRoot parses a Sigstore trusted_root.json (application/vnd.dev.sigstore.trustedroot+json;version=0.1). A root with
// no CT log means its owner does not require SCTs; otherwise an SCT from a pinned CT log is required.
func ParseTrustedRoot(js []byte) (r *PinnedRoots, err error) {
	v, isJSON := decodeOneJSON(js)
	if !isJSON {
		return nil, fmt.Errorf("not a trusted root v0.1")
	}
	err = catch(func() { r = parseTrustedRoot(v) })
	if err != nil {
		return nil, err
	}
	return r, nil
}

func parseTrustedRoot(v any) *PinnedRoots {
	o := obj(v)
	if o == nil || o["mediaType"] != "application/vnd.dev.sigstore.trustedroot+json;version=0.1" {
		throw("not a trusted root v0.1")
	}
	list := func(k string) []any { a, _ := arr(o[k]); return a }
	r := &PinnedRoots{}
	for _, t := range list("tlogs") {
		if l := pinnedLog(t, true); l != nil {
			r.tlogs = append(r.tlogs, *l)
		}
	}
	for _, t := range list("ctlogs") {
		if l := pinnedLog(t, false); l != nil {
			r.ctlogs = append(r.ctlogs, *l)
		}
	}
	for _, c := range list("certificateAuthorities") {
		r.cas = append(r.cas, pinnedChain(c))
	}
	for _, c := range list("timestampAuthorities") {
		r.tsas = append(r.tsas, pinnedChain(c))
	}
	if len(r.tlogs) == 0 || len(r.cas) == 0 {
		throw("a trusted root needs a transparency log and a CA")
	}
	return r
}

// ------------------------------------------------------------------------------------------------ DER

type tlvT struct{ tag, start, body, end int }

func tlv(b []byte, off, limit int) tlvT {
	if off+2 > limit {
		throw("DER truncated")
	}
	tag := int(b[off])
	if tag&0x1f == 0x1f {
		throw("DER multi-byte tag")
	}
	n, body := int(b[off+1]), off+2
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 4 || body+k > limit {
			throw("DER length")
		}
		n = 0
		for i := 0; i < k; i++ {
			n = n*256 + int(b[body+i])
		}
		body += k
	}
	if body+n > limit {
		throw("DER overrun")
	}
	return tlvT{tag, off, body, body + n}
}

func kids(b []byte, t tlvT) []tlvT {
	var out []tlvT
	for o := t.body; o < t.end; {
		c := tlv(b, o, t.end)
		out = append(out, c)
		o = c.end
	}
	return out
}

// oidText renders an OID as the reference does (arcs as JavaScript numbers).
func oidText(b []byte, t tlvT) string {
	if t.tag != 0x06 || t.end <= t.body {
		throw("not an OID")
	}
	var parts []float64
	v := 0.0
	for i := t.body; i < t.end; i++ {
		if b[i] == 0x80 && (i == t.body || b[i-1]&0x80 == 0) {
			throw("OID arc is not minimally encoded")
		}
		v = v*128 + float64(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			parts = append(parts, v)
			v = 0
		}
	}
	if b[t.end-1]&0x80 != 0 {
		throw("OID ends inside an arc")
	}
	a := math.Min(2, math.Floor(parts[0]/40))
	out := []string{jsNum(a), jsNum(parts[0] - a*40)}
	for _, p := range parts[1:] {
		out = append(out, jsNum(p))
	}
	return strings.Join(out, ".")
}

// jsNum is ECMAScript Number::toString (String(-0) is "0").
func jsNum(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 0):
		return map[bool]string{false: "Infinity", true: "-Infinity"}[f < 0]
	case f == 0:
		return "0"
	case f < 0:
		return "-" + jsNum(-f)
	}
	mant, expS, _ := strings.Cut(strconv.FormatFloat(f, 'e', -1, 64), "e") // shortest round-trip digits
	digits := strings.Replace(mant, ".", "", 1)
	x, _ := strconv.Atoi(expS)
	k, n := len(digits), x+1
	switch {
	case k <= n && n <= 21:
		return digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		return digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		return "0." + strings.Repeat("0", -n) + digits
	}
	e := fmt.Sprintf("e%+d", n-1)
	if k == 1 {
		return digits + e
	}
	return digits[:1] + "." + digits[1:] + e
}

// jsStr is ECMAScript String(o[k]) over a decoded JSON object: "undefined" when missing, "null", the boolean, the string,
// Number::toString, an array joined with "," (null elements empty), "[object Object]".
func jsStr(o map[string]any, k string) string {
	v, ok := o[k]
	if !ok {
		return "undefined"
	}
	return jsVal(v)
}

func jsVal(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case string:
		return x
	case json.Number:
		f, _ := strconv.ParseFloat(string(x), 64) // out of range is +-Inf, as JSON.parse
		return jsNum(f)
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			if e != nil {
				parts[i] = jsVal(e)
			}
		}
		return strings.Join(parts, ",")
	case map[string]any:
		return "[object Object]"
	}
	return fmt.Sprint(v) // bool
}

// enc is a DER TLV with the reference's length encoding.
func enc(tag byte, content []byte) []byte {
	n := len(content)
	var l []byte
	switch {
	case n < 0x80:
		l = []byte{byte(n)}
	case n < 0x100:
		l = []byte{0x81, byte(n)}
	case n < 0x10000:
		l = []byte{0x82, byte(n >> 8), byte(n)}
	default:
		l = []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return append(append([]byte{tag}, l...), content...)
}

type ext struct {
	oid   string
	value []byte
	t     tlvT
}

type parsedCert struct {
	der         []byte
	tbsKids     []tlvT
	extsWrapper tlvT
	exts        []ext
}

func parseCert(der []byte) *parsedCert {
	cert := tlv(der, 0, len(der))
	if cert.tag != 0x30 || cert.end != len(der) {
		throw("certificate is not one SEQUENCE")
	}
	ck := kids(der, cert)
	if len(ck) == 0 || ck[0].tag != 0x30 {
		throw("no TBSCertificate")
	}
	pc := &parsedCert{der: der, tbsKids: kids(der, ck[0])}
	found := false
	for _, k := range pc.tbsKids {
		if k.tag == 0xa3 {
			pc.extsWrapper, found = k, true
			break
		}
	}
	if !found {
		throw("no extensions")
	}
	seq := kids(der, pc.extsWrapper)
	if len(seq) == 0 || seq[0].tag != 0x30 {
		throw("extensions malformed")
	}
	seen := map[string]bool{}
	for _, e := range kids(der, seq[0]) {
		parts := kids(der, e)
		oct := parts[len(parts)-1]
		if oct.tag != 0x04 {
			throw("extension value is not an OCTET STRING")
		}
		x := ext{oid: oidText(der, parts[0]), value: der[oct.body:oct.end], t: e}
		pc.exts = append(pc.exts, x)
	}
	for _, x := range pc.exts {
		if seen[x.oid] {
			throw("duplicate extension " + x.oid)
		}
		seen[x.oid] = true
	}
	return pc
}

func (c *parsedCert) ext(oid string) *ext {
	for i := range c.exts {
		if c.exts[i].oid == oid {
			return &c.exts[i]
		}
	}
	return nil
}

// hasEKU is X509Certificate.keyUsage (the extended key usages) including eku; false when absent or unreadable.
func hasEKU(der []byte, eku string) (has bool) {
	_ = catch(func() {
		e := parseCert(der).ext(oidEKU)
		if e == nil {
			return
		}
		for _, o := range kids(e.value, tlv(e.value, 0, len(e.value))) {
			if oidText(e.value, o) == eku {
				has = true
			}
		}
	})
	return has
}

// basicConstraintsCA: basicConstraints (2.5.29.19) says cA TRUE (a leaf must not claim it, whatever keyUsage says).
func (c *parsedCert) basicConstraintsCA() bool {
	e := c.ext("2.5.29.19")
	if e == nil {
		return false
	}
	sq := tlv(e.value, 0, len(e.value))
	if sq.tag != 0x30 {
		return false
	}
	k := kids(e.value, sq)
	return len(k) > 0 && k[0].tag == 0x01 && k[0].end-k[0].body == 1 && e.value[k[0].body] != 0
}

// utf8Strict is TextDecoder('utf-8', {fatal: true}): a malformed sequence throws, a leading BOM is dropped.
func utf8Strict(b []byte) string {
	if !utf8.Valid(b) {
		throw("The encoded data was not valid for encoding utf-8")
	}
	return strings.TrimPrefix(string(b), "\uFEFF")
}

// fulcioExt is extension 1.3.6.1.4.1.57264.1.n: raw UTF-8 for n <= 6, a DER UTF8String for n >= 8 (fulcio docs/oid-info.md).
func fulcioExt(c *parsedCert, n int) *string {
	e := c.ext(oidFulcio + strconv.Itoa(n))
	if e == nil {
		return nil
	}
	if n <= 6 {
		s := utf8Strict(e.value)
		return &s
	}
	t := tlv(e.value, 0, len(e.value))
	if t.tag != 0x0c || t.end != len(e.value) {
		throw(fmt.Sprintf("extension .1.%d is not a DER UTF8String", n))
	}
	s := utf8Strict(e.value[t.body:t.end])
	return &s
}

// sanIdentity: exactly one SAN, a URI or an email; anything else (OtherName, several names) is refused.
func sanIdentity(c *parsedCert) string {
	e := c.ext(oidSAN)
	if e == nil {
		throw("no subjectAltName")
	}
	seq := tlv(e.value, 0, len(e.value))
	names := kids(e.value, seq)
	if seq.tag != 0x30 || len(names) != 1 {
		throw("subjectAltName must hold exactly one name")
	}
	n := names[0]
	if n.tag != 0x86 && n.tag != 0x81 {
		throw("subjectAltName must be a URI or an email")
	}
	return utf8Strict(e.value[n.body:n.end])
}

// ------------------------------------------------------------------------------------------------ certificates

// keyIDsMatch is X509_check_issued's key-identifier rule: when c names an authority key id and up has a subject key id, they
// must be equal, and neither extension may be undecodable (OpenSSL then marks the certificate invalid). An AKI without a key id
// has nothing to compare here.
func keyIDsMatch(c, up []byte) (ok bool) {
	err := catch(func() {
		var aki, ski *ext
		if p, err := parsedOrNil(c); err == nil {
			aki = p.ext(oidAKI)
		}
		upCert, upErr := parsedOrNil(up)
		if upErr == nil {
			ski = upCert.ext(oidSKI)
		}
		var skid []byte
		if ski != nil {
			sk := tlv(ski.value, 0, len(ski.value))
			if sk.tag != 0x04 || sk.end != len(ski.value) {
				return
			}
			skid = ski.value[sk.body:sk.end]
		}
		if aki == nil {
			ok = true
			return
		}
		seq := tlv(aki.value, 0, len(aki.value))
		if seq.tag != 0x30 || seq.end != len(aki.value) {
			return
		}
		last := -1
		for _, k := range kids(aki.value, seq) {
			i := slices.Index([]int{0x80, 0xa1, 0x82}, k.tag)
			if i <= last {
				return
			}
			last = i
			body := aki.value[k.body:k.end]
			switch {
			case i == 0 && ski != nil && !bytes.Equal(body, skid):
				return
			case i == 1 && upErr == nil && !akiNamesIssuerOf(aki.value, k, upCert):
				return
			case i == 2 && upErr == nil && !bytes.Equal(body, upCert.tbsField(0)):
				return
			}
		}
		ok = true
	})
	return err == nil && ok
}

// tbsField is the content of the i-th TBSCertificate member after the optional version; i 2 (the issuer) includes its header.
func (c *parsedCert) tbsField(i int) []byte {
	if c.tbsKids[0].tag == 0xa0 {
		i++
	}
	k := c.tbsKids[i]
	if k.tag == 0x30 {
		return c.der[k.start:k.end]
	}
	return c.der[k.body:k.end]
}

// akiNamesIssuerOf: the first directoryName of an AKI's authorityCertIssuer, if any, is up's own issuer (X509_check_akid).
func akiNamesIssuerOf(v []byte, gens tlvT, up *parsedCert) bool {
	for _, n := range kids(v, gens) {
		if n.tag == 0xa4 {
			return bytes.Equal(v[n.body:n.end], up.tbsField(2))
		}
	}
	return true
}

func parsedOrNil(der []byte) (p *parsedCert, err error) {
	err = catch(func() { p = parseCert(der) })
	return p, err
}

// checkIssued is X509Certificate.checkIssued. NodeCert.CheckIssued reads every certificate node:crypto reads, also an issuer parseCert
// refuses, which keyIDsMatch does not compare against.
func checkIssued(c *pca.NodeCert, cRaw []byte, up *pca.NodeCert, upRaw []byte) bool {
	return c.CheckIssued(up) && keyIDsMatch(cRaw, upRaw) && sanDecodes(cRaw) && sanDecodes(upRaw)
}

// sanDecodes: an absent subjectAltName, or one that is exactly a SEQUENCE of well-formed elements (GeneralNames).
func sanDecodes(der []byte) bool {
	p, err := parsedOrNil(der)
	if err != nil {
		return true // judged by the reader that refused it
	}
	e := p.ext(oidSAN)
	return e == nil || catch(func() {
		t := tlv(e.value, 0, len(e.value))
		if t.tag != 0x30 || t.end != len(e.value) {
			throw("subjectAltName is not one SEQUENCE")
		}
		for _, n := range kids(e.value, t) {
			if !slices.Contains([]int{0xa0, 0x81, 0x82, 0xa3, 0xa4, 0xa5, 0x86, 0x87, 0x88}, n.tag) {
				throw("subjectAltName entry is not a GeneralName")
			}
		}
	}) == nil
}

// chainOK: the chain (leaf first, self-signed root last): issuer links, signatures, CA flags; every certificate valid at at.
func chainOK(ca *PinnedCA, at int64) bool {
	for i, c := range ca.chain {
		j := min(i+1, len(ca.chain)-1)
		if !checkIssued(c, ca.raw[i], ca.chain[j], ca.raw[j]) || !c.SignedBy(ca.chain[j]) || !c.ValidAt(at) || (i > 0 && !c.CA()) {
			return false
		}
	}
	return true
}

// nodeVerify is crypto.verify(alg, msg, key, sig): ECDSA (DER signature) and RSA PKCS#1 v1.5 under alg, Ed25519 with no alg
// (alg 0 on another key type is node's default, SHA-256).
func nodeVerify(alg crypto.Hash, msg []byte, key crypto.PublicKey, sig []byte) bool {
	if k, ok := key.(ed25519.PublicKey); ok {
		return alg == 0 && ed25519.Verify(k, msg, sig)
	}
	if alg == 0 {
		alg = crypto.SHA256
	}
	h := alg.New()
	h.Write(msg)
	d := h.Sum(nil)
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(k, d, sig)
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, alg, d, sig) == nil
	}
	return false
}

func digest(alg crypto.Hash, b []byte) []byte {
	h := alg.New()
	h.Write(b)
	return h.Sum(nil)
}

// ------------------------------------------------------------------------------------------------ SCT (RFC 6962 3.2)

func verifySCT(leaf *parsedCert, issuer *pca.NodeCert, roots *PinnedRoots) string {
	e := leaf.ext(oidSCTList)
	if e == nil {
		return "no embedded SCT"
	}
	outer := tlv(e.value, 0, len(e.value))
	if outer.tag != 0x04 {
		return "SCT list is not an OCTET STRING"
	}
	list := e.value[outer.body:outer.end]
	if len(list) < 2 || int(binary.BigEndian.Uint16(list)) != len(list)-2 {
		return "SCT list length"
	}
	// the precertificate TBS: the leaf TBS without the SCT list extension
	der := leaf.der
	var kept, tbsBody []byte
	for _, k := range kids(der, kids(der, leaf.extsWrapper)[0]) {
		if k.start != e.t.start {
			kept = append(kept, der[k.start:k.end]...)
		}
	}
	for _, k := range leaf.tbsKids {
		if k == leaf.extsWrapper {
			tbsBody = append(tbsBody, enc(0xa3, enc(0x30, kept))...)
		} else {
			tbsBody = append(tbsBody, der[k.start:k.end]...)
		}
	}
	tbs := enc(0x30, tbsBody)
	issuerKeyHash := sha256Of(issuer.SPKI())
	why := "no SCT from a pinned CT log"
	u16 := func(b []byte, i int) int { return int(b[i])<<8 | int(b[i+1]) }
	clip := func(b []byte, from, to int) []byte { return b[min(from, len(b)):min(to, len(b))] }
	for o := 2; o < len(list); {
		if o+2 > len(list) {
			return "SCT truncated"
		}
		n := u16(list, o)
		s := clip(list, o+2, o+2+n)
		o += 2 + n
		if len(s) != n || n < 47 {
			return "SCT truncated"
		}
		if s[0] != 0 {
			continue
		}
		logID := s[1:33]
		ts := binary.BigEndian.Uint64(s[33:])
		extLen := u16(s, 41)
		ex := clip(s, 43, 43+extLen)
		p := 43 + extLen
		if p+4 > len(s) {
			return "SCT truncated"
		}
		hashAlg, sigAlg, sigLen := s[p], s[p+1], u16(s, p+2)
		sig := clip(s, p+4, p+4+sigLen)
		p += 4 + sigLen
		if p != len(s) || len(sig) != sigLen {
			return "SCT malformed"
		}
		var log *PinnedLog
		for i := range roots.ctlogs {
			if bytes.Equal(roots.ctlogs[i].keyID, logID) {
				log = &roots.ctlogs[i]
				break
			}
		}
		if log == nil {
			continue
		}
		if hashAlg != 4 || (sigAlg != 3 && sigAlg != 1) {
			why = "SCT is not SHA-256 with ECDSA or RSA"
			continue
		}
		// exact 64-bit read; past 2^53-1 the reference's Number would round
		if ts > maxSafe {
			why = "SCT timestamp out of range"
			continue
		}
		if !log.valid.has(int64(ts)) {
			why = "SCT log key not valid at its timestamp"
			continue
		}
		signed := []byte{0, 0}
		signed = binary.BigEndian.AppendUint64(signed, ts)
		signed = append(signed, 0, 1)
		signed = append(signed, issuerKeyHash...)
		signed = append(signed, byte(len(tbs)>>16), byte(len(tbs)>>8), byte(len(tbs)))
		signed = append(signed, tbs...)
		signed = append(signed, byte(len(ex)>>8), byte(len(ex)))
		signed = append(signed, ex...)
		if nodeVerify(crypto.SHA256, signed, log.key, sig) {
			return ""
		}
		why = "SCT signature invalid"
	}
	return why
}

// ------------------------------------------------------------------------------------------------ RFC 3161 timestamps

func digestOf(b []byte, t tlvT) crypto.Hash {
	h, ok := digestOIDs[oidText(b, kids(b, t)[0])]
	if !ok {
		throw("unsupported digest algorithm")
	}
	return h
}

var genTimeRe = regexp.MustCompile(`^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d{1,9}))?Z$`)

func generalizedTime(b []byte, t tlvT) int64 {
	if t.tag != 0x18 {
		throw("genTime is not a GeneralizedTime")
	}
	m := genTimeRe.FindStringSubmatch(string(b[t.body:t.end]))
	if m == nil {
		throw("genTime malformed")
	}
	n := func(s string) int { x, _ := strconv.Atoi(s); return x }
	y, mo, d, h, mi, s := n(m[1]), n(m[2]), n(m[3]), n(m[4]), n(m[5]), n(m[6])
	at := time.Date(y, time.Month(mo), d, h, mi, s, 0, time.UTC)
	// an impossible date (Feb 30, hour 24) would roll over in Date.UTC (and years 0-99 read as 19xx): refuse it
	if y < 100 || at.Year() != y || int(at.Month()) != mo || at.Day() != d || at.Hour() != h || at.Minute() != mi || at.Second() != s {
		throw("genTime is not a real date")
	}
	ms := 0
	if m[7] != "" {
		ms = n((m[7] + "00")[:3]) // exact truncation to ms
	}
	return at.UnixMilli() + int64(ms)
}

// VerifyRFC3161 verifies an RFC 3161 TimeStampResp (or bare TimeStampToken) over data (the raw signature bytes, client spec
// 4.2.1) against the pinned timestamp authorities: CMS SignedData with TSTInfo content, messageImprint the hash of data, signed
// attributes carrying the content type and the digest of the TSTInfo, the signature over the DER SET of signed attributes under
// the leaf of a pinned authority whose chain (and validFor) is valid at genTime, with the timeStamping EKU. Returns genTime (ms).
func (r *PinnedRoots) VerifyRFC3161(token, data []byte) (ms int64, err error) {
	err = catch(func() { ms = verifyRFC3161(token, data, r.tsas) })
	return ms, err
}

func verifyRFC3161(token, data []byte, tsas []PinnedCA) int64 {
	ci := tlv(token, 0, len(token))
	if ci.end != len(token) || ci.tag != 0x30 {
		throw("timestamp is not one SEQUENCE")
	}
	parts := kids(token, ci)
	if len(parts) > 0 && parts[0].tag == 0x30 && parts[0].end-parts[0].body >= 3 && token[kids(token, parts[0])[0].start] == 0x02 {
		// TimeStampResp: status (granted 0 or grantedWithMods 1), then the token
		st := kids(token, parts[0])[0]
		status := token[st.body:st.end]
		if !(len(status) == 1 && (status[0] == 0 || status[0] == 1)) {
			throw("timestamp status is not granted")
		}
		if len(parts) < 2 {
			throw("no timeStampToken")
		}
		ci = parts[1]
		parts = kids(token, ci)
	}
	if oidText(token, parts[0]) != oidSignedData || len(parts) < 2 || parts[1].tag != 0xa0 {
		throw("not CMS SignedData")
	}
	sd := kids(token, parts[1])[0]
	sdk := kids(token, sd)
	encap := -1
	for i, k := range sdk {
		if i > 1 && k.tag == 0x30 {
			encap = i
			break
		}
	}
	ek := kids(token, sdk[encap])
	if oidText(token, ek[0]) != oidTSTInfo || len(ek) < 2 || ek[1].tag != 0xa0 {
		throw("content is not TSTInfo")
	}
	octet := kids(token, ek[1])[0]
	if octet.tag != 0x04 {
		throw("TSTInfo is not an OCTET STRING")
	}
	tstBytes := token[octet.body:octet.end]
	tk := kids(tstBytes, tlv(tstBytes, 0, len(tstBytes)))
	mi := kids(tstBytes, tk[2])
	miAlg := digestOf(tstBytes, mi[0])
	if !bytes.Equal(digest(miAlg, data), tstBytes[mi[1].body:mi[1].end]) {
		throw("messageImprint is not the hash of the signature")
	}
	genTime := generalizedTime(tstBytes, tk[4])
	signerInfos := sdk[len(sdk)-1]
	if signerInfos.tag != 0x31 {
		throw("no signerInfos")
	}
	sis := kids(token, signerInfos)
	if len(sis) != 1 {
		throw("exactly one SignerInfo is required")
	}
	si := kids(token, sis[0])
	dAlg := digestOf(token, si[2])
	attrs := si[3]
	if attrs.tag != 0xa0 {
		throw("signed attributes are required")
	}
	ctOK, mdOK := false, false
	for _, a := range kids(token, attrs) {
		ak := kids(token, a)
		vals := kids(token, ak[1])
		o := oidText(token, ak[0])
		if len(vals) != 1 {
			throw("an attribute must have one value")
		}
		if o == oidContentType {
			ctOK = oidText(token, vals[0]) == oidTSTInfo
		}
		if o == oidMessageDigest {
			mdOK = bytes.Equal(digest(dAlg, tstBytes), token[vals[0].body:vals[0].end])
		}
	}
	if !ctOK || !mdOK {
		throw("signed attributes do not commit to the TSTInfo")
	}
	signedAttrs := append([]byte{0x31}, token[attrs.start+1:attrs.end]...)
	sigT := si[5]
	if sigT.tag != 0x04 {
		throw("signature is not an OCTET STRING")
	}
	sig := token[sigT.body:sigT.end]
	for i := range tsas {
		tsa := &tsas[i]
		if !tsa.valid.has(genTime) || !hasEKU(tsa.raw[0], ekuTimeStamping) {
			continue
		}
		k, err := tsa.chain[0].PublicKey()
		if err != nil {
			throw(err.Error())
		}
		if !nodeVerify(dAlg, signedAttrs, k, sig) || !chainOK(tsa, genTime) {
			continue
		}
		return genTime
	}
	panic(thrown("no pinned timestamp authority signed it (valid at its time)"))
}

// ------------------------------------------------------------------------------------------------ Rekor

// isJSSpace is \s in a JavaScript regular expression.
func isJSSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

var sigB64Re = regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)

// verifyCheckpoint checks a signed-note checkpoint: origin, size and base64 root lines, a blank line, then
// "— <name> <base64(keyhint4 || sig)>" lines. Rekor v1: the hint is the first 4 bytes of the log id, ECDSA over the body.
// Rekor v2: the line must carry the log's note name, Ed25519 over the body. Witness co-signatures are ignored.
func verifyCheckpoint(text string, log *PinnedLog, size int64, root []byte) string {
	cut := strings.Index(text, "\n\n")
	if cut < 0 {
		return "checkpoint has no signature block"
	}
	body := text[:cut+1]
	lines := strings.Split(body, "\n")
	if len(lines) < 4 || lines[0] == "" {
		return "checkpoint body too short or without an origin"
	}
	// lines[1] is never empty (the body holds no blank line before its last newline): checked anyway, never indexed blind
	if lines[1] == "" || lines[1][0] == '0' || strings.Trim(lines[1], "0123456789") != "" || lines[1] != strconv.FormatInt(size, 10) {
		return "checkpoint size differs from the proof"
	}
	if !bytes.Equal(b64(lines[2]), root) {
		return "checkpoint root differs from the proof"
	}
	for _, l := range strings.Split(text[cut+2:], "\n") {
		rest, ok := strings.CutPrefix(l, "— ")
		name, sig64, ok2 := strings.Cut(rest, " ")
		if !ok || !ok2 || name == "" || strings.IndexFunc(name, isJSSpace) >= 0 || !sigB64Re.MatchString(sig64) {
			continue
		}
		raw := b64(sig64)
		if len(raw) < 5 || !bytes.Equal(raw[:4], log.keyID[:4]) {
			continue
		}
		if log.v2Name != "" && name != log.v2Name {
			continue
		}
		// alg 0: Ed25519 (Rekor v2) takes no digest, ECDSA (Rekor v1) defaults to SHA-256
		if nodeVerify(0, []byte(body), log.key, raw[4:]) {
			return ""
		}
	}
	return "no checkpoint signature by the pinned log key"
}

var decIntRe = regexp.MustCompile(`^(0|[1-9][0-9]{0,15})$`)

func decInt(v any) int64 {
	s, ok := v.(string)
	if !ok || !decIntRe.MatchString(s) {
		throw("not a decimal integer string")
	}
	n, _ := strconv.ParseInt(s, 10, 64)
	if n > maxSafe {
		throw("integer out of range")
	}
	return n
}

// DSSEPAE is the DSSE pre-authentication encoding (secure-systems-lab/dsse protocol.md).
func DSSEPAE(payloadType string, payload []byte) []byte {
	return append([]byte(fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))), payload...)
}

func leafHashAlg(k crypto.PublicKey) crypto.Hash {
	if e, ok := k.(*ecdsa.PublicKey); ok {
		switch e.Curve {
		case elliptic.P256():
			return crypto.SHA256
		case elliptic.P384():
			return crypto.SHA384
		}
	}
	return 0
}

var pemRe = regexp.MustCompile(`^-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)-----END CERTIFICATE-----\n?$`)

func pemDer(pem []byte) []byte {
	m := pemRe.FindSubmatch(pem)
	if m == nil {
		return nil
	}
	return b64(strings.ReplaceAll(string(m[1]), "\n", ""))
}

// ------------------------------------------------------------------------------------------------ the verifier

// VerifySigstoreBundleCore verifies a Sigstore bundle (JSON bytes) carrying a DSSE in-toto statement against the pinned roots.
// Never panics; every refusal has the reference's code. Supports Rekor v1 dsse 0.0.1 and intoto 0.0.2 entries and Rekor v2
// hashedrekord 0.0.2 entries, RFC 3161 timestamps and the Rekor v1 SET as time sources.
func VerifySigstoreBundleCore(bundleJSON []byte, roots *PinnedRoots) (res CoreResult) {
	if roots == nil {
		return CoreResult{Code: "malformed", Detail: "no trusted root"}
	}
	v, isJSON := decodeOneJSON(bundleJSON)
	if !isJSON {
		return CoreResult{Code: "malformed", Detail: "not a bundle"}
	}
	stage := "malformed"
	if err := catch(func() { res = verifyCore(v, roots, &stage) }); err != nil {
		return CoreResult{Code: stage, Detail: "fail closed: " + err.Error()}
	}
	return res
}

// pinnedIssuer is the leaf of the first pinned CA that issued the certificate and is valid at every signing time (nil: none).
func pinnedIssuer(leaf *pca.NodeCert, leafDer []byte, times []int64, o *PinnedRoots) *pca.NodeCert {
	for i := range o.cas {
		ca := &o.cas[i]
		good := checkIssued(leaf, leafDer, ca.chain[0], ca.raw[0]) && leaf.SignedBy(ca.chain[0])
		for _, at := range times {
			good = good && ca.valid.has(at) && chainOK(ca, at)
		}
		for _, c := range ca.chain {
			good = good && c.CA()
		}
		if good {
			return ca.chain[0]
		}
	}
	return nil
}

// stageFault is a test seam: it lets a test raise a fault at a named point of verifyCore, to check the stage the fault is
// reported under. Always nil in production.
var stageFault func(site string)

func faultAt(site string) {
	if stageFault != nil {
		stageFault(site)
	}
}

func verifyCore(bundle any, o *PinnedRoots, stage *string) CoreResult {
	no := func(code, detail string) CoreResult { return CoreResult{Code: code, Detail: detail} }
	b := obj(bundle)
	vm := obj(b["verificationMaterial"])
	if b == nil || vm == nil {
		return no("malformed", "not a bundle")
	}
	mt, _ := b["mediaType"].(string)
	known := false
	for _, m := range mediaTypes {
		known = known || b["mediaType"] == m
	}
	if !known {
		return no("media_type", "unsupported media type "+jsStr(b, "mediaType"))
	}
	// keyless only: v0.3 carries `certificate`, v0.2 `x509CertificateChain` (the leaf first; intermediates are ignored)
	var certRaw any
	hasCert := false
	if mt != mediaTypes[0] {
		certRaw, hasCert = obj(vm["certificate"])["rawBytes"]
	} else if certs, ok := arr(obj(vm["x509CertificateChain"])["certificates"]); ok && len(certs) > 0 && obj(certs[0]) != nil {
		certRaw, hasCert = obj(certs[0])["rawBytes"]
	}
	if !hasCert {
		return no("not_keyless", "no Fulcio certificate (public-key bundles are not supported)")
	}
	env := obj(b["dsseEnvelope"])
	if _, ms := b["messageSignature"]; env == nil || ms {
		return no("envelope", "not a DSSE bundle")
	}
	if env["payloadType"] != inTotoPayloadType {
		return no("envelope", "payloadType is not application/vnd.in-toto+json")
	}
	sigs, ok := arr(env["signatures"])
	if !ok || len(sigs) != 1 || obj(sigs[0]) == nil {
		return no("envelope", "a DSSE envelope must carry exactly one signature")
	}
	payload := b64(env["payload"])
	dsseSig := b64(obj(sigs[0])["sig"])
	pae := DSSEPAE(inTotoPayloadType, payload)
	*stage = "cert_parse"
	leafDer := b64(certRaw)
	leaf := fullCert(leafDer)
	pc := parseCert(leafDer)
	leafKey, err := leaf.PublicKey()
	if err != nil {
		throw(err.Error())
	}
	alg := leafHashAlg(leafKey)

	// ---- the log entry and its log
	*stage = "tlog_count"
	faultAt("tlog_count")
	entries, ok := arr(vm["tlogEntries"])
	if !ok || len(entries) != 1 || obj(entries[0]) == nil {
		return no("tlog_count", "exactly one transparency log entry is required")
	}
	t := obj(entries[0])
	*stage = "tlog_kind"
	faultAt("tlog_kind")
	kv := ""
	k := obj(t["kindVersion"])
	kind, ok1 := k["kind"].(string)
	ver, ok2 := k["version"].(string)
	if ok1 && ok2 {
		kv = kind + "/" + ver
	}
	if kv != "dsse/0.0.1" && kv != "intoto/0.0.2" && kv != "hashedrekord/0.0.2" {
		return no("tlog_kind", "unsupported entry "+kv)
	}
	v2 := kv == "hashedrekord/0.0.2"
	*stage = "tlog_key"
	keyID := b64(obj(t["logId"])["keyId"])
	var log *PinnedLog
	for i := range o.tlogs {
		if bytes.Equal(o.tlogs[i].keyID, keyID) {
			log = &o.tlogs[i]
			break
		}
	}
	if log == nil {
		return no("tlog_key", "the entry names a log the verifier did not pin")
	}
	if v2 != (log.v2Name != "") {
		return no("tlog_key", "the entry type does not match the log version")
	}
	logIndex := decInt(t["logIndex"])
	body := b64(t["canonicalizedBody"])

	// ---- time first (client spec 4.2): every RFC 3161 timestamp must verify; a Rekor v1 SET must verify when present
	*stage = "tsa"
	var times []int64
	tsList, _ := arr(obj(vm["timestampVerificationData"])["rfc3161Timestamps"])
	for _, ts := range tsList {
		times = append(times, verifyRFC3161(b64(obj(ts)["signedTimestamp"]), dsseSig, o.tsas))
	}
	tsaCount := len(times)
	set := false
	if ip := obj(t["inclusionPromise"]); !v2 && ip != nil {
		*stage = "tlog_set"
		integrated := decInt(t["integratedTime"])
		msg := fmt.Sprintf(`{"body":"%s","integratedTime":%d,"logID":"%s","logIndex":%d}`, t["canonicalizedBody"], integrated, hex.EncodeToString(keyID), logIndex)
		if !nodeVerify(crypto.SHA256, []byte(msg), log.key, b64(ip["signedEntryTimestamp"])) {
			return no("tlog_set", "signed entry timestamp invalid")
		}
		times = append(times, int64(float64(integrated)*1000)) // a JavaScript Number product, as the reference computes it
		set = true
	}
	if len(times) == 0 {
		return no("no_verified_time", "no verified time: no RFC 3161 timestamp and no Rekor v1 signed entry timestamp")
	}
	for _, at := range times {
		if !log.valid.has(at) {
			return no("tlog_key", "the log key was not valid at a signing time")
		}
	}

	// ---- inclusion
	*stage = "tlog_inclusion"
	ip := obj(t["inclusionProof"])
	hashes, ok := arr(ip["hashes"])
	cp := obj(ip["checkpoint"])
	if ip == nil || !ok || cp == nil {
		return no("tlog_inclusion", "no inclusion proof")
	}
	root := b64(ip["rootHash"])
	size := decInt(ip["treeSize"])
	proofIndex := decInt(ip["logIndex"])
	proof := make([][]byte, len(hashes))
	for i, h := range hashes {
		proof[i] = b64(h)
	}
	if !pca.VerifyRFC9162Inclusion(pca.RFC9162LeafHash(body), proofIndex, size, proof, root) {
		return no("tlog_inclusion", "the inclusion proof does not lead to the root")
	}
	// the reported index must be a verified one: the SET signs the entry's (v1 sharded, global) logIndex; without a SET (Rekor
	// v2, v1 TSA-only) the entry's own logIndex is unauthenticated, so the inclusion proof's verified index is reported instead
	verifiedIndex := proofIndex
	if set {
		verifiedIndex = logIndex
	}
	*stage = "tlog_checkpoint"
	envelope, ok := cp["envelope"].(string)
	if !ok {
		return no("tlog_checkpoint", "the checkpoint envelope is not a string")
	}
	if e := verifyCheckpoint(envelope, log, size, root); e != "" {
		return no("tlog_checkpoint", e)
	}

	// ---- certificate path at every verified time (hybrid model), CT
	*stage = "cert_chain"
	faultAt("cert_chain")
	issuer := pinnedIssuer(leaf, leafDer, times, o)
	if issuer == nil {
		return no("cert_chain", "no pinned CA issued the certificate, valid at every signing time")
	}
	if leaf.CA() || pc.basicConstraintsCA() {
		return no("cert_chain", "the leaf is a CA certificate")
	}
	for _, at := range times {
		if !leaf.ValidAt(at) {
			return no("cert_time", "the certificate was not valid at a signing time")
		}
	}
	if !hasEKU(leafDer, ekuCodeSigning) {
		return no("cert_eku", "the certificate lacks the code-signing EKU")
	}
	if len(o.ctlogs) > 0 {
		*stage = "sct"
		faultAt("sct")
		if e := verifySCT(pc, issuer, o); e != "" {
			return no("sct", e)
		}
	}

	// ---- the entry body names this envelope
	*stage = "tlog_body"
	ebv, isJSON := decodeOneJSON(body)
	if !isJSON {
		throw("the entry body is not JSON")
	}
	eb := obj(ebv)
	spec := obj(eb["spec"])
	// a missing kind or apiVersion reads as "", and kv always has both parts non-empty
	ek, _ := eb["kind"].(string)
	ev, _ := eb["apiVersion"].(string)
	if ek+"/"+ev != kv {
		return no("tlog_body", "the entry body is not the kind the bundle names")
	}
	sum := sha256.Sum256(payload)
	payloadSha := hex.EncodeToString(sum[:])
	phOK := func(ph map[string]any) bool { return ph["algorithm"] == "sha256" && ph["value"] == payloadSha }
	oneSig := func(v any) map[string]any {
		if a, ok := arr(v); ok && len(a) == 1 {
			return obj(a[0])
		}
		return nil
	}
	switch kv {
	case "dsse/0.0.1":
		if !phOK(obj(spec["payloadHash"])) {
			return no("tlog_body", "the entry names another payload")
		}
		s := oneSig(spec["signatures"])
		if s == nil {
			return no("tlog_body", "the entry must name exactly one signature")
		}
		if !bytes.Equal(b64(s["signature"]), dsseSig) {
			return no("tlog_body", "the entry names another signature")
		}
		if !bytes.Equal(pemDer(b64(s["verifier"])), leafDer) {
			return no("tlog_body", "the entry names another certificate")
		}
	case "intoto/0.0.2":
		// Rekor intoto 0.0.2 stores the envelope signature and payload base64 twice, and the key as base64 PEM
		c := obj(spec["content"])
		if !phOK(obj(c["payloadHash"])) {
			return no("tlog_body", "the entry names another payload")
		}
		s := oneSig(obj(c["envelope"])["signatures"])
		if s == nil {
			return no("tlog_body", "the entry must name exactly one signature")
		}
		if !bytes.Equal(b64(latin1(b64(s["sig"]))), dsseSig) {
			return no("tlog_body", "the entry names another signature")
		}
		if !bytes.Equal(pemDer(b64(s["publicKey"])), leafDer) {
			return no("tlog_body", "the entry names another certificate")
		}
	default:
		// Rekor v2 hashedrekord over DSSE: digest = Hash(PAE), content = the envelope signature, verifier = the leaf
		h := obj(spec["hashedRekordV002"])
		data := obj(h["data"])
		var hash crypto.Hash
		switch data["algorithm"] {
		case "SHA2_256":
			hash = crypto.SHA256
		case "SHA2_384":
			hash = crypto.SHA384
		case "SHA2_512":
			hash = crypto.SHA512
		}
		if hash == 0 || hash != alg {
			return no("tlog_body", "the entry digest algorithm is not the signing key's")
		}
		if !bytes.Equal(b64(data["digest"]), digest(hash, pae)) {
			return no("tlog_body", "the entry names another envelope")
		}
		sg := obj(h["signature"])
		if !bytes.Equal(b64(sg["content"]), dsseSig) {
			return no("tlog_body", "the entry names another signature")
		}
		if !bytes.Equal(b64(obj(obj(sg["verifier"])["x509Certificate"])["rawBytes"]), leafDer) {
			return no("tlog_body", "the entry names another certificate")
		}
	}

	// ---- DSSE signature
	*stage = "signature"
	faultAt("signature")
	if alg == 0 {
		return no("signature", "unsupported leaf key type")
	}
	if !nodeVerify(alg, pae, leafKey, dsseSig) {
		return no("signature", "DSSE signature invalid")
	}

	// ---- identity (fulcio docs/oid-info.md)
	*stage = "identity"
	identity := sanIdentity(pc)
	issV2, issV1 := fulcioExt(pc, 8), fulcioExt(pc, 1)
	if issV2 != nil && issV1 != nil && *issV2 != *issV1 {
		return no("identity", "the two issuer extensions disagree")
	}
	issuerName := issV1
	if issV2 != nil {
		issuerName = issV2
	}
	if issuerName == nil || *issuerName == "" {
		return no("identity", "no OIDC issuer extension")
	}
	c := Core{Identity: identity, OIDCIssuer: *issuerName, SourceRepo: fulcioExt(pc, 12), SourceDigest: fulcioExt(pc, 13), SourceRef: fulcioExt(pc, 14)}

	// ---- statement (read from the verified payload, keeping subject order)
	*stage = "statement"
	stv, isJSON := decodeOneJSON([]byte(utf8Strict(payload)))
	if !isJSON {
		throw("the statement is not JSON")
	}
	st := obj(stv)
	if st["_type"] != pca.InTotoStatementV1 {
		return no("statement", "not an in-toto Statement v1")
	}
	subs, ok := arr(st["subject"])
	if !ok || len(subs) == 0 {
		return no("statement", "no subject")
	}
	for _, s := range subs {
		dg := obj(obj(s)["digest"])
		for _, a := range []string{"sha256", "sha512"} {
			if v, ok := dg[a].(string); ok {
				c.Subjects = append(c.Subjects, Subject{a, v})
			}
		}
	}
	if len(c.Subjects) == 0 || len(c.Subjects) > 64 {
		return no("statement", "no sha256/sha512 subject digest (or more than 64)")
	}
	pt, ok := st["predicateType"].(string)
	if !ok {
		return no("statement", "no predicateType")
	}
	c.PredicateType = pt
	minMs := times[0]
	for _, at := range times[1:] {
		minMs = min(minMs, at)
	}
	c.SignedTime = int64(math.Floor(float64(minMs) / 1000)) // Math.floor(Math.min(...times) / 1000)
	c.RekorLogIndex = verifiedIndex
	c.Rekor = "v1"
	if v2 {
		c.Rekor = "v2"
	}
	c.Timestamps = Timestamps{TSA: tsaCount, Set: set}
	return CoreResult{OK: true, Core: c, Statement: st}
}

// latin1 is Buffer.toString('latin1'): one character per byte.
func latin1(b []byte) string {
	r := make([]rune, len(b))
	for i, x := range b {
		r[i] = rune(x)
	}
	return string(r)
}

// VerifySigstoreBundle is VerifySigstoreBundleCore, then the SLSA v1 predicate: the facts pca.ProvenanceGate checks.
func VerifySigstoreBundle(bundleJSON []byte, roots *PinnedRoots) Result {
	r := VerifySigstoreBundleCore(bundleJSON, roots)
	if !r.OK {
		return Result{Code: r.Code, Detail: r.Detail}
	}
	st, c := r.Statement, r.Core
	if st["predicateType"] != pca.SLSAProvenanceV1 {
		return Result{Code: "predicate", Detail: fmt.Sprintf("predicate %v is not SLSA provenance v1", st["predicateType"])}
	}
	pr := obj(st["predicate"])
	bd, rd := obj(pr["buildDefinition"]), obj(pr["runDetails"])
	buildType, ok1 := bd["buildType"].(string)
	builderID, ok2 := obj(rd["builder"])["id"].(string)
	if !ok1 || !ok2 || obj(bd["externalParameters"]) == nil {
		return Result{Code: "predicate", Detail: "buildType, externalParameters and builder.id are required (SLSA Build L1)"}
	}
	subs := make([]any, len(c.Subjects))
	for i, s := range c.Subjects {
		subs[i] = map[string]any{"alg": s.Alg, "digest": s.Digest}
	}
	f := map[string]any{
		"v": json.Number("1"), "predicate_type": pca.SLSAProvenanceV1, "build_type": buildType, "builder_id": builderID,
		"subjects": subs, "identity": c.Identity, "oidc_issuer": c.OIDCIssuer,
		"integrated_time": json.Number(strconv.FormatInt(c.SignedTime, 10)), "rekor_log_index": json.Number(strconv.FormatInt(c.RekorLogIndex, 10)),
	}
	for k, v := range map[string]*string{"source_repo": c.SourceRepo, "source_ref": c.SourceRef, "source_digest": c.SourceDigest} {
		if v != nil {
			f[k] = *v
		}
	}
	if deps, ok := arr(bd["resolvedDependencies"]); ok && len(deps) > 0 {
		d0 := obj(deps[0])
		if uri, ok := d0["uri"].(string); ok {
			ps := map[string]any{"uri": uri}
			if g, ok := obj(d0["digest"])["gitCommit"].(string); ok {
				ps["git_commit"] = g
			}
			f["provenance_source"] = ps
		}
	}
	return Result{OK: true, Facts: f}
}

// b64Decode is base64.StdEncoding.DecodeString; a var only so a test can reach b64's decode-error check, which the pattern
// and length checks before it leave no real input to trip.
var b64Decode = base64.StdEncoding.DecodeString
