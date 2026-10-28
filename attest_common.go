package pca

// Hardware attestation verifiers (AMD SEV-SNP, Intel TDX DCAP, Azure MAA, Google Confidential Space, NVIDIA GPU SPDM):
// shared types and helpers. The vendor verifiers answer exactly what the reference verifiers of @atlasauth/pca answer,
// reason text included, and fail closed on anything they cannot establish.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

const attestBindDomain = "atlas-pca/attest-bind/v1\x00"

// AttestationBinding is what a vendor quote's bound value must equal: the server-known holder key, grant, epoch and nonce.
// Epoch is a float64 because the wire form carries a JSON number; only a non-negative safe integer is constructible.
type AttestationBinding struct {
	HolderPub string
	GrantRef  string
	Epoch     float64
	Nonce     string
}

func lengthPrefixed(s string) []byte {
	out := make([]byte, 4, 4+len(s))
	binary.BigEndian.PutUint32(out, uint32(len(s)))
	return append(out, s...)
}

// attestationBindingBytes is SHA-512( "atlas-pca/attest-bind/v1\0" || lp(holderPub) || lp(grantRef) || u64be(epoch) || lp(nonce) ).
func attestationBindingBytes(e AttestationBinding) ([]byte, error) {
	if e.HolderPub == "" {
		return nil, errors.New("binding: holderPub required")
	}
	if e.GrantRef == "" {
		return nil, errors.New("binding: grantRef required")
	}
	if e.Nonce == "" {
		return nil, errors.New("binding: nonce required")
	}
	if math.IsNaN(e.Epoch) || e.Epoch != math.Trunc(e.Epoch) || e.Epoch < 0 || e.Epoch > maxSafeInt {
		return nil, errors.New("binding: epoch must be a non-negative safe integer")
	}
	var buf []byte
	buf = append(buf, attestBindDomain...)
	buf = append(buf, lengthPrefixed(e.HolderPub)...)
	buf = append(buf, lengthPrefixed(e.GrantRef)...)
	var ep [8]byte
	binary.BigEndian.PutUint64(ep[:], uint64(e.Epoch))
	buf = append(buf, ep[:]...)
	buf = append(buf, lengthPrefixed(e.Nonce)...)
	h := sha512.Sum512(buf)
	return h[:], nil
}

// HardwareResult is a vendor verifier's answer (the reference HardwareAttestationResult).
type HardwareResult struct {
	OK           bool
	Bound        bool
	Reason       string
	Measured     map[string]any
	HostAsserted map[string]string
}

func hwFail(reason string) HardwareResult { return HardwareResult{Reason: reason} }

// Wire is the language-neutral form of the result (what the conformance vectors record in `expect`).
func (r HardwareResult) Wire() map[string]any {
	if !r.OK {
		return map[string]any{"ok": false, "reason": r.Reason}
	}
	out := map[string]any{"ok": true, "bound": r.Bound}
	if r.Measured != nil {
		out["measured"] = r.Measured
	}
	if r.HostAsserted != nil {
		ha := map[string]any{}
		for k, v := range r.HostAsserted {
			ha[k] = v
		}
		out["hostAsserted"] = ha
	}
	return out
}

func newMeasured(runtimeMeasurement, operator string) map[string]any {
	return map[string]any{"model_id": "", "weights_digest": "", "weights_measured": false, "runtime_measurement": runtimeMeasurement, "operator": operator}
}

// ───────────────────────────────────────────────────────────── small helpers

func toHexLower(b []byte) string { return hex.EncodeToString(b) }

func timingSafeEq(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

func isJSSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

func jsTrim(s string) string { return strings.TrimFunc(s, isJSSpace) }

// nodeB64 decodes like Buffer.from(s, "base64"): either alphabet, characters outside it are skipped, "=" ends the data.
func nodeB64(s string) []byte {
	out := make([]byte, 0, len(s)*3/4)
	var acc uint32
	bits := 0
loop:
	for i := 0; i < len(s); i++ {
		c := s[i]
		var v int
		switch {
		case c >= 'A' && c <= 'Z':
			v = int(c - 'A')
		case c >= 'a' && c <= 'z':
			v = int(c-'a') + 26
		case c >= '0' && c <= '9':
			v = int(c-'0') + 52
		case c == '+' || c == '-':
			v = 62
		case c == '/' || c == '_':
			v = 63
		case c == '=':
			break loop
		default:
			continue
		}
		acc = acc<<6 | uint32(v)
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>uint(bits)))
			acc &= (1 << uint(bits)) - 1
		}
	}
	return out
}

var hexPattern = regexp.MustCompile(`^[0-9a-fA-F]+$`)

func isHexString(s string) bool { return len(s) > 0 && len(s)%2 == 0 && hexPattern.MatchString(s) }

// decodeClaimBytes decodes a byte-carrying claim: hex (optionally 0x-prefixed), else base64url / base64.
func decodeClaimBytes(value string) []byte {
	t := jsTrim(value)
	hx := t
	if strings.HasPrefix(t, "0x") || strings.HasPrefix(t, "0X") {
		hx = t[2:]
	}
	if isHexString(hx) {
		b, _ := hex.DecodeString(hx)
		return b
	}
	if b := nodeB64(t); len(b) > 0 {
		return b
	}
	return nil
}

// jsonLenient parses like JSON.parse (numbers kept as json.Number; the last of a duplicate key wins).
func jsonLenient(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("unexpected data after the JSON value")
	}
	return v, nil
}

func asRec(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

func asStr(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// asFinite is the reference asNumber: a finite JSON number.
func asFinite(v any) (float64, bool) {
	var f float64
	switch t := v.(type) {
	case json.Number:
		x, err := strconv.ParseFloat(string(t), 64)
		if err != nil {
			return 0, false
		}
		f = x
	case float64:
		f = t
	case int:
		f = float64(t)
	case int64:
		f = float64(t)
	default:
		return 0, false
	}
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, false
	}
	return f, true
}

func asStrList(v any) ([]string, bool) {
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func isNil(v any) bool { return v == nil }

// jsNumString renders a number like String(n) for the integers this package reports.
func jsNumString(f float64) string {
	if f == math.Trunc(f) && math.Abs(f) < 1e21 {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func mergeOverrides(measured map[string]any, ov map[string]any) map[string]any {
	out := make(map[string]any, len(measured)+len(ov))
	for k, v := range measured {
		out[k] = v
	}
	for k, v := range ov {
		out[k] = v
	}
	return out
}

// ───────────────────────────────────────────────────────────── X.509 (crypto/x509 for signatures and names, strict DER for the rules)

var (
	pemCertBlockRe = regexp.MustCompile(`(?s)-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----`)
	pemCertBodyRe  = regexp.MustCompile(`(?s)-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----`)
	oidRSASSAPSS   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
)

func pemCertBlocks(text string) []string { return pemCertBlockRe.FindAllString(text, -1) }

// certKey is a certificate's public key with the details the rules ask about (Node's asymmetricKeyType / namedCurve).
type certKey struct {
	pub   crypto.PublicKey
	typ   string // "ec", "rsa", "rsa-pss", "ed25519", ...
	curve string // OpenSSL curve name for "ec"
	spki  []byte // DER SubjectPublicKeyInfo
}

func curveOpenSSLName(c elliptic.Curve) string {
	switch c.Params().Name {
	case "P-256":
		return "prime256v1"
	case "P-384":
		return "secp384r1"
	case "P-521":
		return "secp521r1"
	case "P-224":
		return "secp224r1"
	}
	return c.Params().Name
}

func keyInfoOf(pub crypto.PublicKey, spki []byte) certKey {
	k := certKey{pub: pub, spki: spki}
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		k.typ, k.curve = "ec", curveOpenSSLName(p.Curve)
	case *rsa.PublicKey:
		k.typ = "rsa"
	case ed25519.PublicKey:
		k.typ = "ed25519"
	default:
		k.typ = "unknown"
	}
	return k
}

func (k certKey) spkiSHA256() string {
	h := sha256.Sum256(k.spki)
	return hex.EncodeToString(h[:])
}

func (k certKey) spkiSHA384() string {
	h := sha512.Sum384(k.spki)
	return hex.EncodeToString(h[:])
}

func normSerial(s string) string { return strings.TrimLeft(strings.ToLower(s), "0") }

// ecPointOfKey is the uncompressed SEC1 point of an EC key on exactly the named curve (P-256 or P-384).
func ecPointOfKey(k certKey, curveName string) ([]byte, error) {
	pk, ok := k.pub.(*ecdsa.PublicKey)
	if k.typ != "ec" || !ok {
		return nil, fmt.Errorf("public key is not EC (got %s)", k.typ)
	}
	want := map[string]int{"P-256": 32, "P-384": 48}[curveName]
	if pk.Curve.Params().Name != curveName {
		return nil, fmt.Errorf("public key is not on %s (got %s)", curveName, pk.Curve.Params().Name)
	}
	out := make([]byte, 1+2*want)
	out[0] = 0x04
	pk.X.FillBytes(out[1 : 1+want])
	pk.Y.FillBytes(out[1+want:])
	return out, nil
}

// ───────────────────────────────────────────────────────────── certificate names (OpenSSL's multi-line rendering)

var dnShortNames = map[string]string{
	"2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU",
	"2.5.4.5": "serialNumber", "2.5.4.9": "street", "2.5.4.17": "postalCode", "2.5.4.4": "SN", "2.5.4.42": "GN",
	"2.5.4.12": "title", "2.5.4.46": "dnQualifier", "1.2.840.113549.1.9.1": "emailAddress",
	"0.9.2342.19200300.100.1.25": "DC", "0.9.2342.19200300.100.1.1": "UID",
}

func escapeDNValue(s string) string {
	var sb strings.Builder
	rs := []rune(s)
	for i, r := range rs {
		switch {
		case r == ',' || r == '+' || r == '"' || r == '\\' || r == '<' || r == '>' || r == ';':
			sb.WriteByte('\\')
			sb.WriteRune(r)
		case (i == 0 && (r == ' ' || r == '#')) || (i == len(rs)-1 && r == ' '):
			sb.WriteByte('\\')
			sb.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			sb.WriteString(fmt.Sprintf("\\%02X", r))
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// nameText renders a DER Name the way Node renders a certificate subject / issuer: one "KEY=value" per attribute, in
// encoded order, joined by newlines.
func nameText(raw []byte) string {
	var rdn pkix.RDNSequence
	if rest, err := asn1.Unmarshal(raw, &rdn); err != nil || len(rest) != 0 {
		return ""
	}
	var lines []string
	for _, set := range rdn {
		var parts []string
		for _, atv := range set {
			key := atv.Type.String()
			if sn, ok := dnShortNames[key]; ok {
				key = sn
			}
			val, ok := atv.Value.(string)
			if !ok {
				val = fmt.Sprint(atv.Value)
			}
			parts = append(parts, key+"="+escapeDNValue(val))
		}
		lines = append(lines, strings.Join(parts, " + "))
	}
	return strings.Join(lines, "\n")
}

func base64StdDecode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// ───────────────────────────────────────────────────────────── P-256 / P-384 raw verification

func bigFromBytes(b []byte) *big.Int { return new(big.Int).SetBytes(b) }

// verifyRawECDSA verifies a raw r||s signature (equal halves) over the digest.
func verifyRawECDSA(pub *ecdsa.PublicKey, digest, sig []byte) bool {
	if len(sig) == 0 || len(sig)%2 != 0 {
		return false
	}
	h := len(sig) / 2
	return ecdsa.Verify(pub, digest, bigFromBytes(sig[:h]), bigFromBytes(sig[h:]))
}

// pointToKey builds an on-curve public key from an uncompressed SEC1 point; ok is false for anything else.
func pointToKey(curve elliptic.Curve, point []byte) (*ecdsa.PublicKey, bool) {
	size := (curve.Params().BitSize + 7) / 8
	if len(point) != 1+2*size || point[0] != 0x04 {
		return nil, false
	}
	x := bigFromBytes(point[1 : 1+size])
	y := bigFromBytes(point[1+size:])
	if !curve.IsOnCurve(x, y) {
		return nil, false
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, true
}

func sha256Sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
func sha384Sum(b []byte) []byte { h := sha512.Sum384(b); return h[:] }
func sha512Sum(b []byte) []byte { h := sha512.Sum512(b); return h[:] }

// checkAzureRuntimeDataBinding checks the Azure runtime-data binding: the hash relation and user-data equality.
// It returns the failure reason, or "" when the quote binds.
func checkAzureRuntimeDataBinding(reportData, runtimeData []byte, expected *AttestationBinding) string {
	if len(reportData) != 64 {
		return "report_data is not 64 bytes"
	}
	for _, b := range reportData[32:] {
		if b != 0 {
			return "report_data[32:64] is not zero (not an Azure runtime-data hash)"
		}
	}
	if !bytes.Equal(sha256Sum(runtimeData), reportData[:32]) {
		return "sha256(runtime data) does not equal the quote report_data"
	}
	parsed, err := jsonLenient(runtimeData)
	if err != nil {
		return "runtime data is not valid JSON"
	}
	obj, ok := parsed.(map[string]any)
	if !ok {
		return "runtime data is not a JSON object"
	}
	userData, ok := obj["user-data"].(string)
	if !ok || len(userData) != 128 || !hexPattern.MatchString(userData) {
		return "runtime data carries no 64-byte hex user-data"
	}
	want, err := attestationBindingBytes(*expected)
	if err != nil {
		return "binding not constructible: " + err.Error()
	}
	got, _ := hex.DecodeString(userData)
	if !bytes.Equal(got, want) {
		return "runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound quote)"
	}
	return ""
}

// errMsg is the text of an error, or "invalid" for a nil one.
func errMsg(err error) string {
	if err == nil {
		return "invalid"
	}
	return err.Error()
}
