package pca

// WebAuthn / FIDO2 assertion verification as the PCA step-up co-sign: a minimal COSE_Key reader, the authenticatorData header,
// the step-up / approval challenges a passkey signs, Secure Payment Confirmation binding, and VerifyAssertion (fail closed: every
// failure is an {ok:false, reason} result, never a panic).

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/cryptobyte"
	asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

const (
	MaxAuthenticatorDataBytes = 4096
	MaxClientDataBytes        = 8192
	MaxSignatureBytes         = 1024
)

// ---- COSE_Key ----

// coseRead reads one CBOR item: unsigned / negative ints (int64), byte strings ([]byte) and maps with integer keys
// (map[int64]any, a repeated key: last wins), with 0..4-byte arguments. Anything else is an error.
func coseRead(b []byte, off int) (any, int, error) {
	short := errors.New("cose: unexpected end of input")
	if off >= len(b) {
		return nil, 0, short
	}
	major, ai, p := b[off]>>5, b[off]&0x1f, off+1
	var arg uint64
	switch {
	case ai < 24:
		arg = uint64(ai)
	case ai <= 26:
		n := 1 << (ai - 24)
		if p+n > len(b) {
			return nil, 0, short
		}
		for i := 0; i < n; i++ {
			arg = arg<<8 | uint64(b[p+i])
		}
		p += n
	default:
		return nil, 0, errors.New("cose: unsupported CBOR argument encoding (8-byte or indefinite length)")
	}
	switch major {
	case 0:
		return int64(arg), p, nil
	case 1:
		return -1 - int64(arg), p, nil
	case 2:
		if uint64(p)+arg > uint64(len(b)) {
			return nil, 0, errors.New("cose: byte string length out of range")
		}
		return append([]byte(nil), b[p:p+int(arg)]...), p + int(arg), nil
	case 5:
		m := map[int64]any{}
		for i := uint64(0); i < arg; i++ {
			k, q, err := coseRead(b, p)
			if err != nil {
				return nil, 0, err
			}
			ki, ok := k.(int64)
			if !ok {
				return nil, 0, errors.New("cose: non-integer map key")
			}
			v, q2, err := coseRead(b, q)
			if err != nil {
				return nil, 0, err
			}
			m[ki], p = v, q2
		}
		return m, p, nil
	}
	return nil, 0, fmt.Errorf("cose: unsupported CBOR major type %d", major)
}

// CoseKeyToJwk converts a COSE_Key (EC2 P-256 or OKP Ed25519) to its public JWK.
func CoseKeyToJwk(cose []byte) (map[string]any, error) {
	v, _, err := coseRead(cose, 0)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[int64]any)
	if !ok {
		return nil, errors.New("coseKeyToJwk: COSE_Key is not a CBOR map")
	}
	isInt := func(x any, n int64) bool { i, ok := x.(int64); return ok && i == n }
	switch kty := m[1]; {
	case isInt(kty, 2):
		if !isInt(m[-1], 1) {
			return nil, errors.New("coseKeyToJwk: EC2 key is not P-256 (crv != 1)")
		}
		x, ok1 := m[-2].([]byte)
		y, ok2 := m[-3].([]byte)
		if !ok1 || !ok2 {
			return nil, errors.New("coseKeyToJwk: EC2 key missing an x/y coordinate")
		}
		if len(x) != 32 || len(y) != 32 {
			return nil, errors.New("coseKeyToJwk: EC2 coordinate is not 32 bytes")
		}
		return map[string]any{"kty": "EC", "crv": "P-256", "x": b64.EncodeToString(x), "y": b64.EncodeToString(y), "alg": "ES256"}, nil
	case isInt(kty, 1):
		if !isInt(m[-1], 6) {
			return nil, errors.New("coseKeyToJwk: OKP key is not Ed25519 (crv != 6)")
		}
		x, ok := m[-2].([]byte)
		if !ok {
			return nil, errors.New("coseKeyToJwk: OKP key missing its public key")
		}
		if len(x) != 32 {
			return nil, errors.New("coseKeyToJwk: Ed25519 public key is not 32 bytes")
		}
		return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64.EncodeToString(x), "alg": "EdDSA"}, nil
	default:
		return nil, fmt.Errorf("coseKeyToJwk: unsupported COSE key type (kty=%s)", coseString(kty))
	}
}

func coseString(v any) string {
	switch x := v.(type) {
	case nil:
		return "undefined"
	case int64:
		return fmt.Sprint(x)
	case []byte:
		s := make([]string, len(x))
		for i, c := range x {
			s[i] = fmt.Sprint(c)
		}
		return strings.Join(s, ",")
	}
	return "[object Map]"
}

var webauthnLooseB64 = regexp.MustCompile(`=+$`)

// webauthnJwkBytes reads a JWK coordinate: trailing '=' dropped, the standard alphabet mapped to base64url, then strict.
func webauthnJwkBytes(v any) []byte {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	s = strings.NewReplacer("+", "-", "/", "_").Replace(webauthnLooseB64.ReplaceAllString(s, ""))
	b, ok := DecodeB64uStrict(s, -1)
	if !ok {
		return nil
	}
	return b
}

// webauthnResolveKey: a COSE_Key ([]byte) or a public JWK (map) -> alg + raw key (SEC1 uncompressed P-256 or Ed25519).
func webauthnResolveKey(pub any) (string, []byte, error) {
	var jwk map[string]any
	switch k := pub.(type) {
	case []byte:
		j, err := CoseKeyToJwk(k)
		if err != nil {
			return "", nil, err
		}
		jwk = j
	case map[string]any:
		jwk = k
	default:
		return "", nil, errors.New("resolveKey: unsupported public key")
	}
	switch jwk["kty"] {
	case "EC":
		if jwk["crv"] != "P-256" {
			return "", nil, errors.New("resolveKey: EC JWK is not P-256")
		}
		x, y := webauthnJwkBytes(jwk["x"]), webauthnJwkBytes(jwk["y"])
		if len(x) != 32 || len(y) != 32 {
			return "", nil, errors.New("resolveKey: invalid EC JWK coordinates")
		}
		return "ES256", append(append([]byte{4}, x...), y...), nil
	case "OKP":
		if jwk["crv"] != "Ed25519" {
			return "", nil, errors.New("resolveKey: OKP JWK is not Ed25519")
		}
		x := webauthnJwkBytes(jwk["x"])
		if len(x) != 32 {
			return "", nil, errors.New("resolveKey: invalid OKP JWK public key")
		}
		return "EdDSA", x, nil
	}
	return "", nil, errors.New("resolveKey: unsupported public key")
}

// ---- authenticatorData ----

// AuthenticatorFlags are the authenticatorData flag bits.
type AuthenticatorFlags struct {
	UP bool `json:"up"`
	UV bool `json:"uv"`
	BE bool `json:"be"`
	BS bool `json:"bs"`
	AT bool `json:"at"`
	ED bool `json:"ed"`
}

// ParsedAuthenticatorData is the fixed 37-byte authenticatorData header.
type ParsedAuthenticatorData struct {
	RPIDHash  []byte
	Flags     AuthenticatorFlags
	SignCount uint32
}

// ParseAuthenticatorData reads the header; nil when shorter than 37 bytes.
func ParseAuthenticatorData(ad []byte) *ParsedAuthenticatorData {
	if len(ad) < 37 {
		return nil
	}
	f := ad[32]
	return &ParsedAuthenticatorData{RPIDHash: append([]byte(nil), ad[:32]...), SignCount: binary.BigEndian.Uint32(ad[33:37]),
		Flags: AuthenticatorFlags{UP: f&0x01 != 0, UV: f&0x04 != 0, BE: f&0x08 != 0, BS: f&0x10 != 0, AT: f&0x40 != 0, ED: f&0x80 != 0}}
}

// ---- challenges ----

// BuildStepUpChallenge is the 32 bytes a passkey signs for a step-up: SHA-256 of the PCActn's threshold message, or a given
// 32-byte action digest (raw bytes, or canonical base64url).
func BuildStepUpChallenge(pcActnOrDigest any) ([]byte, error) {
	switch v := pcActnOrDigest.(type) {
	case []byte:
		if len(v) != 32 {
			return nil, errors.New("buildStepUpChallenge: digest bytes must be 32 bytes")
		}
		return append([]byte(nil), v...), nil
	case string:
		b, ok := DecodeB64uStrict(v, 32)
		if !ok {
			return nil, errors.New("buildStepUpChallenge: digest is not a canonical base64url 32-byte value")
		}
		return b, nil
	case map[string]any:
		m, err := ThresholdMessage(v)
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256(m)
		return h[:], nil
	}
	return nil, errors.New("buildStepUpChallenge: expected a PCActn, a digest string or 32 digest bytes")
}

// BuildApprovalChallenge binds the step-up challenge to the approval render the person saw.
func BuildApprovalChallenge(pcActnOrDigest any, renderDigest string) ([]byte, error) {
	d, err := BuildStepUpChallenge(pcActnOrDigest)
	if err != nil {
		return nil, err
	}
	c, err := ApprovalChallenge(b64.EncodeToString(d), renderDigest)
	if err != nil {
		return nil, err
	}
	return b64.DecodeString(c)
}

// ApprovalChallengeForActn is BuildApprovalChallenge as base64url.
func ApprovalChallengeForActn(pcActnOrDigest any, renderDigest string) (string, error) {
	b, err := BuildApprovalChallenge(pcActnOrDigest, renderDigest)
	return b64.EncodeToString(b), err
}

// StepUpChallengeB64u is BuildStepUpChallenge as base64url.
func StepUpChallengeB64u(pcActnOrDigest any) (string, error) {
	b, err := BuildStepUpChallenge(pcActnOrDigest)
	return b64.EncodeToString(b), err
}

// ---- Secure Payment Confirmation ----

// SpcPaymentExpectation is the canonical payment the person approves. At least one of PayeeName / PayeeOrigin is required.
type SpcPaymentExpectation struct {
	TopOrigin              string
	Total                  struct{ Currency, Value string }
	PayeeName, PayeeOrigin *string
}

// SpcPaymentError checks clientData.payment against the expectation; "" when it matches.
func SpcPaymentError(payment any, e SpcPaymentExpectation, rpID string) string {
	p, ok := payment.(map[string]any)
	if !ok {
		return "clientData.payment is missing"
	}
	if e.PayeeName == nil && e.PayeeOrigin == nil {
		return "the expectation names no payee (refused: a payment approval must bind the payee)"
	}
	if e.TopOrigin == "" {
		return "the expectation names no topOrigin (refused: a payment approval must bind the approval origin)"
	}
	if r, ok := p["rpId"].(string); !ok || r != rpID {
		return "clientData.payment.rpId is not the verifier rpId"
	}
	if t, ok := p["topOrigin"].(string); !ok || t != e.TopOrigin {
		return "clientData.payment.topOrigin is not the verifier approval origin"
	}
	total, _ := p["total"].(map[string]any)
	c, ok1 := total["currency"].(string)
	v, ok2 := total["value"].(string)
	if !ok1 || !ok2 || c != e.Total.Currency || v != e.Total.Value {
		return "clientData.payment.total does not equal the canonical render"
	}
	for _, f := range []struct {
		k string
		e *string
	}{{"payeeName", e.PayeeName}, {"payeeOrigin", e.PayeeOrigin}} {
		if f.e == nil {
			continue
		}
		if s, ok := p[f.k].(string); !ok || s != *f.e {
			return "clientData.payment." + f.k + " does not equal the canonical render"
		}
	}
	return ""
}

// ---- assertion ----

// Assertion is a WebAuthn assertion plus the credential public key (a COSE_Key []byte, or a public JWK map). A nil byte field
// is "not bytes".
type Assertion struct {
	AuthenticatorData, ClientDataJSON, Signature []byte
	PublicKey                                    any
}

// WebAuthnExpectations: ExpectedChallenge is []byte or canonical base64url; Origins is the exact-match allowlist; StoredSignCount
// is required (0 for a credential never used); RejectCrossOrigin nil = true; Payment switches to an SPC payment.get assertion.
type WebAuthnExpectations struct {
	ExpectedChallenge     any
	RPID                  string
	Origins               []string
	RequireUV             bool
	RequireLowS           bool
	StoredSignCount       *float64
	OnSignCountRegression func(stored, reported float64)
	RejectCrossOrigin     *bool
	Payment               *SpcPaymentExpectation
}

// AssertionResult is {ok: true, alg, signCount, flags} or {ok: false, reason}.
type AssertionResult struct {
	OK        bool
	Alg       string
	SignCount uint32
	Flags     AuthenticatorFlags
	Reason    string
}

func (r AssertionResult) MarshalJSON() ([]byte, error) {
	if !r.OK {
		return json.Marshal(map[string]any{"ok": false, "reason": r.Reason})
	}
	return json.Marshal(map[string]any{"ok": true, "alg": r.Alg, "signCount": r.SignCount, "flags": r.Flags})
}

var p256HalfN = new(big.Int).Rsh(elliptic.P256().Params().N, 1)

func webauthnES256(sig, signed, raw []byte, lowS bool) bool {
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		return false
	}
	h := sha256.Sum256(signed)
	var r, s *big.Int
	if len(sig) > 0 && sig[0] == 0x30 && len(sig) != 64 {
		var ok bool
		if r, s, ok = parseECDSADER(sig); !ok {
			return false
		}
	} else {
		if len(sig) != 64 {
			return false
		}
		r, s = new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	}
	if lowS && s.Cmp(p256HalfN) > 0 {
		return false
	}
	return ecdsa.Verify(pub, h[:], r, s)
}

// VerifyAssertion verifies a passkey assertion for a step-up: clientData type / challenge / origin / crossOrigin (and SPC payment),
// the rpIdHash, UP (and UV when required), the signature over authenticatorData || SHA-256(clientDataJSON) (ES256 low-S when
// required, strict RFC 8032 EdDSA), and that the signature counter increased. It never panics.
func VerifyAssertion(a Assertion, e WebAuthnExpectations) (res AssertionResult) {
	fail := func(r string) AssertionResult { return AssertionResult{Reason: r} }
	defer func() {
		if p := recover(); p != nil {
			res = fail(fmt.Sprintf("verification error (fail closed): %v", p))
		}
	}()
	switch {
	case a.AuthenticatorData == nil:
		return fail("authenticatorData is not bytes")
	case a.ClientDataJSON == nil:
		return fail("clientDataJSON is not bytes")
	case a.Signature == nil:
		return fail("signature is not bytes")
	case len(a.AuthenticatorData) > MaxAuthenticatorDataBytes:
		return fail("authenticatorData is too large")
	case len(a.ClientDataJSON) > MaxClientDataBytes:
		return fail("clientDataJSON is too large")
	case len(a.Signature) > MaxSignatureBytes:
		return fail("signature is too large")
	case e.RPID == "":
		return fail("rpId is required")
	case len(e.Origins) == 0:
		return fail("origins allowlist is empty")
	case e.StoredSignCount == nil:
		return fail("storedSignCount is required (use 0 for a credential never used)")
	}
	if !utf8.Valid(a.ClientDataJSON) {
		return fail("clientDataJSON is not valid UTF-8")
	}
	parsed, err := ParseJSONLastWins(bytes.TrimPrefix(a.ClientDataJSON, []byte("\xEF\xBB\xBF"))) // the WHATWG decoder drops a BOM
	if err != nil {
		return fail("clientDataJSON is not valid JSON")
	}
	client, ok := parsed.(map[string]any)
	if !ok {
		return fail("clientDataJSON is not a JSON object")
	}
	wantType := "webauthn.get"
	if e.Payment != nil {
		wantType = "payment.get"
	}
	if t, ok := client["type"].(string); !ok || t != wantType {
		return fail(fmt.Sprintf(`clientData.type is not "%s" (%s)`, wantType, jsMemberString(client, "type")))
	}
	if e.Payment != nil {
		if pe := SpcPaymentError(client["payment"], *e.Payment, e.RPID); pe != "" {
			return fail(pe)
		}
	}
	cs, isStr := client["challenge"].(string)
	got, ok := DecodeB64uStrict(cs, -1)
	if !isStr || !ok {
		return fail("clientData.challenge is missing or not canonical base64url")
	}
	var want []byte
	switch c := e.ExpectedChallenge.(type) {
	case []byte:
		want, ok = c, true
	case string:
		want, ok = DecodeB64uStrict(c, -1)
	default:
		ok = false
	}
	if !ok {
		return fail("expectedChallenge is not decodable")
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return fail("clientData.challenge does not match the step-up challenge")
	}
	if e.RejectCrossOrigin == nil || *e.RejectCrossOrigin {
		if co, has := client["crossOrigin"]; has {
			if co == true {
				return fail("clientData.crossOrigin is true")
			}
			if co != false {
				return fail("clientData.crossOrigin is not a boolean")
			}
		}
	}
	origin, ok := client["origin"].(string)
	if !ok {
		return fail("clientData.origin is missing")
	}
	if !hasStr(e.Origins, origin) {
		return fail(fmt.Sprintf(`clientData.origin "%s" is not in the allowlist`, origin))
	}
	ad := ParseAuthenticatorData(a.AuthenticatorData)
	if ad == nil {
		return fail("authenticatorData is too short (< 37 bytes)")
	}
	rp := sha256.Sum256([]byte(e.RPID))
	if subtle.ConstantTimeCompare(ad.RPIDHash, rp[:]) != 1 {
		return fail("rpIdHash does not match sha256(rpId)")
	}
	if !ad.Flags.UP {
		return fail("User Present (UP) flag is not set")
	}
	if e.RequireUV && !ad.Flags.UV {
		return fail("User Verified (UV) flag is required but not set")
	}
	ch := sha256.Sum256(a.ClientDataJSON)
	signed := append(append([]byte(nil), a.AuthenticatorData...), ch[:]...)
	alg, raw, err := webauthnResolveKey(a.PublicKey)
	if err != nil {
		return fail("public key could not be resolved: " + err.Error())
	}
	valid := false
	if alg == "ES256" {
		valid = webauthnES256(a.Signature, signed, raw, e.RequireLowS)
	} else {
		valid = VerifyStrict(raw, signed, a.Signature)
	}
	if !valid {
		return fail("assertion signature did not verify")
	}
	st := *e.StoredSignCount
	if st != math.Trunc(st) || st < 0 || math.Signbit(st) || st > 0xffffffff {
		return fail("storedSignCount is not a uint32")
	}
	if (ad.SignCount != 0 || st != 0) && float64(ad.SignCount) <= st {
		if e.OnSignCountRegression != nil {
			e.OnSignCountRegression(st, float64(ad.SignCount))
		}
		return fail("signCount did not increase (possible cloned authenticator)")
	}
	return AssertionResult{OK: true, Alg: alg, SignCount: ad.SignCount, Flags: ad.Flags}
}

// parseECDSADER reads a strict DER ECDSA-Sig-Value (SEQUENCE of two minimal non-negative INTEGERs, nothing after).
func parseECDSADER(sig []byte) (*big.Int, *big.Int, bool) {
	var inner cryptobyte.String
	r, s := new(big.Int), new(big.Int)
	in := cryptobyte.String(sig)
	if !in.ReadASN1(&inner, asn1.SEQUENCE) || !in.Empty() || !inner.ReadASN1Integer(r) || !inner.ReadASN1Integer(s) || !inner.Empty() {
		return nil, nil, false
	}
	return r, s, true
}
