package pca

// Verifiable credentials for agent passports: did:key (Ed25519, base58btc), the agent-passport SD-JWT VC (selectively disclosed
// digests) and RFC 9421 HTTP message signatures (the Web Bot Auth profile).

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const (
	VCContext            = "https://www.w3.org/ns/credentials/v2"
	AgentPassportContext = "https://atlasauth.net/credentials/agent-passport/v1"
	AgentPassportVCType  = "AgentPassportCredential"
	b58Alphabet          = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	maxBase58Input       = 1024
)

var vcSDFields = []string{"weights_digest", "system_prompt_digest", "tool_manifest_digest", "runtime_measurement"}

// Base58btcEncode is the Bitcoin base58 alphabet encoding (leading zero bytes become '1').
func Base58btcEncode(b []byte) string {
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	var digits []int
	for _, c := range b[zeros:] {
		carry := int(c)
		for j := range digits {
			carry += digits[j] << 8
			digits[j] = carry % 58
			carry /= 58
		}
		for carry > 0 {
			digits = append(digits, carry%58)
			carry /= 58
		}
	}
	out := strings.Repeat("1", zeros)
	for i := len(digits) - 1; i >= 0; i-- {
		out += string(b58Alphabet[digits[i]])
	}
	return out
}

// Base58btcDecode decodes base58btc (at most 1024 characters).
func Base58btcDecode(s string) ([]byte, error) {
	if jsLen(s) > maxBase58Input {
		return nil, errors.New("pca-vc: base58btc input too long")
	}
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	var bs []int
	for _, r := range s[zeros:] {
		v := strings.IndexRune(b58Alphabet, r)
		if v < 0 {
			return nil, errors.New("pca-vc: invalid base58btc character")
		}
		carry := v
		for j := range bs {
			carry += bs[j] * 58
			bs[j] = carry & 0xff
			carry >>= 8
		}
		for carry > 0 {
			bs = append(bs, carry&0xff)
			carry >>= 8
		}
	}
	out := make([]byte, zeros+len(bs))
	for i, v := range bs {
		out[zeros+len(bs)-1-i] = byte(v)
	}
	return out, nil
}

// DidKeyFromEd25519 is did:key:z + base58btc(0xed 0x01 || key).
func DidKeyFromEd25519(pub []byte) (string, error) {
	if len(pub) != 32 {
		return "", errors.New("pca-vc: Ed25519 public key must be 32 bytes")
	}
	return "did:key:z" + Base58btcEncode(append([]byte{0xed, 0x01}, pub...)), nil
}

// Ed25519FromDidKey extracts the Ed25519 key of a did:key (refusing any other multicodec).
func Ed25519FromDidKey(did string) ([]byte, error) {
	const prefix = "did:key:z"
	if !strings.HasPrefix(did, prefix) {
		return nil, errors.New("pca-vc: not a did:key:z… identifier")
	}
	if jsLen(did) > len(prefix)+64 {
		return nil, errors.New("pca-vc: did:key is not an Ed25519 (0xed01) key")
	}
	mc, err := Base58btcDecode(did[len(prefix):])
	if err != nil {
		return nil, err
	}
	if len(mc) != 34 || mc[0] != 0xed || mc[1] != 0x01 {
		return nil, errors.New("pca-vc: did:key is not an Ed25519 (0xed01) key")
	}
	return mc[2:], nil
}

// AgentPassportContextDoc returns the JSON-LD context document of the agent passport (a fresh copy).
func AgentPassportContextDoc() map[string]any {
	const v, xsd = "https://atlasauth.net/credentials/agent-passport/v1#", "http://www.w3.org/2001/XMLSchema#"
	t := func(id, typ string) map[string]any { return map[string]any{"@id": v + id, "@type": xsd + typ} }
	return map[string]any{"@context": map[string]any{
		"@protected": true,
		"AgentPassportCredential": map[string]any{
			"@id": v + "AgentPassportCredential",
			"@context": map[string]any{
				"@protected": true, "id": "@id", "type": "@type",
				"passport_id": t("passportId", "string"), "model_id": t("modelId", "string"), "operator": t("operator", "string"),
				"hardware_rooted": t("hardwareRooted", "boolean"), "weights_measured": t("weightsMeasured", "boolean"), "issued_at": t("issuedAt", "integer"),
				"weights_digest": t("weightsDigest", "string"), "system_prompt_digest": t("systemPromptDigest", "string"),
				"tool_manifest_digest": t("toolManifestDigest", "string"), "runtime_measurement": t("runtimeMeasurement", "string"),
				"_sd": map[string]any{"@id": v + "selectiveDisclosureDigest", "@container": "@set"},
			},
		},
	}}
}

// AgentPassportContextDigest is the hex SHA-256 of the context document's canonical JSON (sorted keys).
func AgentPassportContextDigest() string {
	c, err := Canonicalize(AgentPassportContextDoc())
	if err != nil {
		panic(err) // a constant document of strings and booleans always canonicalizes
	}
	s := sha256.Sum256([]byte(c))
	return hex.EncodeToString(s[:])
}

// ResolveAgentPassportContext returns the context document for its exact IRI, nil for anything else.
func ResolveAgentPassportContext(iri string) map[string]any {
	if iri == AgentPassportContext {
		return AgentPassportContextDoc()
	}
	return nil
}

// vcJSON is JSON.stringify (lone surrogates escaped; member order is irrelevant here, so keys are sorted).
func vcJSON(v any) (string, error) {
	out, ok := canonicalLenient(v)
	if !ok {
		return "", errors.New("pca-vc: value is not JSON-serializable")
	}
	return out, nil
}

func vcSha(s string) string {
	d := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(d[:])
}

// PassportToVCArgs: the issuer's Ed25519 seed, the issuer and subject DIDs (nil = left out), an optional lifetime and the clock
// (epoch seconds, nil = the wall clock).
type PassportToVCArgs struct {
	IssuerSeed            []byte
	IssuerDid, SubjectDid *string
	TTLSec                *float64
	NowSec                *float64
}

// PassportToVC issues an agent passport as an SD-JWT VC (typ vc+sd-jwt): the digest fields become salted disclosures, the rest
// is the credentialSubject. The result is jwt~disclosure~...~.
func PassportToVC(passport map[string]any, a PassportToVCArgs) (string, error) {
	if passport == nil {
		return "", errors.New("pca-vc: passport is required")
	}
	if len(a.IssuerSeed) != ed25519.SeedSize {
		return "", errors.New("pca-vc: the issuer key must be a 32-byte Ed25519 seed")
	}
	var disclosures []string
	var sd []any
	for _, f := range vcSDFields {
		v, has := passport[f]
		if !has {
			continue
		}
		salt := make([]byte, 16)
		rand.Read(salt)
		j, err := vcJSON([]any{base64.RawURLEncoding.EncodeToString(salt), f, v})
		if err != nil {
			return "", err
		}
		d := base64.RawURLEncoding.EncodeToString([]byte(j))
		disclosures = append(disclosures, d)
		sd = append(sd, vcSha(d))
	}
	cs := map[string]any{}
	if a.SubjectDid != nil {
		cs["id"] = *a.SubjectDid
	}
	for from, to := range map[string]string{"id": "passport_id", "model_id": "model_id", "operator": "operator", "hardware_rooted": "hardware_rooted", "issued_at": "issued_at", "weights_measured": "weights_measured"} {
		if v, has := passport[from]; has {
			cs[to] = v
		}
	}
	if len(sd) > 0 {
		cs["_sd"] = sd
	}
	now := math.Floor(float64(time.Now().UnixMilli()) / 1000)
	if a.NowSec != nil {
		now = *a.NowSec
	}
	payload := map[string]any{"vc": map[string]any{"@context": []any{VCContext, AgentPassportContext}, "type": []any{"VerifiableCredential", AgentPassportVCType},
		"credentialSubject": cs}, "iat": jsNumber(now)}
	if len(sd) > 0 {
		payload["_sd_alg"] = "sha-256"
	}
	if a.IssuerDid != nil {
		payload["iss"] = *a.IssuerDid
	}
	if a.SubjectDid != nil {
		payload["sub"] = *a.SubjectDid
	}
	if a.TTLSec != nil {
		exp := now + *a.TTLSec
		if math.IsNaN(exp) || math.IsInf(exp, 0) {
			return "", errors.New("pca-vc: ttlSec must be a finite number")
		}
		payload["exp"] = jsNumber(exp)
	}
	pj, err := vcJSON(payload)
	if err != nil {
		return "", err
	}
	jwt, err := SignCompactEdDSA(`{"alg":"EdDSA","typ":"vc+sd-jwt"}`, rawJSON(pj), a.IssuerSeed)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, p := range append([]string{jwt}, disclosures...) {
		b.WriteString(p + "~")
	}
	return b.String(), nil
}

// VerifyPassportVCOptions: ExpectedIssuerDid (nil = any issuer) and the clock (epoch seconds, nil = the wall clock).
type VerifyPassportVCOptions struct {
	ExpectedIssuerDid *string
	NowSec            *float64
}

// VerifyPassportVC verifies an agent-passport SD-JWT VC under the issuer's Ed25519 key and returns {passport, issuerDid,
// subjectDid}; every disclosure must match a digest, appear once, and name one of the digest fields.
func VerifyPassportVC(vc string, issuerPub []byte, o VerifyPassportVCOptions) (map[string]any, error) {
	parts := strings.Split(vc, "~")
	jwt := parts[0]
	if jwt == "" {
		return nil, errors.New("pca-vc: empty SD-JWT")
	}
	var disclosures []string
	for _, p := range parts[1:] {
		if p != "" {
			disclosures = append(disclosures, p)
		}
	}
	if _, err := AssertCanonicalCompactJWS(jwt, 3, 0, true); err != nil {
		return nil, err
	}
	for _, d := range disclosures {
		if _, err := decodeCanonicalBase64url(d); err != nil {
			return nil, err
		}
	}
	if len(issuerPub) != ed25519.PublicKeySize {
		return nil, errors.New("pca-vc: the issuer key must be a 32-byte Ed25519 public key")
	}
	key := &JOSEKey{Kty: "OKP", Crv: "Ed25519", Ed25519: ed25519.PublicKey(issuerPub)}
	h, p, err := JWTVerify(jwt, func(map[string]any) (*JOSEKey, error) { return key, nil }, JWTVerifyOptions{Algorithms: []string{"EdDSA"}, NowSec: o.NowSec}, float64(time.Now().Unix()))
	if err != nil {
		return nil, err
	}
	if h["typ"] != "vc+sd-jwt" {
		return nil, errors.New("pca-vc: header typ must be 'vc+sd-jwt'")
	}
	vcl, ok := p["vc"].(map[string]any)
	if !ok {
		return nil, errors.New("pca-vc: missing vc claim")
	}
	ctx, ok := vcl["@context"].([]any)
	if !ok || len(ctx) == 0 || ctx[0] != VCContext {
		return nil, errors.New("pca-vc: @context must begin with " + VCContext)
	}
	if len(ctx) != 2 || ctx[1] != AgentPassportContext {
		return nil, errors.New("pca-vc: @context must be exactly [" + VCContext + ", " + AgentPassportContext + "]")
	}
	types, _ := vcl["type"].([]any)
	hasType := func(t string) bool {
		for _, x := range types {
			if x == t {
				return true
			}
		}
		return false
	}
	if !hasType("VerifiableCredential") || !hasType(AgentPassportVCType) {
		return nil, errors.New("pca-vc: type must include VerifiableCredential and " + AgentPassportVCType)
	}
	cs, ok := vcl["credentialSubject"].(map[string]any)
	if !ok {
		return nil, errors.New("pca-vc: missing credentialSubject")
	}
	if _, has := cs["_sd_alg"]; has {
		return nil, errors.New("pca-vc: _sd_alg must be a top-level claim")
	}
	if a, has := p["_sd_alg"]; has && a != "sha-256" {
		return nil, errors.New("pca-vc: unsupported _sd_alg (require sha-256)")
	}
	sdList := map[string]bool{}
	if l, ok := cs["_sd"].([]any); ok {
		for _, x := range l {
			if s, ok := x.(string); ok {
				sdList[s] = true
			}
		}
	}
	recovered := map[string]string{}
	seen := map[string]bool{}
	for _, d := range disclosures {
		digest := vcSha(d)
		if !sdList[digest] {
			return nil, errors.New("pca-vc: disclosure does not match any _sd digest")
		}
		if seen[digest] {
			return nil, errors.New("pca-vc: duplicate disclosure")
		}
		seen[digest] = true
		raw, _ := base64.RawURLEncoding.DecodeString(d)
		dv, err := ParseNoDuplicates(string(raw)) // JSON.parse keeps the last repeated member: refuse it (numbers stay as written)
		arr, ok := dv.([]any)
		if err != nil || !ok || len(arr) != 3 {
			return nil, errors.New("pca-vc: malformed disclosure")
		}
		name, ok := arr[1].(string)
		if !ok {
			return nil, errors.New("pca-vc: expected string for disclosure name")
		}
		known := false
		for _, f := range vcSDFields {
			known = known || f == name
		}
		if !known {
			return nil, fmt.Errorf("pca-vc: unexpected disclosure claim '%s'", name)
		}
		if _, dup := recovered[name]; dup {
			return nil, fmt.Errorf("pca-vc: disclosure claim '%s' appears more than once", name)
		}
		val, ok := arr[2].(string)
		if !ok {
			return nil, errors.New("pca-vc: expected string for disclosure value")
		}
		recovered[name] = val
	}
	passport := map[string]any{}
	for _, f := range []struct{ to, from, kind string }{{"id", "passport_id", "string"}, {"model_id", "model_id", "string"}, {"operator", "operator", "string"},
		{"hardware_rooted", "hardware_rooted", "boolean"}, {"issued_at", "issued_at", "number"}} {
		v := cs[f.from]
		if !vcIsKind(v, f.kind) {
			return nil, fmt.Errorf("pca-vc: expected %s for %s", f.kind, f.from)
		}
		passport[f.to] = v
	}
	if v, has := cs["weights_measured"]; has {
		if _, ok := v.(bool); !ok {
			return nil, errors.New("pca-vc: expected boolean for weights_measured")
		}
		passport["weights_measured"] = v
	}
	for _, f := range vcSDFields {
		if v, has := recovered[f]; has {
			passport[f] = v
		}
	}
	iss, ok := p["iss"].(string)
	if !ok {
		return nil, errors.New("pca-vc: expected string for iss")
	}
	sub, ok := cs["id"].(string)
	if !ok {
		return nil, errors.New("pca-vc: expected string for credentialSubject.id")
	}
	if p["sub"] != sub {
		return nil, errors.New("pca-vc: sub does not match credentialSubject.id")
	}
	if o.ExpectedIssuerDid != nil && iss != *o.ExpectedIssuerDid {
		return nil, errors.New("pca-vc: iss does not match expectedIssuerDid")
	}
	return map[string]any{"passport": passport, "issuerDid": iss, "subjectDid": sub}, nil
}

func vcIsKind(v any, kind string) bool {
	switch kind {
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	}
	_, ok := jsNum(v)
	return ok
}

// ---- RFC 9421 -----------------------------------------------------------------------------------------------------------------

// HTTPHeader is one request header, in order (a later header whose lower-cased name repeats an earlier one replaces it).
type HTTPHeader struct{ Name, Value string }

func vcNormalizeHeaders(hs []HTTPHeader) map[string]string {
	out := map[string]string{}
	for _, h := range hs {
		out[cases.Lower(language.Und).String(h.Name)] = h.Value
	}
	return out
}

func vcComponent(name, method, url string, headers map[string]string) (string, error) {
	switch name {
	case "@method":
		return cases.Upper(language.Und).String(method), nil
	case "@target-uri":
		return url, nil
	case "@authority":
		return whatwgHost(url)
	}
	v, ok := headers[name]
	if !ok {
		return "", fmt.Errorf("pca-vc: covered header '%s' absent from request", name)
	}
	return jsTrim(v), nil
}

func vcSignatureBase(components []string, params, method, url string, headers map[string]string) (string, error) {
	var lines []string
	for _, c := range components {
		v, err := vcComponent(c, method, url, headers)
		if err != nil {
			return "", err
		}
		lines = append(lines, `"`+c+`": `+v)
	}
	lines = append(lines, `"@signature-params": `+params)
	return strings.Join(lines, "\n"), nil
}

// SignRequestArgs: Created nil = the wall clock (epoch seconds); SignatureAgent non-nil adds the Web Bot Auth Signature-Agent
// header (quoted) and tag.
type SignRequestArgs struct {
	Method, URL    string
	Headers        []HTTPHeader
	Seed           []byte
	KeyID          string
	Created        *float64
	SignatureAgent *string
}

// SignRequestMessage signs @method, @target-uri and every header (sorted) with Ed25519 under label sig1. It returns
// {signatureInput, signature, signatureAgent?}.
func SignRequestMessage(a SignRequestArgs) (map[string]any, error) {
	created := math.Floor(float64(time.Now().UnixMilli()) / 1000)
	if a.Created != nil {
		created = *a.Created
	}
	headers := vcNormalizeHeaders(a.Headers)
	if _, ok := headers["host"]; !ok {
		h, err := whatwgHost(a.URL)
		if err != nil {
			return nil, err
		}
		headers["host"] = h
	}
	if a.SignatureAgent != nil {
		headers["signature-agent"] = `"` + *a.SignatureAgent + `"`
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool { return slices.Compare(utf16Units(names[i]), utf16Units(names[j])) < 0 })
	components := append([]string{"@method", "@target-uri"}, names...)
	quoted := make([]string, len(components))
	for i, c := range components {
		quoted[i] = `"` + c + `"`
	}
	params := "(" + strings.Join(quoted, " ") + ");created=" + jsNumberString(created) + `;keyid="` + a.KeyID + `";alg="ed25519"`
	if a.SignatureAgent != nil {
		params += `;tag="web-bot-auth"`
	}
	base, err := vcSignatureBase(components, params, a.Method, a.URL, headers)
	if err != nil {
		return nil, err
	}
	kp, err := KeyPairFromSeed(a.Seed)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"signatureInput": "sig1=" + params, "signature": "sig1=:" + base64.StdEncoding.EncodeToString(kp.Sign([]byte(wellFormedUTF8(base)))) + ":"}
	if a.SignatureAgent != nil {
		out["signatureAgent"] = `"` + *a.SignatureAgent + `"`
	}
	return out, nil
}

// VerifyRequestArgs: RequiredComponents must all be covered; MaxAgeSec non-nil requires a created parameter within MaxAgeSec in
// the past and at most 5 s in the future of NowSec (nil = the wall clock); SignatureAgent supplies a covered signature-agent
// header the request lacks.
type VerifyRequestArgs struct {
	Method, URL        string
	Headers            []HTTPHeader
	SignatureInput     string
	Signature          string
	SignatureAgent     *string
	RequiredComponents []string
	MaxAgeSec, NowSec  *float64
}

var (
	vcComponentTok = regexp.MustCompile(`^"(.*)"$`)
	vcAlgParam     = regexp.MustCompile(`;alg="([^"]*)"`)
	vcCreatedParam = regexp.MustCompile(`;created=(\d+)`)
	vcWrappedSig   = regexp.MustCompile(`^:([^\n\r\x{2028}\x{2029}]*):$`)
)

func vcParseComponents(params string) ([]string, bool) {
	open, close := strings.IndexByte(params, '('), strings.IndexByte(params, ')')
	if open != 0 || close < 0 {
		return nil, false
	}
	inner := jsTrim(params[open+1 : close])
	if inner == "" {
		return []string{}, true
	}
	var out []string
	for _, tok := range jsWSRun.Split(inner, -1) {
		m := vcComponentTok.FindStringSubmatch(tok)
		if m == nil {
			return nil, false
		}
		out = append(out, m[1])
	}
	return out, true
}

// nodeBase64Lenient decodes as Node's Buffer.from(s, "base64"): both alphabets, other characters skipped, stop at '='.
func nodeBase64Lenient(s string) []byte {
	var clean []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '=':
			i = len(s)
		case c == '-':
			clean = append(clean, '+')
		case c == '_':
			clean = append(clean, '/')
		case c == '+' || c == '/' || c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z':
			clean = append(clean, c)
		}
	}
	if len(clean)%4 == 1 {
		clean = clean[:len(clean)-1]
	}
	out, _ := base64.RawStdEncoding.DecodeString(string(clean)) // non-strict: non-zero trailing bits are ignored, as Node does
	return out
}

// VerifyRequestSignature verifies an RFC 9421 Ed25519 signature; any malformed input is false.
func VerifyRequestSignature(a VerifyRequestArgs, pub []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	eq := strings.IndexByte(a.SignatureInput, '=')
	if eq < 0 {
		return false
	}
	params := a.SignatureInput[eq+1:]
	components, ok := vcParseComponents(params)
	if !ok {
		return false
	}
	for _, need := range a.RequiredComponents {
		found := false
		for _, c := range components {
			found = found || c == need
		}
		if !found {
			return false
		}
	}
	if m := vcAlgParam.FindStringSubmatch(params); m != nil && m[1] != "ed25519" {
		return false
	}
	if a.MaxAgeSec != nil {
		m := vcCreatedParam.FindStringSubmatch(params)
		if m == nil {
			return false
		}
		now := math.Floor(float64(time.Now().UnixMilli()) / 1000)
		if a.NowSec != nil {
			now = *a.NowSec
		}
		c := jsStringToNumber(m[1])
		if !(finite(now) && finite(c) && now-c <= *a.MaxAgeSec) || !(c-now <= 5) {
			return false
		}
	}
	headers := vcNormalizeHeaders(a.Headers)
	if _, ok := headers["host"]; !ok {
		h, err := whatwgHost(a.URL)
		if err != nil {
			return false
		}
		headers["host"] = h
	}
	covered := false
	for _, c := range components {
		covered = covered || c == "signature-agent"
	}
	if _, has := headers["signature-agent"]; covered && !has {
		if a.SignatureAgent == nil {
			return false
		}
		headers["signature-agent"] = *a.SignatureAgent
	}
	base, err := vcSignatureBase(components, params, a.Method, a.URL, headers)
	if err != nil {
		return false
	}
	se := strings.IndexByte(a.Signature, '=')
	if se < 0 {
		return false
	}
	m := vcWrappedSig.FindStringSubmatch(jsTrim(a.Signature[se+1:]))
	if m == nil {
		return false
	}
	sig := nodeBase64Lenient(m[1])
	return len(sig) == ed25519.SignatureSize && ed25519.Verify(ed25519.PublicKey(pub), []byte(wellFormedUTF8(base)), sig)
}
