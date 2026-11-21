package pca

// Per-session attestation freshness and channel binding: emits attestation evidence as an Entity Attestation Token (RFC 9711, a
// compact JWS with the eat+jwt typ), binds it to a live channel and a fresh nonce (IETF SEAT / RA-TLS), verifies it, and appraises
// it with the RATS (RFC 9334) split of evidence, reference values and endorsements into a trust tier. Options and results are
// JSON-shaped maps with the reference's member names, so a claim set or verdict is JSON-identical to the reference. The AMD
// hardware root stays in attest_amd.go (a classical ECDSA/RSA chain, labelled, never upgraded).

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	EatTyp                   = "eat+jwt"
	EatDefaultAlg            = "EdDSA"
	EatDefaultMaxAgeMs       = 5 * 60_000
	EatChannelBindingDomain  = "atlas-pca/eat-channel/v1"
	EatAmdSevSnpSignedRegion = 0x2a0
	EatAmdHardwareRootLabel  = "amd-sev-snp/ecdsa-p384 (VCEK→ASK→ARK; classical hardware root, not post-quantum)"
	eatMaxBytes              = 1 << 20
)

// EatKnownReportVersions are the SEV-SNP report versions the tolerant parser maps fully.
var EatKnownReportVersions = []int{2, 3, 5}

var eatDbgstatValues = []string{"enabled", "disabled", "disabled-since-boot", "disabled-permanently", "disabled-fully-and-permanently"}

// ---------------------------------------------------------------------------------------------------------------- helpers

func eatGet(v any, k string) (any, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	x, ok := m[k]
	return x, ok
}

// eatTruthy is JavaScript truthiness over a JSON value.
func eatTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	}
	if f, ok := jsNum(v); ok {
		return f != 0 && !math.IsNaN(f)
	}
	return true
}

func eatIsNum(v any) bool { _, ok := jsNum(v); return ok }

func eatFinite(v any) (float64, bool) { return asFinite(v) }

func eatNowMs() float64 { return float64(time.Now().UnixMilli()) }

func eatStrEq(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// eatCtEq is the length-checked constant-time compare of a claim against an expected string; a non-string claim throws in the
// reference, so it is an error here.
func eatCtEq(a any, b string) (bool, error) {
	s, ok := a.(string)
	if !ok {
		return false, errors.New("the first argument must be of type string")
	}
	return eatStrEq(s, b), nil
}

// eatIncludes is Array.prototype.includes over a JSON list for a scalar (nil = undefined/absent never matches a JSON element).
func eatIncludes(list []any, v any, present bool) bool {
	if !present {
		return false
	}
	for _, x := range list {
		switch a := x.(type) {
		case string:
			if b, ok := v.(string); ok && a == b {
				return true
			}
		case bool:
			if b, ok := v.(bool); ok && a == b {
				return true
			}
		case nil:
			if v == nil {
				return true
			}
		default:
			if fa, ok := jsNum(x); ok {
				if fb, ok := jsNum(v); ok && fa == fb {
					return true
				}
			}
		}
	}
	return false
}

func eatNonEmptyList(v any) ([]any, bool) {
	l, ok := v.([]any)
	return l, ok && len(l) > 0
}

func eatInStrings(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------------------------------------------- JSON.stringify in insertion order

type eatKV struct {
	k string
	v any
}

// eatOrdered is an object serialized in the listed member order.
type eatOrdered []eatKV

func eatStringify(sb *strings.Builder, v any) error {
	switch t := v.(type) {
	case eatOrdered:
		sb.WriteByte('{')
		for i, kv := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			s, _ := canonicalLenient(kv.k)
			sb.WriteString(s + ":")
			if err := eatStringify(sb, kv.v); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	case map[string]any:
		sb.WriteByte('{')
		for i, k := range jsKeys(t) {
			if i > 0 {
				sb.WriteByte(',')
			}
			s, _ := canonicalLenient(k)
			sb.WriteString(s + ":")
			if err := eatStringify(sb, t[k]); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	case []any:
		sb.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := eatStringify(sb, x); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	default:
		s, ok := canonicalLenient(v)
		if !ok {
			return fmt.Errorf("not serializable: %T", v)
		}
		sb.WriteString(s)
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------------------- nonce + evidence projection

func eatBase36(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	s := strconv.FormatInt(n, 36)
	if neg {
		return "-" + s
	}
	return s
}

// EatIssueNonce is a fresh single-use challenge: b64u(random) "." base36(now). nowMs < 0 = the wall clock; nbytes below 16 is
// raised to 16 (the default 32 when 0).
func EatIssueNonce(nowMs int64, nbytes int) (map[string]any, error) {
	if nowMs < 0 {
		nowMs = time.Now().UnixMilli()
	}
	if nbytes == 0 {
		nbytes = 32
	}
	if nbytes < 16 {
		nbytes = 16
	}
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return map[string]any{"value": b64.EncodeToString(b) + "." + eatBase36(nowMs), "issuedAt": jsNumber(float64(nowMs))}, nil
}

func eatEvidenceOf(version uint32, r *snpReport) map[string]any {
	return map[string]any{
		"version":      jsNumber(float64(version)),
		"measurement":  toHexLower(r.measurement),
		"reported_tcb": strconv.FormatUint(r.reportedTcb, 10),
		"guest_svn":    jsNumber(float64(r.guestSvn)),
		"chip_id":      toHexLower(r.chipID),
		"debug":        r.policy&snpPolicyDebugBit != 0,
	}
}

func eatMeasuredOf(r *snpReport) map[string]any {
	return map[string]any{
		"model_id": "", "weights_digest": "", "weights_measured": false,
		"runtime_measurement": toHexLower(r.measurement), "operator": toHexLower(r.chipID),
	}
}

// EatParseReportTolerant parses an SEV-SNP report across format versions, degrading to the version-stable header instead of
// failing. A known version with a complete buffer gets the full parse (degraded false).
func EatParseReportTolerant(b []byte) map[string]any {
	const (
		offVersion, offGuestSvn, offPolicy, offMeasurement, offReportedTcb, offChipID = 0x000, 0x004, 0x008, 0x090, 0x180, 0x1a0
		fullMin                                                                       = snpOffSigS + 72
	)
	notes := []any{}
	if len(b) < offVersion+4 {
		return map[string]any{"ok": false, "version": jsNumber(0), "known": false, "degraded": true,
			"notes": []any{"buffer too short to read the report version"}, "hasReport": false}
	}
	le := binary.LittleEndian
	version := le.Uint32(b[offVersion:])
	known := false
	for _, v := range EatKnownReportVersions {
		if uint32(v) == version {
			known = true
		}
	}
	switch {
	case known && len(b) >= fullMin:
		if r, err := parseSnpReport(b); err == nil {
			return map[string]any{"ok": true, "version": jsNumber(float64(version)), "known": true, "degraded": false, "notes": notes,
				"hasReport": true, "evidence": eatEvidenceOf(version, r), "measured": eatMeasuredOf(r)}
		} else {
			notes = append(notes, "full parse failed, falling back to the stable header: "+err.Error())
		}
	case !known:
		notes = append(notes, fmt.Sprintf("unknown report version %d — parsing version-stable header fields only (newer firmware, e.g. GCP 2025-10-27, may relocate version-specific fields)", version))
	default:
		notes = append(notes, fmt.Sprintf("buffer length %d < full report %d — degraded header-only parse", len(b), fullMin))
	}
	if len(b) < offMeasurement+48 {
		return map[string]any{"ok": false, "version": jsNumber(float64(version)), "known": known, "degraded": true,
			"notes": append(notes, "buffer too short to read the launch measurement"), "hasReport": false}
	}
	ev := map[string]any{"version": jsNumber(float64(version)), "measurement": toHexLower(b[offMeasurement : offMeasurement+48]), "degraded": true}
	if len(b) >= offGuestSvn+4 {
		ev["guest_svn"] = jsNumber(float64(le.Uint32(b[offGuestSvn:])))
	}
	if len(b) >= offPolicy+8 {
		ev["debug"] = le.Uint64(b[offPolicy:])&snpPolicyDebugBit != 0
	}
	if len(b) >= offReportedTcb+8 {
		ev["reported_tcb"] = strconv.FormatUint(le.Uint64(b[offReportedTcb:]), 10)
	}
	if len(b) >= offChipID+64 {
		ev["chip_id"] = toHexLower(b[offChipID : offChipID+64])
	}
	return map[string]any{"ok": true, "version": jsNumber(float64(version)), "known": known, "degraded": true, "notes": notes,
		"hasReport": false, "evidence": ev}
}

// ---------------------------------------------------------------------------------------------------------------- channel binding

// EatDeriveChannelCnf is cnf.tls_exporter = b64u(sha256(DOMAIN || channelId)) (RA-TLS), plus jkt when a thumbprint is given.
func EatDeriveChannelCnf(channelID string, holderKeyThumbprint string) (map[string]any, error) {
	if channelID == "" {
		return nil, errors.New("deriveChannelCnf: channelId is required")
	}
	h := sha256.Sum256([]byte(EatChannelBindingDomain + channelID))
	cnf := map[string]any{"tls_exporter": b64.EncodeToString(h[:])}
	if holderKeyThumbprint != "" {
		cnf["jkt"] = holderKeyThumbprint
	}
	return cnf, nil
}

// EatBindChannel binds evidence to a TLS channel id and a per-session freshness nonce (the inputs of EatBuild).
func EatBindChannel(evidence any, channelID, nonce string) (map[string]any, error) {
	if nonce == "" {
		return nil, errors.New("bindChannel: a per-session nonce is required for freshness")
	}
	cnf, err := EatDeriveChannelCnf(channelID, "")
	if err != nil {
		return nil, err
	}
	return map[string]any{"evidence": evidence, "nonce": nonce, "cnf": cnf}, nil
}

// ---------------------------------------------------------------------------------------------------------------- build

// EatBuild signs an EAT (compact JWS, typ eat+jwt). args carries issuer, nonce, alg (default EdDSA), channelId and / or
// channelBinding, now (epoch ms), and the optional ueid / sueid / oemid / dbgstat / measurements / measured / sevsnp claims.
// key is an Ed25519 seed ([]byte, 32) for EdDSA or a *ecdsa.PrivateKey on P-256 for ES256. It needs a nonce AND a channel
// binding: an unbound EAT would re-open the replay gap.
func EatBuild(args map[string]any, key any) (string, error) {
	issuer, _ := args["issuer"].(string)
	if issuer == "" {
		return "", errors.New("buildEAT: issuer is required")
	}
	nonce, _ := args["nonce"].(string)
	if nonce == "" {
		return "", errors.New("buildEAT: nonce (eat_nonce) is required for freshness")
	}
	alg := EatDefaultAlg
	if a, present := args["alg"]; present && a != nil {
		s, ok := a.(string)
		if !ok || (s != "EdDSA" && s != "ES256") {
			return "", fmt.Errorf("buildEAT: unsupported alg '%s'", jsAnyString(a))
		}
		alg = s
	}
	var cnf eatOrdered
	var te, jkt string
	var hasTe, hasJkt bool
	if cid, present := args["channelId"]; present && cid != nil {
		s, _ := cid.(string)
		d, err := EatDeriveChannelCnf(s, "")
		if err != nil {
			return "", err
		}
		te, hasTe = d["tls_exporter"].(string), true
	}
	if cb, present := args["channelBinding"]; present && cb != nil {
		if s, ok := eatMember(cb, "tls_exporter").(string); ok {
			te, hasTe = s, true
		}
		if s, ok := eatMember(cb, "jkt").(string); ok {
			jkt, hasJkt = s, true
		}
	}
	if hasTe {
		cnf = append(cnf, eatKV{"tls_exporter", te})
	}
	if hasJkt {
		cnf = append(cnf, eatKV{"jkt", jkt})
	}
	if !hasTe && !hasJkt {
		return "", errors.New("buildEAT: a channel binding (channelId or channelBinding with a TLS exporter / holder-key thumbprint) is required (RA-TLS) — refusing to emit unbound evidence")
	}
	iatMs := eatNowMs()
	if f, ok := eatFinite(args["now"]); ok {
		iatMs = f
	}
	claims := eatOrdered{{"iss", issuer}, {"iat", jsNumber(math.Floor(iatMs / 1000))}, {"eat_nonce", nonce}, {"cnf", cnf}}
	for _, k := range []string{"ueid", "sueid", "oemid", "dbgstat", "measurements", "measured", "sevsnp"} {
		if v, present := args[k]; present {
			claims = append(claims, eatKV{k, v})
		}
	}
	var hb, pb strings.Builder
	if err := eatStringify(&hb, eatOrdered{{"alg", alg}, {"typ", EatTyp}}); err != nil {
		return "", err
	}
	if err := eatStringify(&pb, claims); err != nil {
		return "", err
	}
	input := b64.EncodeToString([]byte(hb.String())) + "." + b64.EncodeToString([]byte(pb.String()))
	sig, err := eatSign(alg, key, []byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + b64.EncodeToString(sig), nil
}

func eatMember(v any, k string) any { x, _ := eatGet(v, k); return x }

func eatSign(alg string, key any, input []byte) ([]byte, error) {
	if alg == "EdDSA" {
		seed, ok := key.([]byte)
		if !ok || len(seed) != ed25519.SeedSize {
			return nil, errors.New("an EdDSA token is signed with a 32-byte Ed25519 seed")
		}
		return ed25519.Sign(ed25519.NewKeyFromSeed(seed), input), nil
	}
	k, ok := key.(*ecdsa.PrivateKey)
	if !ok || k.Curve.Params().Name != "P-256" {
		return nil, errors.New("an ES256 token is signed with a P-256 key")
	}
	h := sha256.Sum256(input)
	r, s, err := ecdsa.Sign(rand.Reader, k, h[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// ---------------------------------------------------------------------------------------------------------------- verify

func eatParseCnf(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := map[string]any{}
	if s, ok := m["tls_exporter"].(string); ok {
		out["tls_exporter"] = s
	}
	if s, ok := m["jkt"].(string); ok {
		out["jkt"] = s
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func eatParseMeasurements(v any) any {
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	out := []any{}
	for _, e := range l {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		t, ok1 := m["type"].(string)
		val, ok2 := m["value"].(string)
		if ok1 && ok2 {
			out = append(out, map[string]any{"type": t, "value": val})
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func eatParseMeasured(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := map[string]any{}
	for _, k := range []string{"model_id", "weights_digest", "runtime_measurement", "operator"} {
		s, ok := m[k].(string)
		if !ok {
			return nil
		}
		out[k] = s
	}
	if b, ok := m["weights_measured"].(bool); ok {
		out["weights_measured"] = b
	}
	for _, k := range []string{"system_prompt_digest", "tool_manifest_digest"} {
		if s, ok := m[k].(string); ok {
			out[k] = s
		}
	}
	return out
}

func eatParseSevSnp(v any) any {
	m, ok := v.(map[string]any)
	if !ok || !eatIsNum(m["version"]) {
		return nil
	}
	meas, ok := m["measurement"].(string)
	if !ok {
		return nil
	}
	out := map[string]any{"version": m["version"], "measurement": meas}
	switch t := m["reported_tcb"].(type) {
	case string:
		out["reported_tcb"] = t
	case map[string]any:
		o := map[string]any{}
		for _, k := range []string{"bootloader", "tee", "snp", "microcode"} {
			if eatIsNum(t[k]) {
				o[k] = t[k]
			}
		}
		out["reported_tcb"] = o
	default:
		if _, ok := eatFinite(m["reported_tcb"]); ok {
			out["reported_tcb"] = m["reported_tcb"]
		}
	}
	if eatIsNum(m["guest_svn"]) {
		out["guest_svn"] = m["guest_svn"]
	}
	if s, ok := m["chip_id"].(string); ok {
		out["chip_id"] = s
	}
	if b, ok := m["debug"].(bool); ok {
		out["debug"] = b
	}
	if b, ok := m["degraded"].(bool); ok {
		out["degraded"] = b
	}
	return out
}

// EatVerify verifies an EAT's signature, typ and iss and parses it into claims. It errors on an invalid signature, wrong key,
// failed iss / typ check, unsupported alg or a missing iss / iat. A claim of the wrong type is dropped, so a later check fails
// closed. Options: algorithms, typ, requireTyp (false = skip), issuer (string or list). This proves AUTHENTICITY only.
func EatVerify(eat any, key *JOSEKey, opts map[string]any) (map[string]any, error) {
	if _, ok := eat.(string); !ok {
		return nil, errors.New("EAT invalid: token is not a string")
	}
	parsed, err := AssertCanonicalCompactJWS(eat, 3, eatMaxBytes, true)
	if err != nil {
		return nil, fmt.Errorf("EAT invalid: %s", err.Error())
	}
	header, payload := parsed.Header, parsed.Payload
	alg, _ := header["alg"].(string)
	if alg != "EdDSA" && alg != "ES256" {
		return nil, errors.New("EAT invalid: missing or unsupported `alg` header")
	}
	allowed := []any{"EdDSA", "ES256"}
	allowedOK := false
	if a, present := opts["algorithms"]; present && a != nil {
		switch l := a.(type) {
		case []any:
			allowed = l
		case string: // JavaScript's String.prototype.includes: a substring test
			allowedOK = strings.Contains(l, alg)
			allowed = nil
		default:
			return nil, errors.New("allowed.includes is not a function")
		}
	}
	if allowed != nil {
		allowedOK = eatIncludes(allowed, alg, true)
	}
	if !allowedOK {
		return nil, fmt.Errorf("EAT invalid: alg %s not in the allowed set", alg)
	}
	if rt, present := opts["requireTyp"]; !(present && rt == false) {
		want := EatTyp
		if w, present := opts["typ"]; present && w != nil {
			want = jsAnyString(w)
		}
		typ, ok := header["typ"].(string)
		if !ok || normalizeTyp(typ) != normalizeTyp(want) {
			shown := "undefined"
			if t, present := header["typ"]; present {
				shown = jsAnyString(t)
			}
			return nil, fmt.Errorf("EAT invalid: typ %s is not %s", shown, want)
		}
	}
	sig, ok := DecodeB64uStrict(parsed.Segments[2], -1)
	if !ok || key == nil || !JOSEVerify(alg, key, []byte(parsed.Segments[0]+"."+parsed.Segments[1]), sig) {
		return nil, errors.New("EAT invalid: signature does not verify")
	}
	iss, ok := payload["iss"].(string)
	if !ok {
		return nil, errors.New("EAT invalid: missing or non-string `iss`")
	}
	if _, ok := eatFinite(payload["iat"]); !ok {
		return nil, errors.New("EAT invalid: missing or non-numeric `iat`")
	}
	if want, present := opts["issuer"]; present {
		list, isList := want.([]any)
		if !isList {
			list = []any{want}
		}
		if !eatIncludes(list, iss, true) {
			return nil, fmt.Errorf("EAT invalid: iss %s is not an accepted issuer", iss)
		}
	}
	claims := map[string]any{"iss": iss, "iat": payload["iat"]}
	if s, ok := payload["eat_nonce"].(string); ok {
		claims["eat_nonce"] = s
	}
	if c := eatParseCnf(payload["cnf"]); c != nil {
		claims["cnf"] = c
	}
	for _, k := range []string{"ueid", "sueid"} {
		if s, ok := payload[k].(string); ok {
			claims[k] = s
		}
	}
	if m := eatParseMeasurements(payload["measurements"]); m != nil {
		claims["measurements"] = m
	}
	if s, ok := payload["dbgstat"].(string); ok && eatInStrings(eatDbgstatValues, s) {
		claims["dbgstat"] = s
	}
	if s, ok := payload["oemid"].(string); ok {
		claims["oemid"] = s
	}
	if m := eatParseMeasured(payload["measured"]); m != nil {
		claims["measured"] = m
	}
	if m := eatParseSevSnp(payload["sevsnp"]); m != nil {
		claims["sevsnp"] = m
	}
	return claims, nil
}

// ---------------------------------------------------------------------------------------------------------------- freshness + channel

// EatVerifyFreshness is the anti-replay gate: eat_nonce must equal the server-issued challenge and iat must lie in
// [now - maxAgeMs, now] (plus clockSkewMs). A present clockSkewMs that is not a finite number is refused: it would disable the
// age window. Options: expectedNonce, maxAgeMs, now, clockSkewMs.
func EatVerifyFreshness(eat any, opts map[string]any) (map[string]any, error) {
	no := func(r string) (map[string]any, error) { return map[string]any{"ok": false, "reason": r}, nil }
	now := eatNowMs()
	if f, ok := eatFinite(opts["now"]); ok {
		now = f
	}
	skew := 0.0
	if sv, present := opts["clockSkewMs"]; present { // only an absent skew is `?? 0`: null is not a finite number
		f, ok := eatFinite(sv)
		if !ok {
			return no("invalid clockSkewMs (must be a finite number)")
		}
		skew = math.Max(0, f)
	}
	expected, _ := opts["expectedNonce"].(string)
	if expected == "" {
		return no("no expected (server-issued) nonce supplied (fail closed)")
	}
	nonce, _ := eatMember(eat, "eat_nonce").(string)
	if nonce == "" {
		return no("EAT carries no eat_nonce — cannot establish freshness (replayable)")
	}
	if !eatStrEq(nonce, expected) {
		return no("eat_nonce does not match the server-issued challenge (replayed or relayed evidence)")
	}
	iat, ok := eatFinite(eatMember(eat, "iat"))
	if !ok {
		return no("EAT has no valid iat (cannot establish age)")
	}
	maxAge, ok := eatFinite(opts["maxAgeMs"])
	if !ok || maxAge <= 0 {
		return no("invalid maxAgeMs")
	}
	iatMs := iat * 1000
	if iatMs-skew > now {
		return no("EAT iat is in the future")
	}
	if now-iatMs > maxAge+skew {
		return no("EAT is stale (iat older than maxAgeMs) — expired/replayed attestation")
	}
	return map[string]any{"ok": true}, nil
}

// EatVerifyChannelBinding (RA-TLS): every field of the expected cnf (derived from channelId and / or an explicit expectedCnf)
// must be present and equal in the token's cnf. No cnf, or one bound to another channel / key, fails closed.
func EatVerifyChannelBinding(eat any, opts map[string]any) (map[string]any, error) {
	no := func(r string) (map[string]any, error) { return map[string]any{"ok": false, "reason": r}, nil }
	expTe, expJkt := "", ""
	hasTe, hasJkt := false, false
	if cid, ok := opts["channelId"].(string); ok && cid != "" {
		d, _ := EatDeriveChannelCnf(cid, "")
		expTe, hasTe = d["tls_exporter"].(string), true
	}
	if e, present := opts["expectedCnf"]; present {
		if e == nil { // opts.expectedCnf !== undefined: null is read (and throws)
			return nil, errors.New("Cannot read properties of null (reading 'tls_exporter')")
		}
		if s, ok := eatMember(e, "tls_exporter").(string); ok {
			expTe, hasTe = s, true
		}
		if s, ok := eatMember(e, "jkt").(string); ok {
			expJkt, hasJkt = s, true
		}
	}
	if !hasTe && !hasJkt {
		return no("no expected channel binding supplied (fail closed)")
	}
	var cTe, cJkt any
	var hasCTe, hasCJkt bool
	if cnf, _ := eatGet(eat, "cnf"); eatTruthy(cnf) {
		cTe, hasCTe = eatGet(cnf, "tls_exporter")
		cJkt, hasCJkt = eatGet(cnf, "jkt")
	}
	if !hasCTe && !hasCJkt {
		return no("EAT carries no channel/key binding (cnf) — evidence is not bound to a live channel (RA-TLS)")
	}
	if hasTe {
		if !hasCTe {
			return no("TLS-exporter channel binding mismatch (evidence lifted to another channel?)")
		}
		eq, err := eatCtEq(cTe, expTe)
		if err != nil {
			return nil, err
		}
		if !eq {
			return no("TLS-exporter channel binding mismatch (evidence lifted to another channel?)")
		}
	}
	if hasJkt {
		if !hasCJkt {
			return no("holder-key thumbprint (cnf.jkt) mismatch")
		}
		eq, err := eatCtEq(cJkt, expJkt)
		if err != nil {
			return nil, err
		}
		if !eq {
			return no("holder-key thumbprint (cnf.jkt) mismatch")
		}
	}
	return map[string]any{"ok": true}, nil
}

// ---------------------------------------------------------------------------------------------------------------- appraisal

var eatDigitsRe = regexp.MustCompile(`^[0-9]+$`)

// eatPackTcb is a TCB version as a comparable integer, or nil for an unknown shape (fail closed). A boolean, array or null is
// not a TCB version.
func eatPackTcb(v any) *big.Int {
	if v == nil {
		return nil
	}
	if s, ok := v.(string); ok {
		t := jsTrim(s)
		if !eatDigitsRe.MatchString(t) {
			return nil // unknown / non-numeric format: fail closed (GCP firmware drift lesson)
		}
		n, _ := new(big.Int).SetString(t, 10)
		return n
	}
	if f, ok := jsNum(v); ok {
		if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
			return nil
		}
		n, _ := new(big.Float).SetFloat64(math.Floor(f)).Int(nil)
		return n
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	comp := func(k string) (uint64, bool) {
		x, present := m[k]
		if !present {
			return 0, true
		}
		f, ok := jsNum(x)
		if !ok || math.IsNaN(f) || math.IsInf(f, 0) || f != math.Floor(f) || (f == 0 && math.Signbit(f)) || f < 0 || f > 255 {
			return 0, false
		}
		return uint64(f), true
	}
	bl, ok1 := comp("bootloader")
	tee, ok2 := comp("tee")
	snp, ok3 := comp("snp")
	uc, ok4 := comp("microcode")
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return nil
	}
	return new(big.Int).SetUint64(bl | tee<<8 | snp<<48 | uc<<56)
}

func eatLC(v any) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", errors.New("s.toLowerCase is not a function")
	}
	return strings.ToLower(s), nil
}

func eatFind(list any, typeIn ...string) (any, bool, error) {
	if list == nil {
		return nil, false, nil
	}
	l, ok := list.([]any)
	if !ok {
		return nil, false, errors.New("eat.measurements?.find is not a function")
	}
	for _, e := range l {
		t, _ := eatMember(e, "type").(string)
		if eatInStrings(typeIn, t) {
			v, present := eatGet(e, "value")
			return v, present, nil
		}
	}
	return nil, false, nil
}

func eatLaunchMeasurement(eat any) (any, bool, error) {
	if measured, _ := eatGet(eat, "measured"); eatTruthy(measured) {
		if rm, ok := eatMember(measured, "runtime_measurement").(string); ok && rm != "" {
			return rm, true, nil
		}
	}
	if sev, _ := eatGet(eat, "sevsnp"); eatTruthy(sev) {
		if m, ok := eatMember(sev, "measurement").(string); ok {
			return m, true, nil
		}
	}
	ms, _ := eatGet(eat, "measurements")
	return eatFind(ms, "launch", "measurement")
}

func eatWeightsMeasurement(eat any) (any, bool, error) {
	if measured, _ := eatGet(eat, "measured"); eatTruthy(measured) {
		if wd, ok := eatMember(measured, "weights_digest").(string); ok && wd != "" {
			return wd, true, nil
		}
	}
	ms, _ := eatGet(eat, "measurements")
	return eatFind(ms, "weights")
}

// eatIsDebugDisabled is true / false when the debug status is known, else nil (the caller fails closed). A present dbgstat that
// is not an RFC 9711 value (hand-built claims) is unknown, never disabled.
func eatIsDebugDisabled(eat any) *bool {
	b := func(x bool) *bool { return &x }
	if d, present := eatGet(eat, "dbgstat"); present {
		s, ok := d.(string)
		if !ok || !eatInStrings(eatDbgstatValues, s) {
			return nil
		}
		return b(s != "enabled")
	}
	if sev, _ := eatGet(eat, "sevsnp"); eatTruthy(sev) {
		if dbg, ok := eatMember(sev, "debug").(bool); ok {
			return b(!dbg)
		}
	}
	return nil
}

// EatAppraise appraises an EAT's evidence against RATS reference values and endorsements (RFC 9334), kept as separate inputs.
// Tiers: affirming-hw-rooted > affirming > warning (acceptable); contraindicated (the measured state is actively bad) and
// rejected (empty policy, or a required input absent / in an unknown format) fail closed. Endorsements gate WHO (mismatch ->
// rejected); reference values gate WHAT (bad -> contraindicated, absent -> rejected). A reference throw (a hand-built value of
// the wrong type) is an error.
func EatAppraise(evidence, referenceValues, endorsements, extras any) (map[string]any, error) {
	reasons := []any{}
	result := func(tier, reason string) (map[string]any, error) {
		return map[string]any{"tier": tier, "trustworthy": tier == "affirming-hw-rooted" || tier == "affirming" || tier == "warning",
			"reasons": append(append([]any{}, reasons...), reason)}, nil
	}
	enIssuers, _ := eatGet(endorsements, "issuers")
	enOemids, _ := eatGet(endorsements, "oemids")
	enOperators, _ := eatGet(endorsements, "operators")
	issuersL, hasIssuers := eatNonEmptyList(enIssuers)
	oemidsL, hasOemids := eatNonEmptyList(enOemids)
	operatorsL, hasOperators := eatNonEmptyList(enOperators)
	rvMeas, _ := eatGet(referenceValues, "measurements")
	rvModels, _ := eatGet(referenceValues, "models")
	rvWeights, _ := eatGet(referenceValues, "weightsMeasurements")
	rvMinTcb, hasMinTcb := eatGet(referenceValues, "minTcb")
	rvMinSvn, _ := eatGet(referenceValues, "minGuestSvn")
	measL, hasMeas := eatNonEmptyList(rvMeas)
	modelsL, hasModels := eatNonEmptyList(rvModels)
	weightsL, hasWeights := eatNonEmptyList(rvWeights)
	reqMeasuredWeights := eatMember(referenceValues, "requireMeasuredWeights") == true
	reqDebug := eatMember(referenceValues, "requireDebugDisabled") == true
	minSvn, hasMinSvn := jsNum(rvMinSvn)
	if !(hasIssuers || hasOemids || hasOperators) && !(hasMeas || hasModels || hasWeights || reqMeasuredWeights || hasMinTcb || hasMinSvn || reqDebug) {
		return map[string]any{"tier": "rejected", "trustworthy": false,
			"reasons": []any{"empty appraisal policy: no endorsements or reference values to appraise against (fail closed)"}}, nil
	}
	iss, issPresent := eatGet(evidence, "iss")
	if hasIssuers {
		if !eatIncludes(issuersL, iss, issPresent) {
			return result("rejected", "issuer "+eatJSString(iss, issPresent)+" is not an endorsed attester")
		}
		reasons = append(reasons, "issuer endorsed")
	}
	if hasOemids {
		oemid, ok := eatMember(evidence, "oemid").(string)
		if !ok || !eatIncludes(oemidsL, oemid, true) {
			return result("rejected", "oemid absent or not endorsed (fail closed)")
		}
		reasons = append(reasons, "oemid endorsed")
	}
	if hasOperators {
		measured, _ := eatGet(evidence, "measured")
		op, ok := eatMember(measured, "operator").(string)
		if !ok || op == "" || !eatIncludes(operatorsL, op, true) {
			return result("rejected", "hardware operator absent or not endorsed (fail closed)")
		}
		reasons = append(reasons, "operator endorsed")
	}
	if hasMeas {
		m, present, err := eatLaunchMeasurement(evidence)
		if err != nil {
			return nil, err
		}
		if !present {
			return result("rejected", "no launch measurement in evidence to compare against reference values (fail closed)")
		}
		lm, err := eatLC(m)
		if err != nil {
			return nil, err
		}
		found := false
		for _, x := range measL {
			lx, err := eatLC(x)
			if err != nil {
				return nil, err
			}
			found = found || lx == lm
		}
		if !found {
			return result("contraindicated", "launch measurement not in reference values")
		}
		reasons = append(reasons, "launch measurement matches a reference value")
	}
	if hasModels {
		measured, _ := eatGet(evidence, "measured")
		model, ok := eatMember(measured, "model_id").(string)
		if !ok || model == "" {
			return result("rejected", "no model id in evidence (fail closed)")
		}
		if !eatIncludes(modelsL, model, true) {
			return result("contraindicated", "model id not in reference values (model swap?)")
		}
		reasons = append(reasons, "model id matches a reference value")
	}
	if reqMeasuredWeights {
		measured, _ := eatGet(evidence, "measured")
		if eatMember(measured, "weights_measured") != true {
			return result("contraindicated", "weights digest is not hardware-measured (require_measured_weights: self-asserted or host-asserted weights rejected)")
		}
		reasons = append(reasons, "weights digest is hardware-measured")
	}
	if hasWeights {
		w, present, err := eatWeightsMeasurement(evidence)
		if err != nil {
			return nil, err
		}
		if s, isStr := w.(string); !present || (isStr && s == "") {
			return result("rejected", "no measured-weights digest in evidence (fail closed)")
		}
		lw, err := eatLC(w)
		if err != nil {
			return nil, err
		}
		found := false
		for _, x := range weightsL {
			lx, err := eatLC(x)
			if err != nil {
				return nil, err
			}
			found = found || lx == lw
		}
		if !found {
			return result("contraindicated", "weights measurement not in reference values (model swap / fine-tune?)")
		}
		reasons = append(reasons, "weights measurement matches a reference value")
	}
	if hasMinTcb {
		minimum := eatPackTcb(rvMinTcb)
		if minimum == nil {
			return result("rejected", "reference minTcb is not a comparable TCB version")
		}
		sev, _ := eatGet(evidence, "sevsnp")
		raw, present := eatGet(sev, "reported_tcb")
		var got *big.Int
		if present {
			got = eatPackTcb(raw)
		}
		if got == nil {
			return result("rejected", "evidence TCB version is absent or an unknown format — failing closed (see 2025-10-27 GCP firmware drift)")
		}
		if got.Cmp(minimum) < 0 {
			return result("contraindicated", "reported TCB is below the reference minimum (downgrade / rollback)")
		}
		reasons = append(reasons, "TCB at or above reference minimum")
	}
	if hasMinSvn {
		sev, _ := eatGet(evidence, "sevsnp")
		svn, ok := eatFinite(eatMember(sev, "guest_svn"))
		if !ok {
			return result("rejected", "guest_svn absent (fail closed)")
		}
		if svn < minSvn {
			return result("contraindicated", fmt.Sprintf("guest_svn %s below reference minimum %s", jsLenientNumber(svn), jsLenientNumber(minSvn)))
		}
		reasons = append(reasons, "guest_svn at or above reference minimum")
	}
	if reqDebug {
		d := eatIsDebugDisabled(evidence)
		if d == nil {
			return result("rejected", "debug status unknown — failing closed")
		}
		if !*d {
			return result("contraindicated", "debug is enabled (host can inspect the guest — no confidentiality)")
		}
		reasons = append(reasons, "debug disabled")
	}
	if sev, _ := eatGet(evidence, "sevsnp"); eatTruthy(sev) && eatMember(sev, "degraded") == true {
		return map[string]any{"tier": "warning", "trustworthy": true,
			"reasons": append(reasons, "evidence came from a degraded (version-tolerant) parse — review")}, nil
	}
	if eatMember(extras, "hardwareVerified") == true {
		label := any(EatAmdHardwareRootLabel)
		if l, present := eatGet(extras, "hardwareRootLabel"); present && l != nil {
			label = l
		}
		return map[string]any{"tier": "affirming-hw-rooted", "trustworthy": true,
			"reasons": append(reasons, "AMD SEV-SNP report signature + VCEK→ASK→ARK chain verified — "+jsAnyString(label))}, nil
	}
	return map[string]any{"tier": "affirming", "trustworthy": true, "reasons": reasons}, nil
}

func eatJSString(v any, present bool) string {
	if !present {
		return "undefined"
	}
	return jsAnyString(v)
}

// ---------------------------------------------------------------------------------------------------------------- composition

// EatVerifyFreshAttested is the end-to-end check a resource server runs: verify the EAT's signature, then FRESHNESS (nonce +
// iat), CHANNEL BINDING (cnf vs the live channel) and APPRAISAL against the RATS policy. The first failing gate stops the
// pipeline and names the reason. Options: nonce, channelId | channelBinding, policy {referenceValues, endorsements}, now,
// maxAgeMs, clockSkewMs, issuer, algorithms, typ, requireTyp, amd. With amd (rawReport []byte, vcek, ask, ark, family or
// trustAnchorArkSpkiSha384, expectedMeasurement, clockSkewMs, allowDebug) the AMD report signature and chain are verified here:
// success lifts the tier to affirming-hw-rooted, failure is contraindicated.
func EatVerifyFreshAttested(eat any, key *JOSEKey, opts map[string]any) (map[string]any, error) {
	reasons := []any{}
	vo := map[string]any{}
	for _, k := range []string{"issuer", "algorithms", "typ", "requireTyp"} {
		if v, present := opts[k]; present {
			vo[k] = v
		}
	}
	claims, err := EatVerify(eat, key, vo)
	if err != nil {
		return map[string]any{"ok": false, "reasons": []any{"EAT signature/claims invalid: " + err.Error()}}, nil
	}
	reasons = append(reasons, "signature + typ/iss verified")
	now := eatNowMs()
	if f, ok := eatFinite(opts["now"]); ok {
		now = f
	}
	var maxAge any = jsNumber(EatDefaultMaxAgeMs)
	if m, present := opts["maxAgeMs"]; present && m != nil {
		maxAge = m
	}
	fo := map[string]any{"expectedNonce": opts["nonce"], "maxAgeMs": maxAge, "now": jsNumber(now)}
	if s, present := opts["clockSkewMs"]; present {
		fo["clockSkewMs"] = s
	}
	fresh, err := EatVerifyFreshness(claims, fo)
	if err != nil {
		return nil, err
	}
	if fresh["ok"] != true {
		return map[string]any{"ok": false, "reasons": append(reasons, fresh["reason"]), "claims": claims}, nil
	}
	reasons = append(reasons, "fresh (nonce + iat within window)")
	co := map[string]any{}
	if v, present := opts["channelId"]; present {
		co["channelId"] = v
	}
	if v, present := opts["channelBinding"]; present {
		co["expectedCnf"] = v
	}
	chan_, err := EatVerifyChannelBinding(claims, co)
	if err != nil {
		return nil, err
	}
	if chan_["ok"] != true {
		return map[string]any{"ok": false, "reasons": append(reasons, chan_["reason"]), "claims": claims}, nil
	}
	reasons = append(reasons, "channel-bound (cnf matches live channel)")
	extras := map[string]any{}
	if amd, present := opts["amd"]; present {
		hw := eatVerifyAmdOption(claims, amd, now)
		if hw["ok"] != true {
			return map[string]any{"ok": false, "tier": "contraindicated",
				"reasons": append(reasons, "AMD hardware root verification failed: "+jsAnyString(eatOr(hw["reason"], "unknown"))), "claims": claims}, nil
		}
		reasons = append(reasons, "AMD SEV-SNP hardware root verified ("+jsAnyString(hw["hardwareRoot"])+")")
		extras = map[string]any{"hardwareVerified": true, "hardwareRootLabel": hw["hardwareRoot"]}
	}
	policy, hasPolicy := opts["policy"]
	if !hasPolicy || policy == nil { // opts.policy.referenceValues: reading through an absent or null policy throws
		who := "undefined"
		if hasPolicy {
			who = "null"
		}
		return nil, errors.New("Cannot read properties of " + who + " (reading 'referenceValues')")
	}
	rv, _ := eatGet(policy, "referenceValues")
	en, _ := eatGet(policy, "endorsements")
	if rv == nil {
		rv = map[string]any{}
	}
	if en == nil {
		en = map[string]any{}
	}
	app, err := EatAppraise(claims, rv, en, extras)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": app["trustworthy"], "tier": app["tier"], "reasons": append(reasons, app["reasons"].([]any)...), "claims": claims}, nil
}
