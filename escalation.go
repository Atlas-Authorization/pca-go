package pca

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Escalation on the wire: a port of packages/pca/src/escalation.ts (security contract C-51). A decision of escalate is
// admitted only with a principal-signed answer bound to (policy digest, action digest, history head), spent by the replay
// counter, never upgrading a deny. EVERY signature suite this verifier implements is accepted (Ed25519, ML-DSA, SLH-DSA,
// FN-DSA where built, and the hybrids: SupportedSuites()) under the TypeScript pin rules: the principal is pinned by its
// Ed25519 key, and a post-quantum / hybrid answer verifies only against the PQ key pinned for that principal. A suite this
// build cannot run is refused (unsupported_suite).

// EscalationAnswerDomain is the signature domain of an escalation answer.
const EscalationAnswerDomain = "atlas-pca/escalation-answer/v1\x00"

// EscalationMaxLifetimeMs is the longest validity of an answer (24 h).
const EscalationMaxLifetimeMs = 86_400_000

// EscalationPolicyDigest is the digest of the grant in force.
func EscalationPolicyDigest(grant map[string]any) (string, error) {
	return HashCanonical(map[string]any{"d": "atlas-pca/escalation-policy/v1", "grant": grant})
}

// EscalationActionDigest is the digest of the exact PCActn (counter and signature included).
func EscalationActionDigest(pcactn map[string]any) (string, error) {
	return HashCanonical(map[string]any{"d": "atlas-pca/escalation-action/v1", "pcactn": pcactn})
}

// EscalationHistoryHead is the digest of the holder's last admitted counter (nil: none yet).
func EscalationHistoryHead(last *int64) (string, error) {
	var v any
	if last != nil {
		v = jsonNumberOf(*last)
	}
	return HashCanonical(map[string]any{"d": "atlas-pca/escalation-history/v1", "last_counter": v})
}

// A Go string cannot hold a lone surrogate, which `s.slice(0, n)` of a JavaScript string produces when the cut falls inside a
// surrogate pair. Such a unit is carried as U+FDD0, its four lowercase hex digits and U+FDD1 (two Unicode noncharacters, never
// valid text) and written as \udXXXX by EscalationReasonsWire / RestoreLoneSurrogates, exactly as JSON.stringify does.
const (
	loneOpen  = "\uFDD0"
	loneClose = "\uFDD1"
)

// truncUTF16 is `s.slice(0, n)` of a JavaScript string: at most n UTF-16 code units; a cut inside a surrogate pair keeps the
// LONE high surrogate (carried as described above).
func truncUTF16(s string, n int) string {
	units := 0
	for i, r := range s {
		w := 1
		if r >= 0x10000 {
			w = 2
		}
		if units+w > n {
			if w == 2 && units+1 == n {
				return s[:i] + loneOpen + fmt.Sprintf("%04x", 0xD800+((int(r)-0x10000)>>10)) + loneClose
			}
			return s[:i]
		}
		units += w
	}
	return s
}

// loneSurrogateRe matches a carried lone surrogate.
var loneSurrogateRe = regexp.MustCompile("\uFDD0([0-9a-f]{4})\uFDD1")

// RestoreLoneSurrogates replaces every carried lone surrogate in serialized JSON text by its \udXXXX escape.
func RestoreLoneSurrogates(jsonText []byte) []byte {
	return loneSurrogateRe.ReplaceAll(jsonText, []byte(`\u$1`))
}

// EscalationReasonsWire is `JSON.stringify(request.reasons)`: strings escaped as the reference writes them (quote, backslash,
// controls, a lone surrogate as \udXXXX; everything else, non-ASCII included, raw).
func EscalationReasonsWire(request map[string]any) string {
	var b strings.Builder
	b.WriteByte('[')
	rs, _ := request["reasons"].([]any)
	for i, x := range rs {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		s, _ := x.(string)
		for _, r := range s {
			switch {
			case r == '"':
				b.WriteString(`\"`)
			case r == '\\':
				b.WriteString(`\\`)
			case r == '\b':
				b.WriteString(`\b`)
			case r == '\f':
				b.WriteString(`\f`)
			case r == '\n':
				b.WriteString(`\n`)
			case r == '\r':
				b.WriteString(`\r`)
			case r == '\t':
				b.WriteString(`\t`)
			case r < 0x20:
				fmt.Fprintf(&b, `\u%04x`, r)
			default:
				b.WriteRune(r)
			}
		}
		b.WriteByte('"')
	}
	b.WriteByte(']')
	return string(RestoreLoneSurrogates([]byte(b.String())))
}

// DefaultEscalationRequestTTLMs is how long an issued EscalationRequest is valid when the caller sets no TTL (one hour).
const DefaultEscalationRequestTTLMs = 3_600_000

// BuildEscalationRequest is the request a refused escalate carries for the principal. ttlMs <= 0: the default (one hour).
func BuildEscalationRequest(aud string, grant, pcactn map[string]any, last *int64, reasons []string, now, ttlMs int64) (map[string]any, error) {
	return BuildEscalationRequestWithRender(aud, grant, pcactn, last, reasons, now, ttlMs, "")
}

// BuildEscalationRequestWithRender is BuildEscalationRequest carrying the verifier's recomputed render digest (K7; "" = none).
func BuildEscalationRequestWithRender(aud string, grant, pcactn map[string]any, last *int64, reasons []string, now, ttlMs int64, renderDigest string) (map[string]any, error) {
	pd, err := EscalationPolicyDigest(grant)
	if err != nil {
		return nil, err
	}
	ad, err := EscalationActionDigest(pcactn)
	if err != nil {
		return nil, err
	}
	hh, err := EscalationHistoryHead(last)
	if err != nil {
		return nil, err
	}
	act, _ := pcactn["action"].(map[string]any)
	ttl := ttlMs
	if ttl <= 0 {
		ttl = DefaultEscalationRequestTTLMs
	}
	rs := []any{}
	for i, r := range reasons {
		if i >= 16 {
			break
		}
		rs = append(rs, truncUTF16(r, 512))
	}
	req := map[string]any{
		"v": jsonNumberOf(1), "kind": "pca-escalation-request", "aud": aud, "policy_digest": pd, "action_digest": ad,
		"history_head": hh, "verb": fmt.Sprint(act["verb"]), "resource": fmt.Sprint(act["resource"]), "reasons": rs,
		"expires_at": jsonNumberOf(now + ttl),
	}
	if renderDigest != "" {
		req["render_digest"] = renderDigest
	}
	return req, nil
}

func nonNegSafe(v any) (int64, bool) {
	i, ok := safeInt(v)
	return i, ok && i >= 0
}

// EscalationAnswerShapeError is "" for a well-formed answer, else the reason.
func EscalationAnswerShapeError(a any) string {
	// a parsed JSON 2.0 or 1e3 is the integer 2 / 1000 (JavaScript has one number type): read every number by its value
	m, ok := normalizeJSON(a).(map[string]any)
	if !ok {
		return "not an object"
	}
	required := []string{"v", "kind", "principal", "policy_digest", "action_digest", "history_head", "decision", "iat", "expires_at", "nonce", "sig"}
	optional := []string{"alg", "pq_pk", "pq_sig", "render_digest"}
	allowed := map[string]bool{}
	for _, k := range append(append([]string{}, required...), optional...) {
		allowed[k] = true
	}
	for k := range m {
		if !allowed[k] {
			return "unknown member 'answer." + k + "'"
		}
	}
	for _, k := range required {
		if _, has := m[k]; !has {
			return "missing member 'answer." + k + "'"
		}
	}
	if v, ok := safeInt(m["v"]); !ok || v != 1 || m["kind"] != "pca-escalation-answer" {
		return "not a pca-escalation-answer v1"
	}
	if !b64uOK(m["principal"], 32) {
		return "principal must be canonical base64url (32 bytes)"
	}
	for _, k := range []string{"policy_digest", "action_digest", "history_head"} {
		if !b64uOK(m[k], 32) {
			return k + " must be canonical base64url (32 bytes)"
		}
	}
	if m["decision"] != "allow" && m["decision"] != "deny" {
		return "decision must be 'allow' or 'deny'"
	}
	iat, ok1 := nonNegSafe(m["iat"])
	exp, ok2 := nonNegSafe(m["expires_at"])
	if !ok1 || !ok2 {
		return "iat and expires_at must be non-negative safe integers"
	}
	if !(exp > iat) {
		return "expires_at must be greater than iat"
	}
	if exp-iat > EscalationMaxLifetimeMs {
		return fmt.Sprintf("an answer lives at most %d ms", EscalationMaxLifetimeMs)
	}
	if _, has := m["render_digest"]; has && !b64uOK(m["render_digest"], 32) {
		return "render_digest must be canonical base64url (32 bytes)"
	}
	ns, isStr := m["nonce"].(string)
	nb, okn := DecodeB64uStrict(ns, -1)
	if !isStr || !okn || len(nb) < 16 {
		return "nonce must be canonical base64url of at least 16 bytes"
	}
	if _, ok := m["sig"].(string); !ok {
		return "sig must be a string"
	}
	return artifactSuiteError(m)
}

// PinnedSigner is a pinned answering principal: its Ed25519 identity and, for a post-quantum or hybrid suite, the PQ public key
// (b64u) the verifier pins for it. An empty PQPK pins no PQ key: such a principal's PQ / hybrid answers are refused.
type PinnedSigner struct {
	PK   string
	PQPK string
}

// Ed25519Pins pins principals by their Ed25519 key alone.
func Ed25519Pins(keys ...string) []PinnedSigner {
	out := make([]PinnedSigner, len(keys))
	for i, k := range keys {
		out[i] = PinnedSigner{PK: k}
	}
	return out
}

// EscalationVerdict is the result of VerifyEscalationAnswer.
type EscalationVerdict struct {
	OK        bool
	Principal string
	Decision  string
	Reason    string
}

// EscalationBinding is what an answer must be bound to.
type EscalationBinding struct {
	PolicyDigest, ActionDigest, HistoryHead string
	// RenderDigest (K7) is the H(R) the verifier recomputed from the executed parameters and its own definition. When set the
	// answer MUST carry exactly it; when empty, an answer that carries a render_digest is refused (the verifier did not check what was shown).
	RenderDigest string
}

// VerifyEscalationAnswer checks an answer against the verifier's pinned principals and the binding of THIS decision.
// Total. A valid deny answer is OK with Decision "deny": the caller must not admit it.
func VerifyEscalationAnswer(answer any, principals []PinnedSigner, bind EscalationBinding, now int64) (res EscalationVerdict) {
	no := func(r string) EscalationVerdict { return EscalationVerdict{Reason: r} }
	defer func() {
		if r := recover(); r != nil {
			res = no(fmt.Sprint("escalation answer error (fail closed): ", r))
		}
	}()
	if now > maxSafeInt || now < -maxSafeInt {
		return no("the verifier clock is not a safe integer (fail closed)")
	}
	if e := EscalationAnswerShapeError(answer); e != "" {
		return no("malformed escalation answer: " + e)
	}
	a := normalizeJSON(answer).(map[string]any)
	if len(principals) == 0 {
		return no("no principal is pinned for escalation answers")
	}
	var pin *PinnedSigner
	for i := range principals { // the first pin naming the principal decides (the reference's find)
		if principals[i].PK == a["principal"] {
			pin = &principals[i]
			break
		}
	}
	if pin == nil {
		return no("the answering principal is not pinned by this verifier")
	}
	var pinPq any
	if pin.PQPK != "" {
		pinPq = pin.PQPK
	}
	if !verifyArtifactSig(EscalationAnswerDomain, a, pin.PK, pinPq) {
		return no("escalation answer signature invalid")
	}
	if a["policy_digest"] != bind.PolicyDigest {
		return no("the answer is bound to another policy")
	}
	if a["action_digest"] != bind.ActionDigest {
		return no("the answer is bound to another action")
	}
	if a["history_head"] != bind.HistoryHead {
		return no("the answer is bound to another state of the history")
	}
	if bind.RenderDigest != "" {
		got, has := a["render_digest"]
		if !has {
			return no("the answer is not bound to the canonical approval render")
		}
		if got != bind.RenderDigest {
			return no("the answer was given for another approval render")
		}
	} else if _, has := a["render_digest"]; has {
		return no("the answer carries an approval render this verifier did not recompute")
	}
	iat, _ := safeInt(a["iat"])
	exp, _ := safeInt(a["expires_at"])
	if now < iat {
		return no("the answer is from the future")
	}
	if now > exp {
		return no("the answer has expired")
	}
	return EscalationVerdict{OK: true, Principal: a["principal"].(string), Decision: a["decision"].(string)}
}

func jsonNumberOf(i int64) json.Number { return json.Number(strconv.FormatInt(i, 10)) }
