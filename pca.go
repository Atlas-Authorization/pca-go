// Package pca is a reference verifier for the CORE PCActn checks (wire format v2): strict wire form,
// freshness binding, capability chain, Merkle plan inclusion, strict Ed25519 leaf signature, counter.
// It byte-matches @atlasauth/pca and passes the format-2 conformance vectors.
package pca

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	sigDomain  = "atlas-pca/actn/v2\x00"
	capDomain  = "atlas-pca/cap/v1\x00"
	defaultRev = "reversible"

	// PCActnVer is the only wire version this verifier accepts.
	PCActnVer     = 2
	MaxChainHops  = 16
	MaxLifetimeMs = 3_600_000
	MaxSkewMs     = 60_000
	maxAudLen     = 256
	maxNonceLen   = 128
	b32, sigLen   = 32, 64
)

var b64 = base64.RawURLEncoding

// Verdict mirrors the TS VerifyResult for the core checks. Checks[name] is true when it passed.
// On a wire failure Checks == {"wire": false} and nothing else is evaluated.
type Verdict struct {
	Allow  bool
	Checks map[string]bool
	Reason string
}

// ---- strict base64url ----------------------------------------------------------------

// DecodeB64uStrict: alphabet A-Za-z0-9-_ only, no padding/whitespace, len%4 != 1, trailing bits zero.
// wantLen < 0 means any decoded length; otherwise the decoded length must equal it.
func DecodeB64uStrict(s string, wantLen int) ([]byte, bool) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return nil, false
		}
	}
	if len(s)%4 == 1 {
		return nil, false
	}
	b, err := b64.Strict().DecodeString(s)
	if err != nil || b64.EncodeToString(b) != s {
		return nil, false
	}
	if wantLen >= 0 && len(b) != wantLen {
		return nil, false
	}
	return b, true
}

func b64uOK(v any, n int) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	_, ok = DecodeB64uStrict(s, n)
	return ok
}

// ---- canonicalization (strict, normative) --------------------------------------------

// Canonicalize: keys sorted bytewise over UTF-8, no whitespace, minimal string escaping, numbers in the
// canonical wire form. Errors on lone surrogates, depth > 32 and non-canonical numbers.
func Canonicalize(v any) (string, error) {
	var sb strings.Builder
	if err := ser(&sb, v, 1); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func jsString(sb *strings.Builder, s string) error {
	if hasLoneSurrogate(s) {
		return fmt.Errorf("canonicalize: lone surrogate in string")
	}
	const hexd = "0123456789abcdef"
	sb.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			sb.WriteString(`\"`)
		case c == '\\':
			sb.WriteString(`\\`)
		case c == '\b':
			sb.WriteString(`\b`)
		case c == '\f':
			sb.WriteString(`\f`)
		case c == '\n':
			sb.WriteString(`\n`)
		case c == '\r':
			sb.WriteString(`\r`)
		case c == '\t':
			sb.WriteString(`\t`)
		case c < 0x20:
			sb.WriteString(`\u00`)
			sb.WriteByte(hexd[c>>4])
			sb.WriteByte(hexd[c&15])
		default:
			sb.WriteByte(c)
		}
	}
	sb.WriteByte('"')
	return nil
}

func ser(sb *strings.Builder, v any, depth int) error {
	switch t := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		if t {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case string:
		return jsString(sb, t)
	case json.Number:
		if e := numberLexemeError(string(t)); e != "" {
			return fmt.Errorf("canonicalize: %s", e)
		}
		sb.WriteString(string(t))
	case int:
		if t > maxSafeInt || t < -maxSafeInt {
			return fmt.Errorf("canonicalize: integer outside the safe range")
		}
		sb.WriteString(strconv.Itoa(t))
	case []any:
		if depth > MaxJSONDepth {
			return fmt.Errorf("canonicalize: nesting too deep")
		}
		sb.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := ser(sb, x, depth+1); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case map[string]any:
		if depth > MaxJSONDepth {
			return fmt.Errorf("canonicalize: nesting too deep")
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys) // Go string order is bytewise == UTF-8 / code point order
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := jsString(sb, k); err != nil {
				return err
			}
			sb.WriteByte(':')
			if err := ser(sb, t[k], depth+1); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	default:
		return fmt.Errorf("canonicalize: unsupported type %T", v)
	}
	return nil
}

func sha(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

func canonBytes(v any) ([]byte, error) {
	s, err := Canonicalize(v)
	return []byte(s), err
}

// HashCanonical = base64url-nopad(sha256(canonical(v))).
func HashCanonical(v any) (string, error) {
	b, err := canonBytes(v)
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(sha(b)), nil
}

// ---- Merkle --------------------------------------------------------------------------

func leafHash(leaf any) ([]byte, error) {
	b, err := canonBytes(leaf)
	if err != nil {
		return nil, err
	}
	return sha(append([]byte{0x00}, b...)), nil
}

func nodeHash(l, r []byte) []byte {
	m := make([]byte, 0, 1+len(l)+len(r))
	m = append(append(append(m, 0x01), l...), r...)
	return sha(m)
}

// MerkleRoot builds the RFC-6962-shaped tree (split at the largest power of two < n).
func MerkleRoot(leaves []any) (string, error) {
	if len(leaves) == 0 {
		return "", fmt.Errorf("empty leaf set")
	}
	hs := make([][]byte, len(leaves))
	for i, l := range leaves {
		h, err := leafHash(l)
		if err != nil {
			return "", err
		}
		hs[i] = h
	}
	return b64.EncodeToString(build(hs)), nil
}

func split(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

func build(hs [][]byte) []byte {
	if len(hs) == 1 {
		return hs[0]
	}
	k := split(len(hs))
	return nodeHash(build(hs[:k]), build(hs[k:]))
}

// pathShape: sibling sides (leaf -> root) for leaf idx in a tree of n leaves (RFC 6962 split).
func pathShape(idx, n int) []string {
	var out []string
	for n > 1 {
		k := split(n)
		if idx < k {
			out = append(out, "R")
			n = k
		} else {
			out = append(out, "L")
			idx -= k
			n -= k
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// safeInt reads a canonical safe-integer json.Number (no float/exponent forms, no -0).
func safeInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	s := string(n)
	if strings.ContainsAny(s, ".eE") || numberLexemeError(s) != "" {
		return 0, false
	}
	i, err := strconv.ParseInt(s, 10, 64)
	return i, err == nil
}

// VerifyInclusion never panics; malformed proofs return false. index/size are bound to the path shape.
func VerifyInclusion(root string, proof map[string]any, leaf any) bool {
	path, ok := proof["path"].([]any)
	if !ok {
		return false
	}
	index, ok1 := safeInt(proof["index"])
	size, ok2 := safeInt(proof["size"])
	if !ok1 || !ok2 || size < 1 || index < 0 || index >= size {
		return false
	}
	shape := pathShape(int(index), int(size))
	if len(shape) != len(path) {
		return false
	}
	h, err := leafHash(leaf)
	if err != nil {
		return false
	}
	for i, s := range path {
		step, ok := s.(map[string]any)
		if !ok {
			return false
		}
		side, _ := step["side"].(string)
		hs, _ := step["hash"].(string)
		if side != shape[i] {
			return false
		}
		sib, ok := DecodeB64uStrict(hs, b32)
		if !ok {
			return false
		}
		if side == "L" {
			h = nodeHash(sib, h)
		} else {
			h = nodeHash(h, sib)
		}
	}
	return b64.EncodeToString(h) == root
}

// ParamsDigest = hashCanonical(params ?? {}).
func ParamsDigest(params any) (string, error) {
	if params == nil {
		params = map[string]any{}
	}
	return HashCanonical(params)
}

func conditionsDigest(pre, post any) (string, error) {
	return HashCanonical(map[string]any{"pre": pre, "post": post})
}

func planLeaf(nodeID any, action map[string]any, cond string) (map[string]any, error) {
	if nodeID == nil {
		return nil, fmt.Errorf("missing node_id")
	}
	pd, ok := action["params_digest"]
	if !ok || pd == nil {
		e, _ := ParamsDigest(nil)
		pd = e
	}
	rc, ok := action["reversibility_class"]
	if !ok || rc == nil {
		rc = defaultRev
	}
	return map[string]any{
		"node_id": nodeID, "verb": action["verb"], "resource": action["resource"],
		"params_digest": pd, "reversibility_class": rc, "conditions": cond,
	}, nil
}

// ---- keys ----------------------------------------------------------------------------

func verifyB64u(pub string, msg []byte, sig string) bool {
	pk, ok := DecodeB64uStrict(pub, b32)
	if !ok {
		return false
	}
	sg, ok := DecodeB64uStrict(sig, sigLen)
	if !ok {
		return false
	}
	return VerifyStrict(pk, msg, sg)
}

// ---- capability chain ----------------------------------------------------------------

// CapHash = hashCanonical(full capability, including its signature).
func CapHash(c map[string]any) (string, error) { return HashCanonical(c) }

func bodyOf(c map[string]any) map[string]any {
	return map[string]any{"issuer": c["issuer"], "holder": c["holder"], "caveats": c["caveats"], "parent": c["parent"]}
}

func capSigMessage(bodyDigest string) ([]byte, error) {
	d, err := b64.DecodeString(bodyDigest)
	if err != nil {
		return nil, err
	}
	return append([]byte(capDomain), d...), nil
}

// signableHopBody mirrors signableBody in capability.ts: bodyOf + the suite fields (`alg`, `pq_pk`) bound
// in for a non-default suite (so a downgrade or ML-DSA key-swap breaks the digest), byte-identical to
// bodyOf for ed25519. Returns (_, false) for an unknown `alg` (fail-closed).
func signableHopBody(c map[string]any) (map[string]any, bool) {
	algV, present := c["alg"]
	suite, ok := resolveSigAlg(algV, present)
	if !ok {
		return nil, false
	}
	body := bodyOf(c)
	if suite.alg != "ed25519" {
		body["alg"] = suite.alg
		if suite.needsPqPk {
			if pk, ok := c["pq_pk"].(string); ok {
				body["pq_pk"] = pk
			}
		}
	}
	return body, true
}

func checkSig(c map[string]any, signer, label string) string {
	// Unknown suite => fail-closed (before any hashing), mirroring capability.ts checkSig.
	body, ok := signableHopBody(c)
	if !ok {
		return fmt.Sprintf("%s: unknown signature alg '%v'", label, c["alg"])
	}
	digest, err := HashCanonical(body)
	if err != nil {
		return label + ": malformed body"
	}
	bd, _ := c["body_digest"].(string)
	id, _ := c["id"].(string)
	if digest != bd || id != bd {
		return label + ": body digest mismatch"
	}
	msg, err := capSigMessage(bd)
	if err != nil {
		return label + ": bad signature (not signed by expected key)"
	}
	// Suite-agile hop verification (mirrors verifyWithSuite): ed25519 == verifyB64u(signer, msg, sig);
	// hybrid requires BOTH the Ed25519 `sig` (under `signer`) AND the ML-DSA `pq_sig` (under `pq_pk`);
	// pure ml-dsa-65 verifies `sig` under `pq_pk`. verifyLeafSuite dispatches on the hop's `alg`.
	algV, present := c["alg"]
	if !verifyLeafSuite(algV, present, signer, c["pq_pk"], msg, c["sig"], c["pq_sig"]) {
		return label + ": bad signature (not signed by expected key)"
	}
	return ""
}

func wellTypedCap(c any) (map[string]any, bool) {
	m, ok := c.(map[string]any)
	if !ok {
		return nil, false
	}
	for _, k := range []string{"id", "issuer", "holder", "body_digest", "sig"} {
		if _, ok := m[k].(string); !ok {
			return nil, false
		}
	}
	if p, has := m["parent"]; has {
		if _, ok := p.(string); !ok {
			return nil, false
		}
	}
	cav, ok := m["caveats"].([]any)
	if !ok {
		return nil, false
	}
	for _, x := range cav {
		cm, ok := x.(map[string]any)
		if !ok {
			return nil, false
		}
		if _, ok := cm["type"].(string); !ok {
			return nil, false
		}
	}
	return m, true
}

// VerifyChain mirrors verifyChain in capability.ts. Returns ("", true) when valid. The hop cap is
// enforced BEFORE any signature work.
func VerifyChain(chain []any, expectedRootIssuer string, haveIssuer bool) (string, bool) {
	if len(chain) == 0 {
		return "empty chain", false
	}
	if len(chain) > MaxChainHops {
		return "chain too long", false
	}
	caps := make([]map[string]any, len(chain))
	for i, c := range chain {
		m, ok := wellTypedCap(c)
		if !ok {
			return fmt.Sprintf("hop %d: malformed capability", i), false
		}
		caps[i] = m
	}
	root := caps[0]
	if _, has := root["parent"]; has {
		return "hop 0: root must not have a parent", false
	}
	if haveIssuer && root["issuer"] != expectedRootIssuer {
		return "hop 0: root issuer is not the expected principal", false
	}
	issuer, _ := root["issuer"].(string)
	if e := checkSig(root, issuer, "hop 0"); e != "" {
		return e, false
	}
	for i := 1; i < len(caps); i++ {
		parent, c := caps[i-1], caps[i]
		label := fmt.Sprintf("hop %d", i)
		ph, err := CapHash(parent)
		if err != nil || c["parent"] != ph {
			return label + ": broken parent link", false
		}
		if c["issuer"] != parent["holder"] {
			return label + ": issuer is not the parent's bound holder", false
		}
		ph2, _ := parent["holder"].(string)
		if e := checkSig(c, ph2, label); e != "" {
			return e, false
		}
		pc, _ := parent["caveats"].([]any)
		cc, _ := c["caveats"].([]any)
		if len(cc) < len(pc) {
			return label + ": drops parent caveat(s)", false
		}
		for j := range pc {
			a, e1 := HashCanonical(cc[j])
			b, e2 := HashCanonical(pc[j])
			if e1 != nil || e2 != nil || a != b {
				return fmt.Sprintf("%s: caveat %d altered or reordered", label, j), false
			}
		}
	}
	return "", true
}

// ---- wire format v2 ------------------------------------------------------------------

var requiredFields = []string{"ver", "action", "grant_ref", "cap_chain", "plan", "attestation", "provenance",
	"freshness", "counter", "risk_claim", "aud", "iat", "exp", "sig"}
var optionalFields = []string{"nonce", "caution", "rationale_commitment", "progress_step", "prohibition_evidence",
	"tool_binding", "threshold", "zk_compliance", "bond_ref",
	// B4 crypto-agility (additive): absent `alg` == "ed25519" and validates exactly as today.
	"alg", "pq_pk", "pq_sig"}

func isObj(v any) (map[string]any, bool) { m, ok := v.(map[string]any); return m, ok }
func isStr(v any) bool                   { _, ok := v.(string); return ok }

func isNum(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok || numberLexemeError(string(n)) != "" {
		return 0, false
	}
	f, err := strconv.ParseFloat(string(n), 64)
	return f, err == nil
}

func closedKeys(m map[string]any, allowed ...string) (string, bool) {
	for k := range m {
		found := false
		for _, a := range allowed {
			if k == a {
				found = true
				break
			}
		}
		if !found {
			return k, false
		}
	}
	return "", true
}

// ValidateWireV2 returns "" when well-formed, else a short reason. Never panics.
func ValidateWireV2(pv any) (reason string) {
	defer func() {
		if r := recover(); r != nil {
			reason = fmt.Sprintf("malformed: %v", r)
		}
	}()
	p, ok := isObj(pv)
	if !ok {
		return "PCActn is not an object"
	}
	known := append(append([]string{}, requiredFields...), optionalFields...)
	if k, ok := closedKeys(p, known...); !ok {
		return "unknown field '" + k + "'"
	}
	for _, k := range requiredFields {
		if _, ok := p[k]; !ok {
			return "missing field '" + k + "'"
		}
	}
	if _, err := Canonicalize(signedBody(p)); err != nil {
		return err.Error()
	}
	for _, k := range []string{"ver", "counter", "iat", "exp"} {
		if _, ok := safeInt(p[k]); !ok {
			return "'" + k + "' must be a safe integer"
		}
	}
	aud, ok := p["aud"].(string)
	if !ok || aud == "" || len(aud) > maxAudLen {
		return "'aud' must be a non-empty string"
	}
	if n, has := p["nonce"]; has {
		s, ok := n.(string)
		if !ok || s == "" || len(s) > maxNonceLen {
			return "'nonce' must be a non-empty string"
		}
	}
	// B4 crypto-agility: validate `alg`/`sig`/`pq_pk`/`pq_sig` per suite. With no `alg` this asserts exactly
	// the classical 64-byte `sig` and that `pq_pk`/`pq_sig` are absent. Unknown `alg` fails closed.
	if e := validateSignatureWire(p); e != "" {
		return e
	}
	if !b64uOK(p["grant_ref"], b32) {
		return "'grant_ref' is not canonical base64url (32 bytes)"
	}

	a, ok := isObj(p["action"])
	if !ok {
		return "'action' must be an object"
	}
	if k, ok := closedKeys(a, "verb", "resource", "params_digest", "reversibility_class"); !ok {
		return "unknown field 'action." + k + "'"
	}
	if !isStr(a["verb"]) || !isStr(a["resource"]) || !isStr(a["reversibility_class"]) {
		return "action.verb/resource/reversibility_class must be strings"
	}
	if !b64uOK(a["params_digest"], b32) {
		return "'action.params_digest' is not canonical base64url (32 bytes)"
	}

	pl, ok := isObj(p["plan"])
	if !ok {
		return "'plan' must be an object"
	}
	if k, ok := closedKeys(pl, "root", "inclusion_proof", "node_id", "conditions_digest"); !ok {
		return "unknown field 'plan." + k + "'"
	}
	if !b64uOK(pl["root"], b32) {
		return "'plan.root' is not canonical base64url (32 bytes)"
	}
	if !isStr(pl["node_id"]) {
		return "'plan.node_id' must be a string"
	}
	if cd, has := pl["conditions_digest"]; has && !b64uOK(cd, b32) {
		return "'plan.conditions_digest' must be a canonical base64url string (32 bytes)"
	}
	ip, ok := isObj(pl["inclusion_proof"])
	if !ok {
		return "'plan.inclusion_proof' must be an object"
	}
	if k, ok := closedKeys(ip, "index", "size", "path"); !ok {
		return "unknown field 'plan.inclusion_proof." + k + "'"
	}
	for _, k := range []string{"index", "size"} {
		if _, ok := safeInt(ip[k]); !ok {
			return "'plan.inclusion_proof." + k + "' must be a safe integer"
		}
	}
	path, ok := ip["path"].([]any)
	if !ok {
		return "'plan.inclusion_proof.path' must be an array"
	}
	for i, sv := range path {
		st, ok := isObj(sv)
		if !ok {
			return fmt.Sprintf("proof step %d must be an object", i)
		}
		if k, ok := closedKeys(st, "side", "hash"); !ok {
			return fmt.Sprintf("unknown field 'path[%d].%s'", i, k)
		}
		if st["side"] != "L" && st["side"] != "R" {
			return fmt.Sprintf("proof step %d: side must be 'L' or 'R'", i)
		}
		if !b64uOK(st["hash"], b32) {
			return fmt.Sprintf("proof step %d: hash is not canonical base64url (32 bytes)", i)
		}
	}

	chain, ok := p["cap_chain"].([]any)
	if !ok {
		return "'cap_chain' must be an array"
	}
	for i, cv := range chain {
		c, ok := isObj(cv)
		if !ok {
			return fmt.Sprintf("cap_chain[%d] must be an object", i)
		}
		if k, ok := closedKeys(c, "id", "issuer", "holder", "body_digest", "caveats", "sig", "parent", "alg", "pq_pk", "pq_sig"); !ok {
			return fmt.Sprintf("unknown field 'cap_chain[%d].%s'", i, k)
		}
		for _, k := range []string{"id", "issuer", "holder", "body_digest"} {
			if !b64uOK(c[k], b32) {
				return fmt.Sprintf("cap_chain[%d].%s is not canonical base64url (32 bytes)", i, k)
			}
		}
		// B4 crypto-agility: validate the hop's `alg`/`sig`/`pq_pk`/`pq_sig` per suite, exactly as the leaf.
		// Absent `alg` asserts the classical 64-byte `sig` and that `pq_pk`/`pq_sig` are absent (byte-identical).
		if e := validateSignatureWire(c); e != "" {
			return fmt.Sprintf("cap_chain[%d]: %s", i, e)
		}
		if par, has := c["parent"]; has && !b64uOK(par, b32) {
			return fmt.Sprintf("cap_chain[%d].parent is not canonical base64url (32 bytes)", i)
		}
		cav, ok := c["caveats"].([]any)
		if !ok {
			return fmt.Sprintf("cap_chain[%d].caveats must be an array of {type,...} objects", i)
		}
		for _, x := range cav {
			cm, ok := isObj(x)
			if !ok || !isStr(cm["type"]) {
				return fmt.Sprintf("cap_chain[%d].caveats must be an array of {type,...} objects", i)
			}
		}
	}

	at, ok := isObj(p["attestation"])
	if !ok {
		return "'attestation' must be an object with an integer 'epoch'"
	}
	if _, ok := safeInt(at["epoch"]); !ok {
		return "'attestation' must be an object with an integer 'epoch'"
	}
	if !isStr(at["quote_digest"]) || !isStr(at["model_id"]) || !isStr(at["measurement"]) || !isStr(at["operator"]) {
		return "attestation string fields must be strings"
	}
	pv2, ok := isObj(p["provenance"])
	if !ok || !isStr(pv2["causal_hash"]) {
		return "'provenance' is malformed"
	}
	if _, ok := isNum(pv2["taint_level"]); !ok {
		return "'provenance' is malformed"
	}
	refs, ok := pv2["trusted_refs"].([]any)
	if !ok {
		return "'provenance' is malformed"
	}
	for _, r := range refs {
		if !isStr(r) {
			return "'provenance' is malformed"
		}
	}
	fr, ok := isObj(p["freshness"])
	if !ok || !isStr(fr["beacon_ref"]) || !isStr(fr["accumulator_witness"]) {
		return "'freshness' is malformed"
	}
	if _, ok := safeInt(fr["epoch"]); !ok {
		return "'freshness' is malformed"
	}
	rc, ok := isObj(p["risk_claim"])
	if !ok {
		return "'risk_claim' is malformed"
	}
	if _, ok := isNum(rc["r"]); !ok {
		return "'risk_claim' is malformed"
	}
	if _, ok := isObj(rc["inputs"]); !ok {
		return "'risk_claim' is malformed"
	}

	if c, has := p["caution"]; has {
		f, ok := isNum(c)
		if !ok || f < 0 || f > 1 {
			return "'caution' must be a number in [0,1]"
		}
	}
	if v, has := p["rationale_commitment"]; has && !b64uOK(v, b32) {
		return "'rationale_commitment' is not canonical base64url (32 bytes)"
	}
	if v, has := p["tool_binding"]; has && !b64uOK(v, b32) {
		return "'tool_binding' is not canonical base64url (32 bytes)"
	}
	if v, has := p["progress_step"]; has {
		if _, ok := isObj(v); !ok {
			return "'progress_step' must be an object"
		}
	}
	if v, has := p["prohibition_evidence"]; has {
		_, o := isObj(v)
		_, a := v.([]any)
		if !o && !a {
			return "'prohibition_evidence' must be an object or array"
		}
	}
	if v, has := p["threshold"]; has {
		th, ok := isObj(v)
		var shares []any
		if ok {
			shares, ok = th["shares"].([]any)
		}
		if !ok {
			return "'threshold' must be {shares:[...]}"
		}
		for i, sv := range shares {
			s, ok := isObj(sv)
			if !ok || !isStr(s["role"]) {
				return fmt.Sprintf("threshold.shares[%d] is malformed", i)
			}
			if !b64uOK(s["publicKey"], b32) {
				return fmt.Sprintf("threshold.shares[%d].publicKey is not canonical base64url (32 bytes)", i)
			}
			if !b64uOK(s["sig"], sigLen) {
				return fmt.Sprintf("threshold.shares[%d].sig is not canonical base64url (64 bytes)", i)
			}
		}
	}
	return ""
}

func signedBody(p map[string]any) map[string]any {
	body := make(map[string]any, len(p))
	for k, v := range p {
		// `sig`, `threshold` and the B4 `pq_sig` are unsigned (stripped); `alg`/`pq_pk` ARE signed.
		if k != "sig" && k != "threshold" && k != "pq_sig" {
			body[k] = v
		}
	}
	return body
}

// ThresholdMessage = SIG_DOMAIN || sha256(strictCanonical(pcactn without `sig` and `threshold`)).
func ThresholdMessage(p map[string]any) ([]byte, error) {
	b, err := canonBytes(signedBody(p))
	if err != nil {
		return nil, err
	}
	return append([]byte(sigDomain), sha(b)...), nil
}

// ParsePCActn strictly parses raw PCActn JSON text; a parse failure or non-object result is a wire failure.
func ParsePCActn(text string) (map[string]any, error) {
	v, err := StrictParse(text)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("PCActn is not an object")
	}
	return m, nil
}

// WireFailure is the terminal verdict for an unparseable / malformed PCActn.
func WireFailure(why string) Verdict {
	return Verdict{Allow: false, Checks: map[string]bool{"wire": false}, Reason: "wire: " + why}
}

// VerifyPCActnCore runs the normative check order: wire, version, audience, validity, chain,
// grant_ref_bound, plan_inclusion, leaf_signature, counter. now is epoch milliseconds; audience is this verifier's own id.
func VerifyPCActnCore(pcactn map[string]any, grant map[string]any, now int64, audience string) (v Verdict, err error) {
	defer func() {
		if r := recover(); r != nil {
			v = WireFailure(fmt.Sprintf("malformed PCActn: %v", r))
		}
	}()
	if why := ValidateWireV2(pcactn); why != "" {
		return WireFailure(why), nil
	}
	v = Verdict{Checks: map[string]bool{}}
	failed := false
	pass := func(name string) { v.Checks[name] = true }
	fail := func(name, why string) {
		failed = true
		v.Checks[name] = false
		if v.Reason == "" {
			v.Reason = name + ": " + why
		}
	}
	pass("wire")

	if ver, _ := safeInt(pcactn["ver"]); ver == PCActnVer {
		pass("version")
	} else {
		fail("version", "unsupported ver")
	}
	if pcactn["aud"] == audience {
		pass("audience")
	} else {
		fail("audience", "aud does not match this resource server / instance")
	}
	iat, _ := safeInt(pcactn["iat"])
	exp, _ := safeInt(pcactn["exp"])
	switch {
	case exp <= iat:
		fail("validity", "exp must be greater than iat")
	case exp-iat > MaxLifetimeMs:
		fail("validity", "lifetime too long")
	case iat > now+MaxSkewMs:
		fail("validity", "iat is in the future (clock skew)")
	case now > exp:
		fail("validity", "the PCActn has expired")
	default:
		pass("validity")
	}

	chain, _ := pcactn["cap_chain"].([]any)
	v.Checks["chain"] = false
	if len(chain) == 0 {
		fail("chain", "empty chain")
	} else if len(chain) > MaxChainHops {
		fail("chain", "chain too long")
	} else {
		root, _ := chain[0].(map[string]any)
		rh, e1 := CapHash(root)
		gh, e2 := CapHash(grant)
		if e1 != nil || e2 != nil || rh != gh {
			fail("chain", "chain root is not the grant")
		} else {
			gi, hasI := grant["issuer"].(string)
			if why, ok := VerifyChain(chain, gi, hasI); ok {
				pass("chain")
			} else {
				fail("chain", why)
			}
		}
	}

	// grant_ref_bound (normative): the signed grant_ref MUST be a non-empty string byte-equal to the id of the
	// ROOT capability of the presented chain (cap_chain[0].id). Evaluated independently of the chain verdict and
	// fail-closed on an empty / malformed chain. Replay state is keyed on grant_ref, so it must not be free.
	{
		gr, _ := pcactn["grant_ref"].(string)
		rootID := ""
		if len(chain) > 0 {
			if rc, ok := chain[0].(map[string]any); ok {
				rootID, _ = rc["id"].(string)
			}
		}
		if gr != "" && rootID != "" && gr == rootID {
			pass("grant_ref_bound")
		} else {
			fail("grant_ref_bound", "grant_ref is not the id of the root capability in cap_chain")
		}
	}

	plan, _ := pcactn["plan"].(map[string]any)
	action, _ := pcactn["action"].(map[string]any)
	cond, ok := plan["conditions_digest"].(string)
	if !ok {
		cond, _ = conditionsDigest(nil, nil)
	}
	root, _ := plan["root"].(string)
	proof, _ := plan["inclusion_proof"].(map[string]any)
	leaf, lerr := planLeaf(plan["node_id"], action, cond)
	if lerr == nil && VerifyInclusion(root, proof, leaf) {
		pass("plan_inclusion")
	} else {
		fail("plan_inclusion", "action is not a node of the committed plan")
	}

	v.Checks["leaf_signature"] = false
	if len(chain) > 0 {
		leafCap, _ := chain[len(chain)-1].(map[string]any)
		holder, _ := leafCap["holder"].(string)
		alg, algPresent := pcactn["alg"]
		msg, merr := ThresholdMessage(pcactn)
		if merr == nil && verifyLeafSuite(alg, algPresent, holder, pcactn["pq_pk"], msg, pcactn["sig"], pcactn["pq_sig"]) {
			pass("leaf_signature")
		} else {
			fail("leaf_signature", "signature does not verify under the leaf holder key")
		}
	} else {
		fail("leaf_signature", "signature does not verify under the leaf holder key")
	}

	if c, ok := safeInt(pcactn["counter"]); ok && c >= 0 {
		pass("counter")
	} else {
		fail("counter", "missing or not a non-negative safe integer")
	}

	v.Allow = !failed
	return v, nil
}
