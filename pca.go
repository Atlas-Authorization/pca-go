// Package pca is a reference verifier for the CORE PCActn checks (M0-M3): capability chain,
// Merkle plan inclusion, Ed25519 leaf signature, counter. It byte-matches @atlasauth/pca.
package pca

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	sigDomain  = "atlas-pca/actn/v1\x00"
	capDomain  = "atlas-pca/cap/v1\x00"
	defaultRev = "reversible"
)

var b64 = base64.RawURLEncoding

// Verdict mirrors the TS VerifyResult for the core checks. Checks[name] is true when it passed.
type Verdict struct {
	Allow  bool
	Checks map[string]bool // chain, plan_inclusion, leaf_signature, counter
	Reason string
}

// ParseJSON decodes JSON keeping numbers exact (json.Number).
func ParseJSON(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// ---- canonicalization ----------------------------------------------------------------

// Canonicalize: keys sorted by UTF-16 code units (recursively), compact, JS JSON string escaping.
func Canonicalize(v any) (string, error) {
	var sb strings.Builder
	if err := ser(&sb, v); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func jsString(sb *strings.Builder, s string) {
	sb.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			sb.WriteString(`\"`)
		case r == '\\':
			sb.WriteString(`\\`)
		case r == '\b':
			sb.WriteString(`\b`)
		case r == '\f':
			sb.WriteString(`\f`)
		case r == '\n':
			sb.WriteString(`\n`)
		case r == '\r':
			sb.WriteString(`\r`)
		case r == '\t':
			sb.WriteString(`\t`)
		case r < 0x20:
			fmt.Fprintf(sb, `\u%04x`, r)
		case r == utf8.RuneError:
			sb.WriteString(`�`) // lone surrogates are not representable in Go strings
		default:
			sb.WriteRune(r)
		}
	}
	sb.WriteByte('"')
}

func fmtNumber(n json.Number) (string, error) {
	f, err := strconv.ParseFloat(string(n), 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return "", fmt.Errorf("canonicalize: non-finite number")
	}
	if f == 0 {
		return "0", nil
	}
	return strconv.FormatFloat(f, 'f', -1, 64), nil
}

func utf16Less(a, b string) bool {
	x, y := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}

func ser(sb *strings.Builder, v any) error {
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
		jsString(sb, t)
	case json.Number:
		s, err := fmtNumber(t)
		if err != nil {
			return err
		}
		sb.WriteString(s)
	case int:
		sb.WriteString(strconv.Itoa(t))
	case float64:
		s, err := fmtNumber(json.Number(strconv.FormatFloat(t, 'g', -1, 64)))
		if err != nil {
			return err
		}
		sb.WriteString(s)
	case []any:
		sb.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := ser(sb, x); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			jsString(sb, k)
			sb.WriteByte(':')
			if err := ser(sb, t[k]); err != nil {
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

// VerifyInclusion never panics; malformed proofs return false.
func VerifyInclusion(root string, proof map[string]any, leaf any) bool {
	path, ok := proof["path"].([]any)
	if !ok {
		return false
	}
	h, err := leafHash(leaf)
	if err != nil {
		return false
	}
	for _, s := range path {
		step, ok := s.(map[string]any)
		if !ok {
			return false
		}
		side, _ := step["side"].(string)
		hs, _ := step["hash"].(string)
		if side != "L" && side != "R" {
			return false
		}
		sib, err := b64.DecodeString(hs)
		if err != nil {
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
	pk, err := b64.DecodeString(pub)
	if err != nil || len(pk) != ed25519.PublicKeySize {
		return false
	}
	sg, err := b64.DecodeString(sig)
	if err != nil || len(sg) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pk, msg, sg)
}

// ---- capability chain ----------------------------------------------------------------

// CapHash = hashCanonical(full capability, including its signature).
func CapHash(c map[string]any) (string, error) { return HashCanonical(c) }

func bodyOf(c map[string]any) map[string]any {
	parent := c["parent"]
	return map[string]any{"issuer": c["issuer"], "holder": c["holder"], "caveats": c["caveats"], "parent": parent}
}

func capSigMessage(bodyDigest string) ([]byte, error) {
	d, err := b64.DecodeString(bodyDigest)
	if err != nil {
		return nil, err
	}
	return append([]byte(capDomain), d...), nil
}

func checkSig(c map[string]any, signer, label string) string {
	digest, err := HashCanonical(bodyOf(c))
	if err != nil {
		return label + ": malformed body"
	}
	bd, _ := c["body_digest"].(string)
	id, _ := c["id"].(string)
	if digest != bd || id != bd {
		return label + ": body digest mismatch"
	}
	msg, err := capSigMessage(bd)
	sg, _ := c["sig"].(string)
	if err != nil || !verifyB64u(signer, msg, sg) {
		return label + ": bad signature (not signed by expected key)"
	}
	return ""
}

// VerifyChain mirrors verifyChain in capability.ts. Returns ("", true) when valid.
func VerifyChain(chain []any, expectedRootIssuer string, haveIssuer bool) (string, bool) {
	if len(chain) == 0 {
		return "empty chain", false
	}
	root, ok := chain[0].(map[string]any)
	if !ok {
		return "hop 0: malformed", false
	}
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
	for i := 1; i < len(chain); i++ {
		parent, ok1 := chain[i-1].(map[string]any)
		c, ok2 := chain[i].(map[string]any)
		label := fmt.Sprintf("hop %d", i)
		if !ok1 || !ok2 {
			return label + ": malformed", false
		}
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

// ---- PCActn --------------------------------------------------------------------------

// ThresholdMessage = SIG_DOMAIN || sha256(canonical(pcactn without `sig` and `threshold`)).
func ThresholdMessage(p map[string]any) ([]byte, error) {
	body := make(map[string]any, len(p))
	for k, v := range p {
		if k != "sig" && k != "threshold" {
			body[k] = v
		}
	}
	b, err := canonBytes(body)
	if err != nil {
		return nil, err
	}
	return append([]byte(sigDomain), sha(b)...), nil
}

// VerifyPCActnCore checks version, capability chain, plan inclusion, leaf signature and counter.
// Later-milestone checks (attestation, threshold, revocation, ...) are out of scope.
func VerifyPCActnCore(pcactn map[string]any, grant map[string]any) (v Verdict, err error) {
	v = Verdict{Checks: map[string]bool{"chain": false, "plan_inclusion": false, "leaf_signature": false, "counter": false}}
	failed := false
	fail := func(name, why string) {
		failed = true
		v.Checks[name] = false
		if v.Reason == "" {
			v.Reason = name + ": " + why
		}
	}
	defer func() {
		if r := recover(); r != nil {
			v.Allow = false
			v.Reason = fmt.Sprintf("malformed PCActn: %v", r)
		}
	}()

	if n, ok := pcactn["ver"].(json.Number); !ok || n.String() != "1" {
		fail("version", "unsupported ver")
	}

	chain, _ := pcactn["cap_chain"].([]any)
	if len(chain) == 0 {
		fail("chain", "empty chain")
	} else {
		root, _ := chain[0].(map[string]any)
		rh, e1 := CapHash(root)
		gh, e2 := CapHash(grant)
		if e1 != nil || e2 != nil {
			return v, fmt.Errorf("malformed capability")
		}
		if rh != gh {
			fail("chain", "chain root is not the grant")
		} else {
			gi, hasI := grant["issuer"].(string)
			if why, ok := VerifyChain(chain, gi, hasI); ok {
				v.Checks["chain"] = true
			} else {
				fail("chain", why)
			}
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
		v.Checks["plan_inclusion"] = true
	} else {
		fail("plan_inclusion", "action is not a node of the committed plan")
	}

	if len(chain) > 0 {
		leafCap, _ := chain[len(chain)-1].(map[string]any)
		holder, _ := leafCap["holder"].(string)
		sig, hasSig := pcactn["sig"].(string)
		msg, merr := ThresholdMessage(pcactn)
		if merr != nil {
			return v, merr
		}
		if hasSig && verifyB64u(holder, msg, sig) {
			v.Checks["leaf_signature"] = true
		} else {
			fail("leaf_signature", "signature does not verify under the leaf holder key")
		}
	} else {
		fail("leaf_signature", "signature does not verify under the leaf holder key")
	}

	if n, ok := pcactn["counter"].(json.Number); ok {
		if i, e := strconv.ParseInt(n.String(), 10, 64); e == nil && i >= 0 {
			v.Checks["counter"] = true
		} else {
			fail("counter", "missing or not a non-negative integer")
		}
	} else {
		fail("counter", "missing or not a non-negative integer")
	}

	v.Allow = !failed
	return v, nil
}
