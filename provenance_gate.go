package pca

// Build provenance as a K1 discharge (track K9): a port of packages/pca/src/provenance-gate.ts (contracts C-520..C-526).
//
// The policy half of a Sigstore / SLSA provenance check: RFC 9162 inclusion, ProvenanceGate (facts against the verifier's
// pinned signer-builder pairs) and ProvenanceCaveat (needs_discharge with issuer_class "artifact"). Values are parsed JSON
// (map[string]any, []any, string, bool, nil, json.Number). Everything is total: malformed input is a refusal, never a panic.

import (
	"bytes"
	"crypto/sha256"
	"regexp"
	"strings"
)

// In-toto / SLSA type URIs.
const (
	SLSAProvenanceV1  = "https://slsa.dev/provenance/v1"
	InTotoStatementV1 = "https://in-toto.io/Statement/v1"
)

var provHex = map[string]*regexp.Regexp{"sha256": regexp.MustCompile(`^[0-9a-f]{64}$`), "sha512": regexp.MustCompile(`^[0-9a-f]{128}$`)}

// RFC9162LeafHash is RFC 9162 section 2.1.1: SHA-256(0x00 || data).
func RFC9162LeafHash(data []byte) []byte {
	h := sha256.Sum256(append([]byte{0}, data...))
	return h[:]
}

func rfc9162Node(l, r []byte) []byte {
	m := make([]byte, 0, 65)
	m = append(append(append(m, 1), l...), r...)
	h := sha256.Sum256(m)
	return h[:]
}

// VerifyRFC9162Inclusion is RFC 9162 section 2.1.3.2: an inclusion proof of leafHash at index in a tree of size leaves with
// root. proof runs from the leaf level up. Index and size are safe integers (<= 2^53-1). False on any malformed input.
func VerifyRFC9162Inclusion(leafHash []byte, index, size int64, proof [][]byte, root []byte) bool {
	if !(index >= 0 && size >= 1 && index < size && size <= maxSafeInt) {
		return false
	}
	if len(leafHash) != 32 || len(root) != 32 || len(proof) > 64 {
		return false
	}
	for _, p := range proof {
		if len(p) != 32 {
			return false
		}
	}
	fn, sn, r := uint64(index), uint64(size-1), leafHash
	for _, p := range proof {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = rfc9162Node(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = rfc9162Node(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytes.Equal(r, root)
}

// ProvenanceGateResult is {ok: true, level, claims} or {ok: false, code}. Claims hold string, int64 and bool values with the
// reference member names (source_* only when the facts carry them).
type ProvenanceGateResult struct {
	OK     bool
	Code   string
	Level  int64
	Claims map[string]any
}

func provStr(v any) bool { return boundedStr(v, 2048) }

func provLevel(v any) bool {
	f, _ := jsNum(v)
	return jsIsInt(v) && (f == 1 || f == 2 || f == 3)
}

func provInt(v any) int64 { return int64(jsF(v)) }

func provSubjectError(v any) bool {
	s, ok := v.(map[string]any)
	if !ok || !closedMembers(s, []string{"alg", "digest"}) {
		return true
	}
	alg, _ := s["alg"].(string)
	d, isStr := s["digest"].(string)
	re := provHex[alg]
	return !(re != nil && isStr && re.MatchString(d))
}

// ProvenanceFactsError is "" when the facts are well-formed (closed members, bounded strings).
func ProvenanceFactsError(v any) string {
	f, ok := v.(map[string]any)
	if !ok {
		return "facts must be an object"
	}
	if e := closedMembersMsg(f, "facts", []string{"v", "predicate_type", "build_type", "builder_id", "subjects", "identity", "oidc_issuer", "integrated_time", "rekor_log_index"},
		"source_repo", "source_ref", "source_digest", "provenance_source"); e != "" {
		return e
	}
	if !(jsIsInt(f["v"]) && jsF(f["v"]) == 1) {
		return "facts.v must be 1"
	}
	for _, k := range []string{"predicate_type", "build_type", "builder_id", "identity", "oidc_issuer"} {
		if !provStr(f[k]) {
			return "facts." + k + " must be a non-empty string"
		}
	}
	for _, k := range []string{"source_repo", "source_ref", "source_digest"} {
		if x, has := f[k]; has && !provStr(x) {
			return "facts." + k + " must be a non-empty string"
		}
	}
	subs, isArr := f["subjects"].([]any)
	if !isArr || len(subs) < 1 || len(subs) > 64 {
		return "facts.subjects must be 1..64 {alg, digest}"
	}
	for _, s := range subs {
		if provSubjectError(s) {
			return "facts.subjects must be 1..64 {alg, digest}"
		}
	}
	for _, k := range []string{"integrated_time", "rekor_log_index"} {
		if !(jsIsInt(f[k]) && jsF(f[k]) >= 0) {
			return "facts." + k + " must be a non-negative integer"
		}
	}
	if x, has := f["provenance_source"]; has {
		p, isObj := x.(map[string]any)
		if !isObj || !closedMembers(p, []string{"uri"}, "git_commit") || !provStr(p["uri"]) {
			return "facts.provenance_source is malformed"
		}
		if g, has := p["git_commit"]; has && !provStr(g) {
			return "facts.provenance_source is malformed"
		}
	}
	return ""
}

// ProvenancePolicyError is "" when the policy is well-formed.
func ProvenancePolicyError(v any) string {
	p, ok := v.(map[string]any)
	if !ok {
		return "policy must be an object"
	}
	if e := closedMembersMsg(p, "policy", []string{"roots", "min_level"}, "source_repo", "source_ref", "source_ref_prefix", "build_types", "max_age_s", "require_runtime"); e != "" {
		return e
	}
	roots, isArr := p["roots"].([]any)
	if !isArr || len(roots) < 1 || len(roots) > 32 {
		return "policy.roots must hold 1..32 pairs"
	}
	for _, x := range roots {
		r, isObj := x.(map[string]any)
		if !isObj || !closedMembers(r, []string{"oidc_issuer", "builder_id", "level"}, "identity", "identity_prefix") {
			return "policy root is malformed"
		}
		if !provStr(r["oidc_issuer"]) || !provStr(r["builder_id"]) {
			return "policy root needs oidc_issuer and builder_id"
		}
		id, hasID := r["identity"]
		pre, hasPre := r["identity_prefix"]
		if hasID == hasPre {
			return "policy root needs exactly one of identity and identity_prefix"
		}
		if hasID && !provStr(id) {
			return "policy root identity is malformed"
		}
		// a prefix must at least name a scheme and a host; an empty-ish prefix would pin nothing
		if hasPre {
			if s, _ := pre.(string); !provStr(pre) || utf16Len(s) < 10 {
				return "policy root identity_prefix must be at least 10 characters"
			}
		}
		if !provLevel(r["level"]) {
			return "policy root level must be 1, 2 or 3"
		}
	}
	if !provLevel(p["min_level"]) {
		return "policy.min_level must be 1, 2 or 3"
	}
	_, hasRef := p["source_ref"]
	_, hasPre := p["source_ref_prefix"]
	if x, has := p["source_repo"]; has && !provStr(x) {
		return "policy.source_repo is malformed"
	}
	if hasRef && hasPre {
		return "policy takes source_ref or source_ref_prefix, not both"
	}
	if hasRef && !provStr(p["source_ref"]) {
		return "policy.source_ref is malformed"
	}
	if hasPre && !provStr(p["source_ref_prefix"]) {
		return "policy.source_ref_prefix is malformed"
	}
	if x, has := p["build_types"]; has {
		b, isArr := x.([]any)
		if !isArr || len(b) < 1 || len(b) > 16 {
			return "policy.build_types must hold 1..16 strings"
		}
		for _, s := range b {
			if !provStr(s) {
				return "policy.build_types must hold 1..16 strings"
			}
		}
	}
	if x, has := p["max_age_s"]; has && !(jsIsInt(x) && jsF(x) >= 1) {
		return "policy.max_age_s must be a positive integer"
	}
	if x, has := p["require_runtime"]; has {
		if _, isBool := x.(bool); !isBool {
			return "policy.require_runtime must be a boolean"
		}
	}
	return ""
}

// ProvenanceGate runs the provenance gates in the reference order over {facts, policy, runtime?, now}: policy, facts, clock,
// runtime shape, predicate type, time, pinned signer-builder pair and level floor, provenance source, source pins, build type,
// subject, claim lengths. Total.
func ProvenanceGate(input any) (res ProvenanceGateResult) {
	no := func(code string) ProvenanceGateResult { return ProvenanceGateResult{Code: code} }
	defer func() {
		if recover() != nil {
			res = no("malformed_facts")
		}
	}()
	in, ok := input.(map[string]any)
	if !ok {
		return no("malformed_facts")
	}
	if ProvenancePolicyError(in["policy"]) != "" {
		return no("malformed_policy")
	}
	if ProvenanceFactsError(in["facts"]) != "" {
		return no("malformed_facts")
	}
	if !(jsIsInt(in["now"]) && jsF(in["now"]) >= 0) {
		return no("malformed_facts")
	}
	f, p, now := in["facts"].(map[string]any), in["policy"].(map[string]any), provInt(in["now"])
	rtv, hasRt := in["runtime"]
	if hasRt && provSubjectError(rtv) {
		return no("malformed_runtime")
	}
	if f["predicate_type"] != SLSAProvenanceV1 {
		return no("predicate_type")
	}
	it := provInt(f["integrated_time"])
	if it > now {
		return no("future")
	}
	if x, has := p["max_age_s"]; has && now-it > provInt(x) {
		return no("stale")
	}
	identity := f["identity"].(string)
	var level int64
	for _, x := range p["roots"].([]any) {
		r := x.(map[string]any)
		if r["oidc_issuer"] != f["oidc_issuer"] || r["builder_id"] != f["builder_id"] {
			continue
		}
		if id, has := r["identity"]; has {
			if id != identity {
				continue
			}
		} else if !strings.HasPrefix(identity, r["identity_prefix"].(string)) {
			continue
		}
		if l := provInt(r["level"]); l > level {
			level = l
		}
	}
	if level == 0 {
		return no("no_root")
	}
	if level < provInt(p["min_level"]) {
		return no("level")
	}
	fRepo, hasFRepo := f["source_repo"].(string)
	fRef, hasFRef := f["source_ref"].(string)
	if x, has := f["provenance_source"]; has {
		ps := x.(map[string]any)
		gc, hasGC := ps["git_commit"]
		sd, hasSD := f["source_digest"]
		if hasGC && hasSD && gc != sd {
			return no("source_mismatch")
		}
		uri := ps["uri"].(string)
		if hasFRepo && !(uri == "git+"+fRepo || strings.HasPrefix(uri, "git+"+fRepo+"@")) {
			return no("source_mismatch")
		}
	}
	if x, has := p["source_repo"]; has && !(hasFRepo && fRepo == x) {
		return no("source_repo")
	}
	if x, has := p["source_ref"]; has && !(hasFRef && fRef == x) {
		return no("source_ref")
	}
	if x, has := p["source_ref_prefix"]; has && !(hasFRef && strings.HasPrefix(fRef, x.(string))) {
		return no("source_ref")
	}
	if x, has := p["build_types"]; has {
		hit := false
		for _, b := range x.([]any) {
			hit = hit || b == f["build_type"]
		}
		if !hit {
			return no("build_type")
		}
	}
	subs := f["subjects"].([]any)
	var subject map[string]any
	bound := false
	if hasRt {
		rt := rtv.(map[string]any)
		for _, s := range subs {
			if m := s.(map[string]any); m["alg"] == rt["alg"] && m["digest"] == rt["digest"] {
				subject = m
				break
			}
		}
		if subject == nil {
			return no("runtime_mismatch")
		}
		bound = true
	} else {
		if p["require_runtime"] == true {
			return no("runtime_required")
		}
		if len(subs) != 1 {
			return no("subject_ambiguous")
		}
		subject = subs[0].(map[string]any)
	}
	claims := map[string]any{
		"subject_alg": subject["alg"], "subject_digest": subject["digest"], "slsa_level": level, "builder_id": f["builder_id"],
		"build_type": f["build_type"], "oidc_issuer": f["oidc_issuer"], "identity": identity,
		"rekor_log_index": provInt(f["rekor_log_index"]), "runtime_bound": bound,
	}
	for _, k := range []string{"source_repo", "source_ref", "source_digest"} {
		if x, has := f[k]; has {
			claims[k] = x
		}
	}
	for _, v := range claims {
		if s, isStr := v.(string); isStr && utf8Len(s) > 256 {
			return no("claim_too_long")
		}
	}
	return ProvenanceGateResult{OK: true, Level: level, Claims: claims}
}

// ProvenanceCaveatOptions are the reference ProvenanceCaveatOptions. Empty strings and a nil slice mean "absent".
type ProvenanceCaveatOptions struct {
	ID         string // default "provenance"
	Issuer     string // label of the verifier's artifact pin
	MinLevel   int64  // 1..3
	SourceRepo string
	BuilderIDs []string
	OIDCIssuer string
	// NoRuntime drops the runtime_bound requirement (the reference require_runtime: false). Default: required.
	NoRuntime bool
	Bind      string // default "action"
	TTLMs     int64  // default 300000
}

// ProvenanceCaveat is a needs_discharge caveat that asks the pinned `artifact` verifier for provenance claims.
func ProvenanceCaveat(o ProvenanceCaveatOptions) map[string]any {
	req := []any{map[string]any{"claim": "slsa_level", "op": "gte", "value": o.MinLevel}}
	if o.SourceRepo != "" {
		req = append(req, map[string]any{"claim": "source_repo", "op": "eq", "value": o.SourceRepo})
	}
	if o.BuilderIDs != nil {
		ids := make([]any, len(o.BuilderIDs))
		for i, b := range o.BuilderIDs {
			ids[i] = b
		}
		req = append(req, map[string]any{"claim": "builder_id", "op": "in", "value": ids})
	}
	if o.OIDCIssuer != "" {
		req = append(req, map[string]any{"claim": "oidc_issuer", "op": "eq", "value": o.OIDCIssuer})
	}
	if !o.NoRuntime {
		req = append(req, map[string]any{"claim": "runtime_bound", "op": "eq", "value": true})
	}
	id, bind, ttl := o.ID, o.Bind, o.TTLMs
	if id == "" {
		id = "provenance"
	}
	if bind == "" {
		bind = "action"
	}
	if ttl == 0 {
		ttl = 300_000
	}
	return map[string]any{"type": "needs_discharge", "id": id, "issuer": o.Issuer, "issuer_class": "artifact", "bind": bind, "ttl_ms": ttl, "require": req}
}
