package pca

// External-fact attestation for proof-carrying actions (port of the TypeScript @atlasauth/pca-notary): a NOTARY witnesses one
// HTTP request/response and signs a canonical record of it (method, URL, a digest of the request headers, the status and a
// commitment to the body); the body commitment is a salted Merkle tree over the body's fields (JSON) or chunks (text), so the
// prover can later DISCLOSE one field with an inclusion proof while every other field stays hidden. The disclosure, the notary
// signature and the body root are then bound to a specific PCActn.
//
// TRUST BOUNDARY: this relies on a trusted or semi-trusted notary that actually observed the TLS session. A colluding or
// compromised notary can attest anything; this is NOT a trustless (MPC-TLS / zkTLS) proof. Everything FAILS CLOSED: a wrong or
// absent notary key, a tampered session, a tampered root, a lie about a disclosed field, or a fact bound to another PCActn is
// rejected.
//
// Attestations, witnesses, disclosures, caveats and PCActns are JSON values (map[string]any / []any, numbers as json.Number)
// with the member names of the reference, so a hostile shape is judged exactly as the reference judges it. A notary key is a
// base64url string, the raw public key bytes or a *KeyPair.
//
// shortcut: request header names are lower-cased and the method upper-cased with Go's Unicode simple case mapping (the reference
// uses full mapping; they agree on ASCII), and header names that collide after lower-casing merge in sorted key order.
// shortcut: a request `headers` that is present but not an object is refused (the reference reads its entries).

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// NotaryBodyCommitAlg tags the body commitment (a salted RFC 6962-shape Merkle tree over SHA-256).
	NotaryBodyCommitAlg = "salted-merkle-sha256-v1"
	// NotaryAttestedFactCaveat is the caveat type "this action is admitted only if a notarized external fact holds".
	NotaryAttestedFactCaveat = "attested_fact"

	notaryDomain = "atlas-pca/notary/v1\x00"
)

// NotarizeOptions configures NotarizeResponse.
type NotarizeOptions struct {
	// NotaryKey is the notary's signing identity (its public key becomes attestation.notary). Required.
	NotaryKey *KeyPair
	// ObservedAt is the epoch-ms the notary observed the session; nil means now.
	ObservedAt *int64
	// TextChunkSize, when >= 1 and the body is a string, commits the body as chunks of that many characters (floored).
	TextChunkSize float64
	// Salt returns one fresh hiding salt (16 random bytes). Nil uses crypto/rand; set it only for reproducible tests.
	Salt func() []byte
}

func nyObj(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

// nyCanonicalEqual is canonical equality over JSON values; false on any error.
func nyCanonicalEqual(a, b any) bool {
	ha, err := HashCanonical(a)
	if err != nil {
		return false
	}
	hb, err := HashCanonical(b)
	if err != nil {
		return false
	}
	return ha == hb
}

// nyPub normalizes a notary key input (string, public key bytes, *KeyPair) to its base64url form.
func nyPub(key any) (string, bool) {
	switch k := key.(type) {
	case string:
		return k, true
	case []byte:
		return b64.EncodeToString(k), true
	case *KeyPair:
		if k == nil {
			return "", false
		}
		return k.Public, true
	}
	return "", false
}

type nyLeaf struct {
	path  []any
	value any
}

func nyAppendPath(prefix []any, seg any) []any {
	p := make([]any, 0, len(prefix)+1)
	p = append(p, prefix...)
	return append(p, seg)
}

// nyFlatten flattens a JSON value into ordered terminal leaves (an empty object / array is itself a leaf).
func nyFlatten(value any, prefix []any) []nyLeaf {
	switch v := value.(type) {
	case []any:
		if len(v) == 0 {
			return []nyLeaf{{path: prefix, value: []any{}}}
		}
		var out []nyLeaf
		for i, x := range v {
			out = append(out, nyFlatten(x, nyAppendPath(prefix, nyNum(i)))...)
		}
		return out
	case map[string]any:
		if len(v) == 0 {
			return []nyLeaf{{path: prefix, value: map[string]any{}}}
		}
		var out []nyLeaf
		for _, k := range sortedKeysUtf8(v) {
			out = append(out, nyFlatten(v[k], nyAppendPath(prefix, k))...)
		}
		return out
	}
	return []nyLeaf{{path: prefix, value: value}}
}

// nyChunk splits s into size-character chunks (by code point, never splitting a surrogate pair).
func nyChunk(s string, size float64) ([]nyLeaf, error) {
	if hasLoneSurrogate(s) || !utf8.ValidString(s) {
		return nil, errors.New("canonicalize: lone surrogate in string")
	}
	chars := []rune(s)
	if len(chars) == 0 {
		return []nyLeaf{{path: []any{"#chunk", nyNum(0)}, value: ""}}, nil
	}
	step := math.Floor(size)
	if step > float64(len(chars)) {
		step = float64(len(chars))
	}
	n := int(step)
	var out []nyLeaf
	for i, idx := 0, 0; i < len(chars); i, idx = i+n, idx+1 {
		end := i + n
		if end > len(chars) {
			end = len(chars)
		}
		out = append(out, nyLeaf{path: []any{"#chunk", nyNum(idx)}, value: string(chars[i:end])})
	}
	return out, nil
}

func nyLeafObject(path, value, salt any) map[string]any {
	return map[string]any{"p": path, "v": value, "s": salt}
}

func nySalt(opts NotarizeOptions) (string, error) {
	if opts.Salt != nil {
		return b64.EncodeToString(opts.Salt()), nil
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b64.EncodeToString(b), nil
}

// nyHeadersDigest lower-cases and key-sorts the request headers, then hashes them canonically (none = the digest of {}).
func nyHeadersDigest(headers any) (string, error) {
	norm := map[string]any{}
	switch h := headers.(type) {
	case nil:
	case map[string]any:
		for _, k := range sortedKeysUtf8(h) {
			norm[strings.ToLower(k)] = h[k]
		}
	default:
		return "", errors.New("notarizeResponse: request.headers must be an object")
	}
	return HashCanonical(norm)
}

// NotaryMessage is the canonical bytes the notary signs: the domain tag, then sha256(canonical(session)).
func NotaryMessage(session any) ([]byte, error) {
	c, err := Canonicalize(session)
	if err != nil {
		return nil, err
	}
	d := sha256.Sum256([]byte(c))
	return append([]byte(notaryDomain), d[:]...), nil
}

func nyNum(i int) any { return json.Number(strconv.Itoa(i)) }

// NotarizeResponse witnesses a request/response ({"request": {method, url, headers?}, "response": {status, body}}) and returns
// {"attestation": ..., "witness": ...}: the signed attestation (over the canonical session and the body's Merkle root) and the
// witness (the session plus every leaf's opening) the prover keeps private to disclose fields later.
func NotarizeResponse(input any, opts NotarizeOptions) (map[string]any, error) {
	in, ok := nyObj(input)
	if !ok {
		return nil, errors.New("notarizeResponse: input must be an object")
	}
	req, ok := nyObj(in["request"])
	if !ok {
		return nil, errors.New("notarizeResponse: request is required")
	}
	method, _ := req["method"].(string)
	if method == "" {
		return nil, errors.New("notarizeResponse: request.method is required")
	}
	url, _ := req["url"].(string)
	if url == "" {
		return nil, errors.New("notarizeResponse: request.url is required")
	}
	resp, ok := nyObj(in["response"])
	if !ok {
		return nil, errors.New("notarizeResponse: response is required")
	}
	if !jsIsSafeInteger(resp["status"]) {
		return nil, errors.New("notarizeResponse: response.status must be an integer")
	}
	if opts.NotaryKey == nil {
		return nil, errors.New("notarizeResponse: a notary key is required")
	}
	body := resp["body"]
	var bare []nyLeaf
	if s, isStr := body.(string); isStr && opts.TextChunkSize >= 1 {
		var err error
		if bare, err = nyChunk(s, opts.TextChunkSize); err != nil {
			return nil, err
		}
	} else {
		bare = nyFlatten(body, []any{})
	}
	leaves := make([]any, 0, len(bare))
	objs := make([]any, 0, len(bare))
	for _, l := range bare {
		salt, err := nySalt(opts)
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, map[string]any{"path": l.path, "value": l.value, "salt": salt})
		objs = append(objs, nyLeafObject(l.path, l.value, salt))
	}
	root, err := MerkleRoot(objs)
	if err != nil {
		return nil, err
	}
	digest, err := nyHeadersDigest(req["headers"])
	if err != nil {
		return nil, err
	}
	observed := time.Now().UnixMilli()
	if opts.ObservedAt != nil {
		observed = *opts.ObservedAt
	}
	session := map[string]any{
		"v":                    jsNumber(1),
		"method":               strings.ToUpper(method),
		"url":                  url,
		"requestHeadersDigest": digest,
		"responseStatus":       resp["status"],
		"responseBodyCommit":   map[string]any{"alg": NotaryBodyCommitAlg, "root": root, "size": nyNum(len(leaves))},
		"observedAt":           json.Number(strconv.FormatInt(observed, 10)),
	}
	msg, err := NotaryMessage(session)
	if err != nil {
		return nil, err
	}
	att := map[string]any{"session": session, "notary": opts.NotaryKey.Public, "sig": b64.EncodeToString(opts.NotaryKey.Sign(msg))}
	return map[string]any{"attestation": att, "witness": map[string]any{"session": session, "leaves": leaves}}, nil
}

// DiscloseField reveals ONE response field (by path: an array, or a bare string for a single top-level key) with its Merkle
// inclusion proof, keeping every other field hidden. The attestation is unused (the proof binds to the attested root when it is
// verified). A path naming no committed leaf is an error.
func DiscloseField(attestation any, witness any, path any) (map[string]any, error) {
	var want []any
	switch p := path.(type) {
	case string:
		want = []any{p}
	case []any:
		want = append([]any{}, p...)
	default:
		return nil, errors.New("discloseField: path must be an array or a string")
	}
	w, ok := nyObj(witness)
	if !ok {
		return nil, errors.New("discloseField: witness must be an object")
	}
	list, ok := w["leaves"].([]any)
	if !ok {
		return nil, errors.New("discloseField: witness has no leaves")
	}
	idx := -1
	for i, l := range list {
		if l == nil {
			return nil, errors.New("discloseField: a witness leaf is null")
		}
		lm, isMap := nyObj(l)
		if !isMap {
			continue
		}
		if p, has := lm["path"]; has && nyCanonicalEqual(p, want) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, errors.New("discloseField: no committed field at that path")
	}
	hs := make([][]byte, 0, len(list))
	for _, l := range list {
		lm, isMap := nyObj(l)
		if !isMap {
			return nil, errors.New("discloseField: a witness leaf is malformed")
		}
		p, h1 := lm["path"]
		v, h2 := lm["value"]
		s, h3 := lm["salt"]
		if !h1 || !h2 || !h3 {
			return nil, errors.New("discloseField: a witness leaf is malformed")
		}
		h, err := leafHash(nyLeafObject(p, v, s))
		if err != nil {
			return nil, err
		}
		hs = append(hs, h)
	}
	var steps []any
	prove(hs, idx, &steps)
	if steps == nil {
		steps = []any{}
	}
	leaf, _ := nyObj(list[idx])
	return map[string]any{
		"path": leaf["path"], "value": leaf["value"], "salt": leaf["salt"],
		"proof": map[string]any{"index": nyNum(idx), "size": nyNum(len(hs)), "path": steps},
	}, nil
}

func nyValidCommit(c any) bool {
	r, ok := nyObj(c)
	if !ok {
		return false
	}
	if alg, _ := r["alg"].(string); alg != NotaryBodyCommitAlg {
		return false
	}
	root, ok := r["root"].(string)
	if !ok {
		return false
	}
	if _, ok := DecodeB64uStrict(root, 32); !ok {
		return false
	}
	return jsIsSafeInteger(r["size"]) && jsF(r["size"]) >= 1
}

func nyValidSession(s any) bool {
	r, ok := nyObj(s)
	if !ok {
		return false
	}
	if f, ok := jsNum(r["v"]); !ok || f != 1 {
		return false
	}
	for _, k := range []string{"method", "url", "requestHeadersDigest"} {
		if _, ok := r[k].(string); !ok {
			return false
		}
	}
	return jsIsInt(r["responseStatus"]) && jsIsInt(r["observedAt"]) && nyValidCommit(r["responseBodyCommit"])
}

// VerifyNotaryAttestation verifies the notary signature AND the session's structural integrity. notaryKey is the TRUSTED notary's
// key (base64url string, raw public key bytes or *KeyPair): the attestation's recorded signer must equal it and the signature
// must verify over the canonical session. FAILS CLOSED (false) on any deviation, including an unusable notaryKey.
func VerifyNotaryAttestation(attestation any, notaryKey any) bool {
	a, ok := nyObj(attestation)
	if !ok || !nyValidSession(a["session"]) {
		return false
	}
	notary, ok1 := a["notary"].(string)
	sig, ok2 := a["sig"].(string)
	if !ok1 || !ok2 {
		return false
	}
	expected, ok := nyPub(notaryKey)
	if !ok || notary != expected {
		return false
	}
	msg, err := NotaryMessage(a["session"])
	if err != nil {
		return false
	}
	return verifyB64u(notary, msg, sig)
}

// VerifyDisclosedField verifies a disclosed field: the attestation is authentic AND the disclosed leaf is included under the
// attested body root at a position consistent with the committed size. A lie about the value, path or salt breaks inclusion.
func VerifyDisclosedField(attestation any, disclosure any, notaryKey any) bool {
	if !VerifyNotaryAttestation(attestation, notaryKey) {
		return false
	}
	d, ok := nyObj(disclosure)
	if !ok {
		return false
	}
	if _, ok := d["path"].([]any); !ok {
		return false
	}
	salt, ok := d["salt"].(string)
	if !ok {
		return false
	}
	proof, ok := nyObj(d["proof"])
	if !ok {
		return false
	}
	if _, ok := proof["path"].([]any); !ok {
		return false
	}
	session, _ := nyObj(attestation.(map[string]any)["session"])
	commit, _ := nyObj(session["responseBodyCommit"])
	if !jsStrictEq(proof["size"], commit["size"]) {
		return false
	}
	value, has := d["value"]
	if !has {
		return false
	}
	root, _ := commit["root"].(string)
	return VerifyInclusion(root, proof, nyLeafObject(d["path"], value, salt))
}

// FactRef is a stable digest identifying the attested FACT (independent of any PCActn binding). The agent places it in its
// PCActn's provenance.trusted_refs so the action COMMITS to the fact it relies on.
func FactRef(attestation any) (string, error) {
	a, ok := nyObj(attestation)
	if !ok {
		return "", errors.New("factRef: attestation must be an object")
	}
	for _, k := range []string{"session", "notary", "sig"} {
		if _, has := a[k]; !has {
			return "", errors.New("canonicalize: unsupported type undefined")
		}
	}
	return HashCanonical(map[string]any{"fact": "atlas-pca-notary/v1", "session": a["session"], "notary": a["notary"], "sig": a["sig"]})
}

// BindFactToPcActn binds an attested fact to a PCActn by stamping the action's digest into a COPY of the attestation.
func BindFactToPcActn(attestation any, pcActn any) (map[string]any, error) {
	d, err := HashCanonical(pcActn)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	switch a := attestation.(type) {
	case nil:
	case map[string]any:
		for k, v := range a {
			out[k] = v
		}
	default:
		return nil, errors.New("bindFactToPcActn: attestation must be an object")
	}
	out["fact_binding"] = map[string]any{"pcactn_digest": d}
	return out, nil
}

// FactMatchesPcActn is true iff the fact is bound to pcActn in BOTH directions: the fact names the action
// (fact_binding.pcactn_digest equals the action's digest) AND the action commits to the fact (its provenance.trusted_refs lists
// FactRef). False if either side is missing.
func FactMatchesPcActn(attestation any, pcActn any) bool {
	a, ok := nyObj(attestation)
	if !ok {
		return false
	}
	binding, ok := nyObj(a["fact_binding"])
	if !ok {
		return false
	}
	digest, ok := binding["pcactn_digest"].(string)
	if !ok {
		return false
	}
	d, err := HashCanonical(pcActn)
	if err != nil || d != digest {
		return false
	}
	p, ok := nyObj(pcActn)
	if !ok {
		return false
	}
	prov, ok := nyObj(p["provenance"])
	if !ok {
		return false
	}
	refs, ok := prov["trusted_refs"].([]any)
	if !ok {
		return false
	}
	ref, err := FactRef(attestation)
	if err != nil {
		return false
	}
	for _, r := range refs {
		if s, ok := r.(string); ok && s == ref {
			return true
		}
	}
	return false
}

// RequireAttestedFactOpts is the input of RequireAttestedFact. Notary is a base64url string, public key bytes or a *KeyPair;
// Path is an array (or a bare string, as the reference allows); URL and BindToPcActn are optional.
type RequireAttestedFactOpts struct {
	Notary       any
	Path         any
	Equals       any
	URL          *string
	BindToPcActn *bool
}

// RequireAttestedFact builds an attested_fact caveat: the action is admitted only if the agent discloses a notarized response
// field equal to Equals.
func RequireAttestedFact(opts RequireAttestedFactOpts) (map[string]any, error) {
	// a string has a length too: it would pass as a one-segment "path" that no disclosure ever matches
	p, isArr := opts.Path.([]any)
	if !isArr {
		return nil, errors.New("requireAttestedFact: path must be an array of segments")
	}
	notary, ok := nyPub(opts.Notary)
	if !ok {
		return nil, errors.New("requireAttestedFact: notary must be a base64url key, public key bytes or a key pair")
	}
	path := append([]any{}, p...)
	out := map[string]any{"type": NotaryAttestedFactCaveat, "notary": notary, "path": path, "equals": opts.Equals}
	if opts.URL != nil {
		out["url"] = *opts.URL
	}
	if opts.BindToPcActn != nil {
		out["bindToPcActn"] = *opts.BindToPcActn
	}
	return out, nil
}

// IsAttestedFactCaveat is true for a caveat object of type attested_fact with a string notary and an array path.
func IsAttestedFactCaveat(cv any) bool {
	m, ok := nyObj(cv)
	if !ok {
		return false
	}
	if t, _ := m["type"].(string); t != NotaryAttestedFactCaveat {
		return false
	}
	if _, ok := m["notary"].(string); !ok {
		return false
	}
	_, ok = m["path"].([]any)
	return ok
}

// NotaryKeyUsable is true iff key is listed in ring (a list of {key, notBefore?, notAfter?, revoked?}), no entry for it is
// revoked, and observedAt lies in the [notBefore, notAfter) window of at least one entry. A key not listed is refused; the
// window bounds compare with JavaScript coercion, as the reference does.
func NotaryKeyUsable(ring any, key any, observedAt any) bool {
	list, ok := ring.([]any)
	if !ok || !jsIsSafeInteger(observedAt) {
		return false
	}
	at := jsF(observedAt)
	var entries []map[string]any
	for _, e := range list {
		m, ok := nyObj(e)
		if !ok {
			continue
		}
		if kv, has := m["key"]; has && jsStrictEq(kv, key) {
			entries = append(entries, m)
		}
	}
	if len(entries) == 0 {
		return false
	}
	for _, m := range entries {
		if r, _ := m["revoked"].(bool); r {
			return false
		}
	}
	for _, m := range entries {
		nb, hasNb := m["notBefore"]
		na, hasNa := m["notAfter"]
		if (!hasNb || at >= jsToNumber(nb)) && (!hasNa || at < jsToNumber(na)) {
			return true
		}
	}
	return false
}

func nyEvalFail(reason string) map[string]any { return map[string]any{"ok": false, "reason": reason} }

// EvaluateAttestedFactCaveat evaluates an attested_fact caveat against disclosed evidence ({attestation, disclosure, pcActn?}).
// It admits ({"ok": true, "trust": "notary-trusted"}) only when, failing closed at every step: the attestation is authentic under
// the caveat's notary; the optional policy keyring trusts the signer for the observation time; the optional maxAgeMs / now
// freshness holds; the optional URL matches; the disclosed field verifies; its path and value equal the caveat's; and, if
// bindToPcActn is truthy, the fact is two-way-bound to the supplied PCActn. policy is a JSON object (nil = none).
func EvaluateAttestedFactCaveat(caveat any, evidence any, policy any) map[string]any {
	cv, ok := nyObj(caveat)
	if !ok {
		return nyEvalFail("not an attested_fact caveat")
	}
	if t, _ := cv["type"].(string); t != NotaryAttestedFactCaveat {
		return nyEvalFail("not an attested_fact caveat")
	}
	notary, isStr := cv["notary"].(string)
	_, isArr := cv["path"].([]any)
	if !isStr || !isArr {
		return nyEvalFail("caveat is malformed (notary/path)")
	}
	if evidence == nil {
		return nyEvalFail("attested_fact evaluation error (fail closed): Cannot destructure property 'attestation' of 'evidence' as it is null.")
	}
	ev, _ := nyObj(evidence)
	attestation, disclosure, pcActn := ev["attestation"], ev["disclosure"], ev["pcActn"]
	if !VerifyNotaryAttestation(attestation, notary) {
		return nyEvalFail("notary attestation does not verify (fail closed)")
	}
	att, _ := nyObj(attestation)
	session, _ := nyObj(att["session"])
	pol, _ := nyObj(policy)
	if ring, has := pol["keyring"]; has {
		if !NotaryKeyUsable(ring, att["notary"], session["observedAt"]) {
			return nyEvalFail("notary key is not trusted for this observation time (unlisted, revoked or out of window)")
		}
	}
	if maxAge, has := pol["maxAgeMs"]; has {
		now := float64(time.Now().UnixMilli())
		finiteNow := true
		if nv, hasNow := pol["now"]; hasNow && nv != nil {
			f, ok := jsNum(nv)
			now, finiteNow = f, ok && !math.IsInf(f, 0) && !math.IsNaN(f)
		}
		ma, ok := jsNum(maxAge)
		finiteMax := ok && !math.IsInf(ma, 0) && !math.IsNaN(ma)
		age := now - jsF(session["observedAt"])
		if !finiteMax || !finiteNow || age < 0 || age > ma {
			return nyEvalFail("attestation is stale or from the future")
		}
	}
	if u, has := cv["url"]; has && !jsStrictEq(session["url"], u) {
		return nyEvalFail("attested session URL does not match the caveat")
	}
	if !VerifyDisclosedField(attestation, disclosure, notary) {
		return nyEvalFail("disclosed field does not verify under the attested root")
	}
	d, _ := nyObj(disclosure)
	if !nyCanonicalEqual(d["path"], cv["path"]) {
		return nyEvalFail("disclosed field is not the path the caveat requires")
	}
	equals, hasEq := cv["equals"]
	if !hasEq || !nyCanonicalEqual(d["value"], equals) {
		return nyEvalFail("disclosed field value does not satisfy the caveat")
	}
	if jsTruthy(cv["bindToPcActn"]) {
		if !jsTruthy(pcActn) {
			return nyEvalFail("caveat requires PCActn binding but no PCActn was supplied")
		}
		if !FactMatchesPcActn(attestation, pcActn) {
			return nyEvalFail("fact is not bound to this PCActn")
		}
	}
	return map[string]any{"ok": true, "trust": "notary-trusted"}
}
