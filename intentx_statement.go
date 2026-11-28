package pca

// Intent capture and commitment: the principal's own words plus the structured reading, signed, with a content address (the
// intent ref). Shape, Ed25519 signing, and verification through the verifier-pinned suite dispatch.

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

const (
	ixIntentSigDomain = "atlas-pca/intent/v1\x00"
	ixIntentRefDomain = "atlas-pca/intent-ref/v1"
)

var ixSourceKinds = []string{"conversation", "ticket", "document", "form", "other"}

// ixStatementBody is the signed body: suite fields and signatures excluded (the ref names the content).
func ixStatementBody(s map[string]any) map[string]any {
	b := map[string]any{}
	for _, k := range []string{"v", "principal", "text", "slots", "sources", "created_at", "nonce"} {
		if v, ok := s[k]; ok {
			b[k] = ixClone(v)
		}
	}
	return b
}

func ixIntentRef(s map[string]any) string {
	return ixHashCanon(map[string]any{"d": ixIntentRefDomain, "s": ixStatementBody(s)})
}

// ixStatementShapeError is "" when the statement is well-formed.
func ixStatementShapeError(sv any) string {
	s, ok := sv.(map[string]any)
	if !ok {
		return "intent statement is not an object"
	}
	if !jsStrictEq(s["v"], 1.0) {
		return "unsupported intent statement version"
	}
	if p, _ := s["principal"].(string); !ixIsB32(p) {
		return "principal is not canonical base64url (32 bytes)"
	}
	if t, ok := s["text"].(string); !ok || t == "" {
		return "text must be a non-empty string"
	}
	if !ixIsObj(s["slots"]) {
		return "slots must be an object"
	}
	sources, ok := s["sources"].([]any)
	if !ok {
		return "sources must be an array"
	}
	for i, sv := range sources {
		src, ok := sv.(map[string]any)
		kind, _ := src["kind"].(string)
		if !ok || ixIndexOf(ixSourceKinds, kind) < 0 {
			return fmt.Sprintf("sources[%d] has an unknown kind", i)
		}
		if u, has := src["uri"]; has && !ixIsStr(u) {
			return fmt.Sprintf("sources[%d].uri must be a string", i)
		}
		if !ixIsB32(src["digest"]) {
			return fmt.Sprintf("sources[%d].digest is not canonical base64url (32 bytes)", i)
		}
	}
	if ca, _ := s["created_at"].(float64); !jsIsSafeInteger(s["created_at"]) || ca < 0 {
		return "created_at must be a non-negative safe integer (epoch ms)"
	}
	if n, ok := s["nonce"].(string); !ok || n == "" {
		return "nonce must be a non-empty string"
	}
	return ""
}

func ixStatementMessage(body map[string]any) ([]byte, bool) {
	b, ok := ixStrictCanon(body)
	if !ok {
		return nil, false
	}
	return append([]byte(ixIntentSigDomain), b...), true
}

// ixSignIntent signs a statement as its principal (an Ed25519 seed); `principal` defaults to the key of the seed.
func ixSignIntent(s map[string]any, seedB64 string) map[string]any {
	seed, ok := DecodeB64uStrict(seedB64, 32)
	if !ok {
		ixFail("secret key must be a 32-byte seed")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	principal := base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	if p, has := s["principal"]; has && p != principal {
		ixFail("signIntentStatement: principal key mismatch")
	}
	withP := ixCopyMap(s)
	withP["principal"] = principal
	body := ixStatementBody(withP)
	if bad := ixStatementShapeError(body); bad != "" {
		ixFail("signIntentStatement: %s", bad)
	}
	msg, ok := ixStatementMessage(body)
	if !ok {
		ixFail("statement is not canonicalizable")
	}
	out := ixCopyMap(body)
	out["sig"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, msg))
	return out
}

// ixVerifyIntent verifies a signed statement (shape, signer, suite signature; a PQ key must be pinned via opts.pqPins).
func ixVerifyIntent(sv any, opts map[string]any) map[string]any {
	fail := func(r string) map[string]any { return map[string]any{"ok": false, "reason": r} }
	if bad := ixStatementShapeError(sv); bad != "" {
		return fail(bad)
	}
	s := sv.(map[string]any)
	if es := opts["expectedSigner"]; es != nil && s["principal"] != es {
		return fail("principal mismatch")
	}
	alg, algP := s["alg"]
	pqPk, pqPkP := s["pq_pk"]
	_, pqSigP := s["pq_sig"]
	if algP && !suiteSupported(alg, true) {
		return fail("unknown signature suite")
	}
	if (!algP || alg == "ed25519") && (pqPkP || pqSigP) {
		return fail("an ed25519 artifact must not carry pq_pk / pq_sig")
	}
	body, ok := bindSuiteFields(ixStatementBody(s), alg, algP, pqPk, pqPkP)
	if !ok {
		return fail("malformed intent statement: canonicalize: unsupported type undefined")
	}
	msg, ok := ixStatementMessage(body)
	if !ok {
		return fail("malformed intent statement: the statement is not canonicalizable")
	}
	if !verifyPinnedSuite(alg, algP, ixS(s["principal"]), pqPk, msg, s["sig"], s["pq_sig"], ixPqPins(opts)) {
		return fail("bad signature")
	}
	return map[string]any{"ok": true}
}
