package pca

// Signed Agent Cards, AgentFacts attested by PCA, the well-known hosting handlers and the registry entry (port of the
// TypeScript @atlasauth/pca-agentcard). The card side is the A2A 1.0 AgentCardSignature: RFC 8785 canonical bytes of the card
// minus `signatures`, a detached-payload JWS (`b64:false`, `crit:["b64"]`) or the A2A 1.0 section 8.4 signing input, and the
// `pca_passport` protected-header commitment. Cards, facts and options are JSON values (map[string]any / []any, numbers as
// json.Number or float64) and results are JSON maps shaped like the reference; every refusal fails closed.
//
// shortcut: signing supports EdDSA over an Ed25519 private JWK only (any other alg or key refuses); upgrade if ES256 / RS256
// issuers are needed. Verification accepts every JOSE algorithm the package's JOSE layer supports.
// shortcut: validity windows are read as ISO 8601 (YYYY[-MM[-DD]] with an optional THH:mm[:ss[.fff]] and Z or +HH:mm; a time
// without an offset reads as UTC). The legacy free-form spellings a JavaScript runtime also accepts are refused as not a valid
// date, which only narrows what is accepted.
// shortcut: a handler body is JSON.stringify with the member order the value's parser recorded; a value built in code has no
// recorded order and is written with sorted keys.

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// AgentCardDefaultAlg is the default JWS algorithm for card and attestation signatures.
	AgentCardDefaultAlg = "EdDSA"
	// AgentCardAttestorID is the attestor identity recorded when PCA signs an AgentFacts attestation.
	AgentCardAttestorID = "did:atlas:pca-attestor"
	// AgentCardWellKnownPath is where a signed Agent Card is served.
	AgentCardWellKnownPath = "/.well-known/agent-card.json"
	// AgentFactsWellKnownPath is where an AgentFacts document is served.
	AgentFactsWellKnownPath = "/.well-known/agent-facts.json"

	agentcardPassportHeader    = "pca_passport"
	agentcardAttestationDomain = "atlas-pca/agentfacts/attestation/v1"
	agentcardMaxDepth          = 64
)

// AgentFactsContext is the default JSON-LD @context of an AgentFacts document.
var AgentFactsContext = []string{"https://www.w3.org/ns/did/v1", "https://nanda.ai/agentfacts/v1"}

// ---- small JS-semantics helpers -----------------------------------------------------------------------------------

func agentcardCopy(m map[string]any) map[string]any {
	out := make(map[string]any, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// agentcardPresent reports whether the member is present and not null (the `??` test).
func agentcardPresent(m map[string]any, k string) bool {
	v, has := m[k]
	return has && v != nil
}

func agentcardAlg(opts map[string]any) (string, error) {
	if !agentcardPresent(opts, "alg") {
		return AgentCardDefaultAlg, nil
	}
	s, ok := opts["alg"].(string)
	if !ok {
		return "", errors.New("alg must be a string")
	}
	return s, nil
}

func agentcardJSON(v any) (string, error) {
	s, ok := canonicalLenient(v)
	if !ok {
		return "", fmt.Errorf("not serializable: %T", v)
	}
	return s, nil
}

// ---- RFC 8785 -----------------------------------------------------------------------------------------------------

// AgentCardJCS is the RFC 8785 canonical UTF-8 bytes of a JSON value: members sorted by UTF-16 code units, numbers by the
// ECMAScript rule, strings with the minimal escapes. A lone surrogate, a non-finite number, a value with no JSON form or
// nesting over 64 refuses.
func AgentCardJCS(v any) ([]byte, error) {
	s, err := agentcardJCS(v, 1)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

func agentcardJCS(v any, depth int) (string, error) {
	switch t := v.(type) {
	case nil:
		return "null", nil
	case bool:
		if t {
			return "true", nil
		}
		return "false", nil
	case string:
		if hasLoneSurrogate(t) {
			return "", errors.New("jcs: lone surrogate in string")
		}
		var sb strings.Builder
		lenientString(&sb, t)
		return sb.String(), nil
	case []any:
		if depth > agentcardMaxDepth {
			return "", errors.New("jcs: nesting too deep")
		}
		parts := make([]string, len(t))
		for i, x := range t {
			s, err := agentcardJCS(x, depth+1)
			if err != nil {
				return "", err
			}
			parts[i] = s
		}
		return "[" + strings.Join(parts, ",") + "]", nil
	case map[string]any:
		if depth > agentcardMaxDepth {
			return "", errors.New("jcs: nesting too deep")
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return compareUnits(utf16Units(keys[i]), utf16Units(keys[j])) < 0 })
		parts := make([]string, len(keys))
		for i, k := range keys {
			if hasLoneSurrogate(k) {
				return "", errors.New("jcs: lone surrogate in key")
			}
			var sb strings.Builder
			lenientString(&sb, k)
			s, err := agentcardJCS(t[k], depth+1)
			if err != nil {
				return "", err
			}
			parts[i] = sb.String() + ":" + s
		}
		return "{" + strings.Join(parts, ",") + "}", nil
	}
	f, ok := jsNum(v)
	if !ok {
		return "", fmt.Errorf("jcs: unsupported type %T", v)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", errors.New("jcs: non-finite number")
	}
	return jsLenientNumber(f), nil
}

// ---- A2A 1.0 AgentCard message ------------------------------------------------------------------------------------

// AgentCardValidate1 checks a value against the A2A 1.0 AgentCard message and returns the problems found, each with a JSON
// path (empty = valid). Unknown members are allowed; securitySchemes and securityRequirements are checked for shape only.
func AgentCardValidate1(card any) []string {
	p := []string{}
	m, ok := card.(map[string]any)
	if !ok {
		return []string{"$: the agent card must be an object"}
	}
	isStr := func(v any) bool { _, ok := v.(string); return ok }
	isObj := func(v any) bool { _, ok := v.(map[string]any); return ok }
	reqStr := func(o map[string]any, k, at string) {
		if s, ok := o[k].(string); !ok || s == "" {
			p = append(p, at+"."+k+": required non-empty string")
		}
	}
	optStr := func(o map[string]any, k, at string) {
		if v, has := o[k]; has && !isStr(v) {
			p = append(p, at+"."+k+": must be a string")
		}
	}
	optBool := func(o map[string]any, k, at string) {
		if v, has := o[k]; has {
			if _, isB := v.(bool); !isB {
				p = append(p, at+"."+k+": must be a boolean")
			}
		}
	}
	strArray := func(v any, at string, nonEmpty bool) {
		l, ok := v.([]any)
		all := ok
		for _, x := range l {
			all = all && isStr(x)
		}
		switch {
		case !ok || !all:
			p = append(p, at+": must be an array of strings")
		case nonEmpty && len(l) == 0:
			p = append(p, at+": must not be empty")
		}
	}
	objArray := func(o map[string]any, k, at string, required, nonEmpty bool, each func(e map[string]any, at string)) {
		v, has := o[k]
		if !has {
			if required {
				p = append(p, at+"."+k+": required array")
			}
			return
		}
		l, ok := v.([]any)
		if !ok {
			p = append(p, at+"."+k+": must be an array")
			return
		}
		if nonEmpty && len(l) == 0 {
			p = append(p, at+"."+k+": must not be empty")
		}
		for i, e := range l {
			if em, ok := e.(map[string]any); ok {
				each(em, at+"."+k+"["+strconv.Itoa(i)+"]")
			} else {
				p = append(p, at+"."+k+"["+strconv.Itoa(i)+"]: must be an object")
			}
		}
	}

	reqStr(m, "name", "$")
	reqStr(m, "description", "$")
	reqStr(m, "version", "$")
	optStr(m, "documentationUrl", "$")
	optStr(m, "iconUrl", "$")
	objArray(m, "supportedInterfaces", "$", true, true, func(e map[string]any, at string) {
		reqStr(e, "url", at)
		reqStr(e, "protocolBinding", at)
		reqStr(e, "protocolVersion", at)
		optStr(e, "tenant", at)
	})
	if v, has := m["provider"]; has {
		if pm, ok := v.(map[string]any); !ok {
			p = append(p, "$.provider: must be an object")
		} else {
			reqStr(pm, "url", "$.provider")
			reqStr(pm, "organization", "$.provider")
		}
	}
	if c, ok := m["capabilities"].(map[string]any); !ok {
		p = append(p, "$.capabilities: required object")
	} else {
		optBool(c, "streaming", "$.capabilities")
		optBool(c, "pushNotifications", "$.capabilities")
		optBool(c, "extendedAgentCard", "$.capabilities")
		objArray(c, "extensions", "$.capabilities", false, false, func(e map[string]any, at string) {
			optStr(e, "uri", at)
			optStr(e, "description", at)
			optBool(e, "required", at)
			if v, has := e["params"]; has && !isObj(v) {
				p = append(p, at+".params: must be an object")
			}
		})
	}
	if v, has := m["securitySchemes"]; has && !isObj(v) {
		p = append(p, "$.securitySchemes: must be an object")
	}
	if v, has := m["securityRequirements"]; has {
		if _, isL := v.([]any); !isL {
			p = append(p, "$.securityRequirements: must be an array")
		}
	}
	for _, k := range []string{"defaultInputModes", "defaultOutputModes"} {
		if v, has := m[k]; !has {
			p = append(p, "$."+k+": required array of strings")
		} else {
			strArray(v, "$."+k, true)
		}
	}
	objArray(m, "skills", "$", true, false, func(e map[string]any, at string) {
		reqStr(e, "id", at)
		reqStr(e, "name", at)
		reqStr(e, "description", at)
		if v, has := e["tags"]; !has {
			p = append(p, at+".tags: required array of strings")
		} else {
			strArray(v, at+".tags", false)
		}
		for _, k := range []string{"examples", "inputModes", "outputModes"} {
			if v, has := e[k]; has {
				strArray(v, at+"."+k, false)
			}
		}
		if v, has := e["securityRequirements"]; has {
			if _, isL := v.([]any); !isL {
				p = append(p, at+".securityRequirements: must be an array")
			}
		}
	})
	objArray(m, "signatures", "$", false, false, func(e map[string]any, at string) {
		reqStr(e, "protected", at)
		reqStr(e, "signature", at)
		if v, has := e["header"]; has && !isObj(v) {
			p = append(p, at+".header: must be an object")
		}
	})
	return p
}

// ---- keys + detached JWS ------------------------------------------------------------------------------------------

// agentcardSignDetached signs payload with an Ed25519 private JWK. members are pre-rendered `"name":json` protected-header
// members appended after alg, (typ | b64 + crit) and kid.
func agentcardSignDetached(payload []byte, key any, alg string, kid any, hasKid bool, members []string, standard bool) (map[string]any, error) {
	jwk, ok := key.(map[string]any)
	if !ok {
		return nil, errors.New("the signing key must be a private JWK")
	}
	if alg != AgentCardDefaultAlg || jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519" {
		return nil, errors.New("Invalid key for this operation: only EdDSA over an Ed25519 private JWK signs")
	}
	seed, err := jwkB64(jwk, "d")
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("KeyObject instances for asymmetric algorithm signing must be of type \"private\"")
	}
	algJSON, err := agentcardJSON(alg)
	if err != nil {
		return nil, err
	}
	h := []string{`"alg":` + algJSON}
	if standard {
		h = append(h, `"typ":"JOSE"`)
	} else {
		h = append(h, `"b64":false`, `"crit":["b64"]`)
	}
	if hasKid {
		k, err := agentcardJSON(kid)
		if err != nil {
			return nil, err
		}
		h = append(h, `"kid":`+k)
	}
	h = append(h, members...)
	prot := b64.EncodeToString([]byte("{" + strings.Join(h, ",") + "}"))
	body := payload
	if standard {
		body = []byte(b64.EncodeToString(payload))
	}
	input := append([]byte(prot+"."), body...)
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), input)
	return map[string]any{"protected": prot, "signature": b64.EncodeToString(sig)}, nil
}

// agentcardKey is the verification key source: a JWKS (kid resolved) or one key. dead is a key that no signature verifies under.
type agentcardKey struct {
	set  OidcKeyResolver
	key  *JOSEKey
	dead bool
}

// agentcardResolve is resolveVerifyKey: a JWKS or a single key, or the reason there is none.
func agentcardResolve(opts map[string]any) (*agentcardKey, string) {
	if jsTruthy(opts["jwks"]) {
		set, err := NewLocalJWKSet(opts["jwks"])
		if err != nil {
			return nil, "could not resolve verification key: " + err.Error()
		}
		return &agentcardKey{set: set}, ""
	}
	if k, has := opts["key"]; has {
		m, isMap := k.(map[string]any)
		if _, hasKty := m["kty"]; !isMap || !hasKty {
			return &agentcardKey{dead: true}, "" // not a JWK: handed to the verifier as is, which refuses it
		}
		jk, err := agentcardImportKey(m)
		if err != nil {
			return nil, "could not resolve verification key: " + err.Error()
		}
		return &agentcardKey{key: jk}, ""
	}
	return nil, "no verification key or JWKS supplied"
}

// agentcardImportKey imports a JWK for verification. A private JWK verifies as its public key.
func agentcardImportKey(m map[string]any) (*JOSEKey, error) {
	kty, _ := m["kty"].(string)
	switch kty {
	case "oct":
		if s, ok := m["k"].(string); !ok || s == "" {
			return nil, errors.New(`missing "k"`)
		}
		k, err := jwkB64(m, "k")
		if err != nil {
			return nil, err
		}
		return &JOSEKey{Kty: kty, HMAC: k}, nil
	case "OKP", "EC", "RSA":
	default:
		return nil, errors.New(`Unsupported "kty" (Key Type) Parameter value`)
	}
	if jsTruthy(m["d"]) && kty == "OKP" && m["crv"] == "Ed25519" {
		seed, err := jwkB64(m, "d")
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, errors.New("invalid Ed25519 private key")
		}
		return &JOSEKey{Kty: kty, Crv: "Ed25519", Ed25519: ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)}, nil
	}
	pub := agentcardCopy(m)
	for _, p := range jwkPrivateMembers {
		delete(pub, p)
	}
	return ImportPublicJWK(pub)
}

// agentcardVerifyDetached verifies a detached-payload JWS over payload. It returns the protected header, or the reason it did
// not verify; the error is a throw of the reference (a null signature).
func agentcardVerifyDetached(payload []byte, sig any, r *agentcardKey) (map[string]any, string, error) {
	if sig == nil {
		return nil, "", errors.New("Cannot read properties of null (reading 'protected')")
	}
	sm, ok := sig.(map[string]any)
	if !ok {
		return nil, "signature is malformed", nil
	}
	prot, ok1 := sm["protected"].(string)
	sg, ok2 := sm["signature"].(string)
	if !ok1 || !ok2 {
		return nil, "signature is malformed", nil
	}
	header, sigBytes, err := gnapJwsSegments(prot, sg) // canonical-spelling gate BEFORE the signature check
	if err != nil {
		return nil, err.Error(), nil
	}
	rawBody := false // the payload is signed as raw bytes (b64:false) rather than as its base64url text
	if c, has := header["crit"]; has {
		l, ok := c.([]any)
		if !ok || len(l) == 0 {
			return nil, `"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present`, nil
		}
		for _, x := range l {
			if s, ok := x.(string); !ok || s != "b64" {
				return nil, "Extension Header Parameter is not recognized", nil
			}
		}
		b, isB := header["b64"].(bool)
		if !isB {
			return nil, `The "b64" (base64url-encode payload) Header Parameter must be a boolean`, nil
		}
		rawBody = !b
	} else if b, isB := header["b64"].(bool); isB && !b {
		return nil, "JWS Payload must be a string", nil
	}
	alg, _ := header["alg"].(string)
	if alg == "" {
		return nil, `JWS "alg" (Algorithm) Header Parameter missing or invalid`, nil
	}
	var k *JOSEKey
	switch {
	case r.dead:
		return nil, "Key must be one of type KeyObject, CryptoKey or Uint8Array", nil
	case r.set != nil:
		k, err = r.set(header)
		if err != nil {
			return nil, err.Error(), nil
		}
	default:
		k = r.key
	}
	if k == nil || !joseKeyFits(alg, k) {
		return nil, "Invalid key for this operation", nil
	}
	body := payload
	if !rawBody {
		body = []byte(b64.EncodeToString(payload))
	}
	if !JOSEVerify(alg, k, append([]byte(prot+"."), body...), sigBytes) {
		return nil, "signature verification failed", nil
	}
	return header, "", nil
}

// ---- 1. signed Agent Card -----------------------------------------------------------------------------------------

// AgentCardBuild builds an unsigned A2A Agent Card whose metadata points at the PCA passport (`pcaPassport`) and, when given,
// the live proof endpoint (`pcaProof`). passport is a full passport or a bare {id, uri?} reference; its own uri wins over
// opts.passportUri. opts: name (required), description, url, version, skills, passportUri, pcaProofRef.
func AgentCardBuild(passport any, opts map[string]any) (map[string]any, error) {
	pm, ok := passport.(map[string]any)
	if !ok {
		return nil, errors.New("Cannot use 'in' operator to search for 'model_id' in a non-object")
	}
	id, hasID := pm["id"]
	if !hasID {
		return nil, errors.New("buildAgentCard: the passport has no id")
	}
	name, hasName := opts["name"]
	if !hasName {
		return nil, errors.New("buildAgentCard: name is required")
	}
	ref := map[string]any{"id": id}
	if _, full := pm["model_id"]; full {
		if u, has := opts["passportUri"]; has {
			ref["uri"] = u
		}
	} else if u, has := pm["uri"]; has {
		ref["uri"] = u
	} else if u, has := opts["passportUri"]; has {
		ref["uri"] = u
	}
	card := map[string]any{"name": name}
	for _, k := range []string{"description", "url", "version", "skills"} {
		if v, has := opts[k]; has {
			card[k] = v
		}
	}
	card["pcaPassport"] = ref
	if v, has := opts["pcaProofRef"]; has {
		card["pcaProof"] = v
	}
	return card, nil
}

// agentcardSigningBytes is the canonical bytes a card signature covers: the card with `signatures` removed.
func agentcardSigningBytes(card map[string]any) ([]byte, error) {
	rest := agentcardCopy(card)
	delete(rest, "signatures")
	return AgentCardJCS(rest)
}

// agentcardPrior is `[...existing]` for the signatures a card already carries.
func agentcardPrior(existing any) ([]any, error) {
	switch t := existing.(type) {
	case nil:
		return []any{}, nil
	case []any:
		return append([]any{}, t...), nil
	case string:
		out := []any{}
		for _, r := range t {
			out = append(out, string(r))
		}
		return out, nil
	}
	return nil, errors.New("existing is not iterable")
}

// AgentCardIssueSigned signs an Agent Card: the passport reference is embedded (and committed in the signed protected header as
// `pca_passport`) before signing, the canonical card minus `signatures` is signed, and the signature is appended. opts: alg
// (EdDSA), passport ({id, uri?} to embed instead of the card's own), kid, profile ("pca-detached" default, or "a2a-1.0" which
// needs a kid and signs the A2A 1.0 section 8.4 input) and schema ("a2a-1.0" refuses a card that does not match the message).
func AgentCardIssueSigned(card map[string]any, signingKey any, opts map[string]any) (map[string]any, error) {
	if card == nil {
		return nil, errors.New("issueSignedAgentCard: the card must be an object")
	}
	var passport any = card["pcaPassport"]
	if p, has := opts["passport"]; has && jsTruthy(p) {
		pm, _ := p.(map[string]any)
		id, hasID := pm["id"]
		if !hasID {
			return nil, errors.New("jcs: unsupported type undefined") // {id: undefined} has no canonical form
		}
		np := map[string]any{"id": id}
		if u, has := pm["uri"]; has {
			np["uri"] = u
		}
		passport = np
	}
	toSign := agentcardCopy(card)
	if jsTruthy(passport) {
		toSign["pcaPassport"] = passport
	}
	if s, _ := opts["schema"].(string); s == "a2a-1.0" {
		if problems := AgentCardValidate1(toSign); len(problems) > 0 {
			return nil, errors.New("issueSignedAgentCard: the card does not match the A2A 1.0 schema: " + strings.Join(problems, "; "))
		}
	}
	payload, err := agentcardSigningBytes(toSign)
	if err != nil {
		return nil, err
	}
	spec := false
	if s, _ := opts["profile"].(string); s == "a2a-1.0" {
		spec = true
	}
	kid, hasKid := opts["kid"]
	if ks, _ := kid.(string); spec && ks == "" {
		return nil, errors.New("issueSignedAgentCard: the 'a2a-1.0' profile requires a kid")
	}
	alg, err := agentcardAlg(opts)
	if err != nil {
		return nil, err
	}
	var members []string
	if jsTruthy(passport) {
		if pm, ok := passport.(map[string]any); ok {
			if pid, has := pm["id"]; has {
				j, err := agentcardJSON(pid)
				if err != nil {
					return nil, err
				}
				members = append(members, `"`+agentcardPassportHeader+`":`+j)
			}
		}
	}
	sig, err := agentcardSignDetached(payload, signingKey, alg, kid, hasKid, members, spec)
	if err != nil {
		return nil, err
	}
	prior, err := agentcardPrior(toSign["signatures"])
	if err != nil {
		return nil, err
	}
	out := agentcardCopy(toSign)
	out["signatures"] = append(prior, sig)
	return out, nil
}

// AgentCardVerify validates a card against its signature(s). Fail closed: no signatures, an unresolvable key or ANY signature that
// does not verify over the canonical card (minus `signatures`) refuses ({ok:false, reason}). opts: jwks, key, alg, schema
// ("a2a-1.0"). On success the result names the passport id the signature commits to (passportRef) and carries the passport and
// proof pointers of the card body.
func AgentCardVerify(card any, opts map[string]any) (map[string]any, error) {
	fail := func(reason string) (map[string]any, error) { return map[string]any{"ok": false, "reason": reason}, nil }
	var cm map[string]any
	switch c := card.(type) {
	case map[string]any:
		cm = c
	case []any:
	default:
		return fail("agent card is not an object")
	}
	sigs, ok := cm["signatures"].([]any)
	if !ok || len(sigs) == 0 {
		return fail("agent card carries no signatures")
	}
	if s, _ := opts["schema"].(string); s == "a2a-1.0" {
		if problems := AgentCardValidate1(card); len(problems) > 0 {
			return fail("agent card does not match the A2A 1.0 schema: " + strings.Join(problems, "; "))
		}
	}
	r, reason := agentcardResolve(opts)
	if r == nil {
		return fail(reason)
	}
	payload, err := agentcardSigningBytes(cm)
	if err != nil {
		return fail("agent card has no canonical form: " + err.Error())
	}
	passportRef, haveRef := "", false
	for i, sig := range sigs {
		if !jsTruthy(sig) {
			return fail(fmt.Sprintf("signature %d is missing", i))
		}
		h, why, err := agentcardVerifyDetached(payload, sig, r)
		if err != nil {
			return nil, err
		}
		if why != "" {
			return fail(fmt.Sprintf("signature %d did not verify: %s", i, why))
		}
		if ref, ok := h[agentcardPassportHeader].(string); ok && !haveRef {
			passportRef, haveRef = ref, true
		}
	}
	out := map[string]any{"ok": true}
	if haveRef {
		out["passportRef"] = passportRef
	}
	if jsTruthy(cm["pcaPassport"]) {
		out["passport"] = cm["pcaPassport"]
	}
	if jsTruthy(cm["pcaProof"]) {
		out["pcaProof"] = cm["pcaProof"]
	}
	return out, nil
}

// ---- 2. AgentFacts ------------------------------------------------------------------------------------------------

var agentcardISORe = regexp.MustCompile(`^([+-]\d{6}|\d{4})(?:-(\d{2})(?:-(\d{2}))?)?(?:T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?(Z|[+-]\d{2}:\d{2})?)?$`)

func agentcardDaysFromCivil(y, m, d int) int {
	if m <= 2 {
		y--
	}
	era := y / 400
	if y < 0 && y%400 != 0 {
		era--
	}
	yoe := y - era*400
	mp := m - 3
	if m <= 2 {
		mp = m + 9
	}
	doy := (153*mp+2)/5 + d - 1
	return era*146097 + yoe*365 + yoe/4 - yoe/100 + doy - 719468
}

// agentcardDateParse is Date.parse for the ISO 8601 spellings (epoch milliseconds); ok is false for anything else.
func agentcardDateParse(v any) (float64, bool) {
	s, isS := v.(string)
	if !isS {
		return 0, false
	}
	m := agentcardISORe.FindStringSubmatch(s)
	if m == nil || m[1] == "-000000" {
		return 0, false
	}
	num := func(x string, def int) int {
		if x == "" {
			return def
		}
		n, _ := strconv.Atoi(x)
		return n
	}
	y, _ := strconv.Atoi(m[1])
	mo, d := num(m[2], 1), num(m[3], 1)
	hh, mi, ss := num(m[4], 0), num(m[5], 0), num(m[6], 0)
	ms := 0
	if m[7] != "" {
		ms, _ = strconv.Atoi((m[7] + "00")[:3])
	}
	if mo < 1 || mo > 12 || d < 1 || d > 31 || mi > 59 || ss > 59 || hh > 24 || (hh == 24 && (mi != 0 || ss != 0 || ms != 0)) {
		return 0, false
	}
	off := 0
	if tz := m[8]; tz != "" && tz != "Z" {
		oh, _ := strconv.Atoi(tz[1:3])
		om, _ := strconv.Atoi(tz[4:6])
		if oh > 23 || om > 59 {
			return 0, false
		}
		off = oh*60 + om
		if tz[0] == '-' {
			off = -off
		}
	}
	t := (int64(agentcardDaysFromCivil(y, mo, d))*86400+int64(hh*3600+mi*60+ss))*1000 + int64(ms) - int64(off)*60000
	if t > 8_640_000_000_000_000 || t < -8_640_000_000_000_000 {
		return 0, false
	}
	return float64(t), true
}

// agentcardISO is new Date(ms).toISOString().
func agentcardISO(ms float64) (string, error) {
	if math.IsNaN(ms) || math.Abs(ms) > 8.64e15 {
		return "", errors.New("Invalid time value")
	}
	t := time.UnixMilli(int64(math.Trunc(ms))).UTC()
	y := t.Year()
	ys := fmt.Sprintf("%04d", y)
	if y < 0 {
		ys = fmt.Sprintf("-%06d", -y)
	} else if y > 9999 {
		ys = fmt.Sprintf("+%06d", y)
	}
	return fmt.Sprintf("%s-%02d-%02dT%02d:%02d:%02d.%03dZ", ys, int(t.Month()), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond()/1000000), nil
}

// agentcardStatementBytes is the canonical statement an attestation signature covers (everything but the signature).
func agentcardStatementBytes(a map[string]any) ([]byte, error) {
	for _, k := range []string{"issuer", "subject", "attests", "validFrom"} {
		if _, has := a[k]; !has {
			return nil, errors.New("canonicalize: unsupported type undefined")
		}
	}
	var until any
	if v, has := a["validUntil"]; has {
		until = v
	}
	s, err := Canonicalize(map[string]any{
		"d": agentcardAttestationDomain, "issuer": a["issuer"], "subject": a["subject"], "attests": a["attests"],
		"validFrom": a["validFrom"], "validUntil": until,
	})
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

// agentcardAttest builds and signs one attestation statement.
func agentcardAttest(subject any, opts map[string]any) (map[string]any, error) {
	issuer := any(AgentCardAttestorID)
	if agentcardPresent(opts, "attestorId") {
		issuer = opts["attestorId"]
	}
	attests, has := opts["attests"]
	if !has {
		return nil, errors.New("canonicalize: unsupported type undefined")
	}
	var validFrom any
	if agentcardPresent(opts, "validFrom") {
		validFrom = opts["validFrom"]
	} else {
		ms := float64(time.Now().UnixMilli())
		if agentcardPresent(opts, "now") {
			f, ok := jsNum(opts["now"])
			if !ok {
				return nil, errors.New("now must be a number of epoch milliseconds")
			}
			ms = f
		}
		iso, err := agentcardISO(ms)
		if err != nil {
			return nil, err
		}
		validFrom = iso
	}
	st := map[string]any{"issuer": issuer, "subject": subject, "attests": attests, "validFrom": validFrom}
	if u, has := opts["validUntil"]; has {
		st["validUntil"] = u
	}
	payload, err := agentcardStatementBytes(st)
	if err != nil {
		return nil, err
	}
	alg, err := agentcardAlg(opts)
	if err != nil {
		return nil, err
	}
	who, err := agentcardJSON(issuer)
	if err != nil {
		return nil, err
	}
	kid, hasKid := opts["kid"]
	sig, err := agentcardSignDetached(payload, opts["attestorKey"], alg, kid, hasKid, []string{`"attestor":` + who}, false)
	if err != nil {
		return nil, err
	}
	st["signature"] = sig
	return st, nil
}

// AgentFactsIssue issues an AgentFacts document for a PCA passport with PCA as the THIRD-PARTY ATTESTOR: the agent's selfAsserted
// claims are carried verbatim and unsigned, the attests claims are wrapped in a statement (issuer, subject, validity) and signed.
// opts: attestorKey, attests, selfAsserted, attestorId, agentId, alg, kid, validFrom, validUntil, now (epoch ms), context.
func AgentFactsIssue(passport any, opts map[string]any) (map[string]any, error) {
	agentID := opts["agentId"]
	if !agentcardPresent(opts, "agentId") {
		pm, ok := passport.(map[string]any)
		if !ok && passport == nil {
			return nil, errors.New("Cannot read properties of null (reading 'id')")
		}
		id, hasID := pm["id"]
		if !hasID {
			return nil, errors.New("canonicalize: unsupported type undefined")
		}
		agentID = id
	}
	att, err := agentcardAttest(agentID, opts)
	if err != nil {
		return nil, err
	}
	var ctx any = []any{AgentFactsContext[0], AgentFactsContext[1]}
	if agentcardPresent(opts, "context") {
		ctx = opts["context"]
	}
	var self any = map[string]any{}
	if agentcardPresent(opts, "selfAsserted") {
		self = opts["selfAsserted"]
	}
	return map[string]any{"@context": ctx, "id": agentID, "type": "AgentFacts", "selfAsserted": self, "attestations": []any{att}}, nil
}

// AgentFactsAddAttestation returns a copy of an AgentFacts document with one more third-party attestation appended (several
// attestors each vouch for a different subset of claims). opts as AgentFactsIssue.
func AgentFactsAddAttestation(facts any, opts map[string]any) (map[string]any, error) {
	fm, ok := facts.(map[string]any)
	if !ok {
		return nil, errors.New("addAttestation: facts must be an AgentFacts object")
	}
	id, hasID := fm["id"]
	if !hasID {
		return nil, errors.New("canonicalize: unsupported type undefined")
	}
	att, err := agentcardAttest(id, opts)
	if err != nil {
		return nil, err
	}
	if fm["attestations"] == nil {
		return nil, errors.New("facts.attestations is not iterable")
	}
	prior, err := agentcardPrior(fm["attestations"])
	if err != nil {
		return nil, err
	}
	out := agentcardCopy(fm)
	out["attestations"] = append(prior, att)
	return out, nil
}

func agentcardIssuerOf(a any) string {
	if m, ok := a.(map[string]any); ok {
		if s, ok := m["issuer"].(string); ok {
			return s
		}
	}
	return "<unknown>"
}

// agentcardVerifyOne checks one attestation: shape, subject, validity window, then the detached signature.
func agentcardVerifyOne(a any, docID any, haveID bool, now float64, r *agentcardKey) (map[string]any, error) {
	issuer := agentcardIssuerOf(a)
	no := func(reason string) (map[string]any, error) {
		return map[string]any{"issuer": issuer, "ok": false, "reason": reason}, nil
	}
	am, _ := a.(map[string]any)
	subject, subjOK := am["subject"].(string)
	attests, attOK := am["attests"].(map[string]any)
	from, fromOK := am["validFrom"].(string)
	if !jsTruthy(a) || !subjOK || !attOK || !fromOK {
		return no("attestation is malformed")
	}
	if id, isS := docID.(string); !haveID || !isS || id != subject {
		shown := "undefined"
		if haveID {
			shown = jsValueString(docID)
		}
		return no(fmt.Sprintf("attestation subject '%s' does not match agent id '%s'", subject, shown))
	}
	start, ok := agentcardDateParse(from)
	if !ok {
		return no("attestation validFrom is not a valid date")
	}
	if !(finite(now) && finite(start) && now >= start) {
		return no("attestation is not yet valid")
	}
	if u, has := am["validUntil"]; has {
		until, ok := agentcardDateParse(u)
		if !ok {
			return no("attestation validUntil is not a valid date")
		}
		if !(finite(now) && finite(until) && now <= until) {
			return no("attestation has expired")
		}
	}
	if r == nil {
		return no("no verification key or JWKS supplied")
	}
	payload, err := agentcardStatementBytes(am)
	if err != nil {
		return nil, err
	}
	_, why, err := agentcardVerifyDetached(payload, am["signature"], r)
	if err != nil {
		return nil, err
	}
	if why != "" {
		return no("signature did not verify: " + why)
	}
	return map[string]any{"issuer": issuer, "ok": true, "attests": attests}, nil
}

// AgentFactsVerify verifies an AgentFacts document, failing closed: an attestation about another subject, outside its validity
// window, malformed or whose detached signature does not verify refuses, and any one failure fails the whole document. On
// success the result separates the claims a third party ATTESTS from those only SELF-ASSERTED (flagged, never promoted). A
// document with no attestation verifies and attests nothing. opts: jwks, key, alg, now (epoch ms; default the wall clock).
func AgentFactsVerify(facts any, opts map[string]any) (map[string]any, error) {
	if facts == nil {
		return nil, errors.New("Cannot read properties of null (reading 'selfAsserted')")
	}
	fm, _ := facts.(map[string]any)
	self := map[string]any{}
	if s, ok := fm["selfAsserted"].(map[string]any); ok {
		self = s
	}
	now := float64(time.Now().UnixMilli())
	if agentcardPresent(opts, "now") {
		f, ok := jsNum(opts["now"])
		if !ok || math.IsNaN(f) {
			return nil, errors.New("now must be a number of epoch milliseconds")
		}
		now = f
	}
	docID, haveID := fm["id"]
	base := func() map[string]any {
		b := map[string]any{"ok": false, "attestations": []any{}, "attested": map[string]any{}, "selfAsserted": self, "claims": map[string]any{}}
		if haveID {
			b["agentId"] = docID
		}
		return b
	}
	list, ok := fm["attestations"].([]any)
	if !ok {
		b := base()
		b["reason"] = "agent facts has no attestations array"
		return b, nil
	}
	var r *agentcardKey
	if len(list) > 0 {
		var reason string
		if r, reason = agentcardResolve(opts); r == nil {
			b := base()
			b["reason"] = reason
			missing := make([]any, len(list))
			for i, a := range list {
				missing[i] = map[string]any{"issuer": agentcardIssuerOf(a), "ok": false, "reason": "no verification key or JWKS supplied"}
			}
			b["attestations"] = missing
			return b, nil
		}
	}
	checks := make([]any, 0, len(list))
	attested := map[string]any{}
	allOK := true
	for _, a := range list {
		c, err := agentcardVerifyOne(a, docID, haveID, now, r)
		if err != nil {
			return nil, err
		}
		checks = append(checks, c)
		if c["ok"] != true {
			allOK = false
			continue
		}
		for k, v := range c["attests"].(map[string]any) {
			attested[k] = v
		}
	}
	claims := map[string]any{}
	for k := range self {
		claims[k] = "self-asserted"
	}
	for k := range attested {
		claims[k] = "attested" // attested wins on overlap
	}
	out := base()
	out["ok"] = allOK
	out["attestations"] = checks
	out["attested"] = attested
	out["claims"] = claims
	if !allOK {
		out["reason"] = "one or more attestations did not verify"
	}
	return out, nil
}

// ---- 3. well-known hosting ----------------------------------------------------------------------------------------

// agentcardStringify is JSON.stringify of a JSON value: members in the order the value's parser recorded, -0 as 0.
func agentcardStringify(sb *strings.Builder, v any) error {
	switch t := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		sb.WriteString(strconv.FormatBool(t))
	case string:
		lenientString(sb, t)
	case []any:
		sb.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := agentcardStringify(sb, x); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case map[string]any:
		sb.WriteByte('{')
		for i, k := range jsKeys(t) {
			if i > 0 {
				sb.WriteByte(',')
			}
			lenientString(sb, k)
			sb.WriteByte(':')
			if err := agentcardStringify(sb, t[k]); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	default:
		f, ok := jsNum(v)
		if !ok {
			return fmt.Errorf("cannot serialize %T", v)
		}
		if math.IsNaN(f) || math.IsInf(f, 0) {
			sb.WriteString("null")
		} else {
			sb.WriteString(jsLenientNumber(f))
		}
	}
	return nil
}

func agentcardNormalizePath(path string) string {
	if q := strings.IndexByte(path, '?'); q != -1 {
		path = path[:q]
	}
	if len(path) > 1 && strings.HasSuffix(path, "/") { // drop a single trailing slash, keep the root
		return path[:len(path)-1]
	}
	return path
}

// agentcardHandler serves value at path; the returned function gives the response for a request path, or nil for any other
// path so it composes in a router.
func agentcardHandler(value any, path string) (func(reqPath string) map[string]any, error) {
	var sb strings.Builder
	if err := agentcardStringify(&sb, value); err != nil {
		return nil, err
	}
	target := agentcardNormalizePath(path)
	body := sb.String()
	return func(reqPath string) map[string]any {
		if agentcardNormalizePath(reqPath) != target {
			return nil
		}
		return map[string]any{
			"status":  200,
			"headers": map[string]any{"content-type": "application/json", "cache-control": "no-store"},
			"body":    body,
		}
	}, nil
}

// AgentCardHandler serves a signed Agent Card at AgentCardWellKnownPath (or the optional path); the handler returns nil for any
// other request path.
func AgentCardHandler(card any, path ...string) (func(reqPath string) map[string]any, error) {
	p := AgentCardWellKnownPath
	if len(path) > 0 {
		p = path[0]
	}
	return agentcardHandler(card, p)
}

// AgentFactsHandler serves an AgentFacts document at AgentFactsWellKnownPath (or the optional path); the handler returns nil for
// any other request path.
func AgentFactsHandler(facts any, path ...string) (func(reqPath string) map[string]any, error) {
	p := AgentFactsWellKnownPath
	if len(path) > 0 {
		p = path[0]
	}
	return agentcardHandler(facts, p)
}

// ---- 4. registry publication --------------------------------------------------------------------------------------

const agentcardUserinfoSet = "\"#<>?`{}/:;=@[\\]^|"

func agentcardPct(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c >= 0x7f || strings.IndexByte(agentcardUserinfoSet, c) >= 0 {
			fmt.Fprintf(&sb, "%%%02X", c)
		} else {
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// agentcardWellKnownURL is new URL(path, serviceUrl).toString() for an absolute path: the base's scheme, credentials and host
// with the path; ok is false where the URL class refuses (an invalid base, or one that cannot be a base).
func agentcardWellKnownURL(serviceURL any, path string) (string, bool) {
	s, isS := serviceURL.(string)
	if !isS {
		return "", false
	}
	u, err := whatwgParse(s)
	if err != nil {
		return "", false
	}
	text := strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(strings.TrimFunc(s, func(r rune) bool { return r <= 0x20 }))
	rest := text[strings.IndexByte(text, ':')+1:]
	_, special := whatwgDefaultPort[u.scheme]
	if !special && !strings.HasPrefix(rest, "//") {
		if strings.HasPrefix(rest, "/") {
			return u.scheme + ":" + path, true
		}
		return "", false // an opaque path cannot be a base
	}
	userinfo := ""
	if u.scheme != "file" {
		var auth string
		if special {
			auth = strings.TrimLeft(rest, `/\`)
			if e := strings.IndexAny(auth, `/\?#`); e >= 0 {
				auth = auth[:e]
			}
		} else {
			auth = rest[2:]
			if e := strings.IndexAny(auth, "/?#"); e >= 0 {
				auth = auth[:e]
			}
		}
		if at := strings.LastIndexByte(auth, '@'); at >= 0 {
			user, pw, _ := strings.Cut(auth[:at], ":")
			if user != "" || pw != "" {
				userinfo = agentcardPct(user)
				if pw != "" {
					userinfo += ":" + agentcardPct(pw)
				}
				userinfo += "@"
			}
		}
	}
	return u.scheme + "://" + userinfo + u.host + path, true
}

// AgentCardToRegistryEntry shapes the entry for an A2A registry or NANDA index from a signed card and an AgentFacts document, with
// the split of claim names a third party ATTESTS from those only SELF-ASSERTED. Purely structural: a registry re-verifies on ingest.
func AgentCardToRegistryEntry(card, facts any) (map[string]any, error) {
	if facts == nil {
		return nil, errors.New("Cannot read properties of null (reading 'attestations')")
	}
	if card == nil {
		return nil, errors.New("Cannot read properties of null (reading 'url')")
	}
	cm, _ := card.(map[string]any)
	fm, _ := facts.(map[string]any)
	var atts []any
	switch t := fm["attestations"].(type) {
	case nil:
	case []any:
		atts = t
	case string: // iterates characters, none of which carries claims
	default:
		return nil, errors.New("facts.attestations is not iterable")
	}
	seen := map[string]bool{}
	attested := []any{}
	for _, a := range atts {
		if !jsTruthy(a) {
			continue
		}
		am, _ := a.(map[string]any)
		if at, ok := am["attests"].(map[string]any); ok {
			for _, k := range jsKeys(at) {
				if !seen[k] {
					seen[k] = true
					attested = append(attested, k)
				}
			}
		}
	}
	selfOnly := []any{}
	if sa, ok := fm["selfAsserted"].(map[string]any); ok {
		for _, k := range jsKeys(sa) {
			if !seen[k] {
				selfOnly = append(selfOnly, k)
			}
		}
	}
	entry := map[string]any{}
	if v, has := fm["id"]; has {
		entry["id"] = v
	}
	if v, has := cm["name"]; has {
		entry["name"] = v
	}
	for _, k := range []string{"url", "version", "skills"} {
		if v, has := cm[k]; has {
			entry[k] = v
		}
	}
	if jsTruthy(cm["pcaPassport"]) {
		entry["passport"] = cm["pcaPassport"]
	}
	if jsTruthy(cm["pcaProof"]) {
		entry["pcaProof"] = cm["pcaProof"]
	}
	entry["card"] = card
	if u, has := cm["url"]; has {
		if s, ok := agentcardWellKnownURL(u, AgentCardWellKnownPath); ok {
			entry["agentCardUrl"] = s
		}
	}
	entry["facts"] = facts
	entry["attestedClaims"] = attested
	entry["selfAssertedClaims"] = selfOnly
	return entry, nil
}
