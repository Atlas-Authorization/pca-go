package pca

// A2A 1.0 Agent Card helpers: RFC 8785 canonical bytes (A2AJcsBytes), the AgentCard schema check (A2AValidateAgentCard1), signed cards
// (A2AIssueSignedAgentCard / A2AVerifyAgentCard: a JWS over the canonical card minus `signatures`) and the extended card derived from
// a residual policy (A2AExtendedAgentCard). Cards are JSON values (map[string]any); results are JSON values shaped like the
// reference. Signing is EdDSA with an Ed25519 private JWK; verification takes any key the JOSE layer supports.

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// The PCA extension of an A2A Agent Card and the JWS header member that names the passport a card signature commits to.
const (
	A2APcaExtensionURI   = "https://atlasauth.net/a2a/ext/pca/v2"
	A2APcaPassportHeader = "pca_passport"
)

const a2acMaxDepth = 64

// a2acJCS writes the RFC 8785 canonical form of a JSON value (ECMAScript number formatting, UTF-16 key order).
func a2acJCS(sb *strings.Builder, v any, depth int) error {
	switch t := v.(type) {
	case nil:
		sb.WriteString("null")
		return nil
	case bool:
		sb.WriteString(strconv.FormatBool(t))
		return nil
	case string:
		if hasLoneSurrogate(t) {
			return errors.New("jcs: lone surrogate in string")
		}
		lenientString(sb, t)
		return nil
	case []any:
		if depth > a2acMaxDepth {
			return errors.New("jcs: nesting too deep")
		}
		sb.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := a2acJCS(sb, x, depth+1); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
		return nil
	case map[string]any:
		if depth > a2acMaxDepth {
			return errors.New("jcs: nesting too deep")
		}
		ks := make([]string, 0, len(t))
		for k := range t {
			ks = append(ks, k)
		}
		sort.Slice(ks, func(i, j int) bool { return compareUnits(utf16Units(ks[i]), utf16Units(ks[j])) < 0 })
		sb.WriteByte('{')
		for i, k := range ks {
			if hasLoneSurrogate(k) {
				return errors.New("jcs: lone surrogate in key")
			}
			if i > 0 {
				sb.WriteByte(',')
			}
			lenientString(sb, k)
			sb.WriteByte(':')
			if err := a2acJCS(sb, t[k], depth+1); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
		return nil
	}
	if v == acpU {
		return errors.New("jcs: unsupported type undefined")
	}
	f, ok := jsNum(v)
	if !ok {
		return fmt.Errorf("jcs: unsupported type %T", v)
	}
	if f != f || f > 1.7976931348623157e308 || f < -1.7976931348623157e308 {
		return errors.New("jcs: non-finite number")
	}
	sb.WriteString(jsLenientNumber(f))
	return nil
}

// A2AJcsBytes is the RFC 8785 canonical UTF-8 bytes of a JSON value; an error for a value with no JSON form (a non-finite number, a
// lone surrogate, nesting over 64 levels).
func A2AJcsBytes(v any) ([]byte, error) {
	var sb strings.Builder
	if err := a2acJCS(&sb, v, 1); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

// ---- A2A 1.0 AgentCard message ----------------------------------------------------------------------------------------

func a2acIsObj(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

// A2AValidateAgentCard1 lists the problems found in an object checked against the A2A 1.0 AgentCard message, each with a JSON path
// (empty = valid).
func A2AValidateAgentCard1(card any) []string {
	p := []string{}
	cm, ok := a2acIsObj(card)
	if !ok {
		return []string{"$: the agent card must be an object"}
	}
	reqStr := func(o map[string]any, k, at string) {
		if s, isS := o[k].(string); !isS || s == "" {
			p = append(p, at+"."+k+": required non-empty string")
		}
	}
	optStr := func(o map[string]any, k, at string) {
		if _, isS := o[k].(string); acpHas(o, k) && !isS {
			p = append(p, at+"."+k+": must be a string")
		}
	}
	optBool := func(o map[string]any, k, at string) {
		if _, isB := o[k].(bool); acpHas(o, k) && !isB {
			p = append(p, at+"."+k+": must be a boolean")
		}
	}
	strArray := func(v any, at string, nonEmpty bool) {
		l, isL := v.([]any)
		good := isL
		if isL {
			for _, x := range l {
				if _, isS := x.(string); !isS {
					good = false
					break
				}
			}
		}
		switch {
		case !good:
			p = append(p, at+": must be an array of strings")
		case nonEmpty && len(l) == 0:
			p = append(p, at+": must not be empty")
		}
	}
	objArray := func(o map[string]any, k, at string, required, nonEmpty bool, each func(e map[string]any, at string)) {
		v, has := o[k]
		if !has || v == acpU {
			if required {
				p = append(p, at+"."+k+": required array")
			}
			return
		}
		l, isL := v.([]any)
		if !isL {
			p = append(p, at+"."+k+": must be an array")
			return
		}
		if nonEmpty && len(l) == 0 {
			p = append(p, at+"."+k+": must not be empty")
		}
		for i, e := range l {
			if em, isO := a2acIsObj(e); isO {
				each(em, fmt.Sprintf("%s.%s[%d]", at, k, i))
			} else {
				p = append(p, fmt.Sprintf("%s.%s[%d]: must be an object", at, k, i))
			}
		}
	}

	reqStr(cm, "name", "$")
	reqStr(cm, "description", "$")
	reqStr(cm, "version", "$")
	optStr(cm, "documentationUrl", "$")
	optStr(cm, "iconUrl", "$")
	objArray(cm, "supportedInterfaces", "$", true, true, func(e map[string]any, at string) {
		reqStr(e, "url", at)
		reqStr(e, "protocolBinding", at)
		reqStr(e, "protocolVersion", at)
		optStr(e, "tenant", at)
	})
	if acpHas(cm, "provider") {
		if pm, isO := a2acIsObj(cm["provider"]); !isO {
			p = append(p, "$.provider: must be an object")
		} else {
			reqStr(pm, "url", "$.provider")
			reqStr(pm, "organization", "$.provider")
		}
	}
	if c, isO := a2acIsObj(cm["capabilities"]); !isO {
		p = append(p, "$.capabilities: required object")
	} else {
		optBool(c, "streaming", "$.capabilities")
		optBool(c, "pushNotifications", "$.capabilities")
		optBool(c, "extendedAgentCard", "$.capabilities")
		objArray(c, "extensions", "$.capabilities", false, false, func(e map[string]any, at string) {
			optStr(e, "uri", at)
			optStr(e, "description", at)
			optBool(e, "required", at)
			if _, isP := a2acIsObj(e["params"]); acpHas(e, "params") && !isP {
				p = append(p, at+".params: must be an object")
			}
		})
	}
	if _, isO := a2acIsObj(cm["securitySchemes"]); acpHas(cm, "securitySchemes") && !isO {
		p = append(p, "$.securitySchemes: must be an object")
	}
	if _, isL := cm["securityRequirements"].([]any); acpHas(cm, "securityRequirements") && !isL {
		p = append(p, "$.securityRequirements: must be an array")
	}
	for _, k := range []string{"defaultInputModes", "defaultOutputModes"} {
		if !acpHas(cm, k) {
			p = append(p, "$."+k+": required array of strings")
		} else {
			strArray(cm[k], "$."+k, true)
		}
	}
	objArray(cm, "skills", "$", true, false, func(e map[string]any, at string) {
		reqStr(e, "id", at)
		reqStr(e, "name", at)
		reqStr(e, "description", at)
		if !acpHas(e, "tags") {
			p = append(p, at+".tags: required array of strings")
		} else {
			strArray(e["tags"], at+".tags", false)
		}
		for _, k := range []string{"examples", "inputModes", "outputModes"} {
			if acpHas(e, k) {
				strArray(e[k], at+"."+k, false)
			}
		}
		if _, isL := e["securityRequirements"].([]any); acpHas(e, "securityRequirements") && !isL {
			p = append(p, at+".securityRequirements: must be an array")
		}
	})
	objArray(cm, "signatures", "$", false, false, func(e map[string]any, at string) {
		reqStr(e, "protected", at)
		reqStr(e, "signature", at)
		if _, isO := a2acIsObj(e["header"]); acpHas(e, "header") && !isO {
			p = append(p, at+".header: must be an object")
		}
	})
	return p
}

// ---- signed cards -----------------------------------------------------------------------------------------------------

func a2acIsJWK(k any) bool {
	m, ok := k.(map[string]any)
	if !ok {
		return false
	}
	_, has := m["kty"]
	return has
}

// a2acCardBytes is the signing input of a card: its RFC 8785 form without `signatures` (A2A 1.0 section 8.4).
func a2acCardBytes(card map[string]any) ([]byte, error) {
	rest := make(map[string]any, len(card))
	for k, v := range card {
		if k != "signatures" {
			rest[k] = v
		}
	}
	return A2AJcsBytes(rest)
}

// a2acPriorSignatures is `[...(card.signatures ?? [])]`.
func a2acPriorSignatures(v any) ([]any, error) {
	switch t := v.(type) {
	case nil:
		return []any{}, nil
	case []any:
		return append([]any{}, t...), nil
	case string:
		units := utf16Units(t)
		out := make([]any, len(units))
		for i, u := range units {
			out[i] = acpUnitString(u)
		}
		return out, nil
	}
	if v == acpU {
		return []any{}, nil
	}
	return nil, errors.New("signatures is not iterable")
}

// A2AIssueSignedAgentCard returns the card with a signature appended: the passport reference is embedded (and put in the signed
// protected header) before signing. opts: alg (EdDSA, the only algorithm signed here), passport ({id, uri?}), kid, profile
// ("pca-detached" default, or "a2a-1.0", which needs a kid) and schema ("a2a-1.0": refuse a card that does not match the schema).
// signingKey is an Ed25519 private JWK. It refuses (an error) on anything it cannot sign honestly.
func A2AIssueSignedAgentCard(card any, signingKey any, opts map[string]any) (map[string]any, error) {
	cm, ok := a2acIsObj(card)
	if !ok {
		return nil, errors.New("issueSignedAgentCard: the card must be an object")
	}
	alg := acpDefault(acpGet(opts, "alg"), "EdDSA")
	var passport any = acpGet(cm, "pcaPassport")
	if pp := acpGet(opts, "passport"); acpTruthy(pp) {
		pm := map[string]any{"id": acpGet(pp, "id")}
		if u := acpGet(pp, "uri"); u != acpU {
			pm["uri"] = u
		}
		passport = pm
	}
	toSign := make(map[string]any, len(cm)+1)
	for k, v := range cm {
		toSign[k] = v
	}
	if acpTruthy(passport) {
		toSign["pcaPassport"] = passport
	}
	if acpGet(opts, "schema") == "a2a-1.0" {
		if problems := A2AValidateAgentCard1(toSign); len(problems) > 0 {
			return nil, errors.New("issueSignedAgentCard: the card does not match the A2A 1.0 schema: " + strings.Join(problems, "; "))
		}
	}
	payload, err := a2acCardBytes(toSign)
	if err != nil {
		return nil, err
	}
	seed, err := acpSigningSeed(signingKey, alg)
	if err != nil {
		return nil, err
	}
	a2a10 := acpGet(opts, "profile") == "a2a-1.0"
	kid := acpGet(opts, "kid")
	if ks, isS := kid.(string); a2a10 && (!isS || ks == "") {
		return nil, errors.New("issueSignedAgentCard: the 'a2a-1.0' profile requires a kid")
	}
	header := acpObj{{"alg", alg}}
	if a2a10 {
		header = append(header, acpKV{"typ", "JOSE"})
	} else {
		header = append(header, acpKV{"b64", false}, acpKV{"crit", []any{"b64"}})
	}
	if kid != acpU {
		header = append(header, acpKV{"kid", kid})
	}
	if acpTruthy(passport) {
		header = append(header, acpKV{A2APcaPassportHeader, acpGet(passport, "id")})
	}
	prot := b64.EncodeToString([]byte(acpStringify(header)))
	input := []byte(prot + ".")
	if a2a10 {
		input = append(input, []byte(b64.EncodeToString(payload))...)
	} else {
		input = append(input, payload...)
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), input)
	prior, err := a2acPriorSignatures(toSign["signatures"])
	if err != nil {
		return nil, err
	}
	toSign["signatures"] = append(prior, map[string]any{"protected": prot, "signature": b64.EncodeToString(sig)})
	return toSign, nil
}

// a2acAssertSegments is the canonical-spelling gate of the protected and signature segments of a flattened JWS.
func a2acAssertSegments(prot, sig string) error {
	if jsLen(prot)+jsLen(sig) > DefaultMaxJWSBytes {
		return errors.New("non-canonical compact JWS: too-long")
	}
	if prot == "" || sig == "" {
		return errors.New("non-canonical compact JWS: empty-segment")
	}
	b, err := decodeCanonicalBase64url(prot)
	if err != nil {
		return err
	}
	h, err := jwsJSONSegment(b)
	if err != nil {
		return err
	}
	if _, isO := h.(map[string]any); !isO {
		return errors.New("non-canonical compact JWS: not-an-object")
	}
	_, err = decodeCanonicalBase64url(sig)
	return err
}

// a2acFlattenedVerify is jose flattenedVerify for a card signature; payload is the raw bytes (detached) or the base64url text. It
// returns the protected header.
func a2acFlattenedVerify(prot string, payload any, signature string, resolve OidcKeyResolver) (map[string]any, error) {
	hv, err := acpParse(acpUTF8(nodeB64(prot)))
	h, ok := hv.(map[string]any)
	if err != nil || !ok {
		return nil, errors.New("JWS Protected Header is invalid")
	}
	b64Payload := true
	if c, has := h["crit"]; has {
		l, isL := c.([]any)
		if !isL || len(l) == 0 {
			return nil, errors.New(`"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present`)
		}
		for _, x := range l {
			s, isS := x.(string)
			if !isS || s == "" {
				return nil, errors.New(`"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present`)
			}
			if s != "b64" {
				return nil, fmt.Errorf("Extension Header Parameter %q is not recognized", s)
			}
		}
		bv, isB := h["b64"].(bool)
		if !isB {
			return nil, errors.New(`The "b64" (base64url-encode payload) Header Parameter must be a boolean`)
		}
		b64Payload = bv
	}
	alg, ok := h["alg"].(string)
	if !ok || alg == "" {
		return nil, errors.New(`JWS "alg" (Algorithm) Header Parameter missing or invalid`)
	}
	var pb []byte
	switch t := payload.(type) {
	case string:
		pb = []byte(t)
	case []byte:
		if b64Payload {
			return nil, errors.New("JWS Payload must be a string")
		}
		pb = t
	}
	key, err := resolve(h)
	if err != nil {
		return nil, err
	}
	if key == nil || !JOSEVerify(alg, key, append([]byte(prot+"."), pb...), nodeB64(signature)) {
		return nil, errors.New("signature verification failed")
	}
	return h, nil
}

// A2AVerifyAgentCard validates a card against its signature(s). Fail closed: no signatures, an unresolvable key or ANY signature
// that does not verify over the canonical card (minus `signatures`) refuses. opts: jwks (a JWK Set), key (a JWK), alg, schema
// ("a2a-1.0"). On success the result names the passport id the signature commits to (passportRef) and the one embedded in the card
// (passport). The result is {ok, reason?, passportRef?, passport?}.
func A2AVerifyAgentCard(card any, opts map[string]any) map[string]any {
	fail := func(reason string) map[string]any { return map[string]any{"ok": false, "reason": reason} }
	if card == nil || (func() bool { _, m := card.(map[string]any); _, l := card.([]any); return !m && !l })() {
		return fail("agent card is not an object")
	}
	signatures, ok := acpGet(card, "signatures").([]any)
	if !ok || len(signatures) == 0 {
		return fail("agent card carries no signatures")
	}
	if acpGet(opts, "schema") == "a2a-1.0" {
		if problems := A2AValidateAgentCard1(card); len(problems) > 0 {
			return fail("agent card does not match the A2A 1.0 schema: " + strings.Join(problems, "; "))
		}
	}
	var resolve OidcKeyResolver
	if acpTruthy(acpGet(opts, "jwks")) {
		r, err := NewLocalJWKSet(opts["jwks"])
		if err != nil {
			return fail("could not resolve verification key: " + err.Error())
		}
		resolve = r
	} else if k := acpGet(opts, "key"); k != acpU {
		if a2acIsJWK(k) {
			key, err := acpImportVerifyKey(k)
			if err != nil {
				return fail("could not resolve verification key: " + err.Error())
			}
			resolve = func(map[string]any) (*JOSEKey, error) { return key, nil }
		} else {
			resolve = func(map[string]any) (*JOSEKey, error) { return nil, errors.New("Invalid key for this operation") }
		}
	} else {
		return fail("no verification key or JWKS supplied")
	}
	cm, _ := card.(map[string]any)
	if cm == nil {
		cm = map[string]any{} // an array card: its members are the elements, none of which is a card member
	}
	payload, err := a2acCardBytes(cm)
	if err != nil {
		return fail("agent card has no canonical form: " + err.Error())
	}
	passportRef := ""
	hasRef := false
	for i, s := range signatures {
		prot, pok := acpGet(s, "protected").(string)
		sg, sok := acpGet(s, "signature").(string)
		if !pok || !sok {
			return fail(fmt.Sprintf("signature %d is malformed", i))
		}
		h, err := func() (map[string]any, error) {
			if err := a2acAssertSegments(prot, sg); err != nil {
				return nil, err
			}
			var body any = b64.EncodeToString(payload)
			if hv, perr := acpParse(acpUTF8(nodeB64(prot))); perr == nil {
				if hm, isO := hv.(map[string]any); isO && hm["b64"] == false {
					body = payload
				}
			}
			return a2acFlattenedVerify(prot, body, sg, resolve)
		}()
		if err != nil {
			return fail(fmt.Sprintf("signature %d did not verify: %s", i, err.Error()))
		}
		if ref, isS := h[A2APcaPassportHeader].(string); isS && !hasRef {
			passportRef, hasRef = ref, true
		}
	}
	out := map[string]any{"ok": true}
	if hasRef {
		out["passportRef"] = passportRef
	}
	if pp := acpGet(card, "pcaPassport"); acpTruthy(pp) {
		out["passport"] = pp
	}
	return out
}

// ---- extended card ----------------------------------------------------------------------------------------------------

// a2acIter is `for (const x of v)`: an array, or a string by UTF-16 code unit; anything else is not iterable.
func a2acIter(v any) ([]any, error) {
	switch t := v.(type) {
	case []any:
		return t, nil
	case string:
		units := utf16Units(t)
		out := make([]any, len(units))
		for i, u := range units {
			out[i] = acpUnitString(u)
		}
		return out, nil
	}
	return nil, errors.New("object is not iterable")
}

// a2acKeyer gives SameValueZero identities to JSON values (containers are distinct from one another).
type a2acKeyer struct{ n int }

func (k *a2acKeyer) key(v any) string {
	switch t := v.(type) {
	case nil:
		return "z"
	case bool:
		return "b:" + strconv.FormatBool(t)
	case string:
		return "s:" + t
	case []any, map[string]any:
		k.n++
		return "o:" + strconv.Itoa(k.n)
	}
	if v == acpU {
		return "u"
	}
	if f, ok := jsNum(v); ok {
		return "n:" + jsLenientNumber(f)
	}
	k.n++
	return "o:" + strconv.Itoa(k.n)
}

func a2acMember(o any, k string) (any, error) {
	if acpNullish(o) {
		return nil, fmt.Errorf("Cannot read properties of %s (reading '%s')", acpS(o), k)
	}
	return acpGet(o, k), nil
}

// a2acDefaultVerbOf is the default verb mapping: the first `pca-verb:<verb>` tag of a skill.
func a2acDefaultVerbOf(s any) (any, error) {
	tags, err := a2acMember(s, "tags")
	if err != nil {
		return nil, err
	}
	if acpNullish(tags) {
		return acpU, nil
	}
	l, ok := tags.([]any)
	if !ok {
		return nil, errors.New("tags.find is not a function")
	}
	for _, t := range l {
		if ts, isS := t.(string); isS && strings.HasPrefix(ts, "pca-verb:") {
			return strings.TrimPrefix(ts, "pca-verb:"), nil
		}
	}
	return acpU, nil
}

// A2AExtendedAgentCard is the card a caller may see after authenticating: hidden skills are revealed only when their verb's envelope
// is "autonomous" or "needs-approval" (no envelope or "denied" reveals nothing), all envelopes must come from one policy (its digest
// is recorded in the PCA extension params). o: authenticated, hiddenSkills, envelopes. verbOf maps a skill to its verb (nil = the
// `pca-verb:<verb>` tag; return acpU-free values: nil means none, as undefined does). The result is unsigned; discovery only,
// attempting a skill still needs its PCActn.
func A2AExtendedAgentCard(publicCard any, o map[string]any, verbOf func(skill any) (any, error)) (map[string]any, error) {
	if acpGet(o, "authenticated") != true {
		return nil, errors.New("extendedAgentCard: the caller must be authenticated (A2A 13.3)")
	}
	envs, err := a2acIter(acpGet(o, "envelopes"))
	if err != nil {
		return nil, err
	}
	var kr a2acKeyer
	digestSeen := map[string]bool{}
	var firstDigest any = acpU
	for _, e := range envs {
		d, err := a2acMember(e, "policyDigest")
		if err != nil {
			return nil, err
		}
		if k := kr.key(d); !digestSeen[k] {
			if len(digestSeen) == 0 {
				firstDigest = d
			}
			digestSeen[k] = true
		}
	}
	if len(digestSeen) > 1 {
		return nil, errors.New("extendedAgentCard: envelopes were computed against different policies")
	}
	byVerb := map[string]any{}
	for _, e := range envs {
		v, err := a2acMember(e, "verb")
		if err != nil {
			return nil, err
		}
		byVerb[kr.key(v)] = e
	}
	if verbOf == nil {
		verbOf = a2acDefaultVerbOf
	}
	hidden, err := a2acIter(acpGet(o, "hiddenSkills"))
	if err != nil {
		return nil, err
	}
	revealed := []any{}
	for _, s := range hidden {
		verb, err := verbOf(s)
		if err != nil {
			return nil, err
		}
		if verb == acpU {
			continue
		}
		env, found := byVerb[kr.key(verb)]
		if !found {
			continue
		}
		status, err := a2acMember(env, "status")
		if err != nil {
			return nil, err
		}
		if status == "denied" {
			continue
		}
		tagsV, err := a2acMember(s, "tags")
		if err != nil {
			return nil, err
		}
		var tags []any
		if !acpNullish(tagsV) {
			if tags, err = a2acIter(tagsV); err != nil {
				return nil, err
			}
		}
		label := "pca:needs-approval"
		if status == "autonomous" {
			label = "pca:autonomous"
		}
		sk := acpSpread(s)
		sk["tags"] = append(append([]any{}, tags...), label)
		revealed = append(revealed, sk)
	}
	if publicCard == nil {
		return nil, errors.New("Cannot destructure 'publicCard' as it is null.")
	}
	rest := acpSpread(publicCard)
	delete(rest, "signatures")
	capsV := rest["capabilities"]
	if capsV == nil {
		capsV = map[string]any{}
	}
	caps := acpSpread(capsV)
	exts, _ := acpGet(capsV, "extensions").([]any)
	nextExts := exts
	if firstDigest != acpU {
		nextExts = make([]any, 0, len(exts))
		for _, e := range exts {
			uri, err := a2acMember(e, "uri")
			if err != nil {
				return nil, err
			}
			if uri == A2APcaExtensionURI {
				ne := acpSpread(e)
				params := acpSpread(acpGet(e, "params"))
				params["policy_digest"] = firstDigest
				ne["params"] = params
				nextExts = append(nextExts, ne)
			} else {
				nextExts = append(nextExts, e)
			}
		}
	}
	if nextExts == nil {
		nextExts = []any{}
	}
	skills, _ := rest["skills"].([]any)
	caps["extensions"] = nextExts
	rest["capabilities"] = caps
	rest["skills"] = append(append([]any{}, skills...), revealed...)
	return rest, nil
}
