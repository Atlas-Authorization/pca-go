package pca

// Replays the reference oracle of the SD-JWT bridge (testdata/ref-sdjwt.json.gz). Keys travel as seeds / raw public bytes
// ({"$bytes"}) or JWKs; options use snake_case names. JS-typed hostile options are mapped to what the typed API can express: a
// value the reference refuses inside its try becomes an {ok:false} result, a null that the reference treats as "present" becomes
// a sentinel that behaves the same. issuePcaSdJwt carries random salts, so its case compares the normalized form the generator
// emits; a verify {ok:false} compares `reason` only when the reason is this package's own (library messages are not stable).

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"testing"
)

func sdjwtIsBytes(v any) bool {
	m, ok := v.(map[string]any)
	_, has := m["$bytes"]
	return ok && len(m) == 1 && has
}

func sdjwtStrings(v any) ([]string, bool) {
	l, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := []string{}
	for _, x := range l {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func sdjwtPub(seed []byte) []byte { return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey) }

// sdjwtAudience maps an expected audience: a string or string list names it, "" / null require presence only (the reference
// library treats a falsy, non-undefined audience that way), anything else is refused.
func sdjwtAudience(m map[string]any, k string, nullFallsThrough bool) ([]string, bool, error) {
	v, has := m[k]
	if !has || v == nil && nullFallsThrough {
		return nil, false, nil
	}
	switch a := v.(type) {
	case nil:
		return []string{""}, true, nil
	case string:
		return []string{a}, true, nil
	case []any:
		out := []string{}
		for _, x := range a {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			out = []string{"\x00none"} // an empty list matches nothing
		}
		return out, true, nil
	}
	return nil, false, errors.New("audOption.includes is not a function")
}

func sdjwtAlgs(m map[string]any, k string) ([]string, error) {
	v, has := m[k]
	if !has || v == nil {
		return nil, nil
	}
	l, ok := sdjwtStrings(v)
	if !ok {
		return nil, fmt.Errorf("%q option must be an array of strings", k)
	}
	return l, nil
}

// sdjwtVerifyW returns the verify result, or an error only where the reference wrapper itself throws (issuer key import).
func sdjwtVerifyW(sd any, m map[string]any) (any, error) {
	fail := func(err error) (any, error) { return SdJwtVerifyResult{Reason: err.Error()}, nil }
	var o SdJwtVerifyOptions
	ik := m["issuer_key"]
	if sdjwtIsBytes(ik) {
		k, err := ImportEd25519PublicKey(vcBytes(ik))
		if err != nil {
			return nil, err
		}
		o.IssuerKey = k
	} else {
		k, err := ImportPublicJWK(sdjwtPublicPart(vecObj(ik))) // the reference imports a private JWK and verifies with its public half
		if err != nil {
			return fail(err)
		}
		o.IssuerKey = k
	}
	if x, has := m["now"]; has {
		f, _ := jsNum(x)
		if math.Abs(f) > 8.64e15 {
			return nil, vecSkip("a clock outside the JS Date range is Invalid Date in the reference (time checks off); the native compares it")
		}
		o.NowMs = &f
	}
	var err error
	if o.ExpectedAudience, _, err = sdjwtAudience(m, "expected_audience", false); err != nil {
		return fail(err)
	}
	if o.ExpectedKbAudience, _, err = sdjwtAudience(m, "expected_kb_audience", true); err != nil {
		return fail(err)
	}
	if x, has := m["expected_nonce"]; has {
		s, ok := x.(string)
		if !ok {
			s = "\x00null" // a null expectation is compared (and matches no string nonce) in the reference
		}
		o.ExpectedNonce = &s
	}
	o.RequireKeyBinding = jsTruthy(m["require_key_binding"])
	if x, has := m["key_binding_key"]; has {
		switch {
		case x == nil:
			o.KeyBindingKey = map[string]any{} // null counts as given (not a key)
		case sdjwtIsBytes(x):
			o.KeyBindingKey = vcBytes(x)
		default:
			o.KeyBindingKey = x
		}
	}
	if o.Algorithms, err = sdjwtAlgs(m, "algorithms"); err != nil {
		return fail(err)
	}
	if o.KbAlgorithms, err = sdjwtAlgs(m, "kb_algorithms"); err != nil {
		return fail(err)
	}
	if l, ok := m["required_disclosures"].([]any); ok {
		o.RequiredDisclosures = []string{}
		for _, x := range l {
			o.RequiredDisclosures = append(o.RequiredDisclosures, jsValueString(x))
		}
	}
	if x, has := m["kb_max_age_sec"]; has {
		f, _ := jsNum(x) // null compares as 0
		o.KbMaxAgeSec = &f
	}
	if x, has := m["clock_tolerance_sec"]; has {
		switch v := x.(type) {
		case string:
			var n int
			var unit string
			if c, _ := fmt.Sscanf(v, "%d %s", &n, &unit); c != 2 || (unit != "seconds" && unit != "second") {
				return fail(errors.New("Invalid time period format"))
			}
			f := float64(n)
			o.ClockToleranceSec = &f
		default:
			f, ok := jsNum(v)
			if !ok {
				return fail(errors.New("Invalid clockTolerance option type"))
			}
			o.ClockToleranceSec = &f
		}
	}
	s, _ := sd.(string)
	return VerifyPcaSdJwt(s, o), nil
}

var sdjwtOwnPrefixes = []string{"pca-sdjwt:", "KB-JWT", "a digest appears", "an array", "an object-property", "_sd must", "disclosure claim",
	"'", "unsupported _sd_alg", "duplicate disclosure", "a presented disclosure", "required disclosure", "cnf key does not", "key binding required"}

const sdjwtKbInvalid = "KB-JWT signature/claims invalid: "

func sdjwtVerifyCmp(want, got any) bool {
	w, g := vecObj(want), vecObj(got)
	if w["ok"] == true {
		return baseCanon(want) == baseCanon(got)
	}
	if g["ok"] != false {
		return false
	}
	wr, _ := w["reason"].(string)
	gr, _ := g["reason"].(string)
	if strings.HasPrefix(wr, sdjwtKbInvalid) {
		return strings.HasPrefix(gr, sdjwtKbInvalid)
	}
	for _, p := range sdjwtOwnPrefixes {
		if strings.HasPrefix(wr, p) {
			return wr == gr
		}
	}
	return true
}

func sdjwtIssueW(a []any) (any, error) {
	pc, m := vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1))
	seed := vcBytes(m["issuer_seed"])
	if _, err := ImportEd25519PrivateKey(seed); err != nil {
		return nil, err
	}
	o := SdJwtIssueOptions{IssuerSeed: seed}
	if l, ok := m["disclosable"].([]any); ok {
		o.Disclosable = []string{}
		for _, x := range l {
			if s, ok := x.(string); ok {
				o.Disclosable = append(o.Disclosable, s)
			}
		}
	}
	if kb, has := m["key_binding"]; has && jsTruthy(kb) {
		e := &SdJwtKeyBindingEmbed{}
		if km, ok := kb.(map[string]any); ok {
			if hp, has := km["holder_public_key"]; has {
				switch {
				case hp == nil:
					e.HolderPublicKey = false // null is neither a JWK nor raw bytes
				case sdjwtIsBytes(hp):
					e.HolderPublicKey = vcBytes(hp)
				default:
					e.HolderPublicKey = hp
				}
			}
		}
		o.KeyBinding = e
	}
	for k, p := range map[string]**string{"iss": &o.Iss, "sub": &o.Sub, "typ": &o.Typ} {
		if s, ok := m[k].(string); ok {
			*p = &s
		}
	}
	if x, has := m["signing_alg"]; has {
		s, ok := x.(string)
		if !ok {
			return nil, errors.New("signing alg must be a string")
		}
		o.SigningAlg = &s
	}
	sd, err := IssuePcaSdJwt(pc, o)
	if err != nil {
		return nil, err
	}
	return sdjwtNormalize(sd, seed)
}

// sdjwtNormalize is the generator's normalized form: header, clear payload, sorted [name, value] disclosures, digest agreement
// and whether the token verifies at its own iat.
func sdjwtNormalize(sd string, seed []byte) (any, error) {
	parts := strings.Split(sd, "~")
	ds := parts[1 : len(parts)-1]
	dec := func(s string) any {
		b, _ := base64.RawURLEncoding.DecodeString(s)
		v, _ := ParseJSONLenient(b)
		return v
	}
	seg := strings.Split(parts[0], ".")
	h, p := dec(seg[0]), vecObj(dec(seg[1]))
	var dig, sdl []string
	disc := [][]any{}
	for _, d := range ds {
		dig = append(dig, sdjwtHash(d))
		l, _ := dec(d).([]any)
		disc = append(disc, []any{l[1], l[2]})
	}
	for _, x := range vecArgList(p["_sd"]) {
		s, _ := x.(string)
		sdl = append(sdl, s)
	}
	sort.Strings(dig)
	sort.Strings(sdl)
	sort.SliceStable(disc, func(i, j int) bool { a, _ := disc[i][0].(string); b, _ := disc[j][0].(string); return a < b })
	rest := map[string]any{}
	for k, v := range p {
		if k != "_sd" {
			rest[k] = v
		}
	}
	key, _ := ImportEd25519PublicKey(sdjwtPub(seed))
	iat, _ := jsNum(p["iat"])
	now := iat * 1000
	o := SdJwtVerifyOptions{IssuerKey: key, NowMs: &now}
	if math.Abs(now) > 8.64e15 {
		// The reference's clock is Invalid Date here (time checks off); these far-future tokens are valid on the wall clock.
		o.NowMs = nil
	}
	return map[string]any{"end": parts[len(parts)-1], "header": h, "payload": rest, "n": len(ds), "digestsOk": strings.Join(dig, ",") == strings.Join(sdl, ","),
		"disclosures": disc, "verified": VerifyPcaSdJwt(sd, o).OK}, nil
}

func sdjwtPresentW(a []any) (any, error) {
	sd, _ := vecArg(a, 0).(string)
	var sel []string
	switch v := vecArg(a, 1).(type) {
	case nil:
	case string:
		for _, r := range v {
			sel = append(sel, string(r)) // a string selector is iterated as its characters
		}
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok {
				sel = append(sel, s)
			}
		}
	default:
		return nil, fmt.Errorf("%v is not iterable", v)
	}
	var kb *sdjwtKbClaims
	if km, ok := vecObj(vecArg(a, 2))["key_binding"].(map[string]any); ok {
		seed := vcBytes(km["holder_seed"])
		if _, err := ImportEd25519PrivateKey(seed); err != nil {
			return nil, err
		}
		kb = &sdjwtKbClaims{seed: seed, alg: SdJwtDefaultSigningAlg, iat: km["iat"]}
		if x, has := km["alg"]; has && x != nil {
			s, ok := x.(string)
			if !ok {
				return nil, errors.New("alg must be a string")
			}
			kb.alg = s
		}
		kb.aud, kb.hasAud = km["audience"]
		kb.nonce, kb.hasNonce = km["nonce"]
	}
	return sdjwtPresent(sd, sel, kb)
}

func sdjwtRecoveredW(a []any) (any, error) {
	res, m := vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1))
	aud, ok := m["audience"].(string)
	if !ok {
		return nil, vecSkip("the native core has no audience opt-out: an absent / null audience is not expressible")
	}
	now, _ := jsNum(m["now"])
	r := SdJwtVerifyResult{OK: true, Claims: vecObj(res["claims"]), Processed: vecObj(res["processed"])}
	v := VerifySdJwtRecovered(r, vecObj(m["grant"]), int64(now), aud, VerifyOptions{InsecureSkipPlanRootCheck: m["insecure_skip_plan_root_check"] == true})
	out := map[string]any{"allow": v.Allow}
	if v.Reason != "" {
		out["reason"] = strings.Replace(v.Reason, "chain: ", "cap_chain: ", 1) // the reference names the chain check cap_chain
		if !strings.HasPrefix(v.Reason, "chain: ") {
			out["reason"] = v.Reason
		}
	}
	return out, nil
}

func TestSdJwtVectors(t *testing.T) {
	replayVectorsCmp(t, "ref-sdjwt.json.gz", map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{"SD_ALG": SdJwtSdAlg, "PCA_SD_JWT_TYP": PcaSdJwtTyp, "KB_JWT_TYP": SdJwtKbTyp, "DEFAULT_SIGNING_ALG": SdJwtDefaultSigningAlg,
				"PCA_CAPABILITY_CLAIMS": PcaCapabilityClaims}, nil
		},
		"ed25519PublicJwk": func(a []any) (any, error) { return Ed25519PublicJwk(vcBytes(vecArg(a, 0))) },
		"importEd25519PrivateKey": func(a []any) (any, error) {
			_, err := ImportEd25519PrivateKey(vcBytes(vecArg(a, 0)))
			return "ok", err
		},
		"importEd25519PublicKey": func(a []any) (any, error) {
			_, err := ImportEd25519PublicKey(vcBytes(vecArg(a, 0)))
			return "ok", err
		},
		"issuePcaSdJwt":   sdjwtIssueW,
		"present":         sdjwtPresentW,
		"verifyPcaSdJwt":  func(a []any) (any, error) { return sdjwtVerifyW(vecArg(a, 0), vecObj(vecArg(a, 1))) },
		"verifyRecovered": sdjwtRecoveredW,
	}, map[string]func(want, got any) bool{"verifyPcaSdJwt": sdjwtVerifyCmp})
}
