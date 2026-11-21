package pca

// k05 differential oracle: the action kit (actions*.go, action_schema.go) against the TypeScript reference
// packages/pca-actions (testdata/k05-actions.json.gz, tools/pca-audit/k05-oracles/actions-oracle.mts). `cmp: "code"` cases
// compare only the `<code>:` prefix (the reference text there comes from a caught exception). A registry argument is
// regOf(custom): null = the core registry, else the core extended by the custom traits (an extension error is the throw).
// reviewMessage: Go builds the review message inline (confirmationError), exercised through isConfirmed; skipped.

import (
	"encoding/json"
	"math"
	"regexp"
	"strings"
	"testing"
)

func k05ActStrs(v any) ([]string, bool) {
	if v == nil {
		return []string{}, true
	}
	return strsOf(v)
}

func k05ActProfile(p Profile) map[string]any { return normalizeJSON(p.raw()).(map[string]any) }

// k05ActCode is the `<code>` of a "<code>: reason" text.
func k05ActCode(s string) string {
	if i := strings.Index(s, ": "); i >= 0 {
		return s[:i]
	}
	return s
}

var k05ReQuoted = regexp.MustCompile(`'[^']*'`)

// k05ProfileDefects is every strict-JSON-profile defect anywhere in v (the reference reports the first in insertion order).
func k05ProfileDefects(v any, depth int, out map[string]bool) map[string]bool {
	if depth > 32 {
		out["nesting deeper than 32"] = true
		return out
	}
	switch t := v.(type) {
	case []any:
		for _, x := range t {
			k05ProfileDefects(x, depth+1, out)
		}
	case map[string]any:
		for k, x := range t {
			if e := defJSONProfileError(map[string]any{k: nil}, 0); e != "" {
				out[e] = true
			}
			k05ProfileDefects(x, depth+1, out)
		}
	default:
		if e := defJSONProfileError(t, depth); e != "" {
			out[e] = true
		}
	}
	return out
}

// k05DefSameRefusal: a def with several defects is refused by the reference for the first in insertion order (lost by a Go
// map), by Go for the first in name order. Equivalent when both are real defects of the def: for strict-JSON-profile
// refusals both are defects found in it; for parameter refusals, dropping each parameter Go names first (each a real
// refusal) reaches exactly the reference's message.
func k05DefSameRefusal(def any, want, got string) bool {
	const sj = "not strict JSON: "
	if strings.HasPrefix(want, sj) || strings.HasPrefix(got, sj) {
		ds := k05ProfileDefects(def, 0, map[string]bool{})
		return strings.HasPrefix(want, sj) && strings.HasPrefix(got, sj) && ds[want[len(sj):]] && ds[got[len(sj):]]
	}
	d, ok := def.(map[string]any)
	params, ok2 := d["params"].(map[string]any)
	if !ok || !ok2 {
		return false
	}
	cp, ps := map[string]any{}, map[string]any{}
	for k, x := range d {
		cp[k] = x
	}
	for k, x := range params {
		ps[k] = x
	}
	cp["params"] = ps
	for range params {
		n := k05ActCode(got)
		if _, has := ps[n]; !has || n == k05ActCode(want) {
			return false
		}
		delete(ps, n)
		if got = validateDef(cp); got == want {
			return true
		}
	}
	return false
}

func TestK05Actions(t *testing.T) {
	var k k05Tally
	regOf := func(custom any) (Registry, error) {
		if custom == nil {
			return coreRegistry, nil
		}
		list, _ := custom.([]any)
		return extendRegistry(coreRegistry, list)
	}
	// res compares a (value, error) result: a reference throw needs an error (with its code when it carries one)
	res := func(c *k05Case, got any, err error) {
		if th, code := k05Throws(c.Out); th {
			if err == nil {
				k.fail(c, "want a throw (%s), got %s", code, k05Canon(normalizeJSON(got)))
			} else if code != "" && !k05HasCode(err.Error(), code) {
				k.fail(c, "want code %s, got %v", code, err)
			}
			return
		}
		if err != nil {
			k.fail(c, "want %s, got error %v", k05Canon(c.Out), err)
			return
		}
		if g := k05Canon(normalizeJSON(got)); g != k05Canon(c.Out) {
			k.fail(c, "want %s, got %s", k05Canon(c.Out), g)
		}
	}
	strOrNull := func(c *k05Case, got string) {
		want, _ := c.Out.(string)
		if c.C["cmp"] == "code" {
			if !strings.HasPrefix(got, k05ActCode(want)+": ") {
				k.fail(c, "want code of %q, got %q", want, got)
			}
			return
		}
		if got != want && !k05SameUnknown(want, got) {
			k.fail(c, "want %v, got %q", c.Out, got)
		}
	}
	boolean := func(c *k05Case, got bool) {
		if got != c.Out {
			k.fail(c, "want %v, got %v", c.Out, got)
		}
	}
	strs := func(xs []string) []any { return anyStrs(xs) }
	k05Each(t, "k05-actions.json.gz", func(c *k05Case) {
		a := c.Args
		k.run(c.Fn)
		switch c.Fn {
		case "validateDef":
			got := validateDef(a[0])
			if want, _ := c.Out.(string); got != want && want != "" && got != "" && k05DefSameRefusal(a[0], want, got) {
				return
			}
			strOrNull(c, got)
		case "isRole":
			boolean(c, isRole(a[0]))
		case "isFormat":
			boolean(c, isFormat(a[0]))
		case "isContextKey":
			s, ok := a[0].(string)
			boolean(c, ok && isContextKey(s))
		case "paramNameError":
			strOrNull(c, paramNameError(a[0].(string)))
		case "jsonProfileError":
			strOrNull(c, defJSONProfileError(a[0], 0))
		case "idPatternError":
			strOrNull(c, idPatternError(a[0]))
		case "profileError":
			strOrNull(c, profileErrorRaw(a[0]))
		case "registryError":
			list, ok := a[0].([]any)
			if !ok {
				k.skip(c.Fn, "typed port: registryErrorRaw takes the trait list ([]any)")
				return
			}
			strOrNull(c, registryErrorRaw(list, a[1] == true))
		case "closure", "floorOf", "topTraits", "traitsDigest":
			reg, err := regOf(a[0])
			if err != nil {
				res(c, nil, err)
				return
			}
			switch c.Fn {
			case "closure", "floorOf":
				ids, _ := k05ActStrs(a[1])
				if c.Fn == "closure" {
					cl, err := reg.closure(ids)
					res(c, strs(cl), err)
				} else {
					fl, err := reg.floorOf(ids)
					res(c, fl.raw(), err)
				}
			case "topTraits":
				res(c, strs(topTraits(reg)), nil)
			default:
				d, err := traitsDigest(reg)
				res(c, d, err)
			}
		case "tablesDigest":
			d, err := tablesDigest()
			res(c, d, err)
		case "floorDecision":
			g := a[0].(map[string]any)
			gc, _ := k05ActStrs(g["caveats"])
			cx, _ := k05ActStrs(a[1].(map[string]any)["context"])
			got := floorDecision(GrantFacts{Caveats: gc, MaxEsc: int(jsF(g["max_esc"])), PreauthEsc: int(jsF(g["preauth_esc"]))}, cx, profileFromRaw(a[2]))
			if got != c.Out {
				k.fail(c, "want %v, got %s", c.Out, got)
			}
		case "worstReversibility":
			pm, _ := a[1].(map[string]any)
			res(c, worstReversibility(a[0], pm), nil)
		case "sensitivityFloor":
			res(c, paramSensitivityFloor(a[0].(map[string]any)), nil)
		case "impliedFromFacts":
			f := a[0].(map[string]any)
			effects, _ := k05ActStrs(f["effects"])
			var params []map[string]any
			for _, p := range f["params"].([]any) {
				params = append(params, p.(map[string]any))
			}
			scope, _ := f["scope"].(string)
			wr, _ := f["worstRev"].(string)
			got, err := impliedFromFacts(effects, params, scope, wr)
			res(c, strs(got), err)
		case "normalize":
			res(c, normalizeDef(a[0].(map[string]any)), nil)
		case "defDigest":
			d, err := defDigest(a[0].(map[string]any))
			res(c, d, err)
		case "declProfile":
			res(c, k05ActProfile(declProfile(a[0].(map[string]any))), nil)
		case "hintTraits":
			res(c, strs(hintTraits(a[0].(map[string]any))), nil)
		case "effective":
			d := a[0].(map[string]any)
			e, err := effective(d, coreRegistry, a[1])
			var got map[string]any
			if err == nil {
				fl, _ := coreRegistry.floorOf(e.Traits)
				got = map[string]any{"confirmed": e.Confirmed, "traits": strs(e.Traits), "closure": strs(e.Closure), "floor": fl.raw(),
					"decl": declProfile(d).raw(), "eff": e.Eff.raw()}
			}
			res(c, got, err)
		case "reviewerPinsError":
			strOrNull(c, reviewerPinsError(a[0]))
		case "reviewMessage":
			k.skip(c.Fn, "Go builds the review message inline (confirmationError); covered by isConfirmed")
		case "isConfirmed":
			boolean(c, defConfirmed(a[0].(map[string]any), coreRegistry, a[1]))
		case "factsDigest":
			d, err := factsDigest(a[0].(map[string]any))
			res(c, d, err)
		case "schemaVerbFloorError":
			v, ok := a[0].(map[string]any)
			if !ok {
				k.skip(c.Fn, "typed port: the verb is not an object")
				return
			}
			got := schemaVerbFloorError(v, coreRegistry, a[1])
			if want, _ := c.Out.(string); got != want && strings.HasPrefix(got, "schema_floor_forged: malformed verb: ") &&
				!(c.C["cmp"] == "code" && k05ActCode(want) == "schema_floor_forged") {
				// Go refuses a verb whose params / reversibility / floors it cannot read exactly; the reference reads some of
				// these leniently (Object.entries of a string, a map value that is no class, string-number floors)
				if want == "" {
					k.skip(c.Fn, "Go refuses a malformed verb field the reference reads leniently (stricter): "+k05ReQuoted.ReplaceAllString(got[len("schema_floor_forged: malformed verb: "):], "'_'"))
				} else {
					k.skip(c.Fn, "both refuse; Go names the malformed verb field first")
				}
				return
			}
			strOrNull(c, got)
		case "schemaFloorError":
			strOrNull(c, schemaFloorError(a[0].(map[string]any), a[1]))
		case "packRoot":
			ds, _ := k05ActStrs(a[0])
			r, err := packRoot(ds)
			res(c, r, err)
		case "packProof":
			ds, _ := k05ActStrs(a[0])
			p, err := packProof(ds, a[1].(string))
			res(c, p, err)
		default:
			k.fail(c, "unknown fn %s", c.Fn)
		}
	})
	k.finish(t)
}

// ---- the reference fixes of d36d91ac7, one each ----

func TestK05Rule22DeniesANonIntegerTier(t *testing.T) {
	fl := map[string]any{"risk": 2.0, "rev": "irreversible", "blast_ppm": 0.0, "esc": 2.0, "caveats": []any{"amount_cap"}, "context": []any{"idempotency"}, "prules": []any{}}
	doc := map[string]any{"verbs": []any{map[string]any{"verb": "a.pay.create", "floors": fl}}}
	decide := func(g map[string]any) string {
		g["caveats"] = []any{"amount_cap"}
		return rule22Decide(doc, "a.pay.create", g, []any{"idempotency"})
	}
	if got := decide(map[string]any{"max_esc": 3.0, "preauth_esc": 2.0}); got != "allow" {
		t.Fatalf("control: %s", got)
	}
	for i, g := range []map[string]any{{"preauth_esc": 2.0}, {"max_esc": "3", "preauth_esc": 2.0}, {"max_esc": 2.5, "preauth_esc": 2.0},
		{"max_esc": 3.0, "preauth_esc": -1.0}, {"max_esc": math.Copysign(0, -1), "preauth_esc": 0.0}, {"max_esc": 3.0, "preauth_esc": true}, {"max_esc": nil, "preauth_esc": 2.0}} {
		if got := decide(g); got != "deny" {
			t.Errorf("tiers #%d: %s, want deny", i, got)
		}
	}
	if floorDecision(GrantFacts{MaxEsc: 3, PreauthEsc: -1}, nil, Profile{}) != "deny" {
		t.Error("floorDecision: a negative tier must deny")
	}
}

func TestK05AReadAttestationWithoutAnArrayFinalTraitsIsNotConfirmed(t *testing.T) {
	var args []any
	k05Each(t, "k05-actions.json.gz", func(c *k05Case) {
		if c.Name == "isConfirmed/read good" {
			args = c.Args
		}
	})
	if args == nil || !defConfirmed(args[0].(map[string]any), coreRegistry, args[1]) {
		t.Fatal("control: isConfirmed/read good is not confirmed")
	}
	for _, f := range []any{"missing", nil, ""} {
		d := deepCopy(args[0]).(map[string]any)
		at := d["review"].(map[string]any)["attestation"].(map[string]any)
		if f == "missing" {
			delete(at, "final_traits")
		} else {
			at["final_traits"] = f
		}
		if defConfirmed(d, coreRegistry, args[1]) {
			t.Errorf("final_traits %v: confirmed", f)
		}
	}
}

func TestK05AReviewTsNegativeZeroIsNotConfirmed(t *testing.T) {
	var args []any
	k05Each(t, "k05-actions.json.gz", func(c *k05Case) {
		if c.Name == "isConfirmed/read ts 0 (control)" {
			args = c.Args
		}
	})
	if args == nil || !defConfirmed(args[0].(map[string]any), coreRegistry, args[1]) {
		t.Fatal("control: isConfirmed/read ts 0 is not confirmed")
	}
	for _, z := range []any{json.Number("-0"), math.Copysign(0, -1)} {
		d := deepCopy(args[0]).(map[string]any)
		d["review"].(map[string]any)["attestation"].(map[string]any)["ts"] = z
		if defConfirmed(d, coreRegistry, args[1]) {
			t.Errorf("ts %v (-0): confirmed", z)
		}
	}
}

func TestK05ANullMaxItemsImpliesBulk(t *testing.T) {
	for _, mi := range []any{"missing", nil, 10.0} {
		p := map[string]any{"type": "array"}
		if mi != "missing" {
			p["max_items"] = mi
		}
		got, err := impliedFromFacts([]string{"create"}, []map[string]any{p}, "", "reversible")
		if err != nil {
			t.Fatal(err)
		}
		if _, bounded := mi.(float64); contains(got, "pca.bulk") == bounded {
			t.Errorf("max_items %v: bulk = %v", mi, !bounded)
		}
	}
}

// 0.5: the action-schema confirmation shape refuses ts -0 (strict profile, as the TS reference).
func TestK05SchemaConfirmationTsNegativeZero(t *testing.T) {
	c := map[string]any{"def_digest": strings.Repeat("Q", 43), "traits_digest": strings.Repeat("A", 43), "facts_digest": strings.Repeat("A", 43),
		"final_traits": []any{"pca.irreversible", "pca.money_moving"}, "dismissed": []any{map[string]any{"trait": "pca.bulk", "reason": "one item"}},
		"reviewer_kid": "rev-1", "ts": json.Number("0"), "sig": strings.Repeat("Q", 86)}
	if e := confirmationShapeError(c); e != "" {
		t.Fatalf("control refused: %s", e)
	}
	for _, z := range []any{json.Number("-0"), math.Copysign(0, -1)} {
		c["ts"] = z
		if e := confirmationShapeError(c); e != "confirmation: ts must be a non-negative safe integer" {
			t.Fatalf("ts %v: got %q", z, e)
		}
	}
}
