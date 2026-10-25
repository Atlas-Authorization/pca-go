package pca

// Kills for the W-B suite agility and absent-vs-null rules of rules 16-18 (follows d63b36e6): optional alg / pq_pk /
// pq_sig on facts, offer sets, label receipts and classifier verdicts, unsupported_suite before anything else about the
// artifact, PQ only under the trusted-side pin; malformed W-B containers fail `facts`; layer ceilings.

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

type wbPQKey struct {
	pk string
	sk *mldsa65.PrivateKey
}

func newWBPQKey(t *testing.T) wbPQKey {
	pk, sk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return wbPQKey{b64.EncodeToString(pk.Bytes()), sk}
}

// signArtPQ signs a W-B artifact under ml-dsa-65 (alg and pq_pk in the signed body).
func signArtPQ(t *testing.T, k wbPQKey, domain string, a map[string]any) map[string]any {
	t.Helper()
	a["alg"], a["pq_pk"] = "ml-dsa-65", k.pk
	b, err := canonBytes(withoutKeys(a, "sig", "pq_sig"))
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(k.sk, append([]byte(domain), b...), nil, false, sig); err != nil {
		t.Fatal(err)
	}
	a["sig"] = b64.EncodeToString(sig)
	return a
}

func TestMutWBFactSuites(t *testing.T) {
	ed := newKey(t)
	pq := newWBPQKey(t)
	body := func() map[string]any {
		return map[string]any{"v": jnum(1), "kind": "pca-fact", "name": "fare", "subject": "OF-2", "value": jnum(5), "t_obs": jnum(v2Now), "oracle": "o0"}
	}
	run := func(f map[string]any, pin map[string]any) (bool, string) {
		pol := map[string]any{"worlds": []any{map[string]any{"name": "fare", "subject_path": "action.params.offer_id", "oracles": []any{pin},
			"freshness_ms": jnum(1000), "min_oracles": jnum(1), "max_faulty": jnum(0)}}}
		in := worldInput(t, nil, []map[string]any{f}, pol)
		r, why := IntentWorldPrimitive(normalizeJSON(in))
		return r["ok"] == true, why
	}
	edPin := map[string]any{"kid": "o0", "pk": ed.id}
	if ok, why := run(signArt(t, ed, factDomain, body()), edPin); !ok {
		t.Fatalf("ed25519 fact: %s", why)
	}
	// unsupported suite: refused with unsupported_suite before anything else (even an undeclared world)
	f := body()
	f["alg"], f["sig"] = "no-such-suite", b64.EncodeToString(make([]byte, 64))
	f["name"] = "undeclared"
	if ok, why := run(f, edPin); ok || !strings.Contains(why, UnsupportedSuite) {
		t.Fatalf("unsupported fact suite: %v %q", ok, why)
	}
	// a non-string alg is malformed (not unsupported_suite)
	f = signArt(t, ed, factDomain, body())
	f["alg"] = jnum(1)
	if ok, why := run(f, edPin); ok || strings.Contains(why, UnsupportedSuite) {
		t.Fatalf("numeric alg: %v %q", ok, why)
	}
	// an ed25519 fact carrying pq_pk / pq_sig
	for _, k := range []string{"pq_pk", "pq_sig"} {
		f = body()
		f[k] = "AAAA"
		f = signArt(t, ed, factDomain, f)
		if ok, _ := run(f, edPin); ok {
			t.Fatalf("ed25519 fact with %s", k)
		}
	}
	// ML-DSA-65: verifies only under the pinned pq_pk
	pqf := signArtPQ(t, pq, factDomain, body())
	if ok, why := run(pqf, map[string]any{"kid": "o0", "pk": ed.id, "pq_pk": pq.pk}); !ok {
		t.Fatalf("pinned ml-dsa-65 fact: %s", why)
	}
	if ok, _ := run(pqf, edPin); ok {
		t.Fatal("unpinned ml-dsa-65 fact")
	}
	if ok, _ := run(pqf, map[string]any{"kid": "o0", "pk": ed.id, "pq_pk": newWBPQKey(t).pk}); ok {
		t.Fatal("ml-dsa-65 fact under another pinned key")
	}
	// pin pq_pk: null / empty is a malformed policy
	for _, bad := range []any{nil, ""} {
		if ok, _ := run(signArt(t, ed, factDomain, body()), map[string]any{"kid": "o0", "pk": ed.id, "pq_pk": bad}); ok {
			t.Fatalf("pin pq_pk %v", bad)
		}
	}
	// supplied offer_set must be an object even without an offers policy
	in := worldInput(t, nil, nil, map[string]any{})
	in["offer_set"] = nil
	if r, _ := IntentWorldPrimitive(normalizeJSON(in)); r["ok"] != false {
		t.Fatal("offer_set null")
	}
	in["offer_set"] = []any{}
	if r, _ := IntentWorldPrimitive(normalizeJSON(in)); r["ok"] != false {
		t.Fatal("offer_set array")
	}
	// absent / null action
	in = worldInput(t, nil, nil, map[string]any{})
	delete(in, "action")
	if r, _ := IntentWorldPrimitive(normalizeJSON(in)); r["ok"] != false {
		t.Fatal("absent action")
	}
}

func TestMutWBOfferLabelVerdictSuites(t *testing.T) {
	site := newKey(t)
	os := signArt(t, site, offerSetDomain, map[string]any{"v": jnum(1), "kind": "pca-offer-set", "site": v2Aud, "session": dg("session"), "query": map[string]any{},
		"rank": "price_asc", "complete": true, "offers": []any{map[string]any{"offer_id": "OF-2", "price": jnum(100)}}, "issued_at": jnum(v2Now), "kid": "s1"})
	os["alg"] = "no-such-suite"
	offers := map[string]any{"offers": map[string]any{"name": "excess", "site_keys": []any{map[string]any{"kid": "s1", "pk": site.id}}, "max_age_ms": jnum(1000),
		"offer_param": "action.params.offer_id", "filter": map[string]any{"query": map[string]any{}, "offer": map[string]any{}}}}
	in := worldInput(t, nil, nil, offers)
	in["committed"] = map[string]any{"offer_set": refOf(t, offerSetRefDomain, "o", os)}
	in["offer_set"] = os
	if r, why := IntentWorldPrimitive(normalizeJSON(in)); r["ok"] != false || !strings.Contains(why, UnsupportedSuite) {
		t.Fatalf("offer set suite: %v %q", r, why)
	}
	// site key pq_pk null is a malformed offers policy
	offers["offers"].(map[string]any)["site_keys"] = []any{map[string]any{"kid": "s1", "pk": site.id, "pq_pk": nil}}
	if r, _ := IntentWorldPrimitive(normalizeJSON(in)); r["ok"] != false {
		t.Fatal("site key pq_pk null")
	}

	// label receipt with an unsupported suite: deny with unsupported_suite
	lk := newKey(t)
	rc := signArt(t, lk, labelsDomain, map[string]any{"v": jnum(1), "kind": "pca-labels", "site": v2Aud, "session": dg("session"), "response_digest": dg("r"),
		"fields": map[string]any{"f": map[string]any{"class": "public", "value_digest": dg("v")}}, "issued_at": jnum(v2Now), "kid": "k1"})
	rc["alg"] = "no-such-suite"
	ref := refOf(t, labelsRefDomain, "l", rc)
	pin := map[string]any{"site": v2Aud, "kid": "k1", "pk": lk.id}
	pin2 := map[string]any{"site": v2Aud, "kid": "k1", "pk": lk.id, "pq_pk": nil}
	prov := func(p map[string]any) (map[string]any, string) {
		return IntentProvenancePrimitive(normalizeJSON(map[string]any{"aud": v2Aud, "session": dg("session"), "action": map[string]any{"params": map[string]any{"a": "x"}},
			"prov": map[string]any{"action.params.a": []any{labelRefPrefix + ref + "#f"}}, "committed_labels": []any{ref}, "labels": []any{rc},
			"policy": map[string]any{"params": map[string]any{}, "label_keys": []any{p}}}))
	}
	if r, why := prov(pin); r["outcome"] != "deny" || !strings.Contains(why, UnsupportedSuite) {
		t.Fatalf("label suite: %v %q", r, why)
	}
	if r, _ := prov(pin2); r["outcome"] != "deny" {
		t.Fatal("label key pq_pk null")
	}

	// classifier: unsupported suite; ml-dsa-65 under the pq_keys pin only
	pqj := newWBPQKey(t)
	judge := newKey(t)
	cd, _ := hashCanonicalV("x")
	verdict := func(pqSigned bool) map[string]any {
		v := map[string]any{"v": jnum(1), "kind": "pca-intent-classification", "classifier": "tone", "session": dg("session"), "content_digest": cd,
			"label": "a", "measurement": "m", "judge": judge.id}
		if pqSigned {
			return signArtPQ(t, pqj, classifierDomain, v)
		}
		return signArt(t, judge, classifierDomain, v)
	}
	cls := func(v map[string]any, pqKeys any) (map[string]any, string) {
		c := map[string]any{"id": "tone", "param": "action.params.body", "labels": []any{"a"}, "keys": []any{judge.id}, "k": jnum(1)}
		if pqKeys != nil {
			c["pq_keys"] = pqKeys
		}
		return IntentClassifierPrimitive(normalizeJSON(map[string]any{"session": dg("session"), "action": map[string]any{"params": map[string]any{"body": "x"}},
			"committed": []any{refOf(t, classifierRefDomain, "c", v)}, "verdicts": []any{v}, "policy": map[string]any{"classifiers": []any{c}}}))
	}
	if r, why := cls(verdict(false), nil); r["ok"] != true {
		t.Fatalf("ed25519 verdict: %s", why)
	}
	u := verdict(false)
	u["alg"] = "no-such-suite"
	if r, why := cls(u, nil); r["ok"] != false || !strings.Contains(why, UnsupportedSuite) {
		t.Fatalf("verdict suite: %v %q", r, why)
	}
	pv := verdict(true)
	if r, why := cls(pv, map[string]any{judge.id: pqj.pk}); r["ok"] != true {
		t.Fatalf("pinned pq verdict: %s", why)
	}
	if r, _ := cls(pv, nil); r["ok"] != false {
		t.Fatal("unpinned pq verdict")
	}
	if r, _ := cls(pv, map[string]any{dg("other"): pqj.pk}); r["ok"] != false {
		t.Fatal("pq_keys for a key not on the allowlist")
	}
	if r, _ := cls(pv, map[string]any{judge.id: ""}); r["ok"] != false {
		t.Fatal("empty pq_keys entry")
	}
}

func TestMutWBContextAndLayers(t *testing.T) {
	is := map[string]any{"session": dg("s")}
	act := map[string]any{"verb": "v", "resource": "r", "params": map[string]any{}}
	for name, c := range map[string]struct{ art, pol any }{
		"artifacts-array":  {[]any{}, map[string]any{}},
		"facts-object":     {map[string]any{"facts": map[string]any{}}, map[string]any{}},
		"offer_set-array":  {map[string]any{"offer_set": []any{}}, map[string]any{}},
		"policy-array":     {nil, []any{}},
		"world-string":     {nil, map[string]any{"world": "x"}},
		"classifiers-obj":  {nil, map[string]any{"classifiers": map[string]any{}}},
		"provenance-array": {nil, map[string]any{"provenance": []any{}}},
	} {
		wb := decideIntentWB(float64(v2Now), v2Aud, dg("s"), act, is, c.art, c.pol)
		if wb.checks["facts"] != "fail" || len(wb.checks) != 1 {
			t.Fatalf("%s: %v", name, wb.checks)
		}
	}
	if wb := decideIntentWB(float64(v2Now), v2Aud, dg("s"), act, is, nil, map[string]any{}); len(wb.checks) != 0 {
		t.Fatalf("empty W-B: %v", wb.checks)
	}
	ctx := map[string]any{"action": map[string]any{"verb": "v", "resource": "r", "params": map[string]any{}}}
	for name, l := range map[string]any{"null": nil, "array": []any{}, "org-null": map[string]any{"org": nil},
		"site-no-predicates": map[string]any{"site": map[string]any{}}, "std-predicates-null": map[string]any{"std": map[string]any{"predicates": nil}}} {
		if decideLayerCeilings(l, ctx) == "" {
			t.Fatalf("layers %s admitted", name)
		}
	}
	if decideLayerCeilings(map[string]any{}, ctx) != "" {
		t.Fatal("no ceilings admit")
	}
}

// Closed and typed W-B / layers policies (follows 0cc44911): an unknown member is malformed at every level.
func TestMutWBClosedPolicies(t *testing.T) {
	ed := newKey(t)
	world := func() map[string]any {
		return map[string]any{"name": "fare", "subject_path": "action.params.offer_id", "oracles": []any{map[string]any{"kid": "o0", "pk": ed.id}},
			"freshness_ms": jnum(1000), "min_oracles": jnum(1), "max_faulty": jnum(0)}
	}
	offers := func() map[string]any {
		return map[string]any{"name": "excess", "site_keys": []any{map[string]any{"kid": "s1", "pk": ed.id}}, "max_age_ms": jnum(1000),
			"offer_param": "action.params.offer_id", "filter": map[string]any{"query": map[string]any{}, "offer": map[string]any{}}}
	}
	base := func() map[string]any {
		return map[string]any{"worlds": []any{world()}, "relational": []any{map[string]any{"name": "d", "fn": "sub", "a": "action.params.total", "b": "action.params.quote"}},
			"offers": offers()}
	}
	if !validateWorldPolicy(normalizeJSON(base())) {
		t.Fatal("base world policy")
	}
	for name, mut := range map[string]func(p map[string]any){
		"policy-unknown": func(p map[string]any) { p["extra"] = jnum(1) },
		"world-unknown":  func(p map[string]any) { p["worlds"].([]any)[0].(map[string]any)["note"] = "x" },
		"world-missing":  func(p map[string]any) { delete(p["worlds"].([]any)[0].(map[string]any), "max_faulty") },
		"oracle-unknown": func(p map[string]any) {
			p["worlds"].([]any)[0].(map[string]any)["oracles"].([]any)[0].(map[string]any)["alg"] = "ed25519"
		},
		"relational-unknown": func(p map[string]any) { p["relational"].([]any)[0].(map[string]any)["c"] = "x" },
		"offers-unknown":     func(p map[string]any) { p["offers"].(map[string]any)["note"] = "x" },
		"site-key-unknown": func(p map[string]any) {
			p["offers"].(map[string]any)["site_keys"].([]any)[0].(map[string]any)["site"] = "x"
		},
		"filter-unknown":   func(p map[string]any) { p["offers"].(map[string]any)["filter"].(map[string]any)["sort"] = "x" },
		"freshness-string": func(p map[string]any) { p["worlds"].([]any)[0].(map[string]any)["freshness_ms"] = "1000" },
		"fn-number":        func(p map[string]any) { p["relational"].([]any)[0].(map[string]any)["fn"] = jnum(1) },
	} {
		p := base()
		mut(p)
		if validateWorldPolicy(normalizeJSON(p)) {
			t.Fatalf("world policy %s accepted", name)
		}
	}
	prov := map[string]any{"params": map[string]any{}, "label_keys": []any{map[string]any{"site": "s", "kid": "k", "pk": ed.id}}}
	if !validateProvenancePolicy(normalizeJSON(prov)) {
		t.Fatal("base provenance policy")
	}
	for name, p := range map[string]map[string]any{
		"policy-unknown":    {"params": map[string]any{}, "note": "x"},
		"label-key-unknown": {"params": map[string]any{}, "label_keys": []any{map[string]any{"site": "s", "kid": "k", "pk": ed.id, "alg": "x"}}},
		"params-missing":    {"registry": map[string]any{}},
		"mode-number":       {"params": map[string]any{}, "material_tainted": jnum(1)},
	} {
		if validateProvenancePolicy(normalizeJSON(p)) {
			t.Fatalf("provenance policy %s accepted", name)
		}
	}
	cls := func() map[string]any {
		return map[string]any{"id": "tone", "param": "action.params.body", "labels": []any{"a"}, "keys": []any{ed.id}, "k": jnum(1)}
	}
	if !validateClassifierPolicy(normalizeJSON(map[string]any{"classifiers": []any{cls()}})) {
		t.Fatal("base classifier policy")
	}
	c := cls()
	c["note"] = "x"
	for name, p := range map[string]map[string]any{
		"policy-unknown":     {"classifiers": []any{cls()}, "note": "x"},
		"classifier-unknown": {"classifiers": []any{c}},
		"policy-missing":     {},
	} {
		if validateClassifierPolicy(normalizeJSON(p)) {
			t.Fatalf("classifier policy %s accepted", name)
		}
	}
	// W-B context: closed artifacts / policy fail `facts`
	is := map[string]any{"session": dg("s")}
	act := map[string]any{"verb": "v", "resource": "r", "params": map[string]any{}}
	for name, c := range map[string]struct{ art, pol any }{
		"artifacts-unknown": {map[string]any{"receipts": []any{}}, map[string]any{}},
		"policy-unknown":    {nil, map[string]any{"layers": map[string]any{}}},
	} {
		wb := decideIntentWB(float64(v2Now), v2Aud, dg("s"), act, is, c.art, c.pol)
		if wb.checks["facts"] != "fail" || len(wb.checks) != 1 {
			t.Fatalf("%s: %v", name, wb.checks)
		}
	}
	// layers: an unknown member of the layers object fails as org; a ceiling with an extra member fails as itself
	ctx := map[string]any{"action": map[string]any{"verb": "v", "resource": "r", "params": map[string]any{}}}
	ok := map[string]any{"predicates": []any{map[string]any{"verb": "*"}}}
	if r := decideLayerCeilings(map[string]any{"org": ok, "extra": ok}, ctx); !strings.Contains(r, "org") {
		t.Fatalf("unknown layers member: %q", r)
	}
	if r := decideLayerCeilings(map[string]any{"site": map[string]any{"predicates": []any{map[string]any{"verb": "*"}}, "note": "x"}}, ctx); !strings.Contains(r, "site") {
		t.Fatalf("extra ceiling member: %q", r)
	}
	if decideLayerCeilings(map[string]any{"org": ok, "site": ok, "std": ok}, ctx) != "" {
		t.Fatal("well-formed ceilings")
	}
}
