package pca

// g04 mutation kills for actions_registry.go: natively signed packs (inline and sharded) driven to every verifyPack
// refusal with its exact reason and a zero def count, shard-ref shape bounds, signed re-approvals and evolution chains
// through decidePin, and the small helpers (failClosed, compareVersions, u16Less, packDefsOutOfRange).

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func g04Sha(c byte) string { return strings.Repeat(string(c), 43) }

func g04RegKeys(k fxKey) []any {
	return []any{map[string]any{"kid": "g04", "alg": "ed25519", "pk": k.id}}
}

// g04RegSign signs m (without its sig) under domain with k as registry key "g04".
func g04RegSign(t *testing.T, k fxKey, domain string, m map[string]any) map[string]any {
	t.Helper()
	m["sig"] = map[string]any{"alg": "ed25519", "kid": "g04", "value": signDomain(t, k, domain, withoutKeys(m, "sig"))}
	return m
}

// g04HonestDefs: the three valid defs of the shared pack-verify-honest vector.
func g04HonestDefs(t *testing.T) []any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(actionVectorDir(t), "pack-verify-honest.json"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := ParseJSONLenient(b)
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)["input"].(map[string]any)["pack"].(map[string]any)["defs"].([]any)
}

func g04DefDigests(t *testing.T, defs []any) []string {
	t.Helper()
	out := make([]string, len(defs))
	for i, d := range defs {
		dg, err := defDigest(d.(map[string]any))
		if err != nil {
			t.Fatal(err)
		}
		out[i] = dg
	}
	return out
}

// g04PackBody is an unsigned, shape-valid pack over defs (root recomputed) with no evolution records.
func g04PackBody(t *testing.T, defs []any) map[string]any {
	t.Helper()
	td, _ := traitsDigest(coreRegistry)
	rd, _ := tablesDigest()
	ud, _ := rulesDigest()
	root, err := packRoot(g04DefDigests(t, defs))
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"v": jnum(1), "kind": actionPackKind, "ns": "stripe", "version": "1.0.0", "stability": "stable",
		"traits_digest": td, "roles_digest": rd, "rules_digest": ud, "root": root, "defs": defs,
		"source": map[string]any{"kind": "hand", "uri": "internal://g04", "spec_digest": g04Sha('A'), "licence": "Apache-2.0", "licence_notes": ""},
		"prev":   nil, "evolution": []any{}}
}

func g04Evo(t *testing.T, k fxKey, ns, verb string, from, to any, class string) map[string]any {
	t.Helper()
	return g04RegSign(t, k, evolutionDomain, map[string]any{"v": jnum(1), "kind": evolutionRecordKind, "ns": ns, "verb": verb,
		"from": from, "to": to, "class": class, "reasons": []any{}})
}

func TestG04VerifyPackRefusals(t *testing.T) {
	k, other := newKey(t), newKey(t)
	keys := g04RegKeys(k)
	defs := g04HonestDefs(t)
	ds := g04DefDigests(t, defs)
	signed := func(mut func(p map[string]any)) map[string]any {
		p := g04PackBody(t, defs)
		if mut != nil {
			mut(p)
		}
		return g04RegSign(t, k, packSigDomain, p)
	}
	if d, n, r := verifyPack(signed(nil), keys, nil); r != "" || n != 3 || len(d) != 43 {
		t.Fatalf("honest pack: %q %d %q", d, n, r)
	}
	check := func(name string, pack any, ks any, shards map[string]any, want string) {
		t.Helper()
		d, n, r := verifyPack(pack, ks, shards)
		if d != "" || n != 0 || r != want {
			t.Errorf("%s: %q %d %q, want %q", name, d, n, r, want)
		}
	}
	check("not an object", "x", keys, nil, "pack must be an object")
	check("foreign key", signed(nil), g04RegKeys(other), nil, "pack signature: signature invalid")
	check("traits", signed(func(p map[string]any) { p["traits_digest"] = g04Sha('A') }), keys, nil, "traits_digest does not match the trait registry")
	check("roles", signed(func(p map[string]any) { p["roles_digest"] = g04Sha('A') }), keys, nil, "roles_digest does not match the vocabulary tables")
	check("rules", signed(func(p map[string]any) { p["rules_digest"] = g04Sha('A') }), keys, nil, "rules_digest does not match the rule tables")
	check("root", signed(func(p map[string]any) { p["root"] = g04Sha('A') }), keys, nil, "the Merkle root does not match the defs")
	check("evolution ns", signed(func(p map[string]any) {
		p["evolution"] = []any{g04Evo(t, k, "other", "other.x", nil, ds[0], "added")}
	}), keys, nil, "evolution record of another namespace")
	check("evolution target", signed(func(p map[string]any) {
		p["evolution"] = []any{g04Evo(t, k, "stripe", "stripe.x", nil, g04Sha('B'), "added")}
	}), keys, nil, "evolution record for 'stripe.x' names a definition that is not in the pack")
	check("evolution signature", signed(func(p map[string]any) {
		p["evolution"] = []any{g04Evo(t, other, "stripe", "stripe.x", nil, ds[0], "added")}
	}), keys, nil, "evolution record: signature invalid")
	// an ed25519 pack ignores pq_value when verifying, but its digest canonicalises the whole pack: a lone surrogate there fails it
	lone := signed(nil)
	lone["sig"].(map[string]any)["pq_value"] = "\xed\xa0\x80"
	if d, n, r := verifyPack(lone, keys, nil); d != "" || n != 0 || !strings.Contains(r, "lone surrogate") {
		t.Errorf("lone surrogate in pq_value: %q %d %q", d, n, r)
	}

	// sharded packs
	sharded := func(shardDefs any, root string) (map[string]any, map[string]any) {
		shard := map[string]any{"v": jnum(1), "kind": packShardKind, "ns": "stripe", "version": "1.0.0", "name": "s1", "defs": shardDefs}
		sd, err := shardDigest(shard)
		if err != nil {
			t.Fatal(err)
		}
		p := g04PackBody(t, defs)
		p["defs"] = map[string]any{"shards": []any{map[string]any{"name": "s1", "digest": sd, "uri": "u"}}}
		p["root"] = root
		return g04RegSign(t, k, packSigDomain, p), map[string]any{"s1": shard}
	}
	honestRoot, _ := packRoot(ds)
	p, sh := sharded(defs, honestRoot)
	if _, n, r := verifyPack(p, keys, sh); r != "" || n != 3 {
		t.Fatalf("honest sharded pack: %d %q", n, r)
	}
	check("missing shard", p, keys, map[string]any{}, "shard 's1' was not supplied")
	p, sh = sharded([]any{}, g04Sha('A'))
	check("no defs", p, keys, sh, "the pack lists no defs or too many")
	p, sh = sharded([]any{map[string]any{"x": jnum(1)}}, g04Sha('A'))
	if d, n, r := verifyPack(p, keys, sh); d != "" || n != 0 || !strings.HasPrefix(r, "def 0: ") {
		t.Errorf("bad shard def: %q %d %q", d, n, r)
	}
	// non-object shard defs make the verb sort panic: verifyPack fails closed with no digest and no count
	p, sh = sharded([]any{jnum(1), jnum(2)}, g04Sha('A'))
	if d, n, r := verifyPack(p, keys, sh); d != "" || n != 0 || !strings.HasPrefix(r, "pack verification error: ") {
		t.Errorf("panicking shard defs: %q %d %q", d, n, r)
	}
}

func TestG04PackShardRefShape(t *testing.T) {
	defs := g04HonestDefs(t)
	shape := func(ref map[string]any) string {
		p := g04PackBody(t, defs)
		p["defs"] = map[string]any{"shards": []any{ref}}
		return packShapeError(p, false)
	}
	const bad = "pack: bad shard digest or uri"
	for name, c := range map[string]struct {
		ref  map[string]any
		want string
	}{
		"ok":            {map[string]any{"name": "s1", "digest": g04Sha('A'), "uri": "u"}, ""},
		"uri 2048":      {map[string]any{"name": "s1", "digest": g04Sha('A'), "uri": strings.Repeat("u", 2048)}, ""},
		"uri 2049":      {map[string]any{"name": "s1", "digest": g04Sha('A'), "uri": strings.Repeat("u", 2049)}, bad},
		"uri empty":     {map[string]any{"name": "s1", "digest": g04Sha('A'), "uri": ""}, bad},
		"uri number":    {map[string]any{"name": "s1", "digest": g04Sha('A'), "uri": jnum(5)}, bad},
		"digest bad":    {map[string]any{"name": "s1", "digest": "x", "uri": "u"}, bad},
		"digest absent": {map[string]any{"name": "s1", "uri": "u"}, bad},
	} {
		if got := shape(c.ref); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
	p := g04PackBody(t, defs)
	p["defs"] = "x"
	if got := packShapeError(p, false); got != "pack: defs must be a list of defs or {shards}" {
		t.Errorf("non-object defs: %q", got)
	}
}

func TestG04RegistryHelpers(t *testing.T) {
	got := func() (s string) {
		defer failClosed(&s, func(r any) string { return fmt.Sprint("x:", r) })
		panic("boom")
	}()
	if got != "x:boom" {
		t.Errorf("failClosed on panic: %q", got)
	}
	got = func() (s string) {
		defer failClosed(&s, func(any) string { return "bad" })
		return "ok"
	}()
	if got != "ok" {
		t.Errorf("failClosed without panic: %q", got)
	}
	if panicFalse("x") {
		t.Error("panicFalse")
	}
	for n, want := range map[int]bool{0: true, 1: false, 1000000: false, 1000001: true} {
		if packDefsOutOfRange(n) != want {
			t.Errorf("packDefsOutOfRange(%d)", n)
		}
	}
	for _, c := range []struct {
		a, b, bad string
		n         int
	}{{"x", "1.0.0", "x", 0}, {"1.0.0", "y", "y", 0}, {"x", "y", "x", 0}, {"1.2.3", "1.2.4", "", -1}, {"2.0.0", "1.9.9", "", 1}, {"1.2.3", "1.2.3", "", 0}, {"1.10.0", "1.9.0", "", 1}} {
		n, err := compareVersions(c.a, c.b)
		if c.bad != "" {
			if n != 0 || err == nil || err.Error() != "bad_version: '"+c.bad+"' is not MAJOR.MINOR.PATCH" {
				t.Errorf("compareVersions(%q, %q) = %d %v", c.a, c.b, n, err)
			}
		} else if err != nil || n != c.n {
			t.Errorf("compareVersions(%q, %q) = %d %v, want %d", c.a, c.b, n, err, c.n)
		}
	}
	for _, c := range []struct {
		a, b string
		want bool
	}{{"a", "b", true}, {"b", "a", false}, {"a", "ab", true}, {"ab", "a", false}, {"a", "a", false}, {"ba", "ab", false}, {"", "a", true}, {"", "", false}, {"\U00010000", "￿", true}} {
		if u16Less(c.a, c.b) != c.want {
			t.Errorf("u16Less(%q, %q)", c.a, c.b)
		}
	}
	if d, ok := evolutionDiffDigest(map[string]any{}); ok || d != "" {
		t.Errorf("diff digest of an empty record: %q %v", d, ok)
	}
}

func TestG04Reapproval(t *testing.T) {
	k := newKey(t)
	diff := dg("g04-diff")
	rec := func(mut func(r map[string]any)) map[string]any {
		r := map[string]any{"v": jnum(1), "kind": reapprovalKind, "grant": "g1", "verb": "stripe.charge", "diff": diff}
		if mut != nil {
			mut(r)
		}
		r["sig"] = map[string]any{"alg": "ed25519", "value": signDomain(t, k, reapprovalDomain, withoutKeys(r, "sig"))}
		return r
	}
	if !reapprovalValid(rec(nil), "g1", k.id, "stripe.charge", diff) {
		t.Fatal("a valid re-approval")
	}
	for name, ok := range map[string]bool{
		"grant":  reapprovalValid(rec(nil), "g2", k.id, "stripe.charge", diff),
		"verb":   reapprovalValid(rec(nil), "g1", k.id, "stripe.refund", diff),
		"diff":   reapprovalValid(rec(nil), "g1", k.id, "stripe.charge", dg("g04-other")),
		"v":      reapprovalValid(rec(func(r map[string]any) { r["v"] = jnum(2) }), "g1", k.id, "stripe.charge", diff),
		"kind":   reapprovalValid(rec(func(r map[string]any) { r["kind"] = "x" }), "g1", k.id, "stripe.charge", diff),
		"extra":  reapprovalValid(rec(func(r map[string]any) { r["x"] = "y" }), "g1", k.id, "stripe.charge", diff),
		"issuer": reapprovalValid(rec(nil), "g1", jnum(5), "stripe.charge", diff),
	} {
		if ok {
			t.Errorf("%s mismatch must refuse", name)
		}
	}
	// a body outside the strict profile has no message: even a signature over the empty message is refused
	e := json.Number("1e3")
	r := map[string]any{"v": jnum(1), "kind": reapprovalKind, "grant": e, "verb": "stripe.charge", "diff": diff,
		"sig": map[string]any{"alg": "ed25519", "value": b64.EncodeToString(ed25519.Sign(k.priv, nil))}}
	if reapprovalValid(r, e, k.id, "stripe.charge", diff) {
		t.Error("an unserialisable re-approval must refuse")
	}
}

func TestG04DecidePinChains(t *testing.T) {
	k := newKey(t)
	p0, pa, pb, p3, rt := dg("g04p0"), dg("g04pa"), dg("g04pb"), dg("g04p3"), g04Sha('R')
	evo := func(from, to, class string) map[string]any {
		return g04Evo(t, k, "stripe", "stripe.charge", from, to, class)
	}
	pin := func(recs ...any) map[string]any {
		return decidePin(map[string]any{
			"pin":     map[string]any{"pack": map[string]any{"ns": "stripe", "root": rt}, "defs": map[string]any{"stripe.charge": p0}, "on_new_action": "deny"},
			"verb":    "stripe.charge",
			"doc":     map[string]any{"verbs": []any{map[string]any{"verb": "stripe.charge", "def": p3}}, "pack": map[string]any{"ns": "stripe", "root": rt}},
			"records": recs, "keys": g04RegKeys(k),
		})
	}
	diffOf := func(r map[string]any) string {
		d, ok := evolutionDiffDigest(r)
		if !ok {
			t.Fatal("diff")
		}
		return d
	}
	if got := pin(evo(p0, p3, "equal")); got["ok"] != true || got["via"] != "chain" {
		t.Fatalf("equal chain: %v", got)
	}
	// a widening step with no re-approvals and no grant: def_changed naming the step to re-approve (not a grant error)
	w := evo(p0, p3, "widen")
	if got := pin(w); got["ok"] != false || got["code"] != "def_changed" || got["escalate"] != false || got["needs_reapproval"] != diffOf(w) {
		t.Fatalf("widen: %v", got)
	}
	// two blocked routes to the same definition: the FIRST route found names the step (a node is reached once)
	a, b := evo(p0, pa, "widen"), evo(p0, pb, "widen")
	if got := pin(a, b, evo(pa, p3, "equal"), evo(pb, p3, "equal")); got["code"] != "def_changed" || got["needs_reapproval"] != diffOf(a) {
		t.Fatalf("diamond: %v (a %s b %s)", got, diffOf(a), diffOf(b))
	}
}
