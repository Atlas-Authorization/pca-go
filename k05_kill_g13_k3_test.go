package pca

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

// Mutation kills for k3.go (policy bundles, decision log, list receipts / cursors, grant authority and management).

func g13k3Strs(n int, s string) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = s
	}
	return out
}

func TestG13K3NumAndCompareVersion(t *testing.T) {
	if got := jsStringToNumber(""); got != 0 {
		t.Fatalf("jsStringToNumber(\"\") = %v", got)
	}
	if got := jsStringToNumber(" 7 "); got != 7 {
		t.Fatalf("jsStringToNumber(\" 7 \") = %v", got)
	}
	if got := jsStringToNumber("x"); !math.IsNaN(got) {
		t.Fatalf("jsStringToNumber(x) = %v", got)
	}
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"2", "1", 1},
		{"1", "2", -1},
		{"1", "1", 0},
		{"1", "1.0", 0},
		{"1.0.1", "1", 1},
		{"1", "1.2", -1},
		{"1.2", "1", 1},
		{"5e-1", "0", 1},  // a difference in (0, 1) is still "greater"
		{"0", "5e-1", -1}, // and in (-1, 0) "smaller"
	} {
		if got := compareVersion(c.a, c.b); got != c.want {
			t.Fatalf("compareVersion(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestG13K3StrList(t *testing.T) {
	if k3StrList("x", 5, 5) {
		t.Fatal("a non-list passed")
	}
	if !k3StrList([]any{"a", "b"}, 2, 5) {
		t.Fatal("a list of exactly max was refused")
	}
	if k3StrList([]any{"a", "b", "c"}, 2, 5) {
		t.Fatal("a list over max passed")
	}
	if k3StrList([]any{""}, 5, 5) {
		t.Fatal("an empty element passed")
	}
}

func g13k3Bundle() map[string]any {
	return map[string]any{"v": jnum(1), "kind": "pca-policy-bundle", "revision": jnum(1), "issued_at": jnum(5),
		"grants": []any{"g"}, "template_digests": []any{"t"}, "min_verifier_version": "1.0"}
}

func TestG13K3BundleShape(t *testing.T) {
	set := func(k string, v any) map[string]any { b := g13k3Bundle(); b[k] = v; return b }
	del := func(k string) map[string]any { b := g13k3Bundle(); delete(b, k); return b }
	rev2 := func(prev any) map[string]any {
		b := set("revision", jnum(2))
		if prev != nil {
			b["prev"] = prev
		}
		return b
	}
	const (
		notBundle = "not a policy bundle"
		badRev    = "bad revision or time"
		badPrev   = "prev must be absent at revision 1 and present after"
	)
	for _, c := range []struct {
		name string
		b    any
		want string
	}{
		{"valid", g13k3Bundle(), ""},
		{"non-object", "x", notBundle},
		{"v 2", set("v", jnum(2)), notBundle},
		{"v missing", del("v"), notBundle},
		{"kind wrong", set("kind", "x"), notBundle},
		{"revision 0", set("revision", jnum(0)), badRev},
		{"revision missing", del("revision"), badRev},
		{"issued_at missing", del("issued_at"), badRev},
		{"revision 1 with prev", set("prev", "p"), badPrev},
		{"revision 2 without prev", rev2(nil), badPrev},
		{"revision 2 prev 128", rev2(strings.Repeat("p", 128)), ""},
		{"revision 2 prev 129", rev2(strings.Repeat("p", 129)), badPrev},
		{"grants 4096", set("grants", g13k3Strs(4096, "g")), ""},
		{"grants 4097", set("grants", g13k3Strs(4097, "g")), "bad grants"},
		{"grant 128", set("grants", []any{strings.Repeat("g", 128)}), ""},
		{"grant 129", set("grants", []any{strings.Repeat("g", 129)}), "bad grants"},
		{"grants missing", del("grants"), "bad grants"},
		{"template_digests 4096", set("template_digests", g13k3Strs(4096, "t")), ""},
		{"template_digests 4097", set("template_digests", g13k3Strs(4097, "t")), "bad template_digests"},
		{"template digest 128", set("template_digests", []any{strings.Repeat("t", 128)}), ""},
		{"template digest 129", set("template_digests", []any{strings.Repeat("t", 129)}), "bad template_digests"},
		{"template_digests missing", del("template_digests"), "bad template_digests"},
		{"schema_digest 128", set("schema_digest", strings.Repeat("s", 128)), ""},
		{"schema_digest 129", set("schema_digest", strings.Repeat("s", 129)), "bad schema_digest"},
		{"min_verifier_version bad", set("min_verifier_version", "x"), "bad min_verifier_version"},
	} {
		if got := bundleShapeError(c.b); got != c.want {
			t.Fatalf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// g13k3SignBundle signs b's body (without sigs) with each key, then appends the extra (unsigned) entries.
func g13k3SignBundle(t *testing.T, b map[string]any, keys []fxKey, extra ...any) map[string]any {
	t.Helper()
	body := withoutKeys(b, "sigs")
	sigs := []any{}
	for _, k := range keys {
		sigs = append(sigs, map[string]any{"signer": k.id, "sig": signDomain(t, k, bundleDomain, body)})
	}
	b["sigs"] = append(sigs, extra...)
	return b
}

func TestG13K3VerifyBundle(t *testing.T) {
	k := newKey(t)
	opts := func(th int64) BundleVerifyOptions {
		return BundleVerifyOptions{Signers: []string{k.id}, Threshold: th, VerifierVersion: "1.0"}
	}
	valid := g13k3SignBundle(t, g13k3Bundle(), []fxKey{k})
	if v := VerifyBundle(valid, opts(1)); !v.OK || v.Revision != 1 || len(v.Signers) != 1 || v.Signers[0] != k.id {
		t.Fatalf("valid bundle: %+v", v)
	}
	if v := VerifyBundle(valid, opts(0)); v.OK || v.Code != "malformed" || v.Reason != "bad sigs or threshold" {
		t.Fatalf("threshold 0: %+v", v)
	}
	notArr := g13k3Bundle()
	notArr["sigs"] = "x"
	if v := VerifyBundle(notArr, opts(1)); v.Code != "malformed" || v.Reason != "bad sigs or threshold" {
		t.Fatalf("sigs not an array: %+v", v)
	}
	nils := func(n int) []any { return make([]any, n) }
	if v := VerifyBundle(g13k3SignBundle(t, g13k3Bundle(), []fxKey{k}, nils(63)...), opts(1)); !v.OK {
		t.Fatalf("64 sigs: %+v", v)
	}
	if v := VerifyBundle(g13k3SignBundle(t, g13k3Bundle(), []fxKey{k}, nils(64)...), opts(1)); v.Code != "malformed" || v.Reason != "bad sigs or threshold" {
		t.Fatalf("65 sigs: %+v", v)
	}
	if v := VerifyBundle(valid, opts(10)); v.Code != "below_threshold" || v.Reason != "1 valid pinned signature(s), need 10" {
		t.Fatalf("below threshold: %+v", v)
	}
	b2 := g13k3Bundle()
	b2["revision"], b2["prev"] = jnum(2), "p"
	o := opts(1)
	o.Last = &BundleLast{Revision: 10, Digest: "d"}
	if v := VerifyBundle(g13k3SignBundle(t, b2, []fxKey{k}), o); v.Code != "rollback" || v.Reason != "revision 2 < accepted 10" {
		t.Fatalf("rollback: %+v", v)
	}
}

func g13k3Head(t *testing.T, k fxKey, mut func(map[string]any)) map[string]any {
	t.Helper()
	h := map[string]any{"v": jnum(1), "signer": k.id, "size": jnum(1), "issued_at": jnum(5), "root": "r", "last_commit": "c"}
	if mut != nil {
		mut(h)
	}
	return signArt(t, k, logHeadDomain, h)
}

func TestG13K3VerifyLogHead(t *testing.T) {
	k, other := newKey(t), newKey(t)
	set := func(key string, v any) func(map[string]any) { return func(m map[string]any) { m[key] = v } }
	del := func(key string) func(map[string]any) { return func(m map[string]any) { delete(m, key) } }
	if !VerifyLogHead(g13k3Head(t, k, nil), k.id) {
		t.Fatal("valid head refused")
	}
	if VerifyLogHead("x", k.id) {
		t.Fatal("non-object head accepted")
	}
	for name, mut := range map[string]func(map[string]any){
		"v 2": set("v", jnum(2)), "v missing": del("v"), "signer field names another key": set("signer", other.id),
		"signer missing": del("signer"), "size not an int": set("size", "x"), "issued_at not an int": set("issued_at", "x"),
		"root missing": del("root"), "last_commit missing": del("last_commit"),
	} {
		if VerifyLogHead(g13k3Head(t, k, mut), k.id) {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func g13k3Commit(t *testing.T, r map[string]any) string {
	t.Helper()
	c, ok := RecordCommit(r)
	if !ok {
		t.Fatal("record commit")
	}
	return c
}

func TestG13K3VerifyDecisionBatch(t *testing.T) {
	k := newKey(t)
	r0 := map[string]any{"seq": jnum(0), "prev": ""}
	c0 := g13k3Commit(t, r0)
	r1 := map[string]any{"seq": jnum(1), "prev": c0}
	c1 := g13k3Commit(t, r1)
	head := func(size int64, last string) map[string]any {
		return g13k3Head(t, k, func(m map[string]any) { m["size"], m["last_commit"] = jnum(size), last })
	}
	batch := func(from int64, h map[string]any, recs any) map[string]any {
		return map[string]any{"from": jnum(from), "head": h, "records": recs}
	}
	if v := VerifyDecisionBatch(batch(0, head(2, c1), []any{r0, r1}), 0, "", k.id); !v.OK || v.Next != 2 || v.LastCommit != c1 {
		t.Fatalf("valid batch: %+v", v)
	}
	if v := VerifyDecisionBatch(batch(0, head(3, "zz"), []any{r0, r1}), 0, "", k.id); !v.OK || v.Next != 2 {
		t.Fatalf("batch short of the head: %+v", v)
	}
	for _, c := range []struct {
		name string
		b    any
		next int64
		want string
	}{
		{"non-object", "x", 0, "malformed batch"},
		{"gap", batch(3, head(2, c1), []any{r0, r1}), 10, "gap or replay: batch starts at 3, expected 10"},
		{"records not an array", batch(0, head(2, c1), "x"), 0, "malformed batch"},
		{"record not an object", batch(0, head(2, c1), []any{"x"}), 0, "malformed batch"},
		{"seq wrong", batch(0, head(2, c1), []any{map[string]any{"seq": jnum(5), "prev": ""}}), 0, "chain broken at seq 5"},
		{"prev missing", batch(0, head(2, c1), []any{map[string]any{"seq": jnum(0)}}), 0, "chain broken at seq 0"},
		{"record not canonicalizable", batch(0, head(2, c1), []any{map[string]any{"seq": jnum(0), "prev": "", "x": float64(1)}}), 0, "malformed batch"},
		{"longer than the head", batch(0, head(1, c0), []any{r0, r1}), 0, "batch is longer than the signed head"},
		{"end mismatch", batch(0, head(2, "zz"), []any{r0, r1}), 0, "batch end does not match the signed head"},
	} {
		if v := VerifyDecisionBatch(c.b, c.next, "", k.id); v.OK || v.Reason != c.want {
			t.Fatalf("%s: %+v, want %q", c.name, v, c.want)
		}
	}
}

func TestG13K3VerifyListReceipt(t *testing.T) {
	k, other := newKey(t), newKey(t)
	objs := []string{"a", "b"}
	d, _ := ObjectsDigest(objs)
	rec := func(mut func(map[string]any)) map[string]any {
		r := map[string]any{"v": jnum(1), "signer": k.id, "subject": "s", "resource_type": "doc", "count": jnum(2), "issued_at": jnum(5), "objects_digest": d}
		if mut != nil {
			mut(r)
		}
		return signArt(t, k, listReceiptDomain, r)
	}
	set := func(key string, v any) func(map[string]any) { return func(m map[string]any) { m[key] = v } }
	del := func(key string) func(map[string]any) { return func(m map[string]any) { delete(m, key) } }
	if !VerifyListReceipt(rec(nil), k.id, objs) || !VerifyListReceipt(rec(nil), k.id, nil) {
		t.Fatal("valid receipt refused")
	}
	if VerifyListReceipt("x", k.id, nil) {
		t.Fatal("non-object accepted")
	}
	for _, c := range []struct {
		name string
		mut  func(map[string]any)
		want bool
	}{
		{"v 2", set("v", jnum(2)), false},
		{"v missing", del("v"), false},
		{"signer missing", del("signer"), false},
		{"signer field names another key", set("signer", other.id), false},
		{"subject empty", set("subject", ""), false},
		{"subject 512", set("subject", strings.Repeat("s", 512)), true},
		{"subject 513", set("subject", strings.Repeat("s", 513)), false},
		{"resource_type 512", set("resource_type", strings.Repeat("r", 512)), true},
		{"resource_type 513", set("resource_type", strings.Repeat("r", 513)), false},
		{"count not an int", set("count", "x"), false},
		{"issued_at negative", set("issued_at", jnum(-1)), false},
	} {
		if got := VerifyListReceipt(rec(c.mut), k.id, nil); got != c.want {
			t.Fatalf("%s: got %v", c.name, got)
		}
	}
}

func TestG13K3VerifyListCursor(t *testing.T) {
	k, other := newKey(t), newKey(t)
	in := ListBindInputs{Subject: "s", ResourceType: "doc", FilterID: "f", PolicyDigest: "p", Limit: 10}
	bind, ok := ListBind(in)
	if !ok {
		t.Fatal("bind")
	}
	payload := func(mut func(map[string]any)) (map[string]any, string) {
		c := map[string]any{"v": jnum(1), "bind": bind, "skip": jnum(3), "signer": k.id, "inner": "i"}
		if mut != nil {
			mut(c)
		}
		b, err := canonBytes(c)
		if err != nil {
			t.Fatal(err)
		}
		return c, b64.EncodeToString(b)
	}
	tok := func(mut func(map[string]any)) string {
		c, p := payload(mut)
		return p + "." + signDomain(t, k, listCursorDomain, c)
	}
	set := func(key string, v any) func(map[string]any) { return func(m map[string]any) { m[key] = v } }
	del := func(key string) func(map[string]any) { return func(m map[string]any) { delete(m, key) } }

	if v := VerifyListCursor(tok(nil), k.id, &in); !v.OK || v.Inner != "i" || !v.HasInner || v.Skip != 3 {
		t.Fatalf("valid cursor: %+v", v)
	}
	if v := VerifyListCursor(tok(del("inner")), k.id, &in); !v.OK || v.HasInner || v.Inner != "" || v.Skip != 3 {
		t.Fatalf("valid cursor without inner: %+v", v)
	}
	_, bare := payload(nil)
	for _, c := range []struct {
		name string
		tok  any
		want string
	}{
		{"non-string", 5, "malformed"},
		{"no dot", bare, "malformed"},
		{"empty signature part", bare + ".", "malformed"},
		{"empty payload part", ".x", "malformed"},
		{"three parts", bare + ".x.y", "malformed"},
		{"bad base64url", "!!.x", "malformed"},
		{"payload not an object", b64.EncodeToString([]byte("[1]")) + ".x", "malformed"},
		{"v 2", tok(set("v", jnum(2))), "malformed"},
		{"bind missing", tok(del("bind")), "malformed"},
		{"skip negative", tok(set("skip", jnum(-1))), "malformed"},
		{"inner not a string", tok(set("inner", jnum(5))), "malformed"},
		{"signer field missing", tok(del("signer")), "signature"},
		{"signer field names another key", tok(set("signer", other.id)), "signature"},
		{"bad signature", bare + "." + b64.EncodeToString(make([]byte, 64)), "signature"},
		{"bind differs", tok(set("bind", "zz")), "bind"},
	} {
		if v := VerifyListCursor(c.tok, k.id, &in); v.OK || v.Reason != c.want {
			t.Fatalf("%s: %+v, want %q", c.name, v, c.want)
		}
	}
}

func g13k3Auth(verbs, res []any) map[string]any {
	return map[string]any{"verbs": verbs, "resources": res}
}

func TestG13K3Strings(t *testing.T) {
	if _, ok := k3Strings([]any{""}, 5, 5); ok {
		t.Fatal("empty element accepted")
	}
	if _, ok := k3Strings([]any{"abcdef"}, 5, 5); ok {
		t.Fatal("over-long element accepted")
	}
	if got, ok := k3Strings([]any{"a", "b"}, 2, 5); !ok || len(got) != 2 || got[1] != "b" {
		t.Fatalf("list of exactly max: %v %v", got, ok)
	}
	if _, ok := k3Strings([]any{"a", "b", "c"}, 2, 5); ok {
		t.Fatal("list over max accepted")
	}
}

func TestG13K3ParseAuthority(t *testing.T) {
	base := func() map[string]any { return g13k3Auth([]any{"read"}, []any{"r/1"}) }
	with := func(k string, v any) map[string]any { a := base(); a[k] = v; return a }
	lim := func(v any) map[string]any { return with("limits", map[string]any{"amt": v}) }
	if a, ok := parseAuthority(base()); !ok || a.hasExp || !math.IsInf(a.exp, 1) || a.limits != nil {
		t.Fatalf("base: %+v %v", a, ok)
	}
	if a, ok := parseAuthority(with("expires_at", jnum(5))); !ok || !a.hasExp || a.exp != 5 {
		t.Fatalf("expires_at 5: %+v %v", a, ok)
	}
	if a, ok := parseAuthority(lim(jnum(0))); !ok || a.limits["amt"] != 0 {
		t.Fatalf("limit 0: %+v %v", a, ok)
	}
	if a, ok := parseAuthority(lim(json.Number("0.5"))); !ok || a.limits["amt"] != 0.5 {
		t.Fatalf("limit 0.5: %+v %v", a, ok)
	}
	for _, c := range []struct {
		name string
		a    any
		want bool
	}{
		{"non-object", "x", false},
		{"verbs 256", g13k3Auth(g13k3Strs(256, "v"), []any{"r"}), true},
		{"verbs 257", g13k3Auth(g13k3Strs(257, "v"), []any{"r"}), false},
		{"verb 128", g13k3Auth([]any{strings.Repeat("v", 128)}, []any{"r"}), true},
		{"verb 129", g13k3Auth([]any{strings.Repeat("v", 129)}, []any{"r"}), false},
		{"resources missing", map[string]any{"verbs": []any{"v"}}, false},
		{"resources 1024", g13k3Auth([]any{"v"}, g13k3Strs(1024, "r")), true},
		{"resources 1025", g13k3Auth([]any{"v"}, g13k3Strs(1025, "r")), false},
		{"resource 512", g13k3Auth([]any{"v"}, []any{strings.Repeat("r", 512)}), true},
		{"resource 513", g13k3Auth([]any{"v"}, []any{strings.Repeat("r", 513)}), false},
		{"limits not an object", with("limits", "x"), false},
		{"limit not a number", lim("x"), false},
		{"limit +Inf", lim(math.Inf(1)), false},
		{"limit NaN", lim(math.NaN()), false},
		{"limit -1", lim(jnum(-1)), false},
		{"expires_at not an int", with("expires_at", "x"), false},
		{"expires_at negative", with("expires_at", jnum(-1)), false},
	} {
		if _, ok := parseAuthority(c.a); ok != c.want {
			t.Fatalf("%s: ok=%v", c.name, ok)
		}
	}
}

func TestG13K3Covers(t *testing.T) {
	for _, c := range []struct {
		p, r string
		want bool
	}{
		{"abc", "abd", false},
		{"a", "a", true},
		{"ab*", "ac", false},
		{"ab*", "abx", true},
		{"*", "x", true},
	} {
		if got := k3Covers(c.p, c.r); got != c.want {
			t.Fatalf("k3Covers(%q, %q) = %v", c.p, c.r, got)
		}
	}
}

func TestG13K3CompareAndDigest(t *testing.T) {
	good := g13k3Auth([]any{"read"}, []any{"r/1"})
	if o, ok := CompareAuthority("x", good); ok || o != "" {
		t.Fatalf("bad old: %q %v", o, ok)
	}
	if o, ok := CompareAuthority(good, "x"); ok || o != "" {
		t.Fatalf("bad new: %q %v", o, ok)
	}
	if o, ok := CompareAuthority(good, good); !ok || o != "equal" {
		t.Fatalf("equal: %q %v", o, ok)
	}
	if d, ok := BundleDigest("x"); ok || d != "" {
		t.Fatal("bundle digest of a non-object")
	}
	if _, ok := AuthorityDigest("x"); ok {
		t.Fatal("digest of a non-object")
	}
	if _, ok := AuthorityDigest(map[string]any{"resources": []any{"r"}}); ok {
		t.Fatal("digest without verbs")
	}
	if _, ok := AuthorityDigest(map[string]any{"verbs": []any{"v"}}); ok {
		t.Fatal("digest without resources")
	}
	if _, ok := AuthorityDigest(good); !ok {
		t.Fatal("digest of a valid authority")
	}
}

func TestG13K3Merge(t *testing.T) {
	parse := func(a map[string]any) *k3Authority {
		x, ok := parseAuthority(a)
		if !ok {
			t.Fatalf("parse %v", a)
		}
		return x
	}
	plain := parse(g13k3Auth([]any{"a"}, []any{"r"}))
	rich := g13k3Auth([]any{"b"}, []any{"s"})
	rich["limits"], rich["expires_at"] = map[string]any{"x": jnum(5)}, jnum(9)
	out := k3Merge(plain, parse(rich))
	if _, has := out["limits"]; has {
		t.Fatalf("limits appeared from the delta alone: %v", out)
	}
	if _, has := out["expires_at"]; has {
		t.Fatalf("expires_at appeared from the delta alone: %v", out)
	}
	exp := g13k3Auth([]any{"a"}, []any{"r"})
	exp["expires_at"] = jnum(5)
	out = k3Merge(parse(exp), plain)
	if out["expires_at"] != json.Number("5") {
		t.Fatalf("an omitted delta expiry changed the kept one: %v", out["expires_at"])
	}
}

func TestG13K3VerifyAmendment(t *testing.T) {
	p, a := newKey(t), newKey(t)
	cur := func(auth any) map[string]any {
		return map[string]any{"id": "g1", "rev": jnum(1), "principal": p.id, "agent": a.id, "status": "active", "authority": auth}
	}
	full := g13k3Auth([]any{"read", "write"}, []any{"r/*"})
	narrow := g13k3Auth([]any{"read"}, []any{"r/*"})
	req := func(action string, auth map[string]any, by string, k fxKey) map[string]any {
		dd, ok := AuthorityDigest(auth)
		if !ok {
			t.Fatal("digest")
		}
		sig := signDomain(t, k, grantAmendDomain, map[string]any{"grant": "g1", "rev": jnum(1), "action": action, "authority": dd})
		return map[string]any{"action": action, "authority": auth, "signed_by": by, "sig": sig}
	}
	if v := VerifyAmendment(cur(full), req("narrow", narrow, "holder", a), false); !v.OK || v.Widens {
		t.Fatalf("valid narrowing: %+v", v)
	}
	if v := VerifyAmendment(cur("x"), req("narrow", narrow, "holder", a), false); v.Code != "bad_request" {
		t.Fatalf("bad current authority: %+v", v)
	}
	noSig := req("narrow", narrow, "holder", a)
	delete(noSig, "sig")
	if v := VerifyAmendment(cur(full), noSig, false); v.Code != "signature_required" {
		t.Fatalf("missing sig: %+v", v)
	}
	if v := VerifyAmendment(cur(full), req("narrow", narrow, "someone", a), false); v.Code != "signature_required" {
		t.Fatalf("unknown signed_by: %+v", v)
	}
	wide := g13k3Auth([]any{"read", "write", "admin"}, []any{"r/*"})
	if v := VerifyAmendment(cur(full), req("replace", wide, "holder", a), true); v.Code != "signature_required" {
		t.Fatalf("widening by the holder: %+v", v)
	}
	if v := VerifyAmendment(cur(full), req("replace", wide, "principal", p), true); !v.OK || !v.Widens {
		t.Fatalf("widening by the principal: %+v", v)
	}
}

func TestG13K3VerifyNeedApproval(t *testing.T) {
	p := newKey(t)
	grant := func(amt int64) map[string]any {
		auth := g13k3Auth([]any{"read"}, []any{"r/1"})
		auth["limits"] = map[string]any{"amt": jnum(amt)}
		return map[string]any{"principal": p.id, "rev": jnum(1), "authority": auth}
	}
	need := func(verb, res any, limits map[string]any, adjustable bool) map[string]any {
		n := map[string]any{"verb": verb, "resource": res, "limits": limits}
		if adjustable {
			n["adjustable"] = true
		}
		return n
	}
	run := func(g map[string]any, needs, approved []any) NeedVerdict {
		nr := map[string]any{"id": "n1", "grant_id": "g1", "status": "pending", "needs": needs}
		sig := signDomain(t, p, needApproveDomain, map[string]any{"need": "n1", "grant": "g1", "rev": jnum(1), "approved": approved})
		return VerifyNeedApproval(nr, g, approved, sig, true)
	}
	amt := func(v any) map[string]any { return map[string]any{"amt": v} }
	mergedAmt := func(v NeedVerdict) any {
		l, _ := v.Authority["limits"].(map[string]any)
		return l["amt"]
	}

	if v := VerifyNeedApproval("x", grant(1), []any{}, "s", true); v.Code != "bad_request" {
		t.Fatalf("need request not an object: %+v", v)
	}
	if v := VerifyNeedApproval(map[string]any{"status": "pending"}, "x", []any{}, "s", true); v.Code != "bad_request" {
		t.Fatalf("grant not an object: %+v", v)
	}

	// the largest approved amount per key wins, whatever the order
	n3, n5 := need("read", "r/1", amt(jnum(3)), false), need("read", "r/1", amt(jnum(5)), false)
	for _, order := range [][]any{{n3, n5}, {n5, n3}} {
		if v := run(grant(1), order, order); !v.OK || mergedAmt(v) != json.Number("5") {
			t.Fatalf("max of approved amounts: %+v", v)
		}
	}
	z := []any{need("read", "r/1", amt(jnum(0)), false)}
	if v := run(grant(0), z, z); !v.OK || mergedAmt(v) != json.Number("0") {
		t.Fatalf("approved 0 against a 0 ceiling: %+v", v)
	}
	eq := []any{need("read", "r/1", amt(jnum(4)), false)}
	if v := run(grant(1), eq, eq); !v.OK || mergedAmt(v) != json.Number("4") {
		t.Fatalf("approved == asked, not adjustable: %+v", v)
	}

	const lowered = "need_not_lowered_only"
	for _, c := range []struct {
		name   string
		needs  []any
		appr   []any
		reason string
	}{
		{"numeric verb on both", []any{need(jnum(5), "r/1", nil, false)}, []any{need(jnum(5), "r/1", nil, false)}, lowered},
		{"numeric resource on both", []any{need("read", jnum(5), nil, false)}, []any{need("read", jnum(5), nil, false)}, lowered},
		{"verb differs", []any{need("read", "r/1", nil, false)}, []any{need("write", "r/1", nil, false)}, lowered},
		{"resource differs", []any{need("read", "r/1", nil, false)}, []any{need("read", "r/2", nil, false)}, lowered},
		{"approved amount not a number", []any{need("read", "r/1", amt(jnum(5)), true)}, []any{need("read", "r/1", amt("x"), true)}, lowered},
		{"asked amount not a number", []any{need("read", "r/1", amt("x"), true)}, []any{need("read", "r/1", amt(jnum(0)), true)}, lowered},
		{"asked amount missing", []any{need("read", "r/1", map[string]any{}, true)}, []any{need("read", "r/1", amt(jnum(0)), true)}, lowered},
		{"raised", []any{need("read", "r/1", amt(jnum(5)), true)}, []any{need("read", "r/1", amt(jnum(6)), true)}, lowered},
		{"lowered, not adjustable", []any{need("read", "r/1", amt(jnum(5)), false)}, []any{need("read", "r/1", amt(jnum(4)), false)}, "need_not_adjustable"},
	} {
		if v := run(grant(1), c.needs, c.appr); v.OK || v.Code != c.reason {
			t.Fatalf("%s: %+v, want %s", c.name, v, c.reason)
		}
	}
}
