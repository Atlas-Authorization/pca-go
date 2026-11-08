package pca

// g03: break-glass record / review well-formedness at every length and range boundary, and the registry's input checks.

import (
	"strings"
	"testing"
)

func g03bgSign(t *testing.T, kp *KeyPair, domain string, m map[string]any, keys []string) {
	t.Helper()
	c, err := canonBytes(leasePick(m, keys))
	if err != nil {
		t.Fatal(err)
	}
	m["sig"] = b64.EncodeToString(kp.Sign(append([]byte(domain), c...)))
}

func g03bgRecord() map[string]any {
	return map[string]any{
		"v": 1, "id": "g1", "holder": "h", "grant_ref": "gr", "reason_digest": "rd", "max_uses": 2, "issued_at": 1000,
		"expires_at": 5000, "review_within": 100000, "notify_to": "n", "authority": "a",
	}
}

func g03bgReview() map[string]any {
	return map[string]any{"v": 1, "id": "g1", "outcome": "justified", "notes_digest": "nd", "at": 2000, "reviewer": "r"}
}

func TestG03BreakGlassRecordShape(t *testing.T) {
	if _, ok := bgWellFormed(g03bgRecord()); !ok {
		t.Fatal("baseline record refused")
	}
	type row struct {
		name string
		mut  func(m map[string]any)
		ok   bool
	}
	set := func(k string, v any) func(m map[string]any) { return func(m map[string]any) { m[k] = v } }
	rows := []row{
		{"v missing", func(m map[string]any) { delete(m, "v") }, false},
		{"v 2", set("v", 2), false},
		{"max_uses not an integer", set("max_uses", "2"), false},
		{"issued_at negative", set("issued_at", -1), false},
		{"max_uses 0", set("max_uses", 0), false},
		{"max_uses 1", set("max_uses", 1), true},
		{"max_uses 16", set("max_uses", 16), true},
		{"max_uses 17", set("max_uses", 17), false},
		{"expires_at == issued_at", set("expires_at", 1000), false},
		{"expires_at == issued_at+1", set("expires_at", 1001), true},
		{"window exactly 24 h", set("expires_at", 1000+86_400_000), true},
		{"window 24 h + 1 ms", set("expires_at", 1000+86_400_001), false},
		{"review_within 0", set("review_within", 0), false},
		{"review_within 1", set("review_within", 1), true},
		{"review_within 30 days", set("review_within", 30*86_400_000), true},
		{"review_within 30 days + 1 ms", set("review_within", 30*86_400_000+1), false},
	}
	for _, f := range []struct {
		k   string
		max int
	}{{"id", 128}, {"holder", 128}, {"grant_ref", 256}, {"reason_digest", 128}, {"notify_to", 256}, {"authority", 128}} {
		rows = append(rows,
			row{f.k + " at max", set(f.k, strings.Repeat("x", f.max)), true},
			row{f.k + " over max", set(f.k, strings.Repeat("x", f.max+1)), false},
			row{f.k + " empty", set(f.k, ""), false},
		)
	}
	for _, r := range rows {
		m := g03bgRecord()
		r.mut(m)
		if got, ok := bgWellFormed(m); ok != r.ok || (ok && got == nil) || (!ok && got != nil) {
			t.Errorf("%s: ok=%v, want %v", r.name, ok, r.ok)
		}
	}
	if got, ok := bgWellFormed("not an object"); ok || got != nil {
		t.Error("non-object record accepted")
	}
}

func TestG03BreakGlassReviewShape(t *testing.T) {
	if _, ok := bgReviewWellFormed(g03bgReview()); !ok {
		t.Fatal("baseline review refused")
	}
	type row struct {
		name string
		mut  func(m map[string]any)
		ok   bool
	}
	set := func(k string, v any) func(m map[string]any) { return func(m map[string]any) { m[k] = v } }
	rows := []row{
		{"v missing", func(m map[string]any) { delete(m, "v") }, false},
		{"v 2", set("v", 2), false},
		{"outcome other", set("outcome", "other"), false},
		{"outcome unjustified", set("outcome", "unjustified"), true},
		{"at not an integer", set("at", "2000"), false},
	}
	for _, k := range []string{"id", "notes_digest", "reviewer"} {
		rows = append(rows,
			row{k + " at 128", set(k, strings.Repeat("x", 128)), true},
			row{k + " at 129", set(k, strings.Repeat("x", 129)), false},
			row{k + " empty", set(k, ""), false},
		)
	}
	for _, r := range rows {
		m := g03bgReview()
		r.mut(m)
		if got, ok := bgReviewWellFormed(m); ok != r.ok || (ok && got == nil) || (!ok && got != nil) {
			t.Errorf("%s: ok=%v, want %v", r.name, ok, r.ok)
		}
	}
	if got, ok := bgReviewWellFormed(42); ok || got != nil {
		t.Error("non-object review accepted")
	}
}

func TestG03BreakGlassRegistryInputs(t *testing.T) {
	auth, _ := NewKeyPair()
	rev, _ := NewKeyPair()
	reg := NewBreakGlassRegistry(BreakGlassPolicy{Authorities: []string{auth.Public}, Reviewers: []string{rev.Public}})
	x128, x129 := strings.Repeat("x", 128), strings.Repeat("x", 129)

	// Use: each string input at 128 passes the input check (unknown grant), at 129 or empty it is bad_input
	for i, in := range [][3]string{{x128, "h", "d"}, {"g", x128, "d"}, {"g", "h", x128}} {
		if d := reg.Use(in[0], in[1], in[2], 0, true); d.Decision != "deny" || d.Code != "unknown_break_glass" || d.ID != in[0] {
			t.Errorf("use at 128 #%d: %+v", i, d)
		}
	}
	for i, in := range [][3]string{{x129, "h", "d"}, {"g", x129, "d"}, {"g", "h", x129}, {"", "h", "d"}, {"g", "", "d"}, {"g", "h", ""}} {
		if d := reg.Use(in[0], in[1], in[2], 0, true); d.Decision != "deny" || d.Code != "bad_input" || d.ID != "" {
			t.Errorf("use bad input #%d: %+v", i, d)
		}
	}
	if d := reg.Use("g", "h", "d", -1, true); d.Code != "bad_input" {
		t.Errorf("use negative now: %+v", d)
	}
	if d := reg.Use("g", "h", "d", 0, "yes"); d.Code != "bad_input" {
		t.Errorf("use non-bool notified: %+v", d)
	}

	// Frozen fails closed on bad input
	if reg.Frozen(x128, 0) {
		t.Error("frozen: a 128-unit holder with no grants is not frozen")
	}
	for i, c := range []struct {
		h   string
		now any
	}{{x129, 0}, {"", 0}, {"h", -1}, {"h", "0"}} {
		if !reg.Frozen(c.h, c.now) {
			t.Errorf("frozen bad input #%d not frozen", i)
		}
	}

	// a grant used once at t=2000, then reviewed at exactly its first use
	rec := g03bgRecord()
	rec["authority"] = auth.Public
	g03bgSign(t, auth, breakGlassDomain, rec, breakGlassBodyKeys)
	if r := reg.Accept(rec, 1000); !r.Ok || !r.Replaced {
		t.Fatalf("accept: %+v", r)
	}
	if d := reg.Use("g1", "h", "d", 2000, true); d.Decision != "allow" || d.Use != 1 || d.Remaining != 1 || d.ReviewDue != 102000 {
		t.Fatalf("use: %+v", d)
	}
	rv := g03bgReview()
	rv["reviewer"] = rev.Public
	g03bgSign(t, rev, breakGlassReviewDomain, rv, breakGlassReviewKeys)

	// Review: the holder argument at 128 passes the input check, at 129 / empty it is bad_record
	if r := reg.Review(rv, x128, 3000); r.Ok || r.Code != "unknown_break_glass" {
		t.Errorf("review holder at 128: %+v", r)
	}
	for _, h := range []string{x129, ""} {
		if r := reg.Review(rv, h, 3000); r.Ok || r.Code != "bad_record" {
			t.Errorf("review holder %d units: %+v", len(h), r)
		}
	}
	if r := reg.Review(rv, "h", -1); r.Ok || r.Code != "bad_record" {
		t.Errorf("review negative now: %+v", r)
	}
	if r := reg.Review(rv, "h", 3000); !r.Ok || !r.Replaced {
		t.Errorf("review at the first use instant: %+v", r)
	}
}

func TestG03BreakGlassUnjustifiedFreezes(t *testing.T) {
	auth, _ := NewKeyPair()
	rev, _ := NewKeyPair()
	reg := NewBreakGlassRegistry(BreakGlassPolicy{Authorities: []string{auth.Public}, Reviewers: []string{rev.Public}})
	rec := g03bgRecord()
	rec["authority"] = auth.Public
	g03bgSign(t, auth, breakGlassDomain, rec, breakGlassBodyKeys)
	reg.Accept(rec, 1000)
	reg.Use("g1", "h", "d", 2000, true)
	rv := g03bgReview()
	rv["reviewer"], rv["outcome"] = rev.Public, "unjustified"
	g03bgSign(t, rev, breakGlassReviewDomain, rv, breakGlassReviewKeys)
	if r := reg.Review(rv, "h", 2500); !r.Ok {
		t.Fatalf("review: %+v", r)
	}
	if d := reg.Use("g1", "h", "d", 3000, true); d.Decision != "deny" || d.Code != "holder_frozen" || d.ID != "g1" {
		t.Errorf("use after an unjustified review: %+v", d)
	}
}
