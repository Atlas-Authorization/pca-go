package pca

import "testing"

func goCBGRec(t *testing.T, auth *KeyPair, id, holder string, mut func(m map[string]any)) map[string]any {
	t.Helper()
	rec := g03bgRecord()
	rec["id"], rec["holder"], rec["authority"] = id, holder, auth.Public
	if mut != nil {
		mut(rec)
	}
	g03bgSign(t, auth, breakGlassDomain, rec, breakGlassBodyKeys)
	return rec
}

func goCBGRev(t *testing.T, k *KeyPair, id, notes string, at int) map[string]any {
	t.Helper()
	rv := g03bgReview()
	rv["id"], rv["reviewer"], rv["notes_digest"], rv["at"] = id, k.Public, notes, at
	g03bgSign(t, k, breakGlassReviewDomain, rv, breakGlassReviewKeys)
	return rv
}

func TestGoCBreakGlassDecisionsDoNotWrite(t *testing.T) {
	auth, _ := NewKeyPair()
	rev, _ := NewKeyPair()
	kv := goCNewKV()
	reg := NewBreakGlassRegistry(BreakGlassPolicy{Authorities: []string{auth.Public}, Reviewers: []string{rev.Public, auth.Public}}, kv)
	w := func(h string) int { return kv.writes[bgKey(h)] }

	rec := goCBGRec(t, auth, "g1", "h", nil)
	if r := reg.Accept(rec, 1000); !r.Ok || !r.Replaced || w("h") != 1 {
		t.Fatalf("accept: %+v", r)
	}
	// idempotent resend
	if r := reg.Accept(rec, 1000); !r.Ok || r.Replaced || w("h") != 1 {
		t.Errorf("resend: %+v writes=%d", r, w("h"))
	}
	// same id, other content
	if r := reg.Accept(goCBGRec(t, auth, "g1", "h", func(m map[string]any) { m["reason_digest"] = "other" }), 1000); r.Ok || r.Code != "id_conflict" || w("h") != 1 {
		t.Errorf("conflict: %+v writes=%d", r, w("h"))
	}
	// use refusals before any use
	for _, c := range []struct {
		name, id string
		now      int
		notified bool
		code     string
	}{
		{"unknown", "zz", 2000, true, "unknown_break_glass"},
		{"not yet valid", "g1", 999, true, "not_yet_valid"},
		{"expired", "g1", 5000, true, "expired"},
		{"not notified", "g1", 1500, false, "not_notified"},
	} {
		if d := reg.Use(c.id, "h", "d", c.now, c.notified); d.Decision != "deny" || d.Code != c.code || d.ID != c.id || w("h") != 1 {
			t.Errorf("%s: %+v writes=%d", c.name, d, w("h"))
		}
	}
	// the window is [issued_at, expires_at)
	if d := reg.Use("g1", "h", "d", 1000, true); d.Decision != "allow" || d.Use != 1 || d.Remaining != 1 || d.ReviewDue != 101000 || w("h") != 2 {
		t.Errorf("first use: %+v", d)
	}
	if d := reg.Use("g1", "h", "d2", 1100, true); d.Decision != "allow" || d.Use != 2 || d.Remaining != 0 || d.ReviewDue != 101000 || w("h") != 3 {
		t.Errorf("second use: %+v", d)
	}
	if d := reg.Use("g1", "h", "d3", 1200, true); d.Decision != "deny" || d.Code != "budget_exhausted" || w("h") != 3 {
		t.Errorf("exhausted: %+v writes=%d", d, w("h"))
	}
	// review refusals
	if r := reg.Review(goCBGRev(t, rev, "zz", "n", 1500), "h", 2000); r.Ok || r.Code != "unknown_break_glass" || w("h") != 3 {
		t.Errorf("review unknown: %+v", r)
	}
	if r := reg.Review(goCBGRev(t, auth, "g1", "n", 1500), "h", 2000); r.Ok || r.Code != "sod" || w("h") != 3 {
		t.Errorf("review sod: %+v", r)
	}
	if r := reg.Review(goCBGRev(t, rev, "g1", "n", 999), "h", 2000); r.Ok || r.Code != "bad_time" || w("h") != 3 {
		t.Errorf("review before first use: %+v", r)
	}
	if r := reg.Review(goCBGRev(t, rev, "g1", "n", 2001), "h", 2000); r.Ok || r.Code != "bad_time" || w("h") != 3 {
		t.Errorf("review after now: %+v", r)
	}
	// a holder frozen by an overdue review takes no new grant
	if r := reg.Accept(goCBGRec(t, auth, "g2", "h", nil), 101000); r.Ok || r.Code != "holder_frozen" || w("h") != 3 {
		t.Errorf("frozen accept: %+v writes=%d", r, w("h"))
	}
	good := goCBGRev(t, rev, "g1", "n", 1000)
	if r := reg.Review(good, "h", 2000); !r.Ok || !r.Replaced || w("h") != 4 {
		t.Fatalf("review: %+v", r)
	}
	if r := reg.Review(good, "h", 2000); !r.Ok || r.Replaced || w("h") != 4 {
		t.Errorf("review resend: %+v writes=%d", r, w("h"))
	}
	if r := reg.Review(goCBGRev(t, rev, "g1", "other", 1000), "h", 2000); r.Ok || r.Code != "already_reviewed" || w("h") != 4 {
		t.Errorf("second review: %+v writes=%d", r, w("h"))
	}
	// a grant with no use has nothing to review
	if r := reg.Accept(goCBGRec(t, auth, "g3", "h3", nil), 1000); !r.Ok {
		t.Fatalf("accept g3: %+v", r)
	}
	before := w("h3")
	if r := reg.Review(goCBGRev(t, rev, "g3", "n", 1500), "h3", 2000); r.Ok || r.Code != "nothing_to_review" || w("h3") != before {
		t.Errorf("nothing to review: %+v", r)
	}
}

func TestGoCBreakGlassStoreFaults(t *testing.T) {
	auth, _ := NewKeyPair()
	rev, _ := NewKeyPair()
	pol := BreakGlassPolicy{Authorities: []string{auth.Public}, Reviewers: []string{rev.Public}}
	rec := goCBGRec(t, auth, "g1", "h", nil)

	// the update is applied but not acknowledged: never an allow
	kv := goCNewKV()
	reg := NewBreakGlassRegistry(pol, kv)
	kv.errAfter = func(string) bool { return true }
	if r := reg.Accept(rec, 1000); r.Ok || r.Code != "store_unreachable" {
		t.Errorf("accept late fault: %+v", r)
	}
	kv.errAfter = nil
	if r := reg.Accept(rec, 1000); !r.Ok {
		t.Fatalf("accept: %+v", r)
	}
	kv.errAfter = func(string) bool { return true }
	if d := reg.Use("g1", "h", "d", 1500, true); d.Decision != "deny" || d.Code != "store_unreachable" || d.Use != 0 {
		t.Errorf("use late fault: %+v", d)
	}
	kv.errAfter = nil

	// a stored document that does not decode, or holds a grant without a record
	bad := goCNewKV()
	regBad := NewBreakGlassRegistry(pol, bad)
	for name, raw := range map[string]string{"garbage": "not json", "no record": `{"g1":{"rec":null,"uses":[]}}`} {
		_ = bad.inner.Update(bgKey("h"), func([]byte) []byte { return []byte(raw) })
		if r := regBad.Accept(rec, 1000); r.Ok || r.Code != "store_unreachable" {
			t.Errorf("%s accept: %+v", name, r)
		}
		if d := regBad.Use("g1", "h", "d", 1500, true); d.Decision != "deny" || d.Code != "store_unreachable" {
			t.Errorf("%s use: %+v", name, d)
		}
		if !regBad.Frozen("h", 1500) {
			t.Errorf("%s: a holder whose state cannot be read is frozen", name)
		}
	}

	// the working copy never outlives its document
	if d := reg.Use("g1", "h", "d", 1500, true); d.Decision != "allow" {
		t.Fatalf("use: %+v", d)
	}
	delete(kv.inner.m, bgKey("h"))
	if d := reg.Use("g1", "h", "d", 1600, true); d.Decision != "deny" || d.Code != "unknown_break_glass" {
		t.Errorf("document gone: %+v", d)
	}
	if reg.Frozen("h", 999999999) {
		t.Error("an absent document has nothing to freeze")
	}
}
