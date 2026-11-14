package pca

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// ---- ledger.go ----------------------------------------------------------------------------------------------------------

// A body the strict canonicalizer refuses is never verified, even against a genuine signature over the domain alone (the
// bytes a verifier that ignored the canonicalization error would check).
func TestR5N1_LedgerUncanonicalBodyIsRefusedUnderAGenuineDomainOnlySignature(t *testing.T) {
	w := g05Key(t, 0x61)
	edHead := map[string]any{"witness": w.Public, "principal": "\xed\xa0\x80", "size": g05N(1), "root": "r",
		"sig": b64.EncodeToString(w.Sign([]byte(ledgerHeadDomain)))}
	if VerifyWitnessedHead(edHead, w.Public) {
		t.Fatal("an uncanonicalizable body verified (ed25519)")
	}
	pq, err := GeneratePqKeyPair("ML-DSA-65")
	if err != nil {
		t.Fatal(err)
	}
	const alg = "hybrid-ed25519-ml-dsa-65"
	sig, pqSig, err := signWithSuite(&SuiteOpts{Alg: alg, Pq: pq}, w, []byte(ledgerHeadDomain))
	if err != nil {
		t.Fatal(err)
	}
	pqHead := copyMap(edHead)
	pqHead["alg"], pqHead["pq_pk"], pqHead["sig"], pqHead["pq_sig"] = alg, pq.Public, sig, pqSig
	if VerifyWitnessedHead(pqHead, w.Public, map[string]string{w.Public: pq.Public}) {
		t.Fatal("an uncanonicalizable body verified (hybrid)")
	}
}

// A member absent from the head is refused, not signed as null.
func TestR5N1_LedgerWitnessedHeadWithAnAbsentMemberIsRefused(t *testing.T) {
	w := g05Key(t, 0x62)
	signedNull := g05Sign(t, w, ledgerHeadDomain, map[string]any{"principal": "p", "size": g05N(1), "root": nil})
	head := map[string]any{"witness": w.Public, "principal": "p", "size": g05N(1), "sig": signedNull}
	if VerifyWitnessedHead(head, w.Public) {
		t.Fatal("a head without root verified against a signature over root: null")
	}
}

// A cosignature names the witness whose key verifies it.
func TestR5N1_LedgerCosignatureKeyMustBeTheWitness(t *testing.T) {
	w := g05Key(t, 0x63)
	sth := g05Sth()
	cs := g05Cosig(t, w, sth)
	if !VerifyWitnessCosignature(sth, cs, w.Public) {
		t.Fatal("genuine cosignature refused")
	}
	other := copyMap(cs)
	other["key"] = g05Key(t, 0x64).Public
	if VerifyWitnessCosignature(sth, other, w.Public) {
		t.Fatal("a cosignature naming another key verified under the witness key")
	}
}

// 1 -> 2: the old root must decode to 32 bytes. An empty old root would otherwise make the walk compute H(nothing, c).
func TestR5N1_LedgerConsistencyOldRootMustDecode(t *testing.T) {
	c := sha([]byte("c"))
	nr := b64.EncodeToString(nodeHash(nil, c))
	proof := map[string]any{"oldSize": g05N(1), "newSize": g05N(2), "path": []any{b64.EncodeToString(c)}}
	if VerifyLedgerConsistency("", nr, proof) {
		t.Fatal("an empty old root verified")
	}
}

// A non-string trusted witness key is not the key "": a pure post-quantum cosignature whose pin is keyed "" must not count.
func TestR5N1_LedgerNonStringWitnessKeyIsNotTrusted(t *testing.T) {
	pq, err := GeneratePqKeyPair("ML-DSA-65")
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"instance_id": "ins", "principal": "p", "size": g05N(3), "root": "r", "prev_root": "q", "guardian_epoch": 0,
		"alg": "ml-dsa-65", "pq_pk": pq.Public}
	cb, err := canonBytes(body)
	if err != nil {
		t.Fatal(err)
	}
	sig, _, err := signWithSuite(&SuiteOpts{Alg: "ml-dsa-65", Pq: pq}, nil, append([]byte(sthWitnessDomain), cb...))
	if err != nil {
		t.Fatal(err)
	}
	cosig := map[string]any{"key": "", "alg": "ml-dsa-65", "pq_pk": pq.Public, "sig": sig}
	sth := g05Sth()
	sth["witnesses"] = []any{cosig}
	if !VerifyWitnessCosignature(sth, cosig, "", map[string]string{"": pq.Public}) {
		t.Fatal("the control cosignature must verify under the key \"\" and its pin")
	}
	policy := map[string]any{"threshold": g05N(1), "witnessKeys": []any{g05N(5)}}
	if VerifyWitnessCosignatures(sth, policy, map[string]string{"": pq.Public}) {
		t.Fatal("a non-string witnessKeys entry made the key \"\" trusted")
	}
}

// ---- stepup.go ----------------------------------------------------------------------------------------------------------

type r5n1CloseBody struct {
	io.Reader
	closed *bool
}

func (b r5n1CloseBody) Close() error { *b.closed = true; return nil }

func TestR5N1_StepUpErrorsReturnNoValue(t *testing.T) {
	boom := errors.New("boom")
	if pub, err := NewPrincipalDeviceKey(&g13suStore{saveErr: boom}).Generate(); pub != "" || !IsStepUpKind(err, StepUpTransport) {
		t.Errorf("Generate with a failing store: %q %v", pub, err)
	}
	if pub, err := NewPrincipalDeviceKey(&g13suStore{}).ImportSecret("AAAA"); pub != "" || !IsStepUpKind(err, StepUpInvalidSecret) {
		t.Errorf("ImportSecret with a short secret: %q %v", pub, err)
	}
	if pub, err := NewPrincipalDeviceKey(&g13suStore{saveErr: boom}).ImportSecret(b64.EncodeToString(make([]byte, 32))); pub != "" || !IsStepUpKind(err, StepUpTransport) {
		t.Errorf("ImportSecret with a failing store: %q %v", pub, err)
	}
	failing := func() *PrincipalDeviceKey {
		return NewPrincipalDeviceKey(&g13suStore{val: make([]byte, 32), failOn: map[int]bool{1: true}})
	}
	if pub, err := failing().PublicKey(); pub != "" || !IsStepUpKind(err, StepUpTransport) {
		t.Errorf("PublicKey with a failing store: %q %v", pub, err)
	}
	if sig, err := failing().Sign([]byte("m")); sig != "" || !IsStepUpKind(err, StepUpTransport) {
		t.Errorf("Sign with a failing store: %q %v", sig, err)
	}
	if sec, err := failing().ExportSecret(); sec != "" || !IsStepUpKind(err, StepUpTransport) {
		t.Errorf("ExportSecret with a failing store: %q %v", sec, err)
	}
	empty := NewPrincipalDeviceKey(&g13suStore{})
	if pub, err := empty.PublicKey(); pub != "" || !IsStepUpKind(err, StepUpNoDeviceKey) {
		t.Errorf("PublicKey with no key: %q %v", pub, err)
	}
	if sig, err := empty.Sign([]byte("m")); sig != "" || !IsStepUpKind(err, StepUpNoDeviceKey) {
		t.Errorf("Sign with no key: %q %v", sig, err)
	}
}

func TestR5N1_StepUpClient(t *testing.T) {
	ctx := context.Background()
	// the dashboard token error returns no token
	c := g13suClient(t, nil, func(*http.Request) (*http.Response, error) { return g13suResp(200, "{}"), nil }, errors.New("no token"))
	if tok, err := c.bearer(ctx); tok != "" || !IsStepUpKind(err, StepUpTransport) {
		t.Errorf("bearer: %q %v", tok, err)
	}
	// an expired entry is skipped, not the end of the list
	body := `{"stepups":[` + g13suEntry("su_old", "g", "AQ", isoMs(g13suNow)) + `,` + g13suEntry("su_new", "g", "AQ", isoMs(g13suNow+1)) + `]}`
	list := func(*http.Request) (*http.Response, error) { return g13suResp(200, body), nil }
	items, err := g13suClient(t, nil, list, nil).Pending(ctx)
	if err != nil || len(items) != 1 || items[0].ID != "su_new" {
		t.Errorf("an entry after an expired one: %+v %v", items, err)
	}
	// a refused denial is an error
	refuse := func(*http.Request) (*http.Response, error) {
		return g13suResp(500, `{"errors":[{"message":"boom"}]}`), nil
	}
	if err := g13suClient(t, nil, refuse, nil).Deny(ctx, PendingStepUp{ID: "su_1"}, ""); !IsStepUpKind(err, StepUpAPI) {
		t.Errorf("Deny on a 500: %v", err)
	}
	// the response body is closed
	closed := false
	track := func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: r5n1CloseBody{strings.NewReader("{}"), &closed}}, nil
	}
	if err := g13suClient(t, nil, track, nil).Deny(ctx, PendingStepUp{ID: "su_1"}, ""); err != nil {
		t.Fatal(err)
	}
	if !closed {
		t.Error("the response body was not closed")
	}
}

// ---- protect.go ---------------------------------------------------------------------------------------------------------

func TestR5N1_ProtectDoesNotIndexAGrantWithoutAnID(t *testing.T) {
	p := Protect(ProtectOptions{Grants: []map[string]any{{"x": 1}, {"id": "g1", "v": 1}}})
	if g, _ := p.Options.ResolveGrant(""); g != nil {
		t.Errorf("a grant without an id resolved under the empty id: %v", g)
	}
	if g, _ := p.Options.ResolveGrant("g1"); g == nil || g["v"] != 1 {
		t.Errorf("g1: %v", g)
	}
}

// ---- arg_provenance.go --------------------------------------------------------------------------------------------------

func TestR5N1_ProvenanceDigestOfNonJSONParams(t *testing.T) {
	d, err := ProvActionDigest(Operation{Verb: "v", Resource: "r", Params: map[string]any{"f": make(chan int)}})
	if d != "" || err == nil {
		t.Errorf("got %q, %v", d, err)
	}
}

func TestR5N1_ProvenanceSegmentText(t *testing.T) {
	rec, err := harnessRecorder()
	if err != nil {
		t.Fatal(err)
	}
	digestOf := func(text string) string {
		d, err := HashCanonical(text)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	// a value the lenient serializer refuses is recorded as its plain string form
	rc, err := rec.Tool("t", math.NaN())
	if err != nil || rc["content_digest"] != digestOf("NaN") {
		t.Errorf("NaN: %v %v", rc["content_digest"], err)
	}
	// anything else as its lenient canonical JSON, key order independent
	rc, err = rec.Tool("t", map[string]any{"b": "x", "a": "y"})
	if err != nil || rc["content_digest"] != digestOf(`{"a":"y","b":"x"}`) {
		t.Errorf("map: %v %v", rc["content_digest"], err)
	}
}

func TestR5N1_ProvenanceVerifyChain(t *testing.T) {
	rec, err := harnessRecorder()
	if err != nil {
		t.Fatal(err)
	}
	op := Operation{Verb: "pay", Resource: "inv/1", Params: map[string]any{"a": "b"}}
	opm := map[string]any{"verb": "pay", "resource": "inv/1", "params": map[string]any{"a": "b"}}
	pins := normalizeJSON([]any{harnessPins()[0].JSON()}).([]any)
	// principal, an earlier action, a tool result, the action presented: the action in the middle is skipped, the tool counts
	if _, err := rec.Principal("hello"); err != nil {
		t.Fatal(err)
	}
	if _, err := rec.ForAction(op); err != nil {
		t.Fatal(err)
	}
	if _, err := rec.Tool("search", "result"); err != nil {
		t.Fatal(err)
	}
	b, err := rec.ForAction(op)
	if err != nil {
		t.Fatal(err)
	}
	nb := normalizeJSON(b)
	ch, code, reason := provVerifyChain(nb, opm, pins)
	if code != "" || reason != "" || !ch.verified || ch.context != "tool" || !reflect.DeepEqual(ch.path, []string{"tool:search"}) {
		t.Errorf("verified chain: %+v %q %q", ch, code, reason)
	}
	// a mediator this verifier does not pin vouches for nothing
	ch, code, reason = provVerifyChain(nb, opm, []any{})
	if code != "" || reason != "" || ch.verified || ch.context != "agent" {
		t.Errorf("unpinned chain: %+v %q %q", ch, code, reason)
	}
	// no bundle at all
	ch, code, reason = provVerifyChain(nil, opm, pins)
	if code != "" || reason != "" || ch.verified || ch.context != "agent" || !reflect.DeepEqual(ch.path, []string{"unlabelled"}) {
		t.Errorf("no bundle: %+v %q %q", ch, code, reason)
	}
}

func TestR5N1_ProvenanceGate(t *testing.T) {
	_, c, s := firstFixtureStep(t)
	op := *fixOp(s["operation"].(map[string]any))
	p := s["pcactn"].(map[string]any)
	grant := c["grant"].(map[string]any)
	if st, why := argProvenanceGate(AuthorizeInput{Risk: InsecureCalmRisk, ArgProvenance: harnessProv()}, p, grant, op, false, false); st != "pass" || why != "" {
		t.Errorf("a principal-direct bundle: %q %q", st, why)
	}
	// a panic inside the gate is a refusal with this reason, not a panic of the caller
	boom := AuthorizeInput{Risk: InsecureCalmRisk, ArgProvenance: &ArgProvenanceOptions{Bundle: func(map[string]any, Operation) (any, error) { panic("boom") }}}
	var st, why string
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("the gate let a panic escape: %v", r)
			}
		}()
		st, why = argProvenanceGate(boom, p, grant, op, false, false)
	}()
	if st != "fail" || why != "evaluation error (fail closed)" {
		t.Errorf("panicking bundle source: %q %q", st, why)
	}
}

// ---- intent_acc.go ------------------------------------------------------------------------------------------------------

func TestR5N1_AccValueReasons(t *testing.T) {
	doc := killASchemaDoc()
	throwing := map[string]any{"verbs": []any{nil}}
	sum := map[string]any{"agg": "sum", "sel": map[string]any{"accumulates_into": "spend.usd_cents"}}
	sumVal := map[string]any{"agg": "sum", "val": "action.params.total", "sel": map[string]any{"verbs": []any{"air.book"}}}
	count := map[string]any{"agg": "count", "sel": map[string]any{"verbs": []any{"air.book"}}}
	dist := map[string]any{"agg": "distinct", "val": "action.params.offer_id", "sel": map[string]any{"verbs": []any{"air.book"}}}
	big := jnum(9007199254740991)
	for _, c := range []struct {
		name   string
		a      map[string]any
		verb   string
		params map[string]any
		schema any
		have   bool
		reason string
	}{
		{"count", count, "air.book", map[string]any{}, doc, true, ""},
		{"distinct", dist, "air.book", map[string]any{"offer_id": "OF-1"}, doc, true, ""},
		{"distinct-bad", dist, "air.book", map[string]any{"offer_id": true}, doc, true, "action.params.offer_id must be a string or a safe integer"},
		{"val-ok", sumVal, "air.book", map[string]any{"total": jnum(5)}, doc, true, ""},
		{"val-neg", sumVal, "air.book", map[string]any{"total": jnum(-1)}, doc, true, "action.params.total must be a non-negative safe integer"},
		{"no-schema", sum, "air.book", map[string]any{"total": jnum(5)}, doc, false, "no schema entry for 'air.book' to read accumulates_into"},
		{"throwing", sum, "air.book", map[string]any{"total": jnum(5)}, throwing, true, ""},
		{"unknown-verb", sum, "air.cancel", map[string]any{"total": jnum(5)}, doc, true, "no schema entry for 'air.cancel' to read accumulates_into"},
		{"no-params", sum, "air.noparams", map[string]any{"total": jnum(5)}, doc, true, ""},
		{"sum", sum, "air.book", map[string]any{"total": jnum(5), "fee": jnum(2)}, doc, true, ""},
		{"neg", sum, "air.book", map[string]any{"total": jnum(5), "fee": jnum(-2)}, doc, true, "action.params.fee must be a non-negative safe integer"},
		{"overflow", sum, "air.book", map[string]any{"total": big, "fee": big}, doc, true, "accumulated value exceeds 2^53-1"},
	} {
		if _, _, _, reason := accValueOfReason(c.a, c.verb, c.params, c.schema, c.have); reason != c.reason {
			t.Errorf("%s: reason %q, want %q", c.name, reason, c.reason)
		}
	}
}

// A key set that does not take the receipt (key not yet valid, key retired, another suite) does not end the search.
func TestR5N1_ReceiptAgainstHolderTriesTheNextKeySet(t *testing.T) {
	root, sk := newKey(t), newKey(t)
	holder := map[string]any{"kind": "sequenced", "uri": "https://atlas.example/seq", "root": root.id}
	def := receiptFreshness{maxReceiptAgeMs: defaultMaxReceiptAgeMs, maxKeySetAgeMs: defaultMaxKeySetAgeMs}
	r := killAReceipt(sk.id)
	r["issued_at"], r["expires_at"] = jnum(v2Now), jnum(v2Now+60_000)
	r = killASignReceipt(t, sk, r)
	set := func(e map[string]any) map[string]any { return killAKeySet(t, root, root.id, 1, v2Now-100, e) }
	good := set(keyEntry("s2", sk, 0, nil))
	notYet := set(keyEntry("s2", sk, v2Now+1, nil))
	retired := set(keyEntry("s2", sk, 0, i64(v2Now-1)))
	pqEntry := keyEntry("s2", sk, 0, nil)
	pqEntry["alg"] = "ml-dsa-65"
	otherSuite := set(pqEntry)
	now := float64(v2Now)
	if !verifyReceiptAgainstHolder(r, holder, []any{good}, now, def) {
		t.Fatal("the good key set refused")
	}
	for name, bad := range map[string]map[string]any{"not-yet": notYet, "retired": retired, "other-suite": otherSuite} {
		if verifyReceiptAgainstHolder(r, holder, []any{bad}, now, def) {
			t.Errorf("%s alone must not take the receipt", name)
		}
		if !verifyReceiptAgainstHolder(r, holder, []any{bad, good}, now, def) {
			t.Errorf("%s then the good key set: the search ended early", name)
		}
	}
}

// ---- intent_revocation.go -----------------------------------------------------------------------------------------------

func TestR5N1_RevocationEpochBindFailure(t *testing.T) {
	ep := map[string]any{"guardian": "g", "alg": "ml-dsa-65"} // a post-quantum suite names its key: pq_pk is absent
	if got := checkRevocationEpoch(ep, "g", 0, "scope", nil); got != "revocation epoch signature invalid" {
		t.Errorf("got %q", got)
	}
}

func TestR5N1_RevocationRootBindings(t *testing.T) {
	for _, size := range []float64{1.5, 9007199254740992, math.NaN(), math.Inf(1)} {
		if r, ok := bindRevRoot(size, emptyRevTree()); r != "" || ok {
			t.Errorf("bindRevRoot(%v): %q %v", size, r, ok)
		}
	}
	if r, ok := bindRevRoot(2, "\xed\xa0\x80"); r != "" || ok {
		t.Errorf("a tree outside the strict profile: %q %v", r, ok)
	}
	if r, ok := bindRevRoot(2, emptyRevTree()); r == "" || !ok {
		t.Errorf("control: %q %v", r, ok)
	}
	if r, ok := revsetRoot([]string{"\xed\xa0\x80"}); r != "" || ok {
		t.Errorf("a list the tree cannot be built for: %q %v", r, ok)
	}
}

func TestR5N1_RevocationEquivocation(t *testing.T) {
	a := map[string]any{"epoch": jnum(3), "root": "r1"}
	for _, c := range []struct {
		name string
		le   map[string]any
		want string
	}{
		{"same number, other root", map[string]any{"epoch": jnum(3), "root": "r2"}, "two different revocation sets under one epoch number (equivocation)"},
		{"same number, same root", map[string]any{"epoch": jnum(3), "root": "r1"}, ""},
		{"other number, other root", map[string]any{"epoch": jnum(2), "root": "r2"}, ""},
	} {
		if got := revEquivocation(a, c.le); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// ---- intent_history.go --------------------------------------------------------------------------------------------------

func TestR5N1_HistoryAccKeyOfMissingParam(t *testing.T) {
	a := map[string]any{"key": "action.params.k"}
	if k, ok := accKeyOf(a, map[string]any{}); k != "" || ok {
		t.Errorf("missing: %q %v", k, ok)
	}
	if k, ok := accKeyOf(a, map[string]any{"k": "v"}); k != `"v"` || !ok {
		t.Errorf("present: %q %v", k, ok)
	}
}

// An event the accumulator does not select leaves the walk going: a later selected event still counts.
func TestR5N1_HistoryPreStateSkipsUnselectedEvents(t *testing.T) {
	a := map[string]any{"agg": "count", "sel": map[string]any{"verbs": []any{"v"}}, "win": map[string]any{"kind": "task"}}
	hist := []any{g09iEv("other", 1, map[string]any{}), g09iEv("v", 2, map[string]any{}), g09iEv("other", 3, map[string]any{}), g09iEv("v", 4, map[string]any{})}
	pre, ok := accPreState(a, hist, map[string]any{}, jnum(10), nil, false)
	if !ok || !reflect.DeepEqual(pre, map[string]any{"count": jsNumber(2)}) {
		t.Errorf("got %v %v", pre, ok)
	}
}

// intent-history.ts monitorStep: a p-match while a deadline is pending keeps the nearer of the pending count and within.
func TestR5N1_HistoryRespondsWithinKeepsTheNearerDeadline(t *testing.T) {
	m := map[string]any{"id": "m", "kind": "responds_within", "within": jnum(3), "p": map[string]any{"verb": "a"}, "q": map[string]any{"verb": "b"}}
	e := map[string]any{"status": "committed", "verb": "a", "resource": "r", "params": map[string]any{}}
	if got := monitorStep(m, "pending:9", e); got != "pending:3" {
		t.Errorf("got %q, want pending:3", got)
	}
	if got := monitorStep(m, "pending:2", e); got != "pending:1" {
		t.Errorf("got %q, want pending:1", got)
	}
}

// A tracked last epoch that the new one extends does not end the check: ids revoked in the new epoch are still refused.
func TestR5N1_RevocationExtendedEpochStillRefusesRevokedIDs(t *testing.T) {
	f := newV2Fx(t)
	f.withRevocation(60)
	set := newRevSet(t, "pca-intent:session:aa", "pca-intent:session:zz")
	ev := deepM(t, f.evidence(f.revAuth, set, v2Now-1_000, v2Now+299_000))
	cur := deepM(t, f.evidence(f.revAuth, newRevSet(t, "pca-intent:session:aa"), v2Now-1_000, v2Now+299_000))
	got := checkSessionRevocation(ev, f.session, f.revAuth.id, []any{"x", "pca-intent:session:zz"}, jnum(v2Now), jnum(60_000), cur, true, nil)
	if got != "'pca-intent:session:zz' is revoked" {
		t.Errorf("got %q", got)
	}
}
