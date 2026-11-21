package pca

// k05 mutation kills (group g06): RequirePCA (middleware.go): the fresh_at side-carried read, the context accessor, the
// authorize denial writer, the request readers (escalation answer, provenance bundle, workflow step, presented K1), the
// construction panic, and the authorize handler's body handling and hook wiring. Self-contained.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func g06b64(s string) string { return b64.EncodeToString([]byte(s)) }

func g06req(hdr map[string]string, body []byte) *http.Request {
	req := httptest.NewRequest("POST", "/x", bytes.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return req
}

func TestK05G06MwFreshAtOption(t *testing.T) {
	req := g06req(map[string]string{"pca-fresh-at": "{}"}, nil)
	pol := func(fp *FreshAtPolicy) RequirePCAOptions {
		return RequirePCAOptions{Authorize: &AuthorizeOptions{Risk: InsecureCalmRisk, Plan: PlanSingleStep}, FreshAt: func(*http.Request, map[string]any) *FreshAtPolicy { return fp }}
	}
	if got := pol(nil).freshAt(req, map[string]any{}); got != nil {
		t.Fatalf("no policy: %+v", got)
	}
	fp := &FreshAtPolicy{Signer: "s"}
	if got := pol(fp).freshAt(req, map[string]any{"fresh_at": 1}); got != fp || got.HasSideCarried {
		t.Fatalf("a member: the header is not read: %+v", got)
	}
	side := &FreshAtPolicy{HasSideCarried: true}
	if got := pol(side).freshAt(req, map[string]any{}); got != side || got.SideCarried != nil {
		t.Fatalf("already side-carried: %+v", got)
	}
	got := pol(fp).freshAt(req, map[string]any{})
	if got == fp || !got.HasSideCarried || !reflect.DeepEqual(got.SideCarried, map[string]any{}) || fp.HasSideCarried {
		t.Fatalf("header read into a copy: %+v", got)
	}
}

func TestK05G06MwAuthorizationFromContext(t *testing.T) {
	bg := context.Background()
	for _, ctx := range []context.Context{bg, context.WithValue(bg, ctxKey{}, &contextValue{}), context.WithValue(bg, ctxKey{}, (*contextValue)(nil))} {
		if a, ok := AuthorizationFromContext(ctx); ok || a != nil {
			t.Fatalf("no authorization: %v %v", a, ok)
		}
	}
	res := &AuthorizeResult{Allow: true}
	if a, ok := AuthorizationFromContext(context.WithValue(bg, ctxKey{}, &contextValue{authz: res})); !ok || a != res {
		t.Fatalf("stashed authorization: %v %v", a, ok)
	}
}

func TestK05G06MwWriteAuthorizeError(t *testing.T) {
	w := httptest.NewRecorder()
	writeAuthorizeError(w, AuthorizeResult{Status: 403, Decision: "deny"}, "insufficient_authority")
	if w.Code != 403 || w.Header().Get("WWW-Authenticate") != `PCA realm="pca", error="insufficient_authority"` || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"error": "insufficient_authority", "error_description": "", "reason": "", "checks": nil, "decision": "deny"}
	if !reflect.DeepEqual(m, want) {
		t.Fatalf("no reason, escalation or missing: %v", m)
	}
}

func TestK05G06MwEscalationAnswer(t *testing.T) {
	five, _ := StrictParse("5")
	body := []byte(`{"escalation_answer":5}`)
	hdr := func(v string) map[string]string { return map[string]string{"PCA-Escalation-Answer": v} }
	if got := extractEscalationAnswer(g06req(hdr(g06b64(`{"a":"b"}`)), nil), body, true); !reflect.DeepEqual(got, map[string]any{"a": "b"}) {
		t.Fatalf("header wins: %v", got)
	}
	for _, h := range []string{"%%", g06b64("{")} {
		if got := extractEscalationAnswer(g06req(hdr(h), nil), body, true); got != nil {
			t.Fatalf("unreadable header %q: %v", h, got)
		}
	}
	if got := extractEscalationAnswer(g06req(nil, nil), body, true); !reflect.DeepEqual(got, five) {
		t.Fatalf("body member: %v", got)
	}
	if got := extractEscalationAnswer(g06req(nil, nil), body, false); got != nil {
		t.Fatalf("oversized body: %v", got)
	}
	for _, b := range []string{"", "[1]", "{"} {
		if got := extractEscalationAnswer(g06req(nil, nil), []byte(b), true); got != nil {
			t.Fatalf("body %q: %v", b, got)
		}
	}
}

func TestK05G06MwProvenanceBundle(t *testing.T) {
	one, _ := StrictParse("1")
	body := []byte(`{"pca_provenance":1}`)
	hdr := func(v string) map[string]string { return map[string]string{ProvenanceHeader: v} }
	for _, h := range []string{"%%", g06b64("{")} {
		if got := extractProvenanceBundle(g06req(hdr(h), nil), body, true); got != (provUnreadable{}) {
			t.Fatalf("unreadable header %q: %v", h, got)
		}
	}
	two, _ := StrictParse("2")
	if got := extractProvenanceBundle(g06req(hdr(g06b64("2")), nil), body, true); !reflect.DeepEqual(got, two) {
		t.Fatalf("header: %v", got)
	}
	if got := extractProvenanceBundle(g06req(nil, nil), body, true); !reflect.DeepEqual(got, one) {
		t.Fatalf("body member: %v", got)
	}
	if got := extractProvenanceBundle(g06req(nil, nil), body, false); got != nil {
		t.Fatalf("oversized body: %v", got)
	}
	for _, b := range []string{"", "[1]", "{"} {
		if got := extractProvenanceBundle(g06req(nil, nil), []byte(b), true); got != nil {
			t.Fatalf("body %q: %v", b, got)
		}
	}
}

func TestK05G06MwWorkflowStep(t *testing.T) {
	req := g06req(nil, nil)
	boom := &AuthorizeOptions{Risk: InsecureCalmRisk, Plan: PlanSingleStep, WorkflowStep: func(*http.Request, map[string]any) *WorkflowCall { panic("boom") }}
	if wc := workflowStepOf(boom, req, nil, nil, true); !reflect.DeepEqual(wc, &WorkflowCall{}) {
		t.Fatalf("panicking callback: %+v", wc)
	}
	az := &AuthorizeOptions{Risk: InsecureCalmRisk, Plan: PlanSingleStep}
	good := []byte(`{"workflow":{"step":"s"}}`)
	if wc := workflowStepOf(az, req, nil, good, false); wc != nil {
		t.Fatalf("oversized body: %+v", wc)
	}
	if wc := workflowStepOf(az, req, nil, good, true); !reflect.DeepEqual(wc, &WorkflowCall{Step: "s"}) {
		t.Fatalf("body step: %+v", wc)
	}
	if wc := workflowStepOf(az, req, nil, []byte(`{"workflow":{"step":5,"commitment":"c"}}`), true); !reflect.DeepEqual(wc, &WorkflowCall{}) {
		t.Fatalf("non-string step: %+v", wc)
	}
	if wc := workflowStepOf(az, req, nil, nil, true); wc != nil {
		t.Fatalf("empty body: %+v", wc)
	}
}

func TestK05G06MwMapOperation(t *testing.T) {
	req := g06req(nil, nil)
	if op := mapOperation(func(*http.Request, []byte) (*Operation, error) { panic("boom") }, req, nil); op != nil {
		t.Fatalf("panic: %+v", op)
	}
	if op := mapOperation(func(*http.Request, []byte) (*Operation, error) { return &Operation{Verb: "v"}, errors.New("x") }, req, nil); op != nil {
		t.Fatalf("error: %+v", op)
	}
}

func TestK05G06MwPresentedK1(t *testing.T) {
	_, parseErr := StrictParse("{")
	for _, c := range []struct {
		name, val string
		want      error
	}{
		{"PCA-Discharges", "%%", ErrPCAHeader},
		{"PCA-Discharges", g06b64("{"), parseErr},
		{"PCA-Discharges", g06b64("{}"), errors.New("PCA-Discharges must be a JSON array")},
		{"PCA-Narrow", "%%", ErrPCAHeader},
		{"PCA-Narrow", g06b64("{"), parseErr},
	} {
		h := http.Header{}
		h.Set(c.name, c.val)
		if k, err := PresentedK1(h); err == nil || err.Error() != c.want.Error() || !reflect.DeepEqual(k, K1Input{}) {
			t.Fatalf("%s %q: %+v %v", c.name, c.val, k, err)
		}
	}
	h := http.Header{}
	h.Add("PCA-Narrow", g06b64("1"))
	h.Add("PCA-Narrow", g06b64("1"))
	if _, err := PresentedK1(h); err == nil || err.Error() != "PCA-Narrow is sent more than once" {
		t.Fatalf("narrow twice: %v", err)
	}
	h = http.Header{}
	h.Set("PCA-Discharges", g06b64(`["d"]`))
	h.Set("PCA-Narrow", g06b64(`"n"`))
	if k, err := PresentedK1(h); err != nil || !reflect.DeepEqual(k.Discharges, []any{"d"}) || k.Narrow != "n" || !k.HasNarrow {
		t.Fatalf("presented: %+v %v", k, err)
	}
}

func TestK05G06MwK1Hooks(t *testing.T) {
	s := NewMemoryStateStore()
	req := g06req(map[string]string{"PCA-Discharges": g06b64(`["d"]`)}, nil)
	if f, st := k1Hooks(&AuthorizeOptions{Risk: InsecureCalmRisk, Plan: PlanSingleStep, UsesStore: s}, req); f != nil || st != nil {
		t.Fatal("no K1: no hook and no uses store")
	}
	errX := errors.New("x")
	var seen *http.Request
	az := &AuthorizeOptions{Risk: InsecureCalmRisk, Plan: PlanSingleStep, UsesStore: s, K1: func(r *http.Request, p map[string]any) (*K1Input, error) {
		seen = r
		switch p["c"] {
		case "err":
			return &K1Input{}, errX
		case "errnil":
			return nil, errX
		case "nil":
			return nil, nil
		}
		return &K1Input{}, nil
	}}
	f, st := k1Hooks(az, req)
	if f == nil || st != StateStore(s) {
		t.Fatal("K1: hook and uses store")
	}
	for _, c := range []struct {
		c   string
		err error
	}{{"err", errX}, {"errnil", errX}, {"nil", nil}} {
		if k, err := f(map[string]any{"c": c.c}); k != nil || err != c.err {
			t.Fatalf("%s: %+v %v", c.c, k, err)
		}
	}
	k, err := f(map[string]any{})
	if err != nil || k == nil || !reflect.DeepEqual(k.Discharges, []any{"d"}) || seen != req {
		t.Fatalf("merged: %+v %v", k, err)
	}
}

type g06mwStore struct{ StateStore } // a StateStore that is not a LastStore

func TestK05G06MwConstructionPanics(t *testing.T) {
	panics := func(az *AuthorizeOptions) (p bool) {
		defer func() { p = recover() != nil }()
		RequirePCA(RequirePCAOptions{Authorize: az})
		return false
	}
	st := g06mwStore{NewMemoryStateStore()}
	if panics(&AuthorizeOptions{Risk: InsecureCalmRisk, Plan: PlanSingleStep, StateStore: st}) {
		t.Fatal("no escalation principals: no LastStore needed")
	}
	if !panics(&AuthorizeOptions{Risk: InsecureCalmRisk, Plan: PlanSingleStep, StateStore: st, EscalationPrincipals: []string{"a"}, EscalationPinned: []PinnedSigner{{}}}) {
		t.Fatal("one Ed25519 and one pinned principal without a LastStore")
	}
}

// g06mw is an authorize-mode RequirePCA over the faRig PCActn (the plan is exactly the operation).
func g06mw(r *faRig, mut func(*RequirePCAOptions, *AuthorizeOptions), next http.HandlerFunc) http.Handler {
	in := r.input(nil)
	o := RequirePCAOptions{Authorize: &AuthorizeOptions{Risk: InsecureCalmRisk, Plan: PlanSingleStep}, Audience: r.f.aud, Now: func() int64 { return r.f.now }, ResolveGrant: in.ResolveGrant}
	az := &AuthorizeOptions{Risk: InsecureCalmRisk, Plan: PlanSingleStep, StateStore: NewMemoryStateStore(), IsRevoked: in.IsRevoked, ArgProvenance: in.ArgProvenance,
		Operation: func(*http.Request, []byte) (*Operation, error) { return r.op, nil }}
	if mut != nil {
		mut(&o, az)
	}
	o.Authorize = az
	if next == nil {
		next = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }
	}
	return RequirePCA(o)(next)
}

func g06mwDo(t *testing.T, h http.Handler, p map[string]any, req *http.Request) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(p)
	req.Header.Set(PCAHeader, b64.EncodeToString(b))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return w, m
}

func TestK05G06MwBodyHandling(t *testing.T) {
	r := newFaRig(t, false)
	var opBody []byte
	opCalls := 0
	var nextBody io.ReadCloser
	var nextRead []byte
	// a fresh handler (and StateStore) per request: the same PCActn twice on one store is a replay
	h := func() http.Handler {
		return g06mw(r, func(_ *RequirePCAOptions, az *AuthorizeOptions) {
			az.Operation = func(q *http.Request, b []byte) (*Operation, error) {
				opCalls++
				opBody = b
				if q.Body != nil {
					_, _ = io.ReadAll(q.Body) // the mapping drains the request body
				}
				return r.op, nil
			}
		}, func(w http.ResponseWriter, q *http.Request) {
			nextBody = q.Body
			if q.Body != nil && q.Body != http.NoBody {
				nextRead, _ = io.ReadAll(q.Body)
			}
			w.WriteHeader(200)
		})
	}

	// no body at all, and http.NoBody: nothing is read, nothing is put back
	nilReq := g06req(nil, nil)
	nilReq.Body = nil
	if w, _ := g06mwDo(t, h(), r.f.p, nilReq); w.Code != 200 || opCalls != 1 || opBody != nil || nextBody != nil {
		t.Fatalf("nil body: %d %d %v %v", w.Code, opCalls, opBody, nextBody)
	}
	noBody := g06req(nil, nil)
	noBody.Body = http.NoBody
	if w, _ := g06mwDo(t, h(), r.f.p, noBody); w.Code != 200 || opCalls != 2 || opBody != nil || nextBody != http.NoBody {
		t.Fatalf("NoBody: %d %d %v %v", w.Code, opCalls, opBody, nextBody)
	}
	// a body: the mapping sees it, and the handler reads it again after the mapping drained it
	if w, _ := g06mwDo(t, h(), r.f.p, g06req(nil, []byte(`{"k":1}`))); w.Code != 200 || string(opBody) != `{"k":1}` || string(nextRead) != `{"k":1}` {
		t.Fatalf("body: %d %q %q", w.Code, opBody, nextRead)
	}
	// MaxJSONChars bytes are mapped; one more is never mapped (403)
	opCalls = 0
	if w, _ := g06mwDo(t, h(), r.f.p, g06req(nil, bytes.Repeat([]byte("a"), MaxJSONChars))); w.Code != 200 || opCalls != 1 || len(opBody) != MaxJSONChars {
		t.Fatalf("MaxJSONChars body: %d %d %d", w.Code, opCalls, len(opBody))
	}
	w, m := g06mwDo(t, h(), r.f.p, g06req(nil, bytes.Repeat([]byte("a"), MaxJSONChars+1)))
	if w.Code != 403 || opCalls != 1 || w.Header().Get("WWW-Authenticate") != `PCA realm="pca", error="insufficient_authority"` || m["error"] != "insufficient_authority" {
		t.Fatalf("oversized body: %d %d %v %v", w.Code, opCalls, w.Header(), m)
	}
}

func TestK05G06MwUnknownGrant(t *testing.T) {
	r := newFaRig(t, false)
	h := g06mw(r, func(o *RequirePCAOptions, _ *AuthorizeOptions) {
		o.ResolveGrant = func(string) (map[string]any, error) { return nil, nil } // unknown (an error is a 403 resolve_grant failure)
	}, nil)
	w, m := g06mwDo(t, h, r.f.p, g06req(nil, nil))
	if w.Code != 401 || w.Header().Get("WWW-Authenticate") != `PCA realm="pca", error="invalid_pcactn"` || m["error"] != "invalid_pcactn" {
		t.Fatalf("%d %v %v", w.Code, w.Header(), m)
	}
}

func TestK05G06MwHookWiring(t *testing.T) {
	r := newFaRig(t, false)
	intents, steps := 0, 0
	h := g06mw(r, func(o *RequirePCAOptions, az *AuthorizeOptions) {
		o.IntentV2 = func(*http.Request, map[string]any) *IntentV2Context { intents++; return nil }
		az.WorkflowStep = func(*http.Request, map[string]any) *WorkflowCall { steps++; return nil } // Workflow is off: never asked
	}, nil)
	g06mwDo(t, h, r.f.p, g06req(nil, nil))
	if intents == 0 || steps != 0 {
		t.Fatalf("IntentV2 calls %d, WorkflowStep calls %d", intents, steps)
	}
}

func TestK05G06MwRevocationHooks(t *testing.T) {
	r := newFaRig(t, false)
	age := 600_000.0
	issued := float64(r.f.now)
	id, _ := r.f.grant["id"].(string)
	var states, proofs, idCalls int
	run := func(state, proof, ids bool) (*httptest.ResponseRecorder, map[string]any) {
		states, proofs, idCalls = 0, 0, 0
		h := g06mw(r, func(_ *RequirePCAOptions, az *AuthorizeOptions) {
			az.RevocationStaleness = &RevocationStalenessPolicy{MaxRevocationAgeMs: &age}
			if state {
				az.RevocationState = func(*http.Request, map[string]any, map[string]any) (*RevocationState, error) {
					states++
					return &RevocationState{Root: "root", RootIssuedAt: &issued}, nil
				}
			}
			if proof {
				az.RevocationProof = func(*http.Request, string, map[string]any) any { proofs++; return nil }
			}
			if ids {
				az.RevocationIds = func(*http.Request, map[string]any) []string { idCalls++; return []string{"x"} }
			}
		}, nil)
		return g06mwDo(t, h, r.f.p, g06req(nil, nil))
	}
	if w, m := run(false, false, false); w.Code != 403 || !reflect.DeepEqual(m["missing"], []any{"RevocationState (required by RevocationStaleness)"}) {
		t.Fatalf("no state source: %d %v", w.Code, m)
	}
	if w, m := run(true, false, false); w.Code != 403 || states != 1 || m["reason"] != "freshness: no non-membership proof for "+id {
		t.Fatalf("no proof source: %d %d %v", w.Code, states, m)
	}
	if w, m := run(true, true, false); w.Code != 403 || proofs != 1 || m["reason"] != "freshness: no non-membership proof for "+id {
		t.Fatalf("proof source: %d %d %v", w.Code, proofs, m)
	}
	if w, m := run(true, false, true); w.Code != 403 || idCalls != 1 || m["reason"] != "freshness: no non-membership proof for x" {
		t.Fatalf("id source: %d %d %v", w.Code, idCalls, m)
	}
}

func TestK05G06MwEscalationAnswerGate(t *testing.T) {
	r := newFaRig(t, true)
	pin := b64.EncodeToString(newKey(t).pub)
	undo := func(*http.Request, UndoAdmitInput) (*UndoAdmission, error) {
		return &UndoAdmission{ID: "op_1", WindowEnd: 1792930500000, Compensation: UndoCompensation{Verb: "payments.refund", Resource: "payments/acme"}}, nil
	}
	run := func(pins []string) int {
		h := g06mw(r, func(o *RequirePCAOptions, az *AuthorizeOptions) {
			o.FreshAt = func(*http.Request, map[string]any) *FreshAtPolicy { return r.policy(4) } // stale: escalate
			az.EscalationPrincipals, az.Undo = pins, undo
		}, nil)
		w, _ := g06mwDo(t, h, r.f.p, g06req(map[string]string{"PCA-Escalation-Answer": g06b64("{}")}, nil))
		return w.Code
	}
	// no principal pinned: the answer header is not read, so the undo window admits the escalated action
	if c := run(nil); c != 200 {
		t.Fatalf("no pins: %d", c)
	}
	// a principal pinned: the (unverifiable) answer is read, and an answered escalation never opens an undo window
	if c := run([]string{pin}); c != 403 {
		t.Fatalf("pinned: %d", c)
	}
}
