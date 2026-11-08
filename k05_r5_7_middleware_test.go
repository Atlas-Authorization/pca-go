package pca

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// r5-7: middleware.go survivors.

type r5n7Closer struct {
	io.Reader
	closed bool
}

func (c *r5n7Closer) Close() error { c.closed = true; return nil }

// The request body that was read is closed, by the PCActn extractor and by the authorize handler.
func TestR5N7_MwClosesTheRequestBody(t *testing.T) {
	c := &r5n7Closer{Reader: strings.NewReader(`{"pcactn":{"a":1}}`)}
	req := g06req(nil, nil)
	req.Body = c
	if p, reason, ok := extractPCActn(req); !ok || p == nil {
		t.Fatalf("extract: %v %q %v", p, reason, ok)
	}
	if !c.closed {
		t.Error("extractPCActn left the body open")
	}

	r := newFaRig(t, false)
	h := g06mw(r, nil, nil)
	c2 := &r5n7Closer{Reader: strings.NewReader(`{"k":1}`)}
	req2 := g06req(nil, nil)
	req2.Body = c2
	if w, _ := g06mwDo(t, h, r.f.p, req2); w.Code != 200 {
		t.Fatalf("handler: %d", w.Code)
	}
	if !c2.closed {
		t.Error("the authorize handler left the body open")
	}
}

// PlanFromContext turns the single-step plan off without naming a plan: Authorize still asks only for its usual components.
func TestR5N7_MwPlanFromContextIsNotAPlanName(t *testing.T) {
	d, grant, s := guardCase(t, "envelope-predicate-within")
	g := serve(t, RequirePCAOptions{Audience: d["audience"].(string), Now: func() int64 { return fixNum(d["now"]) },
		ResolveGrant: func(string) (map[string]any, error) { return grant, nil },
		Authorize:    &AuthorizeOptions{Plan: PlanFromContext}}, s["pcactn"].(map[string]any))
	missing, _ := json.Marshal(g.body["missing"])
	if g.code != 403 || string(missing) != `["StateStore","IsRevoked"]` {
		t.Fatalf("%d missing = %s", g.code, missing)
	}
}

// RequireAssurance and the K1 hook of the options reach Authorize.
func TestR5N7_MwWiresAssuranceAndK1(t *testing.T) {
	r := newFaRig(t, false)
	if w, _ := g06mwDo(t, g06mw(r, nil, nil), r.f.p, g06req(nil, nil)); w.Code != 200 {
		t.Fatalf("premise: %d", w.Code)
	}
	h := g06mw(r, func(_ *RequirePCAOptions, az *AuthorizeOptions) {
		az.RequireAssurance = &AssuranceRequirement{Attestation: "hardware"}
	}, nil)
	w, m := g06mwDo(t, h, r.f.p, g06req(nil, nil))
	if w.Code != 403 || !strings.Contains(fmt.Sprint(m["reason"]), "assurance") {
		t.Fatalf("assurance: %d %v", w.Code, m)
	}
	calls := 0
	h = g06mw(r, func(_ *RequirePCAOptions, az *AuthorizeOptions) {
		az.K1 = func(*http.Request, map[string]any) (*K1Input, error) { calls++; return &K1Input{}, nil }
	}, nil)
	g06mwDo(t, h, r.f.p, g06req(nil, nil))
	if calls == 0 {
		t.Fatal("the K1 hook was never asked")
	}
}

// An unparseable pca-fresh-at header is a null token: nothing of the policy's own SideCarried survives it (the reference
// replaces the token with null).
func TestR5N7_MwFreshAtUnparseableHeaderIsNull(t *testing.T) {
	o := RequirePCAOptions{FreshAt: func(*http.Request, map[string]any) *FreshAtPolicy {
		return &FreshAtPolicy{Signer: "s", SideCarried: "preset"}
	}}
	got := o.freshAt(g06req(map[string]string{"pca-fresh-at": "{"}, nil), map[string]any{})
	if got == nil || !got.HasSideCarried || got.SideCarried != nil {
		t.Fatalf("got %+v", got)
	}
}

// Unreadable discharge headers add nothing: the K1 input the host returned is kept as it is.
func TestR5N7_MwMergeKeepsOwnOnUnreadableHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("PCA-Discharges", "%%")
	out := mergePresentedK1(h, &K1Input{Narrow: "n"})
	if out.Narrow != "n" || out.HasNarrow || out.Discharges != nil {
		t.Fatalf("got %+v", out)
	}
}
