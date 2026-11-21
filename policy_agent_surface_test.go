package pca

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVaultErrorConstructors(t *testing.T) {
	cases := []struct {
		e    *VaultError
		code string
		msg  string
	}{
		{NewExpiredNoRefreshError("google", "c1"), "expired_no_refresh", "connection 'google/c1' token is expired and has no refresh token"},
		{NewUnknownConnectionError("a", "p", "c"), "unknown_connection", "no connection for agent 'a' provider 'p' id 'c'"},
		{NewStoreError(""), "store_error", "the connection store failed"},
		{NewUnconfirmedActionError("x.y"), "unconfirmed_action", "the definition of 'x.y' has no valid signed confirmation: refusing to release a credential"},
		{NewRequestMismatchError("outbound request refused: url"), "request_mismatch", "outbound request refused: url"},
		{NewProxyFailedError("boom"), "proxy_failed", "boom"},
		{NewUnknownActionError("x.y"), "unknown_action", "no pinned action definition for verb 'x.y': refusing to release a credential"},
	}
	for _, c := range cases {
		var ce *CodedError
		if c.e.Code != c.code || c.e.Error() != c.msg || !errors.As(c.e, &ce) || ce.Code != c.code {
			t.Errorf("%s: got %q %q", c.code, c.e.Code, c.e.Error())
		}
	}
	if NewBearerReleaseDisabledError().Code != "bearer_release_disabled" || NewManifestValidationError([]string{"a", "b"}).Message != "invalid provider manifest: a; b" {
		t.Error("bearer or manifest error")
	}
	if NewUnknownProviderError("zz").Error() != "no connector registered for provider 'zz'" || GetProvider("zz") != nil || len(ListProviders()) == 0 {
		t.Error("provider registry accessors")
	}
}

func TestOprfRandomKeyPairIsConsistent(t *testing.T) {
	sk, pk, err := OprfRandomKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	want, err := OprfPublicKeyFor(sk)
	if err != nil || !bytes.Equal(want, pk) {
		t.Fatalf("public key does not match: %v", err)
	}
	if again, err := OprfSerializeElement(pk); err != nil || !bytes.Equal(again, pk) {
		t.Fatalf("serialize round trip: %v", err)
	}
	if _, err := OprfSerializeElement([]byte{1, 2, 3}); err == nil {
		t.Fatal("a malformed element must be refused")
	}
}

func TestGrantClientFoldsOnlyFresherTokens(t *testing.T) {
	token := func(epoch string) string {
		return `{"revocation_epoch":` + epoch + `,"policy_revision":1,"ledger_tree_size":1,"budget_version":1}`
	}
	next := token("5")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("pca-fresh-at", next)
		if r.URL.Path == GrantsPath+"/missing" {
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"error":"not_found","message":"no such grant"}`))
			return
		}
		_, _ = w.Write([]byte(`{"grants":[]}`))
	}))
	defer srv.Close()
	c := NewGrantClient(GrantClientOptions{BaseURL: srv.URL + "/"})
	if c.FreshAt() != nil {
		t.Fatal("no token before any call")
	}
	if _, err := c.List(map[string]string{"status": "active"}); err != nil {
		t.Fatal(err)
	}
	next = token("3") // an older token never replaces a fresher one
	if _, err := c.List(nil); err != nil {
		t.Fatal(err)
	}
	if got := c.FreshAt()["revocation_epoch"]; jsF(got) != 5 {
		t.Fatalf("fresher token was replaced: %v", got)
	}
	_, err := c.Inspect("missing")
	var ge *GrantApiError
	if !errors.As(err, &ge) || ge.Status != 404 || ge.Code != "not_found" {
		t.Fatalf("want a 404 GrantApiError, got %v", err)
	}
}

func TestPolicyBuilderMergesAndCatalogPins(t *testing.T) {
	b := NewPolicyBuilder().Allow("stripe", []string{"refund"}).Allow("stripe", []string{"charge", "refund"}).Limit("refund", "$5")
	p, err := b.Build()
	if err != nil || len(p.Permissions["stripe"].([]any)) != 2 || p.Limits["refund"] != "$5" {
		t.Fatalf("builder: %v %v", p, err)
	}
	if _, err := NewPolicyBuilder().Build(); err == nil {
		t.Fatal("an empty builder must refuse to build")
	}
	if _, err := DefineAction(CatalogAction{Connector: "a b", Action: "x", Reversibility: "reversible"}); err == nil {
		t.Fatal("a connector with whitespace is refused")
	}
	base := DefaultCatalog()
	d, err := ActionCatalogDigest(base)
	if err != nil || AssertCatalogPinned(base, d) != nil {
		t.Fatalf("pin: %v", err)
	}
	loosened := CatalogAction{Connector: "gmail", Action: "send", Verb: "gmail.send", Reversibility: "reversible", BlastRadius: 0.8}
	if _, err := ExtendCatalog(base, []CatalogAction{loosened}); err == nil {
		t.Fatal("relabelling gmail.send as reversible must be refused")
	}
	if s, known := ResolveAction(base, "nope.nope"); known || s.Reversibility != "irreversible" || s.BlastRadius != 1 {
		t.Fatalf("an unknown verb fails closed: %v", s)
	}
}

func TestDlpAndImmuneFailClosed(t *testing.T) {
	r, err := EvaluateDlp(map[string]any{"classes": []any{map[string]any{"name": "pii", "resource": "db:*", "maxTaintForAuto": jsNumber(0), "hardDenyAbove": jsNumber(2)}}},
		map[string]any{"verb": "read", "resource": "db:users", "taint": "high"})
	if err != nil || r["outcome"] != "deny" {
		t.Fatalf("a non-finite taint is maximally tainted: %v %v", r, err)
	}
	if lvl := ImmuneAssess(nil)["level"]; lvl != "high" {
		t.Fatalf("a missing state is the maximal threat: %v", lvl)
	}
}

func TestExplainRiskReproducesRiskScore(t *testing.T) {
	in := RiskInputs{SemanticDistance: 0.2, Reversibility: 0.4, BlastRadius: 0.9, Taint: 0.1, Confidence: 0.7, Age: 0.3}
	w := RiskWeights{Alpha: 0.25, Beta: 0.2, Gamma: 0.2, Delta: 0.2, Epsilon: 0.1, Zeta: 0.05}
	x := ExplainRisk(in, w, 0)
	if len(x.Terms) != 6 || x.R != RiskScore(in, w) {
		t.Fatalf("explanation r %v != RiskScore %v", x.R, RiskScore(in, w))
	}
	if f := ExplainRisk(in, w, 0.99); f.R != 0.99 || f.RScore != x.RScore {
		t.Fatalf("the caution floor lifts r: %v", f.R)
	}
}
