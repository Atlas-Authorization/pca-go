package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	pca "github.com/Atlas-Authorization/pca-go"
	"github.com/gin-gonic/gin"
)

// A genuinely valid proof from the shared authorize fixtures: signed for payments.send on payments/acme with
// {"amount":50,"currency":"usd"}, audience payments-rs.
func fixture(t *testing.T) (grant, proof map[string]any, aud string, now int64) {
	t.Helper()
	b, err := os.ReadFile("../../testdata/authorize-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	d, err := pca.ParseJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	c := d["cases"].([]any)[0].(map[string]any)
	step := c["steps"].([]any)[0].(map[string]any)
	n, _ := d["now"].(interface{ Int64() (int64, error) }).Int64()
	return c["grant"].(map[string]any), step["pcactn"].(map[string]any), d["audience"].(string), n
}

func call(t *testing.T, r http.Handler, proof map[string]any, body string) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/refunds", strings.NewReader(body))
	req.Header.Set(pca.PCAHeader, base64.RawURLEncoding.EncodeToString(raw))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("status %d, body %q: %v", rec.Code, rec.Body.String(), err)
	}
	return rec.Code, out
}

func TestRefundAllowedThenReplayRefusedWithDoc(t *testing.T) {
	gin.SetMode(gin.TestMode)
	grant, proof, aud, now := fixture(t)
	p := pca.Protect(pca.ProtectOptions{Audience: aud, Grants: []map[string]any{grant}, Operation: operationFor, Now: func() int64 { return now }})
	r := newRouter(p)
	const body = `{"amount":50,"currency":"usd"}`

	if code, out := call(t, r, proof, body); code != 200 || out["status"] != "done" {
		t.Fatalf("allow: %d %v", code, out)
	}
	code, out := call(t, r, proof, body) // the same proof again
	doc, _ := out["doc"].(string)
	if code != 403 || !strings.HasPrefix(doc, "https://") || !strings.Contains(doc, "refusals.md#replay") {
		t.Fatalf("replay: %d %v", code, out)
	}
}

func TestRefundWithOtherAmountRefused(t *testing.T) {
	gin.SetMode(gin.TestMode)
	grant, proof, aud, now := fixture(t)
	r := newRouter(pca.Protect(pca.ProtectOptions{Audience: aud, Grants: []map[string]any{grant}, Operation: operationFor, Now: func() int64 { return now }}))
	code, out := call(t, r, proof, `{"amount":5000,"currency":"usd"}`) // the proof was signed for 50
	if _, has := out["doc"].(string); code != 403 || !has {
		t.Fatalf("%d %v", code, out)
	}
}
