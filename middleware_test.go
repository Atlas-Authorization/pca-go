package pca

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// loadValidVector returns the first always-allow object vector (ed25519 suite) from the shared
// conformance set, along with its grant, audience and `now`. Reusing a signed conformance vector
// means the test drives the middleware with a genuinely valid PCActn without re-implementing signing.
func loadValidVector(t *testing.T) (pcactn, grant map[string]any, aud string, now int64) {
	t.Helper()
	doc := load(t, "vectors.json")
	for _, x := range doc["vectors"].([]any) {
		v := x.(map[string]any)
		if req, ok := v["requires"].(string); ok && req != "" && req != "ed25519" {
			continue // skip post-quantum-only vectors
		}
		exp, _ := v["expect"].(map[string]any)
		if exp == nil || exp["allow"] != true {
			continue
		}
		p, ok := v["pcactn"].(map[string]any)
		if !ok {
			continue
		}
		g, ok := v["grant"].(map[string]any)
		if !ok {
			continue
		}
		ctx := v["context"].(map[string]any)
		return p, g, ctx["aud"].(string), num(ctx["now"])
	}
	t.Fatal("no passing ed25519 object vector found in conformance set")
	return nil, nil, "", 0
}

// headerFor marshals a PCActn to JSON and base64url-encodes it for the PCA-Action header. json.Marshal
// round-trips json.Number losslessly, so the verifier recomputes an identical canonical form and the
// signature still verifies.
func headerFor(t *testing.T, p map[string]any) string {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal pcactn: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func mw(t *testing.T, audience string) func(http.Handler) http.Handler {
	t.Helper()
	pcactn, grant, aud, now := loadValidVector(t)
	if audience == "" {
		audience = aud
	}
	wantRef := pcactn["grant_ref"].(string)
	return RequirePCA(RequirePCAOptions{
		Audience: audience,
		Now:      func() int64 { return now },
		ResolveGrant: func(ref string) (map[string]any, error) {
			if ref == wantRef {
				return grant, nil
			}
			return nil, fmt.Errorf("unknown grant %q", ref)
		},
	})
}

func TestRequirePCA_ValidHeader(t *testing.T) {
	pcactn, _, _, _ := loadValidVector(t)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		verdict, got, ok := FromContext(r.Context())
		if !ok {
			t.Error("FromContext returned ok=false in the next handler")
			return
		}
		if verdict == nil || !verdict.Allow {
			t.Errorf("verdict not Allow: %+v", verdict)
		}
		if got["grant_ref"] != pcactn["grant_ref"] {
			t.Error("FromContext returned a different PCActn")
		}
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "/do", nil)
	req.Header.Set(PCAHeader, headerFor(t, pcactn))
	rec := httptest.NewRecorder()

	mw(t, "")(next).ServeHTTP(rec, req)

	if !called {
		t.Fatal("next handler was not called for a valid PCActn")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d (%s)", rec.Code, http.StatusNoContent, rec.Body.String())
	}
}

func TestRequirePCA_NoHeaderNoBody(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler ran despite no PCActn")
	})
	req := httptest.NewRequest(http.MethodGet, "/do", nil)
	rec := httptest.NewRecorder()

	mw(t, "")(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if wa := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(wa, `PCA realm="pca"`) {
		t.Fatalf("WWW-Authenticate = %q, want a PCA challenge", wa)
	}
}

func TestRequirePCA_UndecodableHeader(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler ran despite an undecodable header")
	})
	req := httptest.NewRequest(http.MethodGet, "/do", nil)
	req.Header.Set(PCAHeader, "!!!not-base64!!!")
	rec := httptest.NewRecorder()

	mw(t, "")(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("missing WWW-Authenticate challenge")
	}
}

func TestRequirePCA_UnknownGrant(t *testing.T) {
	pcactn, _, aud, now := loadValidVector(t)
	handler := RequirePCA(RequirePCAOptions{
		Audience: aud,
		Now:      func() int64 { return now },
		ResolveGrant: func(ref string) (map[string]any, error) {
			return nil, fmt.Errorf("no such grant")
		},
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler ran despite an unknown grant")
	})
	req := httptest.NewRequest(http.MethodPost, "/do", nil)
	req.Header.Set(PCAHeader, headerFor(t, pcactn))
	rec := httptest.NewRecorder()

	handler(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for unknown grant (%s)", rec.Code, rec.Body.String())
	}
}

func TestRequirePCA_WrongAudience(t *testing.T) {
	pcactn, _, _, _ := loadValidVector(t)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler ran despite a failing verdict")
	})
	req := httptest.NewRequest(http.MethodPost, "/do", nil)
	req.Header.Set(PCAHeader, headerFor(t, pcactn))
	rec := httptest.NewRecorder()

	// Audience that does not match the PCActn's signed aud -> failing verdict -> 403.
	mw(t, "rs-wrong-audience")(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for wrong audience (%s)", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("missing WWW-Authenticate challenge on 403")
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not JSON: %v", err)
	}
	checks, _ := body["checks"].(map[string]any)
	if checks["audience"] != false {
		t.Errorf("expected checks.audience=false in body, got %v", body["checks"])
	}
}

func TestRequirePCA_BodyAndBodyRestored(t *testing.T) {
	pcactn, _, _, _ := loadValidVector(t)

	wrapper := map[string]any{"pcactn": pcactn}
	raw, err := json.Marshal(wrapper)
	if err != nil {
		t.Fatal(err)
	}

	var downstreamBody []byte
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := FromContext(r.Context()); !ok {
			t.Error("FromContext ok=false for a valid body PCActn")
		}
		downstreamBody, _ = io.ReadAll(r.Body) // must still be readable
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/do", bytes.NewReader(raw))
	rec := httptest.NewRecorder()

	mw(t, "")(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(downstreamBody, raw) {
		t.Fatalf("downstream body not restored: got %d bytes, want %d", len(downstreamBody), len(raw))
	}
}
