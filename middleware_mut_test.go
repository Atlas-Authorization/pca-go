package pca

// Mutation-kill tests for middleware.go (exact reasons, status codes, headers, body restore, limits).

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type errAfterReader struct {
	data []byte
	done bool
}

func (e *errAfterReader) Read(p []byte) (int, error) {
	if !e.done {
		e.done = true
		n := copy(p, e.data)
		return n, nil
	}
	return 0, errors.New("boom")
}

func rawReq(body io.ReadCloser) *http.Request {
	return &http.Request{Method: "POST", Header: http.Header{}, Body: body}
}

// 0.4.1: the header decoder is strict (the lenient decodeB64u accepted padding and is gone).
func TestMutDecodePCAHeader(t *testing.T) {
	if s, err := DecodePCAHeader("YQ"); err != nil || s != "a" {
		t.Fatalf("raw: %q %v", s, err)
	}
	if s, err := DecodePCAHeader("YQ=="); err == nil || s != "" {
		t.Fatalf("padded accepted: %q %v", s, err)
	}
	if s, err := DecodePCAHeader("Y"); err == nil || s != "" {
		t.Fatalf("invalid: %q %v", s, err)
	}
}

func TestMutExtractPCActn(t *testing.T) {
	missing := "no PCActn presented (missing PCA-Action header and request body)"
	long := `{"pcactn":{}}` + strings.Repeat(" ", 1048576-len(`{"pcactn":{}}`)+1)
	exact := `{"pcactn":{}}` + strings.Repeat(" ", 1048576-len(`{"pcactn":{}}`))
	if len(long) != 1048576+1 || len(exact) != 1048576 {
		t.Fatal("setup")
	}
	cases := []struct {
		name   string
		mk     func() *http.Request
		ok     bool
		reason string
		body   string // expected restored body (if body path)
	}{
		{"nil body", func() *http.Request { return rawReq(nil) }, false, missing, ""},
		{"NoBody", func() *http.Request { return rawReq(http.NoBody) }, false, missing, ""},
		{"empty body", func() *http.Request { return rawReq(io.NopCloser(strings.NewReader(""))) }, false, missing, ""},
		{"read error", func() *http.Request {
			return rawReq(io.NopCloser(&errAfterReader{data: []byte(`{"pcactn":{}}`)}))
		}, false, missing, ""},
		{"one byte", func() *http.Request { return rawReq(io.NopCloser(strings.NewReader("x"))) }, false, "request body is not valid strict JSON", "x"},
		{"bad json", func() *http.Request { return rawReq(io.NopCloser(strings.NewReader("{"))) }, false, "request body is not valid strict JSON", "{"},
		{"array", func() *http.Request { return rawReq(io.NopCloser(strings.NewReader("[]"))) }, false, "request body is not a JSON object", "[]"},
		{"no pcactn", func() *http.Request { return rawReq(io.NopCloser(strings.NewReader("{}"))) }, false, "request body has no 'pcactn' field", "{}"},
		{"pcactn not obj", func() *http.Request { return rawReq(io.NopCloser(strings.NewReader(`{"pcactn":1}`))) }, false, "'pcactn' is not a JSON object", `{"pcactn":1}`},
		{"ok", func() *http.Request { return rawReq(io.NopCloser(strings.NewReader(`{"pcactn":{"a":1}}`))) }, true, "", `{"pcactn":{"a":1}}`},
		{"limit exact", func() *http.Request { return rawReq(io.NopCloser(strings.NewReader(exact))) }, true, "", exact},
		{"limit+1", func() *http.Request { return rawReq(io.NopCloser(strings.NewReader(long))) }, false, "request body is not valid strict JSON", long},
		{"limit+1 trailing garbage", func() *http.Request {
			return rawReq(io.NopCloser(strings.NewReader(exact + "garbage-after-the-limit")))
		}, false, "request body is not valid strict JSON", ""},
		{"header bad b64", func() *http.Request {
			r := rawReq(nil)
			r.Header.Set(PCAHeader, "!!!")
			return r
		}, false, "PCA-Action header is not valid base64url", ""},
		{"header bad json", func() *http.Request {
			r := rawReq(nil)
			r.Header.Set(PCAHeader, "bm90IGpzb24")
			return r
		}, false, "PCA-Action header is not a valid PCActn JSON object", ""},
		{"header padded refused", func() *http.Request {
			r := rawReq(nil)
			r.Header.Set(PCAHeader, "eyJhIjoxfQ==") // {"a":1}, padded: 0.4.1 strict
			return r
		}, false, "PCA-Action header is not valid base64url", ""},
		{"header ok", func() *http.Request {
			r := rawReq(nil)
			r.Header.Set(PCAHeader, "eyJhIjoxfQ") // {"a":1}
			return r
		}, true, "", ""},
		{"header invalid utf-8", func() *http.Request {
			r := rawReq(nil)
			r.Header.Set(PCAHeader, "__57") // FF FE 7B
			return r
		}, false, "PCA-Action header is not valid base64url", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := c.mk()
			p, reason, ok := extractPCActn(r)
			if ok != c.ok || reason != c.reason {
				t.Fatalf("got ok=%v reason=%q, want ok=%v reason=%q", ok, reason, c.ok, c.reason)
			}
			if ok && p == nil {
				t.Fatal("nil pcactn on success")
			}
			if !ok && p != nil {
				t.Fatal("non-nil pcactn on failure")
			}
			if c.body != "" {
				b, _ := io.ReadAll(r.Body)
				if string(b) != c.body {
					t.Fatalf("body not restored: %d vs %d bytes", len(b), len(c.body))
				}
			}
		})
	}
}

func TestMutWritePCAError(t *testing.T) {
	cases := []struct {
		desc    string
		verdict *Verdict
		chal    string
		keys    []string
	}{
		{"", nil, `PCA realm="pca", error="x_code"`, []string{"error"}},
		{"why", nil, `PCA realm="pca", error="x_code", error_description="why"`, []string{"error", "error_description"}},
		{"", &Verdict{Checks: map[string]bool{"a": true}}, `PCA realm="pca", error="x_code"`, []string{"checks", "error"}},
		{"d", &Verdict{Reason: "r", Checks: map[string]bool{"a": false}}, `PCA realm="pca", error="x_code", error_description="d"`, []string{"checks", "error", "error_description", "reason"}},
	}
	for i, c := range cases {
		rec := httptest.NewRecorder()
		writePCAError(rec, 418, "x_code", c.desc, c.verdict)
		if rec.Code != 418 {
			t.Fatalf("%d status %d", i, rec.Code)
		}
		if got := rec.Header().Get("WWW-Authenticate"); got != c.chal {
			t.Fatalf("%d challenge %q want %q", i, got, c.chal)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Fatalf("%d content-type %q", i, ct)
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		var keys []string
		for k := range body {
			keys = append(keys, k)
		}
		sortStrings(keys)
		if fmt.Sprint(keys) != fmt.Sprint(c.keys) {
			t.Fatalf("%d keys %v want %v", i, keys, c.keys)
		}
		if body["error"] != "x_code" {
			t.Fatal("error code")
		}
	}
}

func sortStrings(a []string) {
	for i := range a {
		for j := i + 1; j < len(a); j++ {
			if a[j] < a[i] {
				a[i], a[j] = a[j], a[i]
			}
		}
	}
}

func doReq(t *testing.T, opts RequirePCAOptions, p map[string]any) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	req := httptest.NewRequest("POST", "/do", nil)
	req.Header.Set(PCAHeader, headerFor(t, p))
	rec := httptest.NewRecorder()
	RequirePCA(opts)(next).ServeHTTP(rec, req)
	return rec, called
}

func errBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var b map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMutRequirePCAErrors(t *testing.T) {
	p, grant, aud, now := loadValidVector(t)
	resolve := func(string) (map[string]any, error) { return grant, nil }

	// default clock: the vector is long expired relative to real time -> 403 validity, and no nil-func panic.
	rec, called := doReq(t, RequirePCAOptions{Audience: aud, ResolveGrant: resolve}, p)
	b := errBody(t, rec)
	if rec.Code != 403 || called || b["error"] != "insufficient_authority" {
		t.Fatalf("default clock: %d %v", rec.Code, b)
	}
	if ch, _ := b["checks"].(map[string]any); ch["validity"] != false {
		t.Fatalf("validity should fail with real clock: %v", b)
	}
	if b["reason"] == nil || b["reason"] == "" {
		t.Fatal("reason missing")
	}

	// missing / empty grant_ref
	for _, gr := range []any{nil, ""} {
		q := map[string]any{}
		for k, v := range p {
			q[k] = v
		}
		if gr == nil {
			delete(q, "grant_ref")
		} else {
			q["grant_ref"] = gr
		}
		resolved := false
		rec, called = doReq(t, RequirePCAOptions{Audience: aud, Now: func() int64 { return now },
			ResolveGrant: func(string) (map[string]any, error) { resolved = true; return grant, nil }}, q)
		b = errBody(t, rec)
		if rec.Code != 401 || called || resolved || b["error"] != "invalid_request" || b["error_description"] != "PCActn has no grant_ref" {
			t.Fatalf("grant_ref %v: %d %v resolved=%v", gr, rec.Code, b, resolved)
		}
	}

	// nil resolver
	rec, called = doReq(t, RequirePCAOptions{Audience: aud, Now: func() int64 { return now }}, p)
	b = errBody(t, rec)
	if rec.Code != 401 || called || b["error"] != "invalid_request" || b["error_description"] != "no grant resolver configured" {
		t.Fatalf("nil resolver: %d %v", rec.Code, b)
	}

	// resolver (nil,nil), (grant,err), (nil,err)
	for i, rf := range []func(string) (map[string]any, error){
		func(string) (map[string]any, error) { return nil, nil },
		func(string) (map[string]any, error) { return grant, errors.New("x") },
		func(string) (map[string]any, error) { return nil, errors.New("x") },
	} {
		rec, called = doReq(t, RequirePCAOptions{Audience: aud, Now: func() int64 { return now }, ResolveGrant: rf}, p)
		b = errBody(t, rec)
		if rec.Code != 401 || called || b["error"] != "unknown_grant" || b["error_description"] != "grant_ref does not resolve to a known grant" {
			t.Fatalf("resolver %d: %d %v", i, rec.Code, b)
		}
	}

	// failing verdict: error code, reason and checks are surfaced
	rec, called = doReq(t, RequirePCAOptions{Audience: "other", Now: func() int64 { return now }, ResolveGrant: resolve}, p)
	b = errBody(t, rec)
	if rec.Code != 403 || called || b["error"] != "insufficient_authority" || b["error_description"] != b["reason"] ||
		!strings.HasPrefix(fmt.Sprint(b["reason"]), "audience: ") {
		t.Fatalf("verdict: %d %v", rec.Code, b)
	}
}

func TestMutExtractBodyReadCap(t *testing.T) {
	// an oversize body is read up to exactly limit+1 bytes (enough to prove it is oversize) and that prefix is restored
	big := strings.Repeat("x", 1048576+500)
	r := rawReq(io.NopCloser(strings.NewReader(big)))
	if _, reason, ok := extractPCActn(r); ok || reason != "request body is not valid strict JSON" {
		t.Fatalf("%v %q", ok, reason)
	}
	b, _ := io.ReadAll(r.Body)
	if len(b) != 1048576+1 {
		t.Fatalf("restored %d bytes, want %d", len(b), 1048576+1)
	}
}
