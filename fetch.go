package pca

// Request-in, response-out guards over RequirePCA, for code that is not written as net/http middleware: a Handler wrapper
// (WithPCA) and a RoundTripper wrapper (WithPCARoundTripper, an in-process guard in front of any transport). Both verify the inbound
// PCActn first and run the wrapped handler only on success; a refusal is the 401/403 response with the reference deny body
// {error, verdict, decision}. Nothing here authorizes on its own: the verifier configured in the options decides.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// fetchRecorder collects a refusal written by RequirePCA.
type fetchRecorder struct {
	h      http.Header
	status int
	body   bytes.Buffer
}

func (r *fetchRecorder) Header() http.Header         { return r.h }
func (r *fetchRecorder) WriteHeader(code int)        { r.status = code }
func (r *fetchRecorder) Write(b []byte) (int, error) { return r.body.Write(b) }

// fetchCheck refuses the configurations the reference refuses at construction: no audience, or no way to bind the request to an
// operation (neither Authorize.Operation nor the explicit SignatureOnly opt-in).
func fetchCheck(opts RequirePCAOptions) error {
	if opts.Audience == "" {
		return errors.New("WithPCA: audience is required")
	}
	if !opts.SignatureOnly && (opts.Authorize == nil || opts.Authorize.Operation == nil) {
		return errors.New("WithPCA: set Authorize.Operation (the operation this request executes) or opt in with SignatureOnly")
	}
	return nil
}

// fetchDeny is a refusal in the reference shape.
type fetchDeny struct {
	status int
	header http.Header
	body   []byte
}

// fetchGuard returns a function that verifies r and yields either the request to hand on (it carries the verdict in its context) or the
// refusal.
func fetchGuard(opts RequirePCAOptions) (func(r *http.Request) (*http.Request, *fetchDeny), error) {
	if err := fetchCheck(opts); err != nil {
		return nil, err
	}
	return func(r *http.Request) (*http.Request, *fetchDeny) {
		var passed *http.Request
		rec := &fetchRecorder{h: http.Header{}, status: http.StatusOK}
		RequirePCA(opts)(http.HandlerFunc(func(_ http.ResponseWriter, r2 *http.Request) { passed = r2 })).ServeHTTP(rec, r)
		if passed != nil {
			return passed, nil
		}
		src := map[string]any{}
		_ = json.Unmarshal(rec.body.Bytes(), &src)
		reason, _ := src["error_description"].(string)
		if reason == "" {
			reason, _ = src["reason"].(string)
		}
		if reason == "" {
			reason, _ = src["error"].(string)
		}
		verdict := map[string]any{"allow": false, "reasons": []any{}}
		if reason != "" {
			verdict["reasons"] = []any{reason}
		}
		if c, ok := src["checks"]; ok {
			verdict["checks"] = c
		}
		errText := reason
		if errText == "" {
			errText = "forbidden"
		}
		decision, _ := src["decision"].(string)
		if decision == "" {
			decision = "deny"
		}
		body := map[string]any{"error": errText, "verdict": verdict, "decision": decision}
		if e, ok := src["escalation"]; ok {
			body["escalation"] = e
		}
		b, _ := json.Marshal(body)
		h := http.Header{"Content-Type": {"application/json"}}
		if w := rec.h.Get("WWW-Authenticate"); w != "" {
			h.Set("WWW-Authenticate", w)
		}
		return nil, &fetchDeny{status: rec.status, header: h, body: b}
	}, nil
}

// WithPCA wraps next so the inbound PCActn is verified first; on success next runs with the verdict in the request context (read
// it with FromContext). It returns an error for a configuration the reference refuses to construct (see fetchCheck).
func WithPCA(opts RequirePCAOptions, next http.Handler) (http.Handler, error) {
	g, err := fetchGuard(opts)
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		passed, deny := g(r)
		if deny == nil {
			next.ServeHTTP(w, passed)
			return
		}
		for k, v := range deny.header {
			w.Header()[k] = v
		}
		w.WriteHeader(deny.status)
		_, _ = w.Write(deny.body)
	}), nil
}

type guardedTransport struct {
	g    func(*http.Request) (*http.Request, *fetchDeny)
	next http.RoundTripper
}

// WithPCARoundTripper puts the same guard in front of a RoundTripper: a request that carries no valid PCActn gets the refusal
// response and never reaches next.
func WithPCARoundTripper(opts RequirePCAOptions, next http.RoundTripper) (http.RoundTripper, error) {
	g, err := fetchGuard(opts)
	if err != nil {
		return nil, err
	}
	if next == nil {
		next = http.DefaultTransport
	}
	return &guardedTransport{g: g, next: next}, nil
}

func (t *guardedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	passed, deny := t.g(r)
	if deny == nil {
		return t.next.RoundTrip(passed)
	}
	return &http.Response{StatusCode: deny.status, Status: http.StatusText(deny.status), Header: deny.header, Body: io.NopCloser(bytes.NewReader(deny.body)),
		ContentLength: int64(len(deny.body)), Request: r, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1}, nil
}
