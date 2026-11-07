package pca

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Mutation kills for stepup.go. HTTP goes through an in-process RoundTripper: no sockets.

type g13suRT func(*http.Request) (*http.Response, error)

func (f g13suRT) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func g13suResp(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
}

type g13suErrBody struct{}

func (g13suErrBody) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (g13suErrBody) Close() error             { return nil }

// g13suStore fails the Load calls whose 1-based index is in failOn.
type g13suStore struct {
	val     []byte
	saveErr error
	failOn  map[int]bool
	loads   int
}

func (s *g13suStore) Load() ([]byte, error) {
	s.loads++
	if s.failOn[s.loads] {
		return s.val, errors.New("load failed")
	}
	return s.val, nil
}

func (s *g13suStore) Save(b []byte) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.val = append([]byte(nil), b...)
	return nil
}

func (s *g13suStore) Delete() error { s.val = nil; return nil }

const g13suNow = int64(1_800_000_000_000)

func g13suClient(t *testing.T, key *PrincipalDeviceKey, rt g13suRT, tokenErr error) *StepUpClient {
	t.Helper()
	if key == nil {
		key, _ = newStepupKey(t)
	}
	c, err := NewStepUpClient(StepUpClientOptions{DashboardURL: "https://dash.example", InstanceURL: "https://inst.example",
		AccountID: "acc", InstanceID: "ins", Key: key, HTTP: &http.Client{Transport: rt},
		Token: func(context.Context) (string, error) { return "dsk_x", tokenErr }, Now: func() int64 { return g13suNow }})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func g13suKind(t *testing.T, what string, err error, kind StepUpKind, msg string) {
	t.Helper()
	var e *StepUpError
	if !errors.As(err, &e) || e.Kind != kind || (msg != "" && e.Message != msg) {
		t.Fatalf("%s: got %#v, want kind %d %q", what, err, kind, msg)
	}
}

func TestG13StepUpKindsAndError(t *testing.T) {
	kinds := []StepUpKind{StepUpNoDeviceKey, StepUpInvalidSecret, StepUpInvalidThresholdMessage, StepUpInvalidStepUp,
		StepUpPrincipalMismatch, StepUpAPI, StepUpTransport}
	for i, k := range kinds {
		if int(k) != i+1 {
			t.Fatalf("kind %d has value %d", i, k)
		}
	}
	if got := stepUpErr(StepUpInvalidSecret, "m").Error(); got != "m" {
		t.Fatalf("non-API error text %q", got)
	}
	if got := (&StepUpError{Kind: StepUpAPI, Status: 409, Message: "x"}).Error(); got != "HTTP 409: x" {
		t.Fatalf("API error text %q", got)
	}
	if IsStepUpKind(errors.New("x"), StepUpAPI) {
		t.Fatal("a plain error is not a StepUpError")
	}
	if IsStepUpKind(stepUpErr(StepUpAPI, ""), StepUpTransport) || !IsStepUpKind(stepUpErr(StepUpAPI, ""), StepUpAPI) {
		t.Fatal("kind match")
	}
}

func TestG13StepUpValidID(t *testing.T) {
	for _, id := range []string{"A", "Z", "a", "z", "0", "9", "_", "-", "su.1", "...", strings.Repeat("a", 200)} {
		if !validStepUpID(id) {
			t.Fatalf("%q refused", id)
		}
	}
	for _, id := range []string{"", ".", "..", strings.Repeat("a", 201), "!a", "a!", "@", "[", "`", "{", "/", ":"} {
		if validStepUpID(id) {
			t.Fatalf("%q accepted", id)
		}
	}
}

func TestG13StepUpDeviceKeyStore(t *testing.T) {
	seed := make([]byte, 32)
	if NewPrincipalDeviceKey(&g13suStore{val: []byte{1}, failOn: map[int]bool{1: true}}).Exists() {
		t.Fatal("Exists with a failing Load")
	}
	if NewPrincipalDeviceKey(&g13suStore{val: []byte{}}).Exists() {
		t.Fatal("Exists with an empty value")
	}
	if !NewPrincipalDeviceKey(&g13suStore{val: []byte{1}}).Exists() {
		t.Fatal("Exists with a one-byte value")
	}
	saveErr := errors.New("disk full")
	_, err := NewPrincipalDeviceKey(&g13suStore{saveErr: saveErr}).Generate()
	g13suKind(t, "generate with a failing Save", err, StepUpTransport, "Could not persist the principal key.")
	if !errors.Is(err, saveErr) {
		t.Fatalf("the save error is not wrapped: %v", err)
	}
	_, err = NewPrincipalDeviceKey(&g13suStore{failOn: map[int]bool{1: true}}).PublicKey()
	g13suKind(t, "failing Load", err, StepUpTransport, "Could not read the principal key.")
	_, err = NewPrincipalDeviceKey(&g13suStore{val: seed[:31]}).PublicKey()
	g13suKind(t, "31-byte seed", err, StepUpInvalidSecret, "")
	if s, err := NewPrincipalDeviceKey(&g13suStore{}).ExportSecret(); s != "" || !IsStepUpKind(err, StepUpNoDeviceKey) {
		t.Fatalf("export without a key: %q %v", s, err)
	}
}

func TestG13StepUpNewClient(t *testing.T) {
	key, _ := newStepupKey(t)
	tok := func(context.Context) (string, error) { return "t", nil }
	base := func() StepUpClientOptions {
		return StepUpClientOptions{DashboardURL: "https://d.example", InstanceURL: "https://i.example", AccountID: "acc", InstanceID: "ins", Key: key, Token: tok}
	}
	const needs = "pca: NewStepUpClient needs Key, Token and a valid AccountID and InstanceID"
	for _, c := range []struct {
		name string
		mut  func(*StepUpClientOptions)
		want string
	}{
		{"bad instance URL", func(o *StepUpClientOptions) { o.InstanceURL = "ftp://i" }, "pca: InstanceURL must be an http(s) URL"},
		{"no key", func(o *StepUpClientOptions) { o.Key = nil }, needs},
		{"no token", func(o *StepUpClientOptions) { o.Token = nil }, needs},
		{"bad account", func(o *StepUpClientOptions) { o.AccountID = "a/b" }, needs},
		{"bad instance", func(o *StepUpClientOptions) { o.InstanceID = ".." }, needs},
	} {
		o := base()
		c.mut(&o)
		if _, err := NewStepUpClient(o); err == nil || err.Error() != c.want {
			t.Fatalf("%s: %v", c.name, err)
		}
	}
	c, err := NewStepUpClient(base())
	if err != nil || c.http == nil || c.http.Timeout != 30*time.Second {
		t.Fatalf("default client: %v %+v", err, c)
	}
	if c.o.Now == nil || c.o.Now() < 1_600_000_000_000 {
		t.Fatal("default clock")
	}
	hc := &http.Client{}
	o := base()
	o.HTTP, o.Now = hc, func() int64 { return 5 }
	c, err = NewStepUpClient(o)
	if err != nil || c.http != hc || c.o.Now() != 5 {
		t.Fatalf("supplied client and clock not kept: %v", err)
	}
}

func TestG13StepUpCall(t *testing.T) {
	ctx := context.Background()
	rtErr := errors.New("dial failed")
	var seen *http.Request
	status, body := 200, "{}"
	var errBody, fail bool
	c := g13suClient(t, nil, func(r *http.Request) (*http.Response, error) {
		seen = r
		if fail {
			return nil, rtErr
		}
		resp := g13suResp(status, body)
		if errBody {
			resp.Body = g13suErrBody{}
		}
		return resp, nil
	}, nil)

	st, _, err := c.call(ctx, "BAD METHOD", "https://x.example", "", nil)
	if st != 0 {
		t.Fatalf("bad method status %d", st)
	}
	g13suKind(t, "bad method", err, StepUpTransport, "")

	fail = true
	st, _, err = c.call(ctx, http.MethodGet, "https://x.example", "", nil)
	if st != 0 || !errors.Is(err, rtErr) {
		t.Fatalf("transport error: %d %v", st, err)
	}
	g13suKind(t, "transport error", err, StepUpTransport, "")
	fail = false

	errBody = true
	st, _, err = c.call(ctx, http.MethodGet, "https://x.example", "", nil)
	if st != 0 {
		t.Fatalf("unreadable body status %d", st)
	}
	g13suKind(t, "unreadable body", err, StepUpTransport, "read failed")
	errBody = false

	if _, _, err = c.call(ctx, http.MethodGet, "https://x.example", "", nil); err != nil {
		t.Fatal(err)
	}
	if seen.GetBody != nil || seen.Header.Get("Content-Type") != "" {
		t.Fatalf("a bodiless call carried a body or a content type: %v", seen.Header)
	}
	if _, _, err = c.call(ctx, http.MethodPost, "https://x.example", "", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if seen.GetBody == nil || seen.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("a JSON call lost its body or content type: %v", seen.Header)
	}

	for _, c2 := range []struct {
		status int
		ok     bool
	}{{199, false}, {200, true}, {299, true}, {300, false}} {
		status = c2.status
		st, _, err = c.call(ctx, http.MethodGet, "https://x.example", "", nil)
		if st != c2.status || (err == nil) != c2.ok {
			t.Fatalf("status %d: %d %v", c2.status, st, err)
		}
		if !c2.ok {
			var e *StepUpError
			if !errors.As(err, &e) || e.Kind != StepUpAPI || e.Status != c2.status {
				t.Fatalf("status %d: %#v", c2.status, err)
			}
		}
	}

	status, body = 200, strings.Repeat("a", 3<<20)
	if _, data, err := c.call(ctx, http.MethodGet, "https://x.example", "", nil); err != nil || len(data) != 1<<20 {
		t.Fatalf("body cap: %d %v", len(data), err)
	}
}

func TestG13StepUpHTTPError(t *testing.T) {
	for _, c := range []struct {
		status int
		body   string
		kind   StepUpKind
		msg    string
	}{
		{409, `{"errors":[]}`, StepUpAPI, "The request failed."},
		{409, `{}`, StepUpAPI, "The request failed."},
		{500, `x`, StepUpAPI, "The request failed."},
		{409, `{"errors":[{"message":""}]}`, StepUpAPI, "The request failed."},
		{403, `{"errors":[{"message":"m"}]}`, StepUpPrincipalMismatch, "m"},
	} {
		e := httpStepUpError(c.status, []byte(c.body))
		if e.Kind != c.kind || e.Status != c.status || e.Message != c.msg {
			t.Fatalf("%d %s: %+v", c.status, c.body, e)
		}
	}
}

func g13suEntry(id, grant, msg, exp string) string {
	return `{"id":"` + id + `","grant_ref":"` + grant + `","action":{"verb":"v","resource":"r"},"required_t":2,"threshold_message":"` + msg + `","expires_at":"` + exp + `"}`
}

func TestG13StepUpPending(t *testing.T) {
	ctx := context.Background()
	future := isoMs(g13suNow + 1)
	okList := `{"stepups":[` + g13suEntry("su_1", "g", "AQ", future) + `]}`
	list := func(status int, body string) g13suRT {
		return func(*http.Request) (*http.Response, error) { return g13suResp(status, body), nil }
	}

	_, err := g13suClient(t, nil, list(200, okList), errors.New("no token")).Pending(ctx)
	g13suKind(t, "token error", err, StepUpTransport, "Could not get the dashboard token.")

	_, err = g13suClient(t, nil, list(500, `{"errors":[{"message":"boom"}]}`), nil).Pending(ctx)
	var e *StepUpError
	if !errors.As(err, &e) || e.Kind != StepUpAPI || e.Status != 500 || e.Message != "boom" {
		t.Fatalf("server error: %#v", err)
	}

	for _, body := range []string{`{}`, `x`} {
		_, err = g13suClient(t, nil, list(200, body), nil).Pending(ctx)
		g13suKind(t, "list "+body, err, StepUpTransport, "Unreadable step-up list.")
	}
	for name, entry := range map[string]string{
		"bad expiry":    g13suEntry("su_1", "g", "AQ", "soon"),
		"empty id":      g13suEntry("", "g", "AQ", future),
		"empty grant":   g13suEntry("su_1", "", "AQ", future),
		"empty message": g13suEntry("su_1", "g", "", future),
	} {
		_, err = g13suClient(t, nil, list(200, `{"stepups":[`+entry+`]}`), nil).Pending(ctx)
		g13suKind(t, name, err, StepUpTransport, "Unreadable step-up entry.")
	}

	items, err := g13suClient(t, nil, list(200, `{"stepups":[`+g13suEntry("su_1", "g", "AQ", isoMs(g13suNow))+`]}`), nil).Pending(ctx)
	if err != nil || len(items) != 0 {
		t.Fatalf("a step-up expiring exactly now must be dropped: %+v %v", items, err)
	}
	items, err = g13suClient(t, nil, list(200, okList), nil).Pending(ctx)
	if err != nil || len(items) != 1 || items[0].ExpiresAt != g13suNow+1 {
		t.Fatalf("a step-up expiring after now: %+v %v", items, err)
	}
}

func TestG13StepUpApprove(t *testing.T) {
	ctx := context.Background()
	calls := 0
	ok := func(*http.Request) (*http.Response, error) {
		calls++
		return g13suResp(200, `{"status":"approved","allow":true}`), nil
	}
	c := g13suClient(t, nil, ok, nil)
	for _, m := range []string{"", "!!"} {
		_, err := c.Approve(ctx, PendingStepUp{ID: "su_1", ThresholdMessageB64u: m})
		g13suKind(t, "message "+m, err, StepUpInvalidThresholdMessage, "")
	}
	if res, err := c.Approve(ctx, PendingStepUp{ID: "su_1", ThresholdMessageB64u: "AQ"}); err != nil || !res.Anchored || res.HTTPStatus != 200 {
		t.Fatalf("one-byte message: %+v %v", res, err)
	}
	seed := make([]byte, 32)
	for _, failOn := range []int{1, 2} { // the public-key read, then the signing read
		calls = 0
		key := NewPrincipalDeviceKey(&g13suStore{val: seed, failOn: map[int]bool{failOn: true}})
		_, err := g13suClient(t, key, ok, nil).Approve(ctx, PendingStepUp{ID: "su_1", ThresholdMessageB64u: "AQ"})
		g13suKind(t, "key read failure", err, StepUpTransport, "Could not read the principal key.")
		if calls != 0 {
			t.Fatalf("load failure %d still called the server", failOn)
		}
	}
}

func TestG13StepUpDeny(t *testing.T) {
	ctx := context.Background()
	var got string
	rt := func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		return g13suResp(200, "{}"), nil
	}
	err := g13suClient(t, nil, rt, errors.New("no token")).Deny(ctx, PendingStepUp{ID: "su_1"}, "")
	g13suKind(t, "deny token error", err, StepUpTransport, "Could not get the dashboard token.")
	c := g13suClient(t, nil, rt, nil)
	if err := c.Deny(ctx, PendingStepUp{ID: "su_1"}, ""); err != nil || got != "{}" {
		t.Fatalf("deny without reason: %q %v", got, err)
	}
	if err := c.Deny(ctx, PendingStepUp{ID: "su_1"}, "r"); err != nil || got != `{"reason":"r"}` {
		t.Fatalf("deny with reason: %q %v", got, err)
	}
}
