package pca

// HTTP client for a real OpenID Provider's CIBA endpoints (OpenID CIBA Core 1.0): start a backchannel authentication request and wait
// for the human's decision by POLL or PING. Poll discipline follows CIBA Core 7.3 / 11: never faster than the OP's interval, at least
// 5 s added on every slow_down, stop at expires_in. A terminal answer is cached, so a settled flow is never re-sent to the token
// endpoint (an approved auth_req_id is single-use at real providers). Authenticates with client_secret_basic. The returned tokens are
// the OP's response and are not verified here: verify an ID token with your own JOSE library.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	cibaGrant                = "urn:openid:params:grant-type:ciba"
	cibaSlowDownStepSec      = 5
	cibaMinNotifTokenChars   = 22
	cibaMaxNotifTokenChars   = 1024
	cibaDefaultTimeout       = 30 * time.Second
	cibaMaxBackoffMs         = 60000
	cibaMaxConsecutiveFailed = 5
	cibaMaxBody              = 1 << 20
)

var cibaPrintableTokenRE = regexp.MustCompile(`^[\x21-\x7E]+$`)

// CibaProviderError is an error response from the OP (RFC 6749 5.2 / CIBA Core 13), or a malformed reply or transport failure.
type CibaProviderError struct {
	Status           int
	Code             string
	ErrorDescription string
	// Retryable is true for network errors, timeouts, 5xx and non-JSON replies; false for a definitive OP answer.
	Retryable bool
}

func (e *CibaProviderError) Error() string {
	s := fmt.Sprintf("ciba: provider returned %d %s", e.Status, e.Code)
	if e.ErrorDescription != "" {
		s += " (" + e.ErrorDescription + ")"
	}
	return s
}

var errCibaAborted = errors.New("ciba: wait aborted")

// CibaClientConfig configures the client. HTTPClient, Sleep and Now are injectable; zero values take the defaults.
type CibaClientConfig struct {
	BackchannelAuthenticationEndpoint string
	TokenEndpoint                     string
	ClientID                          string
	ClientSecret                      string
	HTTPClient                        *http.Client
	// Sleep waits d or returns early (with ctx.Err()) when ctx ends. Default: a timer.
	Sleep func(ctx context.Context, d time.Duration) error
	// Now is the clock in ms since the epoch. Default: time.Now.
	Now func() int64
	// Timeout is the per-request timeout. Default 30 s.
	Timeout time.Duration
	// AllowInsecureHTTP permits http:// endpoints (local test providers only: the secret and auth_req_id travel on them).
	AllowInsecureHTTP bool
}

// CibaInitiateOptions: CibaRequestOptions plus exactly one hint (LoginHint, LoginHintToken or IDTokenHint).
type CibaInitiateOptions struct {
	CibaRequestOptions
	LoginHintToken, IDTokenHint *string
	// Delivery is "poll" (default) or "ping"; ping sends a client_notification_token (generated if not given).
	Delivery                string
	ClientNotificationToken *string
	AcrValues, UserCode     *string
}

// CibaFlow is a started request.
type CibaFlow struct {
	AuthReqID               string
	ExpiresInSec            int64
	IntervalSec             int64
	StartedAt               int64 // ms epoch the OP answered
	Delivery                string
	ClientNotificationToken *string
	Request                 CibaAuthRequest
}

// CibaTokenResponse is the OP's token response.
type CibaTokenResponse struct {
	AccessToken  string  `json:"access_token"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    *int64  `json:"expires_in,omitempty"`
	IDToken      *string `json:"id_token,omitempty"`
	RefreshToken *string `json:"refresh_token,omitempty"`
	Scope        *string `json:"scope,omitempty"`
}

// CibaPollResult: Status is "pending" (IntervalSec set), "approved" (Tokens set), "denied" (Error set) or "expired".
type CibaPollResult struct {
	Status      string
	IntervalSec float64
	Tokens      *CibaTokenResponse
	Error       string
}

// CibaClient talks to one OP.
type CibaClient struct {
	cfg     CibaClientConfig
	hc      *http.Client
	basic   string
	timeout time.Duration
	now     func() int64
}

func cibaCheckEndpoint(name, v string, allowInsecure bool) error {
	u, err := url.Parse(v)
	if err != nil || u.Host == "" {
		return fmt.Errorf("ciba: %s is not a valid URL", name)
	}
	if u.Scheme == "https" || (u.Scheme == "http" && allowInsecure) {
		return nil
	}
	return fmt.Errorf("ciba: %s must be an https:// URL (set AllowInsecureHTTP only for a local test provider)", name)
}

// cibaFormEscape is application/x-www-form-urlencoded escaping with %20 for space (RFC 6749 2.3.1).
func cibaFormEscape(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }

// NewCibaClient validates the config and returns a client.
func NewCibaClient(cfg CibaClientConfig) (*CibaClient, error) {
	c := &CibaClient{cfg: cfg, hc: cfg.HTTPClient, timeout: cfg.Timeout, now: cfg.Now}
	if c.hc == nil {
		c.hc = http.DefaultClient
	}
	if c.timeout == 0 {
		c.timeout = cibaDefaultTimeout
	}
	if c.timeout < 0 {
		return nil, errors.New("ciba: Timeout must be positive")
	}
	if c.now == nil {
		c.now = func() int64 { return time.Now().UnixMilli() }
	}
	if err := cibaCheckEndpoint("BackchannelAuthenticationEndpoint", cfg.BackchannelAuthenticationEndpoint, cfg.AllowInsecureHTTP); err != nil {
		return nil, err
	}
	if err := cibaCheckEndpoint("TokenEndpoint", cfg.TokenEndpoint, cfg.AllowInsecureHTTP); err != nil {
		return nil, err
	}
	if hasLoneSurrogate(cfg.ClientID) || hasLoneSurrogate(cfg.ClientSecret) {
		return nil, errors.New("URI malformed") // encodeURIComponent throws on a lone surrogate
	}
	c.basic = "Basic " + base64.StdEncoding.EncodeToString([]byte(cibaFormEscape(cfg.ClientID)+":"+cibaFormEscape(cfg.ClientSecret)))
	return c, nil
}

// post sends one form with a hard timeout; ctx also cancels the request. A caller cancel is errCibaAborted.
func (c *CibaClient) post(ctx context.Context, endpoint string, form url.Values) (int, []byte, error) {
	if ctx.Err() != nil {
		return 0, nil, errCibaAborted
	}
	rctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, &CibaProviderError{Code: "network_error", ErrorDescription: err.Error(), Retryable: true}
	}
	req.Header.Set("Authorization", c.basic)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := c.hc.Do(req)
	var body []byte
	if err == nil {
		body, err = io.ReadAll(io.LimitReader(res.Body, cibaMaxBody))
		res.Body.Close()
	}
	if err != nil {
		if ctx.Err() != nil {
			return 0, nil, errCibaAborted
		}
		return 0, nil, &CibaProviderError{Code: "network_error", ErrorDescription: err.Error(), Retryable: true}
	}
	return res.StatusCode, body, nil
}

func cibaReadJSON(status int, body []byte) (map[string]any, error) {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, &CibaProviderError{Status: status, Code: "invalid_response", ErrorDescription: "the provider reply was not JSON", Retryable: true}
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, &CibaProviderError{Status: status, Code: "invalid_response", ErrorDescription: "the provider reply was not a JSON object"}
	}
	return m, nil
}

func cibaProviderErr(status int, b map[string]any) *CibaProviderError {
	e := &CibaProviderError{Status: status, Code: "invalid_response"}
	if s, ok := b["error"].(string); ok {
		e.Code = s
	}
	if s, ok := b["error_description"].(string); ok {
		e.ErrorDescription = s
	}
	return e
}

func cibaPositiveInt(v any, name string, status int) (int64, error) {
	f, ok := v.(float64)
	if !ok || f != math.Trunc(f) || f <= 0 || f > 1<<53-1 {
		return 0, &CibaProviderError{Status: status, Code: "invalid_response", ErrorDescription: name + " must be a positive integer"}
	}
	return int64(f), nil
}

// Initiate starts a backchannel authentication request for a step-up.
func (c *CibaClient) Initiate(ctx context.Context, stepUp map[string]any, o CibaInitiateOptions) (CibaFlow, error) {
	var f CibaFlow
	hints := 0
	for _, h := range []*string{o.LoginHint, o.LoginHintToken, o.IDTokenHint} {
		if h != nil {
			hints++
		}
	}
	if hints != 1 {
		return f, errors.New("ciba: exactly one of LoginHint, LoginHintToken, IDTokenHint is required (CIBA Core 7.1)")
	}
	delivery := o.Delivery
	if delivery == "" {
		delivery = "poll"
	}
	if delivery != "poll" && delivery != "ping" {
		return f, errors.New("ciba: Delivery must be \"poll\" or \"ping\"")
	}
	var notif *string
	if delivery == "ping" {
		if o.ClientNotificationToken != nil {
			notif = o.ClientNotificationToken
		} else {
			t := NewClientNotificationToken()
			notif = &t
		}
	}
	if t := o.ClientNotificationToken; t != nil && (len(*t) < cibaMinNotifTokenChars || len(*t) > cibaMaxNotifTokenChars || !cibaPrintableTokenRE.MatchString(*t)) {
		return f, fmt.Errorf("ciba: ClientNotificationToken must be %d..%d printable characters (>= 128 bits, CIBA Core 7.1)", cibaMinNotifTokenChars, cibaMaxNotifTokenChars)
	}
	req, err := ToCibaAuthRequest(stepUp, o.CibaRequestOptions)
	if err != nil {
		return f, err
	}
	form := url.Values{}
	form.Set("scope", req.Scope)
	form.Set("binding_message", req.BindingMessage)
	form.Set("requested_expiry", strconv.FormatFloat(req.RequestedExpiry, 'f', -1, 64))
	for k, v := range map[string]*string{"login_hint": o.LoginHint, "login_hint_token": o.LoginHintToken, "id_token_hint": o.IDTokenHint,
		"acr_values": o.AcrValues, "user_code": o.UserCode, "client_notification_token": notif} {
		if v != nil {
			form.Set(k, *v)
		}
	}
	status, raw, err := c.post(ctx, c.cfg.BackchannelAuthenticationEndpoint, form)
	if err != nil {
		return f, err
	}
	body, err := cibaReadJSON(status, raw)
	if err != nil {
		return f, err
	}
	if status < 200 || status > 299 {
		return f, cibaProviderErr(status, body)
	}
	id, ok := body["auth_req_id"].(string)
	if !ok || id == "" {
		return f, &CibaProviderError{Status: status, Code: "invalid_response", ErrorDescription: "auth_req_id missing"}
	}
	exp, err := cibaPositiveInt(body["expires_in"], "expires_in", status)
	if err != nil {
		return f, err
	}
	interval := int64(5) // CIBA Core 7.3 default
	if iv, has := body["interval"]; has {
		if interval, err = cibaPositiveInt(iv, "interval", status); err != nil {
			return f, err
		}
	}
	return CibaFlow{AuthReqID: id, ExpiresInSec: exp, IntervalSec: interval, StartedAt: c.now(), Delivery: delivery,
		ClientNotificationToken: notif, Request: req}, nil
}

type cibaPollCall struct {
	done chan struct{}
	res  CibaPollResult
	err  error
}

// CibaPoller polls the token endpoint for one flow. Safe for concurrent use.
type CibaPoller struct {
	c                  *CibaClient
	flow               CibaFlow
	deadline           int64
	mu                 sync.Mutex
	intervalMs, nextAt int64
	settled            *CibaPollResult
	inflight           *cibaPollCall
	wake               chan struct{}
	failures           int
}

// Poller returns the poller for a flow.
func (c *CibaClient) Poller(flow CibaFlow) *CibaPoller {
	ms := flow.IntervalSec * 1000
	return &CibaPoller{c: c, flow: flow, intervalMs: ms, nextAt: flow.StartedAt + ms, deadline: flow.StartedAt + flow.ExpiresInSec*1000}
}

// IntervalSec is the current poll interval (grows on slow_down).
func (p *CibaPoller) IntervalSec() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return float64(p.intervalMs) / 1000
}

// Notify records that a PING arrived: the next Poll may go out immediately, and a sleeping Poll wakes now.
func (p *CibaPoller) Notify() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextAt = p.c.now()
	if p.wake != nil {
		close(p.wake)
		p.wake = nil
	}
}

func (p *CibaPoller) pause(ctx context.Context, ms int64) error {
	p.mu.Lock()
	w := make(chan struct{})
	p.wake = w
	p.mu.Unlock()
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { // ends the sleep early on Notify
		select {
		case <-w:
			cancel()
		case <-sctx.Done():
		}
	}()
	d := time.Duration(ms) * time.Millisecond
	if p.c.cfg.Sleep != nil {
		_ = p.c.cfg.Sleep(sctx, d)
	} else {
		t := time.NewTimer(d)
		select {
		case <-t.C:
		case <-sctx.Done():
			t.Stop()
		}
	}
	p.mu.Lock()
	if p.wake == w {
		p.wake = nil
	}
	p.mu.Unlock()
	if ctx.Err() != nil {
		return errCibaAborted
	}
	return nil
}

// Poll sleeps until the interval allows it, then asks the token endpoint once. Concurrent callers share one in-flight request.
func (p *CibaPoller) Poll(ctx context.Context) (CibaPollResult, error) {
	p.mu.Lock()
	if call := p.inflight; call != nil {
		p.mu.Unlock()
		<-call.done
		return call.res, call.err
	}
	call := &cibaPollCall{done: make(chan struct{})}
	p.inflight = call
	p.mu.Unlock()
	call.res, call.err = p.doPoll(ctx)
	p.mu.Lock()
	p.inflight = nil
	p.mu.Unlock()
	close(call.done)
	return call.res, call.err
}

func (p *CibaPoller) settle(r CibaPollResult) CibaPollResult {
	p.mu.Lock()
	p.settled = &r
	p.mu.Unlock()
	return r
}

func (p *CibaPoller) doPoll(ctx context.Context) (CibaPollResult, error) {
	p.mu.Lock()
	if p.settled != nil {
		defer p.mu.Unlock()
		return *p.settled, nil
	}
	wait := p.nextAt - p.c.now()
	p.mu.Unlock()
	if wait > 0 {
		if err := p.pause(ctx, wait); err != nil {
			return CibaPollResult{}, err
		}
	}
	p.mu.Lock()
	if p.settled != nil {
		defer p.mu.Unlock()
		return *p.settled, nil
	}
	p.mu.Unlock()
	if p.c.now() >= p.deadline {
		return p.settle(CibaPollResult{Status: "expired"}), nil
	}
	status, raw, err := p.c.post(ctx, p.c.cfg.TokenEndpoint, url.Values{"grant_type": {cibaGrant}, "auth_req_id": {p.flow.AuthReqID}})
	var body map[string]any
	if err == nil && status >= 500 {
		err = &CibaProviderError{Status: status, Code: "server_error", ErrorDescription: "the provider answered with a server error", Retryable: true}
	}
	if err == nil {
		body, err = cibaReadJSON(status, raw)
	}
	var pe *CibaProviderError
	if err != nil {
		if errors.As(err, &pe) && pe.Retryable {
			p.mu.Lock()
			p.failures++
			delay := math.Min(cibaMaxBackoffMs, float64(p.intervalMs)*math.Pow(2, math.Min(float64(p.failures), 6)))
			p.nextAt = p.c.now() + int64(delay)
			p.mu.Unlock()
		}
		return CibaPollResult{}, err
	}
	p.mu.Lock()
	p.failures = 0
	p.nextAt = p.c.now() + p.intervalMs
	p.mu.Unlock()
	if status >= 200 && status <= 299 {
		var t CibaTokenResponse
		at, ok1 := body["access_token"].(string)
		tt, ok2 := body["token_type"].(string)
		if !ok1 || !ok2 || json.Unmarshal(raw, &t) != nil {
			return CibaPollResult{}, &CibaProviderError{Status: status, Code: "invalid_response", ErrorDescription: "token response lacks access_token / token_type"}
		}
		t.AccessToken, t.TokenType = at, tt
		return p.settle(CibaPollResult{Status: "approved", Tokens: &t}), nil
	}
	e := cibaProviderErr(status, body)
	switch e.Code {
	case "authorization_pending":
		p.mu.Lock()
		defer p.mu.Unlock()
		return CibaPollResult{Status: "pending", IntervalSec: float64(p.intervalMs) / 1000}, nil
	case "slow_down":
		p.mu.Lock()
		defer p.mu.Unlock()
		p.intervalMs += cibaSlowDownStepSec * 1000
		p.nextAt = p.c.now() + p.intervalMs
		return CibaPollResult{Status: "pending", IntervalSec: float64(p.intervalMs) / 1000}, nil
	case "access_denied":
		return p.settle(CibaPollResult{Status: "denied", Error: e.Code}), nil
	case "expired_token":
		return p.settle(CibaPollResult{Status: "expired"}), nil
	}
	return CibaPollResult{}, e
}

// Wait polls until the flow settles (approved, denied or expired). Up to 5 consecutive transient failures are retried.
func (p *CibaPoller) Wait(ctx context.Context) (CibaPollResult, error) {
	transient := 0
	for {
		if ctx.Err() != nil {
			return CibaPollResult{}, errCibaAborted
		}
		r, err := p.Poll(ctx)
		if err == nil {
			transient = 0
			if r.Status != "pending" {
				return r, nil
			}
			continue
		}
		var pe *CibaProviderError
		transient++
		if !errors.As(err, &pe) || !pe.Retryable || transient >= cibaMaxConsecutiveFailed {
			return CibaPollResult{}, err
		}
	}
}
