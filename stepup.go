package pca

// Step-up client for the principal's device: list the pending step-ups of an instance, approve one with the principal's
// Ed25519 device key, or deny it. The device signature over the step-up's threshold message is the credential of the
// cosign call, so no session is needed to approve; listing and denying go through the dashboard API with a bearer token.
//
//   - DashboardURL + a dashboard bearer token (a service key or console session token) serve the list and deny calls
//     (deny needs an owner or admin role).
//   - InstanceURL (the host the agent talks to) serves the public, self-authenticating cosign call.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// SecretStore is where the 32-byte Ed25519 seed is persisted. Load returns (nil, nil) when nothing is stored.
type SecretStore interface {
	Load() ([]byte, error)
	Save(secret []byte) error
	Delete() error
}

// MemorySecretStore keeps the seed in memory, for tests and previews only.
type MemorySecretStore struct {
	mu    sync.Mutex
	value []byte
}

// Load implements SecretStore.
func (s *MemorySecretStore) Load() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.value...), nil
}

// Save implements SecretStore.
func (s *MemorySecretStore) Save(secret []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.value = append([]byte(nil), secret...)
	return nil
}

// Delete implements SecretStore.
func (s *MemorySecretStore) Delete() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.value = nil
	return nil
}

// StepUpKind classifies a StepUpError.
type StepUpKind int

// The StepUpError kinds.
const (
	// StepUpNoDeviceKey: no principal key is stored yet; call Generate or ImportSecret.
	StepUpNoDeviceKey StepUpKind = iota + 1
	// StepUpInvalidSecret: the principal secret is not a base64url 32-byte Ed25519 seed.
	StepUpInvalidSecret
	// StepUpInvalidThresholdMessage: the server's threshold_message is not valid base64url.
	StepUpInvalidThresholdMessage
	// StepUpInvalidStepUp: the step-up id is not a plain URL segment.
	StepUpInvalidStepUp
	// StepUpPrincipalMismatch: HTTP 403, this device key is not the grant's principal key; Message is the server's guidance.
	StepUpPrincipalMismatch
	// StepUpAPI: any other non-2xx answer (409 already approved, denied or expired, 401, 404, 422, ...).
	StepUpAPI
	// StepUpTransport: a network failure or an unreadable body.
	StepUpTransport
)

// StepUpError is everything the step-up client returns as an error.
type StepUpError struct {
	Kind    StepUpKind
	Status  int // the HTTP status, for StepUpPrincipalMismatch and StepUpAPI
	Message string
	Err     error
}

func (e *StepUpError) Error() string {
	if e.Kind == StepUpAPI {
		return fmt.Sprintf("HTTP %d: %s", e.Status, e.Message)
	}
	return e.Message
}

// Unwrap returns the underlying cause (a transport error).
func (e *StepUpError) Unwrap() error { return e.Err }

// validStepUpID: a path segment the client may put in a URL (letters, digits, '_', '-' and '.', not "." or "..").
func validStepUpID(id string) bool {
	if id == "" || id == "." || id == ".." || len(id) > 200 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func stepUpErr(kind StepUpKind, msg string) *StepUpError {
	return &StepUpError{Kind: kind, Message: msg}
}

// IsStepUpKind reports whether err is a StepUpError of the kind.
func IsStepUpKind(err error, kind StepUpKind) bool {
	var e *StepUpError
	return errors.As(err, &e) && e.Kind == kind
}

// PrincipalDeviceKey is the principal's Ed25519 device key.
//
// Honest caveat: the PCA principal key MUST be Ed25519, and hardware key stores rarely offer a portable Ed25519 key, so
// this is a software key: the 32-byte seed lives in the SecretStore you provide (put it in your platform's secure store).
// Once loaded it is in process memory. Gate approvals behind a user-presence check in your application.
type PrincipalDeviceKey struct{ store SecretStore }

// NewPrincipalDeviceKey backs the key with store.
func NewPrincipalDeviceKey(store SecretStore) *PrincipalDeviceKey {
	return &PrincipalDeviceKey{store: store}
}

// Exists reports whether a key is stored.
func (k *PrincipalDeviceKey) Exists() bool {
	s, err := k.store.Load()
	return err == nil && s != nil && len(s) > 0
}

func (k *PrincipalDeviceKey) save(seed []byte) (string, error) {
	if err := k.store.Save(seed); err != nil {
		return "", &StepUpError{Kind: StepUpTransport, Message: "Could not persist the principal key.", Err: err}
	}
	return publicOf(seed), nil
}

func publicOf(seed []byte) string {
	return b64.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
}

// Generate creates a fresh key (replacing any existing one) and returns its public key (base64url) to register as the
// grant's principal.
func (k *PrincipalDeviceKey) Generate() (string, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return "", err
	}
	return k.save(seed)
}

// ImportSecret imports an existing principal secret (a base64url 32-byte seed). The key MUST match the grant's principal.
// It returns the public key.
func (k *PrincipalDeviceKey) ImportSecret(secretB64u string) (string, error) {
	raw, ok := DecodeB64uStrict(secretB64u, ed25519.SeedSize)
	if !ok {
		return "", stepUpErr(StepUpInvalidSecret, "The principal secret must be a base64url-encoded 32-byte Ed25519 seed.")
	}
	return k.save(raw)
}

func (k *PrincipalDeviceKey) loadSeed() ([]byte, error) {
	seed, err := k.store.Load()
	if err != nil {
		return nil, &StepUpError{Kind: StepUpTransport, Message: "Could not read the principal key.", Err: err}
	}
	if len(seed) == 0 {
		return nil, stepUpErr(StepUpNoDeviceKey, "No principal device key is stored on this device.")
	}
	if len(seed) != ed25519.SeedSize {
		return nil, stepUpErr(StepUpInvalidSecret, "The principal secret must be a base64url-encoded 32-byte Ed25519 seed.")
	}
	return seed, nil
}

// ExportSecret returns the secret (base64url seed) for backup or migration. Treat it like a password.
func (k *PrincipalDeviceKey) ExportSecret() (string, error) {
	seed, err := k.loadSeed()
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(seed), nil
}

// PublicKey returns the public key (base64url), as registered on the grant.
func (k *PrincipalDeviceKey) PublicKey() (string, error) {
	seed, err := k.loadSeed()
	if err != nil {
		return "", err
	}
	return publicOf(seed), nil
}

// Sign Ed25519-signs message and returns the signature as base64url.
func (k *PrincipalDeviceKey) Sign(message []byte) (string, error) {
	seed, err := k.loadSeed()
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), message)), nil
}

// Delete removes the key from the store.
func (k *PrincipalDeviceKey) Delete() error { return k.store.Delete() }

// PendingStepUp is an action waiting for the principal's device signature.
type PendingStepUp struct {
	ID             string
	GrantRef       string
	ActionVerb     string
	ActionResource string
	RequiredT      int
	// ThresholdMessageB64u is the base64url of the exact bytes the principal key must sign.
	ThresholdMessageB64u string
	// ExpiresAt is the expiry in epoch milliseconds.
	ExpiresAt int64
}

// Summary is a human summary for a confirmation sheet, for example "payments.refund on order/1234".
func (p PendingStepUp) Summary() string { return p.ActionVerb + " on " + p.ActionResource }

// ApproveResult is the result of an approval. Anchored is true once enough roles signed and the action was released.
type ApproveResult struct {
	Status     string
	Anchored   bool
	HTTPStatus int
}

// StepUpClientOptions configures NewStepUpClient.
type StepUpClientOptions struct {
	DashboardURL string
	InstanceURL  string
	AccountID    string
	InstanceID   string
	Key          *PrincipalDeviceKey
	// Token returns the dashboard bearer token.
	Token func(ctx context.Context) (string, error)
	// HTTP is the client to use (nil: a client with a 30 second timeout).
	HTTP *http.Client
	// Now is the clock in epoch ms (nil: the wall clock); expired step-ups are dropped from Pending.
	Now func() int64
}

// StepUpClient lists, approves and denies PCA step-ups from the principal's device.
type StepUpClient struct {
	o         StepUpClientOptions
	dashboard *url.URL
	instance  *url.URL
	http      *http.Client
}

func parseBase(raw, what string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("pca: %s must be an http(s) URL", what)
	}
	return u, nil
}

// NewStepUpClient validates the options and builds the client.
func NewStepUpClient(o StepUpClientOptions) (*StepUpClient, error) {
	d, err := parseBase(o.DashboardURL, "DashboardURL")
	if err != nil {
		return nil, err
	}
	i, err := parseBase(o.InstanceURL, "InstanceURL")
	if err != nil {
		return nil, err
	}
	if o.Key == nil || o.Token == nil || !validStepUpID(o.AccountID) || !validStepUpID(o.InstanceID) {
		return nil, errors.New("pca: NewStepUpClient needs Key, Token and a valid AccountID and InstanceID")
	}
	h := o.HTTP
	if h == nil {
		h = &http.Client{Timeout: 30 * time.Second}
	}
	if o.Now == nil {
		o.Now = func() int64 { return time.Now().UnixMilli() }
	}
	return &StepUpClient{o: o, dashboard: d, instance: i, http: h}, nil
}

func (c *StepUpClient) stepupsURL(parts ...string) string {
	elems := append([]string{"v1/dashboard/accounts", c.o.AccountID, "instances", c.o.InstanceID, "pca/stepups"}, parts...)
	return c.dashboard.JoinPath(elems...).String()
}

// maxStepUpBody bounds what the client reads from a response.
const maxStepUpBody = 1 << 20

func (c *StepUpClient) call(ctx context.Context, method, target, bearer string, body []byte) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return 0, nil, &StepUpError{Kind: StepUpTransport, Message: err.Error(), Err: err}
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, &StepUpError{Kind: StepUpTransport, Message: err.Error(), Err: err}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxStepUpBody))
	if err != nil {
		return 0, nil, &StepUpError{Kind: StepUpTransport, Message: err.Error(), Err: err}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, data, httpStepUpError(resp.StatusCode, data)
	}
	return resp.StatusCode, data, nil
}

// httpStepUpError reads the { errors: [{ code, message }] } envelope.
func httpStepUpError(status int, body []byte) *StepUpError {
	msg := "The request failed."
	var env struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(body, &env) == nil && len(env.Errors) > 0 && env.Errors[0].Message != "" {
		msg = env.Errors[0].Message
	}
	if status == http.StatusForbidden {
		return &StepUpError{Kind: StepUpPrincipalMismatch, Status: status, Message: msg}
	}
	return &StepUpError{Kind: StepUpAPI, Status: status, Message: msg}
}

func (c *StepUpClient) bearer(ctx context.Context) (string, error) {
	t, err := c.o.Token(ctx)
	if err != nil {
		return "", &StepUpError{Kind: StepUpTransport, Message: "Could not get the dashboard token.", Err: err}
	}
	return t, nil
}

// Pending lists the pending, not-yet-expired step-ups.
func (c *StepUpClient) Pending(ctx context.Context) ([]PendingStepUp, error) {
	tok, err := c.bearer(ctx)
	if err != nil {
		return nil, err
	}
	target := c.stepupsURL() + "?status=pending"
	_, body, err := c.call(ctx, http.MethodGet, target, tok, nil)
	if err != nil {
		return nil, err
	}
	var list struct {
		Stepups []struct {
			ID     string `json:"id"`
			Grant  string `json:"grant_ref"`
			Action struct {
				Verb     string `json:"verb"`
				Resource string `json:"resource"`
			} `json:"action"`
			RequiredT int    `json:"required_t"`
			Message   string `json:"threshold_message"`
			ExpiresAt string `json:"expires_at"`
		} `json:"stepups"`
	}
	if json.Unmarshal(body, &list) != nil || list.Stepups == nil {
		return nil, stepUpErr(StepUpTransport, "Unreadable step-up list.")
	}
	now := c.o.Now()
	out := []PendingStepUp{}
	for _, s := range list.Stepups {
		exp, err := time.Parse(time.RFC3339Nano, s.ExpiresAt)
		if err != nil || s.ID == "" || s.Grant == "" || s.Message == "" {
			return nil, stepUpErr(StepUpTransport, "Unreadable step-up entry.")
		}
		if exp.UnixMilli() <= now {
			continue
		}
		out = append(out, PendingStepUp{ID: s.ID, GrantRef: s.Grant, ActionVerb: s.Action.Verb, ActionResource: s.Action.Resource,
			RequiredT: s.RequiredT, ThresholdMessageB64u: s.Message, ExpiresAt: exp.UnixMilli()})
	}
	return out, nil
}

// Approve signs the step-up's threshold message with the device key and submits it. It returns a StepUpError of kind
// StepUpPrincipalMismatch (server 403) when this key is not the grant's principal.
func (c *StepUpClient) Approve(ctx context.Context, stepUp PendingStepUp) (ApproveResult, error) {
	message, ok := DecodeB64uStrict(stepUp.ThresholdMessageB64u, -1)
	if !ok || len(message) == 0 {
		return ApproveResult{}, stepUpErr(StepUpInvalidThresholdMessage, "The step-up's threshold message is not valid base64url.")
	}
	if !validStepUpID(stepUp.ID) {
		return ApproveResult{}, stepUpErr(StepUpInvalidStepUp, "The step-up id is not valid.")
	}
	pub, err := c.o.Key.PublicKey()
	if err != nil {
		return ApproveResult{}, err
	}
	sig, err := c.o.Key.Sign(message)
	if err != nil {
		return ApproveResult{}, err
	}
	payload, _ := json.Marshal(map[string]string{"role": "principal", "publicKey": pub, "sig": sig})
	target := c.instance.JoinPath("v1/pca/stepups", stepUp.ID, "cosign").String()
	status, body, err := c.call(ctx, http.MethodPost, target, "", payload)
	if err != nil {
		return ApproveResult{}, err
	}
	// 200 + allow:true = anchored; 202 = more roles still required.
	var r struct {
		Status string `json:"status"`
		Allow  bool   `json:"allow"`
	}
	_ = json.Unmarshal(body, &r)
	return ApproveResult{Status: r.Status, Anchored: r.Allow, HTTPStatus: status}, nil
}

// Deny denies a pending step-up (dashboard endpoint; audited; owner or admin). reason may be empty.
func (c *StepUpClient) Deny(ctx context.Context, stepUp PendingStepUp, reason string) error {
	if !validStepUpID(stepUp.ID) {
		return stepUpErr(StepUpInvalidStepUp, "The step-up id is not valid.")
	}
	tok, err := c.bearer(ctx)
	if err != nil {
		return err
	}
	payload := []byte("{}")
	if reason != "" {
		payload, _ = json.Marshal(map[string]string{"reason": reason})
	}
	_, _, err = c.call(ctx, http.MethodPost, c.stepupsURL(stepUp.ID, "deny"), tok, payload)
	return err
}
