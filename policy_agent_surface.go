package pca

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	ed "filippo.io/edwards25519"
)

// The exported surface of the policy-and-agent packages that the implementation files keep behind unexported helpers: the typed
// vault and connector errors, the fetch guard, the grant management client, OPRF key generation, analyzer enumeration, goal helpers
// and wallet constants.

// ---- vault errors (pca-connect) ----------------------------------------------------------------------------------

// NewNotAuthorizedError is the refusal for a PCActn that is not a valid, provider-bound authorization for this connection; checks is
// the verifier's per-check verdict map (nil for none).
func NewNotAuthorizedError(message string, checks map[string]bool) *VaultError {
	return newNotAuthorized(message, checks)
}

// NewScopeExceededError is the refusal for scopes that are not a subset of what the capability chain grants.
func NewScopeExceededError(provider string, requested, granted, missing []string) *VaultError {
	_, _ = requested, granted // the refusal names the provider and the missing scopes only
	return newScopeExceeded(provider, missing)
}

// NewExpiredNoRefreshError is the refusal for a stale access token with no refresh token to mint a fresh one.
func NewExpiredNoRefreshError(provider, connectionID string) *VaultError {
	return vaultErr("ExpiredNoRefreshError", "expired_no_refresh",
		fmt.Sprintf("connection '%s/%s' token is expired and has no refresh token", provider, connectionID))
}

// NewRefreshFailedError is the refusal for a refresh that did not yield a usable token; status is the provider's HTTP status (nil for none).
func NewRefreshFailedError(provider, detail string, status *float64) *VaultError {
	return newRefreshFailed(provider, detail, status)
}

// NewUnknownConnectionError is the refusal for an agent, provider and connection id with no stored connection.
func NewUnknownConnectionError(agentID, provider, connectionID string) *VaultError {
	return vaultErr("UnknownConnectionError", "unknown_connection",
		fmt.Sprintf("no connection for agent '%s' provider '%s' id '%s'", agentID, provider, connectionID))
}

// NewStoreError is the refusal for a connection store or encryption failure; message "" is the default text. It never carries the
// underlying error text.
func NewStoreError(message string) *VaultError {
	if message == "" {
		message = "the connection store failed"
	}
	return newStoreError(message)
}

// NewUnknownActionError is the refusal for a verb with no pinned action definition (no scope can be derived).
func NewUnknownActionError(verb string) *VaultError { return newUnknownAction(verb) }

// NewUnconfirmedActionError is the refusal for an action definition with no valid signed confirmation.
func NewUnconfirmedActionError(verb string) *VaultError {
	return vaultErr("UnconfirmedActionError", "unconfirmed_action",
		fmt.Sprintf("the definition of '%s' has no valid signed confirmation: refusing to release a credential", verb))
}

// NewRequestMismatchError is the refusal for an outbound request that does not re-derive the signed params digest.
func NewRequestMismatchError(message string) *VaultError {
	return vaultErr("RequestMismatchError", "request_mismatch", message)
}

// NewBearerReleaseDisabledError is the refusal of a bare bearer token without the explicit insecure opt-in.
func NewBearerReleaseDisabledError() *VaultError {
	return vaultErr("BearerReleaseDisabledError", "bearer_release_disabled",
		"this vault does not release bearer tokens to callers; use proxyCall(), or construct it with insecureBearerRelease: true (insecure: the caller can use the token for anything inside its scopes until it expires)")
}

// NewProxyFailedError is the refusal for a proxied call that failed after the action was spent.
func NewProxyFailedError(message string) *VaultError {
	return vaultErr("ProxyFailedError", "proxy_failed", message)
}

// ---- connector catalog errors and the default registry (pca-connectors) -------------------------------------------

// NewManifestValidationError is the error of a manifest that failed structural validation; issues lists every problem found.
func NewManifestValidationError(issues []string) *ConnectorError {
	return &ConnectorError{Name: "ManifestValidationError", Message: "invalid provider manifest: " + strings.Join(issues, "; "), Issues: append([]string{}, issues...)}
}

// NewUnknownProviderError is the error for a provider id with no registered manifest.
func NewUnknownProviderError(providerID string) *ConnectorError {
	return &ConnectorError{Name: "UnknownProviderError", Message: fmt.Sprintf("no connector registered for provider '%s'", providerID)}
}

// GetProvider is the manifest for id in the process-wide registry, or nil.
func GetProvider(id string) map[string]any { return connDefaultRegistry.Get(id) }

// ListProviders is every manifest in the process-wide registry, in ascending id order.
func ListProviders() []map[string]any { return connDefaultRegistry.List() }

// NewGnapInteractionError is a GNAP interaction refusal with one of the codes invalid_interaction, unknown_interaction,
// too_many_attempts, invalid_request, expired, wrong_state or unsupported_hash.
func NewGnapInteractionError(code, message string) error { return gnapInteractionErr(code, message) }

// NewScittLogError is a durable SCITT log refusal with one of the codes store_required, store_corrupt, append_contention,
// out_of_range or bad_statement.
func NewScittLogError(code, message string) error { return &CodedError{Code: code, Msg: message} }

// ---- the fetch guard (pca-fetch) -----------------------------------------------------------------------------------

// FetchRefusal is the 401/403 response a PCA fetch guard produces: Status, Header and Body are what to write to the caller.
type FetchRefusal = fetchDeny

// Status is the HTTP status of the refusal.
func (d *fetchDeny) Status() int { return d.status }

// Header is the response header of the refusal (content type, WWW-Authenticate challenge).
func (d *fetchDeny) Header() http.Header { return d.header.Clone() }

// Body is the JSON body of the refusal: {error, verdict, decision, escalation?}.
func (d *fetchDeny) Body() []byte { return append([]byte(nil), d.body...) }

// CreatePcaFetchGuard builds a verifier over an inbound request for code that composes the check itself. It returns the request to
// hand on (it carries the verdict in its context) or the refusal. It errors for a configuration the reference refuses to construct.
func CreatePcaFetchGuard(opts RequirePCAOptions) (func(r *http.Request) (*http.Request, *FetchRefusal), error) {
	return fetchGuard(opts)
}

// ---- the grant management client (pca-grants) ----------------------------------------------------------------------

// GrantApiError is a non-2xx answer of the grant management resource.
type GrantApiError struct {
	Status  int
	Code    string
	Message string
}

func (e *GrantApiError) Error() string { return e.Message }

// GrantClientOptions configures a GrantClient.
type GrantClientOptions struct {
	// BaseURL is the grant management resource's base URL.
	BaseURL string
	// HTTP is the transport (nil: a client with a 30 second timeout).
	HTTP *http.Client
	// FreshSigner is the authorization server's pinned token signer; when set, a pca-fresh-at header that does not verify is ignored.
	FreshSigner string
	// Headers returns extra request headers (credentials), or nil.
	Headers func() map[string]string
}

// GrantClient is a thin net/http client for the grant management resource. It carries the newest pca-fresh-at token it has seen: a
// token that does not verify under FreshSigner (when set) is ignored, and a token never replaces a fresher one.
type GrantClient struct {
	o      GrantClientOptions
	mu     sync.Mutex
	latest map[string]any
}

// NewGrantClient builds a client.
func NewGrantClient(o GrantClientOptions) *GrantClient {
	if o.HTTP == nil {
		o.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	o.BaseURL = strings.TrimSuffix(o.BaseURL, "/")
	return &GrantClient{o: o}
}

var grantClientCounters = []string{"revocation_epoch", "policy_revision", "ledger_tree_size", "budget_version"}

// FreshAt is the newest consistency token seen on any response (attach it to later requests for read-your-writes), or nil.
func (c *GrantClient) FreshAt() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.latest
}

// FoldFreshAt folds the newest token into a local state; nil when none was seen.
func (c *GrantClient) FoldFreshAt(state map[string]any) map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.latest == nil {
		return nil
	}
	return MergeFreshAt(c.latest, state)
}

func (c *GrantClient) fold(tok string) {
	v, err := ParseJSONLenient([]byte(tok))
	t, ok := v.(map[string]any)
	if err != nil || !ok {
		return // a malformed header is ignored: freshness is only ever tightened by a valid token
	}
	if c.o.FreshSigner != "" && !VerifyFreshAt(t, c.o.FreshSigner) {
		return
	}
	for _, k := range grantClientCounters {
		if !jsIsSafeInteger(t[k]) {
			return
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	newer := c.latest == nil
	if !newer {
		newer = true
		for _, k := range grantClientCounters {
			newer = newer && jsF(t[k]) >= jsF(c.latest[k])
		}
	}
	if newer {
		c.latest = t // monotone fold: never replace a fresher token with an older one
	}
}

func (c *GrantClient) call(method, path string, body any) (map[string]any, error) {
	var rd io.Reader
	if body != nil {
		b, err := Canonicalize(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader([]byte(b))
	}
	req, err := http.NewRequest(method, c.o.BaseURL+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	if l := c.FreshAt(); l != nil {
		if s, err := Canonicalize(l); err == nil {
			req.Header.Set("pca-fresh-at", s)
		}
	}
	if c.o.Headers != nil {
		for k, v := range c.o.Headers() {
			req.Header.Set(k, v)
		}
	}
	res, err := c.o.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if tok := res.Header.Get("pca-fresh-at"); tok != "" {
		c.fold(tok)
	}
	json, _ := ParseJSONLenient(raw)
	m, _ := json.(map[string]any)
	if m == nil {
		m = map[string]any{}
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		code, msg := "error", fmt.Sprintf("HTTP %d", res.StatusCode)
		if s, ok := m["error"].(string); ok {
			code = s
		}
		if s, ok := m["message"].(string); ok {
			msg = s
		}
		return nil, &GrantApiError{Status: res.StatusCode, Code: code, Message: msg}
	}
	return m, nil
}

// List lists grants; q may carry principal, agent, status, limit and cursor.
func (c *GrantClient) List(q map[string]string) (map[string]any, error) {
	p := url.Values{}
	for k, v := range q {
		p.Set(k, v)
	}
	qs := ""
	if len(p) > 0 {
		qs = "?" + p.Encode()
	}
	return c.call("GET", GrantsPath+qs, nil)
}

// Inspect reads one grant.
func (c *GrantClient) Inspect(id string) (map[string]any, error) {
	return c.call("GET", GrantsPath+"/"+approvalEncodeURIComponent(id), nil)
}

// Amend submits an amend request for a grant.
func (c *GrantClient) Amend(id string, req map[string]any) (map[string]any, error) {
	return c.call("POST", GrantsPath+"/"+approvalEncodeURIComponent(id)+"/amend", req)
}

// Revoke revokes a grant; scope "" means "grant"; sig "" sends no body (an admin revoke).
func (c *GrantClient) Revoke(id, scope, sig string) (map[string]any, error) {
	if scope == "" {
		scope = "grant"
	}
	var body any
	if sig != "" {
		body = map[string]any{"sig": sig}
	}
	return c.call("DELETE", GrantsPath+"/"+approvalEncodeURIComponent(id)+"?scope="+scope, body)
}

// RequestNeeds asks for more authority on a grant.
func (c *GrantClient) RequestNeeds(id string, needs []any) (map[string]any, error) {
	return c.call("POST", GrantsPath+"/"+approvalEncodeURIComponent(id)+"/needs", map[string]any{"needs": needs})
}

// ApproveNeeds approves a need request with the principal's signature; stepUpRef "" omits the step-up reference.
func (c *GrantClient) ApproveNeeds(needID string, approved []any, sig, stepUpRef string) (map[string]any, error) {
	body := map[string]any{"approved": approved, "sig": sig}
	if stepUpRef != "" {
		body["step_up_ref"] = stepUpRef
	}
	return c.call("POST", NeedsPath+"/"+approvalEncodeURIComponent(needID)+"/approve", body)
}

// DenyNeeds denies a need request.
func (c *GrantClient) DenyNeeds(needID string) (map[string]any, error) {
	return c.call("POST", NeedsPath+"/"+approvalEncodeURIComponent(needID)+"/deny", nil)
}

// ---- OPRF key generation (pca-oprf) --------------------------------------------------------------------------------

// OprfSerializeElement is the canonical 32-byte ristretto255 encoding of a group element given in any valid encoding.
func OprfSerializeElement(element []byte) ([]byte, error) {
	p, err := rDecode(element)
	if err != nil {
		return nil, fmt.Errorf("SerializeElement: %w", err)
	}
	return rEncode(p), nil
}

// OprfRandomScalar is a uniformly random non-zero scalar (RFC 9497 RandomScalar) as 32 little-endian bytes. It fails closed when the
// entropy source keeps returning zero.
func OprfRandomScalar() ([]byte, error) {
	for attempt := 0; attempt < 8; attempt++ {
		var wide [64]byte
		if _, err := io.ReadFull(rand.Reader, wide[:]); err != nil {
			return nil, err
		}
		s, err := ed.NewScalar().SetUniformBytes(wide[:])
		if err != nil {
			return nil, err
		}
		if s.Equal(ed.NewScalar()) != 1 {
			return s.Bytes(), nil
		}
	}
	return nil, errors.New("randomScalar: entropy source returned zero repeatedly (RNG failure); refusing to continue")
}

// OprfRandomKeyPair is a fresh random key pair (mode-independent; the public key is skS * G).
func OprfRandomKeyPair() (secretKey, publicKey []byte, err error) {
	sk, err := OprfRandomScalar()
	if err != nil {
		return nil, nil, err
	}
	pk, err := OprfPublicKeyFor(sk)
	if err != nil {
		return nil, nil, err
	}
	return sk, pk, nil
}

// ---- analyzer enumeration (pca-analyzer) ----------------------------------------------------------------------------

// AnalyzerTightenInterval narrows a numeric interval by one comparison (op eq, lt, lte, gt or gte against a finite value); any other
// operator or a non-finite value leaves it unchanged.
func AnalyzerTightenInterval(iv AnlIv, op, value any) AnlIv { return anlTighten(iv, op, value) }

// AnalyzerRepresentatives walks the probe grid, calling yield for each representative action until yield returns true.
func AnalyzerRepresentatives(pr *AnlProbes, yield func(*AnlRep) bool) { anlEachRep(pr, yield) }

// AnalyzerSearch walks the grid to the first representative the predicate accepts; overflow is true when the grid is larger than max.
func AnalyzerSearch(pr *AnlProbes, pred func(*AnlRep) bool, max float64) (hit *AnlRep, overflow bool) {
	return anlSearch(pr, pred, max)
}

// AnalyzerCoverage measures how much of a policy a traffic sample exercises: clause, boundary and mutation coverage, the unreachable
// clauses and the surviving mutants. opts may carry epsilon.
func AnalyzerCoverage(policy, traffic, opts any) map[string]any {
	return anlCoverage(policy, traffic, opts)
}

// ---- goal and wallet helpers ---------------------------------------------------------------------------------------

// GoalEmptyHist is the history of an action stream with nothing admitted yet (a fresh copy).
func GoalEmptyHist() map[string]any { return goalFreshHist() }

// GoalDecisionOf names a decision code: 2 allow, 1 escalate, anything else deny.
func GoalDecisionOf(d int64) string { return goalDecisionOf(d) }

// GoalRankOf orders decisions from the most permissive (allow 0, escalate 1, deny 2).
func GoalRankOf(d any) int { return goalRankOf(d) }

// WalletEmptyNoise is the noise count of a channel with no canary answers yet.
var WalletEmptyNoise = WalletNoiseCounts{}

// WalletCatLabel is the label of categorical value i of a dimension, as used in coordinates: its raw value ("⊥" for any other).
func WalletCatLabel(d WalletDim, i int) (string, error) {
	if d.Kind != "cat" || i < 0 || i >= len(d.Values) {
		return "", errors.New("catLabel: no such categorical value")
	}
	return d.Values[i].Value, nil
}
