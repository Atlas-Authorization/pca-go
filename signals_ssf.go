package pca

// SSF streams (OpenID Shared Signals Framework 1.0): stream configuration checks, receiver-side stream health, the verification
// round trip, the RFC 8936 poll queue, the RFC 8935 push response, the CAEP risk / assurance builders and the framework-neutral
// stream management API (SSF 8.1). Mirrors the reference (@atlasauth/pca-signals ssf-stream / ssf-manage).

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

const (
	DeliveryPush = "urn:ietf:rfc:8935"
	DeliveryPoll = "urn:ietf:rfc:8936"
)

// StreamStatuses are the SSF stream status values.
var StreamStatuses = []string{"enabled", "paused", "disabled"}

func sigRandomB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// sigArray is Array.isArray with the value as a list ([]string counts).
func sigArray(v any) ([]any, bool) {
	switch t := v.(type) {
	case []any:
		return t, true
	case []string:
		out := make([]any, len(t))
		for i, s := range t {
			out[i] = s
		}
		return out, true
	}
	return nil, false
}

// sigStrs is `Array.isArray(x) && x.every(nonEmptyString)`.
func sigStrs(v any) ([]string, bool) {
	l, ok := sigArray(v)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(l))
	for _, x := range l {
		s, ok := x.(string)
		if !ok || s == "" {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// jsWhitespace is the set JavaScript's \s matches.
func jsWhitespace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

// httpsURL is /^https:\/\/[^\s]+$/.
func httpsURL(v any) bool {
	s, ok := v.(string)
	if !ok || !strings.HasPrefix(s, "https://") || len(s) == len("https://") {
		return false
	}
	return !strings.ContainsFunc(s[len("https://"):], jsWhitespace)
}

// nonNegSafeInt is Number.isSafeInteger(v) && v >= 0 && !Object.is(v, -0).
func nonNegSafeInt(v any) bool {
	f, ok := sigNumber(v)
	return ok && f == math.Trunc(f) && f >= 0 && f <= 9007199254740991 && !math.Signbit(f)
}

// ValidateStreamConfig runs the SSF 8.1.1 shape checks and returns the problems found (empty = valid).
func ValidateStreamConfig(c any) []string {
	o, ok := c.(map[string]any)
	if !ok {
		return []string{"not an object"}
	}
	e := []string{}
	if !strNE(o["stream_id"]) {
		e = append(e, "stream_id is required")
	}
	if !strNE(o["iss"]) {
		e = append(e, "iss is required")
	}
	if l, ok := sigStrs(o["aud"]); !strNE(o["aud"]) && !(ok && len(l) > 0) {
		e = append(e, "aud must be a non-empty string or array")
	}
	delivered, dOK := sigStrs(o["events_delivered"])
	supported, sOK := sigStrs(o["events_supported"])
	if !dOK || len(delivered) == 0 {
		e = append(e, "events_delivered must be a non-empty array of event type URIs")
	}
	if sigHas(o, "events_supported") && !sOK {
		e = append(e, "events_supported must be an array of URIs")
	}
	if sigHas(o, "events_requested") {
		if l, ok := sigStrs(o["events_requested"]); !ok || len(l) == 0 {
			e = append(e, "events_requested must be a non-empty array of URIs")
		}
	}
	if dOK && sOK {
		for _, x := range delivered {
			if !slices.Contains(supported, x) {
				e = append(e, "events_delivered must be a subset of events_supported")
				break
			}
		}
	}
	d, _ := o["delivery"].(map[string]any)
	if m := d["method"]; d == nil || (m != DeliveryPush && m != DeliveryPoll) {
		e = append(e, "delivery.method must be the RFC 8935 or RFC 8936 URI")
	} else if !httpsURL(d["endpoint_url"]) {
		e = append(e, "delivery.endpoint_url must be an https URL")
	}
	if sigHas(o, "min_verification_interval") && !nonNegSafeInt(o["min_verification_interval"]) {
		e = append(e, "min_verification_interval must be a non-negative integer (seconds)")
	}
	return e
}

func minVerificationInterval(config map[string]any) float64 {
	if f, ok := sigNumber(config["min_verification_interval"]); ok {
		return f
	}
	return 0
}

// ---- receiver-side stream health ---------------------------------------------------------------------------------------------

// StreamHealthOptions (0 = the default): VerifyTimeoutSec 60, VerifiedWithinSec 300, FailAfter 3, MaxPending 16.
type StreamHealthOptions struct {
	VerifyTimeoutSec, VerifiedWithinSec, FailAfter, MaxPending float64
}

func sigOrDefault(v, d float64) float64 {
	if v == 0 {
		return d
	}
	return v
}

// StreamHealth is the receiver-side health of one stream. Times are epoch seconds passed in; a verification state is single use,
// expiring, and only valid if this tracker issued it. Safe for concurrent use.
type StreamHealth struct {
	mu                                     sync.Mutex
	config                                 map[string]any
	o                                      StreamHealthOptions
	status                                 string
	lastEvent, lastVerified, lastRequested *float64
	fails, rejected                        int
	pending                                map[string]float64
}

func NewStreamHealth(config map[string]any, o *StreamHealthOptions) *StreamHealth {
	h := &StreamHealth{config: config, status: "enabled", pending: map[string]float64{}}
	if o != nil {
		h.o = *o
	}
	return h
}

func (h *StreamHealth) SetStatus(s string) error {
	if !slices.Contains(StreamStatuses, s) {
		return errors.New("unknown stream status")
	}
	h.mu.Lock()
	h.status = s
	h.mu.Unlock()
	return nil
}

func maxPtr(p *float64, now float64) *float64 {
	v := now
	if p != nil {
		v = math.Max(*p, now)
	} else {
		v = math.Max(0, now)
	}
	return &v
}

func (h *StreamHealth) RecordEvent(nowSec float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastEvent = maxPtr(h.lastEvent, nowSec)
}

// RequestVerification issues a verification state, or "" when the stream is not enabled, inside min_verification_interval, or
// too many are pending.
func (h *StreamHealth) RequestVerification(nowSec float64) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.status != "enabled" {
		return ""
	}
	if !finite(nowSec) {
		return ""
	}
	if h.lastRequested != nil && !(nowSec-*h.lastRequested >= minVerificationInterval(h.config)) {
		return ""
	}
	h.expire(nowSec)
	if !(float64(len(h.pending)) < sigOrDefault(h.o.MaxPending, 16)) {
		return ""
	}
	state := sigRandomB64(16)
	exp := nowSec + sigOrDefault(h.o.VerifyTimeoutSec, 60)
	if !finite(exp) { // a NaN or infinite timeout would leave the request pending forever
		return ""
	}
	h.pending[state] = exp
	t := nowSec
	h.lastRequested = &t
	return state
}

// AckVerification accepts a verification state this tracker issued and that has not expired (once).
func (h *StreamHealth) AckVerification(state string, nowSec float64) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !finite(nowSec) {
		h.rejected++
		return false
	}
	h.expire(nowSec)
	if _, ok := h.pending[state]; !ok {
		h.rejected++
		return false
	}
	delete(h.pending, state)
	t := nowSec
	h.lastVerified = &t
	h.lastEvent = maxPtr(h.lastEvent, nowSec)
	h.fails = 0
	return true
}

func (h *StreamHealth) expire(nowSec float64) {
	for k, exp := range h.pending {
		if nowSec > exp {
			delete(h.pending, k)
			h.fails++
		}
	}
}

// StreamHealthReport is the health verdict (state: healthy | degraded | failing | paused | disabled | unverified).
type StreamHealthReport struct {
	State                           string   `json:"state"`
	Status                          string   `json:"status"`
	Reasons                         []string `json:"reasons"`
	LastEventAt                     *float64 `json:"last_event_at,omitempty"`
	LastVerifiedAt                  *float64 `json:"last_verified_at,omitempty"`
	PendingVerifications            int      `json:"pending_verifications"`
	ConsecutiveVerificationFailures int      `json:"consecutive_verification_failures"`
	RejectedVerifications           int      `json:"rejected_verifications"`
}

func (h *StreamHealth) Report(nowSec float64) StreamHealthReport {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.expire(nowSec)
	within := sigOrDefault(h.o.VerifiedWithinSec, 300)
	r := StreamHealthReport{Status: h.status, Reasons: []string{}, LastEventAt: h.lastEvent, LastVerifiedAt: h.lastVerified,
		PendingVerifications: len(h.pending), ConsecutiveVerificationFailures: h.fails, RejectedVerifications: h.rejected}
	switch {
	case h.status == "disabled":
		r.State, r.Reasons = "disabled", append(r.Reasons, "stream is disabled: no events are transmitted or held")
	case h.status == "paused":
		r.State, r.Reasons = "paused", append(r.Reasons, "stream is paused: events may be delayed")
	case !(float64(h.fails) < sigOrDefault(h.o.FailAfter, 3)):
		r.State, r.Reasons = "failing", append(r.Reasons, fmt.Sprintf("%d consecutive verification requests timed out", h.fails))
	case h.lastVerified == nil:
		r.State, r.Reasons = "unverified", append(r.Reasons, "no verification round trip has completed")
	case !(finite(nowSec) && nowSec-*h.lastVerified <= within):
		r.State, r.Reasons = "degraded", append(r.Reasons, "last verified "+jsNumberString(nowSec-*h.lastVerified)+"s ago, over "+jsNumberString(within)+"s")
	default:
		r.State = "healthy"
	}
	return r
}

// RevocationFreshWithin: may the verifier assume no pushed revocation was missed in the last maxAgeSec? Only if the stream is
// enabled and a verified round trip completed inside that window; otherwise fall back to the signed epoch pull bound.
func (h *StreamHealth) RevocationFreshWithin(maxAgeSec, nowSec float64) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.status == "enabled" && h.lastVerified != nil && finite(nowSec) && nowSec-*h.lastVerified <= maxAgeSec
}

// ---- verification (transmitter side) ----------------------------------------------------------------------------------------

// VerificationStream is a transmitter's view of one stream for HandleVerificationRequest.
type VerificationStream struct {
	Config           map[string]any
	LastVerification *float64
}

// VerificationOutcome: 204 with the signed verification SET, else 400 / 404 / 429 with the error.
type VerificationOutcome struct {
	Status int    `json:"status"`
	SET    string `json:"set,omitempty"`
	Error  string `json:"error,omitempty"`
}

// HandleVerificationRequest is SSF 8.1.4.2: 400 malformed, 404 unknown stream, 429 inside min_verification_interval, else 204
// with the verification SET signed by key (a 32-byte Ed25519 seed). req is the JSON request body.
func HandleVerificationRequest(streams map[string]*VerificationStream, req any, nowSec float64, key []byte) (VerificationOutcome, error) {
	r, _ := req.(map[string]any)
	sid, ok := r["stream_id"].(string)
	state, hasState := r["state"]
	if _, isStr := state.(string); r == nil || !ok || (hasState && !isStr) {
		return VerificationOutcome{Status: 400, Error: "stream_id (string) is required; state must be a string"}, nil
	}
	s := streams[sid]
	if s == nil {
		return VerificationOutcome{Status: 404, Error: "no such stream"}, nil
	}
	if s.Config == nil {
		return VerificationOutcome{}, errors.New("stream has no config")
	}
	if s.LastVerification != nil && nowSec-*s.LastVerification < minVerificationInterval(s.Config) {
		return VerificationOutcome{Status: 429, Error: "verification requested too soon"}, nil
	}
	t := nowSec
	s.LastVerification = &t
	ev := sigObj{m: map[string]any{}}
	if hasState {
		ev = sigObj{[]string{"state"}, map[string]any{"state": state}}
	}
	a := BuildSETArgs{Audience: s.Config["aud"], Key: key}
	a.Issuer, _ = s.Config["iss"].(string)
	if id, ok := s.Config["stream_id"].(string); ok {
		a.Subject = &id
	}
	vt := SetEventTypes["verification"]
	set, err := buildSETEvents(sigObj{[]string{vt}, map[string]any{vt: ev}}, a)
	if err != nil {
		return VerificationOutcome{}, err
	}
	return VerificationOutcome{Status: 204, SET: set}, nil
}

// ---- RFC 8936 poll queue -----------------------------------------------------------------------------------------------------

// PollQueue is the transmitter queue: a SET is retained until acknowledged; unacknowledged ones are retransmitted; receiver errors
// are recorded. Safe for concurrent use.
type PollQueue struct {
	mu     sync.Mutex
	keys   []string
	q      map[string]string
	errors []map[string]any
}

func NewPollQueue() *PollQueue { return &PollQueue{q: map[string]string{}} }

func (p *PollQueue) Enqueue(jti, set string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.q == nil {
		p.q = map[string]string{}
	}
	if _, ok := p.q[jti]; !ok {
		p.keys = append(p.keys, jti)
	}
	p.q[jti] = set
}

func (p *PollQueue) remove(jti string) bool {
	if _, ok := p.q[jti]; !ok {
		return false
	}
	delete(p.q, jti)
	p.keys = slices.DeleteFunc(p.keys, func(k string) bool { return k == jti })
	return true
}

func (p *PollQueue) Depth() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.q)
}

// Errors are the receiver-reported SET errors ({jti, err, description}), oldest first.
func (p *PollQueue) Errors() []map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]map[string]any{}, p.errors...)
}

// Poll answers one RFC 8936 poll request (the JSON body: maxEvents, ack, setErrs): acknowledged and errored SETs leave the
// queue, then up to maxEvents queued SETs are returned ({sets, moreAvailable?}).
func (p *PollQueue) Poll(req any) (map[string]any, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if req == nil {
		return nil, errors.New("Cannot read properties of null (reading 'maxEvents')")
	}
	r, _ := req.(map[string]any)
	mx, hasMax := r["maxEvents"]
	if hasMax && !nonNegSafeInt(mx) {
		return nil, errors.New("maxEvents must be a non-negative integer")
	}
	switch a := r["ack"].(type) {
	case nil:
	case []any:
		for _, j := range a {
			if s, ok := j.(string); ok {
				p.remove(s)
			}
		}
	default:
		return nil, errors.New("req.ack is not iterable")
	}
	if se := r["setErrs"]; se != nil {
		if m, ok := se.(map[string]any); ok {
			for _, jti := range jsKeys(m) {
				if !p.remove(jti) {
					continue
				}
				e := m[jti]
				if e == nil {
					return nil, errors.New("Cannot read properties of null (reading 'err')")
				}
				rec := map[string]any{"jti": jti}
				if em, ok := e.(map[string]any); ok {
					for _, k := range []string{"err", "description"} {
						if v, has := em[k]; has {
							rec[k] = v
						}
					}
				}
				p.errors = append(p.errors, rec)
			}
		}
	}
	limit := math.Inf(1)
	if hasMax {
		limit, _ = sigNumber(mx)
	}
	sets := map[string]any{}
	n := 0
	for _, jti := range p.keys {
		if float64(n) >= limit {
			break
		}
		sets[jti] = p.q[jti]
		n++
	}
	out := map[string]any{"sets": sets}
	if len(p.q) > n {
		out["moreAvailable"] = true
	}
	return out, nil
}

// PushResponse is the RFC 8935 receiver status for a ReceiveSET outcome (a ReceiveSETResult or its JSON shape): 202 on success,
// else 400 with {err, description}.
func PushResponse(r any) (map[string]any, error) {
	var m map[string]any
	switch t := r.(type) {
	case ReceiveSETResult:
		m = t.Map()
	case *ReceiveSETResult:
		if t == nil {
			return nil, errors.New("Cannot read properties of null (reading 'ok')")
		}
		m = t.Map()
	case nil:
		return nil, errors.New("Cannot read properties of null (reading 'ok')")
	default:
		m, _ = r.(map[string]any)
	}
	if jsTruthy(m["ok"]) {
		return map[string]any{"status": 202}, nil
	}
	err := "invalid_request"
	switch m["code"] {
	case "verify_failed":
		err = "invalid_key"
	case "misconfigured", "replay_store_error":
		err = "access_denied"
	}
	body := map[string]any{"err": err}
	if v, has := m["reason"]; has {
		body["description"] = v
	}
	return map[string]any{"status": 400, "body": body}, nil
}

// ---- CAEP builders -----------------------------------------------------------------------------------------------------------

// CaepSETArgs: the event payload, and (assurance only) the level order that derives change_direction.
type CaepSETArgs struct {
	Issuer   string
	Audience any
	Key      []byte
	Event    map[string]any
	Order    []string
}

// RiskLevelChangeSET builds a CAEP risk-level-change SET.
func RiskLevelChangeSET(a CaepSETArgs) (string, error) {
	t := SetEventTypes["riskLevelChange"]
	return buildSETEvents(sigObj{[]string{t}, map[string]any{t: sigObj{jsKeys(a.Event), a.Event}}}, BuildSETArgs{Issuer: a.Issuer, Audience: a.Audience, Key: a.Key})
}

// AssuranceLevelChangeSET builds a CAEP assurance-level-change SET; change_direction is derived when absent and both levels are in
// Order (a non-nil Order, even empty, is consulted).
func AssuranceLevelChangeSET(a CaepSETArgs) (string, error) {
	keys := jsKeys(a.Event)
	e := make(map[string]any, len(a.Event)+1)
	for k, v := range a.Event {
		e[k] = v
	}
	prev, hasPrev := e["previous_level"]
	if _, hasDir := e["change_direction"]; hasPrev && !hasDir && a.Order != nil {
		idx := func(v any) int {
			if s, ok := v.(string); ok {
				return slices.Index(a.Order, s)
			}
			return -1
		}
		if i, j := idx(prev), idx(e["current_level"]); i >= 0 && j >= 0 && i != j {
			e["change_direction"] = map[bool]string{true: "increase", false: "decrease"}[j > i]
			keys = append(keys, "change_direction")
		}
	}
	t := SetEventTypes["assuranceLevelChange"]
	return buildSETEvents(sigObj{[]string{t}, map[string]any{t: sigObj{keys, e}}}, BuildSETArgs{Issuer: a.Issuer, Audience: a.Audience, Key: a.Key})
}

// ---- SSF stream management API -----------------------------------------------------------------------------------------------

// StreamRecord is one stream as the management API stores it.
type StreamRecord struct {
	Receiver         string          `json:"receiver"`
	Config           map[string]any  `json:"config"`
	EventsRequested  []string        `json:"events_requested,omitempty"`
	Status           string          `json:"status"`
	StatusReason     *string         `json:"status_reason,omitempty"`
	Subjects         map[string]bool `json:"subjects"`
	LastVerification *float64        `json:"lastVerification,omitempty"`
}

func sigClone(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = sigClone(x)
		}
		return m
	case []any:
		l := make([]any, len(t))
		for i, x := range t {
			l[i] = sigClone(x)
		}
		return l
	case []string:
		return append([]string{}, t...)
	}
	return v
}

// Clone is a deep copy (structuredClone).
func (r *StreamRecord) Clone() *StreamRecord {
	if r == nil {
		return nil
	}
	c := *r
	c.Config, _ = sigClone(r.Config).(map[string]any)
	if r.EventsRequested != nil {
		c.EventsRequested = append([]string{}, r.EventsRequested...)
	}
	if r.StatusReason != nil {
		s := *r.StatusReason
		c.StatusReason = &s
	}
	c.Subjects = make(map[string]bool, len(r.Subjects))
	for k, v := range r.Subjects {
		c.Subjects[k] = v
	}
	if r.LastVerification != nil {
		f := *r.LastVerification
		c.LastVerification = &f
	}
	return &c
}

// StreamEntry is one [id, record] of a receiver's streams (JSON: a two-element array).
type StreamEntry struct {
	ID     string
	Record *StreamRecord
}

func (e StreamEntry) MarshalJSON() ([]byte, error) {
	r, err := json.Marshal(e.Record)
	if err != nil {
		return nil, err
	}
	var sb strings.Builder
	sb.WriteByte('[')
	lenientString(&sb, e.ID)
	sb.WriteByte(',')
	sb.Write(r)
	sb.WriteByte(']')
	return []byte(sb.String()), nil
}

// StreamStore persists stream records; Get returns nil for an unknown id. ListByReceiver keeps creation order.
type StreamStore interface {
	Get(id string) (*StreamRecord, error)
	Put(id string, r *StreamRecord) error
	Delete(id string) error
	ListByReceiver(receiver string) ([]StreamEntry, error)
}

// MemoryStreamStore is an in-process StreamStore (records are copied in and out).
type MemoryStreamStore struct {
	mu   sync.Mutex
	keys []string
	m    map[string]*StreamRecord
}

func NewMemoryStreamStore() *MemoryStreamStore {
	return &MemoryStreamStore{m: map[string]*StreamRecord{}}
}

func (s *MemoryStreamStore) Get(id string) (*StreamRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[id].Clone(), nil
}

func (s *MemoryStreamStore) Put(id string, r *StreamRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[id]; !ok {
		s.keys = append(s.keys, id)
	}
	s.m[id] = r.Clone()
	return nil
}

func (s *MemoryStreamStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[id]; ok {
		delete(s.m, id)
		s.keys = slices.DeleteFunc(s.keys, func(k string) bool { return k == id })
	}
	return nil
}

func (s *MemoryStreamStore) ListByReceiver(receiver string) ([]StreamEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []StreamEntry{}
	for _, id := range s.keys {
		if r := s.m[id]; r.Receiver == receiver {
			out = append(out, StreamEntry{id, r.Clone()})
		}
	}
	return out, nil
}

// TransmitterMetadata is SSF 7.1 transmitter configuration metadata (served at /.well-known/ssf-configuration). deliveryMethods
// nil = push and poll; jwksURI "" = omitted.
func TransmitterMetadata(issuer string, deliveryMethods []string, base, jwksURI string) map[string]any {
	if deliveryMethods == nil {
		deliveryMethods = []string{DeliveryPush, DeliveryPoll}
	}
	out := map[string]any{"spec_version": "1_0", "issuer": issuer, "delivery_methods_supported": deliveryMethods, "default_subjects": "NONE"}
	if jwksURI != "" {
		out["jwks_uri"] = jwksURI
	}
	for _, p := range []string{"configuration", "status", "add_subject", "remove_subject", "verification"} {
		out[p+"_endpoint"] = base + "/ssf/" + p
	}
	return out
}

// SsfReceiver is an authenticated receiver: its id and the aud its streams carry (a string or a list of strings).
type SsfReceiver struct {
	ID  string
	Aud any
}

// SsfRequest is one management request: method, path (its last segment names the endpoint), query and the JSON body.
type SsfRequest struct {
	Method string
	Path   string
	Query  map[string]any
	Body   any
}

// SsfResponse is {status, body?}.
type SsfResponse struct {
	Status int `json:"status"`
	Body   any `json:"body,omitempty"`
}

// SsfManageOptions configures SsfManagementHandler. Required: Store, Issuer, EventsSupported, PollEndpoint, SigningKey (a 32-byte
// Ed25519 seed) and Deliver. Defaults: DeliveryMethods push and poll, MaxStreamsPerReceiver 1, MaxSubjectsPerStream 10000, Now the
// wall clock (epoch seconds), NewID 16 random base64url characters.
type SsfManageOptions struct {
	Store                 StreamStore
	Issuer                string
	EventsSupported       []string
	DeliveryMethods       []string
	PollEndpoint          func(streamID string) string
	SigningKey            []byte
	Deliver               func(stream *StreamRecord, set string) error
	MaxStreamsPerReceiver int
	MaxSubjectsPerStream  int
	Now                   func() float64
	NewID                 func() string
}

var (
	ssfEndpoints           = []string{"configuration", "status", "add_subject", "remove_subject", "verification"}
	ssfReceiverSupplied    = []string{"events_requested", "delivery", "description"}
	ssfTransmitterSupplied = []string{"stream_id", "iss", "aud", "events_supported", "events_delivered", "min_verification_interval"}
	ssfNotFound            = SsfResponse{404, map[string]any{"error": "not_found"}}
	ssfNotAllowed          = SsfResponse{405, map[string]any{"error": "method_not_allowed"}}
)

func ssfBad(m string) SsfResponse {
	return SsfResponse{400, map[string]any{"error": "invalid_request", "description": m}}
}

// ssfSubjectKey is the canonical key of a subject identifier: members sorted by UTF-16 code unit, array-index names first (object
// semantics), values in their own member order. "" for a value that is not a subject identifier.
func ssfSubjectKey(s any) string {
	m, ok := s.(map[string]any)
	if !ok || !strNE(m["format"]) {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
	var idx, rest []string
	for _, k := range keys {
		if _, ok := jsArrayIndex(k); ok {
			idx = append(idx, k)
		} else {
			rest = append(rest, k)
		}
	}
	sort.Slice(idx, func(i, j int) bool { a, _ := jsArrayIndex(idx[i]); b, _ := jsArrayIndex(idx[j]); return a < b })
	k, err := sigJSON(sigObj{append(idx, rest...), m})
	if err != nil {
		return ""
	}
	return k
}

// sigSlice16 is String.prototype.slice(0, n) (UTF-16 code units).
func sigSlice16(s string, n int) string {
	u := utf16Units(s)
	if len(u) <= n {
		return s
	}
	var sb strings.Builder
	for i := 0; i < n; i++ {
		c := u[i]
		switch {
		case utf16.IsSurrogate(rune(c)) && c < 0xdc00 && i+1 < n && u[i+1] >= 0xdc00 && u[i+1] <= 0xdfff:
			sb.WriteRune(utf16.DecodeRune(rune(c), rune(u[i+1])))
			i++
		case utf16.IsSurrogate(rune(c)): // a lone surrogate, kept in its WTF-8 form as the package's strings carry it
			sb.Write([]byte{0xed, byte(0xa0 | (c>>6)&0x1f), byte(0x80 | c&0x3f)})
		default:
			sb.WriteRune(rune(c))
		}
	}
	return sb.String()
}

// SsfManagement is the framework-neutral SSF 8.1 stream management API.
type SsfManagement struct {
	o            SsfManageOptions
	methods      []string
	authenticate func(req SsfRequest) (*SsfReceiver, error)
}

// SsfManagementHandler builds the management API. authenticate returns the receiver, or nil (401). A stream belongs to one
// receiver; anyone else sees 404, never 403. Any internal error is a 500.
func SsfManagementHandler(o SsfManageOptions, authenticate func(req SsfRequest) (*SsfReceiver, error)) *SsfManagement {
	h := &SsfManagement{o: o, methods: o.DeliveryMethods, authenticate: authenticate}
	if h.methods == nil {
		h.methods = []string{DeliveryPush, DeliveryPoll}
	}
	if h.o.NewID == nil {
		h.o.NewID = func() string { return sigRandomB64(12) }
	}
	if h.o.MaxStreamsPerReceiver == 0 {
		h.o.MaxStreamsPerReceiver = 1
	}
	if h.o.MaxSubjectsPerStream == 0 {
		h.o.MaxSubjectsPerStream = 10_000
	}
	if h.o.Now == nil {
		h.o.Now = func() float64 { return math.Floor(float64(time.Now().UnixMilli()) / 1000) }
	}
	return h
}

// Handle serves one request: an SsfRequest, or its JSON shape ({method, path, query, body}).
func (h *SsfManagement) Handle(req any) (resp SsfResponse) {
	defer func() {
		if recover() != nil {
			resp = SsfResponse{500, map[string]any{"error": "server_error"}}
		}
	}()
	var r SsfRequest
	var bad bool
	switch t := req.(type) {
	case SsfRequest:
		r = t
	case *SsfRequest:
		if t == nil {
			bad = true
		} else {
			r = *t
		}
	default:
		m, _ := req.(map[string]any)
		var ok1, ok2 bool
		r.Method, ok1 = m["method"].(string)
		r.Path, ok2 = m["path"].(string)
		r.Query, _ = m["query"].(map[string]any)
		r.Body = m["body"]
		bad = !ok1 || !ok2
	}
	rcv, err := h.authenticate(r)
	if err != nil {
		return SsfResponse{500, map[string]any{"error": "server_error"}}
	}
	if rcv == nil {
		return SsfResponse{401, map[string]any{"error": "unauthenticated"}}
	}
	if bad { // a path or method that is not a string
		return SsfResponse{500, map[string]any{"error": "server_error"}}
	}
	resp, err = h.route(r, rcv)
	if err != nil {
		return SsfResponse{500, map[string]any{"error": "server_error"}}
	}
	return resp
}

func (h *SsfManagement) own(rcv *SsfReceiver, id any) (*StreamRecord, error) {
	s, ok := id.(string)
	if !ok {
		return nil, nil
	}
	rec, err := h.o.Store.Get(s)
	if err != nil || rec == nil || rec.Receiver != rcv.ID {
		return nil, err
	}
	return rec, nil
}

func (h *SsfManagement) delivered(requested []string) []any {
	out := []any{}
	for _, e := range h.o.EventsSupported {
		if requested == nil || slices.Contains(requested, e) {
			out = append(out, e)
		}
	}
	return out
}

func eventsRequestedOK(v any) ([]string, bool) {
	l, ok := sigStrs(v)
	return l, ok && len(l) > 0
}

func (h *SsfManagement) deliveryFor(id string, d any, present bool) (map[string]any, string) {
	poll := func() map[string]any {
		return map[string]any{"method": DeliveryPoll, "endpoint_url": h.o.PollEndpoint(id)}
	}
	if !present {
		if !slices.Contains(h.methods, DeliveryPoll) {
			return nil, "delivery is required: this transmitter does not support poll"
		}
		return poll(), ""
	}
	dm, _ := d.(map[string]any)
	method, ok := dm["method"].(string)
	if !ok || !slices.Contains(h.methods, method) {
		return nil, "delivery.method is not supported by this transmitter"
	}
	if method == DeliveryPoll { // transmitter-set; a receiver value is ignored
		return poll(), ""
	}
	if !httpsURL(dm["endpoint_url"]) {
		return nil, "push delivery needs an https endpoint_url"
	}
	return map[string]any{"method": DeliveryPush, "endpoint_url": dm["endpoint_url"]}, ""
}

func (h *SsfManagement) build(id string, rcv *SsfReceiver, requested []string, delivery map[string]any, description *string) map[string]any {
	sup := make([]any, len(h.o.EventsSupported))
	for i, e := range h.o.EventsSupported {
		sup[i] = e
	}
	c := map[string]any{"stream_id": id, "iss": h.o.Issuer, "aud": sigClone(rcv.Aud), "events_supported": sup,
		"events_delivered": h.delivered(requested), "delivery": delivery}
	if description != nil {
		c["description"] = sigSlice16(*description, 256)
	}
	return c
}

func ssfStatusBody(id any, s *StreamRecord) map[string]any {
	out := map[string]any{"stream_id": id, "status": s.Status}
	if s.StatusReason != nil {
		out["reason"] = *s.StatusReason
	}
	return out
}

func (h *SsfManagement) route(req SsfRequest, rcv *SsfReceiver) (SsfResponse, error) {
	var seg string
	for _, p := range strings.Split(req.Path, "/") {
		if p != "" {
			seg = p
		}
	}
	q := req.Query
	b, _ := req.Body.(map[string]any)
	m := strings.ToUpper(req.Method)
	if !slices.Contains(ssfEndpoints, seg) {
		return ssfNotFound, nil
	}
	qsid, hasQsid := q["stream_id"]
	str := func(k string) (*string, bool) { // b[k] absent (nil, true), a string, or not a string (nil, false)
		v, has := b[k]
		if !has {
			return nil, true
		}
		s, ok := v.(string)
		return &s, ok
	}
	switch seg {
	case "configuration":
		switch m {
		case "POST":
			if b == nil {
				return ssfBad("a JSON object body is required"), nil
			}
			for _, k := range jsKeys(b) {
				if !slices.Contains(ssfReceiverSupplied, k) {
					return ssfBad(fmt.Sprintf("'%s' is not a receiver-supplied member", k)), nil
				}
			}
			er, hasER := b["events_requested"]
			requested, ok := eventsRequestedOK(er)
			if hasER && !ok {
				return ssfBad("events_requested must be a non-empty array of event type URIs"), nil
			}
			desc, ok := str("description")
			if !ok {
				return ssfBad("description must be a string"), nil
			}
			list, err := h.o.Store.ListByReceiver(rcv.ID)
			if err != nil {
				return SsfResponse{}, err
			}
			if len(list) >= h.o.MaxStreamsPerReceiver {
				return SsfResponse{409, map[string]any{"error": "conflict", "description": "this receiver already has the maximum number of streams"}}, nil
			}
			id := h.o.NewID()
			dv, has := b["delivery"]
			d, why := h.deliveryFor(id, dv, has)
			if d == nil {
				return ssfBad(why), nil
			}
			if len(h.delivered(requested)) == 0 {
				return ssfBad("none of events_requested is supported by this transmitter"), nil
			}
			config := h.build(id, rcv, requested, d, desc)
			if problems := ValidateStreamConfig(config); len(problems) > 0 {
				return ssfBad(strings.Join(problems, "; ")), nil
			}
			rec := &StreamRecord{Receiver: rcv.ID, Config: config, EventsRequested: requested, Status: "enabled", Subjects: map[string]bool{}}
			if err := h.o.Store.Put(id, rec); err != nil {
				return SsfResponse{}, err
			}
			return SsfResponse{201, config}, nil
		case "GET":
			if !hasQsid {
				list, err := h.o.Store.ListByReceiver(rcv.ID)
				if err != nil {
					return SsfResponse{}, err
				}
				out := make([]any, len(list))
				for i, e := range list {
					out[i] = e.Record.Config
				}
				return SsfResponse{200, out}, nil
			}
			s, err := h.own(rcv, qsid)
			if err != nil || s == nil {
				return ssfNotFound, err
			}
			return SsfResponse{200, s.Config}, nil
		case "PATCH", "PUT":
			if b == nil {
				return ssfBad("a JSON object body is required"), nil
			}
			s, err := h.own(rcv, b["stream_id"])
			if err != nil {
				return SsfResponse{}, err
			}
			if _, ok := b["stream_id"].(string); !ok {
				return ssfBad("stream_id is required"), nil
			}
			if s == nil {
				return ssfNotFound, nil
			}
			for _, k := range jsKeys(b) {
				if !slices.Contains(ssfReceiverSupplied, k) && !slices.Contains(ssfTransmitterSupplied, k) {
					return ssfBad(fmt.Sprintf("unknown member '%s'", k)), nil
				}
			}
			for _, k := range ssfTransmitterSupplied {
				v, has := b[k]
				if !has {
					continue
				}
				got, err := sigJSON(v)
				if err != nil {
					return SsfResponse{}, err
				}
				exp, has := s.Config[k]
				want := ""
				if has {
					if want, err = sigJSON(exp); err != nil {
						return SsfResponse{}, err
					}
				}
				if !has || got != want {
					return ssfBad(fmt.Sprintf("'%s' is transmitter-supplied and does not match", k)), nil
				}
			}
			er, hasER := b["events_requested"]
			erList, ok := eventsRequestedOK(er)
			if hasER && !ok {
				return ssfBad("events_requested must be a non-empty array of event type URIs"), nil
			}
			desc, ok := str("description")
			if !ok {
				return ssfBad("description must be a string"), nil
			}
			sid, _ := s.Config["stream_id"].(string)
			delivery, _ := s.Config["delivery"].(map[string]any)
			if dv, has := b["delivery"]; has || m == "PUT" {
				d, why := h.deliveryFor(sid, dv, has)
				if d == nil {
					return ssfBad(why), nil
				}
				if d["method"] != delivery["method"] {
					return ssfBad("delivery.method cannot be changed: create a new stream"), nil
				}
				delivery = d
			}
			requested, description := erList, desc
			if m == "PATCH" {
				if !hasER {
					requested = s.EventsRequested
				}
				if _, has := b["description"]; !has {
					description = nil
					if cd, ok := s.Config["description"].(string); ok {
						description = &cd
					}
				}
			}
			if len(h.delivered(requested)) == 0 {
				return ssfBad("none of events_requested is supported by this transmitter"), nil
			}
			next := h.build(sid, rcv, requested, delivery, description)
			if mvi, has := s.Config["min_verification_interval"]; has {
				next["min_verification_interval"] = mvi
			}
			s.Config, s.EventsRequested = next, requested
			if err := h.o.Store.Put(sid, s); err != nil {
				return SsfResponse{}, err
			}
			return SsfResponse{200, next}, nil
		case "DELETE":
			s, err := h.own(rcv, qsid)
			if err != nil || s == nil {
				return ssfNotFound, err
			}
			return SsfResponse{Status: 204}, h.o.Store.Delete(qsid.(string))
		}
		return ssfNotAllowed, nil
	case "status":
		switch m {
		case "GET":
			s, err := h.own(rcv, qsid)
			if err != nil {
				return SsfResponse{}, err
			}
			if s == nil {
				if !hasQsid {
					return ssfBad("stream_id is required"), nil
				}
				return ssfNotFound, nil
			}
			return SsfResponse{200, ssfStatusBody(qsid, s)}, nil
		case "POST":
			sid, ok := b["stream_id"].(string)
			if b == nil || !ok {
				return ssfBad("stream_id is required"), nil
			}
			st, _ := b["status"].(string)
			if !slices.Contains(StreamStatuses, st) {
				return ssfBad("status must be 'enabled', 'paused' or 'disabled'"), nil
			}
			reason, ok := str("reason")
			if !ok {
				return ssfBad("reason must be a string"), nil
			}
			s, err := h.own(rcv, sid)
			if err != nil || s == nil {
				return ssfNotFound, err
			}
			s.Status, s.StatusReason = st, reason
			if err := h.o.Store.Put(sid, s); err != nil {
				return SsfResponse{}, err
			}
			return SsfResponse{200, ssfStatusBody(sid, s)}, nil
		}
		return ssfNotAllowed, nil
	case "add_subject", "remove_subject":
		if m != "POST" {
			return ssfNotAllowed, nil
		}
		sid, ok := b["stream_id"].(string)
		if b == nil || !ok {
			return ssfBad("stream_id is required"), nil
		}
		key := ssfSubjectKey(b["subject"])
		if key == "" {
			return ssfBad("subject must be a Subject Identifier object with a format"), nil
		}
		verified := true
		if v, has := b["verified"]; has {
			bv, ok := v.(bool)
			if !ok {
				return ssfBad("verified must be a boolean"), nil
			}
			verified = bv
		}
		s, err := h.own(rcv, sid)
		if err != nil || s == nil {
			return ssfNotFound, err
		}
		if s.Subjects == nil {
			s.Subjects = map[string]bool{}
		}
		if seg == "add_subject" {
			if _, known := s.Subjects[key]; !known && len(s.Subjects) >= h.o.MaxSubjectsPerStream {
				return SsfResponse{429, map[string]any{"error": "too_many_requests", "description": "subject limit reached"}}, nil
			}
			s.Subjects[key] = verified // SSF: SHOULD assume verified when omitted
			return SsfResponse{Status: 200}, h.o.Store.Put(sid, s)
		}
		delete(s.Subjects, key) // an unknown subject is silently ignored (204)
		return SsfResponse{Status: 204}, h.o.Store.Put(sid, s)
	}
	// verification
	if m != "POST" {
		return ssfNotAllowed, nil
	}
	if b == nil {
		return ssfBad("a JSON object body is required"), nil
	}
	s, err := h.own(rcv, b["stream_id"])
	if err != nil {
		return SsfResponse{}, err
	}
	if s == nil {
		if _, ok := b["stream_id"].(string); ok {
			return ssfNotFound, nil
		}
		return ssfBad("stream_id is required"), nil
	}
	if s.Status == "disabled" {
		return ssfBad("the stream is disabled"), nil
	}
	sid, _ := s.Config["stream_id"].(string)
	view := map[string]*VerificationStream{sid: {Config: s.Config, LastVerification: s.LastVerification}}
	vreq := map[string]any{"stream_id": b["stream_id"]}
	if st, has := b["state"]; has {
		vreq["state"] = st
	}
	out, err := HandleVerificationRequest(view, vreq, h.o.Now(), h.o.SigningKey)
	if err != nil {
		return SsfResponse{}, err
	}
	if out.Status != 204 {
		e := "invalid_request"
		if out.Status == 429 {
			e = "too_many_requests"
		}
		return SsfResponse{out.Status, map[string]any{"error": e, "description": out.Error}}, nil
	}
	now := h.o.Now()
	s.LastVerification = &now
	if err := h.o.Store.Put(sid, s); err != nil {
		return SsfResponse{}, err
	}
	return SsfResponse{Status: 204}, h.o.Deliver(s, out.SET)
}
