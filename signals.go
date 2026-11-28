package pca

// Shared Signals Framework / CAEP for PCA: Security Event Tokens (RFC 8417) built and verified, the subscriber-side revocation
// state, the fail-closed SET receiver (size cap, canonical spelling, signature, iss / aud, iat window, atomic jti replay guard),
// standard CAEP / RISC revocation events, authorize() adapters and snapshot / restore. Mirrors the reference
// (@atlasauth/pca-signals). JSON-shaped inputs follow the reference's JavaScript semantics (missing members, member order,
// truthiness), so a hostile input is refused or accepted exactly as there.

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	SetTyp                = "secevent+jwt"
	SetAlg                = "EdDSA"
	SetInMemoryMaxEntries = 100_000
)

// SetEventTypes are the event type URIs this package builds and folds.
var SetEventTypes = map[string]string{
	"sessionRevoked":       "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
	"credentialChange":     "https://schemas.openid.net/secevent/caep/event-type/credential-change",
	"grantRevoked":         "https://atlasauth.net/caep/grant-revoked",
	"killSwitch":           "https://atlasauth.net/caep/kill-switch",
	"intentRevoked":        "https://atlasauth.net/caep/intent-revoked",
	"verification":         "https://schemas.openid.net/secevent/ssf/event-type/verification",
	"riskLevelChange":      "https://schemas.openid.net/secevent/caep/event-type/risk-level-change",
	"assuranceLevelChange": "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change",
}

// RiscEventTypes are the RISC event types treated as revoking.
var RiscEventTypes = map[string]string{
	"sessionsRevoked":      "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked",
	"accountDisabled":      "https://schemas.openid.net/secevent/risc/event-type/account-disabled",
	"accountPurged":        "https://schemas.openid.net/secevent/risc/event-type/account-purged",
	"credentialCompromise": "https://schemas.openid.net/secevent/risc/event-type/credential-compromise",
}

func isRiscEventType(t string) bool {
	for _, v := range RiscEventTypes {
		if v == t {
			return true
		}
	}
	return false
}

func signalsErr(code, msg string) error { return &CodedError{Code: code, Msg: msg} }

func strNE(v any) bool { s, ok := v.(string); return ok && s != "" }

// sigField is `ev.k` of a JSON value that is not null: the member of an object, nil (undefined) for anything else.
func sigField(v any, k string) any {
	if m, ok := v.(map[string]any); ok {
		return m[k]
	}
	return nil
}

func sigHas(m map[string]any, k string) bool { _, ok := m[k]; return ok }

// sigNumber is `typeof v === 'number'` (JSON numbers only, never a boolean).
func sigNumber(v any) (float64, bool) {
	if _, b := v.(bool); b {
		return 0, false
	}
	return jsNum(v)
}

func eventTimestamp(ev any) float64 {
	if t, ok := sigNumber(sigField(ev, "event_timestamp")); ok {
		return t
	}
	return 0
}

// ---- JSON.stringify in member order -------------------------------------------------------------------------------------------

// sigObj is an object whose member order is explicit (a copied map loses the order its source was parsed with).
type sigObj struct {
	keys []string
	m    map[string]any
}

func sigStringify(sb *strings.Builder, v any) error {
	switch t := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		if t {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case string:
		lenientString(sb, t)
	case sigObj:
		sb.WriteByte('{')
		for i, k := range t.keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			lenientString(sb, k)
			sb.WriteByte(':')
			if err := sigStringify(sb, t.m[k]); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	case map[string]any:
		return sigStringify(sb, sigObj{jsKeys(t), t})
	case map[string]bool:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = x
		}
		return sigStringify(sb, m)
	case []string:
		l := make([]any, len(t))
		for i, x := range t {
			l[i] = x
		}
		return sigStringify(sb, l)
	case []any:
		sb.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := sigStringify(sb, x); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	default:
		f, ok := jsNum(v)
		if !ok {
			return fmt.Errorf("not JSON-serializable: %T", v)
		}
		if math.IsNaN(f) || math.IsInf(f, 0) {
			sb.WriteString("null")
		} else {
			sb.WriteString(jsLenientNumber(f))
		}
	}
	return nil
}

func sigJSON(v any) (string, error) {
	var sb strings.Builder
	err := sigStringify(&sb, v)
	return sb.String(), err
}

// ---- SET build / verify -----------------------------------------------------------------------------------------------------

// BuildSETArgs: Events is the non-empty `events` map; Audience a string or a list of strings; Subject (when set) adds sub and an
// opaque sub_id; Key is the 32-byte Ed25519 seed. Now (epoch seconds, 0 = the wall clock) and Jti ("" = a random UUID) are for tests.
type BuildSETArgs struct {
	Events   map[string]any
	Issuer   string
	Audience any
	Subject  *string
	Key      []byte
	Now      int64
	Jti      string
}

// BuildSET builds a signed SET (typ secevent+jwt, EdDSA) with the reference's claim order: events, sub_id, iss, iat, jti, aud, sub.
func BuildSET(a BuildSETArgs) (string, error) {
	return buildSETEvents(sigObj{jsKeys(a.Events), a.Events}, a)
}

func buildSETEvents(events sigObj, a BuildSETArgs) (string, error) {
	if events.m == nil || len(events.keys) == 0 {
		return "", errors.New("buildSET: at least one event is required in the `events` map (RFC 8417 §2.2)")
	}
	if len(a.Key) != ed25519.SeedSize {
		return "", errors.New("buildSET: the signing key must be a 32-byte Ed25519 seed")
	}
	iat := a.Now
	if iat == 0 {
		iat = time.Now().Unix()
	}
	jti := a.Jti
	if jti == "" {
		jti = randomUUID()
	}
	p := sigObj{m: map[string]any{}}
	put := func(k string, v any) { p.keys, p.m[k] = append(p.keys, k), v }
	put("events", events)
	if a.Subject != nil {
		put("sub_id", sigObj{[]string{"format", "id"}, map[string]any{"format": "opaque", "id": *a.Subject}})
	}
	put("iss", a.Issuer)
	put("iat", float64(iat))
	put("jti", jti)
	put("aud", a.Audience)
	if a.Subject != nil {
		put("sub", *a.Subject)
	}
	payload, err := sigJSON(p)
	if err != nil {
		return "", err
	}
	return SignCompactEdDSA(rawJSON(`{"alg":"EdDSA","typ":"secevent+jwt"}`), rawJSON(payload), a.Key)
}

// VerifySETOptions: Issuer / Audience nil skip the check (a non-nil list requires the claim and one of its values);
// ClockTolerance is seconds or a period string ("1m"); CurrentDate pins now (zero = the wall clock); Typ overrides the required
// typ header (nil = secevent+jwt, "" = no check); SkipTyp skips the typ check entirely.
type VerifySETOptions struct {
	Issuer         []string
	Audience       []string
	ClockTolerance any
	CurrentDate    time.Time
	Typ            *string
	SkipTyp        bool
}

// ParsedSET is a verified SET: the validated events map, iss, jti, sub (nil when absent or not a string) and the full payload.
type ParsedSET struct {
	Events  map[string]any
	Iss     string
	Jti     string
	Sub     *string
	Payload map[string]any
}

// Map is the reference's ParsedSet shape.
func (p *ParsedSET) Map() map[string]any {
	out := map[string]any{"events": p.Events, "iss": p.Iss, "jti": p.Jti, "payload": p.Payload}
	if p.Sub != nil {
		out["sub"] = *p.Sub
	}
	return out
}

func parseSETEvents(raw any) (map[string]any, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("SET invalid: `events` claim is missing or not a JSON object (RFC 8417 §2.2)")
	}
	keys := jsKeys(m)
	if len(keys) == 0 {
		return nil, errors.New("SET invalid: `events` claim is empty (RFC 8417 §2.2)")
	}
	for _, k := range keys {
		if _, ok := m[k].(map[string]any); !ok {
			return nil, fmt.Errorf("SET invalid: event payload for `%s` is not a JSON object (RFC 8417 §2.2)", k)
		}
	}
	return m, nil
}

// VerifySET verifies a SET under an Ed25519 public key: the canonical-spelling gate, then EdDSA only, typ, iss / aud and the
// time claims, then a string iss and jti and a non-empty events map of objects. Any failure is an error.
func VerifySET(set any, key ed25519.PublicKey, o *VerifySETOptions) (*ParsedSET, error) {
	if o == nil {
		o = &VerifySETOptions{}
	}
	cj, err := AssertCanonicalCompactJWS(set, 3, 0, true)
	if err != nil {
		return nil, err
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, errors.New("verifySET: the verification key must be a 32-byte Ed25519 public key")
	}
	tol, err := joseSecs(o.ClockTolerance)
	if err != nil {
		return nil, err
	}
	vo := JWTVerifyOptions{Algorithms: []string{SetAlg}, Issuer: o.Issuer, Audience: o.Audience, ClockTolerance: tol}
	if !o.SkipTyp {
		vo.Typ = SetTyp
		if o.Typ != nil {
			vo.Typ = *o.Typ
		}
	}
	if !o.CurrentDate.IsZero() {
		now := math.Floor(float64(o.CurrentDate.UnixMilli()) / 1000)
		vo.NowSec = &now
	}
	jk := &JOSEKey{Kty: "OKP", Crv: "Ed25519", Ed25519: key}
	if _, _, err := JWTVerify(set.(string), func(map[string]any) (*JOSEKey, error) { return jk, nil }, vo, float64(time.Now().UnixMilli())/1000); err != nil {
		return nil, err
	}
	payload := cj.Payload // the same bytes, parsed strictly with member order kept
	iss, ok := payload["iss"].(string)
	if !ok {
		return nil, errors.New("SET invalid: missing or non-string `iss`")
	}
	jti, ok := payload["jti"].(string)
	if !ok {
		return nil, errors.New("SET invalid: missing or non-string `jti` (RFC 8417 §2.2 requires it)")
	}
	events, err := parseSETEvents(payload["events"])
	if err != nil {
		return nil, err
	}
	out := &ParsedSET{Events: events, Iss: iss, Jti: jti, Payload: payload}
	if s, ok := payload["sub"].(string); ok {
		out.Sub = &s
	}
	return out, nil
}

// ---- subscriber-side revocation state ---------------------------------------------------------------------------------------

// sigTimes is a Map<string, number> in insertion order.
type sigTimes struct {
	keys []string
	at   map[string]float64
}

func (m *sigTimes) recordMax(k string, ts float64) {
	if m.at == nil {
		m.at = map[string]float64{}
	}
	prev, ok := m.at[k]
	if !ok {
		m.keys = append(m.keys, k)
		m.at[k] = ts
	} else if ts > prev {
		m.at[k] = ts
	}
}

func (m *sigTimes) has(k string) bool { _, ok := m.at[k]; return ok }

func (m *sigTimes) pairs() [][]any {
	out := [][]any{}
	if m == nil {
		return out
	}
	for _, k := range m.keys {
		out = append(out, []any{k, m.at[k]})
	}
	return out
}

// SignalsRevocationState is the subscriber-side state a resource server consults on every request: revoked grants, killed agents and
// revoked intent ids, each with the latest event_timestamp seen. Monotone; safe for concurrent use.
type SignalsRevocationState struct {
	mu      sync.RWMutex
	grants  sigTimes
	agents  sigTimes
	intents *sigTimes
}

// NewRevocationState is createRevocationState().
func NewRevocationState() *SignalsRevocationState { return &SignalsRevocationState{} }

func assertRevocationState(s *SignalsRevocationState) error {
	if s == nil {
		return signalsErr("misconfigured", "state must come from createRevocationState()")
	}
	return nil
}

// RevokedGrants, KilledAgents and RevokedIntentIDs list [key, event_timestamp] pairs in insertion order (intents nil when none was
// ever recorded).
func (s *SignalsRevocationState) RevokedGrants() [][]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.grants.pairs()
}

func (s *SignalsRevocationState) KilledAgents() [][]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.agents.pairs()
}

func (s *SignalsRevocationState) RevokedIntentIDs() [][]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.intents == nil {
		return nil
	}
	return s.intents.pairs()
}

func (s *SignalsRevocationState) intentSet() *sigTimes {
	if s.intents == nil {
		s.intents = &sigTimes{}
	}
	return s.intents
}

func errEvents(p *ParsedSET) error {
	if p == nil {
		return errors.New("Cannot read properties of null (reading 'events')")
	}
	if p.Events == nil {
		return errors.New("Cannot convert undefined or null to object")
	}
	return nil
}

// ApplySET folds one verified SET into the state, in the events' member order; each key keeps its max event_timestamp. A null
// event payload is an error (the events before it stay applied, as in the reference).
func ApplySET(state *SignalsRevocationState, p *ParsedSET) (*SignalsRevocationState, error) {
	if err := assertRevocationState(state); err != nil {
		return nil, err
	}
	if err := errEvents(p); err != nil {
		return nil, err
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state, applySETLocked(state, p)
}

func applySETLocked(state *SignalsRevocationState, p *ParsedSET) error {
	for _, typ := range jsKeys(p.Events) {
		ev := p.Events[typ]
		if ev == nil {
			return errors.New("Cannot read properties of null (reading 'event_timestamp')")
		}
		ts := eventTimestamp(ev)
		switch typ {
		case SetEventTypes["grantRevoked"]:
			if ref, ok := sigField(ev, "grant_ref").(string); ok && ref != "" {
				state.grants.recordMax(ref, ts)
			}
		case SetEventTypes["killSwitch"]:
			if a, ok := sigField(ev, "agent").(string); ok && a != "" {
				state.agents.recordMax(a, ts)
			}
			if ref, ok := sigField(ev, "grant_ref").(string); ok && ref != "" {
				state.grants.recordMax(ref, ts)
			}
		case SetEventTypes["intentRevoked"]:
			if ids, ok := sigField(ev, "ids").([]any); ok {
				for _, id := range ids {
					if s, ok := id.(string); ok && strings.HasPrefix(s, "pca-intent:") {
						state.intentSet().recordMax(s, ts)
					}
				}
			}
		}
	}
	return nil
}

// IsIntentRevoked reports whether an intent id was revoked by a signal.
func IsIntentRevoked(state *SignalsRevocationState, id string) bool {
	state.mu.RLock()
	defer state.mu.RUnlock()
	return state.intents != nil && state.intents.has(id)
}

// IsRevoked reports whether the grant was revoked, or the agent ("" = none) was killed.
func IsRevoked(state *SignalsRevocationState, grantRef, agent string) bool {
	state.mu.RLock()
	defer state.mu.RUnlock()
	return state.grants.has(grantRef) || (agent != "" && state.agents.has(agent))
}

func setTimestamp(p *ParsedSET) (float64, error) {
	if err := errEvents(p); err != nil {
		return 0, err
	}
	m := math.Inf(1)
	for _, k := range jsKeys(p.Events) {
		ev := p.Events[k]
		if ev == nil {
			return 0, errors.New("Cannot read properties of null (reading 'event_timestamp')")
		}
		if t, ok := sigNumber(sigField(ev, "event_timestamp")); ok && t < m {
			m = t
		}
	}
	if math.IsInf(m, 0) || math.IsNaN(m) {
		return 0, nil
	}
	return m, nil
}

// StreamProcessor folds verified SETs in event_timestamp order (stable), so delivery order cannot matter. A nil state is a fresh one.
func StreamProcessor(sets []*ParsedSET, state *SignalsRevocationState) (*SignalsRevocationState, error) {
	if state == nil {
		state = NewRevocationState()
	}
	type keyed struct {
		ts float64
		p  *ParsedSET
	}
	ks := make([]keyed, len(sets))
	for i, p := range sets {
		ks[i].p = p
		if len(sets) > 1 { // the reference's sort compares every element of a list of two or more
			t, err := setTimestamp(p)
			if err != nil {
				return nil, err
			}
			ks[i].ts = t
		}
	}
	sort.SliceStable(ks, func(i, j int) bool { return ks[i].ts < ks[j].ts })
	for _, k := range ks {
		if _, err := ApplySET(state, k.p); err != nil {
			return nil, err
		}
	}
	return state, nil
}

// ---- replay store -----------------------------------------------------------------------------------------------------------

// SetReplayStore remembers SET jtis until they expire. AddIfAbsent must be atomic: true exactly once per live jti.
type SetReplayStore interface {
	AddIfAbsent(jti string, expiresAtSec, nowSec float64) (bool, error)
}

// InMemorySetReplayStore is a bounded single-process store: when full, a new jti is an error (the receiver then refuses) instead
// of evicting a live entry.
type InMemorySetReplayStore struct {
	mu   sync.Mutex
	max  float64
	seen map[string]float64
}

// NewInMemorySetReplayStore: maxEntries nil = SetInMemoryMaxEntries; otherwise a positive integer.
func NewInMemorySetReplayStore(maxEntries *float64) (*InMemorySetReplayStore, error) {
	mx := float64(SetInMemoryMaxEntries)
	if maxEntries != nil {
		mx = *maxEntries
	}
	if math.IsNaN(mx) || math.IsInf(mx, 0) || mx != math.Trunc(mx) || mx < 1 {
		return nil, signalsErr("misconfigured", "maxEntries must be a positive integer")
	}
	return &InMemorySetReplayStore{max: mx, seen: map[string]float64{}}, nil
}

func (s *InMemorySetReplayStore) AddIfAbsent(jti string, expiresAtSec, nowSec float64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	held, ok := s.seen[jti]
	if ok && !(finite(nowSec) && nowSec >= held) {
		return false, nil
	}
	if !ok && float64(len(s.seen)) >= s.max {
		for k, exp := range s.seen {
			if finite(nowSec) && nowSec >= exp {
				delete(s.seen, k)
			}
		}
		if float64(len(s.seen)) >= s.max {
			return false, errors.New("replay store is full")
		}
	}
	s.seen[jti] = expiresAtSec
	return true, nil
}

// RunSetReplayStoreConformance checks a replay store implementation; it returns the failed checks (empty = conformant). A store
// error is returned as the error.
func RunSetReplayStoreConformance(newStore func() SetReplayStore) ([]string, error) {
	failures := []string{}
	var ferr error
	add := func(s SetReplayStore, jti string, exp, now float64) bool {
		ok, err := s.AddIfAbsent(jti, exp, now)
		if err != nil && ferr == nil {
			ferr = err
		}
		return ok
	}
	check := func(ok bool, name string) {
		if ferr == nil && !ok {
			failures = append(failures, name)
		}
	}
	s := newStore()
	check(add(s, "a", 200, 100), "first sight of a jti returns true")
	check(ferr == nil && !add(s, "a", 200, 101), "second sight of the same jti returns false")
	check(ferr == nil && add(s, "b", 200, 101), "a different jti is independent")
	check(ferr == nil && !add(s, "a", 200, 199), "still seen one second before expiry")
	if ferr != nil {
		return nil, ferr
	}
	t := newStore()
	add(t, "c", 200, 100)
	check(ferr == nil && add(t, "c", 400, 200), "an expired entry may be added again (nowSec >= expiresAtSec)")
	if ferr != nil {
		return nil, ferr
	}
	u := newStore()
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := u.AddIfAbsent("race", 200, 100)
			mu.Lock()
			defer mu.Unlock()
			if err != nil && ferr == nil {
				ferr = err
			}
			if ok {
				wins++
			}
		}()
	}
	wg.Wait()
	if ferr != nil {
		return nil, ferr
	}
	check(wins == 1, fmt.Sprintf("16 concurrent adds of one jti: exactly one wins (got %d)", wins))
	return failures, nil
}

// ---- receiver -----------------------------------------------------------------------------------------------------------------

// ReceiveSETOptions: Issuer, Audience, ReplayStore, State and a positive finite MaxAgeSec are required. ClockSkewSec nil = 60,
// NowSec nil = the wall clock, MaxBytes nil = 16384 (UTF-16 units, as the reference counts). StandardRevocations, when set, also
// folds CAEP / RISC revoking events (an unmappable one refuses the SET when FailOnUnmapped).
type ReceiveSETOptions struct {
	Issuer              []string
	Audience            []string
	ReplayStore         SetReplayStore
	State               *SignalsRevocationState
	MaxAgeSec           float64
	ClockSkewSec        *float64
	NowSec              *float64
	MaxBytes            *int
	StandardRevocations *StandardRevocationOptions
}

// ReceiveSETResult: OK with Parsed, or a refusal Code (misconfigured | oversize | malformed | verify_failed | iat_missing |
// iat_future | iat_stale | unmapped_subject | replay | replay_store_error) and Reason.
type ReceiveSETResult struct {
	OK     bool
	Code   string
	Reason string
	Parsed *ParsedSET
}

// Map is the reference's ReceiveSetResult shape.
func (r ReceiveSETResult) Map() map[string]any {
	if r.OK {
		return map[string]any{"ok": true, "parsed": r.Parsed.Map()}
	}
	return map[string]any{"ok": false, "code": r.Code, "reason": r.Reason}
}

func receiveFail(code, reason string) ReceiveSETResult {
	return ReceiveSETResult{Code: code, Reason: reason}
}

// ReceiveSET is the recommended receive path. Every refusal is a value; a replay store error denies (the SET is not applied).
func ReceiveSET(set any, key ed25519.PublicKey, o *ReceiveSETOptions) ReceiveSETResult {
	if o == nil || o.Issuer == nil || o.Audience == nil || o.ReplayStore == nil || o.State == nil ||
		math.IsNaN(o.MaxAgeSec) || math.IsInf(o.MaxAgeSec, 0) || o.MaxAgeSec <= 0 {
		return receiveFail("misconfigured", "issuer, audience, replayStore, state and a positive maxAgeSec are all required")
	}
	maxBytes := 16384
	if o.MaxBytes != nil {
		maxBytes = *o.MaxBytes
	}
	s, ok := set.(string)
	if !ok || jsLen(s) > maxBytes {
		return receiveFail("oversize", "SET is not a string or exceeds maxBytes")
	}
	if _, err := AssertCanonicalCompactJWS(s, 3, 0, true); err != nil {
		return receiveFail("malformed", err.Error())
	}
	now := math.Floor(float64(time.Now().UnixMilli()) / 1000)
	if o.NowSec != nil {
		now = *o.NowSec
	}
	// a time beyond +-8.64e15 ms is an invalid Date, which a JWT library reads as no clock: refuse it (NaN and infinities fail this test too)
	if !(math.Abs(now*1000) <= 8.64e15) {
		return receiveFail("verify_failed", "nowSec is not a representable time")
	}
	parsed, err := VerifySET(s, key, &VerifySETOptions{Issuer: o.Issuer, Audience: o.Audience, CurrentDate: time.UnixMilli(int64(now * 1000))})
	if err != nil {
		return receiveFail("verify_failed", err.Error())
	}
	iat, ok := sigNumber(parsed.Payload["iat"])
	if !ok || math.IsNaN(iat) || math.IsInf(iat, 0) {
		return receiveFail("iat_missing", "SET has no numeric iat")
	}
	skew := 60.0
	if o.ClockSkewSec != nil {
		skew = *o.ClockSkewSec
	}
	if !(finite(now) && finite(skew) && iat <= now+skew) {
		return receiveFail("iat_future", "SET iat is in the future")
	}
	if now-iat > o.MaxAgeSec {
		return receiveFail("iat_stale", "SET is older than "+jsNumberString(o.MaxAgeSec)+"s")
	}
	var plan *StandardRevocationPlan
	if o.StandardRevocations != nil {
		if plan, err = PlanStandardRevocations(parsed, o.StandardRevocations); err != nil {
			return receiveFail("unmapped_subject", err.Error())
		}
	}
	fresh, err := o.ReplayStore.AddIfAbsent(parsed.Jti, iat+o.MaxAgeSec+skew, now)
	if err != nil {
		return receiveFail("replay_store_error", err.Error())
	}
	if !fresh {
		return receiveFail("replay", fmt.Sprintf("jti '%s' has already been received", parsed.Jti))
	}
	o.State.mu.Lock()
	defer o.State.mu.Unlock()
	if err := applySETLocked(o.State, parsed); err != nil { // unreachable: a verified SET's events are objects
		return receiveFail("verify_failed", err.Error())
	}
	if plan != nil {
		for _, a := range plan.Agents {
			o.State.agents.recordMax(a.Agent, a.At)
		}
	}
	return ReceiveSETResult{OK: true, Parsed: parsed}
}

// ---- standard (CAEP / RISC) revocation events -------------------------------------------------------------------------------

// StandardRevocationOptions: SubjectToAgent maps a subject identifier to an agent ("" or an error = unmapped; nil = an opaque
// subject's id); FailOnUnmapped makes an unmappable revoking event an error instead of a listed one.
type StandardRevocationOptions struct {
	SubjectToAgent func(subject map[string]any) (string, error)
	FailOnUnmapped bool
}

// AgentRevocation is one [agent, event_timestamp] pair of a plan.
type AgentRevocation struct {
	Agent string
	At    float64
}

func (a AgentRevocation) MarshalJSON() ([]byte, error) {
	s, err := sigJSON([]any{a.Agent, a.At})
	return []byte(s), err
}

// StandardRevocationPlan is the agents a SET's revoking events revoke, and the revoking event types that named no mappable agent.
type StandardRevocationPlan struct {
	Agents   []AgentRevocation `json:"agents"`
	Unmapped []string          `json:"unmapped"`
}

func defaultSubjectToAgent(s map[string]any) (string, error) {
	if s["format"] == "opaque" {
		if id, ok := s["id"].(string); ok {
			return id, nil
		}
	}
	return "", nil
}

func isStandardEventType(t string) bool {
	return t == SetEventTypes["sessionRevoked"] || t == SetEventTypes["credentialChange"] || isRiscEventType(t)
}

// PlanStandardRevocations decides, without touching any state, which agents the SET's CAEP / RISC revoking events revoke. A
// credential-change event revokes unless its change_type is "create" (unknown or absent fails closed).
func PlanStandardRevocations(p *ParsedSET, o *StandardRevocationOptions) (*StandardRevocationPlan, error) {
	if o == nil {
		o = &StandardRevocationOptions{}
	}
	toAgent := o.SubjectToAgent
	if toAgent == nil {
		toAgent = defaultSubjectToAgent
	}
	if p == nil || p.Payload == nil {
		return nil, errors.New("Cannot read properties of undefined (reading 'sub_id')")
	}
	setSubject, _ := p.Payload["sub_id"].(map[string]any)
	if err := errEvents(p); err != nil {
		return nil, err
	}
	plan := &StandardRevocationPlan{Agents: []AgentRevocation{}, Unmapped: []string{}}
	for _, typ := range jsKeys(p.Events) {
		ev := p.Events[typ]
		if !isStandardEventType(typ) {
			continue
		}
		if ev == nil {
			return nil, errors.New("Cannot read properties of null")
		}
		if typ == SetEventTypes["credentialChange"] && sigField(ev, "change_type") == "create" {
			continue
		}
		own := setSubject
		if es, ok := sigField(ev, "subject").(map[string]any); ok {
			own = es
		}
		agent := ""
		if _, ok := own["format"].(string); own != nil && ok {
			if a, err := safeSubjectToAgent(toAgent, own); err == nil {
				agent = a
			}
		}
		if agent == "" {
			if o.FailOnUnmapped {
				return nil, signalsErr("unmapped_subject", fmt.Sprintf("event '%s' names no mappable agent", typ))
			}
			plan.Unmapped = append(plan.Unmapped, typ)
			continue
		}
		plan.Agents = append(plan.Agents, AgentRevocation{agent, eventTimestamp(ev)})
	}
	return plan, nil
}

// safeSubjectToAgent: a mapper that panics names no agent.
func safeSubjectToAgent(f func(map[string]any) (string, error), s map[string]any) (a string, err error) {
	defer func() {
		if r := recover(); r != nil {
			a, err = "", fmt.Errorf("subjectToAgent panicked: %v", r)
		}
	}()
	return f(s)
}

// ApplyStandardRevocations plans and folds the CAEP / RISC revoking events (killed agents keep the max timestamp).
func ApplyStandardRevocations(state *SignalsRevocationState, p *ParsedSET, o *StandardRevocationOptions) (*StandardRevocationPlan, error) {
	if err := assertRevocationState(state); err != nil {
		return nil, err
	}
	plan, err := PlanStandardRevocations(p, o)
	if err != nil {
		return nil, err
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	for _, a := range plan.Agents {
		state.agents.recordMax(a.Agent, a.At)
	}
	return plan, nil
}

// ---- authorize() adapters ---------------------------------------------------------------------------------------------------

// RevocationAdapterOptions: AgentOf determines the acting agent ("" or an error = undeterminable, which denies); nil = the
// holder of the last capability in pcactn.cap_chain.
type RevocationAdapterOptions struct {
	AgentOf func(pcactn, grant any) (string, error)
}

func leafHolderAgent(pcactn, _ any) (string, error) {
	chain := sigField(pcactn, "cap_chain")
	switch c := chain.(type) {
	case nil:
		return "", errors.New("Cannot read properties of undefined (reading 'length')")
	case []any:
		if len(c) > 0 {
			h, _ := sigField(c[len(c)-1], "holder").(string)
			return h, nil
		}
	}
	return "", nil
}

func revocationReason(state *SignalsRevocationState, pcactn, grant any, agentOf func(pcactn, grant any) (string, error)) (reason string) {
	defer func() {
		if recover() != nil {
			reason = "revocation check error (fail closed)"
		}
	}()
	if pcactn == nil {
		return "revocation check error (fail closed)"
	}
	if m, ok := pcactn.(map[string]any); ok && m == nil {
		return "revocation check error (fail closed)"
	}
	ref, ok := sigField(pcactn, "grant_ref").(string)
	if !ok || ref == "" {
		return "grant_ref is missing"
	}
	state.mu.RLock()
	revoked := state.grants.has(ref)
	if id, ok := sigField(grant, "id").(string); ok && state.grants.has(id) {
		revoked = true
	}
	state.mu.RUnlock()
	if revoked {
		return "grant revoked by signal"
	}
	agent, err := agentOf(pcactn, grant)
	if err != nil {
		return "revocation check error (fail closed)"
	}
	if agent == "" {
		return "agent could not be determined"
	}
	state.mu.RLock()
	killed := state.agents.has(agent)
	state.mu.RUnlock()
	if killed {
		return "agent killed by signal"
	}
	return ""
}

// RevocationHookResult is the hook's verdict: always enforced; OK false with the reason denies.
type RevocationHookResult struct {
	Enforced bool   `json:"enforced"`
	OK       bool   `json:"ok"`
	Reason   string `json:"reason,omitempty"`
}

// CreateRevocationHook returns a hook that reads the state live: a revoked grant, a killed or undeterminable agent, or any error denies.
func CreateRevocationHook(state *SignalsRevocationState, o *RevocationAdapterOptions) (func(pcactn, grant any) RevocationHookResult, error) {
	if err := assertRevocationState(state); err != nil {
		return nil, err
	}
	agentOf := leafHolderAgent
	if o != nil && o.AgentOf != nil {
		agentOf = o.AgentOf
	}
	return func(pcactn, grant any) RevocationHookResult {
		if r := revocationReason(state, pcactn, grant, agentOf); r != "" {
			return RevocationHookResult{Enforced: true, Reason: r}
		}
		return RevocationHookResult{Enforced: true, OK: true}
	}, nil
}

// CreateIsRevoked returns an AuthorizeInput.IsRevoked: true (deny) on the same conditions as CreateRevocationHook.
func CreateIsRevoked(state *SignalsRevocationState, o *RevocationAdapterOptions) (func(pcactn, grant map[string]any) (bool, error), error) {
	f, err := createIsRevokedAny(state, o)
	if err != nil {
		return nil, err
	}
	return func(pcactn, grant map[string]any) (bool, error) {
		var p, g any
		if pcactn != nil {
			p = pcactn
		}
		if grant != nil {
			g = grant
		}
		return f(p, g), nil
	}, nil
}

func createIsRevokedAny(state *SignalsRevocationState, o *RevocationAdapterOptions) (func(pcactn, grant any) bool, error) {
	if err := assertRevocationState(state); err != nil {
		return nil, err
	}
	agentOf := leafHolderAgent
	if o != nil && o.AgentOf != nil {
		agentOf = o.AgentOf
	}
	return func(pcactn, grant any) bool { return revocationReason(state, pcactn, grant, agentOf) != "" }, nil
}

// ---- snapshot / restore -----------------------------------------------------------------------------------------------------

// SnapshotRevocationState is {v: 1, grants, agents, intents} as [key, event_timestamp] pairs.
func SnapshotRevocationState(state *SignalsRevocationState) (map[string]any, error) {
	if err := assertRevocationState(state); err != nil {
		return nil, err
	}
	state.mu.RLock()
	defer state.mu.RUnlock()
	return map[string]any{"v": 1, "grants": state.grants.pairs(), "agents": state.agents.pairs(), "intents": state.intents.pairs()}, nil
}

func snapshotPairs(v any, what string) ([]AgentRevocation, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, signalsErr("bad_snapshot", what+" is not an array")
	}
	out := make([]AgentRevocation, 0, len(l))
	for _, p := range l {
		pl, ok := p.([]any)
		var k string
		var t float64
		if ok && len(pl) == 2 {
			k, _ = pl[0].(string)
			var isNum bool
			t, isNum = sigNumber(pl[1])
			ok = isNum && !math.IsNaN(t) && !math.IsInf(t, 0)
		}
		if !ok || len(pl) != 2 || k == "" {
			return nil, signalsErr("bad_snapshot", what+" holds an entry that is not [string, number]")
		}
		out = append(out, AgentRevocation{k, t})
	}
	return out, nil
}

// RestoreRevocationState merges a snapshot into `into` (nil = a fresh state). Strict: any shape error is `bad_snapshot` and
// `into` is untouched. Monotone (max timestamp), so restoring never un-revokes.
func RestoreRevocationState(snapshot any, into *SignalsRevocationState) (*SignalsRevocationState, error) {
	if into == nil {
		into = NewRevocationState()
	}
	m, ok := snapshot.(map[string]any)
	if v, isNum := sigNumber(m["v"]); !ok || !isNum || v != 1 {
		return nil, signalsErr("bad_snapshot", "snapshot is not a version 1 object")
	}
	for _, k := range jsKeys(m) {
		if k != "v" && k != "grants" && k != "agents" && k != "intents" {
			return nil, signalsErr("bad_snapshot", fmt.Sprintf("snapshot has unknown member '%s'", k))
		}
	}
	grants, err := snapshotPairs(m["grants"], "grants")
	if err != nil {
		return nil, err
	}
	agents, err := snapshotPairs(m["agents"], "agents")
	if err != nil {
		return nil, err
	}
	intents, err := snapshotPairs(m["intents"], "intents")
	if err != nil {
		return nil, err
	}
	into.mu.Lock()
	defer into.mu.Unlock()
	for _, p := range grants {
		into.grants.recordMax(p.Agent, p.At)
	}
	for _, p := range agents {
		into.agents.recordMax(p.Agent, p.At)
	}
	for _, p := range intents {
		into.intentSet().recordMax(p.Agent, p.At)
	}
	return into, nil
}
