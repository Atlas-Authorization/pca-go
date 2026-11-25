package pca

// Realtime revocation and the mid-run kill-switch (port of the TypeScript @atlasauth/pca-revoke): revoke a capability, a holder,
// an issuer or a delegation subtree (a cap-id path prefix), check a PCActn's chain against the registry (fail closed: a missing
// clock, chain or hop field, or a failing store, counts as revoked), combine that with the core verdict, and ingest CAEP /
// SSF revocation events. Entries are JSON values (map[string]any) with the reference members: kind, value, prefix?, reason,
// revokedAt (epoch ms), notBefore?.

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"time"
)

// RevocationEntry is one stored revocation.
type RevocationEntry = map[string]any

// CAEP / SSF event types the registry ingests.
const (
	CaepSessionRevoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	CaepGrantRevoked   = "https://atlasauth.net/caep/grant-revoked"
	CaepKillSwitch     = "https://atlasauth.net/caep/kill-switch"
)

// RevocationStore persists entries keyed by (kind, value). Implementations must be safe for concurrent use.
type RevocationStore interface {
	Add(e RevocationEntry) error
	Remove(kind, value string) (bool, error)
	Get(kind, value string) (RevocationEntry, error) // nil when absent
	All() ([]RevocationEntry, error)                 // in insertion order (a replaced key keeps its place)
	Clear() error
}

// jsTemplate is `${x}` for a JSON value (absent = "undefined").
func jsTemplate(x any, has bool) string {
	if !has {
		return "undefined"
	}
	return jsValueString(x)
}

func revocationStoreKey(kind, value string) string { return kind + "\x00" + value }

func entryKey(e RevocationEntry) string {
	k, hk := e["kind"]
	v, hv := e["value"]
	return revocationStoreKey(jsTemplate(k, hk), jsTemplate(v, hv))
}

// MemoryRevocationStore is the in-process store (insertion ordered).
type MemoryRevocationStore struct {
	mu   sync.Mutex
	keys []string
	m    map[string]RevocationEntry
}

// NewMemoryRevocationStore returns an empty in-process store.
func NewMemoryRevocationStore() *MemoryRevocationStore {
	return &MemoryRevocationStore{m: map[string]RevocationEntry{}}
}

func (s *MemoryRevocationStore) set(k string, e RevocationEntry) {
	if _, has := s.m[k]; !has {
		s.keys = append(s.keys, k)
	}
	s.m[k] = e
}

func (s *MemoryRevocationStore) del(k string) bool {
	if _, has := s.m[k]; !has {
		return false
	}
	delete(s.m, k)
	for i, x := range s.keys {
		if x == k {
			s.keys = append(s.keys[:i:i], s.keys[i+1:]...)
			break
		}
	}
	return true
}

func (s *MemoryRevocationStore) list() []RevocationEntry {
	out := make([]RevocationEntry, len(s.keys))
	for i, k := range s.keys {
		out[i] = s.m[k]
	}
	return out
}

func (s *MemoryRevocationStore) Add(e RevocationEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.set(entryKey(e), e)
	return nil
}

func (s *MemoryRevocationStore) Remove(kind, value string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.del(revocationStoreKey(kind, value)), nil
}

func (s *MemoryRevocationStore) Get(kind, value string) (RevocationEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[revocationStoreKey(kind, value)], nil
}

func (s *MemoryRevocationStore) All() ([]RevocationEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.list(), nil
}

func (s *MemoryRevocationStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys, s.m = nil, map[string]RevocationEntry{}
	return nil
}

// FileRevocationStore is a durable single-process store: every change is written to a temp file, fsynced and renamed over the
// file before it is acknowledged; a failed write restores the previous state. A file that exists but is not a valid entry list
// is refused at open (never silently started empty).
type FileRevocationStore struct {
	mem  MemoryRevocationStore
	path string
}

var revocationKinds = map[string]bool{"cap": true, "holder": true, "issuer": true, "prefix": true}

func validRevocationEntry(x any) bool {
	o, ok := x.(map[string]any)
	if !ok {
		return false
	}
	kind, _ := o["kind"].(string)
	value, _ := o["value"].(string)
	if !revocationKinds[kind] || value == "" {
		return false
	}
	if _, ok := o["reason"].(string); !ok {
		return false
	}
	if f, ok := jsNum(o["revokedAt"]); !ok || !finite(f) {
		return false
	}
	if nb, has := o["notBefore"]; has {
		if f, ok := jsNum(nb); !ok || !finite(f) {
			return false
		}
	}
	if kind == "prefix" {
		l, ok := o["prefix"].([]any)
		if !ok || len(l) == 0 {
			return false
		}
		parts := make([]string, len(l))
		for i, p := range l {
			s, ok := p.(string)
			if !ok || s == "" {
				return false
			}
			parts[i] = s
		}
		if strings.Join(parts, ",") != value {
			return false
		}
	}
	return true
}

// OpenFileRevocationStore opens (or starts) the store at path.
func OpenFileRevocationStore(path string) (*FileRevocationStore, error) {
	s := &FileRevocationStore{mem: MemoryRevocationStore{m: map[string]RevocationEntry{}}, path: path}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("FileRevocationStore: %w", err)
	}
	v, err := ParseJSONLenient(b)
	if err != nil {
		return nil, errors.New("FileRevocationStore: the revocation file cannot be read as JSON; refusing to start empty")
	}
	doc, _ := normalizeJSON(v).(map[string]any)
	list, ok := doc["entries"].([]any)
	if !ok {
		return nil, errors.New("FileRevocationStore: the revocation file is not a valid entry list; refusing to start empty")
	}
	for _, e := range list {
		if !validRevocationEntry(e) {
			return nil, errors.New("FileRevocationStore: the revocation file is not a valid entry list; refusing to start empty")
		}
		s.mem.set(entryKey(e.(map[string]any)), e.(map[string]any))
	}
	return s, nil
}

func (s *FileRevocationStore) flush() error {
	b, err := json.Marshal(map[string]any{"v": 1, "entries": s.mem.list()})
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	f, err := CreateOwnerOnly(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *FileRevocationStore) write(change func()) error {
	s.mem.mu.Lock()
	defer s.mem.mu.Unlock()
	keys, m := append([]string(nil), s.mem.keys...), make(map[string]RevocationEntry, len(s.mem.m))
	for k, v := range s.mem.m {
		m[k] = v
	}
	change()
	if err := s.flush(); err != nil {
		s.mem.keys, s.mem.m = keys, m
		return err
	}
	return nil
}

func (s *FileRevocationStore) Add(e RevocationEntry) error {
	return s.write(func() { s.mem.set(entryKey(e), e) })
}

func (s *FileRevocationStore) Remove(kind, value string) (bool, error) {
	var ok bool
	err := s.write(func() { ok = s.mem.del(revocationStoreKey(kind, value)) })
	return ok && err == nil, err
}

func (s *FileRevocationStore) Get(kind, value string) (RevocationEntry, error) {
	return s.mem.Get(kind, value)
}
func (s *FileRevocationStore) All() ([]RevocationEntry, error) { return s.mem.All() }
func (s *FileRevocationStore) Clear() error {
	return s.write(func() { s.mem.keys, s.mem.m = nil, map[string]RevocationEntry{} })
}

// RevocationRegistry is the revocation API over a store. Now is the clock for a defaulted revokedAt (epoch ms; nil = wall clock).
type RevocationRegistry struct {
	Store RevocationStore
	Now   func() float64
}

// NewRevocationRegistry wraps a store (nil = a fresh in-memory store).
func NewRevocationRegistry(store RevocationStore) *RevocationRegistry {
	if store == nil {
		store = NewMemoryRevocationStore()
	}
	return &RevocationRegistry{Store: store}
}

func (r *RevocationRegistry) now() float64 {
	if r.Now != nil {
		return r.Now()
	}
	return float64(time.Now().UnixMilli())
}

// Revoke records a revocation. input: {kind, value | prefix, reason?, revokedAt?, notBefore?}. A null reason / revokedAt takes
// the default ("" / now).
func (r *RevocationRegistry) Revoke(input map[string]any) (RevocationEntry, error) {
	if input == nil {
		return nil, errors.New("revoke: input must be an object")
	}
	revokedAt := r.now()
	if v := input["revokedAt"]; v != nil {
		f, ok := jsNum(v)
		if !ok || !finite(f) {
			return nil, errors.New("revoke: revokedAt must be a finite number")
		}
		revokedAt = f + 0 // -0 is stored as 0 (JSON drops the sign anyway)
	}
	nb, hasNB := input["notBefore"]
	var notBefore float64
	if hasNB {
		f, ok := jsNum(nb)
		if !ok || !finite(f) {
			return nil, errors.New("revoke: notBefore must be a finite number")
		}
		notBefore = f + 0
	}
	reason := ""
	if v := input["reason"]; v != nil {
		s, ok := v.(string)
		if !ok {
			return nil, errors.New("revoke: reason must be a string")
		}
		reason = s
	}
	var e RevocationEntry
	kind, hasKind := input["kind"]
	if kind == "prefix" {
		l, ok := input["prefix"].([]any)
		if !ok || len(l) == 0 {
			return nil, errors.New("revoke: a prefix revocation requires a non-empty cap-id path")
		}
		parts := make([]string, len(l))
		for i, x := range l {
			s, ok := x.(string)
			if !ok || s == "" || strings.Contains(s, ",") {
				return nil, errors.New("revoke: every prefix element must be a non-empty string without ','")
			}
			parts[i] = s
		}
		e = RevocationEntry{"kind": "prefix", "value": strings.Join(parts, ","), "prefix": jsStrList(parts), "reason": reason, "revokedAt": jsNumber(revokedAt)}
	} else {
		v, ok := input["value"].(string)
		if !ok || v == "" {
			return nil, fmt.Errorf("revoke: a %s revocation requires a non-empty value", jsTemplate(kind, hasKind))
		}
		e = RevocationEntry{"value": v, "reason": reason, "revokedAt": jsNumber(revokedAt)}
		if hasKind {
			e["kind"] = kind
		}
	}
	if hasNB {
		e["notBefore"] = jsNumber(notBefore)
	}
	if err := r.Store.Add(e); err != nil {
		return nil, err
	}
	return e, nil
}

func withOpts(base map[string]any, opts map[string]any) map[string]any {
	for k, v := range opts {
		base[k] = v
	}
	return base
}

// RevokeSubtree revokes a whole delegation subtree: a cap id (string) or a cap-id path ([]any / []string, a prefix).
// opts: reason, revokedAt, notBefore.
func (r *RevocationRegistry) RevokeSubtree(target any, opts map[string]any) (RevocationEntry, error) {
	if l, ok := target.([]string); ok {
		target = jsStrList(l)
	}
	if l, ok := target.([]any); ok {
		return r.Revoke(withOpts(map[string]any{"kind": "prefix", "prefix": l}, opts))
	}
	return r.Revoke(withOpts(map[string]any{"kind": "cap", "value": target}, opts))
}

// Unrevoke removes a revocation by key {kind, value} or {kind: "prefix", prefix}.
func (r *RevocationRegistry) Unrevoke(key any) (bool, error) {
	k, ok := key.(map[string]any)
	if !ok {
		if _, arr := key.([]any); !arr {
			return false, errors.New("unrevoke: key must be an object")
		}
	}
	kind, hasKind := k["kind"]
	if kind == "prefix" {
		l, ok := k["prefix"].([]any)
		if !ok || len(l) == 0 {
			return false, nil
		}
		return r.Store.Remove("prefix", jsTemplate(l, true))
	}
	v, hasV := k["value"]
	return r.Store.Remove(jsTemplate(kind, hasKind), jsTemplate(v, hasV))
}

func (r *RevocationRegistry) List() ([]RevocationEntry, error) { return r.Store.All() }

// Lookup returns the entry for (kind, value), or nil.
func (r *RevocationRegistry) Lookup(kind, value string) (RevocationEntry, error) {
	return r.Store.Get(kind, value)
}

// Prefixes lists the subtree (prefix) revocations.
func (r *RevocationRegistry) Prefixes() ([]RevocationEntry, error) {
	all, err := r.Store.All()
	if err != nil {
		return nil, err
	}
	var out []RevocationEntry
	for _, e := range all {
		if e["kind"] == "prefix" {
			out = append(out, e)
		}
	}
	if out == nil {
		out = []RevocationEntry{}
	}
	return out, nil
}

func (r *RevocationRegistry) Clear() error { return r.Store.Clear() }

func killOpts(opts map[string]any, def string) map[string]any {
	reason := opts["reason"]
	if reason == nil {
		reason = def
	}
	return map[string]any{"reason": reason, "revokedAt": opts["revokedAt"]}
}

// KillAgent revokes a holder: every action it signs is refused from now on. opts: reason, revokedAt.
func (r *RevocationRegistry) KillAgent(holder any, opts map[string]any) (RevocationEntry, error) {
	return r.Revoke(withOpts(map[string]any{"kind": "holder", "value": holder}, killOpts(opts, "kill-switch: agent killed")))
}

// KillSubtree revokes a root capability and with it the subtree below it. opts: reason, revokedAt.
func (r *RevocationRegistry) KillSubtree(rootCapID any, opts map[string]any) (RevocationEntry, error) {
	return r.Revoke(withOpts(map[string]any{"kind": "cap", "value": rootCapID}, killOpts(opts, "kill-switch: subtree killed")))
}

// IsActiveAt: an entry without notBefore is active; a non-finite clock or notBefore counts as active (fail closed).
func IsActiveAt(entry RevocationEntry, nowMs float64) bool {
	nbv, has := entry["notBefore"]
	if !has {
		return true
	}
	nb, ok := jsNum(nbv)
	if !ok || !finite(nb) || !finite(nowMs) {
		return true
	}
	return nowMs >= nb
}

// IsRevokedResult is the outcome of CheckRevocation.
type IsRevokedResult struct {
	Revoked bool            `json:"revoked"`
	Matched RevocationEntry `json:"matched,omitempty"`
	Reason  string          `json:"reason,omitempty"`
}

func matchReason(e RevocationEntry) string {
	k, hk := e["kind"]
	v, hv := e["value"]
	base := jsTemplate(k, hk) + " " + jsTemplate(v, hv) + " is revoked"
	if s, _ := e["reason"].(string); s != "" {
		return base + ": " + s
	}
	return base
}

// CheckRevocation checks every hop of p.cap_chain (its id, issuer and holder) and the chain's id path against the registry.
// nowMs nil = the wall clock. It fails closed: a non-finite clock, a missing or malformed chain, or a failing store is revoked.
func CheckRevocation(p any, reg *RevocationRegistry, nowMs *float64) IsRevokedResult {
	closed := func(why string) IsRevokedResult {
		return IsRevokedResult{Revoked: true, Reason: "revocation check failed closed: " + why}
	}
	now := float64(time.Now().UnixMilli())
	if nowMs != nil {
		now = *nowMs
	}
	if !finite(now) {
		return closed("clock is not a finite number")
	}
	pm, _ := p.(map[string]any)
	chain, ok := pm["cap_chain"].([]any)
	if !ok || len(chain) == 0 {
		return closed("the action carries no capability chain")
	}
	for _, hop := range chain {
		h, _ := hop.(map[string]any)
		for _, k := range []string{"id", "issuer", "holder"} {
			if s, ok := h[k].(string); !ok || s == "" {
				return closed("a chain hop has no " + k)
			}
		}
	}
	if reg == nil || reg.Store == nil {
		return closed("the revocation store failed (Error)")
	}
	res, err := scanRevoked(chain, reg, now)
	if err != nil {
		return closed("the revocation store failed (Error)")
	}
	return res
}

func scanRevoked(chain []any, reg *RevocationRegistry, now float64) (IsRevokedResult, error) {
	ids := make([]string, 0, len(chain))
	for _, hop := range chain {
		h := hop.(map[string]any)
		for _, kk := range [][2]string{{"cap", "id"}, {"issuer", "issuer"}, {"holder", "holder"}} {
			e, err := reg.Lookup(kk[0], h[kk[1]].(string))
			if err != nil {
				return IsRevokedResult{}, err
			}
			if e != nil && IsActiveAt(e, now) {
				return IsRevokedResult{Revoked: true, Matched: e, Reason: matchReason(e)}, nil
			}
		}
		ids = append(ids, h["id"].(string))
	}
	prefixes, err := reg.Prefixes()
	if err != nil {
		return IsRevokedResult{}, err
	}
	for _, e := range prefixes {
		pre, _ := e["prefix"].([]any)
		if len(pre) == 0 || len(ids) < len(pre) || !IsActiveAt(e, now) {
			continue
		}
		match := true
		for i, x := range pre {
			if x != ids[i] {
				match = false
				break
			}
		}
		if match {
			return IsRevokedResult{Revoked: true, Matched: e, Reason: matchReason(e)}, nil
		}
	}
	return IsRevokedResult{}, nil
}

// VerifyWithRevocationResult combines the core verdict and the revocation check. Reason (any JSON value) is set on a deny.
type VerifyWithRevocationResult struct {
	Allow      bool            `json:"allow"`
	CoreAllow  bool            `json:"coreAllow"`
	Revocation IsRevokedResult `json:"revocation"`
	Reason     any             `json:"reason,omitempty"`
}

// VerifyWithRevocation allows only when the core verdict ({allow: true, ...}) allows AND nothing in the chain is revoked.
func VerifyWithRevocation(p any, coreVerdict any, reg *RevocationRegistry, nowMs *float64) VerifyWithRevocationResult {
	cm, _ := coreVerdict.(map[string]any)
	coreAllow := cm["allow"] == true
	rev := CheckRevocation(p, reg, nowMs)
	out := VerifyWithRevocationResult{Allow: coreAllow && !rev.Revoked, CoreAllow: coreAllow, Revocation: rev}
	if out.Allow {
		return out
	}
	if !coreAllow {
		out.Reason = "core verification failed"
		if r := cm["reason"]; r != nil {
			out.Reason = r
		}
	} else {
		out.Reason = rev.Reason
	}
	return out
}

func caepRevokedAt(ts any, reg *RevocationRegistry) float64 {
	if f, ok := jsNum(ts); ok && finite(f) {
		x := float64(f * 1000) // rounded here so arm64 cannot fuse the product into x-r below
		r := math.Floor(x) // Math.round: half up, exact for every double (floor(x+0.5) is not)
		if x-r >= 0.5 {
			r++
		}
		return r
	}
	return reg.now()
}

func caepString(subject map[string]any, key string) (string, bool) {
	s, ok := subject[key].(string)
	return s, ok && s != ""
}

func orDefault(v any, def string) any {
	if v == nil {
		return def
	}
	return v
}

// IngestCaepEvent turns a CAEP / SSF event ({type, payload}) into registry entries: grant-revoked revokes the grant, kill-switch
// kills the agent and/or the grant, session-revoked (and any other type) kills the subject's holder / agent / id.
func IngestCaepEvent(event any, reg *RevocationRegistry) ([]RevocationEntry, error) {
	ev, _ := event.(map[string]any)
	if !isJSObject(event) && event != nil {
		ev = map[string]any{} // a primitive has no members; its payload is undefined
	}
	if event == nil {
		return nil, errors.New("ingestCaepEvent: event must be an object")
	}
	payload, has := ev["payload"]
	if !has || payload == nil {
		return nil, errors.New("ingestCaepEvent: the event has no payload")
	}
	pl, _ := payload.(map[string]any)
	added := []RevocationEntry{}
	switch ev["type"] {
	case CaepGrantRevoked:
		if g, ok := caepString(pl, "grant_ref"); ok {
			e, err := reg.Revoke(map[string]any{"kind": "cap", "value": g, "reason": orDefault(pl["reason"], "CAEP grant-revoked"), "revokedAt": caepRevokedAt(pl["event_timestamp"], reg)})
			if err != nil {
				return nil, err
			}
			added = append(added, e)
		}
	case CaepKillSwitch:
		at := caepRevokedAt(pl["event_timestamp"], reg)
		reason := orDefault(pl["reason"], "CAEP kill-switch")
		if a, ok := caepString(pl, "agent"); ok {
			e, err := reg.KillAgent(a, map[string]any{"reason": reason, "revokedAt": at})
			if err != nil {
				return nil, err
			}
			added = append(added, e)
		}
		if g, ok := caepString(pl, "grant_ref"); ok {
			e, err := reg.Revoke(map[string]any{"kind": "cap", "value": g, "reason": reason, "revokedAt": at})
			if err != nil {
				return nil, err
			}
			added = append(added, e)
		}
	default:
		subj, hasSubj := pl["subject"]
		if hasSubj && subj == nil {
			return nil, errors.New("ingestCaepEvent: subject is null")
		}
		sm, _ := subj.(map[string]any)
		holder, ok := caepString(sm, "holder")
		if !ok {
			holder, ok = caepString(sm, "agent")
		}
		if !ok {
			holder, ok = caepString(sm, "id")
		}
		if ok {
			reason := pl["reason_admin"]
			if reason == nil {
				reason = orDefault(pl["reason_user"], "CAEP session-revoked")
			}
			e, err := reg.KillAgent(holder, map[string]any{"reason": reason, "revokedAt": caepRevokedAt(pl["event_timestamp"], reg)})
			if err != nil {
				return nil, err
			}
			added = append(added, e)
		}
	}
	return added, nil
}
