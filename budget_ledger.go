package pca

// The aggregate budget ledger (no overspend at principal, org and fleet scope): the reference KvBudgetLedger, its pure per-key
// document transitions, and the signed releases and scope keys that go with it. It implements the BudgetLedger contract of the
// store conformance profiles (requests, events and outcomes are JSON-shaped maps with the reference's member names).
//
// Two phases: Reserve (counted at once), then Start (recorded BEFORE the effect runs), then Commit (the effect happened) or
// Release (it did not). Expire frees only a reservation that was never started. A committed event is never released and a
// released one is never committed. Each operation is atomic per key; the same reservation again is a replay that changes nothing.

import (
	"encoding/json"
	"errors"
	"fmt"
)

// BudgetLedgerError is the typed failure of the aggregate budget ledger: Code is one of not_durable, scope_unbound, store_missing,
// store_corrupt, invalid, conflict_exhausted.
type BudgetLedgerError struct {
	Code    string
	Message string
}

// Error implements error: "<code>: <message>".
func (e *BudgetLedgerError) Error() string { return e.Code + ": " + e.Message }

// BudgetRangeError is an argument the ledger refuses (the reference's RangeError); nothing was written.
type BudgetRangeError struct{ Message string }

// Error implements error.
func (e *BudgetRangeError) Error() string { return e.Message }

func budRange(msg string) error { return &BudgetRangeError{msg} }

func budCorrupt() error {
	return &BudgetLedgerError{"store_corrupt", "budget document has the wrong shape"}
}

// BudgetIDOK is true for a ledger key or reservation id: a non-empty string of at most 256 UTF-16 units without control characters.
func BudgetIDOK(v any) bool {
	s, ok := v.(string)
	if !ok || s == "" || jsLen(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x1f {
			return false
		}
	}
	return true
}

// budgetDoc is one key's reservations and the pure transitions over them; every reference budget store is these plus a per-key lock.
type budgetDoc struct {
	ver    int64
	events []map[string]any
}

func (d *budgetDoc) encode() ([]byte, error) {
	es := make([]any, len(d.events))
	for i, e := range d.events {
		es[i] = normalizeJSON(e)
	}
	return json.Marshal(map[string]any{"v": jsNumber(1), "ver": jsNumber(float64(d.ver)), "events": es})
}

// budgetDecode decodes a stored document (nil = empty); it fails closed with store_corrupt.
func budgetDecode(raw []byte) (*budgetDoc, error) {
	if raw == nil {
		return &budgetDoc{}, nil
	}
	v, err := ParseJSONLenient(raw)
	m, ok := v.(map[string]any)
	if err != nil || !ok {
		return nil, budCorrupt()
	}
	evs, isList := m["events"].([]any)
	if x, _ := jsNum(m["v"]); !jsIsInt(m["v"]) || x != 1 || !jsIsInt(m["ver"]) || !isList {
		return nil, budCorrupt()
	}
	ver, _ := jsNum(m["ver"])
	d := &budgetDoc{ver: int64(ver)}
	for _, e := range evs {
		em, ok := e.(map[string]any)
		if _, isStr := em["id"].(string); !ok || !isStr {
			return nil, budCorrupt()
		}
		d.events = append(d.events, normalizeJSON(em).(map[string]any))
	}
	return d, nil
}

func (d *budgetDoc) find(id string) map[string]any {
	for _, e := range d.events {
		if e["id"] == any(id) {
			return e
		}
	}
	return nil
}

func budgetCore(e map[string]any) map[string]any {
	m := map[string]any{}
	for _, k := range []string{"id", "verb", "resource", "params", "t"} {
		if v, has := e[k]; has {
			m[k] = v
		}
	}
	return m
}

func budgetSameEvent(a, b map[string]any) bool {
	x, err1 := HashCanonical(budgetCore(a))
	y, err2 := HashCanonical(budgetCore(b))
	return err1 == nil && err2 == nil && x == y
}

func budgetOutcome(outcome string, ver int64, status string) map[string]any {
	m := map[string]any{"outcome": outcome, "version": jsNumber(float64(ver))}
	if status != "" {
		m["status"] = status
	}
	return m
}

func (d *budgetDoc) reserve(req map[string]any) (map[string]any, error) {
	e, _ := req["event"].(map[string]any)
	_, paramsMap := e["params"].(map[string]any)
	_, paramsList := e["params"].([]any)
	_, verbOK := e["verb"].(string)
	_, resOK := e["resource"].(string)
	if e == nil || !BudgetIDOK(e["id"]) || !verbOK || !resOK || !jsIsInt(e["t"]) || !(paramsMap || paramsList) {
		return nil, budRange("reserve: a malformed event")
	}
	accs, ok := req["accumulators"].([]any)
	if !ok {
		return nil, budRange("reserve: accumulators must be an array")
	}
	var expected *int64
	if v, has := req["expectedVersion"]; has {
		f, _ := jsNum(v)
		if !jsIsInt(v) {
			return nil, budRange("not a safe integer")
		}
		if f < 0 {
			return nil, budRange("reserve: expectedVersion must be a non-negative safe integer")
		}
		x := int64(f)
		expected = &x
	}
	if v, has := req["expiresAt"]; has && !jsIsInt(v) {
		return nil, budRange("not a safe integer")
	}
	id := e["id"].(string)
	if prior := d.find(id); prior != nil {
		if budgetSameEvent(prior, e) {
			st, _ := prior["status"].(string)
			return budgetOutcome("replayed", d.ver, st), nil
		}
		return budgetOutcome("id_conflict", d.ver, ""), nil
	}
	if expected != nil && *expected != d.ver {
		return budgetOutcome("conflict", d.ver, ""), nil
	}
	schema := req["schema"]
	haveSchema := schema != nil
	verb := e["verb"].(string)
	params, _ := e["params"].(map[string]any)
	post := map[string]any{}
	history := make([]any, len(d.events))
	for i, x := range d.events {
		history[i] = x
	}
	for _, a0 := range accs {
		a, _ := a0.(map[string]any)
		if a["domain_max"] == nil {
			return nil, budRange(fmt.Sprintf("reserve: accumulator %s has no domain_max (the cap)", jsValueString(a["id"])))
		}
		sel, throws := accSelects(a, verb, schema, haveSchema)
		if throws {
			return nil, errors.New("accSelects: unusable accumulator")
		}
		if !sel {
			continue
		}
		p, pok := accPost(a, history, verb, params, e["t"], schema, haveSchema)
		if !pok {
			return nil, &BudgetLedgerError{"store_corrupt", "unreadable history"}
		}
		cap, _ := jsNum(a["domain_max"])
		if !(finite(p) && p <= cap) { // an infinite cap is the unbounded one
			return map[string]any{"outcome": "over_cap", "version": jsNumber(float64(d.ver)), "acc": a["id"], "post": jsNumber(p), "cap": jsNumber(cap)}, nil
		}
		post[jsValueString(a["id"])] = jsNumber(p)
	}
	entry := map[string]any{"id": id, "verb": e["verb"], "resource": e["resource"], "params": normalizeJSON(e["params"]), "t": e["t"], "status": "reserved"}
	if v, has := req["expiresAt"]; has {
		f, _ := jsNum(v)
		entry["exp"] = jsNumber(f)
	}
	d.events = append(d.events, normalizeJSON(entry).(map[string]any))
	d.ver++
	out := budgetOutcome("reserved", d.ver, "")
	out["post"] = post
	return out, nil
}

func (d *budgetDoc) start(id string) map[string]any {
	e := d.find(id)
	if e == nil {
		return budgetOutcome("unknown", d.ver, "")
	}
	if e["status"] == "released" {
		return budgetOutcome("refused", d.ver, "released")
	}
	if _, started := e["started"]; started || e["status"] == "committed" {
		return budgetOutcome("replayed", d.ver, "")
	}
	e["started"] = true
	d.ver++
	return budgetOutcome("settled", d.ver, "")
}

func (d *budgetDoc) commit(id string) map[string]any {
	e := d.find(id)
	if e == nil {
		return budgetOutcome("unknown", d.ver, "")
	}
	if e["status"] == "committed" {
		return budgetOutcome("replayed", d.ver, "")
	}
	if e["status"] != "reserved" {
		st, _ := e["status"].(string)
		return budgetOutcome("refused", d.ver, st)
	}
	e["status"] = "committed"
	d.ver++
	return budgetOutcome("settled", d.ver, "")
}

func (d *budgetDoc) release(key, id string, evidence map[string]any) (map[string]any, error) {
	e := d.find(id)
	if e == nil {
		return budgetOutcome("unknown", d.ver, ""), nil
	}
	if e["status"] == "released" {
		return budgetOutcome("replayed", d.ver, ""), nil
	}
	if e["status"] != "reserved" {
		st, _ := e["status"].(string)
		return budgetOutcome("refused", d.ver, st), nil
	}
	if evidence != nil && (evidence["key"] != any(key) || evidence["id"] != any(id)) {
		return nil, budRange("release: the evidence is for another reservation")
	}
	e["status"] = "released"
	if evidence != nil {
		e["rel"] = normalizeJSON(evidence)
	}
	d.ver++
	return budgetOutcome("settled", d.ver, ""), nil
}

func (d *budgetDoc) expire(now float64) (map[string]any, error) {
	if !jsIsInt(jsNumber(now)) {
		return nil, budRange("expire: now must be a safe integer")
	}
	released := []any{}
	for _, e := range d.events {
		exp, hasExp := jsNum(e["exp"])
		_, started := e["started"]
		if e["status"] == "reserved" && !started && hasExp && exp <= now {
			e["status"] = "released"
			e["rel"] = map[string]any{"reason": "expired", "at": jsNumber(now)}
			released = append(released, e["id"])
		}
	}
	if len(released) > 0 {
		d.ver++
	}
	return map[string]any{"released": released, "version": jsNumber(float64(d.ver))}, nil
}

// ---- the kv ledger -------------------------------------------------------------------------------------------------------------

const budgetLedgerPrefix = "pca-budget-ledger/v1/"

// KvBudgetLedger is the reference budget ledger: one document per key in an AtomicKV, so every operation is one atomic
// read-modify-write. durable is declared by the caller because a kv cannot tell: pass true only for a persistent one
// (NewDurableAtomicKV, NewSQLAtomicKV); over MemoryAtomicKV it must be false. LIMIT: one document per key, rewritten per write; a
// production ledger is a database row-per-event with a unique index on (key, id) and a version column.
type KvBudgetLedger struct {
	kv      AtomicKV
	durable bool
}

// NewKvBudgetLedger builds the ledger over kv.
func NewKvBudgetLedger(kv AtomicKV, durable bool) (*KvBudgetLedger, error) {
	if kv == nil {
		return nil, &BudgetLedgerError{"store_missing", "KvBudgetLedger needs an AtomicKV"}
	}
	return &KvBudgetLedger{kv: kv, durable: durable}, nil
}

// Durable implements BudgetLedger.
func (l *KvBudgetLedger) Durable() bool { return l.durable }

func (l *KvBudgetLedger) k(key string) (string, error) {
	if !BudgetIDOK(key) {
		return "", budRange("a ledger key is a non-empty string without control characters")
	}
	return budgetLedgerPrefix + key, nil
}

// txn runs fn on the key's document atomically; the document is written back only when writes says so for the result.
func (l *KvBudgetLedger) txn(key string, fn func(d *budgetDoc) (map[string]any, error), writes func(map[string]any) bool) (res map[string]any, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, err = nil, fmt.Errorf("budget ledger: %v", r)
		}
	}()
	k, err := l.k(key)
	if err != nil {
		return nil, err
	}
	var ferr error
	uerr := l.kv.Update(k, func(prev []byte) []byte {
		d, e := budgetDecode(prev)
		if e != nil {
			ferr = e
			return nil
		}
		r, e := fn(d)
		if e != nil {
			ferr = e
			return nil
		}
		res = r
		if !writes(r) {
			return nil
		}
		b, e := d.encode()
		if e != nil {
			ferr = e
			return nil
		}
		return b
	})
	if uerr != nil {
		return nil, uerr
	}
	if ferr != nil {
		return nil, ferr
	}
	return res, nil
}

func budOutcomeIs(want string) func(map[string]any) bool {
	return func(r map[string]any) bool { return r["outcome"] == any(want) }
}

// Snapshot implements BudgetLedger: {version, events}.
func (l *KvBudgetLedger) Snapshot(key string) (map[string]any, error) {
	k, err := l.k(key)
	if err != nil {
		return nil, err
	}
	b, ok, err := l.kv.Get(k)
	if err != nil {
		return nil, err
	}
	var raw []byte
	if ok {
		raw = b
	}
	d, err := budgetDecode(raw)
	if err != nil {
		return nil, err
	}
	evs := make([]any, len(d.events))
	for i, e := range d.events {
		evs[i] = normalizeJSON(e)
	}
	return map[string]any{"version": jsNumber(float64(d.ver)), "events": evs}, nil
}

// Reserve implements BudgetLedger.
func (l *KvBudgetLedger) Reserve(key string, request map[string]any) (map[string]any, error) {
	return l.txn(key, func(d *budgetDoc) (map[string]any, error) { return d.reserve(request) }, budOutcomeIs("reserved"))
}

// Start implements BudgetLedger.
func (l *KvBudgetLedger) Start(key, id string) (map[string]any, error) {
	return l.txn(key, func(d *budgetDoc) (map[string]any, error) { return d.start(id), nil }, budOutcomeIs("settled"))
}

// Commit implements BudgetLedger.
func (l *KvBudgetLedger) Commit(key, id string) (map[string]any, error) {
	return l.txn(key, func(d *budgetDoc) (map[string]any, error) { return d.commit(id), nil }, budOutcomeIs("settled"))
}

// Release implements BudgetLedger (evidence nil: none).
func (l *KvBudgetLedger) Release(key, id string, evidence map[string]any) (map[string]any, error) {
	return l.txn(key, func(d *budgetDoc) (map[string]any, error) { return d.release(key, id, evidence) }, budOutcomeIs("settled"))
}

// Expire implements BudgetLedger.
func (l *KvBudgetLedger) Expire(key string, now float64) (map[string]any, error) {
	return l.txn(key, func(d *budgetDoc) (map[string]any, error) { return d.expire(now) },
		func(r map[string]any) bool { rel, _ := r["released"].([]any); return len(rel) > 0 })
}

// ---- scope keys and signed releases ---------------------------------------------------------------------------------------

// BudgetReleaseDomain is the signing domain of a release.
const BudgetReleaseDomain = "atlas-pca/budget-release/v1\x00"

var budgetReleaseReasons = []string{"effect_failed", "effect_not_run", "denied_downstream", "rollback"}

// BudgetScopeKey is the ledger key of a scope (principal, org, fleet) and its id; injective (the id is percent-encoded).
func BudgetScopeKey(scope, id string) (string, error) {
	if !BudgetIDOK(id) {
		return "", &BudgetLedgerError{"invalid", "a scope id is a non-empty string of at most 256 characters without control characters"}
	}
	return scope + "/" + encodeURIComponent(id), nil
}

func budgetReleaseMessage(r map[string]any) ([]byte, bool) {
	body := map[string]any{}
	for _, k := range []string{"v", "key", "id", "reason", "at", "signer"} {
		body[k] = r[k]
	}
	return domainMessage(BudgetReleaseDomain, normalizeJSON(body))
}

// SignBudgetRelease signs a release of key/id under the releaser's key: a statement that the reservation's effect did NOT happen.
// reason is one of effect_failed, effect_not_run, denied_downstream, rollback.
func SignBudgetRelease(key, id, reason string, at int64, secret *KeyPair) (map[string]any, error) {
	if secret == nil || !contains(budgetReleaseReasons, reason) || at < -maxSafeInt || at > maxSafeInt || !BudgetIDOK(key) || !BudgetIDOK(id) {
		return nil, budRange("signRelease: a malformed release")
	}
	base := map[string]any{"v": jsNumber(1), "key": key, "id": id, "reason": reason, "at": jsNumber(float64(at)), "signer": secret.Public}
	msg, ok := budgetReleaseMessage(base)
	if !ok {
		return nil, budRange("signRelease: a malformed release")
	}
	base["sig"] = b64.EncodeToString(secret.Sign(msg))
	return base, nil
}

// VerifyBudgetRelease is true iff r is well formed and signed by expectedSigner over exactly its content. Never panics.
func VerifyBudgetRelease(ro any, expectedSigner string) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	r, isMap := ro.(map[string]any)
	if !isMap {
		return false
	}
	reason, _ := r["reason"].(string)
	sig, sigOK := r["sig"].(string)
	if v, _ := jsNum(r["v"]); !jsIsInt(r["v"]) || v != 1 || r["signer"] != any(expectedSigner) || !contains(budgetReleaseReasons, reason) || !jsIsInt(r["at"]) ||
		!BudgetIDOK(r["key"]) || !BudgetIDOK(r["id"]) || !sigOK {
		return false
	}
	if _, ok := DecodeB64uStrict(sig, sigLen); !ok {
		return false
	}
	msg, mok := budgetReleaseMessage(r)
	return mok && verifyB64u(expectedSigner, msg, sig)
}

// BudgetReleaseDigest is the content address of a signed release.
func BudgetReleaseDigest(r map[string]any) (string, error) {
	return HashCanonical(map[string]any{"d": "atlas-pca/budget-release-ref/v1", "r": normalizeJSON(r)})
}

// BudgetReleaseCommit is the log leaf of a release.
func BudgetReleaseCommit(r map[string]any) (string, error) {
	d, err := BudgetReleaseDigest(r)
	if err != nil {
		return "", err
	}
	return HashCanonical(map[string]any{"d": "atlas-pca/budget-release-leaf/v1", "digest": d})
}

// ---- the undo coordinator's seam ------------------------------------------------------------------------------------------------

type undoBudgetFromLedger struct{ l BudgetLedger }

// UndoBudgetFromLedger adapts a BudgetLedger to the settle seam of the undo coordinator (UndoBudget.Ledger).
func UndoBudgetFromLedger(l BudgetLedger) UndoBudgetLedger { return undoBudgetFromLedger{l} }

func budOutcomeOf(m map[string]any, err error) (string, error) {
	if err != nil {
		return "", err
	}
	s, _ := m["outcome"].(string)
	return s, nil
}

// Commit implements UndoBudgetLedger.
func (u undoBudgetFromLedger) Commit(key, id string) (string, error) {
	return budOutcomeOf(u.l.Commit(key, id))
}

// Release implements UndoBudgetLedger; evidence (a signed release) may be nil.
func (u undoBudgetFromLedger) Release(key, id string, evidence any) (string, error) {
	ev, _ := evidence.(map[string]any)
	return budOutcomeOf(u.l.Release(key, id, ev))
}
