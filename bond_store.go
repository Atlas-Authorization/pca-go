package pca

// Durable bonds: KvBondStore, the reference BondStore over an atomic key-value store, and StoreBondLedger, the bond ledger whose
// every state change is one atomic store commit of a signed plan.
//
// THE STORE holds one document {v, balances, bonds, highWater}. Commit applies a plan iff the bond is in the phase the plan
// expects: the balance moves, the phase change and the settlement record land together or not at all, the same plan again is a
// replay (it answers the stored record and moves nothing), and anything else is a conflict. So two processes can never both
// settle one bond, and a retry after a lost answer never pays twice.
//
// THE LEDGER reads a snapshot, plans against it with BondSettlementPlanner (which verifies the evidence), and commits. The
// challenge window is enforced on the store-registered time, never on a time the claim carries, and against the store's own
// high-water mark so a clock that jumped back cannot reopen a window.

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
)

// BondDocKey is the key KvBondStore keeps its single document under by default.
const BondDocKey = "pca-bond-store/v1"

// bdoc is the decoded bond document; balances and bonds keep their insertion order.
type bdoc struct {
	balOrder  []string
	balances  map[string]float64
	bondOrder []string
	bonds     map[string]map[string]any
	highWater float64
}

func bdocEmpty() *bdoc {
	return &bdoc{balances: map[string]float64{}, bonds: map[string]map[string]any{}}
}

func (d *bdoc) setBalance(account string, v float64) {
	if _, ok := d.balances[account]; !ok {
		d.balOrder = append(d.balOrder, account)
	}
	d.balances[account] = v
}

func (d *bdoc) balance(account string) float64 { return d.balances[account] }

func bdocCorrupt(why string) error { return &BondStoreError{"store_corrupt", why} }

func bdocDecode(raw []byte) (*bdoc, error) {
	d := bdocEmpty()
	if raw == nil {
		return d, nil
	}
	v, err := ParseJSONLenient(raw)
	m, ok := v.(map[string]any)
	if err != nil || !ok {
		return nil, bdocCorrupt("bond document has the wrong shape")
	}
	ver, isNum := jsNum(m["v"])
	bals, balsOK := m["balances"].([]any)
	bonds, bondsOK := m["bonds"].([]any)
	hw, hwOK := jsNum(m["highWater"])
	if !isNum || ver != 1 || !balsOK || !bondsOK || !hwOK {
		return nil, bdocCorrupt("bond document has the wrong shape")
	}
	if !bsFinite(hw) || hw < 0 {
		return nil, bdocCorrupt("highWater is not a non-negative number")
	}
	d.highWater = hw
	for _, e := range bals {
		pair, isList := e.([]any)
		if !isList || len(pair) != 2 {
			return nil, bdocCorrupt("malformed balance entry")
		}
		acct, isStr := pair[0].(string)
		n, isN := extFinite(pair[1])
		if !isStr || !isN || n < 0 {
			return nil, bdocCorrupt("malformed balance entry")
		}
		d.setBalance(acct, n)
	}
	for _, b := range bonds {
		row, isMap := b.(map[string]any)
		id, idOK := row["claimId"].(string)
		_, depOK := row["depositor"].(string)
		_, amtOK := extFinite(row["amount"])
		st, _ := row["status"].(string)
		recs, recsOK := row["records"].([]any)
		if !isMap || !idOK || !depOK || !amtOK || !(st == "open" || st == "released" || st == "slashed") || !recsOK || len(recs) == 0 {
			return nil, bdocCorrupt("malformed bond row")
		}
		if _, dup := d.bonds[id]; dup {
			return nil, bdocCorrupt("duplicate bond row")
		}
		d.bondOrder = append(d.bondOrder, id)
		d.bonds[id] = normalizeJSON(row).(map[string]any)
	}
	return d, nil
}

func (d *bdoc) encode() ([]byte, error) {
	bals := make([]any, len(d.balOrder))
	for i, a := range d.balOrder {
		bals[i] = []any{a, bsNum(d.balances[a])}
	}
	bonds := make([]any, len(d.bondOrder))
	for i, id := range d.bondOrder {
		bonds[i] = d.bonds[id]
	}
	return json.Marshal(map[string]any{"v": jsNumber(1), "balances": bals, "bonds": bonds, "highWater": bsNum(d.highWater)})
}

func bdocStatus(bond map[string]any) string {
	if bond == nil {
		return "none"
	}
	s, _ := bond["status"].(string)
	return s
}

func bdocConflict(reason, current string) map[string]any {
	return map[string]any{"outcome": "conflict", "reason": reason, "current": current}
}

// SameSettlement reports whether two settlement records describe the same movement (claim, action, amount, parties, evidence and
// split); the time and the signature are not compared, so a retry planned later still matches the stored record.
func SameSettlement(a, b map[string]any) (bool, error) {
	if a == nil || b == nil {
		return false, errors.New("sameSettlement: a settlement record is required")
	}
	for _, k := range []string{"claimId", "action", "amount", "from", "to", "evidenceDigest"} {
		if !oaSame(a, k, b, k) {
			return false, nil
		}
	}
	ha, err := HashCanonicalLenient(a["split"])
	if err != nil {
		return false, err
	}
	hb, err := HashCanonicalLenient(b["split"])
	if err != nil {
		return false, err
	}
	return ha == hb, nil
}

func bdocWindow(m map[string]any) map[string]any {
	w, _ := m["window"].(map[string]any)
	return w
}

func bdocSameWindow(a, b map[string]any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return oaSame(a, "windowMs", b, "windowMs") && oaSame(a, "claimDigest", b, "claimDigest") // registeredAt is the first call's
}

func bdocRecords(bond map[string]any) []any {
	r, _ := bond["records"].([]any)
	return r
}

func (d *bdoc) openTotals(depositor string) (count, sum float64) {
	for _, id := range d.bondOrder {
		b := d.bonds[id]
		if dep, _ := b["depositor"].(string); bdocStatus(b) == "open" && dep == depositor {
			count++
			sum += jsF(b["amount"])
		}
	}
	return count, sum
}

// bdocCommit applies plan to d (see BondStore.Commit); an error is a malformed plan the reference would throw on.
func bdocCommit(d *bdoc, plan map[string]any, observedAt float64) (map[string]any, error) {
	claimID, _ := plan["claimId"].(string)
	bond := d.bonds[claimID]
	record, _ := plan["record"].(map[string]any)
	open, _ := plan["open"].(map[string]any)
	expect, _ := plan["expect"].(string)
	next, _ := plan["next"].(string)
	switch {
	case expect == "none":
		if open == nil || next != "open" {
			return bdocConflict("malformed open plan", bdocStatus(bond)), nil
		}
		if bond != nil {
			recs := bdocRecords(bond)
			same := oaSame(bond, "depositor", open, "depositor") && oaSame(bond, "amount", open, "amount") && bdocSameWindow(bdocWindow(bond), bdocWindow(open)) && len(recs) > 0
			if same {
				first, _ := recs[0].(map[string]any)
				eq, err := SameSettlement(first, record)
				if err != nil {
					return nil, err
				}
				if eq {
					return map[string]any{"outcome": "replayed", "record": first}, nil
				}
			}
			return bdocConflict("bond "+claimID+" already exists", bdocStatus(bond)), nil
		}
		dep, _ := open["depositor"].(string)
		count, sum := d.openTotals(dep)
		if !(bsFinite(count) && count+1 <= jsF(open["maxOpenClaims"])) {
			return bdocConflict("depositor open-claim cap reached", "none"), nil
		}
		if !(bsFinite(sum+jsF(open["amount"])) && sum+jsF(open["amount"]) <= jsF(open["maxOpenAmount"])) { // an infinite cap is the unbounded one
			return bdocConflict("depositor aggregate open-bond cap exceeded", "none"), nil
		}
	case bond == nil:
		return bdocConflict("no bond for "+claimID, "none"), nil
	case bdocStatus(bond) != expect:
		recs := bdocRecords(bond)
		if bdocStatus(bond) == next && len(recs) > 0 {
			last, _ := recs[len(recs)-1].(map[string]any)
			eq, err := SameSettlement(last, record)
			if err != nil {
				return nil, err
			}
			if eq {
				return map[string]any{"outcome": "replayed", "record": last}, nil
			}
		}
		return bdocConflict("bond "+claimID+" is already "+bdocStatus(bond), bdocStatus(bond)), nil
	}
	moved, err := ApplyBondMoves(d.balance, bsMovesOf(plan["moves"]))
	if err != nil {
		return bdocConflict(err.Error(), bdocStatus(bond)), nil
	}
	for _, m := range bsMovesOf(plan["moves"]) { // in move order, so new accounts keep the order they were first touched in
		d.setBalance(m.Account, moved[m.Account])
	}
	if open != nil {
		row := map[string]any{"claimId": claimID, "status": "open", "records": []any{plan["record"]}}
		bsPut(row, "amount", open, "amount")
		bsPut(row, "depositor", open, "depositor")
		if w := bdocWindow(open); w != nil {
			row["window"] = w
		}
		if bond == nil {
			d.bondOrder = append(d.bondOrder, claimID)
		}
		d.bonds[claimID] = normalizeJSON(row).(map[string]any)
	} else {
		bond["status"] = next
		bond["records"] = append(bdocRecords(bond), normalizeJSON(plan["record"]))
	}
	if bsFinite(observedAt) {
		d.highWater = math.Max(d.highWater, observedAt)
	}
	return map[string]any{"outcome": "committed", "record": plan["record"]}, nil
}

func (d *bdoc) snapshot(query map[string]any) map[string]any {
	claimID, _ := query["claimId"].(string)
	out := map[string]any{}
	if b := d.bonds[claimID]; b != nil {
		out["bond"] = normalizeJSON(b)
	}
	balances := []any{}
	count, sum := 0.0, 0.0
	if dep, ok := query["depositor"].(string); ok {
		count, sum = d.openTotals(dep)
		balances = append(balances, []any{dep, bsNum(d.balance(dep))})
	}
	out["balances"] = balances
	out["openTotals"] = map[string]any{"count": bsNum(count), "sum": bsNum(sum)}
	out["highWater"] = bsNum(d.highWater)
	return out
}

// KvBondStore is the reference BondStore: the whole state is one document in an atomic key-value store, so every commit is one
// atomic read-modify-write. LIMIT: the document is rewritten on every write; a production store keeps a row per bond.
type KvBondStore struct {
	kv  AtomicKV
	key string
}

var _ BondStore = (*KvBondStore)(nil)

// NewKvBondStore returns a bond store over kv under BondDocKey (store_missing without a kv).
func NewKvBondStore(kv AtomicKV) (*KvBondStore, error) { return NewKvBondStoreAt(kv, BondDocKey) }

// NewKvBondStoreAt is NewKvBondStore under another key.
func NewKvBondStoreAt(kv AtomicKV, key string) (*KvBondStore, error) {
	if kv == nil {
		return nil, &BondStoreError{"store_missing", "KvBondStore needs an atomic kv"}
	}
	return &KvBondStore{kv: kv, key: key}, nil
}

// Read returns the snapshot for {claimId, depositor?}: {bond?, balances: [[depositor, balance]], openTotals: {count, sum},
// highWater}. Without a depositor the balances are empty and the totals zero.
func (s *KvBondStore) Read(query map[string]any) (map[string]any, error) {
	raw, ok, err := s.kv.Get(s.key)
	if err != nil {
		return nil, err
	}
	if !ok {
		raw = nil
	}
	d, err := bdocDecode(raw)
	if err != nil {
		return nil, err
	}
	return d.snapshot(query), nil
}

// Commit applies a plan atomically: {outcome: committed | replayed, record} or {outcome: conflict, reason, current}. observedAt
// raises the store's high-water mark.
func (s *KvBondStore) Commit(plan map[string]any, observedAt float64) (map[string]any, error) {
	var out map[string]any
	err := storeKvTxn(s.kv, s.key, func(prev []byte) ([]byte, error) {
		d, e := bdocDecode(prev)
		if e != nil {
			return nil, e
		}
		r, e := bdocCommit(d, plan, observedAt)
		if e != nil {
			return nil, e
		}
		out = r
		if r["outcome"] != any("committed") {
			return nil, nil // leave the key untouched
		}
		return d.encode()
	})
	return out, err
}

// Deposit credits amount (positive and finite) to account and returns the new balance.
func (s *KvBondStore) Deposit(account string, amount float64) (float64, error) {
	if account == "" {
		return 0, storeRange("deposit: account is required")
	}
	if !bsFinite(amount) || amount <= 0 {
		return 0, storeRange("deposit: amount must be a positive finite number")
	}
	balance := 0.0
	err := storeKvTxn(s.kv, s.key, func(prev []byte) ([]byte, error) {
		d, e := bdocDecode(prev)
		if e != nil {
			return nil, e
		}
		moved, e := ApplyBondMoves(d.balance, []BondMove{{account, "credit", amount}})
		if e != nil {
			return nil, e
		}
		balance = moved[account]
		d.setBalance(account, balance)
		return d.encode()
	})
	return balance, err
}

// ---- the store-backed ledger ---------------------------------------------------------------------------------------------------------

// StoreBondLedgerOptions configure NewStoreBondLedger: the planner options, the Store (required: there is no in-memory default),
// the Clock in milliseconds (nil: the wall clock) and the challenge-window policy (nil: the default).
type StoreBondLedgerOptions struct {
	BondPlannerOptions
	Store        BondStore
	Clock        func() float64
	WindowPolicy *ChallengeWindowPolicy
}

// StoreBondLedger is the bond ledger over a BondStore. Every method that fails returns a *BondStoreError (store_unavailable,
// store_corrupt, clock_invalid, invalid_claim, window_open, window_closed, unregistered, claim_mismatch, conflict) or, for a
// request the planner refuses (bad evidence, a double settle, an insufficient balance), a plain error.
type StoreBondLedger struct {
	planner *BondSettlementPlanner
	store   BondStore
	clock   func() float64
	window  ChallengeWindowPolicy
}

// NewStoreBondLedger returns a ledger (store_missing without a store, guardian_key_missing without a guardian key).
func NewStoreBondLedger(o StoreBondLedgerOptions) (*StoreBondLedger, error) {
	if o.Store == nil {
		return nil, &BondStoreError{"store_missing", "a BondStore is required (there is no in-memory default)"}
	}
	if o.Guardian == nil || o.Guardian.Public == "" {
		return nil, &BondStoreError{"guardian_key_missing", "a guardian secret key is required"}
	}
	planner, err := NewBondSettlementPlanner(o.BondPlannerOptions)
	if err != nil {
		return nil, err
	}
	l := &StoreBondLedger{planner: planner, store: o.Store, clock: o.Clock, window: DefaultChallengeWindowPolicy}
	if l.clock == nil {
		l.clock = func() float64 { return float64(time.Now().UnixMilli()) }
	}
	if o.WindowPolicy != nil {
		l.window = *o.WindowPolicy
	}
	return l, nil
}

// GuardianPublicKey is the key every settlement record of this ledger verifies under.
func (l *StoreBondLedger) GuardianPublicKey() string { return l.planner.GuardianPublicKey }

func sblGuard(err error) error {
	var be *BondStoreError
	if err == nil || errors.As(err, &be) {
		return err
	}
	msg := err.Error()
	if msg == "" {
		msg = "store failed"
	}
	return &BondStoreError{"store_unavailable", msg}
}

// sblView is the planner's view of one snapshot.
type sblView struct {
	bond     map[string]any
	balances map[string]float64
	count    float64
	sum      float64
}

func (v sblView) Bond(claimID string) map[string]any {
	if id, _ := v.bond["claimId"].(string); v.bond != nil && id == claimID {
		return v.bond
	}
	return nil
}

func (v sblView) BalanceOf(account string) float64 { return v.balances[account] }

func (v sblView) OpenTotals(string) (float64, float64) { return v.count, v.sum }

func (l *StoreBondLedger) load(claimID, depositor string) (bond map[string]any, view sblView, now float64, err error) {
	query := map[string]any{"claimId": claimID}
	if depositor != "" {
		query["depositor"] = depositor
	}
	snap, err := l.store.Read(query)
	if err != nil {
		return nil, sblView{}, 0, sblGuard(err)
	}
	t := l.clock()
	if !bsFinite(t) {
		return nil, sblView{}, 0, &BondStoreError{"clock_invalid", "the clock returned a non-finite time"}
	}
	bond, _ = snap["bond"].(map[string]any)
	view = sblView{bond: bond, balances: map[string]float64{}}
	if list, ok := snap["balances"].([]any); ok {
		for _, e := range list {
			if pair, ok := e.([]any); ok && len(pair) == 2 {
				acct, _ := pair[0].(string)
				view.balances[acct] = jsF(pair[1])
			}
		}
	}
	totals, _ := snap["openTotals"].(map[string]any)
	view.count, view.sum = jsF(totals["count"]), jsF(totals["sum"])
	return bond, view, math.Max(t, jsF(snap["highWater"])), nil
}

func (l *StoreBondLedger) submit(plan map[string]any, now float64) (map[string]any, error) {
	out, err := l.store.Commit(plan, now)
	if err != nil {
		return nil, sblGuard(err)
	}
	if out["outcome"] == any("conflict") {
		reason, _ := out["reason"].(string)
		return nil, &BondStoreError{"conflict", reason}
	}
	record, _ := out["record"].(map[string]any)
	return record, nil
}

func bdocRecordOf(plan map[string]any) map[string]any {
	r, _ := plan["record"].(map[string]any)
	return r
}

// settle runs one settlement: a bond already settled answers its stored record when the same evidence would settle it the same
// way again (a retry), and refuses otherwise; an open bond passes the gate, is planned and committed.
func (l *StoreBondLedger) settle(claimID string, plan func(view BondView, now float64) (map[string]any, error), gate func(bond map[string]any, now float64) error) (map[string]any, error) {
	bond, view, now, err := l.load(claimID, "")
	if err != nil {
		return nil, err
	}
	if bond != nil && bdocStatus(bond) != "open" {
		asOpen := view
		asOpen.bond = copyMap(bond)
		asOpen.bond["status"] = "open"
		again, err := plan(asOpen, now) // fails if the evidence no longer holds
		if err != nil {
			return nil, err
		}
		if recs := bdocRecords(bond); len(recs) > 0 {
			last, _ := recs[len(recs)-1].(map[string]any)
			if eq, err := SameSettlement(last, bdocRecordOf(again)); err != nil {
				return nil, err
			} else if eq {
				return last, nil
			}
		}
		p, err := plan(view, now) // the standard double-settle refusal
		if err != nil {
			return nil, err
		}
		return bdocRecordOf(p), nil
	}
	if bond != nil && gate != nil {
		if err := gate(bond, now); err != nil {
			return nil, err
		}
	}
	p, err := plan(view, now)
	if err != nil {
		return nil, err
	}
	return l.submit(p, now)
}

// Deposit credits an account and returns its new balance.
func (l *StoreBondLedger) Deposit(account string, amount float64) (float64, error) {
	b, err := l.store.Deposit(account, amount)
	return b, sblGuard(err)
}

// BalanceOf is the balance of an account (0 for an unknown one).
func (l *StoreBondLedger) BalanceOf(account string) (float64, error) {
	query := map[string]any{"claimId": "", "depositor": account}
	snap, err := l.store.Read(query)
	if err != nil {
		return 0, sblGuard(err)
	}
	if list, ok := snap["balances"].([]any); ok && len(list) > 0 {
		if pair, ok := list[0].([]any); ok && len(pair) == 2 {
			if f, ok := jsNum(pair[1]); ok {
				return f, nil
			}
		}
	}
	return 0, nil
}

// GetBond returns the bond row {claimId, amount, depositor, status, window?, records}, or nil when there is none.
func (l *StoreBondLedger) GetBond(claimID string) (map[string]any, error) {
	snap, err := l.store.Read(map[string]any{"claimId": claimID})
	if err != nil {
		return nil, sblGuard(err)
	}
	bond, _ := snap["bond"].(map[string]any)
	return bond, nil
}

// BondStatus is none, open, released or slashed.
func (l *StoreBondLedger) BondStatus(claimID string) (string, error) {
	bond, err := l.GetBond(claimID)
	if err != nil {
		return "", err
	}
	return bdocStatus(bond), nil
}

func sblWindowEnd(w map[string]any) float64 { return jsF(w["registeredAt"]) + jsF(w["windowMs"]) }

// ChallengeStatus is {phase: open | finalized, endsAt, now} of a registered claim's challenge window on the store's time
// (unregistered when the bond backs no registered claim).
func (l *StoreBondLedger) ChallengeStatus(claimID string) (map[string]any, error) {
	bond, _, now, err := l.load(claimID, "")
	if err != nil {
		return nil, err
	}
	w := bdocWindow(bond)
	if w == nil {
		return nil, &BondStoreError{"unregistered", "bond " + claimID + " has no registered claim"}
	}
	if !finite(now) || !finite(sblWindowEnd(w)) { // never report finalized (it opens settlement) on a time that is not a number
		return nil, &BondStoreError{"clock_invalid", "the challenge window or clock is not finite"}
	}
	phase := "open"
	if now > sblWindowEnd(w) {
		phase = "finalized"
	}
	return map[string]any{"phase": phase, "endsAt": bsNum(sblWindowEnd(w)), "now": bsNum(now)}, nil
}

func (l *StoreBondLedger) replayOpen(prior map[string]any, depositor string, amount float64, claimDigest *string) (map[string]any, error) {
	dep, _ := prior["depositor"].(string)
	same := dep == depositor && jsF(prior["amount"]) == amount
	if w := bdocWindow(prior); same {
		d, has := w["claimDigest"].(string)
		same = (claimDigest == nil && !has) || (claimDigest != nil && has && d == *claimDigest)
	}
	if recs := bdocRecords(prior); same && len(recs) > 0 {
		if first, ok := recs[0].(map[string]any); ok {
			return first, nil
		}
	}
	id, _ := prior["claimId"].(string)
	return nil, &BondStoreError{"conflict", "openBond: bond " + id + " already exists (double-open refused)"}
}

func sblExposure(exposure *float64) float64 {
	if exposure == nil {
		return 0
	}
	return *exposure
}

// OpenClaim verifies a bonded claim on the store's time, registers its challenge window and opens its bond (the claim's bond_ref)
// with the depositor's collateral. The same call again answers the stored open record. It refuses a claim that does not verify or
// whose window is below the 30 s floor (invalid_claim).
func (l *StoreBondLedger) OpenClaim(claim, pcactn map[string]any, signerPublic string, amount float64, depositor string, exposure *float64) (map[string]any, error) {
	prior, view, now, err := l.load(oaString(oaGet(claim, "bond_ref")), depositor)
	if err != nil {
		return nil, err
	}
	var c any
	if claim != nil {
		c = claim
	}
	if v := VerifyClaim(c, pcactn, signerPublic, now, &l.window); v["ok"] != true {
		reason, _ := v["reason"].(string)
		return nil, &BondStoreError{"invalid_claim", reason}
	}
	floor := math.Max(l.window.MinWindowMs, DefaultMinChallengeWindowMs)
	windowMs := jsF(claim["challenge_window_ms"])
	if windowMs < floor {
		return nil, &BondStoreError{"invalid_claim", fmt.Sprintf("challenge window %s ms is below the %s ms floor", rsNumStr(windowMs), rsNumStr(floor))}
	}
	ref, _ := claim["bond_ref"].(string)
	if ref == "" {
		return nil, &BondStoreError{"invalid_claim", "claim has no bond_ref"}
	}
	digest, err := HashCanonicalLenient(claim)
	if err != nil {
		return nil, err
	}
	if prior != nil {
		return l.replayOpen(prior, depositor, amount, &digest)
	}
	plan, err := l.planner.PlanOpen(view, ref, amount, depositor, sblExposure(exposure), now, &BondRegistration{RegisteredAt: now, WindowMs: windowMs, ClaimDigest: digest})
	if err != nil {
		return nil, err
	}
	return l.submit(plan, now)
}

// OpenBond opens a bond that backs no registered claim (a challenger's counter-bond). The same call again answers the stored
// open record.
func (l *StoreBondLedger) OpenBond(claimID string, amount float64, depositor string, exposure *float64) (map[string]any, error) {
	prior, view, now, err := l.load(claimID, depositor)
	if err != nil {
		return nil, err
	}
	if prior != nil {
		return l.replayOpen(prior, depositor, amount, nil)
	}
	plan, err := l.planner.PlanOpen(view, claimID, amount, depositor, sblExposure(exposure), now, nil)
	if err != nil {
		return nil, err
	}
	return l.submit(plan, now)
}

func (l *StoreBondLedger) planRelease(claimID string) func(BondView, float64) (map[string]any, error) {
	return func(view BondView, now float64) (map[string]any, error) {
		return l.planner.PlanRelease(view, claimID, now)
	}
}

// Release returns the bond of a registered claim to its depositor once the challenge window has closed (window_open before;
// unregistered for a bond that backs no claim).
func (l *StoreBondLedger) Release(claimID string) (map[string]any, error) {
	return l.settle(claimID, l.planRelease(claimID), func(bond map[string]any, now float64) error {
		w := bdocWindow(bond)
		if w == nil {
			return &BondStoreError{"unregistered", "bond " + claimID + " has no registered claim; use ReleaseUnregistered for a counter-bond"}
		}
		if !(finite(now) && finite(sblWindowEnd(w)) && now > sblWindowEnd(w)) {
			return &BondStoreError{"window_open", "the challenge window of " + claimID + " closes at " + rsNumStr(sblWindowEnd(w))}
		}
		return nil
	})
}

// ReleaseUnregistered returns a bond that backs no registered claim (a counter-bond); a bond that backs one is a conflict.
func (l *StoreBondLedger) ReleaseUnregistered(claimID string) (map[string]any, error) {
	return l.settle(claimID, l.planRelease(claimID), func(bond map[string]any, _ float64) error {
		if bdocWindow(bond) != nil {
			return &BondStoreError{"conflict", "bond " + claimID + " backs a registered claim; use Release"}
		}
		return nil
	})
}

func sblClaimDigest(claim map[string]any) (string, error) {
	if claim == nil {
		return "", errors.New("a claim is required")
	}
	return HashCanonicalLenient(claim)
}

func sblChallengeGate(claim map[string]any) func(map[string]any, float64) error {
	return func(bond map[string]any, now float64) error {
		id, _ := bond["claimId"].(string)
		w := bdocWindow(bond)
		if w == nil {
			return &BondStoreError{"unregistered", "bond " + id + " has no registered claim"}
		}
		digest, err := sblClaimDigest(claim)
		if err != nil {
			return err
		}
		if d, _ := w["claimDigest"].(string); d != digest {
			return &BondStoreError{"claim_mismatch", "the claim is not the one registered for " + id}
		}
		if !(finite(now) && finite(sblWindowEnd(w)) && now <= sblWindowEnd(w)) {
			return &BondStoreError{"window_closed", "the challenge window of " + id + " closed at " + rsNumStr(sblWindowEnd(w))}
		}
		return nil
	}
}

// SlashBond slashes the bond of the registered claim on a verified fraud proof, inside the challenge window (window_closed after;
// claim_mismatch for another claim).
func (l *StoreBondLedger) SlashBond(q SlashParams) (map[string]any, error) {
	return l.settle(q.ClaimID, func(view BondView, now float64) (map[string]any, error) { return l.planner.PlanSlash(view, q, now) }, sblChallengeGate(q.Claim))
}

// SlashBondOnDispute slashes the bond of the registered claim on an adjudicated dispute, inside the challenge window.
func (l *StoreBondLedger) SlashBondOnDispute(q SlashParams) (map[string]any, error) {
	return l.settle(q.ClaimID, func(view BondView, now float64) (map[string]any, error) {
		return l.planner.PlanSlashOnDispute(view, q, now)
	}, sblChallengeGate(q.Claim))
}

// SlashBondOnRevocation slashes a bond because the capability behind its claim was revoked; revocation has no window.
func (l *StoreBondLedger) SlashBondOnRevocation(q SlashParams) (map[string]any, error) {
	return l.settle(q.ClaimID, func(view BondView, now float64) (map[string]any, error) {
		return l.planner.PlanSlashOnRevocation(view, q, now)
	}, func(bond map[string]any, _ float64) error {
		w := bdocWindow(bond)
		if w == nil {
			return nil
		}
		digest, err := sblClaimDigest(q.Claim)
		if err != nil {
			return err
		}
		if d, _ := w["claimDigest"].(string); d != digest {
			id, _ := bond["claimId"].(string)
			return &BondStoreError{"claim_mismatch", "the claim is not the one registered for " + id}
		}
		return nil
	})
}

// SlashCounterBond slashes a challenger's counter-bond (q.ClaimID) because the dispute was frivolous.
func (l *StoreBondLedger) SlashCounterBond(q SlashParams) (map[string]any, error) {
	return l.settle(q.ClaimID, func(view BondView, now float64) (map[string]any, error) {
		return l.planner.PlanSlashCounterBond(view, q, now)
	}, nil)
}
