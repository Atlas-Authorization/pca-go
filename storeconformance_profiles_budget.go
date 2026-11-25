package pca

// The aggregate budget ledger and bond-settlement store profiles (see storeconformance_profiles.go for the adapter model).

import (
	"fmt"
	"math"
	"sort"
)

// BudgetLedger is an aggregate budget ledger. Requests, events and outcomes are JSON-shaped maps with the reference's member names:
// Reserve takes {event, accumulators, expectedVersion?, expiresAt?} and returns {outcome: reserved | replayed | over_cap |
// id_conflict | conflict, ...}; Snapshot is {version, events}; Commit, Release (evidence nil: none), Start return {outcome:
// settled | replayed | unknown | refused, ...}; Expire returns {released: [ids]}. Durable reports whether the ledger survives a
// restart. Invalid input is an error that writes nothing.
type BudgetLedger interface {
	Reserve(key string, request map[string]any) (map[string]any, error)
	Snapshot(key string) (map[string]any, error)
	Commit(key, id string) (map[string]any, error)
	Release(key, id string, evidence map[string]any) (map[string]any, error)
	Start(key, id string) (map[string]any, error)
	Expire(key string, now float64) (map[string]any, error)
	Durable() bool
}

const (
	budCap = 200
	budK   = "principal/alice"
	budK2  = "principal/bob"
)

func budSpend(over map[string]any) map[string]any {
	a := map[string]any{"id": "spend", "agg": "sum", "val": "action.params.amount", "sel": map[string]any{"verbs": []any{"pay"}}, "win": map[string]any{"kind": "task"},
		"key": nil, "domain_max": budCap, "holder": map[string]any{"kind": "site_local"}, "scope": "principal"}
	for k, v := range over {
		a[k] = v
	}
	return a
}

func budEv(id string, amount, t any) map[string]any {
	return map[string]any{"id": id, "verb": "pay", "resource": "r", "params": map[string]any{"amount": amount}, "t": t}
}

func budReq(id string, amount any, extra map[string]any) map[string]any {
	r := map[string]any{"event": budEv(id, amount, 1000), "accumulators": []any{budSpend(nil)}}
	for k, v := range extra {
		r[k] = v
	}
	return r
}

// budEvents is the events of a snapshot, as the maps the store returned (so a mutation reaches what the store handed out).
func budEvents(snap map[string]any) []map[string]any {
	switch l := snap["events"].(type) {
	case []map[string]any:
		return l
	case []any:
		out := make([]map[string]any, 0, len(l))
		for _, e := range l {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

func budSnap(l BudgetLedger, key string) map[string]any { return pMust(l.Snapshot(key)) }

func budReserve(l BudgetLedger, key string, req map[string]any) map[string]any {
	return pMust(l.Reserve(key, req))
}

func budTotal(l BudgetLedger, key string) float64 {
	t := 0.0
	for _, e := range budEvents(budSnap(l, key)) {
		if e["status"] != "released" {
			t += jsF(e["params"].(map[string]any)["amount"])
		}
	}
	return t
}

func budIDs(l BudgetLedger, key string) []any {
	var out []any
	for _, e := range budEvents(budSnap(l, key)) {
		out = append(out, e["id"])
	}
	return out
}

func budOutcome(m map[string]any, err error) string {
	pNoErr(err)
	return pOutcome(m)
}

func budEmpty(h *ProfileHandle[BudgetLedger]) {
	s := budSnap(h.Store, budK)
	pEq(s["version"], 0)
	pEq(len(budEvents(s)), 0)
}

func budCapCheck(h *ProfileHandle[BudgetLedger]) {
	l := h.Store
	a := budReserve(l, budK, budReq("a", 150, nil))
	pEq(a["outcome"], "reserved")
	pEq(a["post"], map[string]any{"spend": 150})
	b := budReserve(l, budK, budReq("b", 51, nil))
	pEq([]any{b["outcome"], b["acc"], b["post"], b["cap"]}, []any{"over_cap", "spend", 201, budCap})
	pEq(budOutcome(l.Reserve(budK, budReq("c", 50, nil))), "reserved")
	pEq(budTotal(l, budK), budCap)
}

func budRefusal(h *ProfileHandle[BudgetLedger]) {
	l := h.Store
	budReserve(l, budK, budReq("a", 150, nil))
	before := profNorm(budSnap(l, budK))
	pEq(budOutcome(l.Reserve(budK, budReq("b", 60, nil))), "over_cap")
	pEq(budSnap(l, budK), before)
}

func budReplay(h *ProfileHandle[BudgetLedger]) {
	l := h.Store
	first := budReserve(l, budK, budReq("a", 150, nil))
	pEq(budReserve(l, budK, budReq("a", 150, nil)), map[string]any{"outcome": "replayed", "version": first["version"], "status": "reserved"})
	pEq(budOutcome(l.Reserve(budK, budReq("a", 10, nil))), "id_conflict")
	pEq(budTotal(l, budK), 150)
	pEq(budOutcome(l.Reserve(budK, budReq("b", 50, nil))), "reserved")
}

func budCas(h *ProfileHandle[BudgetLedger]) {
	l := h.Store
	ver := func(v int) map[string]any { return map[string]any{"expectedVersion": v} }
	pEq(budOutcome(l.Reserve(budK, budReq("a", 10, ver(0)))), "reserved")
	pEq(budReserve(l, budK, budReq("b", 10, ver(0))), map[string]any{"outcome": "conflict", "version": 1})
	pEq(len(budEvents(budSnap(l, budK))), 1)
	pEq(budOutcome(l.Reserve(budK, budReq("b", 10, ver(1)))), "reserved")
	pEq(budOutcome(l.Reserve(budK, budReq("a", 10, ver(0)))), "replayed")
}

func budRaceCap(h *ProfileHandle[BudgetLedger]) {
	clients := []BudgetLedger{h.Store, pMust(h.Reopen()), pMust(h.Reopen()), pMust(h.Reopen())}
	var fns []func() any
	for i := 0; i < 40; i++ {
		fns = append(fns, func() any { return budReserve(clients[i%4], budK, budReq(fmt.Sprintf("r%d", i), 30, nil)) })
	}
	rs := pRace(fns...)
	pEq(pCount(rs, "reserved"), 6)
	pEq(pCount(rs, "over_cap"), 34)
	pEq(budTotal(h.Store, budK), 180)
	seen := map[any]bool{}
	for _, id := range budIDs(h.Store, budK) {
		seen[id] = true
	}
	pEq(len(seen), 6)
}

func budRaceVersion(h *ProfileHandle[BudgetLedger]) {
	clients := []BudgetLedger{h.Store, pMust(h.Reopen()), pMust(h.Reopen())}
	var fns []func() any
	for i := 0; i < 9; i++ {
		fns = append(fns, func() any {
			return budReserve(clients[i%3], budK, budReq(fmt.Sprintf("v%d", i), 1, map[string]any{"expectedVersion": 0}))
		})
	}
	rs := pRace(fns...)
	pEq(pCount(rs, "reserved"), 1)
	pEq(pCount(rs, "conflict"), 8)
	pEq(len(budEvents(budSnap(h.Store, budK))), 1)
}

func budRaceRetry(h *ProfileHandle[BudgetLedger]) {
	clients := []BudgetLedger{h.Store, pMust(h.Reopen()), pMust(h.Reopen())}
	one := func(c BudgetLedger, i int) any {
		for {
			s := budSnap(c, budK)
			r := budReserve(c, budK, budReq(fmt.Sprintf("w%d", i), 10, map[string]any{"expectedVersion": s["version"]}))
			if pOutcome(r) != "conflict" {
				return pOutcome(r)
			}
		}
	}
	var fns []func() any
	for i := 0; i < 20; i++ {
		fns = append(fns, func() any { return one(clients[i%3], i) })
	}
	for _, o := range pRace(fns...) {
		pOK(o == "reserved", fmt.Sprintf("a retrying writer ended %v", o))
	}
	pEq(budTotal(h.Store, budK), budCap)
	pEq(budOutcome(h.Store.Reserve(budK, budReq("extra", 1, nil))), "over_cap")
}

func budSettle(h *ProfileHandle[BudgetLedger]) {
	l := h.Store
	budReserve(l, budK, budReq("a", 10, nil))
	budReserve(l, budK, budReq("b", 10, nil))
	pEq(budOutcome(l.Commit(budK, "ghost")), "unknown")
	pEq(budOutcome(l.Release(budK, "ghost", nil)), "unknown")
	pEq(budOutcome(l.Commit(budK, "a")), "settled")
	pEq(budOutcome(l.Commit(budK, "a")), "replayed")
	r1 := pMust(l.Release(budK, "a", nil))
	if pOutcome(r1) == "refused" {
		pEq(r1["status"], "committed")
	} else {
		pEq(r1["outcome"], "committed")
	}
	pEq(budOutcome(l.Release(budK, "b", nil)), "settled")
	pEq(budOutcome(l.Release(budK, "b", nil)), "replayed")
	c1 := pMust(l.Commit(budK, "b"))
	if pOutcome(c1) == "refused" {
		pEq(c1["status"], "released")
	} else {
		pEq(c1["outcome"], "released")
	}
	var st []any
	for _, e := range budEvents(budSnap(l, budK)) {
		st = append(st, e["status"])
	}
	pEq(st, []any{"committed", "released"})
}

func budReleaseFrees(h *ProfileHandle[BudgetLedger]) {
	l := h.Store
	budReserve(l, budK, budReq("a", 100, nil))
	budReserve(l, budK, budReq("b", 100, nil))
	pEq(budOutcome(l.Reserve(budK, budReq("c", 1, nil))), "over_cap")
	pMust(l.Release(budK, "a", nil))
	pMust(l.Commit(budK, "b"))
	pEq(budOutcome(l.Reserve(budK, budReq("d", 100, nil))), "reserved")
	pEq(budOutcome(l.Reserve(budK, budReq("e", 1, nil))), "over_cap")
}

func budReleaseUnreserved(h *ProfileHandle[BudgetLedger]) {
	l := h.Store
	pEq(budOutcome(l.Release(budK, "ghost", nil)), "unknown")
	pEq(budOutcome(l.Reserve(budK, budReq("a", 201, nil))), "over_cap")
	pEq(budOutcome(l.Reserve(budK, budReq("ghost", 200, nil))), "reserved")
	pEq(budOutcome(l.Reserve(budK, budReq("b", 1, nil))), "over_cap")
}

func budLateCommit(h *ProfileHandle[BudgetLedger]) {
	l := h.Store
	budReserve(l, budK, budReq("a", 200, nil))
	pMust(l.Release(budK, "a", nil))
	budReserve(l, budK, budReq("b", 200, nil))
	pEq(budOutcome(l.Commit(budK, "a")), "refused")
	pMust(l.Commit(budK, "b"))
	n := 0
	for _, e := range budEvents(budSnap(l, budK)) {
		if e["status"] == "committed" {
			n++
		}
	}
	pEq(n, 1)
}

func budExpired(l BudgetLedger, now float64) any {
	r := pMust(l.Expire(budK, now))
	if r["released"] == nil {
		return []any{}
	}
	return r["released"]
}

func budExpiry(h *ProfileHandle[BudgetLedger]) {
	l := h.Store
	exp := map[string]any{"expiresAt": 500}
	budReserve(l, budK, budReq("a", 40, exp))
	budReserve(l, budK, budReq("b", 40, exp))
	budReserve(l, budK, budReq("c", 40, nil))
	budReserve(l, budK, budReq("d", 40, exp))
	pMust(l.Commit(budK, "b"))
	pMust(l.Start(budK, "d"))
	pEq(budExpired(l, 499), []any{})
	pEq(budExpired(l, 500), []any{"a"})
	pEq(budExpired(l, 10_000), []any{})
	pEq(budTotal(l, budK), 120)
	pEq(budOutcome(l.Commit(budK, "a")), "refused")
	pEq(budOutcome(l.Start(budK, "a")), "refused")
}

func budStart(h *ProfileHandle[BudgetLedger]) {
	l := h.Store
	budReserve(l, budK, budReq("a", 10, map[string]any{"expiresAt": 5}))
	budReserve(l, budK, budReq("b", 10, nil))
	budReserve(l, budK, budReq("c", 10, nil))
	v := budSnap(l, budK)["version"]
	pEq(budOutcome(l.Start(budK, "ghost")), "unknown")
	pEq(budSnap(l, budK)["version"], v)
	pEq(budOutcome(l.Start(budK, "a")), "settled")
	pEq(budOutcome(l.Start(budK, "a")), "replayed")
	pEq(budExpired(l, 100), []any{})
	pEq(budOutcome(l.Commit(budK, "a")), "settled")
	pEq(budOutcome(l.Start(budK, "a")), "replayed")
	pMust(l.Start(budK, "b"))
	pEq(budOutcome(l.Release(budK, "b", nil)), "settled")
	s := pMust(l.Start(budK, "b"))
	if pOutcome(s) == "refused" {
		pEq(s["status"], "released")
	} else {
		pEq(s["outcome"], "released")
	}
	for _, e := range budEvents(budSnap(l, budK)) {
		if e["id"] == "c" {
			pEq(e["started"], nil)
		}
	}
}

func budKeys(h *ProfileHandle[BudgetLedger]) {
	l := h.Store
	budReserve(l, budK, budReq("a", 200, nil))
	pEq(budOutcome(l.Reserve(budK2, budReq("a", 200, nil))), "reserved")
	pEq(budOutcome(l.Reserve(budK, budReq("b", 1, nil))), "over_cap")
	pEq(budIDs(l, budK2), []any{"a"})
	pEq(budSnap(l, budK2)["version"], 1)
}

func budWindows(h *ProfileHandle[BudgetLedger]) {
	l := h.Store
	w := []any{budSpend(map[string]any{"win": map[string]any{"kind": "period", "ms": 1000, "t0": 0}})}
	pEq(budOutcome(l.Reserve(budK, map[string]any{"event": budEv("a", 200, 100), "accumulators": w})), "reserved")
	pEq(budOutcome(l.Reserve(budK, map[string]any{"event": budEv("b", 1, 900), "accumulators": w})), "over_cap")
	pEq(budOutcome(l.Reserve(budK, map[string]any{"event": budEv("c", 200, 1100), "accumulators": w})), "reserved")
}

func budEvidence(h *ProfileHandle[BudgetLedger]) {
	l := h.Store
	budReserve(l, budK, budReq("a", 10, nil))
	mk := func(id string) map[string]any {
		return map[string]any{"v": 1, "key": budK, "id": id, "reason": "effect_failed", "at": 5, "signer": "s", "sig": "x"}
	}
	pRejects(l.Release(budK, "a", mk("other")))
	pEq(budEvents(budSnap(l, budK))[0]["status"], "reserved")
	pEq(budOutcome(l.Release(budK, "a", mk("a"))), "settled")
	pEq(budEvents(budSnap(l, budK))[0]["rel"], mk("a"))
}

func budInvalid(h *ProfileHandle[BudgetLedger]) {
	l := h.Store
	acc := []any{budSpend(nil)}
	withEv := func(over map[string]any) map[string]any {
		e := budEv("x", 1, 1000)
		for k, v := range over {
			e[k] = v
		}
		return e
	}
	for _, bad := range []map[string]any{budEv("", 1, 1000), withEv(map[string]any{"t": 0.5}), withEv(map[string]any{"verb": 7})} {
		pRejects(l.Reserve(budK, map[string]any{"event": bad, "accumulators": acc}))
	}
	pRejects(l.Reserve(budK, budReq("x", 1, map[string]any{"expectedVersion": -1})))
	noMax := budSpend(nil)
	delete(noMax, "domain_max")
	pRejects(l.Reserve(budK, map[string]any{"event": budEv("x", 1, 1000), "accumulators": []any{noMax}}))
	s := budSnap(l, budK)
	pEq(s["version"], 0)
	pEq(len(budEvents(s)), 0)
}

func budCopies(h *ProfileHandle[BudgetLedger]) {
	l := h.Store
	budReserve(l, budK, budReq("a", 10, nil))
	budEvents(budSnap(l, budK))[0]["status"] = "released"
	pEq(budEvents(budSnap(l, budK))[0]["status"], "reserved")
}

func budDurableClaim(h *ProfileHandle[BudgetLedger]) {
	want := h.adapterDurable == nil || *h.adapterDurable
	pEq(h.Store.Durable(), want, fmt.Sprintf("ledger.Durable()=%v but the adapter declares durable=%v", h.Store.Durable(), want))
}

func budReopen(h *ProfileHandle[BudgetLedger]) {
	l := h.Store
	budReserve(l, budK, budReq("a", 150, nil))
	budReserve(l, budK, budReq("b", 50, nil))
	pMust(l.Commit(budK, "a"))
	pMust(l.Release(budK, "b", nil))
	back := pMust(h.Reopen())
	var got []any
	for _, e := range budEvents(budSnap(back, budK)) {
		got = append(got, []any{e["id"], e["status"]})
	}
	pEq(got, []any{[]any{"a", "committed"}, []any{"b", "released"}})
	pEq(budOutcome(back.Reserve(budK, budReq("c", 51, nil))), "over_cap")
	pEq(budOutcome(back.Reserve(budK, budReq("c", 50, nil))), "reserved")
}

func budCrash(h *ProfileHandle[BudgetLedger]) {
	budReserve(h.Store, budK, budReq("a", 200, nil))
	pBackground(func() { _, _ = h.Store.Reserve(budK, budReq("b", 0, nil)) })
	back := pMust(h.Crash())
	pEq(budOutcome(back.Reserve(budK, budReq("c", 1, nil))), "over_cap")
	pEq(budEvents(budSnap(back, budK))[0]["id"], "a")
}

// BudgetChecks is the aggregate budget ledger profile.
var BudgetChecks = []ProfileCheck[BudgetLedger]{
	{"empty-key-is-empty", "a key nobody reserved on has version 0 and no events", "", budEmpty},
	{"reservation-counts-at-once-and-cap-is-inclusive", "a reservation counts as soon as it is made; one that would pass the cap is refused with the post-value, one that reaches it exactly is admitted", "", budCapCheck},
	{"a-refusal-writes-nothing", "an over-cap reservation leaves no event and does not move the version", "", budRefusal},
	{"reserve-retry-is-a-replay", "the same event again is a replay that changes nothing and does not count twice; another event under the same id conflicts", "", budReplay},
	{"expected-version-is-compare-and-swap", "a reservation naming a stale version conflicts and writes nothing; the current version succeeds; a replay wins over a stale version", "", budCas},
	{"racing-reserves-never-pass-the-cap", "forty reservations of 30 racing from four clients against a cap of 200: exactly six land, the total is never above the cap, none is lost or counted twice", "", budRaceCap},
	{"racing-reserves-at-one-version-have-one-winner", "clients reserving with the same expected version: exactly one lands, the others conflict", "", budRaceVersion},
	{"racing-writers-with-retry-fill-the-cap-exactly", "twenty writers of 10 each retrying on conflict against a cap of 200: all twenty land, the twenty-first is refused", "", budRaceRetry},
	{"settle-rules", "commit and release settle only a reservation, are idempotent, and refuse the opposite settlement; an unknown id changes nothing", "", budSettle},
	{"release-frees-budget-and-commit-keeps-it", "a released reservation no longer counts; a committed one still does; an open one keeps counting until settled", "", budReleaseFrees},
	{"release-without-reserve-credits-nothing", "releasing an id that was never reserved does not create headroom, now or after the id is reserved later", "", budReleaseUnreserved},
	{"a-late-commit-cannot-overspend", "after a reservation was released and its budget reused, committing it is refused, so the committed total never passes the cap", "", budLateCommit},
	{"expiry-releases-only-open-reservations-past-their-deadline", "expire frees a reservation at or after its deadline, never an earlier one, never a committed, started or deadline-less one, and a late commit or start of it is refused", "", budExpiry},
	{"start-rules", "start marks an open reservation non-expirable and is idempotent; an unknown id changes nothing; a started one can still be committed, or released (the effect did not happen); a released one cannot start", "", budStart},
	{"keys-are-independent", "two keys have their own caps, versions and events", "", budKeys},
	{"windows-reset-the-count", "a period window counts only the events of the period of the new event", "", budWindows},
	{"release-evidence-is-stored-and-bound", "evidence for the reservation is kept with the released event; evidence for another reservation is refused and the reservation stays open", "", budEvidence},
	{"invalid-input-is-refused", "a malformed event or request throws and writes nothing", "", budInvalid},
	{"snapshots-are-copies", "mutating what a snapshot returned cannot change the ledger", "", budCopies},
	{"durable-claim-matches-the-adapter", "a ledger says durable: true exactly when its adapter declares durability, so a volatile ledger can never satisfy the non-session refusal", "", budDurableClaim},
	{"state-survives-reopen", "every acknowledged reserve, commit and release is visible to a new client after the backend restarts, and the cap still holds", "durable", budReopen},
	{"acknowledged-writes-survive-a-crash", "after an abrupt kill every acknowledged reservation still counts, so a crash can only over-restrict, never reset a cap", "crash", budCrash},
}

// RunBudgetLedgerConformance runs BudgetChecks against an aggregate budget ledger.
func RunBudgetLedgerConformance(a ProfileAdapter[BudgetLedger], only []string) ConformanceReport {
	return runProfile("budget ledger", BudgetChecks, a, only)
}

// ---- bond-settlement stores -------------------------------------------------------------------------------------------------------

// BondStore is a bond-settlement store. Read takes {claimId, depositor?} and returns {bond?, balances: [[account, amount]],
// openTotals: {count, sum}, highWater}; Deposit credits an account and returns the new balance; Commit applies a settlement plan
// {claimId, expect, next, open?, moves, record} at observedAt and returns {outcome: committed | replayed | conflict, record?}.
type BondStore interface {
	Read(query map[string]any) (map[string]any, error)
	Deposit(account string, amount float64) (float64, error)
	Commit(plan map[string]any, observedAt float64) (map[string]any, error)
}

func bondRec(claimID, action string, amount any, from, to string, evidence string, split map[string]any) map[string]any {
	r := map[string]any{"claimId": claimID, "action": action, "amount": amount, "from": from, "to": to, "at": 1, "evidenceDigest": evidence}
	if split != nil {
		r["split"] = split
	}
	r["sig"] = "sig"
	return r
}

func bondOpenPlan(id, dep string, amount float64, caps map[string]any) map[string]any {
	if caps == nil {
		caps = map[string]any{"maxOpenClaims": 100, "maxOpenAmount": 1e9}
	}
	open := map[string]any{"amount": amount, "depositor": dep}
	for k, v := range caps {
		open[k] = v
	}
	return map[string]any{"claimId": id, "expect": "none", "next": "open", "open": open,
		"moves":  []any{map[string]any{"account": dep, "op": "debit", "amount": amount}, map[string]any{"account": "escrow", "op": "credit", "amount": amount}},
		"record": bondRec(id, "open", amount, dep, "escrow", "", nil)}
}

func bondReleasePlan(id, dep string, amount float64) map[string]any {
	return map[string]any{"claimId": id, "expect": "open", "next": "released",
		"moves":  []any{map[string]any{"account": "escrow", "op": "debit", "amount": amount}, map[string]any{"account": dep, "op": "credit", "amount": amount}},
		"record": bondRec(id, "release", amount, "escrow", dep, "", nil)}
}

func bondSlashPlan(id string, amount float64, evidence ...string) map[string]any {
	ev := "ev"
	if len(evidence) > 0 {
		ev = evidence[0]
	}
	return map[string]any{"claimId": id, "expect": "open", "next": "slashed",
		"moves": []any{map[string]any{"account": "escrow", "op": "debit", "amount": amount}, map[string]any{"account": "chal", "op": "credit", "amount": amount / 2},
			map[string]any{"account": "treasury", "op": "credit", "amount": amount / 2}},
		"record": bondRec(id, "slash", amount, "escrow", "treasury", ev, map[string]any{"amount": amount, "challengerReward": amount / 2, "victimCompensation": 0,
			"treasuryRemainder": amount / 2, "challengerAccount": "chal", "victimAccount": "pool", "treasuryAccount": "treasury"})}
}

func bondBal(s BondStore, accounts ...string) []any {
	var out []any
	for _, a := range accounts {
		r := profNorm(pMust(s.Read(map[string]any{"claimId": "", "depositor": a}))).(map[string]any)
		b, _ := r["balances"].([]any)
		v := any(0.0)
		if len(b) > 0 {
			if pair, ok := b[0].([]any); ok && len(pair) > 1 && pair[1] != nil {
				v = pair[1]
			}
		}
		out = append(out, v)
	}
	return out
}

func bondStatus(s BondStore, id string) string {
	r := pMust(s.Read(map[string]any{"claimId": id}))
	b, ok := r["bond"].(map[string]any)
	if !ok {
		return "none"
	}
	st, _ := b["status"].(string)
	return st
}

var bondAccounts = []string{"alice", "bob", "escrow", "chal", "treasury"}

func bondTotal(s BondStore) float64 {
	t := 0.0
	for _, v := range bondBal(s, bondAccounts...) {
		t += jsF(v)
	}
	return t
}

func bondOutcomes(rs []any) []string {
	var out []string
	for _, r := range rs {
		out = append(out, pOutcome(r))
	}
	sort.Strings(out)
	return out
}

func bondCommit(s BondStore, plan map[string]any, at float64) map[string]any {
	return pMust(s.Commit(plan, at))
}

func bondEmpty(h *ProfileHandle[BondStore]) {
	pEq(pMust(h.Store.Read(map[string]any{"claimId": "nope", "depositor": "alice"})),
		map[string]any{"balances": []any{[]any{"alice", 0}}, "openTotals": map[string]any{"count": 0, "sum": 0}, "highWater": 0})
}

func bondDeposit(h *ProfileHandle[BondStore]) {
	s := h.Store
	pEq(pMust(s.Deposit("alice", 2.5)), 2.5)
	pEq(pMust(s.Deposit("alice", 0.5)), 3)
	for _, bad := range []float64{0, -1, math.NaN(), math.Inf(1)} {
		pRejects(s.Deposit("alice", bad))
	}
	pRejects(s.Deposit("", 1))
	pEq(bondBal(s, "alice"), []any{3})
}

func bondOpen(h *ProfileHandle[BondStore]) {
	s := h.Store
	pMust(s.Deposit("alice", 100))
	plan := bondOpenPlan("b1", "alice", 60, nil)
	pEq(bondCommit(s, plan, 500), map[string]any{"outcome": "committed", "record": plan["record"]})
	pEq(pMust(s.Read(map[string]any{"claimId": "b1", "depositor": "alice"})),
		map[string]any{"bond": map[string]any{"claimId": "b1", "amount": 60, "depositor": "alice", "status": "open", "records": []any{plan["record"]}},
			"balances": []any{[]any{"alice", 40}}, "openTotals": map[string]any{"count": 1, "sum": 60}, "highWater": 500})
	pEq(bondBal(s, "escrow"), []any{60})
}

func bondOverdraft(h *ProfileHandle[BondStore]) {
	s := h.Store
	pMust(s.Deposit("alice", 10))
	pEq(pOutcome(bondCommit(s, bondOpenPlan("b1", "alice", 60, nil), 900)), "conflict")
	pEq(pMust(s.Read(map[string]any{"claimId": "b1", "depositor": "alice"})),
		map[string]any{"balances": []any{[]any{"alice", 10}}, "openTotals": map[string]any{"count": 0, "sum": 0}, "highWater": 0})
	pEq(bondBal(s, "escrow"), []any{0})
}

func bondOpenRetry(h *ProfileHandle[BondStore]) {
	s := h.Store
	pMust(s.Deposit("alice", 100))
	plan := bondOpenPlan("b1", "alice", 60, nil)
	bondCommit(s, plan, 1)
	pEq(bondCommit(s, plan, 2), map[string]any{"outcome": "replayed", "record": plan["record"]})
	pEq(pOutcome(bondCommit(s, bondOpenPlan("b1", "alice", 61, nil), 3)), "conflict")
	pEq(pOutcome(bondCommit(s, bondOpenPlan("b1", "bob", 60, nil), 3)), "conflict")
	pEq(bondBal(s, "alice", "escrow"), []any{40, 60})
	pEq(len(profNorm(pMust(s.Read(map[string]any{"claimId": "b1"}))).(map[string]any)["bond"].(map[string]any)["records"].([]any)), 1)
}

func bondCaps(h *ProfileHandle[BondStore]) {
	s := h.Store
	pMust(s.Deposit("alice", 100))
	caps := map[string]any{"maxOpenClaims": 2, "maxOpenAmount": 50}
	pEq(pOutcome(bondCommit(s, bondOpenPlan("c1", "alice", 30, caps), 1)), "committed")
	pEq(pOutcome(bondCommit(s, bondOpenPlan("c2", "alice", 21, caps), 1)), "conflict") // 30 + 21 > 50
	pEq(pOutcome(bondCommit(s, bondOpenPlan("c3", "alice", 20, caps), 1)), "committed")
	pEq(pOutcome(bondCommit(s, bondOpenPlan("c4", "alice", 1, caps), 1)), "conflict") // third open claim
	pEq(bondBal(s, "alice", "escrow"), []any{50, 50})
}

func bondRecords(s BondStore, id string) []any {
	b := profNorm(pMust(s.Read(map[string]any{"claimId": id}))).(map[string]any)["bond"].(map[string]any)
	return b["records"].([]any)
}

func bondSettle(h *ProfileHandle[BondStore]) {
	s := h.Store
	pMust(s.Deposit("alice", 100))
	bondCommit(s, bondOpenPlan("r", "alice", 20, nil), 1)
	bondCommit(s, bondOpenPlan("s", "alice", 40, nil), 1)
	rel, sl := bondReleasePlan("r", "alice", 20), bondSlashPlan("s", 40)
	pEq(bondCommit(s, rel, 2), map[string]any{"outcome": "committed", "record": rel["record"]})
	pEq(bondCommit(s, sl, 3), map[string]any{"outcome": "committed", "record": sl["record"]})
	pEq(bondBal(s, "alice", "escrow", "chal", "treasury"), []any{60, 0, 20, 20})
	pEq(bondTotal(s), 100)
	pEq([]any{bondStatus(s, "r"), bondStatus(s, "s")}, []any{"released", "slashed"})
	pEq(bondRecords(s, "s"), []any{bondOpenPlan("s", "alice", 40, nil)["record"], sl["record"]})
}

func bondHighWater(s BondStore, id string) any {
	return pMust(s.Read(map[string]any{"claimId": id}))["highWater"]
}

func bondPhase(h *ProfileHandle[BondStore]) {
	s := h.Store
	pMust(s.Deposit("alice", 100))
	pEq(pOutcome(bondCommit(s, bondReleasePlan("ghost", "alice", 5), 9)), "conflict")
	bondCommit(s, bondOpenPlan("b", "alice", 20, nil), 10)
	bondCommit(s, bondReleasePlan("b", "alice", 20), 11)
	snap := func() []any { return []any{bondBal(s, "alice", "escrow", "treasury", "chal"), bondHighWater(s, "b")} }
	before := snap()
	pEq(pOutcome(bondCommit(s, bondSlashPlan("b", 20), 99)), "conflict")
	pEq(snap(), before)
	pEq(bondStatus(s, "b"), "released")
}

func bondOverdraw(h *ProfileHandle[BondStore]) {
	s := h.Store
	pMust(s.Deposit("alice", 100))
	bondCommit(s, bondOpenPlan("b", "alice", 20, nil), 1)
	greedy := bondSlashPlan("b", 20)
	greedy["moves"] = []any{map[string]any{"account": "escrow", "op": "debit", "amount": 21}, map[string]any{"account": "treasury", "op": "credit", "amount": 21}}
	pEq(pOutcome(bondCommit(s, greedy, 5)), "conflict")
	pEq(bondBal(s, "escrow", "treasury"), []any{20, 0})
	pEq(bondStatus(s, "b"), "open")
}

func bondSettleRetry(h *ProfileHandle[BondStore]) {
	s := h.Store
	pMust(s.Deposit("alice", 100))
	bondCommit(s, bondOpenPlan("b", "alice", 40, nil), 1)
	sl := bondSlashPlan("b", 40, "ev-1")
	bondCommit(s, sl, 2)
	again := bondSlashPlan("b", 40, "ev-1")
	rec := map[string]any{}
	for k, v := range sl["record"].(map[string]any) {
		rec[k] = v
	}
	rec["at"], rec["sig"] = 77, "other"
	again["record"] = rec
	pEq(bondCommit(s, again, 3), map[string]any{"outcome": "replayed", "record": sl["record"]})
	pEq(pOutcome(bondCommit(s, bondSlashPlan("b", 40, "ev-2"), 3)), "conflict")
	pEq(pOutcome(bondCommit(s, bondReleasePlan("b", "alice", 40), 3)), "conflict")
	pEq(bondBal(s, "alice", "escrow", "chal", "treasury"), []any{60, 0, 20, 20})
	pEq(len(bondRecords(s, "b")), 2)
}

func bondRaceSame(h *ProfileHandle[BondStore]) {
	pMust(h.Store.Deposit("alice", 100))
	bondCommit(h.Store, bondOpenPlan("b", "alice", 40, nil), 1)
	clients := []BondStore{h.Store, pMust(h.Reopen()), pMust(h.Reopen()), pMust(h.Reopen())}
	var fns []func() any
	for i := 0; i < 8; i++ {
		fns = append(fns, func() any {
			return bondCommit(clients[i%len(clients)], bondReleasePlan("b", "alice", 40), float64(10+i))
		})
	}
	pEq(bondOutcomes(pRace(fns...)), []string{"committed", "replayed", "replayed", "replayed", "replayed", "replayed", "replayed", "replayed"})
	pEq(bondBal(h.Store, "alice", "escrow"), []any{100, 0})
	pEq(len(bondRecords(h.Store, "b")), 2)
}

func bondRaceConflict(h *ProfileHandle[BondStore]) {
	pMust(h.Store.Deposit("alice", 100))
	bondCommit(h.Store, bondOpenPlan("b", "alice", 40, nil), 1)
	other := pMust(h.Reopen())
	r := pRace(func() any { return bondCommit(h.Store, bondReleasePlan("b", "alice", 40), 5) }, func() any { return bondCommit(other, bondSlashPlan("b", 40), 5) },
		func() any { return bondCommit(h.Store, bondSlashPlan("b", 40), 5) }, func() any { return bondCommit(other, bondReleasePlan("b", "alice", 40), 5) })
	pEq(pCount(r, "committed"), 1)
	pEq(pCount(r, "conflict")+pCount(r, "replayed"), 3)
	want := []any{60, 0, 20, 20}
	if bondStatus(h.Store, "b") == "released" {
		want = []any{100, 0, 0, 0}
	}
	pEq(bondBal(h.Store, "alice", "escrow", "chal", "treasury"), want)
	pEq(bondTotal(h.Store), 100)
}

func bondRaceOpens(h *ProfileHandle[BondStore]) {
	pMust(h.Store.Deposit("alice", 100))
	other := pMust(h.Reopen())
	r := pRace(func() any { return bondCommit(h.Store, bondOpenPlan("b", "alice", 60, nil), 1) }, func() any { return bondCommit(other, bondOpenPlan("b", "alice", 60, nil), 1) },
		func() any { return bondCommit(h.Store, bondOpenPlan("b", "alice", 60, nil), 1) }, func() any { return bondCommit(other, bondOpenPlan("b", "alice", 50, nil), 1) })
	pEq(pCount(r, "committed"), 1)
	want := []any{40, 60}
	if pOutcome(r[3]) == "committed" {
		want = []any{50, 50}
	}
	pEq(bondBal(h.Store, "alice", "escrow"), want)
	pEq(bondTotal(h.Store), 100)
}

func bondRaceOverdraw(h *ProfileHandle[BondStore]) {
	pMust(h.Store.Deposit("alice", 100))
	other := pMust(h.Reopen())
	var fns []func() any
	for i := 0; i < 6; i++ {
		fns = append(fns, func() any {
			c := other
			if i%2 == 1 {
				c = h.Store
			}
			return bondCommit(c, bondOpenPlan(fmt.Sprintf("b%d", i), "alice", 40, nil), 1)
		})
	}
	pEq(pCount(pRace(fns...), "committed"), 2)
	pEq(bondBal(h.Store, "alice", "escrow"), []any{20, 80})
}

func bondRaceDeposits(h *ProfileHandle[BondStore]) {
	other := pMust(h.Reopen())
	var fns []func() any
	for i := 0; i < 16; i++ {
		fns = append(fns, func() any {
			c := other
			if i%2 == 1 {
				c = h.Store
			}
			return pMust(c.Deposit("alice", 1))
		})
	}
	pRace(fns...)
	pEq(bondBal(h.Store, "alice"), []any{16})
}

func bondHighWaterCheck(h *ProfileHandle[BondStore]) {
	s := h.Store
	pMust(s.Deposit("alice", 100))
	bondCommit(s, bondOpenPlan("a", "alice", 10, nil), 100)
	bondCommit(s, bondOpenPlan("b", "alice", 10, nil), 40)
	pEq(bondHighWater(s, ""), 100)
	bondCommit(s, bondOpenPlan("c", "alice", 10, nil), math.NaN())
	pEq(bondHighWater(s, ""), 100)
	bondCommit(s, bondOpenPlan("d", "alice", 10, nil), 101)
	pEq(bondHighWater(s, ""), 101)
}

func bondSnapshots(h *ProfileHandle[BondStore]) {
	s := h.Store
	pMust(s.Deposit("alice", 100))
	bondCommit(s, bondOpenPlan("b", "alice", 10, nil), 1)
	snap := pMust(s.Read(map[string]any{"claimId": "b", "depositor": "alice"}))
	func() {
		defer func() { _ = recover() }() // an immutable pair cannot be changed through a snapshot, which is the point
		if b, ok := snap["bond"].(map[string]any); ok {
			b["amount"] = 999
			b["records"] = []any{}
		}
		snap["balances"].([]any)[0].([]any)[1] = 12345
	}()
	again := profNorm(pMust(s.Read(map[string]any{"claimId": "b", "depositor": "alice"}))).(map[string]any)
	pEq(again["bond"].(map[string]any)["amount"], 10)
	pEq(len(again["bond"].(map[string]any)["records"].([]any)), 1)
	pEq(again["balances"], []any{[]any{"alice", 90}})
}

func bondHostile(h *ProfileHandle[BondStore]) {
	s := h.Store
	for _, n := range []string{"__proto__", "constructor", "toString", "hasOwnProperty"} {
		pMust(s.Deposit(n, 50))
		pEq(pOutcome(bondCommit(s, bondOpenPlan(n, n, 20, nil), 1)), "committed", n)
		pEq(bondBal(s, n), []any{30}, n)
		pEq(bondStatus(s, n), "open", n)
	}
	pEq(bondStatus(s, "valueOf"), "none")
	pEq(bondBal(s, "valueOf"), []any{0})
}

func bondReopen(h *ProfileHandle[BondStore]) {
	pMust(h.Store.Deposit("alice", 100))
	bondCommit(h.Store, bondOpenPlan("a", "alice", 40, nil), 7)
	bondCommit(h.Store, bondOpenPlan("b", "alice", 20, nil), 8)
	sl := bondSlashPlan("b", 20)
	bondCommit(h.Store, sl, 9)
	back := pMust(h.Reopen())
	pEq(pMust(back.Read(map[string]any{"claimId": "b", "depositor": "alice"})),
		map[string]any{"bond": map[string]any{"claimId": "b", "amount": 20, "depositor": "alice", "status": "slashed", "records": []any{bondOpenPlan("b", "alice", 20, nil)["record"], sl["record"]}},
			"balances": []any{[]any{"alice", 40}}, "openTotals": map[string]any{"count": 1, "sum": 40}, "highWater": 9})
	pEq(bondBal(back, "escrow", "chal", "treasury"), []any{40, 10, 10})
	pEq(pOutcome(bondCommit(back, sl, 10)), "replayed")
}

func bondCrash(h *ProfileHandle[BondStore]) {
	pMust(h.Store.Deposit("alice", 100))
	bondCommit(h.Store, bondOpenPlan("a", "alice", 40, nil), 1)
	bondCommit(h.Store, bondOpenPlan("b", "alice", 30, nil), 2)
	pBackground(func() { _, _ = h.Store.Commit(bondSlashPlan("b", 30), 3) })
	back := pMust(h.Crash())
	pEq(bondStatus(back, "a"), "open")
	st := bondStatus(back, "b")
	pOK(st == "open" || st == "slashed", "bond b is "+st)
	want, replay := []any{30, 70, 0, 0}, "committed"
	if st == "slashed" {
		want, replay = []any{30, 40, 15, 15}, "replayed"
	}
	pEq(bondBal(back, "alice", "escrow", "chal", "treasury"), want)
	pEq(bondTotal(back), 100)
	pEq(pOutcome(bondCommit(back, bondSlashPlan("b", 30), 4)), replay)
	pEq(bondBal(back, "alice", "escrow", "chal", "treasury"), []any{30, 40, 15, 15})
}

// BondChecks is the bond-settlement store profile.
var BondChecks = []ProfileCheck[BondStore]{
	{"empty-store-reads-empty", "an unknown bond reads as absent, an unknown account as balance 0, and the time high-water mark starts at 0", "", bondEmpty},
	{"deposit-validates-and-accumulates", "deposit credits exactly, returns the new balance, and refuses a non-positive, non-finite or unnamed deposit", "", bondDeposit},
	{"open-is-atomic-and-recorded", "an open moves the collateral, stores the row with its record, and raises the high-water mark, all together", "", bondOpen},
	{"open-overdraft-refused-without-trace", "an open the depositor cannot fund is a conflict and leaves balances, bonds and the high-water mark untouched", "", bondOverdraft},
	{"open-retry-is-replayed-and-different-terms-conflict", "committing the same open again returns the stored record and moves nothing; other terms for that bond conflict", "", bondOpenRetry},
	{"open-caps-are-rechecked-at-commit", "the per-depositor open-claim and open-amount caps hold inside the store, whatever the planner saw", "", bondCaps},
	{"settle-applies-every-move-once", "a release and a slash apply all their balance moves, store the record, and conserve the total", "", bondSettle},
	{"settle-needs-the-expected-phase", "settling an absent bond or from the wrong phase is a conflict that changes nothing, high-water mark included", "", bondPhase},
	{"settle-overdraw-refused-without-trace", "a settlement whose debit would overdraw an account is refused whole: no credit lands, the phase does not change", "", bondOverdraw},
	{"settle-retry-returns-the-stored-record", "the same settlement again is replayed with the first record and moves nothing; the same action with other evidence conflicts", "", bondSettleRetry},
	{"racing-identical-settles-commit-once", "eight clients racing the same release: one commits, seven are replays, funds move once", "", bondRaceSame},
	{"racing-conflicting-settles-have-one-winner", "a release racing a slash on one bond: exactly one commits, the books show only the winner, the total is conserved", "", bondRaceConflict},
	{"racing-opens-for-the-same-bond-commit-once", "concurrent identical opens collect the collateral once; a differing open loses", "", bondRaceOpens},
	{"racing-opens-cannot-overdraw", "concurrent opens by one depositor that together exceed the balance: the sum committed never exceeds what was deposited", "", bondRaceOverdraw},
	{"concurrent-deposits-lose-nothing", "sixteen racing deposits add up exactly", "", bondRaceDeposits},
	{"time-high-water-only-moves-forward", "the recorded time is the maximum of every committed observedAt; a smaller or non-finite one never lowers it", "", bondHighWaterCheck},
	{"reads-are-snapshots", "mutating a returned snapshot cannot change the store", "", bondSnapshots},
	{"hostile-names-are-plain-keys", "claim and account names such as __proto__, constructor and toString behave like any other name", "", bondHostile},
	{"state-survives-reopen", "every acknowledged commit and deposit is visible to a new client after the backend restarts", "durable", bondReopen},
	{"acknowledged-commits-survive-a-crash", "after an abrupt kill, every acknowledged transition is present, and a transition that was in flight is applied entirely or not at all", "crash", bondCrash},
}

// RunBondStoreConformance runs BondChecks against a bond-settlement store.
func RunBondStoreConformance(a ProfileAdapter[BondStore], only []string) ConformanceReport {
	return runProfile("bond store", BondChecks, a, only)
}
