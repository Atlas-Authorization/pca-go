package pca

// Aggregate admission over a BudgetLedger: accumulators scoped to a principal, an org or a fleet are admitted against the durable
// ledger of that scope (session-scoped ones stay with the session), all-or-nothing across the scopes an action touches, plus the
// transparency anchor of a signed release.

import (
	"errors"
	"fmt"
	"sort"
)

// AggregateReservation names one reservation an admission made: the ledger key of the scope and the event id.
type AggregateReservation struct{ Key, ID string }

// AggregateAdmission is the outcome of AdmitAggregateAction. Admitted: the verdict, the reservations made (one per scope key, in
// key order) and the accumulator pre-states the verifier saw. Refused: the reason, and the verdict when the verifier ran.
type AggregateAdmission struct {
	Admitted     bool
	Reason       string
	Verdict      map[string]any
	Reservations []AggregateReservation
	State        map[string]any
}

// AggregateAdmitArgs are the inputs of AdmitAggregateAction: the scope ids ({principal, org, fleet}), the accumulator
// declarations, the action schema (nil: none), the candidate event (without status), the verifier (it receives the pre-states and
// returns a verdict whose `allow` decides), the reservation expiry (nil: none) and the retry bound (0: 256).
type AggregateAdmitArgs struct {
	IDs          map[string]string
	Accumulators []any
	Schema       any
	Event        map[string]any
	Verify       func(state map[string]any) (map[string]any, error)
	ExpiresAt    *int64
	MaxAttempts  int
}

func aggScope(acc map[string]any) (string, bool) {
	s, ok := acc["scope"].(string)
	return s, ok && s != "session"
}

// AggregateKeyOf is the ledger key an accumulator's cap lives under: scoped is false for a session-scoped (or unscoped)
// accumulator; a scope without its id in ids is the scope_unbound error.
func AggregateKeyOf(acc map[string]any, ids map[string]string) (key string, scoped bool, err error) {
	scope, scoped := aggScope(acc)
	if !scoped {
		return "", false, nil
	}
	id, has := ids[scope]
	if !has {
		accID, _ := acc["id"].(string)
		return "", true, &BudgetLedgerError{"scope_unbound", fmt.Sprintf("accumulator %s is %s-scoped but no %s id was given", accID, scope, scope)}
	}
	key, err = BudgetScopeKey(scope, id)
	return key, true, err
}

// AdmitAggregateAction admits one action against every scoped aggregate it touches: it snapshots each scope, lets the verifier
// decide on the pre-states, then reserves under each scope at the version it read. A concurrent change releases what was reserved
// and retries; a cap that would be exceeded, or a verifier denial, refuses with nothing reserved. Scoped accumulators need a
// durable ledger (not_durable): a restart would otherwise reset every cap.
func AdmitAggregateAction(ledger BudgetLedger, a AggregateAdmitArgs) (*AggregateAdmission, error) {
	var scoped []map[string]any
	for _, v := range a.Accumulators {
		if acc, ok := v.(map[string]any); ok {
			if _, is := aggScope(acc); is {
				scoped = append(scoped, acc)
			}
		}
	}
	if len(scoped) > 0 && (ledger == nil || !ledger.Durable()) {
		return nil, &BudgetLedgerError{"not_durable", "a principal, org or fleet aggregate needs a durable BudgetLedger (a restart would reset every cap)"}
	}
	if a.Verify == nil {
		return nil, errors.New("admitAggregateAction: a verifier is required")
	}
	byKey := map[string][]any{}
	for _, acc := range scoped {
		k, _, err := AggregateKeyOf(acc, a.IDs)
		if err != nil {
			var le *BudgetLedgerError
			if errors.As(err, &le) && le.Code == "scope_unbound" {
				return &AggregateAdmission{Reason: "scope_unbound: " + le.Error()}, nil
			}
			return nil, err
		}
		byKey[k] = append(byKey[k], acc)
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	eventID, _ := a.Event["id"].(string)
	candParams, _ := a.Event["params"].(map[string]any)
	attempts := a.MaxAttempts
	if attempts == 0 {
		attempts = 256
	}
	for attempt := 0; attempt < attempts; attempt++ {
		versions := map[string]any{}
		state := map[string]any{}
		for _, k := range keys {
			s, err := ledger.Snapshot(k)
			if err != nil {
				return nil, err
			}
			versions[k] = s["version"]
			events, _ := s["events"].([]any)
			ctx, err := AccContextFor(map[string]any{"accumulators": byKey[k], "monitors": []any{}}, events, candParams, a.Event["t"], a.Schema, a.Schema != nil)
			if err != nil {
				return nil, err
			}
			pre, _ := ctx["state"].(map[string]any)
			for id, v := range pre {
				state[id] = v
			}
		}
		verdict, err := a.Verify(state)
		if err != nil {
			return nil, err
		}
		if verdict["allow"] != true {
			return &AggregateAdmission{Reason: "verifier denied", Verdict: verdict}, nil
		}
		done := []AggregateReservation{}
		moved := false
		for _, k := range keys {
			req := map[string]any{"event": a.Event, "accumulators": byKey[k], "expectedVersion": versions[k]}
			if a.Schema != nil {
				req["schema"] = a.Schema
			}
			if a.ExpiresAt != nil {
				req["expiresAt"] = jsNumber(float64(*a.ExpiresAt))
			}
			r, err := ledger.Reserve(k, req)
			if err != nil {
				return nil, err
			}
			outcome, _ := r["outcome"].(string)
			if outcome == "reserved" || (outcome == "replayed" && r["status"] == any("reserved")) {
				done = append(done, AggregateReservation{Key: k, ID: eventID})
				continue
			}
			for _, d := range done {
				if _, err := ledger.Release(d.Key, d.ID, nil); err != nil {
					return nil, err
				}
			}
			if outcome == "conflict" {
				moved = true
				break
			}
			why := outcome
			switch outcome {
			case "over_cap":
				why = fmt.Sprintf("over_cap: %s would reach %s (cap %s)", oaString(oaGet(r, "acc")), oaString(oaGet(r, "post")), oaString(oaGet(r, "cap")))
			case "replayed":
				why = "already " + oaString(oaGet(r, "status"))
			}
			return &AggregateAdmission{Reason: "aggregate: " + why, Verdict: verdict}, nil
		}
		if !moved {
			return &AggregateAdmission{Admitted: true, Verdict: verdict, Reservations: done, State: state}, nil
		}
	}
	return nil, &BudgetLedgerError{"conflict_exhausted", "the aggregate kept moving under this admission"}
}

// StartAggregate marks every reservation as started (its effect is about to run); false as soon as one cannot be.
func StartAggregate(ledger BudgetLedger, reservations []AggregateReservation) (bool, error) {
	for _, r := range reservations {
		o, err := ledger.Start(r.Key, r.ID)
		if err != nil {
			return false, err
		}
		if out, _ := o["outcome"].(string); out != "settled" && out != "replayed" {
			return false, nil
		}
	}
	return true, nil
}

// SettleAggregate commits (status "committed") or releases (status "released") every reservation and returns each outcome. A
// release of a started reservation needs the signed evidence that evidence returns for it (nil evidence: none).
func SettleAggregate(ledger BudgetLedger, reservations []AggregateReservation, status string, evidence func(AggregateReservation) map[string]any) ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(reservations))
	for _, r := range reservations {
		var o map[string]any
		var err error
		switch status {
		case "committed":
			o, err = ledger.Commit(r.Key, r.ID)
		case "released":
			var ev map[string]any
			if evidence != nil {
				ev = evidence(r)
			}
			o, err = ledger.Release(r.Key, r.ID, ev)
		default:
			err = &BudgetRangeError{"settleAggregate: status must be committed or released"}
		}
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, nil
}

// AnchorBudgetRelease appends the commitment of a signed release to a transparency log and returns its index, so a release (the
// statement that a reserved effect did not happen) is publicly accountable. Anchoring the same release at the tail again answers
// the same index.
func AnchorBudgetRelease(log LedgerStore, release map[string]any) (int, error) {
	commit, err := BudgetReleaseCommit(release)
	if err != nil {
		return 0, err
	}
	for i := 0; i < 64; i++ {
		size, err := log.Size()
		if err != nil {
			return 0, err
		}
		o, err := log.Append(size, []string{commit})
		if err != nil {
			return 0, err
		}
		if out, _ := o["outcome"].(string); out == "appended" || out == "replayed" {
			return size, nil
		}
	}
	return 0, &BudgetLedgerError{"conflict_exhausted", "could not anchor the release: the log kept moving"}
}
