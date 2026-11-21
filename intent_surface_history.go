package pca

// Host-side session history for accumulators and monitors (the session store port and its atomic admission), the layered grant
// decision, and the small value predicates of the intent artifacts.

import (
	"errors"
	"fmt"
	"math"
)

// SessionTx is a transaction on ONE session's history, holding its exclusive lock.
type SessionTx interface {
	// Events returns the session's events in admission order.
	Events() ([]any, error)
	// Append adds an event {id, verb, resource, params, t, status}.
	Append(e map[string]any) error
	// SetStatus moves the event with that id to status; false when no such event exists.
	SetStatus(id, status string) (bool, error)
}

// IntentSessionStore is the accumulator state holder. Linearisability holds iff WithSession serialises every admission of a session:
// the pre-state read, the verification and the `reserved` append happen under one lock (a row lock in a database, a mutex in process).
type IntentSessionStore interface {
	// WithSession runs fn under the session's exclusive lock; fn's error aborts the transaction.
	WithSession(session string, fn func(tx SessionTx) error) error
	// Durable reports whether the history survives a restart of the process. A volatile store would let every cap admit again after one.
	Durable() bool
}

// AccContextFor is the verifier context (`intentV2.acc`) for a candidate action: the pre-states of the site-local accumulators and the
// monitor states, as {state, monitors}. An accumulator whose grouping parameter the candidate lacks is left out (the verifier fails
// that claim). An unreadable history (store corruption) is an error.
func AccContextFor(root map[string]any, history []any, candParams map[string]any, candT any, schema any, haveSchema bool) (res map[string]any, err error) {
	defer func() {
		if p := recover(); p != nil {
			res, err = nil, fmt.Errorf("accContextFor: malformed declaration: %v", p)
		}
	}()
	state := map[string]any{}
	for _, av := range ixL(root["accumulators"]) {
		a, ok := av.(map[string]any)
		if !ok {
			return nil, errors.New("accContextFor: an accumulator declaration is not an object")
		}
		if holder, _ := a["holder"].(map[string]any); holder["kind"] != "site_local" {
			continue
		}
		if _, grouped := a["key"].(string); grouped {
			if _, kok := accKeyOf(a, candParams); !kok {
				continue
			}
		}
		pre, ok := accPreState(a, history, candParams, candT, schema, haveSchema)
		if !ok {
			return nil, fmt.Errorf("accContextFor: the pre-state of '%s' is unreadable (store corruption)", ixS(a["id"]))
		}
		state[ixS(a["id"])] = pre
	}
	monitors := map[string]any{}
	for _, mv := range ixL(root["monitors"]) {
		m, ok := mv.(map[string]any)
		if !ok {
			return nil, errors.New("accContextFor: a monitor declaration is not an object")
		}
		monitors[ixS(m["id"])] = monitorState(m, history)
	}
	return map[string]any{"state": state, "monitors": monitors}, nil
}

// IntentAdmission describes one action to admit against a session's accumulators.
type IntentAdmission struct {
	// Session is the session id.
	Session string
	// Root is the session root's {accumulators, monitors}.
	Root map[string]any
	// Schema is the action schema the verbs are read against (HaveSchema false: none).
	Schema     any
	HaveSchema bool
	// Event is the candidate {id, verb, resource, params, t}; id is unique per session (the PCActn digest).
	Event map[string]any
	// Verify runs the verification with the pre-states and monitor states ({state, monitors}) and says whether to allow; its result is
	// returned to the caller.
	Verify func(acc map[string]any) (allow bool, result any, err error)
	// AllowVolatile admits against a store that is not durable (tests and single-process sites that accept losing every cap on a restart).
	AllowVolatile bool
}

// AdmitIntentAction admits one action atomically against the session's accumulators: under the session lock it computes the pre-states
// and monitor states from the history, runs Verify with them and, on allow, appends the event as `reserved`. After the effect the host
// calls SettleIntentEvent. A store that is not durable is refused unless AllowVolatile is set.
func AdmitIntentAction(store IntentSessionStore, a IntentAdmission) (any, error) {
	if store == nil || (!a.AllowVolatile && !store.Durable()) {
		return nil, errors.New("admitIntentAction: the session store is not durable (a restart would reset every cap); use a durable IntentSessionStore")
	}
	if a.Verify == nil || a.Event == nil {
		return nil, errors.New("admitIntentAction: an event and a Verify function are required")
	}
	var result any
	err := store.WithSession(a.Session, func(tx SessionTx) error {
		history, err := tx.Events()
		if err != nil {
			return err
		}
		params, _ := a.Event["params"].(map[string]any)
		acc, err := AccContextFor(a.Root, history, params, a.Event["t"], a.Schema, a.HaveSchema)
		if err != nil {
			return err
		}
		allow, v, err := a.Verify(acc)
		if err != nil {
			return err
		}
		result = v
		if allow {
			ev := ixCopyMap(a.Event)
			ev["status"] = "reserved"
			return tx.Append(ev)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// SettleIntentEvent moves an admitted event to committed, released or reverted under the session lock; false when no such event exists.
func SettleIntentEvent(store IntentSessionStore, session, id, status string) (bool, error) {
	if status != "committed" && status != "released" && status != "reverted" {
		return false, errors.New("settleIntentEvent: the status must be committed, released or reverted")
	}
	var found bool
	err := store.WithSession(session, func(tx SessionTx) error {
		ok, err := tx.SetStatus(id, status)
		found = ok
		return err
	})
	return found, err
}

// DecideLayers decides a layered grant {org?, site?, std?, task: [layer policy], denied?} for one action context. The result is
// {decision: "admit", by: i} (the index of the first task layer that admits), {decision: "ceiling", layer} (outside a ceiling the
// principal cannot widen), {decision: "intent_denied"} (vetoed, or malformed) or {decision: "intent_required"} (inside every ceiling
// and no task layer admits yet). It never panics: a failure is intent_denied.
func DecideLayers(g map[string]any, actx map[string]any) (res map[string]any) {
	denied := map[string]any{"decision": "intent_denied"}
	defer func() {
		if p := recover(); p != nil {
			res = denied
		}
	}()
	if g == nil { // not an object: the ceilings are unreadable, which fails as the org ceiling
		return map[string]any{"decision": "ceiling", "layer": "org"}
	}
	if !closedMembers(g, nil, "org", "site", "std", "task", "denied") {
		return denied
	}
	for _, k := range []string{"org", "site", "std"} {
		l, has := g[k]
		if !has {
			continue
		}
		if !IsLayerPolicy(l) || !evaluatePredicates(l.(map[string]any)["predicates"], actx) {
			return map[string]any{"decision": "ceiling", "layer": k}
		}
	}
	vetoes := []any{}
	if dv, has := g["denied"]; has {
		var ok bool
		if vetoes, ok = dv.([]any); !ok {
			return denied
		}
	}
	task, ok := g["task"].([]any)
	if !ok {
		return denied
	}
	for _, d := range vetoes {
		if !IsLayerPolicy(d) {
			return denied
		}
	}
	for _, t := range task {
		if !IsLayerPolicy(t) {
			return denied
		}
	}
	for _, d := range vetoes {
		if evaluatePredicates(d.(map[string]any)["predicates"], actx) {
			return denied
		}
	}
	for i, t := range task {
		if evaluatePredicates(t.(map[string]any)["predicates"], actx) {
			return map[string]any{"decision": "admit", "by": float64(i)}
		}
	}
	return map[string]any{"decision": "intent_required"}
}

// IsSafeInt reports whether v is a safe integer (not -0).
func IsSafeInt(v any) bool { return jsIsInt(v) }

// IsClock reports whether v is a usable verifier clock: a safe integer.
func IsClock(v any) bool { return jsIsInt(v) }

// IsBoundedString reports whether v is a non-empty string of at most max UTF-8 bytes.
func IsBoundedString(v any, max int) bool { return boundedStr(v, max) }

// IsDigest reports whether v is a canonical base64url string of 32 bytes.
func IsDigest(v any) bool { return isDigestV(v) }

// IsScalar reports whether v is a wire scalar: a string, a boolean or a safe integer.
func IsScalar(v any) bool {
	switch v.(type) {
	case string, bool:
		return true
	}
	return jsIsInt(v)
}

// ScalarEq reports whether two wire scalars have the same type and value.
func ScalarEq(a, b any) bool {
	if fa, ok := jsNum(a); ok {
		fb, okb := jsNum(b)
		return okb && fa == fb && !math.IsNaN(fa)
	}
	return jsStrictEq(a, b)
}

// ArtifactMessage is the bytes an artifact's signature covers: the domain followed by the strict canonical artifact without its
// sig and pq_sig members.
func ArtifactMessage(domain string, artifact map[string]any) ([]byte, bool) {
	return domainMessage(domain, withoutKeys(artifact, "sig", "pq_sig"))
}

// PublicKeyB64u is the base64url public identity of a key pair.
func PublicKeyB64u(key *KeyPair) string {
	if key == nil {
		return ""
	}
	return key.Public
}
