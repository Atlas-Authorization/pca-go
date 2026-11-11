package pca

// Durable enforcement of a signed behavioural contract. The monitor state is one document (canonical JSON) in an AtomicKV; the whole
// read-check-advance runs inside one Update. Only a contract signed by the PINNED principal is loaded, the state document is bound to
// the contract id, every corrupt or unreadable state or store error DENIES, and a real violation LATCHES the enforcer until the
// principal signs a reset.

import (
	"math"
	"strconv"
	"time"
)

// ContractResetDomain is the signature domain of a contract reset.
const ContractResetDomain = "atlas-pca/contract-reset/v1\x00"

const (
	contractDocVersion = 1
	contractCorrupt    = "<state>: stored state is corrupt or belongs to another contract"
)

// ContractEnforcerError is the construction / state error of a ContractEnforcer.
type ContractEnforcerError struct{ msg string }

func (e *ContractEnforcerError) Error() string { return "ContractEnforcer: " + e.msg }

func contractResetMsg(id string, seq int64) []byte {
	return append([]byte(ContractResetDomain), sha([]byte(id+":"+strconv.FormatInt(seq, 10)))...)
}

// SignContractReset is the principal's authorisation to un-latch a contract at sequence seq (it binds both, so it cannot be replayed later).
func SignContractReset(principalSeed []byte, contractID string, seq int64) (string, error) {
	kp, err := KeyPairFromSeed(principalSeed)
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(kp.Sign(contractResetMsg(contractID, seq))), nil
}

// contractDoc parses a stored document and checks it belongs to the contract; ok false = corrupt.
func contractDoc(prev []byte, id string) (map[string]any, bool) {
	v, err := StrictParse(string(prev))
	if err != nil {
		return nil, false
	}
	d, isObj := v.(map[string]any)
	if !isObj || !pIsNum1(d["v"]) || d["contract_id"] != any(id) || StateProblem(d["state"]) != "" {
		return nil, false
	}
	l, has := d["latched"]
	if !has {
		return d, true
	}
	lm, isObj := l.(map[string]any)
	viol, isList := lm["violated"].([]any)
	if !isObj || !isList || !pIsInteger(lm["seq"]) || pNegZero(lm["seq"]) {
		return nil, false
	}
	for _, x := range viol {
		if !isString(x) {
			return nil, false
		}
	}
	return d, true
}

func enforcerResult(allow bool, reason string, violated []any, reasons []any, seq any) map[string]any {
	if violated == nil {
		violated = []any{}
	}
	if reasons == nil {
		reasons = []any{}
	}
	return map[string]any{"allow": allow, "reason": reason, "violated": violated, "reasons": reasons, "seq": seq}
}

func latchedReason(l map[string]any) []any {
	return []any{"<latched>: contract violated at seq " + jsValueString(l["seq"])}
}

// ContractEnforcerOptions: Key is the storage key (default "contract/<id>"); Now is the wall clock in ms (default the system clock);
// NoLatch turns the latch on a real violation off.
type ContractEnforcerOptions struct {
	Key     string
	Now     func() float64
	NoLatch bool
}

// ContractEnforcer enforces one contract over a durable store.
type ContractEnforcer struct {
	kv       AtomicKV
	contract map[string]any
	id       string
	key      string
	now      func() float64
	latch    bool
}

// OpenContractEnforcer fails unless the contract verifies under the pinned principal.
func OpenContractEnforcer(kv AtomicKV, contract any, principal string, o ContractEnforcerOptions) (*ContractEnforcer, error) {
	if principal == "" {
		return nil, &ContractEnforcerError{"a pinned principal is required"}
	}
	if kv == nil {
		return nil, &ContractEnforcerError{"a store is required"}
	}
	if v := VerifyContract(contract, principal); v["ok"] != true {
		return nil, &ContractEnforcerError{"contract refused: " + v["reason"].(string)}
	}
	n, _ := pNorm(contract)
	cm := n.(map[string]any)
	id := cm["id"].(string)
	key, now := o.Key, o.Now
	if key == "" {
		key = "contract/" + id
	}
	if now == nil {
		now = func() float64 { return float64(time.Now().UnixMilli()) }
	}
	return &ContractEnforcer{kv: kv, contract: cm, id: id, key: key, now: now, latch: !o.NoLatch}, nil
}

func storeErr() map[string]any {
	return enforcerResult(false, "store-error", nil, []any{"store error (fail closed)"}, pInt(0))
}

func (e *ContractEnforcer) save(doc map[string]any) []byte {
	s, err := Canonicalize(doc)
	if err != nil {
		return nil
	}
	return []byte(s)
}

// Check checks one action against the permission verdict AND the contract, advancing the durable state iff both allow. Never panics.
func (e *ContractEnforcer) Check(action any, permitted bool) (res map[string]any) {
	out := enforcerResult(false, "store-error", nil, []any{"store unavailable"}, pInt(0))
	defer func() {
		if recover() != nil {
			res = storeErr()
		}
	}()
	wall := e.now()
	wallOK := !math.IsNaN(wall) && !math.IsInf(wall, 0)
	an, _ := pNorm(action)
	err := e.kv.Update(e.key, func(prev []byte) []byte {
		out = enforcerResult(false, "store-error", nil, []any{"store unavailable"}, pInt(0))
		var doc map[string]any
		if prev != nil {
			d, ok := contractDoc(prev, e.id)
			if !ok {
				out = enforcerResult(false, "state-error", nil, []any{contractCorrupt}, pInt(0))
				return nil
			}
			if !wallOK {
				out = enforcerResult(false, "state-error", nil, []any{"<state>: clock is not finite"}, d["state"].(map[string]any)["seq"])
				return nil
			}
			doc = d
		} else {
			var genesis any = pInt(0)
			if wallOK {
				genesis = jsNumber(wall)
			}
			doc = map[string]any{"v": pInt(contractDocVersion), "contract_id": e.id, "state": EmptyMonitorState(genesis)}
		}
		st := doc["state"].(map[string]any)
		if l, has := doc["latched"]; has {
			lm := l.(map[string]any)
			out = enforcerResult(false, "latched", lm["violated"].([]any), latchedReason(lm), st["seq"])
			return nil
		}
		r := CheckAndAdvanceContract(permitted, st, an, e.contract,
			map[string]any{"now": jsNumber(math.Max(wall, pNum(st["now"]))), "expectedSeq": st["seq"]})
		if r["allow"] == true {
			next := copyObj(doc)
			next["state"] = r["next"]
			b := e.save(next)
			if b == nil {
				out = storeErr()
				return nil
			}
			out = enforcerResult(true, "ok", nil, nil, r["next"].(map[string]any)["seq"])
			return b
		}
		structural := r["decidedBy"] == "state"
		violated := r["violated"].([]any)
		real := !structural && len(violated) > 0
		reason := "permission"
		if structural {
			reason = "state-error"
		} else if real {
			reason = "violated"
		}
		var shown []any
		if real {
			shown = violated
		}
		out = enforcerResult(false, reason, shown, r["reasons"].([]any), st["seq"])
		if real && e.latch {
			next := copyObj(doc)
			next["latched"] = map[string]any{"seq": st["seq"], "violated": violated}
			if b := e.save(next); b != nil {
				return b
			}
			out = storeErr()
		}
		return nil
	})
	if err != nil {
		return storeErr()
	}
	return out
}

// Peek is a read-only evaluation against the stored state: nothing is advanced or latched. Never panics.
func (e *ContractEnforcer) Peek(action any) (res map[string]any) {
	defer func() {
		if recover() != nil {
			res = storeErr()
		}
	}()
	raw, found, err := e.kv.Get(e.key)
	if err != nil {
		return storeErr()
	}
	var doc map[string]any
	if found {
		d, ok := contractDoc(raw, e.id)
		if !ok {
			return enforcerResult(false, "state-error", nil, []any{contractCorrupt}, pInt(0))
		}
		if l, has := d["latched"]; has {
			lm := l.(map[string]any)
			return enforcerResult(false, "latched", lm["violated"].([]any), latchedReason(lm), d["state"].(map[string]any)["seq"])
		}
		doc = d
	}
	wall := e.now()
	var state any
	var seq any = pInt(0)
	if doc != nil {
		state = doc["state"]
		seq = doc["state"].(map[string]any)["seq"]
	} else {
		var genesis any = pInt(0)
		if !math.IsNaN(wall) && !math.IsInf(wall, 0) {
			genesis = jsNumber(wall)
		}
		state = EmptyMonitorState(genesis)
	}
	r := CheckContract(action, e.contract, state)
	if r["ok"] == true {
		return enforcerResult(true, "ok", nil, nil, seq)
	}
	return enforcerResult(false, "violated", r["violated"].([]any), r["reasons"].([]any), seq)
}

// State is the stored state and whether it is latched ({state, latched}), or nil when nothing was admitted yet. A corrupt document is an error.
func (e *ContractEnforcer) State() (map[string]any, error) {
	raw, found, err := e.kv.Get(e.key)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	d, ok := contractDoc(raw, e.id)
	if !ok {
		return nil, &ContractEnforcerError{"stored state is corrupt or belongs to another contract"}
	}
	_, latched := d["latched"]
	return map[string]any{"state": d["state"], "latched": latched}, nil
}

// Reset un-latches with the principal's signature (see SignContractReset) at the latched sequence. It reports whether it cleared.
func (e *ContractEnforcer) Reset(sig any) bool {
	cleared := false
	err := e.kv.Update(e.key, func(prev []byte) []byte {
		cleared = false
		if prev == nil {
			return nil
		}
		d, ok := contractDoc(prev, e.id)
		if !ok {
			return nil
		}
		l, has := d["latched"]
		if !has {
			return nil
		}
		s, isStr := sig.(string)
		seq, _ := jsNum(l.(map[string]any)["seq"])
		principal, _ := e.contract["principal"].(string)
		if !isStr || !verifyB64u(principal, contractResetMsg(e.id, int64(seq)), s) {
			return nil
		}
		next := copyObj(d)
		delete(next, "latched")
		b := e.save(next)
		if b == nil {
			return nil
		}
		cleared = true
		return b
	})
	return err == nil && cleared
}
