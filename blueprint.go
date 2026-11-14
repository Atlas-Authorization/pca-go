package pca

// Agent blueprints: a fleet ceiling and a group kill (verification side). A blueprint is a record signed by an operator for a
// blueprint KEY; an instance is a chain with a hop issued by that key. The verifier keeps the newest record per key
// (BlueprintRegistry: pinned operators, a strictly higher epoch replaces, the same epoch with different content is a fork) and
// gates a chain with CheckBlueprints (status, expiry, depth, link, optional staleness epoch). This SDK does not evaluate
// ceilings: a non-empty ceiling denies (`ceiling_unevaluable`), so it never allows past a ceiling it cannot read. It does not
// admit instances either: a record with `runtime_pins` denies (`admission_required`), it never falls through. Total.

import (
	"encoding/json"
	"slices"
	"strconv"
	"sync"
)

const agentBlueprintDomain = "atlas-pca/agent-blueprint/v1\x00"

var blueprintBodyKeys = []string{"v", "id", "key", "ceiling", "max_depth", "expires_at", "runtime_pins", "epoch", "status", "issued_at", "operator"}
var blueprintPinKeys = []string{"runtime_measurement", "model_id", "weights_digest", "operator", "spiffe_id"}

func blueprintPinOK(v any) bool {
	m, ok := v.(map[string]any)
	if !ok || len(m) == 0 {
		return false
	}
	for k, x := range m {
		if !slices.Contains(blueprintPinKeys, k) || !k3Str(x, 256) {
			return false
		}
	}
	return true
}

func blueprintWellFormed(v any) (map[string]any, bool) {
	b, _ := v.(map[string]any) // a non-object is a nil map: it fails the v check below
	if f, ok := jsNum(b["v"]); !ok || f != 1 {
		return nil, false
	}
	if !k3Str(b["id"], 128) || !k3Str(b["key"], 128) || !k3Str(b["operator"], 128) || !k3Int(b["epoch"]) || !k3Int(b["issued_at"]) {
		return nil, false
	}
	if s, _ := b["status"].(string); s != "active" && s != "disabled" {
		return nil, false
	}
	if x, has := b["max_depth"]; has {
		if f, _ := jsNum(x); !k3Int(x) || f < 1 {
			return nil, false
		}
	}
	if x, has := b["expires_at"]; has && !k3Int(x) {
		return nil, false
	}
	if x, has := b["runtime_pins"]; has {
		p, ok := x.([]any)
		if !ok || len(p) == 0 || len(p) > 16 {
			return nil, false
		}
		for _, e := range p {
			if !blueprintPinOK(e) {
				return nil, false
			}
		}
	}
	c, ok := b["ceiling"].([]any)
	if !ok || len(c) > 32 {
		return nil, false
	}
	for _, e := range c {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, false
		}
		if _, isStr := m["type"].(string); !isStr {
			return nil, false
		}
	}
	return b, true
}

// VerifyBlueprint: well formed and signed by its operator over exactly its content.
func VerifyBlueprint(v any) bool {
	b, ok := blueprintWellFormed(v)
	if !ok {
		return false
	}
	body := map[string]any{}
	for _, k := range blueprintBodyKeys {
		if x, has := b[k]; has {
			body[k] = x
		}
	}
	return extSigned(b["operator"].(string), agentBlueprintDomain, body, b["sig"])
}

// BlueprintRegistry holds the newest accepted record per blueprint key in a durable AtomicKV: one document per blueprint key
// (`blueprint/key/<key>`) and one monotone document for the highest epoch ever accepted (`blueprint/maxepoch`), as the reference
// store keeps them. Accepting a record is one atomic kv.Update of its key, so a disabled blueprint stays disabled across restarts and
// instances and two racing records of one key have one winner. A kv error is `store_unreachable`.
type BlueprintRegistry struct {
	mu        sync.Mutex // serialises the working copy within this process
	operators []string
	kv        AtomicKV
	store     map[string]map[string]any // the working copy: the record loaded last, under its key
	loadKey   string
}

const blueprintMaxEpochKey = "blueprint/maxepoch"

func blueprintKeyDoc(key string) string { return "blueprint/key/" + key }

// loadFor decodes the document of key into the working copy.
func (r *BlueprintRegistry) loadFor(key string) func(prev []byte) error {
	return func(prev []byte) error {
		r.store = map[string]map[string]any{}
		r.loadKey = key
		if prev == nil {
			return nil
		}
		var rec map[string]any
		if err := kvDecode(prev, &rec); err != nil || rec == nil {
			return errStoreState
		}
		r.store[key] = rec
		return nil
	}
}

// NewBlueprintRegistry panics without a kv, as the reference constructor throws: a process-local default would forget a disabled
// blueprint on restart (MemoryBlueprintKv() is for tests and single-process use).
func NewBlueprintRegistry(operators []string, kv AtomicKV) *BlueprintRegistry {
	if kv == nil {
		panic("BlueprintRegistry: a durable BlueprintStore is required (MemoryBlueprintKv() is for tests and single-process use)")
	}
	return &BlueprintRegistry{operators: operators, kv: kv, store: map[string]map[string]any{}}
}

// Accept returns ("", replaced) when taken, else the refusal code (`store_unreachable` when the kv cannot decide).
func (r *BlueprintRegistry) Accept(v any) (string, bool) {
	if !VerifyBlueprint(v) {
		return "bad_record", false
	}
	b := v.(map[string]any)
	known := false
	for _, o := range r.operators {
		if o == b["operator"] {
			known = true
		}
	}
	if !known {
		return "unknown_operator", false
	}
	key := b["key"].(string)
	r.mu.Lock()
	defer r.mu.Unlock()
	code, replaced := "store_unreachable", false
	if err := kvTxn(r.kv, blueprintKeyDoc(key), r.loadFor(key), func() bool {
		if cur, has := r.store[key]; has {
			if cur["operator"] != b["operator"] {
				code = "operator_changed"
				return false
			}
			ce, _ := safeInt(cur["epoch"])
			be, _ := safeInt(b["epoch"])
			if be < ce {
				code = "stale_epoch"
				return false
			}
			if be == ce {
				code = "epoch_fork"
				if cur["sig"] == b["sig"] {
					code = ""
				}
				return false
			}
		}
		r.store[key] = b
		code, replaced = "", true
		return true
	}, func() []byte { return kvEncode(r.store[key]) }); err != nil {
		return "store_unreachable", false
	}
	if replaced { // the highest epoch only ever rises; a failure here leaves it understated, which only escalates more
		be, _ := safeInt(b["epoch"])
		if err := r.raiseMaxEpoch(be); err != nil {
			return "store_unreachable", false
		}
	}
	return code, replaced
}

func (r *BlueprintRegistry) raiseMaxEpoch(e int64) (err error) {
	defer func() {
		if recover() != nil {
			err = errStoreState
		}
	}()
	return r.kv.Update(blueprintMaxEpochKey, func(prev []byte) []byte {
		var cur int64
		if prev != nil {
			var n json.Number
			if kvDecode(prev, &n) == nil {
				cur, _ = safeInt(n)
			}
		}
		if e > cur {
			return kvEncode(json.Number(strconv.FormatInt(e, 10)))
		}
		return nil
	})
}

// lookup reads the record under a blueprint key from the store; a store error is returned, never read as "no blueprint".
func (r *BlueprintRegistry) lookup(key string) (map[string]any, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := kvRead(r.kv, blueprintKeyDoc(key), r.loadFor(key)); err != nil {
		return nil, false, err
	}
	b, has := r.store[key]
	return b, has, nil
}

// Epoch is the highest epoch accepted so far (0 when empty or when the store cannot be read, see epochOf).
func (r *BlueprintRegistry) Epoch() int64 {
	e, _ := r.epochOf()
	return e
}

func (r *BlueprintRegistry) epochOf() (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var e int64
	err := kvRead(r.kv, blueprintMaxEpochKey, func(prev []byte) error {
		e = 0
		if prev == nil {
			return nil
		}
		var n json.Number
		if err := kvDecode(prev, &n); err != nil {
			return err
		}
		v, ok := safeInt(n)
		if !ok || v < 0 {
			return errStoreState
		}
		e = v
		return nil
	})
	return e, err
}

// BlueprintDecision is the outcome of CheckBlueprints.
type BlueprintDecision struct {
	Decision  string // allow | deny | escalate
	Code      string
	Blueprint string
	Governed  []string
	Have      int64
	Need      int64
}

func bpDeny(code, bp string) BlueprintDecision {
	return BlueprintDecision{Decision: "deny", Code: code, Blueprint: bp}
}

// BlueprintAdmitted is the host's admission hook: is the instance key (the holder of the hop issued by the blueprint key) admitted
// under this record (its runtime pins)? Only an explicit true admits.
type BlueprintAdmitted func(instanceKey string, bp map[string]any) bool

func callAdmitted(f BlueprintAdmitted, holder string, bp map[string]any) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return f(holder, bp)
}

// CheckBlueprints gates a chain (hops {issuer, holder}, root first). mode is "require" or "any"; minEpoch (nil = none) is the
// revocation epoch of the newest fresh_at token the caller showed.
func CheckBlueprints(chain any, r *BlueprintRegistry, now any, mode string, minEpoch *int64, admitted ...BlueprintAdmitted) BlueprintDecision {
	var admit BlueprintAdmitted
	if len(admitted) > 0 {
		admit = admitted[0]
	}
	hops, ok := chain.([]any)
	if !ok || len(hops) == 0 || !k3Int(now) {
		return bpDeny("bad_input", "")
	}
	type hop struct{ issuer, holder string }
	hs := make([]hop, len(hops))
	for i, x := range hops {
		m, ok := x.(map[string]any)
		if !ok || !k3Str(m["issuer"], 128) || !k3Str(m["holder"], 128) {
			return bpDeny("bad_input", "")
		}
		hs[i] = hop{m["issuer"].(string), m["holder"].(string)}
	}
	nowMs, _ := safeInt(now)
	if minEpoch != nil {
		have, eerr := r.epochOf()
		if eerr != nil {
			return bpDeny("store_unreachable", "")
		}
		if have < *minEpoch {
			return BlueprintDecision{Decision: "escalate", Code: "stale_blueprint_state", Have: have, Need: *minEpoch}
		}
	}
	governed := []string{}
	for i, h := range hs {
		bp, has, lerr := r.lookup(h.issuer)
		if lerr != nil {
			return bpDeny("store_unreachable", "")
		}
		if !has {
			continue
		}
		id := bp["id"].(string)
		if i == 0 || hs[i-1].holder != bp["key"] {
			return bpDeny("broken_link", id)
		}
		if bp["status"] != "active" {
			return bpDeny("blueprint_disabled", id)
		}
		if x, has := bp["expires_at"]; has {
			if at, _ := safeInt(x); nowMs >= at {
				return bpDeny("blueprint_expired", id)
			}
		}
		if x, has := bp["max_depth"]; has {
			if d, _ := safeInt(x); int64(len(hs)-i) > d {
				return bpDeny("too_deep", id)
			}
		}
		if _, has := bp["runtime_pins"]; has {
			// a blueprint with runtime pins admits an instance only through the host's hook: none is admission_required, false (or a
			// hook that panics) is not_admitted, only true goes on to the ceiling
			if admit == nil {
				return bpDeny("admission_required", id)
			}
			if !callAdmitted(admit, h.holder, bp) {
				return bpDeny("not_admitted", id)
			}
		}
		if c, _ := bp["ceiling"].([]any); len(c) > 0 {
			return bpDeny("ceiling_unevaluable", id)
		}
		governed = append(governed, id)
	}
	if len(governed) == 0 && mode == "require" {
		return bpDeny("no_blueprint", "")
	}
	return BlueprintDecision{Decision: "allow", Governed: governed}
}
