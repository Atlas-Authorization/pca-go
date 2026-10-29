package pca

// Agent blueprints: a fleet ceiling and a group kill (verification side). A blueprint is a record signed by an operator for a
// blueprint KEY; an instance is a chain with a hop issued by that key. The verifier keeps the newest record per key
// (BlueprintRegistry: pinned operators, a strictly higher epoch replaces, the same epoch with different content is a fork) and
// gates a chain with CheckBlueprints (status, expiry, depth, link, optional staleness epoch). This SDK does not evaluate
// ceilings: a non-empty ceiling denies (`ceiling_unevaluable`), so it never allows past a ceiling it cannot read. Total.

const agentBlueprintDomain = "atlas-pca/agent-blueprint/v1\x00"

var blueprintBodyKeys = []string{"v", "id", "key", "ceiling", "max_depth", "expires_at", "epoch", "status", "issued_at", "operator"}

func blueprintWellFormed(v any) (map[string]any, bool) {
	b, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
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

// BlueprintRegistry holds the newest accepted record per blueprint key.
type BlueprintRegistry struct {
	operators []string
	store     map[string]map[string]any
}

func NewBlueprintRegistry(operators []string) *BlueprintRegistry {
	return &BlueprintRegistry{operators: operators, store: map[string]map[string]any{}}
}

// Accept returns ("", replaced) when taken, else the refusal code.
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
	if cur, has := r.store[b["key"].(string)]; has {
		if cur["operator"] != b["operator"] {
			return "operator_changed", false
		}
		ce, _ := safeInt(cur["epoch"])
		be, _ := safeInt(b["epoch"])
		if be < ce {
			return "stale_epoch", false
		}
		if be == ce {
			if cur["sig"] == b["sig"] {
				return "", false
			}
			return "epoch_fork", false
		}
	}
	r.store[b["key"].(string)] = b
	return "", true
}

// Epoch is the highest epoch accepted so far (0 when empty).
func (r *BlueprintRegistry) Epoch() int64 {
	var e int64
	for _, b := range r.store {
		if x, _ := safeInt(b["epoch"]); x > e {
			e = x
		}
	}
	return e
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

// CheckBlueprints gates a chain (hops {issuer, holder}, root first). mode is "require" or "any"; minEpoch (nil = none) is the
// revocation epoch of the newest fresh_at token the caller showed.
func CheckBlueprints(chain any, r *BlueprintRegistry, now any, mode string, minEpoch *int64) BlueprintDecision {
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
		if have := r.Epoch(); have < *minEpoch {
			return BlueprintDecision{Decision: "escalate", Code: "stale_blueprint_state", Have: have, Need: *minEpoch}
		}
	}
	governed := []string{}
	for i, h := range hs {
		bp, has := r.store[h.issuer]
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
