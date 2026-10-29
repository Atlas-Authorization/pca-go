package pca

import "regexp"

// Decision obligations (verification side): validate, merge, the PEP gate and the overdue outcome. An allow whose obligations the
// enforcement point cannot all perform becomes a deny. Total. Lists are decoded JSON ([]any of map[string]any); nil is the empty list.

const maxObligations = 16

var obligationFieldRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7}$`)
var obligationAllowed = map[string][]string{"log": {"sink"}, "notify": {"to"}, "redact": {"fields"}, "watermark": {"id"}, "require_receipt": {},
	"undo_window": {"id", "window_end"}}

func obligationParamsError(kind string, p map[string]any) string {
	for k := range p {
		if !leaseHas(obligationAllowed[kind], k) {
			return "unknown parameter '" + k + "' for '" + kind + "'"
		}
	}
	if _, has := p["sink"]; kind == "log" && has && !k3Str(p["sink"], 128) {
		return "log.sink must be a non-empty string of at most 128 characters"
	}
	if kind == "notify" && !k3Str(p["to"], 256) {
		return "notify.to is required"
	}
	if kind == "watermark" && !k3Str(p["id"], 128) {
		return "watermark.id is required"
	}
	// undo_window {id, window_end}: the action runs under a veto window (undo record id, open until window_end)
	if kind == "undo_window" && (!k3Str(p["id"], 128) || !k3Int(p["window_end"])) {
		return "undo_window needs id (a non-empty string of at most 128 characters) and window_end (a non-negative safe integer)"
	}
	if kind == "redact" {
		f, ok := p["fields"].([]any)
		if !ok || len(f) == 0 || len(f) > 32 {
			return "redact.fields must be 1..32 dotted field paths"
		}
		seen := map[string]bool{}
		for _, x := range f {
			s, isStr := x.(string)
			if !isStr || !obligationFieldRe.MatchString(s) {
				return "redact.fields must be 1..32 dotted field paths"
			}
			if seen[s] {
				return "redact.fields has a duplicate"
			}
			seen[s] = true
		}
	}
	return ""
}

// ObligationError: "" = well formed.
func ObligationError(v any) string {
	o, ok := v.(map[string]any)
	if !ok {
		return "an obligation must be an object"
	}
	for k := range o {
		if k != "kind" && k != "params" && k != "due" {
			return "unknown member '" + k + "'"
		}
	}
	kind, _ := o["kind"].(string)
	if _, has := obligationAllowed[kind]; !has {
		return "unknown obligation kind"
	}
	if d, has := o["due"]; has && !k3Int(d) {
		return "due must be a non-negative safe integer"
	}
	p := map[string]any{}
	if x, has := o["params"]; has {
		if p, ok = x.(map[string]any); !ok {
			return "params must be an object"
		}
	}
	return obligationParamsError(kind, p)
}

// ObligationKey is the canonical identity of a (valid) obligation: strict canonical JSON of {kind, params ({} when absent), due?}.
func ObligationKey(o map[string]any) (string, bool) {
	params := o["params"]
	if params == nil {
		params = map[string]any{}
	}
	body := map[string]any{"kind": o["kind"], "params": params}
	if d, has := o["due"]; has {
		body["due"] = d
	}
	s, err := Canonicalize(body)
	return s, err == nil
}

// ObligationsError: "" = a well-formed, duplicate-free list of at most 16. nil is the empty list.
func ObligationsError(list any) string {
	if list == nil {
		return ""
	}
	l, ok := list.([]any)
	if !ok {
		return "obligations must be an array"
	}
	if len(l) > maxObligations {
		return "more than 16 obligations"
	}
	seen := map[string]bool{}
	for _, o := range l {
		if e := ObligationError(o); e != "" {
			return "malformed obligation: " + e
		}
		key, ok := ObligationKey(o.(map[string]any))
		if !ok {
			return "an obligation is not canonicalizable"
		}
		if seen[key] {
			return "an obligation duplicates an earlier one"
		}
		seen[key] = true
	}
	return ""
}

// MergeObligations is the union of the lists, deduplicated by key and sorted by key in UTF-8 byte order. ok=false is a refusal.
func MergeObligations(lists ...any) (merged []any, ok bool) {
	by := map[string]any{}
	for _, l := range lists {
		if ObligationsError(l) != "" {
			return nil, false
		}
		items, _ := l.([]any)
		for _, o := range items {
			k, _ := ObligationKey(o.(map[string]any))
			by[k] = o
		}
	}
	if len(by) > maxObligations {
		return nil, false
	}
	keys := make([]string, 0, len(by))
	for k := range by {
		keys = append(keys, k)
	}
	sortUtf8(keys)
	merged = []any{}
	for _, k := range keys {
		merged = append(merged, by[k])
	}
	return merged, true
}

type ObligationGate struct {
	Decision    string
	Perform     []any
	Unsupported []string
	Reason      string
}

// PepObligationGate: an allow (or an answered escalate) with any obligation outside supported is a deny, as is any malformed input.
func PepObligationGate(decision string, answered bool, obligations, supported any) ObligationGate {
	deny := func(reason string, un []string) ObligationGate {
		return ObligationGate{Decision: "deny", Perform: []any{}, Unsupported: un, Reason: reason}
	}
	eff := PepDecision(decision, answered)
	if eff != "allow" {
		if eff == "escalate" {
			return ObligationGate{Decision: "escalate", Perform: []any{}, Unsupported: []string{}}
		}
		return deny("", []string{})
	}
	if e := ObligationsError(obligations); e != "" {
		return deny("malformed obligations: "+e, []string{})
	}
	sup, ok := supported.([]any)
	have := map[string]bool{}
	for _, x := range sup {
		s, isStr := x.(string)
		ok = ok && isStr
		have[s] = true
	}
	if !ok {
		return deny("the supported obligation kinds are malformed", []string{})
	}
	list, _ := obligations.([]any)
	missing, seen := []string{}, map[string]bool{}
	for _, o := range list {
		k := o.(map[string]any)["kind"].(string)
		if !have[k] && !seen[k] {
			seen[k] = true
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		sortUtf8(missing)
		return deny("the enforcement point does not support an obligation", missing)
	}
	if list == nil {
		list = []any{}
	}
	return ObligationGate{Decision: "allow", Perform: list, Unsupported: []string{}}
}

type ObligationOutcomeResult struct {
	Outcome string // "ok" or "escalate"
	Overdue []int
	Status  string // "obligation_unmet" on escalate
}

// ObligationOutcome: which obligations are overdue (due <= now, index not in fulfilled)? Malformed input is overdue-everything.
func ObligationOutcome(obligations, fulfilled, now any) ObligationOutcomeResult {
	list, _ := obligations.([]any)
	f, isList := fulfilled.([]any)
	bad := ObligationsError(obligations) != "" || !isList || !k3Int(now)
	done := map[int64]bool{}
	for _, x := range f {
		bad = bad || !k3Int(x)
		done[leaseInt(x)] = true
	}
	overdue := []int{}
	for i, x := range list {
		o, _ := x.(map[string]any)
		d, has := o["due"]
		if bad || (has && leaseInt(d) <= leaseInt(now) && !done[int64(i)]) {
			overdue = append(overdue, i)
		}
	}
	if bad || len(overdue) > 0 {
		return ObligationOutcomeResult{"escalate", overdue, "obligation_unmet"}
	}
	return ObligationOutcomeResult{"ok", overdue, ""}
}
