package pca

// The tighten-only fold of detector receipts (the policy check and the signal), see detector_receipt.go for the receipts.

import (
	"fmt"
	"sort"
)

// MaxDetectorReceipts is the most receipts one DetectorSignal call folds.
const MaxDetectorReceipts = 32

// DetectorPolicyError is "" when the detector policy {detectors: [{id, keys, on_suspicious, max_age_ms, categories?}]} is
// well-formed: at most 16 detectors with distinct ids other than "invalid", each with 1..8 pinned keys ({pk, pq_pk?}),
// on_suspicious escalate or deny, optional categories (1+ ids) and a max_age_ms of 1..86400000.
func DetectorPolicyError(p any) string {
	pm, ok := p.(map[string]any)
	if !ok || !closedMembers(pm, []string{"detectors"}) {
		return "policy must be {detectors}"
	}
	ds, ok := pm["detectors"].([]any)
	if !ok || len(ds) > 16 {
		return "detectors must hold at most 16 entries"
	}
	ids := map[string]bool{}
	for _, d0 := range ds {
		d, ok := d0.(map[string]any)
		if !ok || !closedMembers(d, []string{"id", "keys", "on_suspicious", "max_age_ms"}, "categories") {
			return "detector entry is malformed"
		}
		id, isStr := d["id"].(string)
		if !isStr || !matchName(id) || id == "invalid" || ids[id] {
			return `detector ids must be distinct ids other than "invalid"`
		}
		ids[id] = true
		keys, ok := d["keys"].([]any)
		okKeys := ok && len(keys) >= 1 && len(keys) <= 8
		for _, k0 := range keys {
			k, isObj := k0.(map[string]any)
			if !isObj {
				okKeys = false
				break
			}
			if _, isStr := k["pk"].(string); !isStr {
				okKeys = false
				break
			}
			if v, has := k["pq_pk"]; has {
				if _, isStr := v.(string); !isStr {
					okKeys = false
					break
				}
			}
		}
		if !okKeys {
			return fmt.Sprintf("detector '%s': keys must hold 1..8 pins", id)
		}
		if os := d["on_suspicious"]; os != "escalate" && os != "deny" {
			return fmt.Sprintf("detector '%s': on_suspicious must be escalate or deny", id)
		}
		if cs, has := d["categories"]; has {
			list, isList := cs.([]any)
			good := isList && len(list) >= 1
			for _, c := range list {
				if s, isStr := c.(string); !isStr || !matchName(s) {
					good = false
				}
			}
			if !good {
				return fmt.Sprintf("detector '%s': categories must be 1+ ids", id)
			}
		}
		if f, _ := jsNum(d["max_age_ms"]); !jsIsInt(d["max_age_ms"]) || f < 1 || f > 86_400_000 {
			return fmt.Sprintf("detector '%s': max_age_ms must be 1..86400000", id)
		}
	}
	return ""
}

// DetectorRejection says why one receipt was not used (Index -1: the policy or the list as a whole).
type DetectorRejection struct {
	Index  int
	Reason string
}

// DetectorOutcome is the result of DetectorSignal.
type DetectorOutcome struct {
	// Signal is "ok" (no friction), "escalate" or "deny". Never anything that raises a decision: fold it with the tighten rules.
	Signal string
	// Detect is env.detect for `tighten[]` rules: {<detector id>: flagged (bool) for every declared detector, invalid: <count>}.
	Detect map[string]any
	// Flagged lists the detector ids whose valid suspicious receipt acted, sorted.
	Flagged []string
	// Rejected says why each receipt was not used.
	Rejected []DetectorRejection
}

var detectorRank = map[string]int{"ok": 2, "escalate": 1, "deny": 0}

// DetectorSignal is the tighten-only fold of detector receipts. input is {receipts?, policy, input_digests, session?, now}. It is
// total. A malformed policy is "deny". For each receipt: shape, declared detector, a pinned key's signature, content in
// input_digests, session (when the receipt has one it must equal session), iat <= now, age <= max_age_ms. A valid suspicious
// receipt with an acting category lowers the signal to the detector's on_suspicious; a valid no_finding does nothing; an invalid
// receipt lowers it to "escalate". With any set of receipts the outcome is at most the outcome with none, and adding valid
// no_finding receipts never changes it.
func DetectorSignal(input map[string]any) (out DetectorOutcome) {
	if pe := DetectorPolicyError(input["policy"]); pe != "" {
		return DetectorOutcome{Signal: "deny", Detect: map[string]any{"invalid": jsNumber(0)}, Flagged: []string{}, Rejected: []DetectorRejection{{-1, "policy: " + pe}}}
	}
	flagged := map[string]bool{}
	var rejected []DetectorRejection
	signal := "ok"
	lower := func(s string) {
		if detectorRank[s] < detectorRank[signal] {
			signal = s
		}
	}
	env := map[string]any{}
	defer func() {
		if r := recover(); r != nil {
			lower("deny")
			rejected = append(rejected, DetectorRejection{-1, fmt.Sprintf("evaluation error (fail closed): %v", r)})
		}
		env["invalid"] = jsNumber(float64(len(rejected)))
		fl := make([]string, 0, len(flagged))
		for k := range flagged {
			fl = append(fl, k)
		}
		sort.Strings(fl)
		if rejected == nil {
			rejected = []DetectorRejection{}
		}
		out = DetectorOutcome{Signal: signal, Detect: env, Flagged: fl, Rejected: rejected}
	}()
	policy := input["policy"].(map[string]any)
	dets := policy["detectors"].([]any)
	for _, d := range dets {
		env[d.(map[string]any)["id"].(string)] = false
	}
	receipts, recOK := input["receipts"].([]any)
	if _, has := input["receipts"]; !has || input["receipts"] == nil {
		receipts, recOK = []any{}, true
	}
	digests, _ := input["input_digests"].([]any)
	now, nowOK := jsNum(input["now"])
	nowOK = nowOK && jsIsInt(input["now"])
	if !recOK || len(receipts) > MaxDetectorReceipts || !nowOK {
		lower("escalate")
		rejected = append(rejected, DetectorRejection{-1, "receipt list or clock malformed"})
		return
	}
	for index, r := range receipts {
		if why := detectorReceiptProblem(r, dets, digests, input["session"], now); why != "" {
			rejected = append(rejected, DetectorRejection{index, why})
			lower("escalate")
			continue
		}
		rc := r.(map[string]any)
		if rc["verdict"] != "suspicious" {
			continue
		}
		var d map[string]any
		for _, x := range dets {
			if xm := x.(map[string]any); xm["id"] == rc["detector"] {
				d = xm
				break
			}
		}
		if cats, has := d["categories"].([]any); has {
			rcats, _ := rc["categories"].([]any)
			acts := false
			for _, c := range rcats {
				if containsV(cats, c) {
					acts = true
					break
				}
			}
			if len(rcats) > 0 && !acts {
				continue
			}
		}
		id := d["id"].(string)
		flagged[id] = true
		env[id] = true
		lower(d["on_suspicious"].(string))
	}
	return
}

func detectorReceiptProblem(r any, dets, digests []any, session any, now float64) string {
	if se := DetectorReceiptShapeError(r); se != "" {
		return "malformed: " + se
	}
	rc := r.(map[string]any)
	var d map[string]any
	for _, x := range dets {
		if xm := x.(map[string]any); xm["id"] == rc["detector"] {
			d = xm
			break
		}
	}
	if d == nil {
		return fmt.Sprintf("undeclared detector '%s'", jsValueString(rc["detector"]))
	}
	id := d["id"].(string)
	signed := false
	for _, k0 := range d["keys"].([]any) {
		k := k0.(map[string]any)
		if verifyArtifactSig(DetectorReceiptDomain, rc, k["pk"], k["pq_pk"]) {
			signed = true
			break
		}
	}
	if !signed {
		return fmt.Sprintf("detector '%s': no pinned key signed it", id)
	}
	if !containsV(digests, rc["input_digest"]) {
		return fmt.Sprintf("detector '%s': the receipt is about other content", id)
	}
	if s, has := rc["session"]; has && s != session {
		return fmt.Sprintf("detector '%s': bound to another session", id)
	}
	iat, _ := jsNum(rc["iat"])
	if iat > now {
		return fmt.Sprintf("detector '%s': from the future", id)
	}
	if maxAge, _ := jsNum(d["max_age_ms"]); now-iat > maxAge {
		return fmt.Sprintf("detector '%s': stale", id)
	}
	return ""
}
