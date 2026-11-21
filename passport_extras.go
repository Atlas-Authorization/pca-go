package pca

// The rest of the passport module of the reference: the version and evidence-age constants, the evidence binding, the
// offline binding match, the in-memory registry, the identity-assurance score and the assurance label of a verified passport.

import (
	"fmt"
	"slices"
)

const (
	// PassportVersion is the only passport wire version this build understands.
	PassportVersion = 1
	// DefaultPassportEvidenceAgeMs is the default ceiling (24 hours) on the age of a hardware quote a passport carries.
	DefaultPassportEvidenceAgeMs = passportDefaultEvidence
)

// PassportEvidenceBinding is the binding a hardware quote must carry for a passport: holder = the subject key, grant =
// "passport:<id>", epoch 0, nonce = the evidence nonce.
func PassportEvidenceBinding(passportID, subject, nonce string) PassportBinding {
	return PassportBinding{HolderPub: subject, GrantRef: "passport:" + passportID, Epoch: 0, Nonce: nonce}
}

// MatchesBinding decides whether an unsigned passport satisfies a grant's agent_binding, offline, with the allowlist semantics of the
// attestation verifier. Every *_allowlist that is present needs its digest present and listed (fail closed); a pinned operator must
// equal; require_hardware needs hardware_rooted; require_measured_weights needs weights_measured; min_measurement is an equality pin
// (a string) or a monotone SVN lower bound ({svn: n}); anything else is malformed and refuses. It returns the failed reasons.
func MatchesBinding(passport, binding map[string]any) (ok bool, reasons []string) {
	reasons = []string{}
	pstr := func(k string) (string, bool) { s, has := passport[k].(string); return s, has }
	list := func(k string) []any { l, _ := binding[k].([]any); return l }
	has := func(l []any, v string) bool {
		return slices.ContainsFunc(l, func(x any) bool { s, isStr := x.(string); return isStr && s == v })
	}
	need := func(key, label string) {
		l := list(key)
		if len(l) == 0 {
			return
		}
		pk := map[string]string{"weights_allowlist": "weights_digest", "system_prompt_allowlist": "system_prompt_digest", "tool_manifest_allowlist": "tool_manifest_digest"}[key]
		v, present := pstr(pk)
		switch {
		case !present:
			reasons = append(reasons, label+" required by binding but absent from passport")
		case !has(l, v):
			reasons = append(reasons, fmt.Sprintf("%s '%s' not in allowlist", label, v))
		}
	}
	modelID, _ := pstr("model_id")
	if l := list("model_allowlist"); len(l) > 0 && !has(l, modelID) {
		reasons = append(reasons, fmt.Sprintf("model_id '%s' not in allowlist", modelID))
	}
	need("weights_allowlist", "weights_digest")
	need("system_prompt_allowlist", "system_prompt_digest")
	need("tool_manifest_allowlist", "tool_manifest_digest")
	if op, pinned := binding["operator"]; pinned {
		have, _ := pstr("operator")
		if want, isStr := op.(string); !isStr || have != want {
			reasons = append(reasons, fmt.Sprintf("operator '%s' != required '%v'", have, op))
		}
	}
	if binding["require_hardware"] == true && passport["hardware_rooted"] != true {
		reasons = append(reasons, "binding requires a hardware-rooted attestation")
	}
	if binding["require_measured_weights"] == true && passport["weights_measured"] != true {
		reasons = append(reasons, "binding requires hardware-measured weights")
	}
	if mm, pinned := binding["min_measurement"]; pinned {
		rm, rmOK := pstr("runtime_measurement")
		if s, isStr := mm.(string); isStr {
			if !rmOK || rm != s {
				reasons = append(reasons, "runtime_measurement does not equal the pinned measurement")
			}
		} else if bound, ok := svnBoundOf(mm); !ok {
			reasons = append(reasons, "min_measurement is malformed: it must be a non-empty string or {svn: n} with n a non-negative safe integer (fail closed)")
		} else if got, ok := canonicalSvn(rm); !rmOK || !ok || got < bound {
			shown := "undefined"
			if raw, has := passport["runtime_measurement"]; has {
				shown = jsValueString(raw) // String(rm) of whatever the passport carries
			}
			reasons = append(reasons, fmt.Sprintf("runtime SVN %s < required %d", shown, bound))
		}
	}
	return len(reasons) == 0, reasons
}

// svnBoundOf reads exactly {svn: n}, n a non-negative safe integer.
func svnBoundOf(v any) (int64, bool) {
	m, isMap := v.(map[string]any)
	if !isMap || len(m) != 1 {
		return 0, false
	}
	n, ok := anySafeInt(m["svn"])
	return n, ok && n >= 0
}

// anySafeInt reads a safe integer from a json.Number, a Go integer or an integral float64 (a hand-built map).
func anySafeInt(v any) (int64, bool) {
	switch t := v.(type) {
	case int:
		return int64(t), int64(t) <= maxSafeInt && int64(t) >= -maxSafeInt
	case int64:
		return t, t <= maxSafeInt && t >= -maxSafeInt
	case float64:
		return int64(t), t == float64(int64(t)) && t <= maxSafeInt && t >= -maxSafeInt && !(t == 0 && 1/t < 0)
	}
	return safeInt(v)
}

// canonicalSvn is the canonical decimal text of a safe non-negative integer ("0" or no leading zero, digits only).
func canonicalSvn(s string) (int64, bool) {
	if s == "" || (len(s) > 1 && s[0] == '0') || len(s) > 16 {
		return 0, false
	}
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int64(c-'0')
	}
	return n, n <= maxSafeInt
}

// BuildRegistry is the reference name of BuildPassportRegistry: an id-indexed passport set.
func BuildRegistry(passports []map[string]any) *PassportRegistry {
	return BuildPassportRegistry(passports)
}

// TrustScore is a coarse identity-assurance score in [0, 1] from the passport's own completeness (not behavioural reputation):
// a hardware root dominates, measured provenance and a known operator add confidence.
func TrustScore(passport map[string]any, knownOperators []string) float64 {
	nz := func(k string) bool { s, ok := passport[k].(string); return ok && s != "" }
	s := 0.0
	if passport["hardware_rooted"] == true {
		s += 0.4
	}
	if nz("weights_digest") {
		if passport["weights_measured"] == true {
			s += 0.2
		} else {
			s += 0.1
		}
	}
	if nz("system_prompt_digest") {
		s += 0.1
	}
	if nz("tool_manifest_digest") {
		s += 0.1
	}
	if op, ok := passport["operator"].(string); ok && slices.Contains(knownOperators, op) {
		s += 0.2
	}
	return max(0, min(1, s))
}

// PassportAssurance is the assurance label of a verified passport: hardware only when its evidence verified through verifier (whose
// own label, or unknown when it has none, is reported); a passport without verified hardware evidence is software.
func PassportAssurance(hardwareVerified bool, verifier any) AssuranceLabel {
	if !hardwareVerified {
		return AssuranceLabel{Level: "software"}
	}
	l := labelOf(verifier)
	if l.Level == "" {
		l.Level = "unknown"
	}
	return AssuranceLabel{Level: l.Level, Vendor: l.Vendor}
}
