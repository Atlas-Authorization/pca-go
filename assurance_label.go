package pca

// The assurance-label helpers of the reference (setAssuranceLabel / assuranceLabelOf / refreshAssurance). The reference tags a
// JavaScript object with a WeakMap; Go labels a value by wrapping it (Labeled) or by implementing AssuranceLabeler.

// SetAssuranceLabel labels a verifier hook, a hardware attestation verifier or a SNARK backend so a requirement can be met by
// it. The library's own constructors label what they build; label a custom one with this. The result is the labelled wrapper
// (the label is a copy: later changes to label do not reach it); use .Hook for the original value.
func SetAssuranceLabel[T any](target T, label AssuranceLabel) Labeled[T] {
	return WithAssuranceLabel(target, label)
}

// AssuranceLabelOf returns the label attached to target; ok is false when it is unlabelled (it implements no AssuranceLabeler).
func AssuranceLabelOf(target any) (label AssuranceLabel, ok bool) {
	if l, is := target.(AssuranceLabeler); is {
		return l.Assurance(), true
	}
	return AssuranceLabel{}, false
}

// RefreshAssurance refreshes a report after more checks were decided (the replay counter, default-deny of required checks):
// a check that is no longer "pass" loses its level, a new check is added in the order given, and `unsupported` stays. It
// returns the refreshed report (the argument is not modified).
func RefreshAssurance(report AssuranceReport, checks []NamedStatus) AssuranceReport {
	out := AssuranceReport{names: append([]string(nil), report.names...), by: make(map[string]CheckAssurance, len(report.by))}
	for k, v := range report.by {
		out.by[k] = v
	}
	set := func(name string, c CheckAssurance) {
		if _, has := out.by[name]; !has {
			out.names = append(out.names, name)
		}
		out.by[name] = c
	}
	for _, c := range checks {
		was, has := out.by[c.Name]
		if has && was.Outcome == "unsupported" {
			continue
		}
		if c.Status != "pass" {
			set(c.Name, CheckAssurance{Outcome: c.Status})
		} else if !has || was.Outcome != "pass" {
			set(c.Name, CheckAssurance{Outcome: "pass"})
		}
	}
	return out
}
