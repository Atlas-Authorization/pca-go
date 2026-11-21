package pca

import "fmt"

// EnforcedVerdict is the outcome of EnforceRequired.
type EnforcedVerdict struct {
	Allow   bool
	Checks  map[string]string
	Reasons []string
}

// EnforceRequired is the default-deny pass: it turns every required check that is not "pass" into a failure and says why (an absent,
// not-enforced or unsupported check is refused with a reason; an already failing one stays failed with its own reason). The old
// check name "counter" means the replay check when the verdict has one (else the counter_format check). Checks that are not
// required are left as they are, an unsupported one included. The arguments are not modified.
func EnforceRequired(allow bool, checks map[string]string, reasons []string, required []string) EnforcedVerdict {
	out := make(map[string]string, len(checks))
	for k, v := range checks {
		out[k] = v
	}
	rs := append([]string{}, reasons...)
	for _, name0 := range required {
		name := name0
		if name0 == "counter" {
			if _, has := out["counter"]; !has {
				if _, hasReplay := out["replay"]; hasReplay {
					name = "replay"
				} else {
					name = "counter_format"
				}
			}
		}
		was, present := out[name]
		if present && was == "pass" {
			continue
		}
		allow = false
		if present && was == "fail" {
			continue
		}
		shown := "absent"
		if present {
			shown = was
		}
		rs = append(rs, fmt.Sprintf("%s: required check is %s (default-deny: not enforced by this resource server)", name, shown))
		out[name] = "fail"
	}
	return EnforcedVerdict{Allow: allow, Checks: out, Reasons: rs}
}
