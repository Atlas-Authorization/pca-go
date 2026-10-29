package pca

// Assurance labels (T8, B7). A check's status ("pass", "fail", "not-enforced", "unsupported") says WHETHER it held; the
// assurance report says WHAT a pass rests on: software or hardware attestation, a SNARK proof or an attested-VM statement,
// a post-quantum or an Ed25519 signature, independent multisig shares or a FROST (awaiting audit) aggregate. It also names the
// features this verifier does not implement ("unsupported": a bond reference), which are reported and never count as a pass.
//
// Labels come from the VERIFIER'S configuration, never from the presented evidence: a hook or verifier carries its label
// (it implements AssuranceLabeler, or is wrapped with WithAssuranceLabel); an unlabelled one is "unknown" and satisfies no
// requirement. A requirement (AssuranceRequirement) turns the report into a gate: when the evidence is weaker, missing,
// failed, unlabelled, awaiting-audit, degraded or unsupported, the `assurance` check fails and the request is denied. Mirrors the
// reference assurance module; assurance-vectors.json pins the report and every reason.

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// AssuranceLabel is what a hook, hardware verifier or SNARK backend declares about itself.
type AssuranceLabel struct {
	// Level is the level / system / scheme: attestation "software" < "hardware" < "multi_root"; zk "groth16",
	// "policyvm_snark", "stark", "zkvm", "attested_vm", "attested_vm_hw"; threshold "multisig", "frost", "frost_dkg", "mpc".
	Level string
	// Vendor is the vendor or root id, for example "amd-sev-snp".
	Vendor string
	// AwaitingAudit marks crypto awaiting audit (not production): FROST, DKG, MPC.
	AwaitingAudit bool
	// Ceremony ("single-party" or "multi-party") tells how a SNARK verifying key was set up.
	Ceremony string
}

// AssuranceLabeler is implemented by a verifier, hook or backend that declares its assurance label.
type AssuranceLabeler interface {
	Assurance() AssuranceLabel
}

// Labeled attaches a label to any hook value (see WithAssuranceLabel).
type Labeled[T any] struct {
	Hook  T
	Label AssuranceLabel
}

// Assurance implements AssuranceLabeler.
func (l Labeled[T]) Assurance() AssuranceLabel { return l.Label }

// WithAssuranceLabel labels hook so a requirement can be met by it.
func WithAssuranceLabel[T any](hook T, label AssuranceLabel) Labeled[T] {
	return Labeled[T]{Hook: hook, Label: label}
}

// Assurance implements AssuranceLabeler: a vendor attestation verifier is hardware evidence of its vendor.
func (v *VendorVerifier) Assurance() AssuranceLabel {
	return AssuranceLabel{Level: "hardware", Vendor: v.vendor}
}

func labelOf(hook any) (AssuranceLabel, bool) {
	if l, ok := hook.(AssuranceLabeler); ok && l != nil {
		return l.Assurance(), true
	}
	return AssuranceLabel{}, false
}

// CheckAssurance is one check in the report.
type CheckAssurance struct {
	// Outcome is the check's status: pass, fail, not-enforced or unsupported.
	Outcome string
	// Level, Vendor, AwaitingAudit and Ceremony: present only on a pass that rests on labelled evidence ("" / false: absent).
	Level    string
	Vendor   string
	AwaitingAudit  bool
	Ceremony string
	// Suites: the signature suites involved (leaf, or root + hops). nil: absent.
	Suites []string
	// T is the threshold the hook enforced (nil: absent).
	T *float64
	// Reason says why the outcome is unsupported, or why a passing check is degraded.
	Reason string
	// Degraded marks a passing check that rests on a compatibility mode; any high-assurance requirement refuses it.
	Degraded bool
}

// ToMap is the JSON form of the entry (the member names of the reference report).
func (c CheckAssurance) ToMap() map[string]any {
	m := map[string]any{"outcome": c.Outcome}
	if c.Level != "" {
		m["level"] = c.Level
	}
	if c.Vendor != "" {
		m["vendor"] = c.Vendor
	}
	if c.AwaitingAudit {
		m["awaiting_audit"] = true
	}
	if c.Ceremony != "" {
		m["ceremony"] = c.Ceremony
	}
	if c.Suites != nil {
		s := make([]any, len(c.Suites))
		for i, x := range c.Suites {
			s[i] = x
		}
		m["suites"] = s
	}
	if c.T != nil {
		m["t"] = jsNumber(*c.T)
	}
	if c.Reason != "" {
		m["reason"] = c.Reason
	}
	if c.Degraded {
		m["degraded"] = true
	}
	return m
}

// AssuranceReport is the per-check report, in the order the checks were decided.
type AssuranceReport struct {
	names []string
	by    map[string]CheckAssurance
}

// Names lists the checks in report order.
func (r AssuranceReport) Names() []string { return append([]string(nil), r.names...) }

// Get returns the entry of a check.
func (r AssuranceReport) Get(name string) (CheckAssurance, bool) {
	c, ok := r.by[name]
	return c, ok
}

// Set adds or replaces an entry (a replaced entry keeps its position).
func (r *AssuranceReport) Set(name string, c CheckAssurance) {
	if r.by == nil {
		r.by = map[string]CheckAssurance{}
	}
	if _, has := r.by[name]; !has {
		r.names = append(r.names, name)
	}
	r.by[name] = c
}

// ToMap is the JSON form of the report.
func (r AssuranceReport) ToMap() map[string]any {
	m := make(map[string]any, len(r.names))
	for _, n := range r.names {
		m[n] = r.by[n].ToMap()
	}
	return m
}

// AssuranceReportFromMap reads a report from parsed JSON (members in text order).
func AssuranceReportFromMap(m map[string]any) AssuranceReport {
	var r AssuranceReport
	for _, name := range jsKeys(m) {
		e, _ := m[name].(map[string]any)
		c := CheckAssurance{}
		c.Outcome, _ = e["outcome"].(string)
		c.Level, _ = e["level"].(string)
		c.Vendor, _ = e["vendor"].(string)
		c.AwaitingAudit, _ = e["awaiting_audit"].(bool)
		if pv, _ := e["preview"].(bool); pv { // deprecated input alias, accepted for one release
			c.AwaitingAudit = true
		}
		c.Ceremony, _ = e["ceremony"].(string)
		c.Reason, _ = e["reason"].(string)
		c.Degraded, _ = e["degraded"].(bool)
		if arr, ok := e["suites"].([]any); ok {
			c.Suites = make([]string, len(arr))
			for i, x := range arr {
				c.Suites[i], _ = x.(string)
			}
		}
		if f, ok := jsNum(e["t"]); ok {
			c.T = &f
		}
		r.Set(name, c)
	}
	return r
}

// NamedStatus is one check and its status.
type NamedStatus struct {
	Name   string
	Status string
}

// AssuranceHooks are the verifier's hooks whose labels the report reads (nil: no such hook; a hook that does not
// implement AssuranceLabeler is unlabelled: "unknown").
type AssuranceHooks struct {
	Attestation any
	Zk          any
	Threshold   any
	Revocation  any
}

// AssuranceSources is what the report is built from: the checks (in order), the presented PCActn, the verifier's hooks and
// its PQ policy.
type AssuranceSources struct {
	Checks []NamedStatus
	PCActn map[string]any
	Hooks  AssuranceHooks
	// AttestationHook is the attestation verifier actually used; it wins over Hooks.Attestation.
	AttestationHook any
	// ThresholdT is the t the threshold hook reported.
	ThresholdT *float64
	// AllowUnboundPq reports a post-quantum signature whose key is not bound to a verifier-side source as "unbound_pq".
	AllowUnboundPq bool
	// Degraded names passing checks that rest on a compatibility mode: check name -> why.
	Degraded map[string]string
}

var attRank = map[string]int{"unknown": 0, "software": 1, "hardware": 2, "multi_root": 3}
var zkRank = map[string]int{"unknown": 0, "attested_vm": 1, "attested_vm_hw": 1, "stark": 2, "zkvm": 2, "groth16": 3, "policyvm_snark": 3}
var zkNeed = map[string]int{"attested_vm": 1, "attested_vm_hardware": 1, "proof": 2, "snark": 3}

func isAwaitingAuditScheme(s string) bool { return s == "frost" || s == "frost_dkg" || s == "mpc" }

// SignatureLevel classifies one signature suite (absent or null = Ed25519): "ed25519", "hybrid", "pq", or "unknown" for an
// unregistered suite.
func SignatureLevel(alg any) string {
	if alg == nil {
		return "ed25519"
	}
	s, ok := alg.(string)
	if ok && s == "ed25519" {
		return "ed25519"
	}
	if !ok || !isRegisteredSuite(s) {
		return "unknown"
	}
	if strings.HasPrefix(s, "hybrid-") {
		return "hybrid"
	}
	return "pq"
}

// weakestLevel: the weakest level in a chain: any unknown suite, then any Ed25519-only signer, then any hybrid, else pure PQ.
func weakestLevel(levels []string) string {
	for _, l := range []string{"unknown", "ed25519", "hybrid"} {
		for _, x := range levels {
			if x == l {
				return l
			}
		}
	}
	if len(levels) > 0 {
		return "pq"
	}
	return "unknown"
}

// AttestationRoot is one root of a multi-root attestation policy: its verifier (labelled or not) and whether it is required.
type AttestationRoot struct {
	Verifier any
	Required bool
}

// MultiRootLevel is the attestation level an N-of-M multi-root policy guarantees: the fewest hardware roots any accepted
// subset can contain (all required roots, filled up to threshold with the weakest optional ones). Two or more hardware
// roots is "multi_root", one is "hardware", none is the weakest level among the roots that could make up the quorum.
func MultiRootLevel(roots []AttestationRoot, threshold int) string {
	rank := func(r AttestationRoot) int {
		l, _ := labelOf(r.Verifier)
		return attRank[l.Level] // an unlabelled or unrecognised level ranks 0
	}
	var req, opt []AttestationRoot
	for _, r := range roots {
		if r.Required {
			req = append(req, r)
		} else {
			opt = append(opt, r)
		}
	}
	sort.SliceStable(opt, func(i, j int) bool { return rank(opt[i]) < rank(opt[j]) })
	chosen := append([]AttestationRoot(nil), req...)
	if n := threshold - len(req); n > 0 {
		if n > len(opt) {
			n = len(opt)
		}
		chosen = append(chosen, opt[:n]...)
	}
	hw := 0
	for _, r := range chosen {
		if rank(r) >= attRank["hardware"] {
			hw++
		}
	}
	switch {
	case hw >= 2:
		return "multi_root"
	case hw == 1:
		return "hardware"
	}
	min := math.MaxInt
	for _, r := range chosen {
		if k := rank(r); k < min {
			min = k
		}
	}
	if min >= attRank["software"] { // also the empty quorum: the minimum of nothing is +Infinity
		return "software"
	}
	return "unknown"
}

// BuildAssuranceReport builds the per-check assurance report (pure; never panics on odd input).
func BuildAssuranceReport(src AssuranceSources) AssuranceReport {
	var out AssuranceReport
	p := src.PCActn
	for _, ns := range src.Checks {
		name := ns.Name
		e := CheckAssurance{Outcome: ns.Status}
		if ns.Status == "unsupported" {
			e.Reason = name + " is not implemented by this verifier"
		}
		if ns.Status == "pass" {
			var hook any
			switch name {
			case "attestation":
				if hook = src.AttestationHook; hook == nil {
					hook = src.Hooks.Attestation
				}
			case "zk_compliance":
				hook = src.Hooks.Zk
			case "threshold":
				hook = src.Hooks.Threshold
			case "revocation":
				hook = src.Hooks.Revocation
			}
			label, labelled := labelOf(hook)
			if name == "attestation" || name == "zk_compliance" || (name == "threshold" && hook != nil) {
				e.Level = label.Level
				if !labelled || e.Level == "" {
					e.Level = "unknown"
				}
				e.Vendor = label.Vendor
				if name == "zk_compliance" {
					e.Ceremony = label.Ceremony
				}
				if label.AwaitingAudit || (name == "threshold" && isAwaitingAuditScheme(e.Level)) {
					e.AwaitingAudit = true
				}
				if name == "threshold" && src.ThresholdT != nil {
					t := *src.ThresholdT
					e.T = &t
				}
			} else if labelled {
				e.Level, e.Vendor, e.AwaitingAudit = label.Level, label.Vendor, label.AwaitingAudit
			}
			if name == "leaf_signature" && p != nil {
				alg := p["alg"]
				if alg == nil {
					alg = "ed25519"
				}
				e.Suites = []string{jsValueString(alg)}
				if src.AllowUnboundPq && alg != any("ed25519") {
					e.Level = "unbound_pq"
				} else {
					e.Level = SignatureLevel(alg)
				}
			}
			if chain, ok := p["cap_chain"].([]any); name == "cap_chain" && p != nil && ok {
				levels := make([]string, len(chain))
				e.Suites = make([]string, len(chain))
				unbound := false
				for i, c := range chain {
					cm, _ := c.(map[string]any)
					a := cm["alg"]
					if a == nil {
						a = "ed25519"
					}
					levels[i], e.Suites[i] = SignatureLevel(a), jsValueString(a)
					unbound = unbound || a != any("ed25519")
				}
				if src.AllowUnboundPq && unbound {
					e.Level = "unbound_pq"
				} else {
					e.Level = weakestLevel(levels)
				}
			}
		}
		out.Set(name, e)
	}
	for name, why := range src.Degraded {
		if c, ok := out.Get(name); ok && c.Outcome == "pass" {
			c.Degraded, c.Reason = true, why
			out.Set(name, c)
		}
	}
	// Features this verifier does not implement: reported, never a pass.
	if _, has := p["bond_ref"]; p != nil && has {
		out.Set("bond", CheckAssurance{Outcome: "unsupported", Reason: "bond verification is not implemented by this verifier"})
	}
	return out
}

// AssuranceRequirement is a high-assurance policy. Every listed dimension must be met by a PASSING check; otherwise the
// `assurance` check fails.
type AssuranceRequirement struct {
	// Attestation is the minimum attestation level: "software" < "hardware" < "multi_root".
	Attestation string
	// Zk: "attested_vm" accepts any enforced statement; "attested_vm_hardware" a statement whose prover key is bound to
	// hardware evidence (or any real proof); "proof" a cryptographic proof; "snark" only Groth16 / Policy-VM SNARK.
	Zk string
	// Signature "pq": the leaf signature and every capability in the chain use a hybrid or pure post-quantum suite.
	Signature string
	// Threshold lists the accepted threshold schemes; nil: not required.
	Threshold []string
	// AllowAwaitingAudit accepts passing evidence awaiting audit (FROST, DKG, MPC) outside an explicit Threshold list.
	AllowAwaitingAudit bool
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// UnmetAssurance checks a report against a requirement. It returns the reason of the first unmet dimension (prefixed
// "assurance: "), or "" when every listed dimension is met. Missing, failed, not-enforced, unlabelled, weaker, awaiting-audit,
// degraded and unsupported evidence never meet a requirement.
func UnmetAssurance(report AssuranceReport, req AssuranceRequirement) string {
	for _, name := range report.names {
		if e := report.by[name]; e.Outcome == "unsupported" {
			why := e.Reason
			if why == "" {
				why = "not implemented"
			}
			return fmt.Sprintf("assurance: unsupported: %s (%s); a high-assurance policy never accepts it", name, why)
		}
	}
	for _, name := range report.names {
		if e := report.by[name]; e.Outcome == "pass" && e.Degraded {
			why := e.Reason
			if why == "" {
				why = "degraded"
			}
			return fmt.Sprintf("assurance: %s rests on a degraded compatibility mode (%s); a high-assurance policy never accepts it", name, why)
		}
	}
	need := func(name, what string) (CheckAssurance, string) {
		e, ok := report.by[name]
		if !ok {
			return e, fmt.Sprintf("assurance: %s required but there is no %s evidence", what, name)
		}
		if e.Outcome != "pass" {
			return e, fmt.Sprintf("assurance: %s required but the %s check is %s", what, name, e.Outcome)
		}
		return e, ""
	}
	if req.Attestation != "" {
		e, why := need("attestation", req.Attestation+" attestation")
		if why != "" {
			return why
		}
		want, known := attRank[req.Attestation]
		if !known {
			want = 99
		}
		if attRank[orUnknown(e.Level)] < want {
			return fmt.Sprintf("assurance: %s attestation required but the evidence is %s", req.Attestation, orUnknown(e.Level))
		}
	}
	if req.Zk != "" {
		e, why := need("zk_compliance", fmt.Sprintf("zk compliance (%s)", req.Zk))
		if why != "" {
			return why
		}
		if req.Zk == "attested_vm_hardware" && (e.Level == "attested_vm" || e.Level == "unknown" || e.Level == "") {
			return fmt.Sprintf("assurance: zk compliance (%s) required but the prover key is not bound to hardware evidence", req.Zk)
		}
		floor, known := zkNeed[req.Zk]
		if !known {
			floor = 99
		}
		if zkRank[orUnknown(e.Level)] < floor {
			return fmt.Sprintf("assurance: zk compliance (%s) required but the evidence is %s", req.Zk, orUnknown(e.Level))
		}
	}
	if req.Signature == "pq" {
		for _, name := range []string{"leaf_signature", "cap_chain"} {
			e, why := need(name, "post-quantum signatures")
			if why != "" {
				return why
			}
			if e.Level != "pq" && e.Level != "hybrid" {
				return fmt.Sprintf("assurance: post-quantum signatures required but %s is %s", name, orUnknown(e.Level))
			}
		}
	}
	if req.Threshold != nil {
		list := strings.Join(req.Threshold, " | ")
		e, why := need("threshold", fmt.Sprintf("threshold (%s)", list))
		if why != "" {
			return why
		}
		if e.Level == "" {
			return fmt.Sprintf("assurance: threshold (%s) required but no threshold verifier enforced it", list)
		}
		accepted := false
		for _, s := range req.Threshold {
			accepted = accepted || s == e.Level
		}
		if !accepted {
			return fmt.Sprintf("assurance: threshold (%s) required but the scheme is %s", list, e.Level)
		}
	}
	if !req.AllowAwaitingAudit {
		for _, name := range report.names {
			e := report.by[name]
			if e.Outcome != "pass" || !e.AwaitingAudit {
				continue
			}
			if name == "threshold" && req.Threshold != nil {
				listed := false
				for _, s := range req.Threshold {
					listed = listed || s == e.Level
				}
				if listed {
					continue
				}
			}
			return fmt.Sprintf("assurance: %s rests on crypto awaiting audit (%s); set allowAwaitingAudit or list the scheme to accept it", name, orUnknown(e.Level))
		}
	}
	return ""
}
