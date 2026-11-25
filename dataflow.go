package pca

// The capability-tagged, positive data-flow model (CaMeL, arXiv:2503.18813): every value carries the provenance it was
// derived from and the sinks it may reach; a policy over provenance decides every flow to a sink. The guarantee is
// conditional on correct tagging at the boundaries (FromTrustedQuery / FromToolOutput): this is a capability model, not a
// detector. Pure and deterministic. A *Tagged is minted only by this package's constructors: a zero or hand-built
// Tagged carries no provenance and never flows.

import (
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
)

// TrustedQuery is the provenance of the genuine user query, the one source control flow may derive from.
const TrustedQuery = "trusted-query"

// ToolProvenance is the provenance tag of a named tool / retrieval output (always untrusted).
func ToolProvenance(name string) string { return "tool:" + name }

// Capability is a value's data-flow label: its lineage (ordered, distinct sources), whether every source is trusted, and an
// optional allow-list of sink ids. Immutable: read it through the accessors.
type Capability struct {
	sources    []string
	trusted    bool
	readers    []string
	restricted bool
}

// Sources returns a copy of the provenance set in insertion order.
func (c Capability) Sources() []string { return append([]string{}, c.sources...) }

// IsTrusted is true only when every contributing source is trusted.
func (c Capability) IsTrusted() bool { return c.trusted }

// Readers returns a copy of the sink allow-list; ok is false when the value does not restrict its readers.
func (c Capability) Readers() (readers []string, ok bool) {
	if !c.restricted {
		return nil, false
	}
	return append([]string{}, c.readers...), true
}

// MarshalJSON writes {sources, isTrusted, readers?} with both sets in insertion order.
func (c Capability) MarshalJSON() ([]byte, error) {
	m := map[string]any{"sources": nonNilStrs(c.sources), "isTrusted": c.trusted}
	if c.restricted {
		m["readers"] = nonNilStrs(c.readers)
	}
	return json.Marshal(m)
}

// NewCapability builds a capability from sources (duplicates dropped, first occurrence kept) and readers: nil readers is
// unrestricted, a non-nil (even empty) slice restricts the value to exactly those sink ids.
func NewCapability(sources []string, isTrusted bool, readers []string) Capability {
	c := Capability{sources: distinct(sources), trusted: isTrusted, restricted: readers != nil}
	if readers != nil {
		c.readers = distinct(readers)
	}
	return c
}

func distinct(xs []string) []string {
	out := make([]string, 0, len(xs))
	seen := make(map[string]bool, len(xs))
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func nonNilStrs(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}

func jsSortStrings(xs []string) []string {
	out := append([]string{}, xs...)
	sort.SliceStable(out, func(i, j int) bool { return compareUnits(utf16Units(out[i]), utf16Units(out[j])) < 0 })
	return out
}

// Tagged is a value carrying its capability. Only this package mints one.
type Tagged struct {
	value  any
	cap    Capability
	minted bool
	absent bool
}

// AbsentArg marks an optional action argument that was not supplied: CheckAction skips it. A nil entry, by contrast, is an
// argument nobody tagged and refuses.
var AbsentArg = &Tagged{absent: true}

// Value is the carried value.
func (t *Tagged) Value() any { return t.value }

// Cap is the carried capability.
func (t *Tagged) Cap() Capability { return t.cap }

// MarshalJSON writes {value, cap}.
func (t *Tagged) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{"value": t.value, "cap": t.cap})
}

// IsTagged is true only for a value minted by Tag, FromTrustedQuery, FromToolOutput, FromSource or Derive.
func IsTagged(t *Tagged) bool { return t != nil && t.minted }

func mintTagged(v any, c Capability) *Tagged { return &Tagged{value: v, cap: c, minted: true} }

// Tag attaches an explicit capability (escape hatch; prefer the boundary constructors). A trusted capability needs at least
// one source and no tool: source.
func Tag(value any, c Capability) (*Tagged, error) {
	if c.trusted {
		if len(c.sources) == 0 {
			return nil, errors.New("tag: a trusted capability needs at least one source")
		}
		for _, s := range c.sources {
			if strings.HasPrefix(s, "tool:") {
				return nil, errors.New("tag: tool output can never be trusted")
			}
		}
	}
	return mintTagged(value, NewCapability(c.sources, c.trusted, readersOrNil(c))), nil
}

func readersOrNil(c Capability) []string {
	if !c.restricted {
		return nil
	}
	return nonNilStrs(c.readers)
}

// FromTrustedQuery tags the genuine user query (a boundary assertion). readers: nil = unrestricted.
func FromTrustedQuery(value any, readers []string) *Tagged {
	t, _ := Tag(value, NewCapability([]string{TrustedQuery}, true, readers))
	return t
}

// FromToolOutput tags a named tool's output: always untrusted.
func FromToolOutput(name string, value any, readers []string) *Tagged {
	t, _ := Tag(value, NewCapability([]string{ToolProvenance(name)}, false, readers))
	return t
}

// FromSource tags a value from a named source, untrusted unless isTrusted (a tool: source can never be trusted).
func FromSource(source string, value any, isTrusted bool, readers []string) (*Tagged, error) {
	return Tag(value, NewCapability([]string{source}, isTrusted, readers))
}

// UnionSources is the union of the sources of caps, in first-seen order.
func UnionSources(caps []Capability) []string {
	var all []string
	for _, c := range caps {
		all = append(all, c.sources...)
	}
	return distinct(all)
}

// CombineCaps: sources = union, trusted = AND over a non-empty list (empty is untrusted), readers = intersection of the
// inputs that restrict them.
func CombineCaps(caps []Capability) Capability {
	trusted := len(caps) > 0
	var readers []string
	restricted := false
	for _, c := range caps {
		trusted = trusted && c.trusted
		if !c.restricted {
			continue
		}
		if !restricted {
			readers, restricted = append([]string{}, c.readers...), true
			continue
		}
		next := []string{}
		for _, id := range readers {
			if containsStr(c.readers, id) {
				next = append(next, id)
			}
		}
		readers = next
	}
	if restricted {
		readers = nonNilStrs(readers)
	}
	return NewCapability(UnionSources(caps), trusted, readers)
}

// Derive computes a new value from tagged inputs; its capability is CombineCaps over theirs, so trust can only be lost.
func Derive(inputs []*Tagged, combine func(values ...any) (any, error)) (*Tagged, error) {
	vals := make([]any, len(inputs))
	caps := make([]Capability, len(inputs))
	for i, t := range inputs {
		if !IsTagged(t) {
			return nil, errors.New("derive: every input must be a tagged value made by this module")
		}
		vals[i], caps[i] = t.value, t.cap
	}
	v, err := combine(vals...)
	if err != nil {
		return nil, err
	}
	return mintTagged(v, CombineCaps(caps)), nil
}

// FlowPolicy is what a sink accepts. Nil source lists are absent; a non-nil empty AllowedSources admits no source.
type FlowPolicy struct {
	External       bool     `json:"external,omitempty"`
	RequireTrusted bool     `json:"requireTrusted,omitempty"`
	AllowedSources []string `json:"allowedSources,omitempty"`
	DeniedSources  []string `json:"deniedSources,omitempty"`
}

// Sink is where a value leaves the trusted interior. A nil Accepts is not a valid sink.
type Sink struct {
	ID      string      `json:"id"`
	Accepts *FlowPolicy `json:"accepts"`
}

// FlowDecision is one value-to-sink decision (allow / step_up / deny) with the responsible provenance path.
type FlowDecision struct {
	Outcome string
	Reason  string
	// Path is nil on allow; otherwise the offending sources (possibly empty).
	Path []string
}

// MarshalJSON writes {outcome, reason?, path?}.
func (d FlowDecision) MarshalJSON() ([]byte, error) {
	m := map[string]any{"outcome": d.Outcome}
	if d.Reason != "" {
		m["reason"] = d.Reason
	}
	if d.Path != nil {
		m["path"] = d.Path
	}
	return json.Marshal(m)
}

func sortedSources(c Capability) []string { return jsSortStrings(c.sources) }

// ClassifyFlow decides one flow from the capability and the sink policy alone: value readers, denied sources, allowed
// sources, external exfiltration (deny), sensitive sink (step_up). An untagged value or an invalid sink is a deny.
func ClassifyFlow(value *Tagged, sink *Sink) FlowDecision {
	if !IsTagged(value) {
		return FlowDecision{Outcome: "deny", Reason: "value carries no provenance tag made by this module (fail closed)", Path: []string{}}
	}
	if sink == nil || sink.ID == "" || sink.Accepts == nil {
		return FlowDecision{Outcome: "deny", Reason: "the sink is not a valid sink (fail closed)", Path: sortedSources(value.cap)}
	}
	c, p := value.cap, sink.Accepts
	if c.restricted && !containsStr(c.readers, sink.ID) {
		rs := strings.Join(jsSortStrings(c.readers), ", ")
		if rs == "" {
			rs = "∅"
		}
		return FlowDecision{Outcome: "deny", Reason: "value's readers capability [" + rs + "] does not include sink '" + sink.ID + "'", Path: sortedSources(c)}
	}
	if p.DeniedSources != nil {
		bad := []string{}
		for _, s := range sortedSources(c) {
			if containsStr(p.DeniedSources, s) {
				bad = append(bad, s)
			}
		}
		if len(bad) > 0 {
			return FlowDecision{Outcome: "deny", Reason: "provenance [" + strings.Join(bad, ", ") + "] is forbidden at sink '" + sink.ID + "'", Path: bad}
		}
	}
	if p.AllowedSources != nil {
		bad := []string{}
		for _, s := range sortedSources(c) {
			if !containsStr(p.AllowedSources, s) {
				bad = append(bad, s)
			}
		}
		if len(bad) > 0 {
			return FlowDecision{Outcome: "deny", Reason: "provenance [" + strings.Join(bad, ", ") + "] is not in the allow-list of sink '" + sink.ID + "'", Path: bad}
		}
	}
	src := strings.Join(sortedSources(c), ", ")
	if p.External && !c.trusted {
		return FlowDecision{Outcome: "deny", Reason: "untrusted value (provenance [" + src + "]) may not flow to external-send sink '" + sink.ID + "' — exfiltration / prompt-injection path", Path: sortedSources(c)}
	}
	if p.RequireTrusted && !c.trusted {
		return FlowDecision{Outcome: "step_up", Reason: "sink '" + sink.ID + "' requires trusted provenance; value provenance [" + src + "] is untrusted — needs human review", Path: sortedSources(c)}
	}
	return FlowDecision{Outcome: "allow"}
}

// CanFlowResult is CanFlow's verdict: OK only for a clean allow.
type CanFlowResult struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

// CanFlow is ClassifyFlow as a boolean (a step_up is not ok without a human).
func CanFlow(value *Tagged, sink *Sink) CanFlowResult {
	d := ClassifyFlow(value, sink)
	return CanFlowResult{OK: d.Outcome == "allow", Reason: d.Reason}
}

// PcaStyleAction is the verb + resource of a PCActn action.
type PcaStyleAction struct {
	Verb     string `json:"verb"`
	Resource string `json:"resource"`
}

// FlowGovernor resolves the sink an action dispatches to.
type FlowGovernor interface {
	SinkFor(action PcaStyleAction) (*Sink, error)
}

// ActionDecision is the worst flow outcome over an action's arguments, with the offending argument and its path.
type ActionDecision struct {
	Outcome string
	Sink    string
	Reason  string
	Arg     *int
	Path    []string
}

// MarshalJSON writes {outcome, sink, reason?, arg?, path?}.
func (d ActionDecision) MarshalJSON() ([]byte, error) {
	m := map[string]any{"outcome": d.Outcome, "sink": d.Sink}
	if d.Reason != "" {
		m["reason"] = d.Reason
	}
	if d.Arg != nil {
		m["arg"] = *d.Arg
	}
	if d.Path != nil {
		m["path"] = d.Path
	}
	return json.Marshal(m)
}

var flowSeverity = map[string]int{"allow": 0, "step_up": 1, "deny": 2}

// CheckAction gates an action by data flow: every argument is classified against the action's sink and the worst outcome
// wins. A nil argument was never tagged (deny); AbsentArg is skipped. expectedArgs, when non-nil, must equal len(args).
func CheckAction(action PcaStyleAction, args []*Tagged, gov FlowGovernor, expectedArgs *int) ActionDecision {
	if gov == nil {
		return ActionDecision{Outcome: "deny", Sink: "(unresolved)", Reason: "the sink for this action could not be resolved (fail closed)"}
	}
	sink, err := safeSinkFor(gov, action)
	if err != nil {
		return ActionDecision{Outcome: "deny", Sink: "(unresolved)", Reason: "the sink for this action could not be resolved (fail closed)"}
	}
	if sink == nil || sink.ID == "" {
		return ActionDecision{Outcome: "deny", Sink: "(unresolved)", Reason: "the sink for this action is not a valid sink (fail closed)"}
	}
	if expectedArgs != nil && len(args) != *expectedArgs {
		return ActionDecision{Outcome: "deny", Sink: sink.ID, Reason: "expected " + strconv.Itoa(*expectedArgs) + " tagged argument(s), got " + strconv.Itoa(len(args)) + " (fail closed)"}
	}
	worst := ActionDecision{Outcome: "allow", Sink: sink.ID}
	for i, a := range args {
		i := i
		if a == AbsentArg {
			continue
		}
		if a == nil {
			return ActionDecision{Outcome: "deny", Sink: sink.ID, Arg: &i, Reason: "an argument was not tagged (fail closed)"}
		}
		d := ClassifyFlow(a, sink)
		if flowSeverity[d.Outcome] > flowSeverity[worst.Outcome] {
			worst = ActionDecision{Outcome: d.Outcome, Sink: sink.ID, Arg: &i, Reason: d.Reason, Path: d.Path}
		}
	}
	return worst
}

// safeSinkFor turns a governor panic into a resolution failure (the reference catches any throw).
func safeSinkFor(gov FlowGovernor, action PcaStyleAction) (s *Sink, err error) {
	defer func() {
		if r := recover(); r != nil {
			s, err = nil, errors.New("governor panicked")
		}
	}()
	return gov.SinkFor(action)
}

// DualContext runs the privileged planner on the TRUSTED query value only, then the quarantined handler on the plan; the
// handler must return a tagged value. Refuses an untagged or untrusted query.
func DualContext(query *Tagged, plan func(trustedQuery any) (any, error), quarantine func(plan any) (*Tagged, error)) (any, *Tagged, error) {
	if !IsTagged(query) {
		return nil, nil, errors.New("dualContext: the query must be a tagged value made by this module")
	}
	if !query.cap.trusted {
		return nil, nil, errors.New("dualContext: the privileged planner may only run on a TRUSTED query; got provenance [" + strings.Join(sortedSources(query.cap), ", ") + "]")
	}
	p, err := plan(query.value)
	if err != nil {
		return nil, nil, err
	}
	r, err := quarantine(p)
	if err != nil {
		return nil, nil, err
	}
	if !IsTagged(r) {
		return nil, nil, errors.New("dualContext: the quarantined handler must return a tagged value made by this module")
	}
	return p, r, nil
}

// ExternalSendSink is an exfiltrating sink: untrusted values hard-deny.
func ExternalSendSink(id string) *Sink { return &Sink{ID: id, Accepts: &FlowPolicy{External: true}} }

// SensitiveSink is a sensitive internal sink: untrusted values step up.
func SensitiveSink(id string) *Sink { return &Sink{ID: id, Accepts: &FlowPolicy{RequireTrusted: true}} }

// LevelOf is the value's label in the verifier's provenance lattice: trusted, tool (every source a tool: output) or agent
// (anything else, including an untagged value).
func LevelOf(v *Tagged) string {
	if !IsTagged(v) {
		return "agent"
	}
	if v.cap.trusted {
		return "trusted"
	}
	if len(v.cap.sources) == 0 {
		return "agent"
	}
	for _, s := range v.cap.sources {
		if !strings.HasPrefix(s, "tool:") {
			return "agent"
		}
	}
	return "tool"
}
