package pca

import (
	"errors"
	"fmt"
	"strings"
)

// Policy templates and a fluent authoring builder: the deterministic backbone of "natural language to policy". A request maps onto a
// named ROLE template (read-only, support agent, finance bot, dev assistant) or is composed with the typed builder; both compile
// through CompilePolicy, so what you author is exactly what the verifier enforces. Pure.

// PolicyTemplate is a named role template: permissions (connector to actions), optional limits and risk-policy members.
type PolicyTemplate struct {
	Name        string
	Description string
	// Permissions maps a connector to its action names ([]any of strings), in the order the template lists them.
	Permissions map[string]any
	// Limits are keyed by verb or action; nil when the template sets none.
	Limits map[string]string
	// RiskPolicy holds risk-policy members; nil when the template sets none.
	RiskPolicy map[string]any
}

type policyTemplateRow struct {
	connector string
	actions   []string
}

func policyTemplatePerms(rows ...policyTemplateRow) map[string]any {
	m := make(map[string]any, len(rows))
	keys := make([]string, 0, len(rows))
	for _, r := range rows {
		l := make([]any, len(r.actions))
		for i, a := range r.actions {
			l[i] = a
		}
		m[r.connector] = l
		keys = append(keys, r.connector)
	}
	recordKeyOrder(m, keys)
	return m
}

// PolicyTemplates are the built-in role templates, in order: conservative starting points, meant to be narrowed, not widened.
func PolicyTemplates() []PolicyTemplate {
	return []PolicyTemplate{
		{Name: "read-only", Description: "Read access only — no side effects anywhere.",
			Permissions: policyTemplatePerms(policyTemplateRow{"github", []string{"read"}}, policyTemplateRow{"slack", []string{"read"}},
				policyTemplateRow{"files", []string{"read"}}, policyTemplateRow{"http", []string{"get"}})},
		{Name: "support-agent", Description: "Draft + send customer email and post to Slack, rate-limited.",
			Permissions: policyTemplatePerms(policyTemplateRow{"gmail", []string{"draft", "send"}}, policyTemplateRow{"slack", []string{"post_message"}}),
			Limits:      map[string]string{"send": "50/day", "post_message": "100/day"}},
		{Name: "finance-bot", Description: "Issue reversible refunds within a daily cap; no payouts.",
			Permissions: policyTemplatePerms(policyTemplateRow{"stripe", []string{"refund"}}), Limits: map[string]string{"refund": "$500/day"}},
		{Name: "dev-assistant", Description: "Read repos, open PRs and comment — never merge or delete.",
			Permissions: policyTemplatePerms(policyTemplateRow{"github", []string{"read", "create_pr", "comment"}}), Limits: map[string]string{"create_pr": "20/day"}},
	}
}

// ListTemplates returns the built-in role templates.
func ListTemplates() []PolicyTemplate { return PolicyTemplates() }

func policyTemplateNames() string {
	var n []string
	for _, t := range PolicyTemplates() {
		n = append(n, t.Name)
	}
	return strings.Join(n, ", ")
}

func policyTemplateByName(name string) (PolicyTemplate, bool) {
	for _, t := range PolicyTemplates() {
		if t.Name == name {
			return t, true
		}
	}
	return PolicyTemplate{}, false
}

// FromTemplateOptions are the inputs of FromTemplate; the override members (Permissions, Limits, RiskPolicy, AgentBinding,
// BudgetModel) replace the template's.
type FromTemplateOptions struct {
	Principal    *KeyPair
	Goal         string
	Holder       *KeyPair // generated when nil
	Aud          string
	BudgetModel  string
	Now          int64 // epoch ms of minting; 0: the wall clock
	Permissions  map[string]any
	Limits       map[string]string
	RiskPolicy   map[string]any
	AgentBinding map[string]any
}

// FromTemplate mints an agent from a named template. It errors on an unknown template.
func FromTemplate(name string, o FromTemplateOptions) (*FacadeAgent, error) {
	t, ok := policyTemplateByName(name)
	if !ok {
		return nil, fmt.Errorf("fromTemplate: unknown template '%s' (have: %s)", name, policyTemplateNames())
	}
	perms := o.Permissions
	if perms == nil {
		perms = t.Permissions
	}
	limits := o.Limits
	if limits == nil {
		limits = t.Limits
	}
	risk := o.RiskPolicy
	if risk == nil {
		risk = t.RiskPolicy
	}
	return CreateAgent(AgentOptions{Principal: o.Principal, Goal: o.Goal, Permissions: perms, Limits: limits, Holder: o.Holder,
		AgentBinding: o.AgentBinding, RiskPolicy: risk, BudgetModel: o.BudgetModel, Aud: o.Aud, Now: o.Now})
}

// BuiltPolicy is the output of PolicyBuilder.Build: permissions, limits and an optional risk-policy override.
type BuiltPolicy struct {
	Permissions map[string]any
	Limits      map[string]string
	RiskPolicy  map[string]any // nil when none was set
}

// PolicyBuilder is a typed, chainable policy builder: NewPolicyBuilder().Allow("stripe", []string{"refund"}).Limit("refund", "$500/day").
type PolicyBuilder struct {
	order    []string
	perms    map[string][]string
	limits   map[string]string
	riskOver map[string]any
}

// NewPolicyBuilder starts an empty builder (the TypeScript `policy()`).
func NewPolicyBuilder() *PolicyBuilder {
	return &PolicyBuilder{perms: map[string][]string{}, limits: map[string]string{}}
}

// PolicyBuilderFrom starts a builder from a named template (its permissions, limits and risk seed the builder).
func PolicyBuilderFrom(name string) (*PolicyBuilder, error) {
	t, ok := policyTemplateByName(name)
	if !ok {
		return nil, fmt.Errorf("PolicyBuilder.from: unknown template '%s'", name)
	}
	b := NewPolicyBuilder()
	for _, c := range jsKeys(t.Permissions) {
		var acts []string
		for _, a := range t.Permissions[c].([]any) {
			acts = append(acts, a.(string))
		}
		b.Allow(c, acts)
	}
	for k, v := range t.Limits {
		b.Limit(k, v)
	}
	if t.RiskPolicy != nil {
		b.Risk(t.RiskPolicy)
	}
	return b, nil
}

// Allow allows actions on a connector (the union with what was allowed before, first-seen order).
func (b *PolicyBuilder) Allow(connector string, actions []string) *PolicyBuilder {
	cur, seen := b.perms[connector]
	if !seen {
		b.order = append(b.order, connector)
	}
	have := map[string]bool{}
	for _, a := range cur {
		have[a] = true
	}
	for _, a := range actions {
		if !have[a] {
			have[a] = true
			cur = append(cur, a)
		}
	}
	b.perms[connector] = cur
	return b
}

// Limit sets the limit of a verb or action ("$500/day", "10/hour").
func (b *PolicyBuilder) Limit(verbOrAction, spec string) *PolicyBuilder {
	b.limits[verbOrAction] = spec
	return b
}

// Risk merges risk-policy members over the earlier ones.
func (b *PolicyBuilder) Risk(partial map[string]any) *PolicyBuilder {
	m := map[string]any{}
	for k, v := range b.riskOver {
		m[k] = v
	}
	for k, v := range partial {
		m[k] = v
	}
	b.riskOver = m
	return b
}

// Build returns the built policy (a deep copy). It errors when no permission was added.
func (b *PolicyBuilder) Build() (*BuiltPolicy, error) {
	if len(b.perms) == 0 {
		return nil, errors.New("PolicyBuilder: no permissions added")
	}
	p := make(map[string]any, len(b.perms))
	for _, c := range b.order {
		l := make([]any, len(b.perms[c]))
		for i, a := range b.perms[c] {
			l[i] = a
		}
		p[c] = l
	}
	recordKeyOrder(p, append([]string(nil), b.order...))
	lim := make(map[string]string, len(b.limits))
	for k, v := range b.limits {
		lim[k] = v
	}
	var risk map[string]any
	if b.riskOver != nil {
		risk = make(map[string]any, len(b.riskOver))
		for k, v := range b.riskOver {
			risk[k] = v
		}
	}
	return &BuiltPolicy{Permissions: p, Limits: lim, RiskPolicy: risk}, nil
}

// Agent mints an agent directly from the built policy (aud, holder and now are optional: "", nil, 0).
func (b *PolicyBuilder) Agent(principal *KeyPair, goal, aud string, holder *KeyPair, now int64) (*FacadeAgent, error) {
	p, err := b.Build()
	if err != nil {
		return nil, err
	}
	return CreateAgent(AgentOptions{Principal: principal, Goal: goal, Permissions: p.Permissions, Limits: p.Limits, RiskPolicy: p.RiskPolicy,
		Aud: aud, Holder: holder, Now: now})
}
