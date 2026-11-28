package pca

// Built-in action data kept from the migration of the old catalog and ontologies, the release pins of the built-ins, and
// the catalog conversion over a list.

// ActionLegacyCatalogEntry is what the old catalog said about one built-in verb.
type ActionLegacyCatalogEntry struct {
	Reversibility string
	BlastRadius   float64
}

// ActionLegacyCatalog is what the old catalog said per built-in verb (recorded; the old catalog is deprecated).
var ActionLegacyCatalog = map[string]ActionLegacyCatalogEntry{
	"stripe.charge": {"reversible", 0.9}, "stripe.refund": {"rate_limited", 0.9},
	"stripe.payout": {"irreversible", 0.9}, "stripe.create_customer": {"reversible", 0.2},
	"gmail.send": {"irreversible", 0.8}, "gmail.draft": {"reversible", 0.2},
	"gmail.delete": {"irreversible", 0.8}, "github.read": {"reversible", 0.05},
	"github.create_pr": {"reversible", 0.2}, "github.comment": {"reversible", 0.2},
	"github.merge_pr": {"rate_limited", 0.5}, "github.delete_repo": {"irreversible", 0.8},
	"slack.post_message": {"rate_limited", 0.5}, "slack.read": {"reversible", 0.05},
	"calendar.create_event": {"reversible", 0.2}, "calendar.delete_event": {"rate_limited", 0.5},
	"files.read": {"reversible", 0.05}, "files.write": {"rate_limited", 0.5},
	"files.delete": {"irreversible", 0.8}, "http.get": {"reversible", 0.05},
	"http.post": {"rate_limited", 0.5},
}

// ActionLegacyOntologyEffect is what the old payments ontology said (effect class) for the verbs that exist in both models.
var ActionLegacyOntologyEffect = map[string]string{
	"stripe.refund": "irreversible", "stripe.charge": "irreversible", "stripe.payout": "irreversible",
}

// ActionResolution is one place the old models disagreed and how it was settled.
type ActionResolution struct{ Verb, Field, Was, Now, Reason string }

// ActionResolutions lists every place the old models disagreed and how it was settled (the stricter class wins).
var ActionResolutions = []ActionResolution{
	{"stripe.refund", "reversibility", "catalog rate_limited / ontology irreversible", "irreversible", "the stricter class; a refund cannot be taken back"},
	{"stripe.charge", "reversibility", "catalog reversible / ontology irreversible", "irreversible", "the stricter class; a refund is a new payment, not an undo"},
	{"stripe.charge", "name", "catalog stripe.charge / ontology charge_customer", "stripe.charge (aliases charge_customer, bill)", "one verb, the ontology id becomes an alias"},
	{"stripe.refund", "name", "catalog stripe.refund / ontology refund", "stripe.refund (aliases refund, issue_refund, reimburse, refund_charge)", "one verb, the ontology ids become aliases"},
	{"stripe.payout", "name", "catalog stripe.payout / ontology payout", "stripe.payout (aliases payout, pay_out)", "one verb"},
	{"slack.post_message", "reversibility", "catalog rate_limited", "irreversible", "a send carries the external_communication floor (irreversible); the declaration says what the floor makes true"},
	{"github.merge_pr", "reversibility", "catalog rate_limited", "irreversible", "a merge triggers deploys and downstream effects; a revert is a new action, not an undo"},
	{"github.create_pr", "traits", "none (reversible)", "effects create+send, audience resource (irreversible)", "visible to other people; the repository is the audience"},
	{"github.comment", "traits", "none (reversible)", "effects create+send, audience resource (irreversible)", "visible to other people; the repository is the audience"},
	{"calendar.create_event", "traits", "none (reversible)", "effects create+send, attendees recipient param (irreversible)", "it sends invites"},
	{"stripe.create_customer", "reversibility", "catalog reversible", "rate_limited", "the pack has no action that undoes it, and a reversible write must name one"},
	{"*", "blast", "catalog 0.05..0.9 floats", "resource radius + trait floors (ppm)", "one blast model; the money floor is 700000 ppm"},
	{"*", "money", "amountField / semantic money.* / kind money / envelope units / toolCallRisk option", "param role money.amount + unit {money, ccy, exp}", "one definition of money"},
}

// ActionBuiltinRelease is the release pin set and per-verb attestations of the built-ins. Until a release step fills it (Pins
// nil, no attestations) the built-ins are unconfirmed and their effective traits are the top of the registry.
var ActionBuiltinRelease = struct {
	Pins         any
	Attestations map[string]any
}{Pins: nil, Attestations: map[string]any{}}

// ActionBuiltinReleaseCtx is the pins the built-in attestations verify against; nil before the first release signing.
func ActionBuiltinReleaseCtx() any { return ActionBuiltinRelease.Pins }

// ActionReleasedBuiltinDefs returns the defs (default: the built-ins) with their release attestation attached where the
// package carries one; the others are returned unchanged and stay unconfirmed.
func ActionReleasedBuiltinDefs(defs []map[string]any) []map[string]any {
	if defs == nil {
		defs = ActionBuiltinDefs()
	}
	out := make([]map[string]any, len(defs))
	for i, d := range defs {
		verb, _ := d["verb"].(string)
		a, has := ActionBuiltinRelease.Attestations[verb]
		if !has {
			out[i] = d
			continue
		}
		c := make(map[string]any, len(d))
		for k, v := range d {
			c[k] = v
		}
		rv := map[string]any{}
		if old, ok := d["review"].(map[string]any); ok {
			for k, v := range old {
				rv[k] = v
			}
		}
		rv["state"], rv["attestation"] = "confirmed", a
		c["review"] = rv
		out[i] = c
	}
	return out
}

// ActionBuiltinReviewPins is the reviewer pins under which the released built-ins count as confirmed (a signature by the
// pinned release key, nothing else); nil (nothing confirmed) before the first release signing. Pass it as `pins` to
// ActionEffective, ActionTraitsOf and ActionIsConfirmed.
func ActionBuiltinReviewPins() any { return ActionBuiltinRelease.Pins }

// ActionFromCatalog converts old catalog entries (see ActionFromCatalogSpec for the option keys ccy, exp, maxAmount).
func ActionFromCatalog(specs []map[string]any, o map[string]any) []map[string]any {
	out := make([]map[string]any, len(specs))
	for i, s := range specs {
		out[i] = ActionFromCatalogSpec(s, o)
	}
	return out
}
