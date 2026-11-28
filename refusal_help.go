package pca

import "strings"

// ExplainRefusal turns a refusal reason from Authorize / RequirePCA / VerifyPCActnCore into what it means, how to fix it
// and the page that explains it. The reasons themselves are pinned across all ten languages and the conformance vectors,
// so they are never reworded; this maps them (by their leading check name) to guidance instead. An unknown reason returns
// a generic entry that still links the table. It never panics. The table text matches the TypeScript explainRefusal.

// PCADocs is the base of the published PCA docs.
const PCADocs = "https://github.com/Atlas-Authorization/pca/blob/main/docs"

// RefusalHelp is the guidance for one refusal reason.
type RefusalHelp struct {
	// Check is the check that refused (the reason's leading token), or "unknown".
	Check   string
	Meaning string
	Fix     string
	Docs    string
}

const refusalsDoc = PCADocs + "/reference/refusals.md"

const (
	helpAuthorizeMeaning = "The guard was built without a required component, so it refuses every request (fail closed)."
	helpAuthorizeFix     = "Add the component the reason names (audience, resolveGrant, budgetStore, hooks.revocation). protect() fills them with safe defaults."
	helpGrantRefFix      = "Register the principal's grant with the server (its grants list or resolveGrant). The grant comes from your store, never from the request."
	helpWireFix          = "Send the proof exactly as encoded by encodePCActn (header PCA-Action, or body { pcactn })."
)

var refusalTable = []RefusalHelp{
	{"authorize_config", helpAuthorizeMeaning, helpAuthorizeFix, PCADocs + "/guides/resource-server-quickstart.md"},
	{"authorize", helpAuthorizeMeaning, helpAuthorizeFix, PCADocs + "/guides/resource-server-quickstart.md"},
	{"operation", "The signed action is not the operation this route executes (other verb, resource or params).", "Sign the action the route runs, with the same params. If this is a tool server, use one tool-to-action mapping on both sides.", refusalsDoc + "#operation"},
	{"audience", "The proof was signed for a different server.", "Make the agent sign with the same audience string the server is configured with.", refusalsDoc + "#audience"},
	{"replay", "This proof (or an older counter) was already used.", "Each action needs a fresh proof. If this is a retry of an action that already ran, use an operation record instead of resending.", refusalsDoc + "#replay"},
	{"counter_format", "The proof carries no valid anti-replay counter.", "Build the proof with the agent facade (act) or buildPCActn, which set it.", refusalsDoc + "#replay"},
	{"plan_root_authorized", "The plan the action belongs to was not authorized by the principal.", "Use plan: single-step (protect() does) for one-action proofs, or have the principal authorize the committed plan root.", refusalsDoc + "#plan_root_authorized"},
	{"plan_state", "The plan is committed but not executable now (not authorized, expired or revoked).", "Check the plan state named in the reason and re-authorize or recommit.", refusalsDoc + "#plan_root_authorized"},
	{"revocation", "The grant, or the revocation source, refused.", "The grant was revoked, or no revocation source is configured. Configure hooks.revocation (protect() does).", refusalsDoc + "#revocation"},
	{"validity", "The proof is outside its validity window.", "Check clocks on both sides; request a fresh proof.", refusalsDoc + "#validity"},
	{"grant_ref", "The proof does not name a grant this server knows.", helpGrantRefFix, refusalsDoc + "#grant_ref"},
	{"grant_ref_bound", "The proof does not name a grant this server knows.", helpGrantRefFix, refusalsDoc + "#grant_ref"},
	{"policy", "The grant does not permit this action or these parameters (a predicate or limit failed).", "Widen the grant if the action is legitimate (the principal signs a new one); otherwise this is the guard working.", refusalsDoc + "#policy"},
	{"delegated_caveats", "A caveat added by a delegation refused the action.", "The sub-agent was narrowed below this action. Delegate with the caveats you intend.", refusalsDoc + "#policy"},
	{"threshold", "The risk needs a co-signature from the principal (step-up).", "Collect the co-sign through the step-up flow, or lower the risk the server prices.", PCADocs + "/concepts/threshold-and-step-up.md"},
	{"risk_inputs", "A risk input the server must vouch for was not supplied.", "Supply it in the risk option (catalogRisk derives the common ones; protect() uses it).", refusalsDoc + "#risk_inputs"},
	{"chain", "The delegation chain does not verify back to the grant.", "Rebuild the chain with delegate()/subAgent(); do not edit a grant or hop after signing.", refusalsDoc + "#chain"},
	{"leaf_signature", "The proof signature does not verify.", "The proof was altered, or signed by a key that is not the chain leaf.", refusalsDoc + "#chain"},
	{"wire", "The proof is not well-formed under the strict wire profile.", helpWireFix, PCADocs + "/reference/wire-formats.md"},
	{"malformed", "The proof could not be read.", helpWireFix, PCADocs + "/reference/wire-formats.md"},
	{"freshness", "The consistency token or revocation epoch is stale.", "Refresh the token from the guardian and retry.", refusalsDoc + "#freshness"},
	{"provenance_flow", "The action, or an argument of it, derives from content the principal did not write (a tool result, a page, an unpinned or missing provenance bundle), or the bundle is forged or unreadable.", "Present the provenance bundle your pinned mediator recorded (PCA-Provenance header), have the principal confirm the escalation, or run the call from a principal-authorized plan.", PCADocs + "/guides/prompt-injection-provenance.md"},
	{"undo_window", "The action ran under a veto window: the principal can undo it until the window ends.", "Report the effect to your undo coordinator and let the window run.", PCADocs + "/guides/undo-windows.md"},
	{"template", "The grant is not an instantiation of a linked policy template.", "Mint the grant from the template the server requires.", PCADocs + "/guides/policy-analysis.md"},
}

// ExplainRefusal returns the guidance for a refusal reason. Never panics.
func ExplainRefusal(reason string) RefusalHelp {
	n := 0
	for n < len(reason) && (reason[n] == '_' || (reason[n] >= 'a' && reason[n] <= 'z')) {
		n++
	}
	head := reason[:n]
	for _, h := range refusalTable {
		if h.Check == head {
			return h
		}
	}
	for _, h := range refusalTable {
		if strings.Contains(reason, h.Check+":") {
			return h
		}
	}
	return RefusalHelp{"unknown", "The guard refused and the reason is not in the table.", "Read the reason as written; every refusal names the check that failed.", refusalsDoc}
}
