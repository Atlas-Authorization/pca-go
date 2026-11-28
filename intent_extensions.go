package pca

// IntentWireExtensionSet is the Intent Layer's wire validators as the full verifier loads them (the reference's
// INTENT_WIRE_EXTENSION). Each validator returns "" when the slot is well formed, else a short reason. This verifier always has
// the intent layer loaded; the values are exported so a caller can run the same checks or compare against the reference.
type IntentWireExtensionSet struct {
	Intent        func(any) string
	IntentSession func(any) string
	FreshAt       func(any) string
}

// IntentWireExtension is the reference's INTENT_WIRE_EXTENSION.
var IntentWireExtension = IntentWireExtensionSet{Intent: ValidateIntentWire, IntentSession: ValidateIntentSessionWire, FreshAt: ValidateFreshAtWire}

// IntentExtensionSet is the full extension set (the reference's FULL_EXTENSIONS / INTENT_EXTENSIONS).
type IntentExtensionSet struct {
	Wire          IntentWireExtensionSet
	IntentBinding func(intent, grant map[string]any, policy *IntentPolicy, session, mapForm string) map[string]any
	IntentV2      func(p, grant map[string]any, ctx *IntentV2Context, now float64) map[string]any
	FreshAt       func(pcactn map[string]any, policy *FreshAtPolicy, now int64) FreshAtCheck
}

// IntentExtensions is the reference's INTENT_EXTENSIONS: the intent layer's wire validators and decision functions.
var IntentExtensions = IntentExtensionSet{Wire: IntentWireExtension, IntentBinding: DecideIntentBinding, IntentV2: DecideIntentV2, FreshAt: DecideFreshAt}
