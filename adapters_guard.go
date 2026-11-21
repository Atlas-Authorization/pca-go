package pca

import "fmt"

// PcaDenied is returned by AdapterGuard when the agent's local dry run rejects a call before dispatch.
type PcaDenied struct{ Reason, Verb, Resource string }

func (e *PcaDenied) Error() string {
	return fmt.Sprintf("PCA denied %s on %s: %s", e.Verb, e.Resource, e.Reason)
}

// AdapterGuardSpec is how AdapterGuard binds a tool to a PCA verb. Resource derives the call's resource from its params (so each
// call binds its own target). Aud overrides the agent's audience. NoFailFast lets dispatch proceed on a failing local dry run, so
// the resource server is the only gate (useful when the client cannot fully evaluate policy).
type AdapterGuardSpec struct {
	Verb       string
	Resource   func(params map[string]any) string
	Aud        string
	NoFailFast bool
}

// AdapterGuardOptions are the per-call overrides of a guarded tool.
type AdapterGuardOptions struct {
	Counter *int64
	Now     int64
}

// AdapterGuard wraps a tool run(params, pca) so every invocation first builds a PCActn through agent.Act, fast-fails on the local
// dry run (a *PcaDenied before dispatch) unless NoFailFast, then dispatches with the proof attached. What the tool returns enters
// the model's context and is recorded as untrusted from there on.
func AdapterGuard[R any](agent *FacadeAgent, spec AdapterGuardSpec, run func(params map[string]any, pca *PcaCall) (R, error)) func(params map[string]any, o *AdapterGuardOptions) (R, error) {
	return func(params map[string]any, o *AdapterGuardOptions) (R, error) {
		var zero R
		resource := ""
		if spec.Resource != nil {
			resource = spec.Resource(params)
		}
		ao := &ActOptions{Aud: spec.Aud}
		if o != nil {
			ao.Counter, ao.Now = o.Counter, o.Now
		}
		res, err := agent.Act(spec.Verb, resource, params, ao)
		if err != nil {
			return zero, err
		}
		if !spec.NoFailFast && !res.DryRun.Allowed {
			reason := res.DryRun.Reason
			if reason == "" {
				reason = "denied"
			}
			return zero, &PcaDenied{Reason: reason, Verb: spec.Verb, Resource: resource}
		}
		out, err := run(params, &PcaCall{Encoded: res.Encoded, PCActn: res.PCActn, Headers: res.Headers, Provenance: res.Provenance})
		if err != nil {
			return zero, err
		}
		if err := AdapterRecordToolResult(agent.Provenance, spec.Verb, out); err != nil {
			return zero, err
		}
		return out, nil
	}
}

// AdapterProvenanceFrom is a provenance bundle from wherever a framework carried it: the bundle object itself, its JSON text, or a
// PCA-Provenance header value (base64url JSON). Nil for anything else (the gate then treats the call as unlabelled: fail closed).
func AdapterProvenanceFrom(v any) any { return OAProvenanceFrom(v) }

// RevokeMessage is the domain-separated bytes a PRINCIPAL signs to revoke a capability under their own grant.
func RevokeMessage(grantRef, revokedCapID string) ([]byte, error) {
	body, err := canonBytes(map[string]any{"grant_ref": grantRef, "revoked_cap_id": revokedCapID})
	if err != nil {
		return nil, err
	}
	return append([]byte("atlas-pca/revoke/v1\x00"), body...), nil
}
