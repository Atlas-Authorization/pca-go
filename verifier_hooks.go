package pca

// The verifier hooks of the core (the reference's hooks.attestation and hooks.zk): the seams through which an attestation
// verifier and a zk compliance verifier decide their checks. A hook reports whether it enforced and, if so, whether it passed.
//
//   - attestation: an enforced result passes or fails the `attestation` check; one that did not enforce leaves it unreported.
//     Authorize requires the check to pass for a grant whose agent_binding pins the agent.
//   - zk: runs only for a PCActn that carries `zk_compliance`. An enforced result passes or fails the `zk_compliance` check; a
//     carried proof that no hook enforced (no hook, or one that did not enforce) is refused. An unverified proof is never
//     accepted.
//
// The context a hook receives is {pcactn, grant, nowEpoch}. A hook that panics denies.

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// AttestationVerifierHook is the attestation hook of the verifier. *AttestationVerifier (CreateAttestationVerifier) implements it.
type AttestationVerifierHook interface {
	Verify(ctx map[string]any) AttestationHookResult
}

// ZkVerifierHook is the zk compliance hook of the verifier. *ZkVerifier (CreateZkVerifier) implements it.
type ZkVerifierHook interface {
	Verify(ctx map[string]any) ZkHookResult
}

// verifierHookContext is the reference's VerifyContext.
func verifierHookContext(pcactn, grant map[string]any, now int64) map[string]any {
	return map[string]any{"pcactn": pcactn, "grant": grant, "nowEpoch": json.Number(strconv.FormatInt(now, 10))}
}

// hookOutcome folds a hook result: enforced false means the hook decided nothing; otherwise ok, or the reason of the refusal.
func hookOutcome(enforced, ok bool, reason string) (bool, bool, string) {
	if !enforced {
		return false, false, ""
	}
	if !ok && reason == "" {
		reason = "rejected"
	}
	return true, ok, reason
}

// runAttestationHook runs the attestation hook (nil: nothing enforced). A panic is an enforced refusal.
func runAttestationHook(h AttestationVerifierHook, ctx map[string]any) (enforced, ok bool, reason string) {
	if h == nil {
		return false, false, ""
	}
	defer func() {
		if r := recover(); r != nil {
			enforced, ok, reason = true, false, fmt.Sprintf("attestation verification error (fail closed): %v", r)
		}
	}()
	res := h.Verify(ctx)
	return hookOutcome(res.Enforced, res.OK, res.Reason)
}

// runZkHook runs the zk compliance hook (nil: nothing enforced). A panic is an enforced refusal.
func runZkHook(h ZkVerifierHook, ctx map[string]any) (enforced, ok bool, reason string) {
	if h == nil {
		return false, false, ""
	}
	defer func() {
		if r := recover(); r != nil {
			enforced, ok, reason = true, false, fmt.Sprintf("zk verification error (fail closed): %v", r)
		}
	}()
	res := h.Verify(ctx)
	return hookOutcome(res.Enforced, res.OK, res.Reason)
}

// zkComplianceCheck decides the `zk_compliance` check of a PCActn that carries a proof: pass, or the reason it fails.
func zkComplianceCheck(h ZkVerifierHook, ctx map[string]any) (pass bool, why string) {
	enforced, ok, reason := runZkHook(h, ctx)
	if !enforced {
		return false, zkNoVerifierReason
	}
	return ok, reason
}
