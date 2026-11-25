package pcasigstore

// The artifact attestation verifier: Sigstore provenance joined to runtime attestation, issued as a discharge. The verifier that
// holds the artifact-class key runs, for one discharge request: (1) the bundle against the pinned trust roots (offline),
// (2) the join with the digest of the image that is actually running (from an EAT it already accepted, never a digest the caller
// states), (3) the provenance gate over the verifier's own pins, (4) it signs the discharge the request asks for with the gate's
// claims. Any failure returns no discharge, so the caveat refuses: provenance can only remove authority.

import (
	"errors"
	"math"

	pca "github.com/Atlas-Authorization/pca-go"
)

// ArtifactDischargeInput is one discharge request to the artifact verifier.
type ArtifactDischargeInput struct {
	// Bundle is the Sigstore bundle JSON and Roots the pinned trust roots.
	Bundle []byte
	Roots  *PinnedRoots
	// Policy is the verifier's provenance policy (pca.ProvenanceGate).
	Policy any
	// Runtime is the running image's digest {alg, digest} from pca.EatRuntimeDigestFromEat. RuntimeSet false omits the join (only
	// when the policy does not require it); RuntimeSet true with a nil Runtime is a failed join (an EAT that yielded no digest).
	Runtime    map[string]any
	RuntimeSet bool
	// Request is the discharge request: caveat_id, issuer, cap_hash, bind, action_digest, ttl_ms.
	Request map[string]any
	// Now is the verifier clock, epoch milliseconds.
	Now int64
	// Issuer is the artifact-class issuer key; Suite its signature suite (nil: ed25519).
	Issuer *pca.KeyPair
	Suite  *pca.SuiteOpts
	// TtlMs is the discharge lifetime, at most the request's ttl_ms; nil means the request's.
	TtlMs *int64
	// Nonce is the discharge nonce; empty means a random one.
	Nonce string
}

// ArtifactDischargeResult is {OK, Discharge, Facts, Level} or {Stage ("sigstore" or "gate"), Code, Detail}.
type ArtifactDischargeResult struct {
	OK        bool
	Discharge map[string]any
	Facts     map[string]any
	Level     int64
	Stage     string
	Code      string
	Detail    string
}

// IssueArtifactDischarge runs the four steps and signs the discharge. A malformed signing input is an error.
func IssueArtifactDischarge(i ArtifactDischargeInput) (*ArtifactDischargeResult, error) {
	v := VerifySigstoreBundle(i.Bundle, i.Roots)
	if !v.OK {
		return &ArtifactDischargeResult{Stage: "sigstore", Code: v.Code, Detail: v.Detail}, nil
	}
	// an EAT that yielded no digest is not "no runtime": it is a failed join
	if i.RuntimeSet && i.Runtime == nil {
		return &ArtifactDischargeResult{Stage: "gate", Code: "no_runtime"}, nil
	}
	in := map[string]any{"facts": v.Facts, "policy": i.Policy, "now": math.Floor(float64(i.Now) / 1000)}
	if i.RuntimeSet {
		in["runtime"] = i.Runtime
	}
	gate := pca.ProvenanceGate(in)
	if !gate.OK {
		return &ArtifactDischargeResult{Stage: "gate", Code: gate.Code}, nil
	}
	req := i.Request
	var ttl int64
	reqTtl, hasReqTtl := req["ttl_ms"].(float64)
	if n, ok := req["ttl_ms"].(interface{ Float64() (float64, error) }); ok {
		reqTtl, _ = n.Float64()
		hasReqTtl = true
	}
	if i.TtlMs != nil {
		ttl = *i.TtlMs
	} else if hasReqTtl {
		ttl = int64(reqTtl)
	}
	if hasReqTtl && float64(ttl) > reqTtl {
		return nil, errors.New("provenanceDischargeBody: ttl_ms exceeds what the caveat accepts")
	}
	str := func(k string) string { s, _ := req[k].(string); return s }
	d, err := pca.SignDischarge(i.Issuer, pca.DischargeInput{
		CaveatID: str("caveat_id"), IssuerLabel: str("issuer"), CapHash: str("cap_hash"), Bind: str("bind"), ActionDigest: str("action_digest"),
		Claims: gate.Claims, Iat: i.Now, NotAfter: i.Now + ttl, Nonce: i.Nonce,
	}, i.Suite)
	if err != nil {
		return nil, err
	}
	return &ArtifactDischargeResult{OK: true, Discharge: d, Facts: v.Facts, Level: gate.Level}, nil
}
