package pca

// Zero-knowledge proof of compliance (intent privacy from the resource server).
//
// The agent proves "action A is a valid derivation under policy P from committed plan Π" without revealing P, Π or its reasoning:
// the resource server learns only "authorized". Two realizations:
//
//   - a Groth16 proof over a compliance circuit (zk_policyvm.go: VerifyPolicyVmProof and the SNARK backends), which removes the
//     trusted party;
//   - the cheaper attested-VM statement of this file: a trusted, attested VM runs the Policy VM (Decide) and signs a statement
//     that it released the action (CreateAttestedComplianceProver). The statement carries only commitments (digests) of the
//     policy and the plan, never their plaintext, but the resource server trusts the prover's key instead of a circuit.
//
// In both modes the verifier (CreateZkVerifier) checks the proof against commitments only, so it can enforce a policy it is not
// allowed to read.

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

const zkStatementDomain = "atlas-pca/zk-compliance/v1\x00"

// ZkProverBindingRef is the grantRef of the binding a prover VM's hardware quote carries (see ProverKeyBinding).
const ZkProverBindingRef = "atlas-pca/zk-prover/v1"

// PolicyCommitment is the commitment to the policy: the grant's content address (its id; the canonical hash of the value when it
// carries none). It binds the whole policy without exposing predicates or caveats.
func PolicyCommitment(grant any) (string, error) {
	if id, ok := zkProp(grant, "id").(string); ok {
		return id, nil
	}
	return HashCanonical(grant)
}

// PinnedPolicyCommitment is the policy commitment a resource server pins when it is not allowed to read the grant's plaintext.
func PinnedPolicyCommitment(grant any) (string, error) { return PolicyCommitment(grant) }

// ActionCommitment is the commitment to the action: the content address of the PCActn's action descriptor (of null when there is
// none).
func ActionCommitment(pcactn any) (string, error) {
	action := zkProp(pcactn, "action")
	if action == zkUndefined {
		action = nil
	}
	return HashCanonical(action)
}

// ProverKeyBinding is the binding a prover VM must put in its hardware quote's report data so that the quote vouches for its key
// (AttestationBindingBytes of the result). A quote taken for another key, epoch or nonce does not bind.
func ProverKeyBinding(proverPublicKey string, epoch float64, nonce string) ExpectedAttestationBinding {
	return ExpectedAttestationBinding{HolderPub: proverPublicKey, GrantRef: ZkProverBindingRef, Epoch: epoch, Nonce: nonce}
}

// zkStatementMessage is what the prover signs: the domain, then the canonical JSON of the statement without its signature.
func zkStatementMessage(body map[string]any) ([]byte, error) {
	b, err := canonBytes(body)
	if err != nil {
		return nil, err
	}
	return append([]byte(zkStatementDomain), b...), nil
}

// zkPlanCommit is the committed plan root of a PCActn ("" when it has none).
func zkPlanCommit(pcactn any) string {
	root, _ := zkProp(zkProp(pcactn, "plan"), "root").(string)
	return root
}

// ZkProveOpts is one statement to prove: the action, the Policy VM input (its grant commits the policy) and the validity window in
// epoch milliseconds.
type ZkProveOpts struct {
	PCActn              map[string]any
	DecideInput         map[string]any
	IssuedAt, ExpiresAt int64
}

// AttestedComplianceProver is the attested-VM prover: the stand-in for a SNARK prover that signs, with the VM's key, that the
// Policy VM released the action.
type AttestedComplianceProver struct {
	// PublicKey is the base64url Ed25519 key a resource server lists in ZkVerifierOpts.TrustedProverKeys.
	PublicKey string
	key       *KeyPair
}

// CreateAttestedComplianceProver builds the prover of a 32-byte Ed25519 secret seed.
func CreateAttestedComplianceProver(attestorSecret []byte) (*AttestedComplianceProver, error) {
	key, err := KeyPairFromSeed(attestorSecret)
	if err != nil {
		return nil, err
	}
	return &AttestedComplianceProver{PublicKey: key.Public, key: key}, nil
}

// Prove runs the Policy VM and, only if it releases the action, returns the signed compliance statement {v, mode, action_commit,
// policy_commit, plan_commit, released, r, issued_at, expires_at, prover, sig}. Only commitments go into it. An action that is not
// compliant is an error: a false statement cannot be proven.
func (p *AttestedComplianceProver) Prove(o ZkProveOpts) (map[string]any, error) {
	decision := Decide(o.DecideInput)
	if released, _ := decision["releaseGuardianShare"].(bool); !released {
		var reasons []string
		if list, ok := decision["reasons"].([]any); ok {
			for _, r := range list {
				reasons = append(reasons, zkString(r))
			}
		}
		return nil, fmt.Errorf("createAttestedComplianceProver: action is not compliant, nothing to prove (%s)", strings.Join(reasons, "; "))
	}
	r, isNum := jsNum(decision["r"])
	if !isNum {
		return nil, errors.New("createAttestedComplianceProver: the decision carries no risk")
	}
	actionCommit, err := ActionCommitment(o.PCActn)
	if err != nil {
		return nil, err
	}
	policyCommit, err := PolicyCommitment(zkOrNull(zkProp(o.DecideInput, "grant")))
	if err != nil {
		return nil, err
	}
	st := map[string]any{
		"v": json.Number("1"), "mode": "attested-vm", "action_commit": actionCommit, "policy_commit": policyCommit,
		"plan_commit": zkPlanCommit(o.PCActn), "released": true, "r": jsNumber(r),
		"issued_at":  json.Number(strconv.FormatInt(o.IssuedAt, 10)),
		"expires_at": json.Number(strconv.FormatInt(o.ExpiresAt, 10)), "prover": p.PublicKey,
	}
	msg, err := zkStatementMessage(st)
	if err != nil {
		return nil, err
	}
	st["sig"] = B64u(p.key.Sign(msg))
	return st, nil
}

func zkOrNull(v any) any {
	if v == zkUndefined {
		return nil
	}
	return v
}

// ZkSnarkInput is what a SNARK backend verifies: the opaque proof carried in the PCActn's zk_compliance member, the three
// commitments as public inputs and the verification context ({pcactn, grant}).
type ZkSnarkInput struct {
	Proof                                  any
	ActionCommit, PolicyCommit, PlanCommit string
	Ctx                                    map[string]any
}

// ZkSnarkBackend verifies a zero-knowledge proof against the public inputs. The library's backends are CreateGroth16SnarkBackend
// and the Policy VM ones; plug one in through ZkVerifierOpts.SnarkBackend. A backend that implements AssuranceLabeler declares its
// proof system (the library's own do; an unlabelled one is reported as "unknown"). An error is a fault, never a verdict: the
// verifier denies on it.
type ZkSnarkBackend interface {
	VerifySnark(in ZkSnarkInput) (bool, error)
}

// ZkSnarkBackendFunc adapts a function to ZkSnarkBackend.
type ZkSnarkBackendFunc func(in ZkSnarkInput) (bool, error)

// VerifySnark implements ZkSnarkBackend.
func (f ZkSnarkBackendFunc) VerifySnark(in ZkSnarkInput) (bool, error) { return f(in) }

// ZkProverAttestationOpts binds the attested-VM prover key to hardware evidence of the VM measurement.
type ZkProverAttestationOpts struct {
	// HardwareVerifier is a vendor verifier (SEV-SNP, TDX, Azure MAA, ...) or a multi-root verifier. It must carry a "hardware" or
	// "multi_root" assurance label: a software or unlabelled verifier is refused at construction. It receives a stub document
	// {attestor: <prover key>, mode: "hardware"}, so its evidence resolver can look up that prover's quote.
	HardwareVerifier AttestationHardwareVerifier
	// ExpectedBinding is the binding the quote must carry for this prover key (server-known epoch and nonce). An error denies.
	ExpectedBinding func(proverPublicKey string) (ExpectedAttestationBinding, error)
	// Measurements is the required, non-empty allowlist of measured runtime measurements (the VM image).
	Measurements []string
}

// ZkVerifierOpts configure CreateZkVerifier.
type ZkVerifierOpts struct {
	// TrustedProverKeys are the base64url keys of the attested prover VMs trusted in attested-VM mode.
	TrustedProverKeys []string
	// PolicyCommitments are the expected policy commitments, as bare hashes: the statement must commit to one of them, and no
	// plaintext policy is read (the intent-privacy path). nil derives the commitment from the context's grant; an empty non-nil
	// list accepts nothing.
	PolicyCommitments []string
	// SnarkBackend, when set, verifies the proof instead of the attested-VM statement checks.
	SnarkBackend ZkSnarkBackend
	// RevokedProverKeys are prover keys no longer trusted (a retired or compromised VM): a statement signed by one is denied even
	// when the key is still listed as trusted.
	RevokedProverKeys []string
	// ProverAttestation, attested-VM mode only, requires hardware evidence that the prover key lives in an attested VM with an
	// allowlisted measurement. nil trusts the key as configured, and the assurance label says so.
	ProverAttestation *ZkProverAttestationOpts
	// Now is the clock in epoch milliseconds (default the wall clock).
	Now func() int64
	// ClockSkewMs is the allowed clock skew for issued_at / expires_at (default 0; a negative or non-finite value is 0).
	ClockSkewMs float64
}

// ZkHookResult is the verdict of the zk compliance hook: always enforced; Reason is set on a denial.
type ZkHookResult struct {
	Enforced, OK bool
	Reason       string
}

// ZkVerifier is the zk compliance hook built by CreateZkVerifier.
type ZkVerifier struct {
	o       ZkVerifierOpts
	label   AssuranceLabel
	trusted map[string]bool
	revoked map[string]bool
	policy  map[string]bool // nil: derive from the grant
	measure map[string]bool
}

func zkSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// CreateZkVerifier builds the hook that checks the compliance proof carried in a PCActn's zk_compliance member. The configuration
// is copied: later edits by the caller do not change what the verifier enforces. The hook binds the proof to this action and the
// committed plan, then:
//
//   - SNARK mode (SnarkBackend set): the backend decides, with the three commitments as public inputs;
//   - attested-VM mode: the statement is well-formed, its prover is trusted and not revoked, its signature verifies, it is fresh
//     and its commitments match (this action, this plan root, an expected policy), and, with ProverAttestation, the prover key is
//     bound to an allowlisted measured VM.
//
// Its assurance label comes from the configuration: the backend's declared system ("unknown" when it declares none),
// "attested_vm_hw" with a hardware-bound prover key, else "attested_vm".
func CreateZkVerifier(opts ZkVerifierOpts) (*ZkVerifier, error) {
	o := opts
	o.TrustedProverKeys = append([]string(nil), opts.TrustedProverKeys...)
	o.RevokedProverKeys = append([]string(nil), opts.RevokedProverKeys...)
	v := &ZkVerifier{trusted: zkSet(o.TrustedProverKeys), revoked: zkSet(o.RevokedProverKeys), label: AssuranceLabel{Level: "attested_vm"}}
	if opts.PolicyCommitments != nil {
		o.PolicyCommitments = append([]string{}, opts.PolicyCommitments...)
		v.policy = zkSet(o.PolicyCommitments)
	}
	if o.SnarkBackend != nil {
		o.ProverAttestation = nil
		if v.label = labelOf(o.SnarkBackend); v.label.Level == "" {
			v.label = AssuranceLabel{Level: "unknown"}
		}
	} else if pa := opts.ProverAttestation; pa != nil {
		hw := labelOf(pa.HardwareVerifier)
		if hw.Level != "hardware" && hw.Level != "multi_root" {
			return nil, errors.New("createZkVerifier: proverAttestation.hardwareVerifier must carry a hardware or multi_root assurance label")
		}
		bad := len(pa.Measurements) == 0
		for _, m := range pa.Measurements {
			bad = bad || m == ""
		}
		if bad {
			return nil, errors.New("createZkVerifier: proverAttestation.measurements must be a non-empty allowlist")
		}
		if pa.ExpectedBinding == nil {
			return nil, errors.New("createZkVerifier: proverAttestation.expectedBinding must be a function")
		}
		c := *pa
		c.Measurements = append([]string(nil), pa.Measurements...)
		o.ProverAttestation, v.measure = &c, zkSet(c.Measurements)
		vendor := hw.Vendor
		if vendor == "" {
			vendor = hw.Level
		}
		v.label = AssuranceLabel{Level: "attested_vm_hw", Vendor: "hardware-bound:" + vendor}
	}
	if o.Now == nil {
		o.Now = func() int64 { return time.Now().UnixMilli() }
	}
	if math.IsNaN(o.ClockSkewMs) || math.IsInf(o.ClockSkewMs, 0) || o.ClockSkewMs < 0 {
		o.ClockSkewMs = 0
	}
	v.o = o
	return v, nil
}

// Assurance implements AssuranceLabeler.
func (v *ZkVerifier) Assurance() AssuranceLabel { return v.label }

const zkFailClosed = "zk verification error (fail closed): "

// Verify runs the hook for one verification context ({pcactn, grant}). It never panics: any fault is a denial.
func (v *ZkVerifier) Verify(ctx map[string]any) (res ZkHookResult) {
	fail := func(reason string) ZkHookResult { return ZkHookResult{Enforced: true, Reason: reason} }
	defer func() {
		if r := recover(); r != nil {
			res = fail(zkFailClosed + fmt.Sprint(r))
		}
	}()
	pcactn := zkProp(ctx, "pcactn")
	proof := zkOrNull(zkProp(pcactn, "zk_compliance"))
	if proof == nil {
		return fail("no zk_compliance proof present")
	}
	actionCommit, err := ActionCommitment(pcactn)
	if err != nil {
		return fail(zkFailClosed + err.Error())
	}
	planCommit := zkPlanCommit(pcactn)
	want := v.policy
	if want == nil {
		c, err := PolicyCommitment(zkOrNull(zkProp(ctx, "grant")))
		if err != nil {
			return fail(zkFailClosed + err.Error())
		}
		want = map[string]bool{c: true}
	}

	// SNARK mode: the proof is opaque; the public inputs are bound to this action and plan, then the backend decides.
	if v.o.SnarkBackend != nil {
		var policyCommit string
		for c := range want { // one pinned commitment, or the one derived from the grant
			policyCommit = c
		}
		if len(want) != 1 {
			if policyCommit, err = PolicyCommitment(zkOrNull(zkProp(ctx, "grant"))); err != nil {
				return fail(zkFailClosed + err.Error())
			}
		}
		ok, err := v.o.SnarkBackend.VerifySnark(ZkSnarkInput{Proof: proof, ActionCommit: actionCommit, PolicyCommit: policyCommit, PlanCommit: planCommit, Ctx: ctx})
		if err != nil {
			return fail(zkFailClosed + err.Error())
		}
		if !ok {
			return fail("snark backend rejected the proof")
		}
		return ZkHookResult{Enforced: true, OK: true}
	}

	// attested-VM mode: the proof is a compliance statement.
	st, _ := proof.(map[string]any)
	if ver, isNum := jsNum(st["v"]); !isNum || ver != 1 || !zkIs(st["mode"], "attested-vm") {
		return fail("unrecognized compliance statement")
	}
	if st["released"] != any(true) {
		return fail("statement does not assert release")
	}
	prover, isStr := st["prover"].(string)
	if !isStr || !v.trusted[prover] {
		return fail("prover key is not trusted")
	}
	if v.revoked[prover] {
		return fail("prover key is revoked")
	}
	sig, isStr := st["sig"].(string)
	if !isStr {
		return fail("compliance statement signature does not verify")
	}
	body := make(map[string]any, len(st))
	for k, x := range st {
		if k != "sig" {
			body[k] = x
		}
	}
	msg, err := zkStatementMessage(body)
	if err != nil {
		return fail(zkFailClosed + err.Error())
	}
	if !verifyB64u(prover, msg, sig) {
		return fail("compliance statement signature does not verify")
	}

	issued, okI := jsNum(st["issued_at"])
	expires, okE := jsNum(st["expires_at"])
	if !okI || !okE || math.IsNaN(issued) || math.IsInf(issued, 0) || math.IsNaN(expires) || math.IsInf(expires, 0) || expires < issued {
		return fail("malformed statement validity window")
	}
	nowMs := v.o.Now()
	if float64(nowMs)+v.o.ClockSkewMs < issued {
		return fail("compliance statement not yet valid")
	}
	if float64(nowMs)-v.o.ClockSkewMs > expires {
		return fail("compliance statement expired")
	}

	// commitment binding: the only policy and plan knowledge the verifier needs is these hashes
	if !zkIs(st["action_commit"], actionCommit) {
		return fail("statement does not bind to this action")
	}
	if !zkIs(st["plan_commit"], planCommit) {
		return fail("statement does not bind to this plan commitment")
	}
	if pc, isStr := st["policy_commit"].(string); !isStr || !want[pc] {
		return fail("statement policy commitment is not an expected policy")
	}

	// hardware binding of the prover key, last (the expensive check): anything but a bound, measured, allowlisted identity denies
	if pa := v.o.ProverAttestation; pa != nil {
		expected, err := pa.ExpectedBinding(prover)
		if err != nil {
			return fail(zkFailClosed + err.Error())
		}
		hw := pa.HardwareVerifier.VerifyHardware(map[string]any{"attestor": prover, "mode": "hardware"}, ctx, nowMs, expected)
		if !hw.OK {
			reason := hw.Reason
			if reason == "" {
				reason = "no reason given"
			}
			return fail("prover hardware evidence invalid: " + reason)
		}
		if !hw.Bound {
			return fail("prover hardware evidence does not bind the prover key")
		}
		measurement, isStr := hw.Measured["runtime_measurement"].(string)
		if !isStr {
			return fail("prover hardware evidence carries no measured identity")
		}
		if !v.measure[measurement] {
			return fail("prover VM measurement is not allowlisted")
		}
	}
	return ZkHookResult{Enforced: true, OK: true}
}
