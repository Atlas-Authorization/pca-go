# pca-go — Proof-Carrying Authority verifier for Go

An **offline verifier for Proof-Carrying Actions (PCActns)** in Go. A PCActn is the credential an
autonomous agent presents with *every* action it takes: a self-contained, cryptographically-checkable
object proving the action is a faithful execution of authority its principal actually granted. Your
resource server verifies it locally — no token introspection, no network call on the hot path.

This library is the Go member of the PCA verifier family. It is a faithful port of the TypeScript
reference implementation and passes the **same shared conformance corpus** as every other language
verifier, so a PCActn that verifies here verifies identically everywhere.

## Install

```sh
go get github.com/Atlas-Authorization/pca-go
```

```go
import pca "github.com/Atlas-Authorization/pca-go"
```

The package has one small runtime dependency (`cloudflare/circl`, for the post-quantum suites).

## Verify a PCActn

A verifier is stateless. Give it the received PCActn, the Root Intent Grant it claims to derive from,
the current time (epoch **milliseconds**), and *your own* audience id. It returns an allow/deny verdict
plus the per-check results.

```go
package main

import (
	"fmt"
	pca "github.com/Atlas-Authorization/pca-go"
)

func main() {
	// `raw` is the PCActn as received (strict canonical JSON, wire version 2).
	// `grant` is the Root Intent Grant the action's capability chain roots in.
	actn, err := pca.ParsePCActn(raw)
	if err != nil {
		// A malformed wire object is a terminal, fail-closed deny.
		fmt.Println("reject:", err)
		return
	}

	now := time.Now().UnixMilli()
	verdict, _ := pca.VerifyPCActnCore(actn, grant, now, "https://api.example.com")

	if verdict.Allow {
		// every core check passed — execute the action
	} else {
		fmt.Println("denied:", verdict.Reason, verdict.Checks)
	}
}
```

`Verdict.Checks` reports each core check (`wire`, `version`, `audience`, `validity`, `chain`,
`plan_inclusion`, `leaf_signature`, `counter`). Every check is **fail-closed** — the action is allowed
only if none reports failure — and a `wire` failure is terminal (nothing else is evaluated).

## Acting as an agent (producing proofs)

The module also produces the proofs it verifies, so an agent written in Go needs no other runtime. The principal mints a root
grant for the agent's public key; the agent signs one PCActn per action and sends it in the `PCA-Action` header (`Agent` keeps
the replay counter, picks the nonce and builds the headers).

```go
principal, _ := pca.NewKeyPair() // the principal's key stays with the principal
agentKey, _ := pca.NewKeyPair()

minted, err := pca.MintGrant(principal, agentKey.Public, map[string]any{
	"predicates": []any{map[string]any{"verb": "refund", "resource": "orders/*"}},
	"caveats":    []any{map[string]any{"type": "max_spend", "usd": 50}},
	"risk_policy": pca.DefaultRiskPolicy(),
}, "refund order 1", "", "", nil)

agent := pca.NewAgent(agentKey, minted.Grant, "https://api.example.com", 0)
action, err := agent.Act("refund", "orders/1", map[string]any{"amount_cents": 500}, nil)
for k, v := range action.Headers { req.Header.Set(k, v) }
```

`agent.Delegate(subKey, []any{pca.SealedCaveat()})` returns a sub-agent holding the chain plus one narrower hop (caveats are only
ever appended). Third-party and approval artifacts: `SignDischarge`, `SignNarrow`, `SignEscalationAnswer`, `SignPassport`,
`SignWorkflow` / `SignStepReceipt`, `SignReadGrant`, `SignFreshAt`. Ed25519 outputs are byte-exact against the shared producer
vectors; ML-DSA and SLH-DSA suites sign through circl (`pca.GeneratePqKeyPair("ML-DSA-65")`, then `agent.Suite =
&pca.SuiteOpts{Alg: "hybrid-ed25519-ml-dsa-65", Pq: pq}`). Persist the counter (`Agent.OnCounter`) if the process can restart: a lower
counter is refused as a replay.

## Caveats (policy layer)

The verifier above checks that the PCActn is well formed and authentic; like every PCA core verifier it does not decide
whether the action satisfies the grant's caveats. A resource server that enforces caveats evaluates them with its own action
parameters: `pca.EvaluateCaveats(pca.PolicyCaveats(grant, chain), ctx)`. `policy_caveats` is every caveat on the root grant except its first `envelope` caveat (0.4.1: root caveats
are enforced exactly like delegated ones) followed by the caveats the delegation hops appended. Supported types: `expires`,
`not_before`, `rate`, `max_blast_radius`, `reversibility_max`, `delegation_depth`, `budget_alloc` and `max_spend`; any other
type is unsatisfied (fail closed). The `PCA-Action` header must be strict unpadded base64url of UTF-8 text (`pca.DecodePCAHeader(value)`).

## Protect: the secure defaults in one call

```go
p := pca.Protect(pca.ProtectOptions{
	Audience:  "payments-rs",
	Grants:    grants,     // []map[string]any, looked up by "id"; or ResolveGrant. Never from the request.
	Operation: operationFor, // from your routing and body, never from the proof
})
mux.Handle("/refunds", p.Middleware()(handler))
p.Revoke(grantID) // every further action under that grant is refused
```

`Protect` fills in an in-memory replay store, a revocation source and the single-step plan; fields you set in
`ProtectOptions.Authorize` win. Unlike the TypeScript `protect()`, it does not price risk from a connector catalog
(Go has none): supply `Authorize.Context` if your grant has thresholds. A runnable Gin server is in `examples/gin-server`.

### Explaining a refusal

`pca.ExplainRefusal(reason)` returns `Check`, `Meaning`, `Fix` and `Docs` for a refusal reason and never panics. The HTTP
refusal bodies of `RequirePCA` carry the same link as an extra `doc` member next to the unchanged `reason`.

## What a passing result does not cover

`counter: pass` is a format check (a non-negative integer); it does **not** mean the action was not replayed.
Verification is stateless and this package has no replay store, so the resource server must persist, per grant and
agent, the last accepted counter and refuse anything not strictly greater, atomically across all of its processes.

The `RequirePCA` middleware runs the core verifier only. It does not check replay, revocation, caveats, envelope predicates, plan
authorization, risk or thresholds, and it does not compare the request body with the signed `params_digest`. Do those
checks in your handler (the caveat helpers above, the params digest of the body you will execute, your replay and
revocation stores), or delegate the decision to a full verifier such as `requirePCA` from `@atlasauth/pca`.

## Conformance

The repo ships a vendored copy of the shared **conformance corpus** (`conformance/vectors.json` +
`conformance/keys.json`): 676 golden and adversarial PCActns with their expected verdicts,
plus canonical-JSON, strict-base64url, and Merkle primitive vectors. `go test ./...` runs the verifier
against every vector; it must reproduce `allow` and every listed check exactly.

## Supported signature suites

- `ed25519` (default)
- `ml-dsa-65` (FIPS-204, post-quantum)
- `hybrid-ed25519-ml-dsa-65` (classical + post-quantum)

The suite id and post-quantum public key are part of the signed body, so a suite downgrade or key swap
invalidates the action.

## Capability maturity

The PCActn wire format and the eight core offline checks are stable and conformance-covered. The broader
framework surface is implemented and tested in the reference implementation: threshold/step-up co-signing
(a real FROST threshold signature over a DKG-established group key, released only on a Policy-VM allow),
TEE/hardware and model-weights attestation, zero-knowledge proof-of-compliance (a real Groth16 proof),
optimistic bonds and the contestable dispute game, and the malicious-secure MPC Policy VM (SPDZ-style MACs
with abort). A few rungs carry a remaining production requirement, stated plainly rather than hidden
behind a label: a live TEE/hardware attestation needs real SEV-SNP/TDX silicon (the verifier is tested
against real-crypto mock reports); unforgeable FROST guardian custody needs each share in a separate trust
domain / HSM with a network signing protocol (the reference runs the signing round in-process); the MPC
Policy VM's offline triple generation is trusted-dealer today (a no-dealer OT/HE phase is designed); and
the zero-knowledge circuit proves a decision subset (plan-membership + risk ≤ budget), with fuller
policy coverage ongoing. See the [PCA framework repo](https://github.com/Atlas-Authorization/pca) for the
full model.

## License

See `LICENSE`.
