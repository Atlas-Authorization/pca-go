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

## Conformance

The repo ships a vendored copy of the shared **conformance corpus** (`conformance/vectors.json` +
`conformance/keys.json`): over a hundred golden and adversarial PCActns with their expected verdicts,
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
