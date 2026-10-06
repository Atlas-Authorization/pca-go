# pca-go

Proof-Carrying Authority (PCA) verifier for Go. **Preview.**

PCA is authF: instead of verifying a token, you verify a proof-carrying action (a PCActn) - the capability chain, Merkle plan inclusion, Ed25519 leaf signature and counter. This is a reference verifier that passes the shared conformance vectors.

> Preview: the wire format and API may change before 1.0.

## Install

`go get github.com/Atlas-Authorization/pca-go`

## Verify

```go
import pca "github.com/Atlas-Authorization/pca-go"

v, err := pca.VerifyPCActnCore(pcactn, grant) // both map[string]any (see pca.ParseJSON)
if err != nil { /* malformed input */ }
if v.Allow {
    // every check passed: chain, plan_inclusion, leaf_signature, counter
} else {
    fmt.Println(v.Reason, v.Checks)
}
```

## Conformance tests

The shared golden vectors are vendored in `conformance/` (synced from the hub). Run:

```
go test ./...
```

The reference verifier must produce the same `allow` and the same pass/fail for each of the four checks on every vector.

## Links

- Hub (spec, other languages): https://github.com/Atlas-Authorization/pca
- Live docs: https://atlasauth.net/pca
- TypeScript reference: npm `@atlasauth/pca`

## License

MIT
