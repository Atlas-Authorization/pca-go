# Gin server protected by PCA

A minimal Gin server with one protected route, `POST /refunds`. It uses `pca.Protect`, which wires the secure defaults
(grants from your own list, an in-memory replay store, a revocation source, the single-step plan), and a small adapter
that runs the PCA net/http middleware inside Gin.

## Run

```sh
go mod tidy
go test ./...                       # allow, then a refusal that carries a `doc` link
go run . -audience payments-rs -grants grants.json -mediators mediators.json
```

`grants.json` is a JSON array of the grants this server accepts. The grant comes from your store, never from the request.
`mediators.json` is a JSON array of the agent-harness keys you pin (`[{"mediator", "kid", "pk"}]`, from
`ProvenanceRecorder.Pin`).

## What it shows

- `pca.Protect(...)` returns the middleware options and `Revoke(grantID)`. Anything you set in `ProtectOptions.Authorize`
  wins over the default.
- `operationFor` builds the operation from the route and the request body, not from the proof. The proof must have been
  signed for exactly that verb, resource and params, so a proof for 50 cannot refund 5000.
- A refused request is a JSON body with the unchanged `reason` plus `doc`, a link that explains the refusal.
  `pca.ExplainRefusal(reason)` returns the same guidance (meaning, fix, docs) in code.

- Provenance by default: the payment is a sensitive action, so the request must carry a provenance bundle in the
  `PCA-Provenance` header, signed by a harness key you pinned, showing the payment came from the user. Without it the
  response is `decision: "escalate"` (the principal must confirm). The test builds the bundle with
  `pca.PrincipalDirectProvenance`.

Replay counters are kept in memory, which is right for one process. For several workers use `pca.NewSQLStateStore`.
