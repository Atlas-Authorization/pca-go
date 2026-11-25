package pca

// Small public entry points of the core that were reachable only through larger ones: opening a goal commitment, naming the unmet
// limit of a predicate list, assembling a threshold signature, the workflow commitment and receipt-chain checks, the cheap
// (Ed25519-only) delegation chain check, the PQ key of a chain hop, discovery over an injectable transport and inclusion in the
// revocation set.

import (
	"errors"
	"fmt"
	"strings"
)

// VerifyGoalCommit checks that a revealed (goal, salt) opens the commitment.
func VerifyGoalCommit(commit, goal, salt string) bool {
	c, err := GoalCommitOf(goal, salt)
	return err == nil && c == commit
}

// NamedUnmetLimitReason is the denial wording that names the first `where` limit the action fails for the first predicate in scope,
// or "" when none is in scope (or the predicates cannot be read).
func NamedUnmetLimitReason(predicates any, ctx map[string]any) (reason string) {
	defer func() {
		if recover() != nil {
			reason = ""
		}
	}()
	arr, ok := predicates.([]any)
	if !ok {
		return ""
	}
	limit, found := firstUnmetLimit(arr, ctx, &regexBudget{})
	if !found {
		return ""
	}
	a, _ := ctx["action"].(map[string]any)
	return limit + " not satisfied for " + jsMemberString(a, "verb") + " on " + jsMemberString(a, "resource")
}

// AssembleThreshold collects shares into a threshold signature {shares}; anything but a list is no shares.
func AssembleThreshold(shares any) map[string]any {
	l, ok := shares.([]any)
	if !ok {
		l = []any{}
	}
	return map[string]any{"shares": append([]any{}, l...)}
}

// WorkflowCommitmentError is "" when the workflow is a well-formed, acyclic commitment signed by the pinned principal and valid at
// now, else the refusal code (bad_workflow, bad_dag, bad_signature, not_yet, expired).
func WorkflowCommitmentError(workflow, principal, now any) string {
	sw, isObj := k5Obj(workflow)
	if !isObj || !k5OnlyKeys(sw, "body", "sig") || !k5ValidWorkflowBody(sw["body"]) || !k5IsB32(principal) || !k5IsUint(now) {
		return "bad_workflow"
	}
	body := sw["body"].(map[string]any)
	if k5DagError(body) != "" {
		return "bad_dag"
	}
	if body["principal"] != principal || !k5VerifyBody(k5WorkflowDomain, body, principal, sw["sig"]) {
		return "bad_signature"
	}
	n := k5F(now)
	if n < k5F(body["issued_at"]) {
		return "not_yet"
	}
	if n >= k5F(body["expires_at"]) {
		return "expired"
	}
	return ""
}

// WorkflowReceiptError checks a step-receipt chain against its workflow body: the index of the first offending receipt, and true,
// or (0, false) when the chain is sound. A workflow body that is not well formed is an error.
func WorkflowReceiptError(w map[string]any, rsSigner string, receipts []any, now int64) (at int, bad bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			at, bad, err = 0, false, fmt.Errorf("workflowReceiptError: %v", r)
		}
	}()
	if i := k5ReceiptError(w, rsSigner, receipts, now); i >= 0 {
		return i, true, nil
	}
	return 0, false, nil
}

// VerifyChainCheap is the structural and Ed25519-half check of a delegation chain, bounded by MaxChainHops Ed25519 verifications
// whatever suites the chain names: it performs no post-quantum verification and resolves no PQ key. pqHops counts the hops that
// still need PQ verification. A nil reason is no refusal; ok is NEVER an authentication: run the full verifier before trusting the
// chain. allowed is the optional suite policy (nil: none; a present, even empty, list enforces).
func VerifyChainCheap(chain []any, expectedRootIssuer string, haveIssuer bool, allowed []string) (pqHops int, reason string) {
	defer func() {
		if r := recover(); r != nil {
			pqHops, reason = 0, fmt.Sprintf("malformed capability chain: %v", r)
		}
	}()
	if len(chain) == 0 {
		return 0, "empty chain"
	}
	if len(chain) > MaxChainHops {
		return 0, fmt.Sprintf("chain too long (max %d hops)", MaxChainHops)
	}
	if caveatLimitExceeded(chain) {
		return 0, CaveatLimitReason
	}
	var prev map[string]any
	for i, x := range chain {
		label := fmt.Sprintf("hop %d", i)
		c, ok := wellTypedCap(x)
		if !ok {
			return 0, label + ": malformed capability"
		}
		alg, present := c["alg"], hasKey(c, "alg")
		su, known := resolveSigAlg(alg, present)
		if !known {
			return 0, fmt.Sprintf("%s: unknown signature alg '%v'", label, alg)
		}
		if !suiteAllowed(alg, present, allowed) {
			return 0, fmt.Sprintf("%s: signature suite '%s' is not allowed by this verifier's suite policy", label, algName(alg, present))
		}
		var signer string
		if i == 0 {
			if _, has := c["parent"]; has {
				return 0, "hop 0: root must not have a parent"
			}
			if haveIssuer && c["issuer"] != expectedRootIssuer {
				return 0, "hop 0: root issuer is not the expected principal"
			}
			signer, _ = c["issuer"].(string)
		} else {
			ph, err := CapHash(prev)
			if err != nil || c["parent"] != ph {
				return 0, label + ": broken parent link"
			}
			if c["issuer"] != prev["holder"] {
				return 0, label + ": issuer is not the parent's bound holder"
			}
			signer, _ = prev["holder"].(string)
		}
		body, ok := signableHopBody(c)
		if !ok {
			return 0, label + ": malformed body"
		}
		digest, err := HashCanonical(body)
		if err != nil {
			return 0, label + ": malformed body"
		}
		bd, _ := c["body_digest"].(string)
		if id, _ := c["id"].(string); digest != bd || id != bd {
			return 0, label + ": body digest mismatch"
		}
		if su.hasEd25519 {
			msg, err := capSigMessage(bd)
			if err != nil || !verifyLeafSuite("ed25519", true, signer, pqVerifyKey{}, msg, c["sig"], nil) {
				return 0, label + ": bad signature (not signed by expected key)"
			}
		}
		if su.needsPqPk {
			pqHops++
		}
		prev = c
	}
	return pqHops, ""
}

// HolderPqKey is the PQ verification key for a signature by a chain leaf or threshold share under alg: the artifact's pq_pk when it
// is the key the holder committed to (holderPq), else ok is false. A suite without a PQ key has none.
func HolderPqKey(alg any, artifactPqPk, holderPq any) (pk string, ok bool) {
	su, known := resolveSigAlg(alg, true)
	if !known || !su.needsPqPk {
		return "", false
	}
	key, bound := resolvePqVerifyKey(alg, true, artifactPqPk, pqAuthority{holderPq: holderPq, hasHolderPq: holderPq != nil})
	if !bound {
		return "", false
	}
	s, isStr := key.pk.(string)
	return s, isStr
}

// DiscoveryFetch is the transport of FetchDiscovery: a GET of url with the headers, answered by the status and the decoded JSON body.
type DiscoveryFetch func(url string, headers map[string]string) (status int, body any, err error)

// FetchDiscovery reads and validates the discovery document of a resource server: the well-known path is appended to the base URL
// (trailing slashes dropped). A non-2xx answer or a malformed document is an error.
func FetchDiscovery(baseURL string, fetch DiscoveryFetch) (map[string]any, error) {
	if fetch == nil {
		return nil, errors.New("fetchDiscovery: no fetch available - pass one explicitly")
	}
	url := strings.TrimRight(baseURL, "/") + WellKnownPcaPath
	status, body, err := fetch(url, map[string]string{"accept": "application/json"})
	if err != nil {
		return nil, err
	}
	if status < 200 || status > 299 {
		return nil, fmt.Errorf("fetchDiscovery: %s returned %d", url, status)
	}
	return ParseDiscoveryDocument(body)
}

// VerifyMembership verifies that id IS in the revocation set the root commits to (an inclusion proof {index, size, path} against
// the size-bound root). A malformed proof is false.
func VerifyMembership(root string, proof any, id string) bool {
	m, ok := proof.(map[string]any)
	if !ok {
		return false
	}
	size, ok := extSafeInt(m["size"])
	return ok && revLeafOK(root, size, id, proof)
}
