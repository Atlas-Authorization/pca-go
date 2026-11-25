package pca

// Key rotation for capability chains: rotate an agent (leaf) key, re-root a chain under a new principal key, revoke and re-issue a
// compromised delegation subtree, and apply the resulting revocation records to a registry atomically (all or nothing).
//
// Chains are JSON values ([]any of capability objects, as parsed or as returned by MintRoot / Delegate). Every hop must carry a
// non-empty string id, string issuer and holder and a caveats array, or the call refuses. Hops that are not re-signed are
// returned as given.

import (
	"errors"
	"fmt"
	"math"
	"time"
)

// RevocationRecord is what a rotation revokes: capId / holder / issuer / subtreeRoot / capIds / reason / revokedAt (epoch ms).
// It is the input ApplyRotation takes.
type RevocationRecord = map[string]any

// RotationResult is the re-issued chain and the record of what it replaces.
type RotationResult struct {
	Chain      []any            `json:"chain"`
	Revocation RevocationRecord `json:"revocation"`
}

// CompromiseResult is one record per revoked hop of the compromised subtree and the re-issued chain.
type CompromiseResult struct {
	Revocations []RevocationRecord `json:"revocations"`
	Reissued    []any              `json:"reissued"`
}

// RotateOptions are the optional members shared by the rotation calls: Reason (nil = the call's default reason) and Now (epoch ms,
// nil = the wall clock; a non-finite value is refused).
type RotateOptions struct {
	Reason *string
	Now    *float64
}

func (o RotateOptions) reason(def string) string {
	if o.Reason != nil {
		return *o.Reason
	}
	return def
}

func (o RotateOptions) at(ctx string) (float64, error) {
	if o.Now == nil {
		return float64(time.Now().UnixMilli()), nil
	}
	if math.IsNaN(*o.Now) || math.IsInf(*o.Now, 0) {
		return 0, fmt.Errorf("%s: now must be a finite number", ctx)
	}
	return *o.Now + 0, nil // -0 is recorded as 0
}

func rotHops(chain []any, ctx string) ([]map[string]any, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("%s: empty chain", ctx)
	}
	out := make([]map[string]any, len(chain))
	for i, h := range chain {
		c, ok := h.(map[string]any)
		id, _ := c["id"].(string)
		_, iok := c["issuer"].(string)
		_, hok := c["holder"].(string)
		_, cok := c["caveats"].([]any)
		if !ok || id == "" || !iok || !hok || !cok {
			return nil, fmt.Errorf("%s: malformed capability at index %d (needs a string id, issuer, holder and a caveats array)", ctx, i)
		}
		out[i] = c
	}
	return out, nil
}

func rotPub(k *KeyPair, ctx, what string) (string, error) {
	if k == nil {
		return "", fmt.Errorf("%s: %s is required", ctx, what)
	}
	return k.Public, nil
}

func rotAppended(parent, child map[string]any) ([]any, error) {
	pc, cc := parent["caveats"].([]any), child["caveats"].([]any)
	if len(cc) < len(pc) {
		return nil, errors.New("malformed chain: a child carries fewer caveats than its parent (not an attenuation)")
	}
	return cc[len(pc):], nil
}

// rotDelegate is the reference delegate: issuer = parent.holder, caveats = parent.caveats ++ added, parent = capHash(parent); the
// holder_pq commitment is kept only when the holder is unchanged.
func rotDelegate(parent map[string]any, holder string, added []any, signer *KeyPair) (map[string]any, error) {
	pc, err := normList(parent["caveats"])
	if err != nil {
		return nil, err
	}
	add, err := normList(added)
	if err != nil {
		return nil, err
	}
	ph := parent["holder"].(string)
	hp := ""
	if holder == ph {
		if v, has := parent["holder_pq"]; has && v != nil {
			s, ok := v.(string)
			if !ok || s == "" {
				return nil, errors.New("malformed capability: holder_pq must be a non-empty string")
			}
			hp = s
		}
	}
	link, err := CapHash(parent)
	if err != nil {
		return nil, err
	}
	return seal(ph, holder, append(pc, add...), link, hp, signer, nil)
}

// RotateAgentKey re-issues the leaf of chain to newKey, signed by the leaf's issuer (oldHolder), and records the old leaf as revoked.
func RotateAgentKey(chain []any, oldHolder, newKey *KeyPair, o RotateOptions) (*RotationResult, error) {
	const ctx = "rotateAgentKey"
	hops, err := rotHops(chain, ctx)
	if err != nil {
		return nil, err
	}
	if len(hops) < 2 {
		return nil, errors.New("rotateAgentKey: a root-only chain has no leaf delegation to re-issue; use rotatePrincipalKey")
	}
	parent, leaf := hops[len(hops)-2], hops[len(hops)-1]
	signerPub, err := rotPub(oldHolder, ctx, "oldHolderSecret")
	if err != nil {
		return nil, err
	}
	if signerPub != leaf["issuer"] {
		return nil, fmt.Errorf("rotateAgentKey: oldHolderSecret (pub %s) is not the leaf's issuer %s", signerPub, leaf["issuer"])
	}
	newHolder, err := rotPub(newKey, ctx, "newKeyPair")
	if err != nil {
		return nil, err
	}
	if newHolder == leaf["holder"] {
		return nil, errors.New("rotateAgentKey: newKeyPair is the key being rotated out")
	}
	at, err := o.at(ctx)
	if err != nil {
		return nil, err
	}
	added, err := rotAppended(parent, leaf)
	if err != nil {
		return nil, err
	}
	nl, err := rotDelegate(parent, newHolder, added, oldHolder)
	if err != nil {
		return nil, err
	}
	out := append(append([]any{}, chain[:len(chain)-1]...), nl)
	return &RotationResult{Chain: out, Revocation: RevocationRecord{
		"capId": leaf["id"], "holder": leaf["holder"], "issuer": leaf["issuer"], "capIds": []any{leaf["id"]},
		"reason": o.reason("agent key rotated"), "revokedAt": jsNumber(at),
	}}, nil
}

// RotatePrincipalKey re-roots chain under newPrincipal: a new root with the old root's holder and caveats, then every later hop
// re-signed by its issuer (holders[i-1] signs hop i). The whole old chain is recorded as revoked.
func RotatePrincipalKey(chain []any, oldPrincipal, newPrincipal *KeyPair, holders []*KeyPair, o RotateOptions) (*RotationResult, error) {
	const ctx = "rotatePrincipalKey"
	hops, err := rotHops(chain, ctx)
	if err != nil {
		return nil, err
	}
	oldRoot := hops[0]
	if _, has := oldRoot["parent"]; has {
		return nil, errors.New("rotatePrincipalKey: chain[0] is not a root (it has a parent)")
	}
	oldPub, err := rotPub(oldPrincipal, ctx, "oldPrincipalSecret")
	if err != nil {
		return nil, err
	}
	if oldPub != oldRoot["issuer"] {
		return nil, fmt.Errorf("rotatePrincipalKey: oldPrincipalSecret (pub %s) is not the root's issuer %s", oldPub, oldRoot["issuer"])
	}
	if len(holders) != len(hops)-1 {
		return nil, fmt.Errorf("rotatePrincipalKey: expected %d holderSecrets (one per non-root hop), got %d", len(hops)-1, len(holders))
	}
	newPub, err := rotPub(newPrincipal, ctx, "newPrincipalKeyPair")
	if err != nil {
		return nil, err
	}
	if newPub == oldRoot["issuer"] {
		return nil, errors.New("rotatePrincipalKey: newPrincipalKeyPair is the key being rotated out")
	}
	at, err := o.at(ctx)
	if err != nil {
		return nil, err
	}
	rc, err := normList(oldRoot["caveats"])
	if err != nil {
		return nil, err
	}
	nr, err := seal(newPub, oldRoot["holder"].(string), rc, "", "", newPrincipal, nil)
	if err != nil {
		return nil, err
	}
	out := []any{nr}
	for i := 1; i < len(hops); i++ {
		sp, err := rotPub(holders[i-1], ctx, fmt.Sprintf("holderSecret for hop %d", i))
		if err != nil {
			return nil, err
		}
		if sp != hops[i]["issuer"] {
			return nil, fmt.Errorf("rotatePrincipalKey: holderSecret for hop %d (pub %s) is not that hop's issuer %s", i, sp, hops[i]["issuer"])
		}
		added, err := rotAppended(hops[i-1], hops[i])
		if err != nil {
			return nil, err
		}
		h, err := rotDelegate(out[i-1].(map[string]any), hops[i]["holder"].(string), added, holders[i-1])
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	ids := make([]any, len(hops))
	for i, h := range hops {
		ids[i] = h["id"]
	}
	return &RotationResult{Chain: out, Revocation: RevocationRecord{
		"capId": oldRoot["id"], "issuer": oldRoot["issuer"], "holder": oldRoot["holder"], "subtreeRoot": oldRoot["id"], "capIds": ids,
		"reason": o.reason("principal key rotated (re-root)"), "revokedAt": jsNumber(at),
	}}, nil
}

func rotHolderIndex(hops []map[string]any, holder string) int {
	for i, h := range hops {
		if h["holder"] == holder {
			return i
		}
	}
	return -1
}

// RevokeAndReissueSubtree cuts the chain at the first hop held by compromisedHolder and re-issues the leaf's authority directly
// from the safe ancestor (signed by ancestor, the holder of the hop before it) to newKey. The cut subtree is recorded as revoked.
func RevokeAndReissueSubtree(chain []any, compromisedHolder string, newKey, ancestor *KeyPair, o RotateOptions) (*RotationResult, error) {
	const ctx = "revokeAndReissueSubtree"
	hops, err := rotHops(chain, ctx)
	if err != nil {
		return nil, err
	}
	idx := rotHolderIndex(hops, compromisedHolder)
	if idx < 0 {
		return nil, fmt.Errorf("revokeAndReissueSubtree: holder %s is not in the chain", compromisedHolder)
	}
	if idx == 0 {
		return nil, errors.New("revokeAndReissueSubtree: the compromised holder is the root holder (no safe delegation ancestor); rotate the root with rotatePrincipalKey")
	}
	anc, sub, leaf := hops[idx-1], hops[idx], hops[len(hops)-1]
	ap, err := rotPub(ancestor, ctx, "ancestorSecret")
	if err != nil {
		return nil, err
	}
	if ap != anc["holder"] {
		return nil, fmt.Errorf("revokeAndReissueSubtree: ancestorSecret (pub %s) is not the safe ancestor's holder %s", ap, anc["holder"])
	}
	newHolder, err := rotPub(newKey, ctx, "newKeyPair")
	if err != nil {
		return nil, err
	}
	if rotHolderIndex(hops[idx:], newHolder) >= 0 {
		return nil, errors.New("revokeAndReissueSubtree: newKeyPair is a key held inside the compromised subtree")
	}
	at, err := o.at(ctx)
	if err != nil {
		return nil, err
	}
	added, err := rotAppended(anc, leaf)
	if err != nil {
		return nil, err
	}
	nh, err := rotDelegate(anc, newHolder, added, ancestor)
	if err != nil {
		return nil, err
	}
	ids := make([]any, 0, len(hops)-idx)
	for _, h := range hops[idx:] {
		ids = append(ids, h["id"])
	}
	return &RotationResult{Chain: append(append([]any{}, chain[:idx]...), nh), Revocation: RevocationRecord{
		"capId": sub["id"], "holder": compromisedHolder, "issuer": sub["issuer"], "subtreeRoot": sub["id"], "capIds": ids,
		"reason": o.reason("delegation subtree compromised"), "revokedAt": jsNumber(at),
	}}, nil
}

// CompromisedKeyFlow is RevokeAndReissueSubtree with one revocation record per cut hop (so each id can be looked up on its own).
func CompromisedKeyFlow(chain []any, compromisedHolder string, newKey, ancestor *KeyPair, o RotateOptions) (*CompromiseResult, error) {
	const ctx = "compromisedKeyFlow"
	hops, err := rotHops(chain, ctx)
	if err != nil {
		return nil, err
	}
	idx := rotHolderIndex(hops, compromisedHolder)
	if idx < 0 {
		return nil, fmt.Errorf("compromisedKeyFlow: holder %s is not in the chain", compromisedHolder)
	}
	r, err := RevokeAndReissueSubtree(chain, compromisedHolder, newKey, ancestor, o)
	if err != nil {
		return nil, err
	}
	at := r.Revocation["revokedAt"]
	reason := o.reason("delegation subtree compromised")
	recs := make([]RevocationRecord, 0, len(hops)-idx)
	for _, h := range hops[idx:] {
		recs = append(recs, RevocationRecord{
			"capId": h["id"], "holder": h["holder"], "issuer": h["issuer"], "subtreeRoot": hops[idx]["id"], "capIds": []any{h["id"]},
			"reason": reason, "revokedAt": at,
		})
	}
	return &CompromiseResult{Revocations: recs, Reissued: r.Chain}, nil
}

// RevocationSink is where ApplyRotation writes; *RevocationRegistry is one.
type RevocationSink interface {
	Revoke(input map[string]any) (RevocationEntry, error)
	Unrevoke(key any) (bool, error)
	Lookup(kind, value string) (RevocationEntry, error)
}

// ApplyRotation revokes every capability the records name (records: one RevocationRecord or a list; ids deduplicated, the first
// record naming an id supplies its reason / revokedAt). It refuses when nothing is named, an id is not a non-empty string, or the
// re-issued chain still contains a revoked id. If a write fails, every id this call newly revoked is unrevoked again (best effort)
// and the error is returned. It returns the revoked ids in order.
func ApplyRotation(sink RevocationSink, records any, reissued any) ([]string, error) {
	rs, err := NormalizeJSON(records)
	if err != nil {
		return nil, err
	}
	list, isList := rs.([]any)
	if !isList {
		list = []any{rs}
	}
	var order []string
	from := map[string]map[string]any{}
	for _, x := range list {
		if x == nil {
			return nil, errors.New("applyRotation: a record is null")
		}
		r, _ := x.(map[string]any) // a non-object record names nothing
		var ids []any
		if v := r["capIds"]; v != nil {
			l, ok := v.([]any)
			if !ok {
				return nil, errors.New("applyRotation: capIds must be an array")
			}
			ids = l
		} else if v, has := r["capId"]; has {
			ids = []any{v}
		}
		for _, v := range ids {
			id, ok := v.(string)
			if !ok || id == "" {
				return nil, errors.New("applyRotation: a record names an invalid capability id")
			}
			if _, seen := from[id]; !seen {
				from[id] = r
				order = append(order, id)
			}
		}
	}
	if len(order) == 0 {
		return nil, errors.New("applyRotation: the record names no capability to revoke")
	}
	ri, err := NormalizeJSON(reissued)
	if err != nil {
		return nil, err
	}
	if ri != nil {
		l, ok := ri.([]any)
		if !ok {
			return nil, errors.New("applyRotation: reissued must be a chain")
		}
		for _, h := range l {
			if h == nil {
				return nil, errors.New("applyRotation: reissued holds a null capability")
			}
			c, _ := h.(map[string]any) // a non-object hop has no id
			if id, ok := c["id"].(string); ok && from[id] != nil {
				return nil, errors.New("applyRotation: the re-issued chain contains a capability that is being revoked")
			}
		}
	}
	var added []string
	fail := func(e error) ([]string, error) {
		for _, id := range added {
			sink.Unrevoke(map[string]any{"kind": "cap", "value": id}) //nolint:errcheck // best-effort rollback; the original error wins
		}
		return nil, e
	}
	for _, id := range order {
		e, err := sink.Lookup("cap", id)
		if err != nil {
			return fail(err)
		}
		if e == nil {
			added = append(added, id)
		}
		in := map[string]any{"kind": "cap", "value": id}
		for _, k := range []string{"reason", "revokedAt"} {
			if v, has := from[id][k]; has {
				in[k] = v
			}
		}
		if _, err := sink.Revoke(in); err != nil {
			return fail(err)
		}
	}
	return order, nil
}
