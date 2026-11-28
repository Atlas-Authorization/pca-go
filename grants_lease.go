package pca

// The operational side of leases and blueprints: lease renewal (the authority signs and registers the next record), the hosted lease
// routes, group kill of a blueprint and attestation-gated blueprint admission. The verification side (registries and checks) is in
// lease.go and blueprint.go. Records are parsed JSON objects (map[string]any, numbers as json.Number).

import (
	"errors"
	"math"
)

// History is the renewal ledger of a lease (empty for an unknown id); an error when the store cannot be read.
func (r *LeaseRegistry) History(id string) ([]LeaseHistoryEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ready(); err != nil {
		return nil, err
	}
	if err := kvRead(r.kv, leaseShardKey(r.shards, leaseShardOf(id, r.shards)), r.load); err != nil {
		return nil, err
	}
	st := r.leases[id]
	if st == nil {
		return []LeaseHistoryEntry{}, nil
	}
	return append([]LeaseHistoryEntry{}, st.history...), nil
}

// ShardRevocations are the revocations kept in one shard (0 to shards-1); an error when the store cannot be read.
func (r *LeaseRegistry) ShardRevocations(i int) ([]map[string]any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i < 0 || i >= r.shards {
		return nil, errors.New("shardRevocations: no such shard")
	}
	if err := r.ready(); err != nil {
		return nil, err
	}
	if err := kvRead(r.kv, leaseShardKey(r.shards, i), r.load); err != nil {
		return nil, err
	}
	return append([]map[string]any{}, r.revocations...), nil
}

// Get is the newest accepted record of a blueprint key (nil when unknown); an error when the store cannot be read.
func (r *BlueprintRegistry) Get(key string) (map[string]any, error) {
	b, has, err := r.lookup(key)
	if err != nil || !has {
		return nil, err
	}
	return b, nil
}

// GrantsLeaseHistoryJSON renders a renewal ledger as JSON values.
func GrantsLeaseHistoryJSON(h []LeaseHistoryEntry) []any {
	out := make([]any, len(h))
	for i, e := range h {
		out[i] = map[string]any{"seq": jsNumber(float64(e.Seq)), "renewed_at": jsNumber(float64(e.RenewedAt)), "expires_at": jsNumber(float64(e.ExpiresAt)), "justification_digest": e.JustificationDigest}
	}
	return out
}

// LeaseRenewOptions are the inputs of RenewLease. Approvers nil: keep the current approvers. Veto may only REFUSE a renewal, never
// lengthen it. Chain is the keys in the holder's delegation chain.
type LeaseRenewOptions struct {
	Now, Increment      any
	JustificationDigest string
	Approvers           any
	Veto                func(current map[string]any) bool
	Chain               []string
}

// RenewLease is the authority side: sign and register the next record of a lease. The result is {ok: true, record} or {ok: false,
// code} with code a lease accept code or bad_input, unknown_lease, vetoed or expired_lease.
func RenewLease(k *KeyPair, reg *LeaseRegistry, id string, o LeaseRenewOptions) map[string]any {
	no := func(code string) map[string]any { return map[string]any{"ok": false, "code": code} }
	if !k3Int(o.Now) || !k3Int(o.Increment) || jsF(o.Increment) < 1 {
		return no("bad_input")
	}
	cur := reg.Get(id)
	if cur == nil {
		return no("unknown_lease")
	}
	if o.Veto != nil && o.Veto(cur) {
		return no("vetoed")
	}
	now := jsF(o.Now)
	expires := math.Min(now+jsF(o.Increment), float64(leaseCap(cur)))
	next := withoutKeys(cur, "v", "sig", "authority")
	next["seq"], next["renewed_at"], next["expires_at"] = jsNumber(jsF(cur["seq"])+1), o.Now, jsNumber(expires)
	next["justification_digest"] = o.JustificationDigest
	if o.Approvers != nil {
		next["approvers"] = o.Approvers
	}
	record, err := SignLease(k, next)
	if err != nil {
		if expires <= now {
			return no("expired_lease")
		}
		return no("bad_input")
	}
	if r := reg.Accept(record, o.Chain); !r.Ok {
		return no(r.Code)
	}
	return map[string]any{"ok": true, "record": record}
}

// ---- lease HTTP binding ----------------------------------------------------------------------------------------------

var grantsLeaseStatus = map[string]int{
	"bad_record": 400, "bad_seq": 409, "stale_seq": 409, "lease_fork": 409, "renewal_mismatch": 422, "over_max_ttl": 422, "ttl_ceiling": 422,
	"not_extending": 422, "stale_justification": 422, "expired_lease": 409, "revoked": 409, "sod": 403, "unknown_authority": 403, "store_unreachable": 503,
}

// LeaseManagementMetadata is the discovery fragment for /.well-known/pca-configuration.
func LeaseManagementMetadata(base string) map[string]any {
	return map[string]any{"leases": map[string]any{"leases_endpoint": base + LeasesPath, "revoke_targets": []any{"lease", "prefix", "grant"}}}
}

// LeaseHTTPOptions: Authenticate returns who is calling ({admin?, principal?}) or nil; Now (epoch ms) defaults to the wall clock.
type LeaseHTTPOptions struct {
	Authenticate func(req *GrantsHTTPRequest) map[string]any
	Now          func() int64
}

// LeaseResourceHandler is the hosted lease routes. The server only stores records the lease authority already signed; it never
// mints one, so a compromised host cannot extend a lease.
//
//	POST /pca/leases           {lease, chain?}  issue (seq 1) or renew (seq n+1); admin only
//	GET  /pca/leases/{id}                      the newest record and its renewal ledger; the holder or an admin
//	POST /pca/leases/{id}/check {lease}        is this record a live lease; the holder or an admin
//	POST /pca/leases/revoke    {revocation}    a signed revoke by lease, prefix or grant; admin only
func LeaseResourceHandler(reg *LeaseRegistry, o LeaseHTTPOptions) func(req *GrantsHTTPRequest) GrantsHTTPResponse {
	return func(req *GrantsHTTPRequest) (resp GrantsHTTPResponse) {
		defer func() {
			if recover() != nil {
				resp = GrantsHTTPResponse{500, map[string]any{"error": "server_error"}}
			}
		}()
		var who map[string]any
		if o.Authenticate != nil {
			who = o.Authenticate(req)
		}
		if who == nil || (!jsTruthy(who["admin"]) && !jsTruthy(who["principal"])) {
			return GrantsHTTPResponse{401, map[string]any{"error": "unauthenticated"}}
		}
		seg := grantsSegments(req.Path)
		b, _ := req.Body.(map[string]any)
		if len(seg) < 2 || seg[0] != "pca" || seg[1] != "leases" {
			return grantsNotFound
		}
		admin := who["admin"] == true
		// a lease belongs to its holder: a non-admin sees and checks only leases it holds
		visible := func(holder any) bool { return admin || grantsEq(who["principal"], holder) }
		forbidden := GrantsHTTPResponse{403, map[string]any{"error": "forbidden"}}
		method := req.Method
		if len(seg) == 2 && method == "POST" {
			if !jsTruthy(who["admin"]) {
				return forbidden
			}
			chain := []string{}
			if l, ok := b["chain"].([]any); ok {
				all := true
				for _, x := range l {
					s, isStr := x.(string)
					all = all && isStr
					chain = append(chain, s)
				}
				if !all {
					chain = []string{}
				}
			}
			r := reg.Accept(b["lease"], chain)
			if r.Ok {
				body := map[string]any{"ok": true, "replaced": r.Replaced, "seq": jsNumber(float64(r.Seq))}
				if r.Replaced {
					return GrantsHTTPResponse{201, body}
				}
				return GrantsHTTPResponse{200, body}
			}
			status, known := grantsLeaseStatus[r.Code]
			if !known {
				status = 400
			}
			body := map[string]any{"error": r.Code}
			if r.Reason != "" {
				body["message"] = r.Reason
			}
			return GrantsHTTPResponse{status, body}
		}
		if len(seg) == 3 && seg[2] == "revoke" && method == "POST" {
			if !jsTruthy(who["admin"]) {
				return forbidden
			}
			code, n := reg.Revoke(b["revocation"])
			if code == "" {
				return GrantsHTTPResponse{200, map[string]any{"ok": true, "revoked": jsNumber(float64(n))}}
			}
			status := 400
			if code == "store_unreachable" {
				status = 503
			} else if code == "unknown_authority" {
				status = 403
			}
			return GrantsHTTPResponse{status, map[string]any{"error": code}}
		}
		id := grantsSeg(seg, 2)
		if id == "" {
			return grantsNotFound
		}
		if len(seg) == 3 && method == "GET" {
			cur := reg.Get(id)
			if cur == nil || !visible(cur["holder"]) {
				return grantsNotFound
			}
			h, err := reg.History(id)
			if err != nil {
				return GrantsHTTPResponse{500, map[string]any{"error": "server_error"}}
			}
			return GrantsHTTPResponse{200, map[string]any{"lease": cur, "history": GrantsLeaseHistoryJSON(h)}}
		}
		if len(seg) == 4 && seg[3] == "check" && method == "POST" {
			cur := reg.Get(id)
			if cur == nil || !visible(cur["holder"]) {
				return grantsNotFound
			}
			now := int64(0)
			if o.Now != nil {
				now = o.Now()
			} else {
				now = reg.clock()
			}
			d := CheckLease(b["lease"], reg, jsNumber(float64(now)))
			body := map[string]any{"decision": d.Decision}
			status := 403
			if d.Decision == "allow" {
				status = 200
				body["lease_id"], body["expires_at"] = d.LeaseID, jsNumber(float64(d.ExpiresAt))
			} else {
				body["code"] = d.Code
				if d.LeaseID != "" {
					body["lease_id"] = d.LeaseID
				}
			}
			return GrantsHTTPResponse{status, body}
		}
		return grantsNotFound
	}
}

// ---- blueprints: group kill and attestation-gated admission ----------------------------------------------------------

// GroupKillOptions: Now (the kill time), Reason (empty: "blueprint disabled (group kill)"), Revoke (optional: revoke the blueprint
// key as an ISSUER in a revocation registry; input is {kind, value, reason, revokedAt}), FreshAt (optional: a *FreshAtIssuer whose
// revocation_epoch advances to the record's epoch).
type GroupKillOptions struct {
	Now     any
	Reason  string
	Revoke  func(input map[string]any) error
	FreshAt interface {
		Advance(patch map[string]any, now any) (map[string]any, error)
	}
}

// GroupKill: the operator signs the blueprint as disabled at the next epoch; the registry accepts it and, with Revoke, also revokes
// the blueprint key as an issuer so verifiers that only read the revocation feed refuse every instance too; with FreshAt the token
// of the write is returned. The result is {ok: true, record, freshAt?} or {ok: false, code}; an error where the reference throws.
func GroupKill(k *KeyPair, reg *BlueprintRegistry, key string, o GroupKillOptions) (map[string]any, error) {
	cur, err := reg.Get(key)
	if err != nil {
		return nil, err
	}
	if cur == nil {
		return map[string]any{"ok": false, "code": "unknown_blueprint"}, nil
	}
	next := withoutKeys(cur, "sig", "operator", "v")
	next["status"], next["epoch"], next["issued_at"] = "disabled", jsNumber(jsF(cur["epoch"])+1), o.Now
	record, err := SignBlueprint(k, next)
	if err != nil {
		return nil, err
	}
	if code, _ := reg.Accept(record); code != "" {
		return map[string]any{"ok": false, "code": code}, nil
	}
	if o.Revoke != nil {
		reason := o.Reason
		if reason == "" {
			reason = "blueprint disabled (group kill)"
		}
		if err := o.Revoke(map[string]any{"kind": "issuer", "value": key, "reason": reason, "revokedAt": o.Now}); err != nil {
			return nil, err
		}
	}
	out := map[string]any{"ok": true, "record": record}
	if o.FreshAt != nil {
		tok, err := o.FreshAt.Advance(map[string]any{"revocation_epoch": record["epoch"]}, o.Now)
		if err != nil {
			return nil, err
		}
		out["freshAt"] = tok
	}
	return out, nil
}

func grantsPinMatches(pin, id any) bool {
	es := grantsEntries(pin)
	if len(es) == 0 {
		return false
	}
	for _, e := range es {
		iv, has := grantsGet(id, e.K)
		if !has || !grantsEq(iv, e.V) {
			return false
		}
	}
	return true
}

// grantsNamed is implemented by an error that carries a JavaScript-style error name.
type grantsNamed interface{ Name() string }

func grantsErrName(err error) string {
	var n grantsNamed
	if errors.As(err, &n) {
		return n.Name()
	}
	return "Error"
}

// AdmitWithEvidence admits from adapter evidence {ok, bound, identity?, reason?}: ok and bound must both be exactly true, and the
// identity the adapter established must match one runtime pin of the blueprint. An error from the evidence (or a panic), a
// malformed result or no pin is a denial. The result is {admitted: true, identity, pin} or {admitted: false, code, reason?}.
func AdmitWithEvidence(bp map[string]any, getEvidence func() (any, error)) map[string]any {
	deny := func(code string, reason ...string) map[string]any {
		r := map[string]any{"admitted": false, "code": code}
		if len(reason) > 0 {
			r["reason"] = reason[0]
		}
		return r
	}
	pins, _ := bp["runtime_pins"].([]any)
	if len(pins) == 0 {
		return deny("no_pins")
	}
	var r any
	var err error
	func() {
		defer func() {
			if recover() != nil {
				r, err = nil, errors.New("error")
			}
		}()
		r, err = getEvidence()
	}()
	if err != nil {
		return deny("verifier_error", grantsErrName(err))
	}
	m, _ := r.(map[string]any)
	if m["ok"] != true {
		if s, ok := m["reason"].(string); ok {
			return deny("not_ok", s)
		}
		return deny("not_ok")
	}
	if m["bound"] != true {
		return deny("not_bound")
	}
	switch m["identity"].(type) {
	case map[string]any, []any:
	default:
		return deny("no_identity")
	}
	for _, p := range pins {
		if grantsPinMatches(p, m["identity"]) {
			return map[string]any{"admitted": true, "identity": m["identity"], "pin": p}
		}
	}
	return deny("no_matching_pin")
}

// AdmitBlueprintInstance admits through a hardware attestation verifier: verify receives {document, ctx, nowMs, expected} and
// returns {ok, bound, measured?, reason?}. No pins or no evidence is a denial.
func AdmitBlueprintInstance(bp map[string]any, document any, verify func(in map[string]any) (any, error), nowMs, ctx, expected any) map[string]any {
	if pins, _ := bp["runtime_pins"].([]any); len(pins) == 0 {
		return map[string]any{"admitted": false, "code": "no_pins"}
	}
	if document == nil {
		return map[string]any{"admitted": false, "code": "not_ok", "reason": "no evidence"}
	}
	return AdmitWithEvidence(bp, func() (any, error) {
		h, err := verify(map[string]any{"document": document, "ctx": ctx, "nowMs": nowMs, "expected": expected})
		if err != nil {
			return nil, err
		}
		hm, _ := h.(map[string]any)
		ev := map[string]any{"ok": hm["ok"] == true, "bound": hm["bound"] == true}
		if jsTruthy(hm["measured"]) {
			ev["identity"] = hm["measured"]
		}
		if s, ok := hm["reason"].(string); ok {
			ev["reason"] = s
		}
		return ev, nil
	})
}

// AdmissionRegistry holds admissions by instance key, blueprint key and the blueprint EPOCH they were made under, so a group kill
// or any new record invalidates them; they also expire. Plug Checker(now) into CheckBlueprints as `admitted`.
type AdmissionRegistry struct{ m map[string][2]any }

// NewAdmissionRegistry returns an empty registry.
func NewAdmissionRegistry() *AdmissionRegistry { return &AdmissionRegistry{m: map[string][2]any{}} }

func grantsAdmKey(bpKey any, instance string) string { return jsValueString(bpKey) + "\x00" + instance }

// Admit records an admission made under bp (its epoch) valid until `until` (epoch ms).
func (a *AdmissionRegistry) Admit(instanceKey string, bp map[string]any, until any) error {
	if bp == nil {
		return errors.New("admit: no blueprint")
	}
	a.m[grantsAdmKey(bp["key"], instanceKey)] = [2]any{bp["epoch"], until}
	return nil
}

// Revoke removes an admission; true when there was one.
func (a *AdmissionRegistry) Revoke(instanceKey, bpKey string) bool {
	k := grantsAdmKey(bpKey, instanceKey)
	_, had := a.m[k]
	delete(a.m, k)
	return had
}

// Checker is true only for an unexpired admission made under the record's current epoch.
func (a *AdmissionRegistry) Checker(now any) func(instanceKey string, bp map[string]any) bool {
	return func(instanceKey string, bp map[string]any) bool {
		e, has := a.m[grantsAdmKey(bp["key"], instanceKey)]
		return has && grantsEq(e[0], bp["epoch"]) && finite(jsF(now)) && jsF(now) < jsF(e[1])
	}
}
