package pca

// Natively signed Intent Layer v2 fixture (no TypeScript): a site-signed action schema, a principal-signed session
// root S, the session grant G_0 (envelope with the v2 goal + the intent_session caveat), a PCActn carrying `intent`
// and `intent_session`, and the verifier context (`context.intent_v2`). Helpers sign accumulator receipts, sequencer
// key sets, revocation epochs with sorted-Merkle non-membership proofs, and the W-B artifacts, all per the reference
// formats (intent-acc.ts, intent-session.ts, revocation.ts, intent-artifacts.ts).

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
)

const (
	v2Now = int64(1_800_000_000_000)
	v2Aud = "skyair.example"
)

func dg(label string) string { return b64.EncodeToString(sha([]byte("v2fx/" + label))) }

func signDomain(t *testing.T, k fxKey, domain string, body any) string {
	t.Helper()
	b, err := canonBytes(body)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	return b64.EncodeToString(ed25519.Sign(k.priv, append([]byte(domain), b...)))
}

// signArt signs a W-B artifact (sig over domain || canonical(artifact without sig)).
func signArt(t *testing.T, k fxKey, domain string, a map[string]any) map[string]any {
	t.Helper()
	a["sig"] = signDomain(t, k, domain, withoutKeys(a, "sig"))
	return a
}

func refOf(t *testing.T, domain, slot string, a any) string {
	t.Helper()
	r, ok := artifactRef(domain, slot, deep(t, a))
	if !ok {
		t.Fatal("artifact ref")
	}
	return r
}

type v2fx struct {
	t                        *testing.T
	principal, site, agent   fxKey
	seqRoot, seqKey          fxKey
	revAuth                  fxKey
	committed                bool
	session, mapD, ref, salt string
	schema                   map[string]any
	schemaD                  string
	S                        map[string]any
	R                        string
	grant                    map[string]any
	params                   map[string]any
	p                        map[string]any
	ctx                      map[string]any
	now                      int64
}

func v2Schema() map[string]any {
	return map[string]any{
		"v": jnum(1), "kind": "pca-action-schema", "site": "https://skyair.example", "aud": v2Aud, "version": "2026-10-01",
		"units": map[string]any{"usd_cents": map[string]any{"kind": "money", "currency": "USD", "exponent": jnum(2)}},
		"verbs": []any{map[string]any{
			"verb": "air.book", "kind": "write",
			"params": map[string]any{
				"action.params.offer_id":   map[string]any{"type": "string", "semantic": "product.ref", "sensitivity": "material"},
				"action.params.total":      map[string]any{"type": "integer", "unit": "usd_cents", "min": jnum(0), "max": jnum(5_000_000), "semantic": "money.amount", "sensitivity": "critical", "accumulates_into": []any{"spend.usd_cents"}},
				"action.params.add_ons":    map[string]any{"type": "set", "values": []any{"none", "tripshield", "seat_plus"}, "semantic": "product.addon", "sensitivity": "material"},
				"action.params.refundable": map[string]any{"type": "boolean", "semantic": "flag", "sensitivity": "material"},
				"action.params.note":       map[string]any{"type": "string", "semantic": "text.note", "sensitivity": "free", "required": false, "max_len": jnum(16)},
			},
		}},
	}
}

func tripAcc() map[string]any {
	return map[string]any{"id": "trip_spend", "agg": "sum", "unit": "usd_cents", "sel": map[string]any{"accumulates_into": "spend.usd_cents"},
		"win": map[string]any{"kind": "task"}, "key": nil, "domain_max": jnum(500_000), "holder": map[string]any{"kind": "site_local"}}
}

// newV2Fx builds an allowed G_0 action: total 38900 into trip_spend (pre 0).
func newV2Fx(t *testing.T) *v2fx {
	f := &v2fx{t: t, principal: newKey(t), site: newKey(t), agent: newKey(t), revAuth: newKey(t), seqRoot: newKey(t), seqKey: newKey(t), now: v2Now}
	f.session, f.mapD, f.ref, f.salt = dg("session"), dg("map0"), dg("ref"), "salt0"
	f.schema = v2Schema()
	f.signSchema()
	f.S = map[string]any{
		"v": jnum(1), "kind": "pca-intent-session", "session": f.session, "principals": []any{map[string]any{"key": f.principal.id}},
		"intent_ref": f.ref, "schema": map[string]any{"aud": v2Aud, "digest": f.schemaD}, "layers": map[string]any{"task": map[string]any{"map_digest": f.mapD}},
		"accumulators": []any{tripAcc()}, "monitors": []any{}, "question_uri": "https://atlas.example/q", "expires_at": jnum(v2Now + 86_400_000),
	}
	f.signRoot()
	f.params = map[string]any{"offer_id": "OF-1", "total": jnum(38_900), "add_ons": []any{"none"}, "refundable": false}
	f.mint(0, "")
	f.p["intent_session"] = map[string]any{"session": f.session, "root": f.R, "seq": jnum(0), "schema": f.schemaD,
		"acc": []any{map[string]any{"id": "trip_spend", "post": jnum(38_900)}}}
	f.resign()
	f.ctx = map[string]any{
		"params":  f.params,
		"schema":  map[string]any{"docs": []any{f.schema}, "keys": []any{map[string]any{"kid": "k1", "alg": "ed25519", "pk": f.site.id}}},
		"session": map[string]any{"root": f.S, "grants": []any{}},
		"acc":     map[string]any{"state": map[string]any{"trip_spend": map[string]any{"sum": jnum(0)}}, "monitors": map[string]any{}},
	}
	return f
}

func (f *v2fx) signSchema() {
	delete(f.schema, "sig")
	v := signDomain(f.t, f.site, actionSchemaDomain, f.schema)
	f.schema["sig"] = map[string]any{"alg": "ed25519", "kid": "k1", "value": v}
	d, ok := actionSchemaDigest(deep(f.t, f.schema))
	if !ok {
		f.t.Fatal("schema digest")
	}
	f.schemaD = d
}

// signRoot (re)signs S with the principal and recomputes its digest.
func (f *v2fx) signRoot() { f.signRootWith(f.principal) }

func (f *v2fx) signRootWith(k fxKey) {
	delete(f.S, "sig")
	f.S["signer"] = k.id
	body := withoutKeys(f.S, "sig")
	f.S["sig"] = signDomain(f.t, k, intentSessionSigDomain, body)
	r, ok := sessionRootDigest(deep(f.t, f.S))
	if !ok {
		f.t.Fatal("root digest")
	}
	f.R = r
}

// sessionGrant mints a principal-signed root capability: envelope (v2 goal) + intent_session caveat.
func (f *v2fx) sessionGrant(issuer fxKey, seq int64, prev, mapD, salt string) map[string]any {
	gc, err := intentGoalCommitV2(f.session, mapD, salt, f.committed)
	if err != nil {
		f.t.Fatal(err)
	}
	sc := map[string]any{"type": "intent_session", "session": f.session, "seq": jnum(seq), "root": f.R}
	if prev != "" {
		sc["prev"] = prev
	}
	env := map[string]any{"type": "envelope", "goal_commit": gc, "predicates": []any{}, "caveats": []any{}}
	return mkCap(f.t, issuer, f.agent.id, []any{env, sc}, "", nil)
}

// mint makes the PCActn under a fresh session grant at seq (prev = id of the previous grant) for f.params.
func (f *v2fx) mint(seq int64, prev string) {
	f.grant = f.sessionGrant(f.principal, seq, prev, f.mapD, f.salt)
	f.build()
}

func (f *v2fx) build() {
	pd, err := ParamsDigest(f.params)
	if err != nil {
		f.t.Fatal(err)
	}
	action := map[string]any{"verb": "air.book", "resource": "skyair.example/bookings", "params_digest": pd, "reversibility_class": "irreversible"}
	cond, _ := conditionsDigest(nil, nil)
	leaves := make([]any, 3)
	for i := range leaves {
		l, _ := planLeaf(fmt.Sprintf("n%d", i), action, cond)
		leaves[i] = l
	}
	hs := leafHashes(f.t, leaves)
	sides, sib := treeProof(hs, 1)
	root, _ := MerkleRoot(leaves)
	old := f.p
	f.p = map[string]any{
		"ver": jnum(2), "action": action, "grant_ref": f.grant["id"], "cap_chain": []any{f.grant},
		"plan":        map[string]any{"root": root, "node_id": "n1", "inclusion_proof": proofMap(sides, sib, 1, 3)},
		"attestation": map[string]any{"epoch": jnum(1), "quote_digest": "q", "model_id": "m", "measurement": "x", "operator": "o"},
		"provenance":  map[string]any{"causal_hash": "h", "taint_level": jnum(0), "trusted_refs": []any{"r"}},
		"freshness":   map[string]any{"beacon_ref": "b", "accumulator_witness": "w", "epoch": jnum(1)},
		"counter":     jnum(1), "risk_claim": map[string]any{"r": json.Number("0.5"), "inputs": map[string]any{}},
		"aud": v2Aud, "iat": jnum(v2Now - 1_000), "exp": jnum(v2Now + 600_000),
		"intent": map[string]any{"ref": f.ref, "map_digest": f.mapD, "goal_salt": f.salt, "fidelity_ppm": jnum(1_000_000), "residual_risk_ppm": jnum(0)},
	}
	if old != nil {
		if is, ok := old["intent_session"]; ok {
			f.p["intent_session"] = is
		}
	}
	f.resign()
}

func (f *v2fx) resign() {
	f.t.Helper()
	msg, err := ThresholdMessage(deepM(f.t, f.p))
	if err != nil {
		f.t.Fatal(err)
	}
	f.p["sig"] = b64.EncodeToString(ed25519.Sign(f.agent.priv, msg))
}

func (f *v2fx) is() map[string]any { return f.p["intent_session"].(map[string]any) }

func (f *v2fx) setClaim(post int64) {
	f.is()["acc"] = []any{map[string]any{"id": "trip_spend", "post": jnum(post)}}
	f.resign()
}

// rebind re-points intent_session.root at the current S, re-mints the grant and re-signs.
func (f *v2fx) rebind() {
	f.is()["root"] = f.R
	f.mint(0, "")
	f.ctx["session"].(map[string]any)["root"] = f.S
}

func (f *v2fx) verify() Verdict {
	f.t.Helper()
	b, err := json.Marshal(f.ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	ctx, err := IntentV2ContextFromJSONText(string(b))
	if err != nil {
		f.t.Fatal(err)
	}
	v, err := VerifyPCActnCoreWith(f.p2(), deepM(f.t, f.grant), f.now, v2Aud, VerifyOptions{IntentV2: ctx})
	if err != nil {
		f.t.Fatal(err)
	}
	return v
}

func (f *v2fx) p2() map[string]any { return deepM(f.t, f.p) }

// ---- revocation sets and epochs ---------------------------------------------------------------------------------

type revSet struct {
	ids []string
}

func newRevSet(t *testing.T, ids ...string) *revSet {
	s := append([]string{}, ids...)
	sort.Strings(s) // ASCII ids: byte order == compareUtf8
	return &revSet{ids: s}
}

func (s *revSet) root(t *testing.T) string {
	r, ok := revsetRoot(s.ids)
	if !ok {
		t.Fatal("revset root")
	}
	return r
}

func (s *revSet) list() []any {
	out := make([]any, len(s.ids))
	for i, id := range s.ids {
		out[i] = id
	}
	return out
}

func (f *v2fx) epoch(signer fxKey, set *revSet, issued, notAfter int64) map[string]any {
	n := jnum(int64(len(set.ids)))
	body := map[string]any{"instance_id": "ana", "grant_ref": sessionRevocationScope(f.session), "epoch": n, "set_size": n,
		"root": set.root(f.t), "issued_at": jnum(issued), "not_after": jnum(notAfter)}
	ep := withoutKeys(body)
	ep["guardian"] = signer.id
	ep["sig"] = signDomain(f.t, signer, revEpochDomain, body)
	return ep
}

func (f *v2fx) revIDs() []string {
	return []string{sessionRevocationID(f.session), mapRevocationID(f.mapD), deltaRevocationID(f.grant["id"].(string))}
}

// evidence is {epoch, revoked}: the epoch signed by signer over the full sorted revoked list of set.
func (f *v2fx) evidence(signer fxKey, set *revSet, issued, notAfter int64) map[string]any {
	return map[string]any{"epoch": f.epoch(signer, set, issued, notAfter), "revoked": set.list()}
}

// withRevocation names the dedicated revocation authority in S (max age in seconds).
func (f *v2fx) withRevocation(maxAgeS int64) {
	f.S["revocation"] = map[string]any{"epoch_uri": "https://atlas.example/rev", "max_age_s": jnum(maxAgeS), "key": f.revAuth.id}
	f.signRoot()
	f.rebind()
}

// ---- sequenced accumulators -------------------------------------------------------------------------------------

func (f *v2fx) useSequenced() {
	a := tripAcc()
	a["holder"] = map[string]any{"kind": "sequenced", "uri": "https://atlas.example/seq", "root": f.seqRoot.id}
	f.S["accumulators"] = []any{a}
	f.signRoot()
	f.rebind()
}

func (f *v2fx) keySet(root fxKey, keys ...map[string]any) map[string]any {
	ks := make([]any, len(keys))
	for i, k := range keys {
		ks[i] = k
	}
	body := map[string]any{"v": jnum(1), "kind": "pca-sequencer-keys", "sequencer": root.id, "version": jnum(1), "issued_at": jnum(v2Now - 100), "keys": ks}
	out := withoutKeys(body)
	out["sig"] = signDomain(f.t, root, sequencerKeysDomain, body)
	return out
}

func keyEntry(kid string, k fxKey, notBefore int64, notAfter *int64) map[string]any {
	e := map[string]any{"kid": kid, "pk": k.id, "not_before": jnum(notBefore)}
	if notAfter != nil {
		e["not_after"] = jnum(*notAfter)
	}
	return e
}

func i64(x int64) *int64 { return &x }

// receipt signs a sum receipt pre 10000 + 38900 = 48900 for the current PCActn.
func (f *v2fx) receipt(k fxKey, kid string, mut func(r map[string]any)) map[string]any {
	rd, ok := pcactnReservationDigest(f.p2())
	if !ok {
		f.t.Fatal("reservation digest")
	}
	r := map[string]any{"v": jnum(1), "kind": "pca-acc-receipt", "session": f.session, "acc": "trip_spend", "seq": jnum(3), "pre": jnum(10_000),
		"delta": jnum(38_900), "post": jnum(48_900), "pcactn_digest": rd, "aud": v2Aud, "issued_at": jnum(v2Now), "expires_at": jnum(v2Now + 60_000),
		"kid": kid, "ledger": map[string]any{"index": jnum(7), "head": dg("head")}, "signer": k.id}
	if mut != nil {
		mut(r)
	}
	r["sig"] = signDomain(f.t, k, accReceiptDomain, receiptBody(r))
	return r
}

// claimReceipt sets the claim (post, receipt digest) and presents receipts + key sets.
func (f *v2fx) claimReceipt(r map[string]any, post int64, keySets []any, receipts ...map[string]any) {
	d, ok := accReceiptDigest(deep(f.t, r))
	if !ok {
		f.t.Fatal("receipt digest")
	}
	f.is()["acc"] = []any{map[string]any{"id": "trip_spend", "post": jnum(post), "receipt": d}}
	f.resign()
	rs := make([]any, len(receipts))
	for i, x := range receipts {
		rs[i] = x
	}
	f.ctx["acc"] = map[string]any{"receipts": rs, "monitors": map[string]any{}, "sequencer_keys": keySets}
}

// ---- assertions -------------------------------------------------------------------------------------------------

var coreChecks = []string{"wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter"}

// expectV2 asserts the exact v2 check set: every name in pass passes, every name in failNames fails, nothing else
// is reported beyond the core checks and `intent`.
func expectV2(t *testing.T, name string, v Verdict, pass []string, failNames ...string) {
	t.Helper()
	want := map[string]bool{}
	for _, c := range coreChecks {
		want[c] = true
	}
	want["intent"] = true
	for _, c := range pass {
		want[c] = true
	}
	for _, c := range failNames {
		want[c] = false
	}
	if len(v.Checks) != len(want) {
		t.Fatalf("%s: checks %v, want %v (%s)", name, v.Checks, want, v.Reason)
	}
	for k, w := range want {
		if g, has := v.Checks[k]; !has || g != w {
			t.Fatalf("%s: check %s = %v (present %v), want %v (%s)", name, k, g, has, w, v.Reason)
		}
	}
	if v.Allow != (len(failNames) == 0) {
		t.Fatalf("%s: allow = %v (%s)", name, v.Allow, v.Reason)
	}
	if len(failNames) > 0 && !strings.HasPrefix(v.Reason, failNames[0]+": ") {
		t.Fatalf("%s: first failure %q, want %s", name, v.Reason, failNames[0])
	}
}

var v2Base = []string{"schema", "intent_session", "accumulators"}

func minus(xs []string, drop ...string) []string {
	out := []string{}
	for _, x := range xs {
		if !contains(drop, x) {
			out = append(out, x)
		}
	}
	return out
}
