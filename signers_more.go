package pca

// More producers, byte for byte the reference's: threshold shares, PQ key bindings, caution claims, lease heartbeats, read
// receipts, mesh actions, intent session roots and session grants, action schemas, label receipts, facts, offer sets and
// policy templates / tighten overlays. Each runs the reference's checks before signing and refuses a suite this package
// cannot sign with ErrUnsupportedSigner.

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"unicode/utf16"
)

// ---- threshold shares ------------------------------------------------------------------------------------------------------

// ShareMessage is the bytes a role's threshold share signs:
// "atlas-pca/share/<role>\0" || sha256(message) || SignerSetHash(signerSet) || t || (for a non-ed25519 suite) the suite tag.
func ShareMessage(role string, message []byte, signerSet []any, t int, alg string) ([]byte, error) {
	if t != 1 && t != 2 && t != 3 {
		return nil, errors.New("ShareMessage: t must be 1, 2 or 3")
	}
	set, err := normList(signerSet)
	if err != nil {
		return nil, err
	}
	ssh, ok := SignerSetHash(set)
	if !ok {
		return nil, errors.New("ShareMessage: malformed signer set")
	}
	h := sha256.Sum256(message)
	out := append([]byte(shareDomainPrefix+role+"\x00"), h[:]...)
	out = append(append(out, ssh...), byte(t))
	if su, known := resolveSigAlg(alg, alg != ""); known && su.alg != "ed25519" {
		out = append(out, []byte(shareSuiteTag+su.alg)...)
	}
	return out, nil
}

// SignThresholdShare is a role's explicit threshold share over message, bound to the signer set and t it is for (every role,
// agent included). s nil: Ed25519; a PQ suite signs with s.Pq, which must be the pq_pk the set registers for the role.
func SignThresholdShare(role string, key *KeyPair, message []byte, signerSet []any, t int, s *SuiteOpts) (map[string]any, error) {
	m, err := ShareMessage(role, message, signerSet, t, s.alg())
	if err != nil {
		return nil, err
	}
	return SignPreparedShare(role, key, m, s)
}

// SignPreparedShare signs share bytes computed elsewhere (the share_message a step-up hands a principal device):
// {role, publicKey, sig} for Ed25519, plus alg (and pq_sig for a hybrid) under a PQ suite.
func SignPreparedShare(role string, key *KeyPair, prepared []byte, s *SuiteOpts) (map[string]any, error) {
	if key == nil {
		return nil, errors.New("SignPreparedShare: a share needs the role's Ed25519 key")
	}
	sig, pqSig, err := signWithSuite(s, key, prepared)
	if err != nil {
		return nil, err
	}
	share := map[string]any{"role": role, "publicKey": key.Public, "sig": sig}
	if su, _ := resolveSigAlg(s.alg(), true); su.alg != "ed25519" { // signWithSuite resolved it
		share["alg"] = su.alg
		if pqSig != "" {
			share["pq_sig"] = pqSig
		}
	}
	return share, nil
}

// ---- PQ key binding ----------------------------------------------------------------------------------------------------------

const pqBindDomain = "atlas-pca/pq-binding/v2\x00"

// SignPqBinding is an identity's signed statement that pqPk is its PQ key as of epoch (a positive integer it raises on every
// rotation) for the audience aud: {ed, pq, epoch, aud, sig}, sig = Ed25519 over domain || "ed\0pq\0epoch\0aud".
func SignPqBinding(ed *KeyPair, pqPk string, epoch int64, aud string) (map[string]any, error) {
	if epoch < 1 || epoch > maxSafeInt {
		return nil, errors.New("SignPqBinding: epoch must be a positive safe integer")
	}
	if aud == "" {
		return nil, errors.New("SignPqBinding: aud (the instance/audience id) is required")
	}
	msg := pqBindDomain + ed.Public + "\x00" + pqPk + "\x00" + strconv.FormatInt(epoch, 10) + "\x00" + aud
	return map[string]any{"ed": ed.Public, "pq": pqPk, "epoch": epoch, "aud": aud, "sig": b64.EncodeToString(ed.Sign([]byte(msg)))}, nil
}

// ---- caution claim, lease heartbeat ------------------------------------------------------------------------------------------

var cautionReasonRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)

// msgOfDB is canonical({d: domain, b: body}), the message of the agent-native artifacts.
func msgOfDB(domain string, body map[string]any) ([]byte, error) {
	return canonBytes(map[string]any{"d": domain, "b": body})
}

// SignCaution signs a holder's caution claim {action_digest, caution in [0,1], reason?, holder}: the caution is bound to one
// action and can only raise server-side risk.
func SignCaution(holder *KeyPair, body map[string]any) (map[string]any, error) {
	b, err := normObj(body)
	if err != nil {
		return nil, err
	}
	if e := cautionBodyError(b); e != "" {
		return nil, errors.New("SignCaution: " + e)
	}
	clean := map[string]any{"action_digest": b["action_digest"], "caution": b["caution"], "holder": b["holder"]}
	if r, has := b["reason"]; has {
		clean["reason"] = r
	}
	m, err := msgOfDB("atlas-pca/caution/v1", clean)
	if err != nil {
		return nil, err
	}
	clean["sig"] = b64.EncodeToString(holder.Sign(m))
	return clean, nil
}

func cautionBodyError(b map[string]any) string {
	if s, ok := b["action_digest"].(string); !ok || s == "" {
		return "action_digest required"
	}
	if s, ok := b["holder"].(string); !ok || s == "" {
		return "holder required"
	}
	if c, ok := numOf(b["caution"]); !ok || c < 0 || c > 1 {
		return "caution must be a finite number in [0,1]"
	}
	if r, has := b["reason"]; has {
		if s, ok := r.(string); !ok || len(s) > 64 || !cautionReasonRe.MatchString(s) {
			return "invalid reason"
		}
	}
	return ""
}

// SignHeartbeat signs a lease heartbeat {cap_id, seq, at, holder, lease_issued_at} as the lease holder (other members dropped).
func SignHeartbeat(holder *KeyPair, body map[string]any) (map[string]any, error) {
	b, err := normObj(body)
	if err != nil {
		return nil, err
	}
	clean := map[string]any{}
	for _, k := range []string{"cap_id", "seq", "at", "holder", "lease_issued_at"} {
		if v, has := b[k]; has { // an absent member stays absent (undefined in the reference), never null
			clean[k] = v
		}
	}
	m, err := msgOfDB("atlas-pca/lease-hb/v2", clean)
	if err != nil {
		return nil, err
	}
	clean["sig"] = b64.EncodeToString(holder.Sign(m))
	return clean, nil
}

// ---- read receipt ---------------------------------------------------------------------------------------------------------------

// SignReadReceipt is the resource server's receipt of one redacted read under grant (a read grant body): fields and labels are
// what RedactRead reported; prev is the previous receipt of the chain (nil: the first, seq 0).
func SignReadReceipt(rs *KeyPair, grant map[string]any, verb, resource, purpose string, fields map[string]any, labels []string, issuedAt int64, prev map[string]any) (map[string]any, error) {
	g, err := normObj(grant)
	if err != nil {
		return nil, err
	}
	gd, _ := ReadGrantDigest(g) // g is normalized: it always hashes
	seq, ref := any(0), any(nil)
	if prev != nil {
		p, err := normObj(prev)
		if err != nil {
			return nil, err
		}
		ps, ok := safeInt(p["seq"])
		if !ok {
			return nil, errors.New("SignReadReceipt: malformed previous receipt")
		}
		seq = ps + 1
		ref, _ = ReadReceiptRef(p)
	}
	ls := make([]any, len(labels))
	for i, l := range labels {
		ls[i] = l
	}
	base, err := normObj(map[string]any{"v": 1, "grant": gd, "verb": verb, "resource": resource, "purpose": purpose, "seq": seq, "prev": ref,
		"fields": fields, "labels": ls, "issued_at": issuedAt, "signer": rs.Public})
	if err != nil {
		return nil, err
	}
	sig, err := signBody(rs, k5ReadReceiptDomain, base)
	if err != nil {
		return nil, err
	}
	base["sig"] = sig
	return base, nil
}

// ---- mesh ------------------------------------------------------------------------------------------------------------------------

// SignMeshAction is the leaf holder's signature over the action bound to the chain tip:
// Ed25519 over "atlas-pca/mesh-action/v1\0" || canonical({action, tip: capHash(tip)}).
func SignMeshAction(chain []map[string]any, action map[string]any, leaf *KeyPair) (string, error) {
	if len(chain) == 0 {
		return "", errors.New("SignMeshAction: empty chain")
	}
	tip, err := normObj(chain[len(chain)-1])
	if err != nil {
		return "", err
	}
	a, err := normObj(action)
	if err != nil {
		return "", err
	}
	th, _ := CapHash(tip) // tip is normalized: it always hashes
	m, ok := meshMsg(meshActionDomain, map[string]any{"action": a, "tip": th})
	if !ok {
		return "", errors.New("SignMeshAction: the action is not canonicalizable")
	}
	return b64.EncodeToString(leaf.Sign(m)), nil
}

// AssembleMeshProof builds the compact mesh proof: hops issued against the same head share one heads entry (their witness
// cosignatures merged), identical revocation bracketing leaves are carried once, and the leaf signs the action. hops are the
// per-hop evidence {domain, head: {head, sig, cosigs}, inclusion, revocation: {cap, issuer_key}, binding?}; pinProofs
// (optional) are {domain, proof}. shortcut: entries are deduplicated by canonical JSON where the reference compares
// JSON.stringify text, so two inputs that differ only in member order merge here and not there; evidence from one mesh
// domain never does.
func AssembleMeshProof(chain []map[string]any, hops []map[string]any, action map[string]any, leaf *KeyPair, pinProofs []any) (map[string]any, error) {
	heads := []any{}
	headIdx := map[string]int{}
	leaves := []any{}
	leafIdx := map[string]int{}
	leafOf := func(l any) (int, error) {
		k, err := Canonicalize(l)
		if err != nil {
			return 0, err
		}
		i, has := leafIdx[k]
		if !has {
			i = len(leaves)
			leaves = append(leaves, l)
			leafIdx[k] = i
		}
		return i, nil
	}
	compact := func(nv any) (map[string]any, error) {
		n, _ := nv.(map[string]any)
		out := map[string]any{"size": n["size"]}
		for _, side := range []string{"lo", "hi"} {
			if l, has := n[side]; has && l != nil {
				i, err := leafOf(l)
				if err != nil {
					return nil, err
				}
				out[side] = i
			}
		}
		return out, nil
	}
	outHops := make([]any, 0, len(hops))
	for _, raw := range hops {
		ev, err := normObj(raw)
		if err != nil {
			return nil, err
		}
		h, ok := ev["head"].(map[string]any)
		if !ok {
			return nil, errors.New("AssembleMeshProof: hop evidence needs a cosigned head")
		}
		hk, err := Canonicalize(h["head"])
		if err != nil {
			return nil, err
		}
		key := fmt.Sprint(h["sig"]) + "|" + hk
		cosigs, _ := h["cosigs"].([]any)
		i, has := headIdx[key]
		if !has {
			i = len(heads)
			heads = append(heads, map[string]any{"head": h["head"], "sig": h["sig"], "cosigs": append([]any{}, cosigs...)})
			headIdx[key] = i
		} else {
			hm := heads[i].(map[string]any)
			seen := map[any]bool{}
			for _, c := range hm["cosigs"].([]any) {
				if cm, ok := c.(map[string]any); ok {
					seen[cm["witness"]] = true
				}
			}
			for _, c := range cosigs {
				if cm, ok := c.(map[string]any); ok && !seen[cm["witness"]] {
					hm["cosigs"] = append(hm["cosigs"].([]any), c)
				}
			}
		}
		rev, _ := ev["revocation"].(map[string]any)
		rc, err := compact(rev["cap"])
		if err != nil {
			return nil, err
		}
		rk, err := compact(rev["issuer_key"])
		if err != nil {
			return nil, err
		}
		out := map[string]any{"domain": ev["domain"], "head": i, "inclusion": ev["inclusion"], "revocation": map[string]any{"cap": rc, "issuer_key": rk}}
		if b, has := ev["binding"]; has && b != nil {
			out["binding"] = b
		}
		outHops = append(outHops, out)
	}
	sig, err := SignMeshAction(chain, action, leaf)
	if err != nil {
		return nil, err
	}
	ch := make([]any, len(chain))
	for i, c := range chain {
		ch[i] = c
	}
	proof := map[string]any{"chain": ch, "heads": heads, "rev_leaves": leaves, "hops": outHops, "action": action, "action_sig": sig}
	if len(pinProofs) > 0 {
		proof["pin_proofs"] = pinProofs
	}
	return normObj(proof)
}

// ---- intent session root and session grants ---------------------------------------------------------------------------------

var sessionRootUnsignedKeys = []string{"v", "kind", "session", "principals", "intent_ref", "schema", "layers", "accumulators", "monitors",
	"question_uri", "revocation", "flows", "expires_at"}

// SignSessionRoot signs the session root S as one of its principals (the signer's Ed25519 identity must be listed in
// principals). A non-ed25519 suite binds alg and pq_pk into the signed body.
func SignSessionRoot(principal *KeyPair, body map[string]any, s *SuiteOpts) (map[string]any, error) {
	b, err := normObj(body)
	if err != nil {
		return nil, err
	}
	if k, ok := firstUnknownKey(b, sessionRootUnsignedKeys); !ok {
		return nil, errors.New("SignSessionRoot: session root: unknown member '" + k + "'")
	}
	base := sessionRootBody(b)
	base["signer"] = principal.Public
	probe, err := bindSuite(base, s)
	if err != nil {
		return nil, err
	}
	probe["sig"] = ""
	if bad := sessionRootShape(probe); bad == "signer is not one of the session principals" {
		return nil, errors.New("SignSessionRoot: the signer is not one of the session principals")
	} else if bad != "" {
		return nil, errors.New("SignSessionRoot: " + bad)
	}
	return SignArtifact(intentSessionSigDomain, base, principal, s)
}

// SessionGrantInput is what MintSessionGrant mints G_0 (Seq 0) or a delta grant D_k (Seq k) from.
type SessionGrantInput struct {
	Principal *KeyPair
	Holder    string
	HolderPq  string // the holder's PQ public key ("" for none), committed as holder_pq
	Session   string
	Seq       int64
	Prev      string // id of D_{k-1} (or G_0); required exactly when Seq > 0
	Root      string // the session root's digest
	MapDigest string // the task map digest (the map commitment when MapForm is "commit")
	MapForm   string // "" or "commit"
	// Predicates and Caveats of the envelope; AgentBinding (nil: {}) and RiskPolicy (nil: DefaultRiskPolicy()).
	Predicates   []any
	Caveats      []any
	AgentBinding map[string]any
	RiskPolicy   map[string]any
	Salt         string // "" draws 16 random bytes
	Suite        *SuiteOpts
}

// MintSessionGrant mints a session grant: a principal-signed root capability whose caveats are the envelope (goal
// "pca-intent:v2:<session>:<map_digest>", or v2c over a committed map) and the intent_session caveat. It returns the grant and
// the goal salt (the PCActn's intent.goal_salt).
func MintSessionGrant(in SessionGrantInput) (grant map[string]any, goalSalt string, err error) {
	sc := map[string]any{"type": intentSessionCaveat, "session": in.Session, "seq": in.Seq, "root": in.Root}
	if in.Prev != "" {
		sc["prev"] = in.Prev
	}
	scn, err := normObj(sc)
	if err != nil {
		return nil, "", err
	}
	if bad := intentSessionCaveatError(scn); bad != "" {
		return nil, "", errors.New("MintSessionGrant: " + bad)
	}
	if !isDigestV(in.MapDigest) {
		return nil, "", errors.New("MintSessionGrant: mapDigest must be canonical base64url (32 bytes)")
	}
	salt := in.Salt
	if salt == "" {
		salt = randNonce()
	}
	commit, err := intentGoalCommitV2(in.Session, in.MapDigest, salt, in.MapForm == "commit")
	if err != nil {
		return nil, "", err
	}
	env := map[string]any{"type": envelopeCaveat, "goal_commit": commit, "predicates": in.Predicates, "caveats": in.Caveats,
		"agent_binding": in.AgentBinding, "risk_policy": in.RiskPolicy}
	if in.Predicates == nil {
		env["predicates"] = []any{}
	}
	if in.Caveats == nil {
		env["caveats"] = []any{}
	}
	if in.AgentBinding == nil {
		env["agent_binding"] = map[string]any{}
	}
	if in.RiskPolicy == nil {
		env["risk_policy"] = DefaultRiskPolicy()
	}
	envN, err := normObj(env)
	if err != nil {
		return nil, "", err
	}
	g, err := MintRoot(in.Principal, in.Holder, []any{envN, scn}, in.HolderPq, in.Suite)
	if err != nil {
		return nil, "", err
	}
	return g, salt, nil
}

// ---- site and oracle artifacts --------------------------------------------------------------------------------------------------

// SignActionSchema signs an action schema as the site: kid names the discovery key entry. The signature covers
// "atlas-pca/action-schema/v1\0" || canonical(doc) and lands in sig: {alg, kid, value, pq_value?}.
func SignActionSchema(doc map[string]any, kid string, site *KeyPair, s *SuiteOpts) (map[string]any, error) {
	d, err := normObj(doc)
	if err != nil {
		return nil, err
	}
	if bad := actionSchemaShapeError(d, false); bad != "" {
		return nil, errors.New("SignActionSchema: " + bad)
	}
	su, known := resolveSigAlg(s.alg(), true)
	if !known {
		return nil, fmt.Errorf("SignActionSchema: unknown signature alg %q", s.alg())
	}
	cb, err := canonBytes(d)
	if err != nil {
		return nil, err
	}
	value, pqValue, err := signWithSuite(s, site, append([]byte(actionSchemaDomain), cb...))
	if err != nil {
		return nil, err
	}
	sig := map[string]any{"alg": su.alg, "kid": kid, "value": value}
	if pqValue != "" {
		sig["pq_value"] = pqValue
	}
	d["sig"] = sig
	return d, nil
}

// SignLabels signs a label receipt (site side): {v: 1, kind: "pca-labels", ...body} under the suite.
func SignLabels(body map[string]any, key *KeyPair, s *SuiteOpts) (map[string]any, error) {
	return signKinded(labelsDomain, "pca-labels", body, key, s)
}

// SignFact signs an oracle fact: {v: 1, kind: "pca-fact", ...body} under the suite.
func SignFact(body map[string]any, key *KeyPair, s *SuiteOpts) (map[string]any, error) {
	return signKinded(factDomain, "pca-fact", body, key, s)
}

// SignOfferSet signs an offer set (site side) under the suite.
func SignOfferSet(body map[string]any, key *KeyPair, s *SuiteOpts) (map[string]any, error) {
	return SignArtifact(offerSetDomain, body, key, s)
}

func signKinded(domain, kind string, body map[string]any, key *KeyPair, s *SuiteOpts) (map[string]any, error) {
	full := map[string]any{"v": 1, "kind": kind}
	for k, v := range body { // body members win, as in the reference's spread
		full[k] = v
	}
	return SignArtifact(domain, full, key, s)
}

// ---- policy templates ------------------------------------------------------------------------------------------------------------

// SignTemplate signs a policy template definition as the organisation: {def, signer, sig}, sig over
// "atlas-pca/policy-template/v1\0" || sha256(templateDigest(def)).
func SignTemplate(def map[string]any, key *KeyPair) (map[string]any, error) {
	d, err := normObj(def)
	if err != nil {
		return nil, err
	}
	if e := TemplateDefError(d); e != "" {
		return nil, errors.New("SignTemplate: " + e)
	}
	digest, _ := TemplateDigest(d) // d is normalized: it always hashes
	return map[string]any{"def": d, "signer": key.Public, "sig": b64.EncodeToString(key.Sign(linkMessage(templateSigDomain, digest)))}, nil
}

// SignTighten signs a tighten overlay (it may only add where conditions and caveats): {overlay, signer, sig}.
func SignTighten(overlay map[string]any, key *KeyPair) (map[string]any, error) {
	o, err := normObj(overlay)
	if err != nil {
		return nil, err
	}
	if e := TightenOverlayError(o); e != "" {
		return nil, errors.New("SignTighten: " + e)
	}
	digest, _ := HashCanonical(o)
	return map[string]any{"overlay": o, "signer": key.Public, "sig": b64.EncodeToString(key.Sign(linkMessage(tightenSigDomain, digest)))}, nil
}

// ---- intent-required questions (site side) and progress steps (holder side) -------------------------------------------------

const intentRequiredDomain = "atlas-pca/intent-required/v1\x00"

// ProgressSigDomain separates a signed progress step's message.
const ProgressSigDomain = "atlas-pca/progress-step/v2"

var (
	intentRequiredKeys = map[string]bool{"v": true, "kind": true, "session": true, "map_digest": true, "schema": true, "pcactn_digest": true,
		"action_digest": true, "cell": true, "reason": true, "question_id": true, "friction": true, "delivered_to": true, "expires_at": true, "sig": true}
	questionIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// jsSafeInt is a JSON integer the reference accepts: a safe integer, not -0.
func jsSafeInt(v any) (int64, bool) {
	n, ok := safeInt(v)
	if !ok || n > maxSafeInt || n < -maxSafeInt || string(v.(json.Number)) == "-0" {
		return 0, false
	}
	return n, true
}

// shortcut: with several bad coordinates the first error follows sorted key order, not the reference's insertion order; a
// body with one bad coordinate reports the same text.
func cellCoordsError(c any) string {
	m, ok := c.(map[string]any)
	if !ok || len(m) == 0 || len(m) > 64 {
		return "coords must be an object of 1..64 dimensions"
	}
	for _, k := range sortedKeysStd(m) {
		if n := len(utf16.Encode([]rune(k))); n == 0 || n > 256 {
			return "a coordinate path must be 1..256 characters"
		}
		l, _ := m[k].([]any)
		if lo, hi, isRange := coordRange(l); isRange {
			if !(lo >= 0 && lo <= hi) {
				return fmt.Sprintf("coords '%s': need 0 <= lo <= hi", k)
			}
			continue
		}
		if m[k] == nil || len(l) == 0 || len(l) > 256 {
			return fmt.Sprintf("coords '%s': an index range [lo, hi] or a value set", k)
		}
		seen := map[string]bool{}
		for _, x := range l {
			sx, ok := x.(string)
			if !ok {
				return fmt.Sprintf("coords '%s': an index range [lo, hi] or a value set", k)
			}
			if seen[sx] {
				return fmt.Sprintf("coords '%s': values must be distinct", k)
			}
			seen[sx] = true
		}
	}
	return ""
}

func coordRange(l []any) (lo, hi int64, ok bool) {
	if len(l) != 2 {
		return 0, 0, false
	}
	lo, ok1 := jsSafeInt(l[0])
	hi, ok2 := jsSafeInt(l[1])
	return lo, hi, ok1 && ok2
}

// IntentRequiredShapeError is the reference's shape check of an UNSIGNED pca-intent-required v1 body ("" when well-formed).
func IntentRequiredShapeError(body any) string {
	b, ok := body.(map[string]any)
	if !ok {
		return "not an object"
	}
	for _, k := range sortedKeysStd(b) {
		if !intentRequiredKeys[k] {
			return "unknown member '" + k + "'"
		}
	}
	if v, ok := jsSafeInt(b["v"]); !ok || v != 1 || b["kind"] != "pca-intent-required" {
		return "not a pca-intent-required v1"
	}
	for _, k := range []string{"session", "map_digest", "schema", "pcactn_digest", "action_digest"} {
		if !b64uOK(b[k], 32) {
			return k + " must be canonical base64url (32 bytes)"
		}
	}
	cell, ok := b["cell"].(map[string]any)
	verb, _ := cell["verb"].(string)
	_, hasCoords := cell["coords"]
	if !ok || len(cell) != 2 || !hasCoords || verb == "" {
		return "cell must be {verb, coords}"
	}
	if e := cellCoordsError(cell["coords"]); e != "" {
		return e
	}
	if b["reason"] != "uncertain" {
		return "reason must be 'uncertain'"
	}
	if q, ok := b["question_id"].(string); !ok || !questionIDRe.MatchString(q) {
		return "question_id must match [A-Za-z0-9_-]{1,64}"
	}
	if f, _ := b["friction"].(string); f != "tap" && f != "hold" && f != "typed" && f != "device" {
		return "unknown friction tier"
	}
	if b["delivered_to"] != "wallet" && b["delivered_to"] != "agent" {
		return "delivered_to must be 'wallet' or 'agent'"
	}
	if e, ok := jsSafeInt(b["expires_at"]); !ok || e < 0 {
		return "expires_at must be a non-negative safe integer"
	}
	if _, has := b["sig"]; has {
		return "an unsigned body must not carry sig"
	}
	return ""
}

// SignIntentRequired signs a site's pca-intent-required v1 question: sig = {alg, kid, value, pq_value?} over
// utf8(domain) || canonical(body), pinned by the same discovery key entry as the action schema.
func SignIntentRequired(body map[string]any, kid string, site *KeyPair, s *SuiteOpts) (map[string]any, error) {
	d, err := normObj(body)
	if err != nil {
		return nil, err
	}
	if bad := IntentRequiredShapeError(d); bad != "" {
		return nil, errors.New("SignIntentRequired: " + bad)
	}
	su, known := resolveSigAlg(s.alg(), true)
	if !known {
		return nil, fmt.Errorf("SignIntentRequired: unknown signature alg %q", s.alg())
	}
	cb, err := canonBytes(d)
	if err != nil {
		return nil, err
	}
	value, pqValue, err := signWithSuite(s, site, append([]byte(intentRequiredDomain), cb...))
	if err != nil {
		return nil, err
	}
	sig := map[string]any{"alg": su.alg, "kid": kid, "value": value}
	if pqValue != "" {
		sig["pq_value"] = pqValue
	}
	d["sig"] = sig
	return d, nil
}

// SignProgressStep signs a progress step as its holder: {step, holder, sig}, Ed25519 over the domain-separated binding of the
// step to the holder, goal, action, before/after state, sequence, chain link and step digest.
func SignProgressStep(step map[string]any, holder *KeyPair) (map[string]any, error) {
	st, err := normObj(step)
	if err != nil {
		return nil, err
	}
	b := map[string]any{"holder": holder.Public}
	for _, k := range [][2]string{{"goal_commitment", "goal_commitment"}, {"action_digest", "action_digest"}, {"before_digest", "before_digest"},
		{"after_digest", "after_digest"}, {"seq", "seq"}, {"prev", "prev"}, {"step_digest", "digest"}} {
		x, has := st[k[1]]
		if !has {
			return nil, errors.New("SignProgressStep: step." + k[1] + " is required")
		}
		b[k[0]] = x
	}
	m, err := msgOfDB(ProgressSigDomain, b)
	if err != nil {
		return nil, err
	}
	return map[string]any{"step": st, "holder": holder.Public, "sig": b64.EncodeToString(holder.Sign(m))}, nil
}
