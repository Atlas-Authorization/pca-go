package pca

import (
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strconv"
)

// Post-quantum t-of-n quorum certificates (the in-core module, distinct from the separate threshold package): a quorum set of n
// registered signers under post-quantum suites, a threshold t and a diversity commitment k (the minimum number of hash-based
// signers); a proof is at least t independent per-signer signatures from distinct registered signers over one domain-separated
// message (set id, epoch, action digest). Every signature is made and checked through the suite seam; this module only counts,
// binds and de-duplicates. It is NOT a threshold signature: the proof is t signatures and its size is t times one share.
// Verification never fails with an error; it returns a typed reason.

const (
	// PqQuorumMaxSigners is the largest signer set.
	PqQuorumMaxSigners = 256
	// PqQuorumMaxChain is the longest rotation chain a verifier walks.
	PqQuorumMaxChain = 1024

	quorumSetDomain  = "atlas-pca/pq-quorum-set/v1"
	quorumMsgDomain  = "atlas-pca/pq-quorum-msg/v1\x00"
	quorumRotateKind = "pq-quorum-rotation"
)

// QuorumSignerEntry is one registered signer: the suite and the key components it needs (base64url). Ed is empty for a suite
// without an Ed25519 half.
type QuorumSignerEntry struct {
	Alg string `json:"alg"`
	Ed  string `json:"ed,omitempty"`
	Pq  string `json:"pq"`
}

// QuorumSet is a committed quorum set; ID is derived and the loader recomputes it.
type QuorumSet struct {
	T            int                 `json:"t"`
	MinHashBased int                 `json:"minHashBased"`
	Signers      []QuorumSignerEntry `json:"signers"` // canonical order; the index is the signer index of a proof
	ID           string              `json:"id"`
}

// QuorumKeys are the public keys of one signer input, base64url, by member of the reference's key object.
type QuorumKeys struct {
	EdPub, MlDsaPub, MlDsa87Pub, SlhDsaPub, SlhDsa256sPub, FnDsa512Pub, FnDsa1024Pub string
}

// QuorumSignerInput is one signer to register.
type QuorumSignerInput struct {
	Alg  string
	Keys QuorumKeys
}

// QuorumShare is one signature of a proof (I indexes QuorumSet.Signers).
type QuorumShare struct {
	I     int    `json:"i"`
	Sig   string `json:"sig"`
	PqSig string `json:"pq_sig,omitempty"`
}

// QuorumProof is the shares of one proof. Sigs holds QuorumShare values or decoded wire objects.
type QuorumProof struct {
	SetID string `json:"set_id"`
	Sigs  []any  `json:"sigs"`
}

// QuorumSetResult is the outcome of building or loading a set: a refusal is always the reason "bad-set".
type QuorumSetResult struct {
	OK     bool
	Set    QuorumSet
	Reason string
}

// JSON is the reference's result object.
func (r QuorumSetResult) JSON() map[string]any {
	if !r.OK {
		return map[string]any{"ok": false, "reason": r.Reason}
	}
	return map[string]any{"ok": true, "set": quorumWire(r.Set)}
}

// QuorumVerdict is the outcome of verifying a proof. Detail is the offending signer index when the reason names one (-1 if none).
type QuorumVerdict struct {
	OK        bool
	Signers   []int
	Count     int
	HashBased int
	Reason    string
	Detail    int
}

// JSON is the reference's verdict object.
func (v QuorumVerdict) JSON() map[string]any {
	if v.OK {
		s := make([]any, len(v.Signers))
		for i, x := range v.Signers {
			s[i] = json.Number(strconv.Itoa(x))
		}
		return map[string]any{"ok": true, "signers": s, "count": json.Number(strconv.Itoa(v.Count)), "hashBased": json.Number(strconv.Itoa(v.HashBased))}
	}
	m := map[string]any{"ok": false, "reason": v.Reason}
	if v.Detail >= 0 {
		m["detail"] = json.Number(strconv.Itoa(v.Detail))
	}
	return m
}

func quorumRefuse(reason string) QuorumVerdict { return QuorumVerdict{Reason: reason, Detail: -1} }

// quorumWire is the decoded-JSON form of a typed value (numbers as the parser's lexemes), so typed and wire inputs share one path.
func quorumWire(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	x, err := ParseJSONLenient(b)
	if err != nil {
		return nil
	}
	return normalizeJSON(x)
}

func quorumIsWire(v any) any {
	switch v.(type) {
	case QuorumSet, *QuorumSet, QuorumProof, *QuorumProof, RotationCert, *RotationCert, QuorumShare, *QuorumShare:
		return quorumWire(v)
	}
	return v
}

func quorumRec(x any) (map[string]any, bool) {
	m, ok := quorumIsWire(x).(map[string]any)
	return m, ok
}

// quorumNumber is the decoded-JSON form of a Go number (the strict canonical form takes the parser's lexemes); other values stay.
func quorumNumber(v any) any {
	switch x := v.(type) {
	case float64:
		return jsNumber(x)
	case int:
		return jsNumber(float64(x))
	case int64:
		return jsNumber(float64(x))
	}
	return v
}

func quorumIsEpoch(v any) bool { return jsIsNonNeg(v) }

func quorumHashBased(alg string) bool {
	su, ok := resolveSigAlg(alg, true)
	return ok && (su.pq == pqSlh128f || su.pq == pqSlh256s)
}

// quorumPqKeyMember is the member of the reference's key object that carries the PQ public key of the suite.
func quorumPqKeyMember(p pqPrim) string {
	switch p {
	case pqMlDsa65:
		return "mlDsaPub"
	case pqMlDsa87:
		return "mlDsa87Pub"
	case pqSlh128f:
		return "slhDsaPub"
	case pqFnDsa512:
		return "fnDsa512Pub"
	case pqFnDsa1024:
		return "fnDsa1024Pub"
	}
	return "slhDsa256sPub"
}

func quorumNormalizeEntry(alg any, ed any, edPresent bool, pq any) (QuorumSignerEntry, bool) {
	su, ok := resolveSigAlg(alg, true)
	if !ok || su.pq == pqNone {
		return QuorumSignerEntry{}, false
	}
	pks, ok := pq.(string)
	if !ok {
		return QuorumSignerEntry{}, false
	}
	pkLen, _ := su.pq.lens()
	if _, ok := DecodeB64uStrict(pks, pkLen); !ok {
		return QuorumSignerEntry{}, false
	}
	if su.hasEd25519 {
		eds, ok := ed.(string)
		if !ok {
			return QuorumSignerEntry{}, false
		}
		if _, ok := DecodeB64uStrict(eds, 32); !ok {
			return QuorumSignerEntry{}, false
		}
		return QuorumSignerEntry{Alg: su.alg, Ed: eds, Pq: pks}, true
	}
	if edPresent {
		return QuorumSignerEntry{}, false
	}
	return QuorumSignerEntry{Alg: su.alg, Pq: pks}, true
}

func quorumEntryKey(e QuorumSignerEntry) string { return e.Alg + "|" + e.Ed + "|" + e.Pq }

func quorumSetID(t, k int, signers []QuorumSignerEntry) (string, error) {
	s := make([]any, len(signers))
	for i, e := range signers {
		var ed any
		if e.Ed != "" {
			ed = e.Ed
		}
		s[i] = map[string]any{"a": e.Alg, "e": ed, "p": e.Pq}
	}
	b, err := canonBytes(map[string]any{"d": quorumSetDomain, "t": t, "k": k, "s": s})
	if err != nil {
		return "", err
	}
	return B64u(sha384Sum(b)), nil
}

func quorumFinalize(entries []QuorumSignerEntry, t, k any) QuorumSetResult {
	bad := QuorumSetResult{Reason: "bad-set"}
	n := len(entries)
	if n < 1 || n > PqQuorumMaxSigners {
		return bad
	}
	if !jsIsSafeInteger(t) {
		return bad
	}
	tf, _ := jsNum(t)
	if tf < 1 || tf > float64(n) {
		return bad
	}
	if !jsIsSafeInteger(k) {
		return bad
	}
	kf, _ := jsNum(k)
	if kf < 0 || kf > tf || (kf == 0 && math.Signbit(kf)) { // -0 has no canonical form
		return bad
	}
	sorted := append([]QuorumSignerEntry(nil), entries...)
	sort.SliceStable(sorted, func(i, j int) bool { return quorumEntryKey(sorted[i]) < quorumEntryKey(sorted[j]) })
	// distinct keys: no key component (Ed25519 or post-quantum) appears in two entries, or twice in one
	seen := map[string]bool{}
	for _, e := range sorted {
		comps := []string{e.Pq}
		if e.Ed != "" {
			comps = []string{e.Ed, e.Pq}
		}
		for _, c := range comps {
			if seen[c] {
				return bad
			}
			seen[c] = true
		}
	}
	hb := 0
	for _, e := range sorted {
		if quorumHashBased(e.Alg) {
			hb++
		}
	}
	if float64(hb) < kf {
		return bad
	}
	id, err := quorumSetID(int(tf), int(kf), sorted)
	if err != nil {
		return bad
	}
	return QuorumSetResult{OK: true, Set: QuorumSet{T: int(tf), MinHashBased: int(kf), Signers: sorted, ID: id}}
}

// BuildQuorumSet builds a committed quorum set from public keys. A refusal is the reason "bad-set".
func BuildQuorumSet(signers []QuorumSignerInput, t, minHashBased int) QuorumSetResult {
	in := make([]any, len(signers))
	for i, s := range signers {
		keys := map[string]any{}
		for k, v := range map[string]string{"edPub": s.Keys.EdPub, "mlDsaPub": s.Keys.MlDsaPub, "mlDsa87Pub": s.Keys.MlDsa87Pub, "slhDsaPub": s.Keys.SlhDsaPub,
			"slhDsa256sPub": s.Keys.SlhDsa256sPub, "fnDsa512Pub": s.Keys.FnDsa512Pub, "fnDsa1024Pub": s.Keys.FnDsa1024Pub} {
			if v != "" {
				keys[k] = v
			}
		}
		in[i] = map[string]any{"alg": s.Alg, "keys": keys}
	}
	return BuildQuorumSetValue(in, json.Number(strconv.Itoa(t)), json.Number(strconv.Itoa(minHashBased)))
}

// BuildQuorumSetValue is BuildQuorumSet over the decoded wire form (signers: [{alg, keys: {edPub, mlDsaPub, ...}}]; t and
// minHashBased any value: a non-integer is refused as "bad-set"). The reference's default minHashBased is 0.
func BuildQuorumSetValue(signers any, t any, minHashBased any) QuorumSetResult {
	bad := QuorumSetResult{Reason: "bad-set"}
	l, ok := quorumIsWire(signers).([]any)
	if !ok {
		return bad
	}
	entries := make([]QuorumSignerEntry, 0, len(l))
	for _, s := range l {
		m, ok := s.(map[string]any)
		if !ok {
			return bad
		}
		keys, ok := m["keys"].(map[string]any)
		if !ok {
			return bad
		}
		su, ok := resolveSigAlg(m["alg"], true)
		if !ok {
			return bad
		}
		ed, edPresent := keys["edPub"]
		e, ok := quorumNormalizeEntry(m["alg"], ed, edPresent, keys[quorumPqKeyMember(su.pq)])
		if !ok {
			return bad
		}
		entries = append(entries, e)
	}
	return quorumFinalize(entries, t, minHashBased)
}

// LoadQuorumSet loads an untrusted wire quorum set (or a typed one), re-deriving the id: a supplied id must match and the wire
// order must already be canonical.
func LoadQuorumSet(x any) QuorumSetResult {
	bad := QuorumSetResult{Reason: "bad-set"}
	m, ok := quorumRec(x)
	if !ok {
		return bad
	}
	l, ok := m["signers"].([]any)
	if !ok {
		return bad
	}
	id, ok := m["id"].(string)
	if !ok {
		return bad
	}
	entries := make([]QuorumSignerEntry, 0, len(l))
	for _, s := range l {
		sm, ok := s.(map[string]any)
		if !ok {
			return bad
		}
		ed, edPresent := sm["ed"]
		e, ok := quorumNormalizeEntry(sm["alg"], ed, edPresent, sm["pq"])
		if !ok {
			return bad
		}
		entries = append(entries, e)
	}
	r := quorumFinalize(entries, m["t"], m["minHashBased"])
	if !r.OK {
		return r
	}
	for i, e := range r.Set.Signers {
		if quorumEntryKey(e) != quorumEntryKey(entries[i]) {
			return bad
		}
	}
	if r.Set.ID != id {
		return bad
	}
	return r
}

// quorumMessageValue is the signed bytes over any JSON values: a value the strict canonical form refuses is an error.
func quorumMessageValue(setID, epoch, action any) ([]byte, error) {
	cb, err := canonBytes(map[string]any{"set_id": setID, "epoch": epoch, "action": action})
	if err != nil {
		return nil, err
	}
	return append([]byte(quorumMsgDomain), sha384Sum(cb)...), nil
}

// QuorumMessage is the domain-separated bytes every signer signs: it binds the set id, the epoch and the action digest.
func QuorumMessage(setID string, epoch float64, actionDigest string) ([]byte, error) {
	return quorumMessageValue(setID, jsNumber(epoch), actionDigest)
}

// QuorumActionDigest digests an arbitrary message (e.g. the threshold message of a PCActn) into the actionDigest string.
func QuorumActionDigest(message []byte) string { return B64u(sha384Sum(message)) }

// SignQuorumShare signs one share as signer `index` of the set. The key material comes from keys: Ed (hybrid suites) and
// Opts.Pq (the post-quantum pair of the suite of that signer); the suite itself is the signer's. A bad index, missing key
// material or an unhashable epoch is an error (the signer side may fail; verification never does).
func SignQuorumShare(set QuorumSet, index int, epoch float64, actionDigest string, keys SuiteKeys) (QuorumShare, error) {
	return signQuorumShareValue(set, index, jsNumber(epoch), actionDigest, keys)
}

func signQuorumShareValue(set QuorumSet, index int, epoch, actionDigest any, keys SuiteKeys) (QuorumShare, error) {
	if index < 0 || index >= len(set.Signers) {
		return QuorumShare{}, errors.New("signQuorumShare: no such signer index")
	}
	e := set.Signers[index]
	msg, err := quorumMessageValue(set.ID, epoch, actionDigest)
	if err != nil {
		return QuorumShare{}, err
	}
	var pq *PqKeyPair
	if keys.Opts != nil {
		pq = keys.Opts.Pq
	}
	sig, pqSig, err := signWithSuite(&SuiteOpts{Alg: e.Alg, Pq: pq}, keys.Ed, msg)
	if err != nil {
		return QuorumShare{}, err
	}
	return QuorumShare{I: index, Sig: sig, PqSig: pqSig}, nil
}

// AssembleQuorumProof gathers shares into a proof for the set.
func AssembleQuorumProof(set QuorumSet, shares []any) QuorumProof {
	return QuorumProof{SetID: set.ID, Sigs: append([]any{}, shares...)}
}

// VerifyQuorumInput is the input of VerifyQuorum. Nil members are absent; ExpectedSetID pins the set id the verifier trusts and
// RequireHashBased is a verifier-side floor: the effective diversity is the larger of the set's commitment and this.
type VerifyQuorumInput struct {
	Set, Proof       any
	Epoch            any
	ActionDigest     any
	ExpectedSetID    any
	RequireHashBased any
}

// VerifyQuorum verifies a quorum proof. It never fails with an error; every failure is a typed reason.
func VerifyQuorum(in VerifyQuorumInput) QuorumVerdict {
	m := map[string]any{"set": in.Set, "proof": in.Proof, "epoch": in.Epoch, "actionDigest": in.ActionDigest}
	if in.ExpectedSetID != nil {
		m["expectedSetId"] = in.ExpectedSetID
	}
	if in.RequireHashBased != nil {
		m["requireHashBased"] = in.RequireHashBased
	}
	for k, v := range m {
		if v == nil {
			delete(m, k)
		}
	}
	return VerifyQuorumValue(m)
}

// quorumVerifyShare checks one share's signature under the registered key (the set is verifier-configured, so its keys are trusted).
func quorumVerifyShare(e QuorumSignerEntry, msg []byte, raw map[string]any) bool {
	key, ok := resolvePqVerifyKey(e.Alg, true, e.Pq, pqAuthority{trustedPk: e.Pq, hasTrusted: true})
	if !ok {
		return false
	}
	return verifyLeafSuite(e.Alg, true, e.Ed, key, msg, raw["sig"], raw["pq_sig"])
}

// VerifyQuorumValue is VerifyQuorum over the decoded wire form: any JSON value as the input object, and set / proof as wire values.
func VerifyQuorumValue(input any) QuorumVerdict {
	in, ok := input.(map[string]any)
	if !ok {
		return quorumRefuse("malformed")
	}
	loaded := LoadQuorumSet(in["set"])
	if !loaded.OK {
		return quorumRefuse("bad-set")
	}
	set := loaded.Set
	if v, has := in["expectedSetId"]; has {
		if s, ok := v.(string); !ok || s != set.ID {
			return quorumRefuse("set-mismatch")
		}
	}
	digest, isStr := in["actionDigest"].(string)
	epoch := quorumNumber(in["epoch"])
	if !quorumIsEpoch(epoch) || !isStr {
		return quorumRefuse("malformed")
	}
	p, ok := quorumRec(in["proof"])
	if !ok {
		return quorumRefuse("malformed")
	}
	pid, ok := p["set_id"].(string)
	sigs, ok2 := p["sigs"].([]any)
	if !ok || !ok2 {
		return quorumRefuse("malformed")
	}
	if pid != set.ID {
		return quorumRefuse("set-mismatch")
	}
	if len(sigs) > len(set.Signers) {
		return quorumRefuse("too-many-signatures")
	}
	msg, err := quorumMessageValue(set.ID, epoch, digest)
	if err != nil {
		return quorumRefuse("malformed")
	}
	seen := map[int]bool{}
	hashBased := 0
	for _, r := range sigs {
		raw, ok := r.(map[string]any)
		if !ok {
			return quorumRefuse("malformed")
		}
		if _, ok := raw["sig"].(string); !ok {
			return quorumRefuse("malformed")
		}
		if !jsIsNonNeg(raw["i"]) {
			return quorumRefuse("unknown-signer")
		}
		f, _ := jsNum(raw["i"])
		if f >= float64(len(set.Signers)) {
			return quorumRefuse("unknown-signer")
		}
		i := int(f)
		if seen[i] {
			return QuorumVerdict{Reason: "duplicate-signer", Detail: i}
		}
		seen[i] = true
		e := set.Signers[i]
		su, _ := resolveSigAlg(e.Alg, true)
		_, hasPqSig := raw["pq_sig"]
		if su.needsPqSig != hasPqSig || !quorumVerifyShare(e, msg, raw) {
			return QuorumVerdict{Reason: "bad-signature", Detail: i}
		}
		if quorumHashBased(e.Alg) {
			hashBased++
		}
	}
	if len(seen) < set.T {
		return quorumRefuse("below-threshold")
	}
	k := float64(set.MinHashBased)
	if v, has := in["requireHashBased"]; has && v != nil {
		k = math.Max(k, jsToNumber(v)) // Math.max coerces its operands; a NaN stays NaN and is refused below
	}
	if math.IsNaN(k) || k != math.Trunc(k) || k < 0 || k > maxSafeInt {
		return quorumRefuse("malformed")
	}
	if float64(hashBased) < k {
		return quorumRefuse("diversity-unmet")
	}
	signers := make([]int, 0, len(seen))
	for i := range seen {
		signers = append(signers, i)
	}
	sort.Ints(signers)
	return QuorumVerdict{OK: true, Signers: signers, Count: len(seen), HashBased: hashBased, Detail: -1}
}

// VerifyQuorumApproval is the boolean adapter for a guardian-approval check slot: (set, proof, message, epoch) => ok. opts
// carries only expectedSetId and requireHashBased (nil = none); a nil message is not bytes and is refused.
func VerifyQuorumApproval(set, proof any, message []byte, epoch any, opts map[string]any) bool {
	if message == nil {
		return false
	}
	m := map[string]any{"set": set, "proof": proof, "epoch": epoch, "actionDigest": QuorumActionDigest(message)}
	for _, k := range []string{"expectedSetId", "requireHashBased"} {
		if v, has := opts[k]; has {
			m[k] = v
		}
	}
	return VerifyQuorumValue(m).OK
}

// ---- rotation ------------------------------------------------------------------------------------

// RotationCert rotates a quorum to its successor: signed by the OLD quorum at FromEpoch over RotationActionDigest.
type RotationCert struct {
	FromSetID string      `json:"from_set_id"`
	FromEpoch float64     `json:"from_epoch"`
	ToSet     QuorumSet   `json:"to_set"`
	ToEpoch   float64     `json:"to_epoch"`
	Proof     QuorumProof `json:"proof"`
}

func rotationDigestValue(toSetID, toEpoch any, hasID, hasEpoch bool) (string, error) {
	m := map[string]any{"kind": quorumRotateKind}
	if hasID {
		m["to_set_id"] = toSetID
	}
	if hasEpoch {
		m["to_epoch"] = toEpoch
	}
	b, err := canonBytes(m)
	if err != nil {
		return "", err
	}
	return B64u(sha384Sum(b)), nil
}

// RotationActionDigest is the action digest the old quorum signs to rotate to the set toSetID at epoch toEpoch.
func RotationActionDigest(toSetID string, toEpoch float64) (string, error) {
	return rotationDigestValue(toSetID, jsNumber(toEpoch), true, true)
}

// BuildRotationCert builds the certificate that rotates `from` at fromEpoch to `to`, signed by the shares of the old quorum.
func BuildRotationCert(from QuorumSet, fromEpoch float64, to QuorumSet, shares []any) RotationCert {
	return RotationCert{FromSetID: from.ID, FromEpoch: fromEpoch, ToSet: to, ToEpoch: fromEpoch + 1, Proof: AssembleQuorumProof(from, shares)}
}

// SignRotationShare signs one rotation share as signer `index` of the old quorum.
func SignRotationShare(from QuorumSet, index int, fromEpoch float64, to QuorumSet, keys SuiteKeys) (QuorumShare, error) {
	d, err := rotationDigestValue(to.ID, jsNumber(fromEpoch+1), true, true)
	if err != nil {
		return QuorumShare{}, err
	}
	return signQuorumShareValue(from, index, jsNumber(fromEpoch), d, keys)
}

// ChainVerdict is the outcome of verifying a rotation chain: the final set, epoch and length, or a reason and the failing link
// (At = -1 for a fault before any link).
type ChainVerdict struct {
	OK     bool
	Set    QuorumSet
	Epoch  int64
	Length int
	Reason string
	At     int
}

// JSON is the reference's verdict object.
func (v ChainVerdict) JSON() map[string]any {
	if v.OK {
		return map[string]any{"ok": true, "set": quorumWire(v.Set), "epoch": json.Number(strconv.FormatInt(v.Epoch, 10)), "length": json.Number(strconv.Itoa(v.Length))}
	}
	return map[string]any{"ok": false, "reason": v.Reason, "at": json.Number(strconv.Itoa(v.At))}
}

// VerifyRotationChain verifies a rotation chain from a trusted genesis (set, epoch): each certificate must be signed by the
// quorum current at that point, link by id and advance the epoch by exactly 1. genesisEpoch and chain are wire values.
func VerifyRotationChain(genesisSet any, genesisEpoch any, chain any) ChainVerdict {
	genesisEpoch = quorumNumber(genesisEpoch)
	g := LoadQuorumSet(genesisSet)
	if !g.OK || !quorumIsEpoch(genesisEpoch) {
		return ChainVerdict{Reason: "bad-set", At: -1}
	}
	chain = quorumIsWire(chain)
	l, ok := chain.([]any)
	if !ok {
		return ChainVerdict{Reason: "malformed", At: -1}
	}
	if len(l) > PqQuorumMaxChain {
		return ChainVerdict{Reason: "chain-too-long", At: -1}
	}
	cur := g.Set
	ef, _ := jsNum(genesisEpoch)
	epoch := int64(ef)
	for n, raw := range l {
		c, ok := quorumRec(raw) // a typed certificate is read through its wire form
		from, okS := "", false
		if ok {
			from, okS = c["from_set_id"].(string)
		}
		if !ok || !okS || !quorumIsEpoch(c["from_epoch"]) || !quorumIsEpoch(c["to_epoch"]) {
			return ChainVerdict{Reason: "malformed", At: n}
		}
		if from != cur.ID {
			return ChainVerdict{Reason: "chain-broken", At: n}
		}
		fe, _ := jsNum(c["from_epoch"])
		te, _ := jsNum(c["to_epoch"])
		if fe != float64(epoch) || te != float64(epoch)+1 {
			return ChainVerdict{Reason: "non-monotone-epoch", At: n}
		}
		next := LoadQuorumSet(c["to_set"])
		if !next.OK || next.Set.ID == cur.ID {
			return ChainVerdict{Reason: "bad-rotation", At: n}
		}
		d, err := rotationDigestValue(next.Set.ID, c["to_epoch"], true, true)
		if err != nil {
			return ChainVerdict{Reason: "malformed", At: -1}
		}
		v := VerifyQuorumValue(map[string]any{"set": cur, "proof": c["proof"], "epoch": json.Number(strconv.FormatInt(epoch, 10)), "actionDigest": d, "expectedSetId": cur.ID})
		if !v.OK {
			return ChainVerdict{Reason: v.Reason, At: n}
		}
		cur = next.Set
		epoch = int64(te)
	}
	return ChainVerdict{OK: true, Set: cur, Epoch: epoch, Length: len(l), At: -1}
}

// IsRotationFork reports whether two certificates rotate the same (set, epoch) to different successor sets (a fork). Anything
// that is not a certificate with a set object is not a fork.
func IsRotationFork(a, b any) bool {
	ma, ok1 := quorumRec(a)
	mb, ok2 := quorumRec(b)
	if !ok1 || !ok2 {
		return false
	}
	ta, ok1 := ma["to_set"].(map[string]any)
	tb, ok2 := mb["to_set"].(map[string]any)
	if !ok1 || !ok2 {
		return false
	}
	same := func(k string) bool { // === over members: two absent members are equal
		x, hx := ma[k]
		y, hy := mb[k]
		if !hx || !hy {
			return !hx && !hy
		}
		return jsStrictEq(x, y)
	}
	ia, ok1 := ta["id"].(string)
	ib, ok2 := tb["id"].(string)
	return same("from_set_id") && same("from_epoch") && ok1 && ok2 && ia != ib
}

// ---- size accounting -----------------------------------------------------------------------------

// QuorumSizeReport is the honest size of a proof: raw signature bytes of the cheapest and the most expensive t-subset, and of
// the chosen signers when given. Compact is always false: the proof is t independent signatures.
type QuorumSizeReport struct {
	MinBytes    int  `json:"minBytes"`
	MaxBytes    int  `json:"maxBytes"`
	ChosenBytes *int `json:"chosenBytes,omitempty"`
	T           int  `json:"t"`
	Compact     bool `json:"compact"`
}

func quorumShareBytes(alg string) (int, error) {
	su, ok := resolveSigAlg(alg, true)
	if !ok {
		return 0, errors.New("quorumProofSize: unknown suite " + alg)
	}
	n := su.sigBytes
	if su.needsPqSig {
		_, sl := su.pq.lens()
		n += sl
	}
	return n, nil
}

// QuorumProofSize accounts the proof size: it grows linearly in t (t signatures), it is not compact. indices (nil = none given)
// names the signers of a concrete proof; an index outside the set counts 0.
func QuorumProofSize(set QuorumSet, indices []int) (QuorumSizeReport, error) {
	sizes := make([]int, len(set.Signers))
	for i, e := range set.Signers {
		n, err := quorumShareBytes(e.Alg)
		if err != nil {
			return QuorumSizeReport{}, err
		}
		sizes[i] = n
	}
	sorted := append([]int(nil), sizes...)
	sort.Ints(sorted)
	sum := func(xs []int) (s int) {
		for _, x := range xs {
			s += x
		}
		return
	}
	t := set.T
	if t > len(sorted) {
		t = len(sorted)
	}
	if t < 0 {
		t = 0
	}
	r := QuorumSizeReport{MinBytes: sum(sorted[:t]), MaxBytes: sum(sorted[len(sorted)-t:]), T: set.T}
	if indices != nil {
		c := 0
		for _, i := range indices {
			if i >= 0 && i < len(sizes) {
				c += sizes[i]
			}
		}
		r.ChosenBytes = &c
	}
	return r, nil
}
