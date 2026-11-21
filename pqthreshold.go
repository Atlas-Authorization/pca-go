package pca

// Post-quantum threshold step-up verification: a signed FROST group descriptor that pins the threshold to the group key, an
// ML-DSA-65 pqT-of-m co-signer quorum, and the hybrid verdict that needs BOTH. The FROST aggregate is checked as the plain Ed25519
// signature it is; the quorum runs on the vetted circl ML-DSA-65 verifier already used by the core. Inputs are JSON-shaped values
// (map[string]any, []any, string, json.Number) with JavaScript field-read semantics: an absent field and a wrong-typed field are
// distinct from null, and every verifier is total (a malformed input is a refusal, never a panic).

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	GroupDescriptorVersion = 1
	GroupSuite             = "frost-ed25519"
	MaxGroupSize           = 1024
	HybridArtifactVersion  = 2
	HybridClassicalAlg     = "frost-ed25519"
	PqQuorumVersion        = 2
	PqQuorumAlg            = "ml-dsa-65"
	MaxPqQuorumEntries     = 256

	pqtDescriptorDomain = "atlas-pca-pq-threshold/group-descriptor/v1\x00"
	pqtSignerSetDomain  = "atlas-pca-pq-threshold/signer-set/v1\x00"
	pqtQuorumDomain     = "atlas-pca/pq-quorum/v2\x00"
)

type pqtAbsentT struct{}

// pqtAbsent is a JS `undefined`: an absent field, distinct from null.
var pqtAbsent any = pqtAbsentT{}

func pqtGet(o any, key string) any {
	if m, ok := o.(map[string]any); ok {
		if v, has := m[key]; has {
			return v
		}
	}
	return pqtAbsent
}

// pqtObject is JS typeof 'object' and not null.
func pqtObject(v any) bool {
	switch v.(type) {
	case map[string]any, []any:
		return true
	}
	return false
}

func pqtIsInteger(v any) bool {
	f, ok := jsNum(v)
	return ok && !math.IsInf(f, 0) && !math.IsNaN(f) && f == math.Trunc(f)
}

func pqtIsSafeInteger(v any) bool {
	f, _ := jsNum(v)
	return pqtIsInteger(v) && math.Abs(f) <= 9007199254740991
}

func pqtIsNum(v any, n float64) bool {
	f, ok := jsNum(v)
	return ok && f == n
}

func pqtIntNum(n int) json.Number { return json.Number(strconv.Itoa(n)) }

// pqtB64 maps raw key bytes to base64url and leaves anything else untouched.
func pqtB64(v any) any {
	if b, ok := v.([]byte); ok {
		return b64.EncodeToString(b)
	}
	return v
}

func pqtJsStr(v any) string {
	switch t := v.(type) {
	case pqtAbsentT:
		return "undefined"
	case nil:
		return "null"
	case bool:
		return strconv.FormatBool(t)
	case string:
		return t
	case map[string]any:
		return "[object Object]"
	}
	if f, ok := jsNum(v); ok {
		return jsNumberString(f)
	}
	return fmt.Sprint(v)
}

func pqtClone(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = pqtClone(x)
		}
		return m
	case []any:
		l := make([]any, len(t))
		for i, x := range t {
			l[i] = pqtClone(x)
		}
		return l
	}
	return v
}

// pqtStrip drops absent members from a result (and from its pq member).
func pqtStrip(m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		if _, ab := v.(pqtAbsentT); !ab {
			out[k] = v
		}
	}
	if p, ok := out["pq"].(map[string]any); ok {
		out["pq"] = pqtStrip(p)
	}
	return out
}

// ---- signed group descriptor

// SignerSetCommitment is base64url(sha256(domain || canonical([{id, pk}] sorted by id))) over the FROST verification shares.
func SignerSetCommitment(participants any) (string, error) {
	l, ok := participants.([]any)
	if !ok || len(l) == 0 || len(l) > MaxGroupSize {
		return "", fmt.Errorf("signerSetCommitment: need 1..%d participants", MaxGroupSize)
	}
	type row struct {
		id float64
		pk string
	}
	rows := make([]row, 0, len(l))
	for _, p := range l {
		m, ok := p.(map[string]any)
		if !ok {
			return "", errors.New("signerSetCommitment: participant must be an object")
		}
		id, _ := jsNum(m["identifier"])
		if !pqtIsSafeInteger(m["identifier"]) || id <= 0 {
			return "", errors.New("signerSetCommitment: participant identifiers must be positive safe integers")
		}
		pk, _ := pqtB64(m["publicKey"]).(string)
		if _, ok := DecodeB64uStrict(pk, 32); !ok {
			return "", errors.New("signerSetCommitment: verification share is not a canonical b64u(32) value")
		}
		rows = append(rows, row{id, pk})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].id < rows[j].id })
	canon := make([]any, len(rows))
	for i, r := range rows {
		if i > 0 && r.id == rows[i-1].id {
			return "", errors.New("signerSetCommitment: duplicate participant identifier")
		}
		canon[i] = map[string]any{"id": json.Number(jsNumberLexeme(r.id)), "pk": r.pk}
	}
	b, err := canonBytes(canon)
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(sha([]byte(pqtSignerSetDomain + string(b)))), nil
}

func pqtDescriptorBytes(d map[string]any) ([]byte, error) {
	b, err := canonBytes(map[string]any{"v": d["v"], "suite": d["suite"], "group_pk": d["groupPublicKey"], "t": d["t"], "n": d["n"], "signer_set": d["signerSetCommitment"]})
	if err != nil {
		return nil, err
	}
	return append([]byte(pqtDescriptorDomain), b...), nil
}

// IssueGroupDescriptor signs {v, suite, groupPublicKey, t, n, signerSetCommitment} with an Ed25519 authority seed.
// groupPublicKey is a base64url string or raw 32 bytes; t is a JSON number.
func IssueGroupDescriptor(authoritySeed []byte, groupPublicKey, t, participants any) (map[string]any, error) {
	pl, ok := participants.([]any)
	if !ok {
		return nil, errors.New("issueGroupDescriptor: participants must be a list")
	}
	n := len(pl)
	tf, _ := jsNum(t)
	if !pqtIsInteger(t) || tf < 1 || tf > float64(n) {
		return nil, fmt.Errorf("issueGroupDescriptor: need 1 <= t <= n (t=%s, n=%d)", pqtJsStr(t), n)
	}
	gpk, _ := pqtB64(groupPublicKey).(string)
	if _, ok := DecodeB64uStrict(gpk, 32); !ok {
		return nil, errors.New("issueGroupDescriptor: group public key is not canonical b64u(32)")
	}
	if len(authoritySeed) != ed25519.SeedSize {
		return nil, errors.New("issueGroupDescriptor: authority key must be a 32-byte Ed25519 secret key")
	}
	ssc, err := SignerSetCommitment(participants)
	if err != nil {
		return nil, err
	}
	d := map[string]any{"v": pqtIntNum(GroupDescriptorVersion), "suite": GroupSuite, "groupPublicKey": gpk, "t": pqtIntNum(int(tf)), "n": pqtIntNum(n), "signerSetCommitment": ssc}
	db, err := pqtDescriptorBytes(d)
	if err != nil {
		return nil, err
	}
	sk := ed25519.NewKeyFromSeed(authoritySeed)
	return map[string]any{"descriptor": d, "authority": b64.EncodeToString(sk.Public().(ed25519.PublicKey)), "sig": b64.EncodeToString(ed25519.Sign(sk, db))}, nil
}

func pqtFail(reason string) map[string]any { return map[string]any{"ok": false, "reason": reason} }

// VerifyGroupDescriptor returns {"ok": true, "descriptor"} or {"ok": false, "reason"}. It pins t to the group key: a FROST
// aggregate is a plain Ed25519 signature, so the threshold cannot be read off the key and must be attested by a trusted setup
// authority. exp carries trustedAuthorities, groupKey, t and optionally signerSetCommitment.
func VerifyGroupDescriptor(s, exp any) map[string]any {
	r, err := pqtVerifyGroupDescriptor(s, exp)
	if err != nil {
		return pqtFail("group descriptor could not be verified (malformed)")
	}
	return r
}

func pqtVerifyGroupDescriptor(s, exp any) (map[string]any, error) {
	if !pqtObject(s) {
		return pqtFail("no signed group descriptor: the threshold is unattested"), nil
	}
	d, authority, sig := pqtGet(s, "descriptor"), pqtGet(s, "authority"), pqtGet(s, "sig")
	authS, ok1 := authority.(string)
	sigS, ok2 := sig.(string)
	if !pqtObject(d) || !ok1 || !ok2 {
		return pqtFail("malformed group descriptor"), nil
	}
	if suite, _ := pqtGet(d, "suite").(string); !pqtIsNum(pqtGet(d, "v"), GroupDescriptorVersion) || suite != GroupSuite {
		return pqtFail("unsupported group descriptor version or suite"), nil
	}
	dg, ok1 := pqtGet(d, "groupPublicKey").(string)
	dssc, ok2 := pqtGet(d, "signerSetCommitment").(string)
	if !ok1 || !ok2 {
		return pqtFail("malformed group descriptor"), nil
	}
	dt, dn := pqtGet(d, "t"), pqtGet(d, "n")
	dtf, _ := jsNum(dt)
	dnf, _ := jsNum(dn)
	if !pqtIsInteger(dt) || !pqtIsInteger(dn) || dtf < 1 || dnf < dtf || dnf > MaxGroupSize {
		return pqtFail("malformed group descriptor: need 1 <= t <= n"), nil
	}
	authorities, ok := pqtGet(exp, "trustedAuthorities").([]any)
	if !ok {
		return nil, errors.New("trustedAuthorities must be an array")
	}
	trusted := false
	for _, a := range authorities {
		if x, ok := pqtB64(a).(string); ok && x == authS {
			trusted = true
		}
	}
	if !trusted {
		return pqtFail("group descriptor authority is not trusted"), nil
	}
	authorityKey, ok1 := DecodeB64uStrict(authS, 32)
	rawSig, ok2 := DecodeB64uStrict(sigS, 64)
	if !ok1 || !ok2 {
		return pqtFail("malformed authority key or signature"), nil
	}
	db, err := pqtDescriptorBytes(d.(map[string]any))
	if err != nil {
		return nil, err
	}
	if !VerifyStrict(authorityKey, db, rawSig) {
		return pqtFail("group descriptor signature does not verify"), nil
	}
	if gk, ok := pqtB64(pqtGet(exp, "groupKey")).(string); !ok || dg != gk {
		return pqtFail("group descriptor is for a different group key"), nil
	}
	et := pqtGet(exp, "t")
	etf, _ := jsNum(et)
	if !pqtIsInteger(et) || etf < 1 {
		return pqtFail("required t must be a positive integer"), nil
	}
	if dtf != etf {
		return pqtFail(fmt.Sprintf("group was set up as %s-of-%s but %s is required: the threshold is not bound to this key", pqtJsStr(dt), pqtJsStr(dn), pqtJsStr(et))), nil
	}
	if pin := pqtGet(exp, "signerSetCommitment"); pin != pqtAbsent {
		if p, ok := pin.(string); !ok || dssc != p {
			return pqtFail("group descriptor is for a different signer set"), nil
		}
	}
	return map[string]any{"ok": true, "descriptor": d}, nil
}

// ---- ML-DSA-65 co-signer quorum (a pqT-of-m multi-signature of single-party keys, not a threshold scheme)

// PqQuorumRepresentative is the bytes every co-signature covers: domain || sha256(message).
func PqQuorumRepresentative(message []byte) []byte {
	h := sha256.Sum256(message)
	return append([]byte(pqtQuorumDomain), h[:]...)
}

// NormalizePqQuorumPool is the trusted pool as canonical base64url strings; entries that are not a well-formed ML-DSA-65 public
// key are ignored. pks is a []any (strings or raw key bytes), []string or [][]byte.
func NormalizePqQuorumPool(pks any) (map[string]bool, error) {
	var items []any
	switch t := pks.(type) {
	case []any:
		items = t
	case []string:
		for _, s := range t {
			items = append(items, s)
		}
	case [][]byte:
		for _, b := range t {
			items = append(items, b)
		}
	default:
		return nil, errors.New("normalizePqQuorumPool: expected an array of public keys")
	}
	pool := map[string]bool{}
	for _, p := range items {
		if s, ok := pqtB64(p).(string); ok {
			if _, ok := DecodeB64uStrict(s, mlDsaPublicKeyBytes); ok {
				pool[s] = true
			}
		}
	}
	return pool, nil
}

// VerifyPqQuorum counts DISTINCT trusted keys whose co-signature verifies over message; ok iff the count reaches pqT. Total (never
// panics on a malformed block); a missing, v1 or unknown version is refused before any verification. need echoes pqT as given.
func VerifyPqQuorum(block any, message []byte, trustedPool map[string]bool, pqT any) map[string]any {
	no := func(reason string) map[string]any {
		return map[string]any{"ok": false, "count": 0, "need": pqT, "reason": reason}
	}
	tf, _ := jsNum(pqT)
	if !pqtIsInteger(pqT) || tf < 1 {
		return no("pqT must be a positive integer")
	}
	if !pqtObject(block) {
		return no("malformed pq block")
	}
	v, alg, signers := pqtGet(block, "v"), pqtGet(block, "alg"), pqtGet(block, "signers")
	switch {
	case v == pqtAbsent:
		return no("pq quorum version missing (pre-0.5 format is refused)")
	case pqtIsNum(v, 1):
		return no("pq quorum version 1 is no longer accepted (pre-0.5 format)")
	case !pqtIsNum(v, PqQuorumVersion):
		return no("unsupported pq quorum version")
	}
	list, isList := signers.([]any)
	if a, _ := alg.(string); a != PqQuorumAlg || !isList {
		return no("malformed pq block")
	}
	rep := PqQuorumRepresentative(message)
	counted := map[string]bool{}
	if len(list) > MaxPqQuorumEntries {
		list = list[:MaxPqQuorumEntries]
	}
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		pk, ok1 := m["pk"].(string)
		sg, ok2 := m["sig"].(string)
		if !ok1 || !ok2 || !trustedPool[pk] || counted[pk] {
			continue
		}
		if !mlDsa65VerifyB64u(callerVouchedPqKey(pk), rep, sg) {
			continue
		}
		counted[pk] = true
	}
	if len(counted) >= int(tf) {
		return map[string]any{"ok": true, "count": len(counted), "need": pqT}
	}
	return map[string]any{"ok": false, "count": len(counted), "need": pqT,
		"reason": fmt.Sprintf("post-quantum quorum short: %d of %s required ML-DSA co-signatures", len(counted), pqtJsStr(pqT))}
}

// ---- hybrid verification: the FROST aggregate AND the ML-DSA quorum, both over the same action message

func pqtGroupKey(k any) (string, bool) {
	s, ok := pqtB64(k).(string)
	if !ok {
		return "", false
	}
	_, ok = DecodeB64uStrict(s, 32)
	return s, ok
}

func pqtVerifyFrostAggregate(sig any, message []byte, trustedGroupKey string) bool {
	s, ok := sig.(string)
	return ok && verifyB64u(trustedGroupKey, message, s)
}

// pqtCheckDescriptor is "" when the signed descriptor pins opts.t to opts.groupKey, else the refusal reason.
func pqtCheckDescriptor(opts any) string {
	exp := map[string]any{}
	for _, k := range []string{"trustedAuthorities", "groupKey", "t", "signerSetCommitment"} {
		if v := pqtGet(opts, k); v != pqtAbsent {
			exp[k] = v
		}
	}
	r := VerifyGroupDescriptor(pqtGet(opts, "groupDescriptor"), exp)
	if r["ok"] == true {
		return ""
	}
	return r["reason"].(string)
}

// VerifyHybridThreshold fails closed unless the FROST aggregate verifies under the trusted group key (whose threshold the signed
// descriptor pins) AND at least pqT distinct trusted ML-DSA-65 keys co-signed. It returns {ok, frost, pq, reason?}.
func VerifyHybridThreshold(action, artifact, opts any) map[string]any {
	r, err := pqtVerifyHybrid(action, artifact, opts)
	if err != nil {
		reason := "malformed action or verifier options"
		return map[string]any{"ok": false, "frost": false, "pq": map[string]any{"ok": false, "count": 0, "need": 0, "reason": reason}, "reason": reason}
	}
	return r
}

func pqtVerifyHybrid(action, artifact, opts any) (map[string]any, error) {
	version := pqtGet(artifact, "v")
	pqT := pqtGet(opts, "pqT")
	if !pqtIsNum(version, HybridArtifactVersion) {
		reason := "unsupported artifact version"
		if version == pqtAbsent {
			reason = "artifact version missing (pre-0.5 format is refused)"
		} else if pqtIsNum(version, 1) {
			reason = "artifact version 1 is no longer accepted (pre-0.5 format)"
		}
		return pqtStrip(map[string]any{"ok": false, "frost": false, "pq": map[string]any{"ok": false, "count": 0, "need": pqT, "reason": reason}, "reason": reason}), nil
	}
	am, ok := action.(map[string]any)
	if !ok {
		return nil, errors.New("action must be an object")
	}
	message, err := ThresholdMessage(am)
	if err != nil {
		return nil, err
	}
	trusted, trustedOK := pqtGroupKey(pqtGet(opts, "groupKey"))
	pool, err := NormalizePqQuorumPool(pqtGet(opts, "pqPublicKeys"))
	if err != nil {
		return nil, err
	}
	frostOK := false
	frostReason := ""
	descriptorReason := pqtCheckDescriptor(opts)
	t := pqtGet(opts, "t")
	tf, _ := jsNum(t)
	frost := pqtGet(artifact, "frost")
	ft := pqtGet(frost, "t")
	ftf, _ := jsNum(ft)
	switch alg, _ := pqtGet(frost, "alg").(string); {
	case !pqtIsInteger(t) || tf < 1:
		frostReason = "t must be a positive integer"
	case !trustedOK:
		frostReason = "trusted FROST group key is not a canonical b64u(32) point"
	case !pqtObject(frost) || alg != HybridClassicalAlg:
		frostReason = "malformed or missing FROST part"
	case descriptorReason != "":
		frostReason = descriptorReason
	case !pqtIsInteger(ft) || ftf < tf:
		frostReason = fmt.Sprintf("FROST declared threshold %s is below the required t=%s (downgrade)", pqtJsStr(ft), pqtJsStr(t))
	case !pqtVerifyFrostAggregate(pqtGet(frost, "sig"), message, trusted):
		frostReason = "FROST aggregate does not verify under the trusted group key (quorum short, wrong group, or forged)"
	default:
		frostOK = true
	}
	pqBlock := pqtGet(artifact, "pq")
	if pqBlock == pqtAbsent {
		pqBlock = nil
	}
	pq := VerifyPqQuorum(pqBlock, message, pool, pqT)
	both := frostOK && pq["ok"] == true
	if both {
		return pqtStrip(map[string]any{"ok": both, "frost": frostOK, "pq": pq}), nil
	}
	reason := any(frostReason)
	if frostOK {
		reason = pq["reason"]
	}
	return pqtStrip(map[string]any{"ok": both, "frost": frostOK, "pq": pq, "reason": reason}), nil
}

// ---- signing, folding into a PCActn, and the core threshold hook

// PqSigner signs with one ML-DSA-65 key.
type PqSigner interface {
	Public() []byte
	Sign(msg []byte) ([]byte, error)
}

type mlDsa65Signer struct {
	pk *mldsa65.PublicKey
	sk *mldsa65.PrivateKey
}

// NewMlDsa65Signer expands a 32-byte seed (FIPS 204 xi) into an ML-DSA-65 key pair (circl).
func NewMlDsa65Signer(seed []byte) (PqSigner, error) {
	if len(seed) != mldsa65.SeedSize {
		return nil, fmt.Errorf("ML-DSA-65 seed must be %d bytes", mldsa65.SeedSize)
	}
	var s [mldsa65.SeedSize]byte
	copy(s[:], seed)
	pk, sk := mldsa65.NewKeyFromSeed(&s)
	return &mlDsa65Signer{pk, sk}, nil
}

func (k *mlDsa65Signer) Public() []byte { return k.pk.Bytes() }

func (k *mlDsa65Signer) Sign(msg []byte) ([]byte, error) {
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(k.sk, msg, nil, false, sig); err != nil {
		return nil, err
	}
	return sig, nil
}

// SignPqQuorum is one ML-DSA-65 co-signature per key pair over the quorum representative. pqT nil means the number of signers.
func SignPqQuorum(message []byte, keyPairs []PqSigner, pqT *int) (map[string]any, error) {
	rep := PqQuorumRepresentative(message)
	signers := make([]any, 0, len(keyPairs))
	for _, k := range keyPairs {
		sg, err := k.Sign(rep)
		if err != nil {
			return nil, err
		}
		signers = append(signers, map[string]any{"pk": b64.EncodeToString(k.Public()), "sig": b64.EncodeToString(sg)})
	}
	t := len(signers)
	if pqT != nil {
		t = *pqT
	}
	return map[string]any{"v": pqtIntNum(PqQuorumVersion), "alg": PqQuorumAlg, "pqT": pqtIntNum(t), "signers": signers}, nil
}

// HybridFrost is the classical half of a hybrid signing request: the group key (base64url string or 32 raw bytes), the quorum of
// participant shares and the threshold t.
type HybridFrost struct {
	GroupPublicKey any
	Quorum         []FrostParticipantShare
	T              int
}

// HybridThresholdSign is the hybrid artifact for action: a FROST t-of-n aggregate plus one ML-DSA-65 co-signature per pq signer,
// both over the same message. It fails closed on a short quorum or an invalid share.
func HybridThresholdSign(action map[string]any, frost HybridFrost, pqSigners []PqSigner, pqT *int) (map[string]any, error) {
	if frost.T < 1 {
		return nil, fmt.Errorf("hybridThresholdSign: frost.t must be a positive integer (got %d)", frost.T)
	}
	if len(frost.Quorum) < frost.T {
		return nil, fmt.Errorf("hybridThresholdSign: FROST quorum of %d is below the threshold t=%d", len(frost.Quorum), frost.T)
	}
	if len(pqSigners) == 0 {
		return nil, errors.New("hybridThresholdSign: at least one ML-DSA co-signer is required")
	}
	message, err := ThresholdMessage(action)
	if err != nil {
		return nil, err
	}
	var gk []byte
	switch g := frost.GroupPublicKey.(type) {
	case string:
		b, ok := DecodeB64uStrict(g, 32)
		if !ok {
			return nil, errors.New("hybridThresholdSign: FROST group public key is not canonical b64u(32)")
		}
		gk = b
	case []byte:
		if len(g) != 32 {
			return nil, errors.New("hybridThresholdSign: FROST group public key must be 32 bytes")
		}
		gk = g
	default:
		return nil, errors.New("hybridThresholdSign: FROST group public key must be 32 bytes")
	}
	t := frost.T
	agg, err := FrostCosign(gk, frost.Quorum, message, &t)
	if err != nil {
		return nil, err
	}
	pq, err := SignPqQuorum(message, pqSigners, pqT)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"v": pqtIntNum(HybridArtifactVersion), "digest": b64.EncodeToString(sha(message)),
		"frost": map[string]any{"alg": HybridClassicalAlg, "group_pk": b64.EncodeToString(gk), "sig": b64.EncodeToString(agg), "t": pqtIntNum(t), "quorum": pqtIntNum(len(frost.Quorum))},
		"pq":    pq,
	}, nil
}

// FoldHybridStepUp returns {pcactn, pq}: the FROST aggregate becomes a `guardian` share of the PCActn's threshold container (the
// signed body is unchanged: ThresholdMessage excludes `threshold`); the PQ block travels beside it.
func FoldHybridStepUp(action map[string]any, artifact any) (map[string]any, error) {
	frost, ok := pqtGet(artifact, "frost").(map[string]any)
	if !ok || action == nil {
		return nil, errors.New("foldHybridStepUp: malformed action or artifact")
	}
	share := map[string]any{"role": "guardian"}
	if v, has := frost["group_pk"]; has {
		share["publicKey"] = v
	}
	if v, has := frost["sig"]; has {
		share["sig"] = v
	}
	shares := []any{}
	if th, ok := action["threshold"].(map[string]any); ok {
		if l, ok := th["shares"].([]any); ok {
			shares = append(shares, l...)
		}
	}
	pcactn := make(map[string]any, len(action)+1)
	for k, v := range action {
		pcactn[k] = v
	}
	pcactn["threshold"] = map[string]any{"shares": append(shares, share)}
	out := map[string]any{"pcactn": pcactn}
	if m, ok := artifact.(map[string]any); ok {
		if pq, has := m["pq"]; has {
			out["pq"] = pq
		}
	}
	return out, nil
}

// CreateHybridThresholdVerifier is the threshold hook enforcing the hybrid step-up: the FROST aggregate folded into
// pcactn.threshold (an Ed25519 signature under the TRUSTED group key) AND the pqT-of-m quorum over this action. opts carries
// groupKey, pqPublicKeys, t, pqT, groupDescriptor, trustedAuthorities, signerSetCommitment? and pqBlock. The configuration is
// snapshotted at creation. The returned function takes the PCActn and returns {enforced, ok, reason?}; it errors only when the
// PCActn cannot be canonicalised.
func CreateHybridThresholdVerifier(opts map[string]any) (func(pcactn map[string]any) (map[string]any, error), error) {
	opts = pqtClone(opts).(map[string]any)
	trusted, trustedOK := pqtGroupKey(pqtGet(opts, "groupKey"))
	pool, err := NormalizePqQuorumPool(pqtGet(opts, "pqPublicKeys"))
	if err != nil {
		return nil, err
	}
	return func(pcactn map[string]any) (map[string]any, error) {
		no := func(reason string) (map[string]any, error) {
			return map[string]any{"enforced": true, "ok": false, "reason": reason}, nil
		}
		if d := pqtCheckDescriptor(opts); d != "" {
			return no(d)
		}
		message, err := ThresholdMessage(pcactn)
		if err != nil {
			return nil, err
		}
		if !trustedOK {
			return no("trusted FROST group key is not a canonical b64u(32) point")
		}
		var shares []any
		if th, ok := pcactn["threshold"].(map[string]any); ok {
			shares, _ = th["shares"].([]any)
		}
		var share map[string]any
		for _, x := range shares {
			if m, ok := x.(map[string]any); ok {
				if _, isStr := m["sig"].(string); isStr && m["publicKey"] == any(trusted) {
					share = m
					break
				}
			}
		}
		if share == nil {
			return no("no FROST aggregate for the trusted group key in the step-up")
		}
		if !pqtVerifyFrostAggregate(share["sig"], message, trusted) {
			return no("FROST aggregate does not verify under the trusted group key (quorum short or forged)")
		}
		blk := pqtGet(opts, "pqBlock")
		if blk == pqtAbsent {
			blk = nil
		}
		pqv := VerifyPqQuorum(blk, message, pool, pqtGet(opts, "pqT"))
		if pqv["ok"] != true {
			if r, _ := pqv["reason"].(string); r != "" {
				return no(r)
			}
			return no("post-quantum quorum short")
		}
		return map[string]any{"enforced": true, "ok": true}, nil
	}, nil
}

// VerifyHybridStepUp is the full verification of a folded step-up: the core verification of the PCActn plus the hybrid threshold
// hook (reported as the check "threshold"), and the standalone pq verdict. opts carries grant (map), groupKey, pqPublicKeys, t,
// pqT, groupDescriptor, trustedAuthorities, signerSetCommitment?, audience (string) and nowEpoch (epoch milliseconds). The core
// runs with the plan-root check switched off (a step-up is not an authorize call). Returns {allow, core (Verdict), pq, reason?}.
func VerifyHybridStepUp(stepUp, opts map[string]any) (map[string]any, error) {
	pcactn, ok := stepUp["pcactn"].(map[string]any)
	if !ok {
		return nil, errors.New("verifyHybridStepUp: step-up has no pcactn")
	}
	pool, err := NormalizePqQuorumPool(pqtGet(opts, "pqPublicKeys"))
	if err != nil {
		return nil, err
	}
	message, err := ThresholdMessage(pcactn)
	if err != nil {
		return nil, err
	}
	pq := VerifyPqQuorum(stepUp["pq"], message, pool, pqtGet(opts, "pqT"))
	hookOpts := map[string]any{}
	for _, k := range []string{"groupKey", "pqPublicKeys", "t", "pqT", "groupDescriptor", "trustedAuthorities", "signerSetCommitment"} {
		if v, has := opts[k]; has {
			hookOpts[k] = v
		}
	}
	hookOpts["pqBlock"] = stepUp["pq"]
	hook, err := CreateHybridThresholdVerifier(hookOpts)
	if err != nil {
		return nil, err
	}
	grant, _ := opts["grant"].(map[string]any)
	nowF, _ := jsNum(opts["nowEpoch"])
	aud, _ := opts["audience"].(string)
	core, err := VerifyPCActnCoreWith(pcactn, grant, int64(nowF), aud, VerifyOptions{InsecureSkipPlanRootCheck: true})
	if err != nil {
		return nil, err
	}
	hv, err := hook(pcactn)
	if err != nil {
		return nil, err
	}
	hookOK := hv["ok"] == true
	if core.Checks != nil {
		core.Checks["threshold"] = hookOK
	}
	out := map[string]any{"allow": core.Allow && hookOK, "core": core, "pq": pq}
	switch {
	case !core.Allow:
		out["reason"] = core.Reason
	case !hookOK:
		out["reason"] = "threshold: " + hv["reason"].(string)
	}
	return out, nil
}
