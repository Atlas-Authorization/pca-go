package pca

// Networked FROST signing, the building blocks: the allow token a policy authority signs for one exact action under one group key,
// the signer proof of possession that gates enrolment (rogue-key defence), the equivocation guard and the strict wire decoders. The
// signer service, the coordinator and their transports build on these.

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"

	ed "filippo.io/edwards25519"
)

const (
	// AllowTokenTyp is the type tag of an allow token body.
	AllowTokenTyp = "pca.frost.allow.v1"
	// SignerPopDst is the domain separation tag of the signer proof of possession.
	SignerPopDst = "pca.frost.signer-pop.v1"
	// MaxFrostSigningSet is the largest signing set a signer or coordinator decodes.
	MaxFrostSigningSet = 256
	// DefaultFrostGroupAlg is the group signature algorithm of a plain FROST group.
	DefaultFrostGroupAlg = "ed25519"
)

// frostNetRand is the source of the 32-byte random draws of this module (a var so a test can script them).
var frostNetRand = func() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return b, err
}

// FrostActionDigest is base64url(sha256(message)): the action digest an allow token authorizes.
func FrostActionDigest(message []byte) string { return b64.EncodeToString(sha(message)) }

// IssueAllowOptions are the options of IssueAllowToken. Message (nil: absent; an empty slice is a message) or FrostActionDigest names
// the action; Nonce defaults to base64url of one random 32-byte draw.
type IssueAllowOptions struct {
	Message           []byte
	FrostActionDigest *string
	GroupPublicKey    []byte
	Nonce             *string
	NotBefore         *float64
	ExpiresAt         *float64
}

// IssueAllowToken mints an allow token {body, authority, sig} with the policy authority's Ed25519 secret key (a 32-byte seed).
func IssueAllowToken(policySecretKey []byte, o IssueAllowOptions) (map[string]any, error) {
	digest, has := "", false
	switch {
	case o.FrostActionDigest != nil:
		digest, has = *o.FrostActionDigest, true
	case o.Message != nil:
		digest, has = FrostActionDigest(o.Message), true
	}
	if !has || digest == "" {
		return nil, errors.New("issueAllowToken: provide message or frostActionDigest")
	}
	kp, err := KeyPairFromSeed(policySecretKey)
	if err != nil {
		return nil, err
	}
	nonce := ""
	if o.Nonce != nil {
		nonce = *o.Nonce
	} else {
		r, err := frostNetRand()
		if err != nil {
			return nil, err
		}
		nonce = b64.EncodeToString(r)
	}
	body := map[string]any{"typ": AllowTokenTyp, "action_digest": digest, "group_pk": b64.EncodeToString(o.GroupPublicKey), "nonce": nonce}
	if o.NotBefore != nil {
		body["not_before"] = jsNumber(*o.NotBefore)
	}
	if o.ExpiresAt != nil {
		body["expires_at"] = jsNumber(*o.ExpiresAt)
	}
	cb, err := CanonicalBytes(body)
	if err != nil {
		return nil, err
	}
	return map[string]any{"body": body, "authority": kp.Public, "sig": b64.EncodeToString(kp.Sign(cb))}, nil
}

// VerifyAllowToken verifies an allow token independently, as each signer does: well formed, the right typ, signed by the CONFIGURED
// authority key (never the token's own `authority` member), naming the configured group key and this message's action digest, and
// inside its validity window. A refusal is ok false with the reason; the text after "(fail closed)" of a verification error is open.
func VerifyAllowToken(token any, policyAuthorityPublicKey, groupPublicKey, message []byte, now float64) (ok bool, reason string) {
	defer func() {
		if r := recover(); r != nil {
			ok, reason = false, fmt.Sprintf("allow token verification error (fail closed): %v", r)
		}
	}()
	var t map[string]any
	switch x := token.(type) {
	case map[string]any:
		t = x
	case []any: // an array is an object that has no members
		t = map[string]any{}
	default:
		return false, "allow token missing or malformed"
	}
	var body map[string]any
	switch x := t["body"].(type) {
	case map[string]any:
		body = x
	case []any:
		body = map[string]any{}
	default:
		return false, "allow token has no body"
	}
	if body["typ"] != AllowTokenTyp {
		typ := "undefined"
		if v, has := body["typ"]; has {
			typ = jsValueString(v)
		}
		return false, fmt.Sprintf("allow token wrong typ (%s)", typ)
	}
	sigS, isStr := t["sig"].(string)
	if !isStr {
		return false, "allow token missing signature"
	}
	sig, good := DecodeB64uStrict(sigS, 64)
	if !good {
		return false, "allow token signature not canonical base64url"
	}
	cb, err := CanonicalBytes(body)
	if err != nil {
		return false, "allow token verification error (fail closed): " + err.Error()
	}
	if len(policyAuthorityPublicKey) != ed25519.PublicKeySize || !ed25519.Verify(policyAuthorityPublicKey, cb, sig) {
		return false, "allow token not signed by the trusted policy authority"
	}
	if body["group_pk"] != b64.EncodeToString(groupPublicKey) {
		return false, "allow token authorizes a different group key"
	}
	if message == nil {
		return false, "allow token verification error (fail closed): frostActionDigest: message must be bytes"
	}
	if body["action_digest"] != FrostActionDigest(message) {
		return false, "allow token authorizes a different action digest"
	}
	if math.IsNaN(now) || math.IsInf(now, 0) {
		return false, "invalid verification time"
	}
	if nb, has := body["not_before"]; has && now < jsToNumber(nb) {
		return false, "allow token not yet valid"
	}
	if ex, has := body["expires_at"]; has && now >= jsToNumber(ex) {
		return false, "allow token expired"
	}
	return true, ""
}

// ---- signer proof of possession -----------------------------------------------------------------------------------------------

// signerPopChallenge is e = SHA-512(DST || group_pk || scalar(id) || PK || R) reduced mod L, never zero.
func signerPopChallenge(groupPublicKey []byte, identifier int64, pk, r []byte) *ed.Scalar {
	m := append([]byte(SignerPopDst), groupPublicKey...)
	m = append(m, frostIDScalar(identifier).Bytes()...)
	m = append(m, pk...)
	m = append(m, r...)
	e := frostH2S(m)
	if e.Equal(ed.NewScalar()) == 1 {
		one, _ := ed.NewScalar().SetCanonicalBytes(append([]byte{1}, make([]byte, 31)...))
		return one
	}
	return e
}

// CreateSignerPoP is the Schnorr proof of possession of the verification share of share, bound to the group key: R = k*B,
// e = H(DST || group_pk || id || PK || R), s = k + e*x. nonce, when given, fixes k (reproducible vectors only); else k is drawn at
// random, redrawn while it reduces to zero. The result is {identifier, publicKey, R, s}.
func CreateSignerPoP(identifier int64, share, groupPublicKey, nonce []byte) (map[string]any, error) {
	return createSignerPoP(identifier, share, groupPublicKey, nonce, frostNetRand)
}

// createSignerPoP is CreateSignerPoP over an explicit source of the random draw.
func createSignerPoP(identifier int64, share, groupPublicKey, nonce []byte, draw func() ([]byte, error)) (map[string]any, error) {
	if !frostIsID(identifier) {
		return nil, errors.New("createSignerPoP: identifier must be a positive integer")
	}
	if len(share) != 32 {
		return nil, errors.New("createSignerPoP: share must be 32 bytes")
	}
	if len(groupPublicKey) != 32 {
		return nil, errors.New("createSignerPoP: groupPublicKey must be 32 bytes")
	}
	x, err := frostReduce(share)
	if err != nil {
		return nil, err
	}
	pk := frostBase(x).Bytes()
	zero := ed.NewScalar()
	var k *ed.Scalar
	if nonce != nil {
		if k, err = frostReduce(nonce); err != nil {
			return nil, err
		}
	} else {
		k = zero
	}
	for k.Equal(zero) == 1 {
		r, err := draw()
		if err != nil {
			return nil, err
		}
		if k, err = frostReduce(r); err != nil {
			return nil, err
		}
	}
	rb := frostBase(k).Bytes()
	e := signerPopChallenge(groupPublicKey, identifier, pk, rb)
	s := ed.NewScalar().MultiplyAdd(e, x, k)
	return map[string]any{"identifier": jsNumber(float64(identifier)), "publicKey": b64.EncodeToString(pk), "R": b64.EncodeToString(rb), "s": b64.EncodeToString(s.Bytes())}, nil
}

// VerifySignerPoP verifies a proof of possession: s*B == R + e*PK with R and PK decoded through the strict point rules and s
// canonical. It never panics; anything malformed is false. Callers also bind pop.publicKey and pop.identifier to the key they expect.
func VerifySignerPoP(pop any, groupPublicKey []byte) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	p, isMap := pop.(map[string]any)
	if !isMap {
		return false
	}
	id, isID := frostIDOf(p["identifier"])
	if !isID || len(groupPublicKey) != 32 {
		return false
	}
	pkS, ok1 := p["publicKey"].(string)
	rS, ok2 := p["R"].(string)
	sS, ok3 := p["s"].(string)
	if !ok1 || !ok2 || !ok3 {
		return false
	}
	pk, g1 := DecodeB64uStrict(pkS, 32)
	rb, g2 := DecodeB64uStrict(rS, 32)
	sb, g3 := DecodeB64uStrict(sS, 32)
	if !g1 || !g2 || !g3 {
		return false
	}
	pkPt, err1 := frostPoint(pk)
	rPt, err2 := frostPoint(rb)
	if err1 != nil || err2 != nil || !FrostIsCanonicalScalar(sb) {
		return false
	}
	s, err := ed.NewScalar().SetCanonicalBytes(sb)
	if err != nil {
		return false
	}
	e := signerPopChallenge(groupPublicKey, id, pk, rb)
	lhs := frostBase(s)
	rhs := frostAdd(rPt, frostMul(pkPt, e))
	return lhs.Equal(rhs) == 1
}

// frostIDOf reads a participant identifier: a positive safe integer JSON number.
func frostIDOf(v any) (int64, bool) {
	f, ok := jsNum(v)
	if !ok || !jsIsInt(v) || f <= 0 {
		return 0, false
	}
	return int64(f), true
}

// PoPError is a signer key without a valid proof of possession; Identifier is set when the refusal names a signer.
type PoPError struct {
	Message       string
	Identifier    int64
	HasIdentifier bool
}

func (e *PoPError) Error() string { return e.Message }

func popErr(id int64, format string, a ...any) *PoPError {
	return &PoPError{Message: fmt.Sprintf(format, a...), Identifier: id, HasIdentifier: true}
}

// EnrollVerificationShares accepts each signer enrollment only if it carries a valid proof of possession binding its verification
// share under the group key, and returns the plain {identifier, publicKey} list for a coordinator. Each enrollment is
// {identifier, publicKey (32 bytes), pop}; a missing, mismatched or invalid proof (a rogue key) or a duplicate is a *PoPError.
func EnrollVerificationShares(enrollments []any, groupPublicKey []byte) ([]FrostVerificationShare, error) {
	if len(enrollments) == 0 {
		return nil, &PoPError{Message: "enrollVerificationShares: no signer enrollments"}
	}
	if len(groupPublicKey) != 32 {
		return nil, &PoPError{Message: "enrollVerificationShares: groupPublicKey must be 32 bytes"}
	}
	out := []FrostVerificationShare{}
	seen := map[int64]bool{}
	for _, x := range enrollments {
		e, isMap := x.(map[string]any)
		id, isID := int64(0), false
		if isMap {
			id, isID = frostIDOf(e["identifier"])
		}
		if !isMap || !isID {
			return nil, &PoPError{Message: "enrollVerificationShares: enrollment with invalid identifier"}
		}
		if seen[id] {
			return nil, popErr(id, "enrollVerificationShares: duplicate enrollment for signer %d", id)
		}
		seen[id] = true
		pk, isBytes := e["publicKey"].([]byte)
		if !isBytes || len(pk) != 32 {
			return nil, popErr(id, "enrollVerificationShares: signer %d verification share must be 32 bytes", id)
		}
		pop, isPop := e["pop"].(map[string]any)
		if pid, _ := frostIDOf(pop["identifier"]); !isPop || pid != id || pop["publicKey"] != b64.EncodeToString(pk) {
			return nil, popErr(id, "enrollVerificationShares: signer %d missing or mismatched proof-of-possession (rogue key rejected)", id)
		}
		if !VerifySignerPoP(pop, groupPublicKey) {
			return nil, popErr(id, "enrollVerificationShares: signer %d invalid proof-of-possession (rogue key rejected)", id)
		}
		out = append(out, FrostVerificationShare{Identifier: id, PublicKey: pk})
	}
	return out, nil
}

// ---- equivocation guard -------------------------------------------------------------------------------------------------------

// EquivocationError is a signer's second, different message for the same (session, round).
type EquivocationError struct {
	SessionID                       string
	Round                           int64
	Identifier                      int64
	PreviousDigest, OffendingDigest string
}

func (e *EquivocationError) Error() string {
	return fmt.Sprintf("equivocation: signer %d sent two different messages for session '%s' round %d", e.Identifier, e.SessionID, e.Round)
}

// EquivocationGuard records the FIRST message seen per (session_id, round, signer) and refuses any second, DIFFERING one; an
// identical repeat is idempotent. Safe for concurrent use.
type EquivocationGuard struct {
	mu   sync.Mutex
	seen map[string]string
}

// NewEquivocationGuard returns an empty guard.
func NewEquivocationGuard() *EquivocationGuard { return &EquivocationGuard{seen: map[string]string{}} }

// Observe records a round message; a second, differing message for the tuple is an *EquivocationError. Anything else malformed is an
// ordinary error.
func (g *EquivocationGuard) Observe(sessionID string, round, identifier int64, message any) error {
	if sessionID == "" {
		return errors.New("EquivocationGuard: session_id must be a non-empty string")
	}
	if round < 1 || round > frostMaxSafeInt {
		return errors.New("EquivocationGuard: round must be a positive integer")
	}
	if !frostIsID(identifier) {
		return errors.New("EquivocationGuard: identifier must be a positive integer")
	}
	cb, err := CanonicalBytes(message)
	if err != nil {
		return err
	}
	digest := b64.EncodeToString(sha(cb))
	key := fmt.Sprintf("%s\x00%d\x00%d", sessionID, round, identifier)
	g.mu.Lock()
	defer g.mu.Unlock()
	prev, has := g.seen[key]
	if !has {
		g.seen[key] = digest
		return nil
	}
	if prev != digest {
		return &EquivocationError{SessionID: sessionID, Round: round, Identifier: identifier, PreviousDigest: prev, OffendingDigest: digest}
	}
	return nil
}

// Forget drops every binding of a session.
func (g *EquivocationGuard) Forget(sessionID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	prefix := sessionID + "\x00"
	for k := range g.seen {
		if strings.HasPrefix(k, prefix) {
			delete(g.seen, k)
		}
	}
}

// ---- wire decoders ------------------------------------------------------------------------------------------------------------

// DecodeCommitment strictly decodes one wire commitment {identifier, hiding, binding}: any non-object, non-integer identifier or
// non-canonical encoding is an error. The points are NOT validated here.
func DecodeCommitment(w any) (FrostCommitment, error) {
	m, ok := w.(map[string]any)
	if !ok {
		return FrostCommitment{}, errors.New("bad commitment")
	}
	hs, _ := m["hiding"].(string)
	bs, _ := m["binding"].(string)
	hiding, ok1 := DecodeB64uStrict(hs, 32)
	binding, ok2 := DecodeB64uStrict(bs, 32)
	if _, isStr := m["hiding"].(string); !isStr {
		ok1 = false
	}
	if _, isStr := m["binding"].(string); !isStr {
		ok2 = false
	}
	id, isID := frostIDOf(m["identifier"])
	if !isID {
		return FrostCommitment{}, errors.New("bad commitment identifier")
	}
	if !ok1 || !ok2 {
		return FrostCommitment{}, errors.New("bad commitment point encoding")
	}
	return FrostCommitment{Identifier: id, Hiding: hiding, Binding: binding}, nil
}

// DecodeCommitments strictly decodes a list of wire commitments, bounded by MaxFrostSigningSet.
func DecodeCommitments(list any) ([]FrostCommitment, error) {
	l, ok := list.([]any)
	if !ok {
		return nil, errors.New("commitments must be a list")
	}
	if len(l) > MaxFrostSigningSet {
		return nil, errors.New("commitments list exceeds the maximum signing set")
	}
	out := make([]FrostCommitment, 0, len(l))
	for _, x := range l {
		c, err := DecodeCommitment(x)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// DecodeVerificationShares strictly decodes the public verification shares of a signing set, bounded by MaxFrostSigningSet.
func DecodeVerificationShares(list any) ([]FrostVerificationShare, error) {
	l, ok := list.([]any)
	if !ok {
		return nil, errors.New("verification_shares must be a list")
	}
	if len(l) > MaxFrostSigningSet {
		return nil, errors.New("verification_shares list exceeds the maximum signing set")
	}
	out := make([]FrostVerificationShare, 0, len(l))
	for _, x := range l {
		m, isMap := x.(map[string]any)
		if !isMap {
			return nil, errors.New("bad verification share")
		}
		ks, isStr := m["publicKey"].(string)
		pk, good := DecodeB64uStrict(ks, 32)
		id, isID := frostIDOf(m["identifier"])
		if !isID {
			return nil, errors.New("bad verification-share identifier")
		}
		if !isStr || !good {
			return nil, errors.New("bad verification-share key encoding")
		}
		out = append(out, FrostVerificationShare{Identifier: id, PublicKey: pk})
	}
	return out, nil
}
