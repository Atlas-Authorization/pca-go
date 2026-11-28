package pca

// The guardian signer service of networked FROST: it holds EXACTLY ONE share and never emits it. Round 1 commits to a fresh nonce pair
// (durable before the commitment leaves the process when a nonce store is configured); round 2 releases a signature share only for
// a session with live round-1 state, naming this signer's group key, whose allow token verifies independently against the policy
// authority key the signer was CONFIGURED with and binds to the exact message. A refusal keeps the round-1 nonces (an honest retry with
// a valid token still works); a success consumes them one-shot. Requests and responses are the JSON-shaped wire values.

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sync"
)

// GuardianSignerOptions configure NewGuardianSignerService. Threshold is t: the signer refuses a signing set below it. SessionTtlMs
// (nil: none) is the stale-session guard. Now is the clock in ms (default the wall clock). NonceStore (nil: nonces are kept in memory
// only) makes a restart resume live sessions and burns a session before its share is computed.
type GuardianSignerOptions struct {
	Identifier               int64
	Share, GroupPublicKey    []byte
	Threshold                int
	PolicyAuthorityPublicKey []byte
	SessionTtlMs             *float64
	Now                      func() float64
	NonceStore               FrostNonceStore
	// Rand draws the 32-byte randomness of the signer (the proof-of-possession nonce, then the two round-1 nonces of each session); nil
	// is crypto/rand. A test scripts it.
	Rand func() ([]byte, error)
}

type frostSession struct {
	nonces     FrostNonces
	commitment FrostCommitment
	createdAt  float64
}

// GuardianSignerService is a single-share FROST signer: one instance, one trust domain.
type GuardianSignerService struct {
	mu           sync.Mutex
	identifier   int64
	verification []byte
	share        []byte
	sessions     map[string]*frostSession
	spent        map[string]bool
	pop          map[string]any
	group        []byte
	threshold    int
	authority    []byte
	ttl          *float64
	now          func() float64
	store        FrostNonceStore
	rand         func() ([]byte, error)
}

// NewGuardianSignerService validates the options and builds the signer; its proof of possession is made once, up front.
func NewGuardianSignerService(o GuardianSignerOptions) (*GuardianSignerService, error) {
	if !frostIsID(o.Identifier) {
		return nil, errors.New("GuardianSignerService: identifier must be a positive integer")
	}
	if len(o.Share) != 32 {
		return nil, errors.New("GuardianSignerService: share must be 32 bytes")
	}
	if len(o.GroupPublicKey) != 32 {
		return nil, errors.New("GuardianSignerService: groupPublicKey must be 32 bytes")
	}
	if o.Threshold < 1 {
		return nil, errors.New("GuardianSignerService: threshold must be a positive integer")
	}
	if len(o.PolicyAuthorityPublicKey) != 32 {
		return nil, errors.New("GuardianSignerService: policyAuthorityPublicKey must be 32 bytes")
	}
	if o.SessionTtlMs != nil && (math.IsNaN(*o.SessionTtlMs) || math.IsInf(*o.SessionTtlMs, 0) || *o.SessionTtlMs <= 0) {
		return nil, errors.New("GuardianSignerService: sessionTtlMs must be a positive finite number")
	}
	s := &GuardianSignerService{identifier: o.Identifier, share: append([]byte{}, o.Share...), group: append([]byte{}, o.GroupPublicKey...), threshold: o.Threshold,
		authority: append([]byte{}, o.PolicyAuthorityPublicKey...), ttl: o.SessionTtlMs, now: o.Now, store: o.NonceStore,
		sessions: map[string]*frostSession{}, spent: map[string]bool{}}
	s.rand = o.Rand
	if s.rand == nil {
		s.rand = frostNetRand
	}
	if s.now == nil {
		s.now = func() float64 { return float64(attNowMs()) }
	}
	vs, err := FrostVerifyingShare(s.share)
	if err != nil {
		return nil, err
	}
	s.verification = vs
	if s.pop, err = createSignerPoP(s.identifier, s.share, s.group, nil, s.rand); err != nil {
		return nil, err
	}
	return s, nil
}

// Identifier is the participant identifier of the signer.
func (s *GuardianSignerService) Identifier() int64 { return s.identifier }

// VerificationShare is the public verification share of the signer's share.
func (s *GuardianSignerService) VerificationShare() []byte {
	return append([]byte{}, s.verification...)
}

// ProofOfPossession is the signer's proof of possession of its verification share (safe to publish).
func (s *GuardianSignerService) ProofOfPossession() map[string]any { return s.pop }

// Enrollment is a ready-to-enroll record (identifier, verification share, proof of possession) for EnrollVerificationShares.
func (s *GuardianSignerService) Enrollment() map[string]any {
	return map[string]any{"identifier": jsNumber(float64(s.identifier)), "publicKey": s.VerificationShare(), "pop": s.pop}
}

func (s *GuardianSignerService) idNum() json.Number { return jsNumber(float64(s.identifier)) }

func (s *GuardianSignerService) fail1(reason string) map[string]any {
	return map[string]any{"ok": false, "identifier": s.idNum(), "reason": reason}
}

func (s *GuardianSignerService) refuse(reason string) map[string]any {
	return map[string]any{"ok": false, "identifier": s.idNum(), "refused": true, "reason": reason}
}

func wireStr(m map[string]any, k string) (string, bool) { v, ok := m[k].(string); return v, ok }

// storeSpent reports whether the durable store knows the session as spent.
func (s *GuardianSignerService) storeSpent(sid string) (bool, error) {
	if s.store == nil {
		return false, nil
	}
	return s.store.IsSpent(sid)
}

// Round1 commits to a fresh nonce pair for the request's session and keeps the SECRET nonces locally. The request is
// {typ: "pca.frost.round1.v1", session_id}; the response {ok, identifier, commitment, pop} or {ok: false, identifier, reason}.
func (s *GuardianSignerService) Round1(req any) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, isMap := req.(map[string]any)
	sid, isStr := wireStr(m, "session_id")
	if !isMap || m["typ"] != "pca.frost.round1.v1" || !isStr || sid == "" {
		return s.fail1("malformed round-1 request")
	}
	spent, err := s.storeSpent(sid)
	if err != nil {
		return s.fail1(err.Error())
	}
	if s.spent[sid] || spent {
		return s.fail1("session already signed")
	}
	live := s.sessions[sid] != nil
	if !live && s.store != nil {
		rec, err := s.store.Load(sid)
		if err != nil {
			return s.fail1(err.Error())
		}
		live = rec != nil
	}
	if live { // never overwrite live nonces for a session (a nonce-reuse foot-gun)
		return s.fail1("duplicate round-1 for session")
	}
	hr, err := s.rand()
	if err != nil {
		return s.fail1(err.Error())
	}
	br, err := s.rand()
	if err != nil {
		return s.fail1(err.Error())
	}
	c, err := FrostCommit(FrostParticipantShare{Identifier: s.identifier, Share: s.share, PublicKey: s.verification}, hr, br)
	if err != nil {
		return s.fail1(err.Error())
	}
	createdAt := s.now()
	if s.store != nil { // durable BEFORE the commitment leaves this process
		if err := s.store.Create(sid, FrostNonceRecord{Hiding: c.HidingNonce, Binding: c.BindingNonce, HidingCommitment: c.Commitment.Hiding, BindingCommitment: c.Commitment.Binding, CreatedAt: createdAt}); err != nil {
			return s.fail1(err.Error())
		}
	}
	s.sessions[sid] = &frostSession{nonces: FrostNonces{Hiding: c.HidingNonce, Binding: c.BindingNonce}, commitment: c.Commitment, createdAt: createdAt}
	return map[string]any{"ok": true, "identifier": s.idNum(), "pop": s.pop,
		"commitment": map[string]any{"identifier": jsNumber(float64(c.Commitment.Identifier)), "hiding": b64.EncodeToString(c.Commitment.Hiding), "binding": b64.EncodeToString(c.Commitment.Binding)}}
}

// Round2 releases a signature share iff the allow token verifies and the session has live round-1 state. The request is the
// round-2 wire object; the response {ok, identifier, sig_share} or {ok: false, identifier, refused: true, reason}.
func (s *GuardianSignerService) Round2(req any) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, isMap := req.(map[string]any)
	sid, isStr := wireStr(m, "session_id")
	if !isMap || m["typ"] != "pca.frost.round2.v1" || !isStr {
		return s.refuse("malformed round-2 request")
	}
	spent, err := s.storeSpent(sid)
	if err != nil {
		return s.refuse(err.Error())
	}
	if s.spent[sid] || spent {
		return s.refuse("session already signed (one-shot)")
	}
	state := s.sessions[sid]
	if state == nil && s.store != nil { // restart recovery: resume a live session from the durable store
		rec, err := s.store.Load(sid)
		if err != nil {
			return s.refuse(err.Error())
		}
		if rec != nil {
			state = &frostSession{nonces: FrostNonces{Hiding: rec.Hiding, Binding: rec.Binding},
				commitment: FrostCommitment{Identifier: s.identifier, Hiding: rec.HidingCommitment, Binding: rec.BindingCommitment}, createdAt: rec.CreatedAt}
			s.sessions[sid] = state
		}
	}
	if state == nil {
		return s.refuse("no round-1 state for this session")
	}
	if age := s.now() - state.createdAt; s.ttl != nil && !(finite(age) && age <= *s.ttl) { // the stale-session guard: dropped, not signed; a non-finite age is stale
		delete(s.sessions, sid)
		if s.store != nil {
			if err := s.store.Drop(sid); err != nil {
				return s.refuse(err.Error())
			}
		}
		return s.refuse(fmt.Sprintf("session expired (stale-session guard: round-1 older than %sms)", jsNumberString(*s.ttl)))
	}
	ms, _ := wireStr(m, "message")
	message, good := DecodeB64uStrict(ms, -1)
	if _, ok := wireStr(m, "message"); !ok || !good {
		return s.refuse("message not canonical base64url")
	}
	if message == nil {
		message = []byte{}
	}
	if message == nil {
		message = []byte{}
	}
	if m["group_pk"] != b64.EncodeToString(s.group) {
		return s.refuse("request names a different group key")
	}
	if ok, why := VerifyAllowToken(m["allow"], s.authority, s.group, message, s.now()); !ok {
		return s.refuse("policy authorization failed: " + why)
	}
	var rawCommitments any = []any{}
	if c, has := m["commitments"]; has && c != nil {
		rawCommitments = c
	}
	commitments, err := DecodeCommitments(rawCommitments)
	if err != nil {
		return s.refuse(err.Error())
	}
	if len(commitments) < s.threshold {
		return s.refuse(fmt.Sprintf("signing set below threshold t=%d", s.threshold))
	}
	var own *FrostCommitment
	for i := range commitments {
		if commitments[i].Identifier == s.identifier {
			own = &commitments[i]
			break
		}
	}
	if own == nil {
		return s.refuse("our commitment is not in the signing set")
	}
	if string(own.Hiding) != string(state.commitment.Hiding) || string(own.Binding) != string(state.commitment.Binding) {
		return s.refuse("equivocation detected: our commitment in the signing set differs from our round-1 commitment")
	}
	vshares, err := DecodeVerificationShares(m["verification_shares"])
	if err != nil {
		return s.refuse(err.Error())
	}
	if s.store != nil { // spent marker first (durable), then sign: a refusal after this line burns the session
		if err := s.store.Spend(sid); err != nil {
			return s.refuse(err.Error())
		}
	}
	t := s.threshold
	sig, err := FrostSign(s.identifier, s.share, s.group, state.nonces, message, commitments, FrostSignOpts{Threshold: &t, VerificationShare: s.verification, VerificationShares: vshares})
	if err != nil {
		return s.refuse(err.Error())
	}
	delete(s.sessions, sid)
	s.spent[sid] = true
	return map[string]any{"ok": true, "identifier": s.idNum(), "sig_share": b64.EncodeToString(sig.SigShare)}
}
