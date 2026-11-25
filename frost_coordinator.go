package pca

// The network coordinator of FROST: it collects commitments and shares from signer transports and aggregates; it holds NO share and,
// with no allow token it can forge, cannot make honest signers release. Round 1 collects t commitments (each signer proves possession
// of the verification share on record, and cannot bind a (session, round) to two different messages); round 2 collects the matching
// shares; the aggregate is re-verified by the FROST primitives. A bounded deadline aborts a slow session with a typed error and no
// signature. Requests and responses are the JSON-shaped wire values.

import (
	"errors"
	"fmt"
	"math"
	"sync"
	"time"
)

// SignerTransport reaches one signer: round 1 and round 2 exchange the wire objects of GuardianSignerService. An error is an unreachable
// signer.
type SignerTransport interface {
	Identifier() int64
	Round1(req map[string]any) (map[string]any, error)
	Round2(req map[string]any) (map[string]any, error)
}

// InProcessTransport wraps a signer service behind the transport interface: a separate object with isolated session state, reached
// only through calls (the coordinator holds this handle, not the share).
func InProcessTransport(s *GuardianSignerService) SignerTransport { return inProcessTransport{s} }

type inProcessTransport struct{ s *GuardianSignerService }

func (t inProcessTransport) Identifier() int64 { return t.s.Identifier() }
func (t inProcessTransport) Round1(req map[string]any) (map[string]any, error) {
	return t.s.Round1(req), nil
}
func (t inProcessTransport) Round2(req map[string]any) (map[string]any, error) {
	return t.s.Round2(req), nil
}

// CoordinatorRefusal names a signer that refused (or was dropped) and why; both are the values of the response as given.
type CoordinatorRefusal struct {
	Identifier any
	Reason     any
}

// CoordinatorError is a signing session that did not reach the threshold; Refusals names the signers that refused.
type CoordinatorError struct {
	Message  string
	Refusals []CoordinatorRefusal
}

func (e *CoordinatorError) Error() string { return e.Message }

// CoordinatorTimeoutError is a session that exceeded its bounded deadline: no signature was produced.
type CoordinatorTimeoutError struct {
	CoordinatorError
	TimeoutMs float64
}

// NetworkCoordinatorOptions configure NewNetworkCoordinator. Provide VerificationShares or Enroll (the hardened form: every proof of
// possession is verified at construction and a rogue key is a *PoPError; it wins when both are given). TimeoutMs (nil: none) is the
// round deadline of a whole Sign call; a per-call value overrides it. NewSessionID defaults to a random id.
type NetworkCoordinatorOptions struct {
	GroupPublicKey     []byte
	Threshold          int
	Signers            []SignerTransport
	VerificationShares []FrostVerificationShare
	Enroll             []any
	NewSessionID       func() (string, error)
	TimeoutMs          *float64
	// NewTimer starts the deadline of a Sign call: a channel closed when ms have passed, and a stop function; nil is the real clock.
	// A test injects a clock it advances itself.
	NewTimer func(ms float64) (<-chan struct{}, func())
}

// NetworkSignResult is a finished session: the aggregate standard Ed25519 signature, the session id and the signers that
// contributed a valid share.
type NetworkSignResult struct {
	Signature []byte
	SessionID string
	Signers   []int64
}

// NetworkCoordinator drives t-of-n network signing sessions.
type NetworkCoordinator struct {
	group     []byte
	threshold int
	signers   []SignerTransport
	vshares   []FrostVerificationShare
	pkByID    map[int64]string
	guard     *EquivocationGuard
	newID     func() (string, error)
	timeoutMs *float64
	newTimer  func(ms float64) (<-chan struct{}, func())
}

// NewNetworkCoordinator validates the options and builds the coordinator.
func NewNetworkCoordinator(o NetworkCoordinatorOptions) (*NetworkCoordinator, error) {
	if len(o.GroupPublicKey) != 32 {
		return nil, errors.New("NetworkCoordinator: groupPublicKey must be 32 bytes")
	}
	if o.Threshold < 1 {
		return nil, errors.New("NetworkCoordinator: threshold must be a positive integer")
	}
	if o.TimeoutMs != nil && (math.IsNaN(*o.TimeoutMs) || math.IsInf(*o.TimeoutMs, 0) || *o.TimeoutMs <= 0) {
		return nil, errors.New("NetworkCoordinator: timeoutMs must be a positive finite number")
	}
	c := &NetworkCoordinator{group: o.GroupPublicKey, threshold: o.Threshold, signers: append([]SignerTransport{}, o.Signers...), guard: NewEquivocationGuard(),
		newID: o.NewSessionID, timeoutMs: o.TimeoutMs, newTimer: o.NewTimer, pkByID: map[int64]string{}}
	switch {
	case o.Enroll != nil:
		vs, err := EnrollVerificationShares(o.Enroll, o.GroupPublicKey)
		if err != nil {
			return nil, err
		}
		c.vshares = vs
	case o.VerificationShares != nil:
		c.vshares = append([]FrostVerificationShare{}, o.VerificationShares...)
	default:
		return nil, errors.New("NetworkCoordinator: provide verificationShares or enroll")
	}
	for _, v := range c.vshares {
		c.pkByID[v.Identifier] = b64.EncodeToString(v.PublicKey)
	}
	if c.newID == nil {
		c.newID = func() (string, error) {
			r, err := frostNetRand()
			return b64.EncodeToString(r), err
		}
	}
	return c, nil
}

// Sign drives one t-of-n session over message with the allow token. signerIDs (nil: the first t signers) picks the signers to ask;
// timeoutMs (nil: the constructor's) bounds the whole call. It returns the aggregate signature, or a *CoordinatorError naming the
// refusals, a *CoordinatorTimeoutError, or another error.
func (c *NetworkCoordinator) Sign(message []byte, allow any, signerIDs []int64, timeoutMs *float64) (*NetworkSignResult, error) {
	window := c.timeoutMs
	if timeoutMs != nil {
		window = timeoutMs
	}
	type outcome struct {
		res *NetworkSignResult
		err error
	}
	done := make(chan outcome, 1)
	var expired <-chan struct{}
	if window != nil && !math.IsNaN(*window) && !math.IsInf(*window, 0) && *window > 0 {
		newTimer := c.newTimer
		if newTimer == nil {
			newTimer = func(ms float64) (<-chan struct{}, func()) {
				ch := make(chan struct{})
				tm := time.AfterFunc(time.Duration(ms*float64(time.Millisecond)), func() { close(ch) })
				return ch, func() { tm.Stop() }
			}
		}
		var stop func()
		expired, stop = newTimer(*window) // started before the session, so a fake clock sees the deadline first
		defer stop()
	}
	go func() {
		r, err := c.drive(message, allow, signerIDs)
		done <- outcome{r, err}
	}()
	if expired == nil {
		o := <-done
		return o.res, o.err
	}
	select {
	case o := <-done:
		return o.res, o.err
	case <-expired:
		return nil, &CoordinatorTimeoutError{CoordinatorError: CoordinatorError{Message: fmt.Sprintf("coordinator: signing session did not reach threshold within %sms", jsNumberString(*window))}, TimeoutMs: *window}
	}
}

// truthy is JavaScript truthiness of a decoded JSON value.
func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	}
	if f, ok := jsNum(v); ok {
		return f != 0 && !math.IsNaN(f)
	}
	return true
}

type r1result struct {
	t    SignerTransport
	resp map[string]any
}

func (c *NetworkCoordinator) drive(message []byte, allow any, signerIDs []int64) (*NetworkSignResult, error) {
	if message == nil {
		return nil, errors.New("coordinator.sign: message must be bytes")
	}
	var chosen []SignerTransport
	if signerIDs != nil {
		for _, s := range c.signers {
			for _, id := range signerIDs {
				if id == s.Identifier() {
					chosen = append(chosen, s)
					break
				}
			}
		}
	} else {
		chosen = c.signers[:min(c.threshold, len(c.signers))]
	}
	if len(chosen) < c.threshold {
		return nil, &CoordinatorError{Message: fmt.Sprintf("coordinator: only %d signer(s) selected, need t=%d", len(chosen), c.threshold)}
	}
	sessionID, err := c.newID()
	if err != nil {
		return nil, err
	}

	// Round 1: collect commitments (every chosen signer at once).
	r1 := make([]r1result, len(chosen))
	var wg sync.WaitGroup
	for i, s := range chosen {
		wg.Add(1)
		go func(i int, s SignerTransport) {
			defer wg.Done()
			resp, err := s.Round1(map[string]any{"typ": "pca.frost.round1.v1", "session_id": sessionID})
			if err != nil {
				resp = map[string]any{"ok": false, "identifier": jsNumber(float64(s.Identifier())), "reason": err.Error()}
			}
			r1[i] = r1result{s, resp}
		}(i, s)
	}
	wg.Wait()
	refusals := []CoordinatorRefusal{}
	type committed struct {
		t          SignerTransport
		commitment any
	}
	var set []committed
	for _, r := range r1 {
		resp := r.resp
		if !truthy(resp["ok"]) {
			refusals = append(refusals, CoordinatorRefusal{resp["identifier"], resp["reason"]})
			continue
		}
		id, isID := frostIDOf(resp["identifier"])
		expected, known := c.pkByID[id]
		if !isID || !known { // no verification share on record for this signer
			refusals = append(refusals, CoordinatorRefusal{resp["identifier"], "no verification share on record for this signer"})
			continue
		}
		pop, isPop := resp["pop"].(map[string]any)
		if popID, ok := frostIDOf(pop["identifier"]); !isPop || !ok || popID != id || pop["publicKey"] != expected || !VerifySignerPoP(pop, c.group) {
			refusals = append(refusals, CoordinatorRefusal{resp["identifier"], "invalid or missing proof-of-possession (rogue-key defense)"})
			continue
		}
		cm, hasCommitment := resp["commitment"]
		if !hasCommitment {
			refusals = append(refusals, CoordinatorRefusal{resp["identifier"], "equivocation check failed"})
			continue
		}
		if err := c.guard.Observe(sessionID, 1, id, cm); err != nil {
			var ee *EquivocationError
			reason := "equivocation check failed"
			if errors.As(err, &ee) {
				reason = err.Error()
			}
			refusals = append(refusals, CoordinatorRefusal{resp["identifier"], reason})
			continue
		}
		set = append(set, committed{r.t, cm})
	}
	if len(set) < c.threshold {
		return nil, &CoordinatorError{Message: fmt.Sprintf("coordinator: round 1 produced %d commitment(s), need t=%d", len(set), c.threshold), Refusals: refusals}
	}
	// exactly t committed signers form the signing set (the verification shares must match this set)
	set = set[:c.threshold]
	commitments := make([]any, len(set))
	setIDs := map[float64]bool{}
	for i, x := range set {
		commitments[i] = x.commitment
		if m, ok := x.commitment.(map[string]any); ok {
			if f, ok := jsNum(m["identifier"]); ok {
				setIDs[f] = true
			}
		}
	}
	var shares []any
	var setShares []FrostVerificationShare
	for _, v := range c.vshares {
		if setIDs[float64(v.Identifier)] {
			shares = append(shares, map[string]any{"identifier": jsNumber(float64(v.Identifier)), "publicKey": b64.EncodeToString(v.PublicKey)})
			setShares = append(setShares, v)
		}
	}
	if len(shares) != len(set) {
		return nil, &CoordinatorError{Message: "coordinator: missing a verification share for a signer in the set"}
	}

	// Round 2: collect signature shares.
	req := func() map[string]any {
		return map[string]any{"typ": "pca.frost.round2.v1", "session_id": sessionID, "message": b64.EncodeToString(message), "group_pk": b64.EncodeToString(c.group),
			"commitments": commitments, "verification_shares": shares, "allow": allow}
	}
	r2 := make([]map[string]any, len(set))
	for i, x := range set {
		wg.Add(1)
		go func(i int, t SignerTransport) {
			defer wg.Done()
			resp, err := t.Round2(req())
			if err != nil {
				resp = map[string]any{"ok": false, "identifier": jsNumber(float64(t.Identifier())), "refused": true, "reason": err.Error()}
			}
			r2[i] = resp
		}(i, x.t)
	}
	wg.Wait()
	var sigShares []FrostSigShare
	for _, resp := range r2 {
		if !truthy(resp["ok"]) {
			refusals = append(refusals, CoordinatorRefusal{resp["identifier"], resp["reason"]})
			continue
		}
		id, _ := frostIDOf(resp["identifier"])
		share, hasShare := resp["sig_share"]
		var obsErr error
		if !hasShare {
			obsErr = errors.New("unsupported type undefined")
		} else {
			obsErr = c.guard.Observe(sessionID, 2, id, map[string]any{"sig_share": share})
		}
		if obsErr != nil {
			var ee *EquivocationError
			reason := "equivocation check failed"
			if errors.As(obsErr, &ee) {
				reason = obsErr.Error()
			}
			refusals = append(refusals, CoordinatorRefusal{resp["identifier"], reason})
			continue
		}
		ss, isStr := share.(string)
		sb, good := DecodeB64uStrict(ss, 32)
		if !isStr || !good {
			refusals = append(refusals, CoordinatorRefusal{resp["identifier"], "malformed signature share"})
			continue
		}
		sigShares = append(sigShares, FrostSigShare{Identifier: id, SigShare: sb})
	}
	if len(sigShares) < c.threshold {
		return nil, &CoordinatorError{Message: fmt.Sprintf("coordinator: round 2 produced %d share(s), need t=%d", len(sigShares), c.threshold), Refusals: refusals}
	}

	// Aggregate with the FROST primitive (it re-verifies and refuses an invalid aggregate).
	agg := make([]FrostCommitment, len(commitments))
	for i, w := range commitments {
		d, err := DecodeCommitment(w)
		if err != nil {
			return nil, err
		}
		agg[i] = d
	}
	t := c.threshold
	sig, err := FrostAggregate(message, agg, sigShares, c.group, setShares, &t)
	if err != nil {
		return nil, err
	}
	ids := make([]int64, len(agg))
	for i, x := range agg {
		ids[i] = x.Identifier
	}
	return &NetworkSignResult{Signature: sig, SessionID: sessionID, Signers: ids}, nil
}
