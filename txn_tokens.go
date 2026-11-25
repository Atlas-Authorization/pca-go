package pca

// OAuth Transaction Tokens for agents (port of the TypeScript @atlasauth/pca-txn-tokens): a PCA capability chain expressed as
// RFC 8693 nested sub / act claims (sub = the root principal, act = the delegation path, the immediate actor outermost), issued
// as an EdDSA-signed Transaction Token (the draft-11 profile by default, the legacy profile on request) and verified fail
// closed (canonical spelling, EdDSA only, typ, required claims, audience, expiry, a replay check that must be configured).

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"time"
)

const (
	TxnTokenTypLegacy  = "txn_token+jwt"
	TxnTokenTypDraft11 = "txntoken+jwt"
	TxnTokenMaxChars   = 16384
	txnDefaultTTLSec   = 120
)

// ErrTxnReplayStoreRequired: neither a SeenTxn hook nor ReplayUnchecked was configured.
var ErrTxnReplayStoreRequired = &CodedError{Code: "replay_store_required", Msg: "fromTransactionToken: supply SeenTxn (a replay store) or set ReplayUnchecked"}

// CodedError is an error with a stable machine code.
type CodedError struct{ Code, Msg string }

func (e *CodedError) Error() string { return e.Msg }

// SubActChain projects a capability chain (hops with issuer / holder) as nested sub / act claims.
func SubActChain(chain any) (map[string]any, error) {
	l, ok := chain.([]any)
	if !ok || len(l) == 0 {
		return nil, errors.New("subActChain: chain must be a non-empty CapabilityChain")
	}
	var act map[string]any
	for i := len(l) - 1; i >= 0; i-- {
		h, _ := l[i].(map[string]any)
		holder, ok := h["holder"].(string)
		if !ok || holder == "" {
			return nil, fmt.Errorf("subActChain: hop %d has no holder", i)
		}
		next := map[string]any{"sub": holder}
		if act != nil {
			next["act"] = act
		}
		act = next
	}
	root, _ := l[0].(map[string]any)
	iss, ok := root["issuer"].(string)
	if !ok || iss == "" {
		return nil, errors.New("subActChain: root hop has no issuer (principal)")
	}
	return map[string]any{"sub": iss, "act": act}, nil
}

func jsTruthy(v any) bool {
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

// ActDepth counts the actors under a sub / act claim.
func ActDepth(claim any) (int, error) {
	if !isJSObject(claim) {
		return 0, errors.New("actDepth: expected a sub/act claim object")
	}
	d := 0
	cur := asRecord(claim)["act"]
	for jsTruthy(cur) {
		d++
		cur = asRecord(cur)["act"]
	}
	return d, nil
}

// ToRfc8693Act rebuilds a claim with only sub / act members (anything else dropped).
func ToRfc8693Act(claim any) (map[string]any, error) {
	if claim == nil {
		return nil, errors.New("toRfc8693Act: claim is null")
	}
	type subOf struct {
		v   any
		has bool
	}
	var actors []subOf
	for c := asRecord(claim)["act"]; jsTruthy(c); c = asRecord(c)["act"] {
		v, has := asRecord(c)["sub"]
		actors = append(actors, subOf{v, has})
	}
	node := func(s subOf, act map[string]any) map[string]any {
		m := map[string]any{}
		if s.has {
			m["sub"] = s.v
		}
		if act != nil {
			m["act"] = act
		}
		return m
	}
	var act map[string]any
	for _, s := range actors { // the reference rebuilds in the same order it read, so the nesting is reversed for 2+ actors
		act = node(s, act)
	}
	v, has := asRecord(claim)["sub"]
	return node(subOf{v, has}, act), nil
}

func actJSON(a map[string]any) (rawJSON, error) {
	if inner, ok := a["act"].(map[string]any); ok {
		in, err := actJSON(inner)
		if err != nil {
			return "", err
		}
		return jsonObject("sub", a["sub"], "act", in)
	}
	return jsonObject("sub", a["sub"])
}

func randomUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// TxnTokenArgs configures ToTransactionToken. Profile "" = draft-11 (Scope and ReqWl required; Txn "" = a random id;
// TrustDomain nil = the action audience). TTLSec nil = 120. Now nil = the wall clock.
type TxnTokenArgs struct {
	Profile     string
	Scope       string
	ReqWl       string
	Txn         string
	TrustDomain *string
	Chain       any
	Action      map[string]any // verb, resource, aud
	IssuerSeed  []byte         // the 32-byte Ed25519 secret key
	Issuer      string
	TTLSec      *float64
	Now         func() time.Time
}

// ToTransactionToken issues an EdDSA Transaction Token for the chain and action.
func ToTransactionToken(a TxnTokenArgs) (string, error) {
	if a.Issuer == "" {
		return "", errors.New("toTransactionToken: `issuer` is required")
	}
	verb, ok1 := a.Action["verb"].(string)
	res, ok2 := a.Action["resource"].(string)
	aud, ok3 := a.Action["aud"].(string)
	if !ok1 || !ok2 || !ok3 {
		return "", errors.New("toTransactionToken: `action` must have string verb, resource and aud")
	}
	custody, err := SubActChain(a.Chain)
	if err != nil {
		return "", err
	}
	ttl := float64(txnDefaultTTLSec)
	if a.TTLSec != nil {
		ttl = *a.TTLSec
	}
	if !finite(ttl) || ttl <= 0 {
		return "", errors.New("toTransactionToken: ttlSec must be > 0")
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	nowSec := math.Floor(float64(now.UnixMilli()) / 1000)
	if len(a.IssuerSeed) != ed25519.SeedSize {
		return "", errors.New("toTransactionToken: a raw Ed25519 secret key must be 32 bytes")
	}
	if a.Profile != "" && a.Profile != "legacy" && a.Profile != "draft-11" {
		return "", errors.New("toTransactionToken: profile must be legacy or draft-11")
	}
	tctx, err := jsonObject("verb", verb, "resource", res, "aud", aud)
	if err != nil {
		return "", err
	}
	var kv []any
	kv = append(kv, "tctx", tctx)
	if act, ok := custody["act"].(map[string]any); ok {
		aj, err := actJSON(act)
		if err != nil {
			return "", err
		}
		kv = append(kv, "act", aj)
	}
	at, exp := jsNumber(nowSec), jsNumber(nowSec+ttl)
	var typ string
	if a.Profile == "legacy" {
		typ = TxnTokenTypLegacy
		kv = append(kv, "iat", at, "iss", a.Issuer, "sub", custody["sub"], "aud", aud, "exp", exp, "jti", randomUUID())
	} else {
		typ = TxnTokenTypDraft11
		if a.Scope == "" {
			return "", errors.New("toTransactionToken: draft-11 requires `scope`")
		}
		if a.ReqWl == "" {
			return "", errors.New("toTransactionToken: draft-11 requires `reqWl`")
		}
		td := aud
		if a.TrustDomain != nil {
			td = *a.TrustDomain
		}
		if td == "" {
			return "", errors.New("toTransactionToken: draft-11 requires a non-empty trust domain (aud)")
		}
		txn := a.Txn
		if txn == "" {
			txn = randomUUID()
		}
		kv = append(kv, "txn", txn, "scope", a.Scope, "req_wl", a.ReqWl, "iat", at, "iss", a.Issuer, "sub", custody["sub"], "aud", td, "exp", exp)
	}
	payload, err := jsonObject(kv...)
	if err != nil {
		return "", err
	}
	header, _ := jsonObject("alg", "EdDSA", "typ", typ)
	return SignCompactEdDSA(header, payload, a.IssuerSeed)
}

// TxnVerifyOptions configures FromTransactionToken. Profile "" = draft-11 (Audience, the trust domain served, required).
// SeenTxn reports whether the transaction id (txn, or jti for legacy) was seen before and records it; it is required unless
// ReplayUnchecked. NowSec nil = the wall clock.
type TxnVerifyOptions struct {
	Profile           string
	Audience          string
	ClockToleranceSec float64
	NowSec            *float64
	SeenTxn           func(id string, exp float64) (bool, error)
	ReplayUnchecked   bool
}

// TxnTokenResult is a verified token: the custody chain, the PCA action (nil for an opaque draft-11 tctx), tctx, the claims.
type TxnTokenResult struct {
	Chain  map[string]any `json:"chain"`
	Action map[string]any `json:"action,omitempty"`
	Tctx   map[string]any `json:"tctx"`
	Claims map[string]any `json:"claims"`
}

func txnNormalizeAct(node any, has bool) (map[string]any, error) {
	if !has {
		return nil, nil
	}
	m, ok := node.(map[string]any)
	if !ok {
		return nil, errors.New("transaction token: malformed `act` claim")
	}
	sub, ok := m["sub"].(string)
	if !ok || sub == "" {
		return nil, errors.New("transaction token: `act.sub` must be a non-empty string")
	}
	in, hasIn := m["act"]
	inner, err := txnNormalizeAct(in, hasIn)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"sub": sub}
	if inner != nil {
		out["act"] = inner
	}
	return out, nil
}

// FromTransactionToken verifies a Transaction Token under a raw 32-byte Ed25519 public key.
func FromTransactionToken(jwt any, verifyKey []byte, o TxnVerifyOptions) (*TxnTokenResult, error) {
	if o.Profile != "" && o.Profile != "legacy" && o.Profile != "draft-11" {
		return nil, errors.New("fromTransactionToken: profile must be legacy or draft-11")
	}
	draft := o.Profile != "legacy"
	if draft && o.Audience == "" {
		return nil, errors.New("fromTransactionToken: draft-11 requires Audience (the trust domain this verifier serves)")
	}
	if o.SeenTxn == nil && !o.ReplayUnchecked {
		return nil, ErrTxnReplayStoreRequired
	}
	if s, ok := jwt.(string); ok && utf16Len(s) > TxnTokenMaxChars {
		return nil, errors.New("transaction token: token exceeds the size limit")
	}
	// a non-finite tolerance or clock makes every exp/nbf comparison pass
	if !(finite(o.ClockToleranceSec) && o.ClockToleranceSec >= 0) {
		return nil, errors.New("fromTransactionToken: clockToleranceSec must be a finite number >= 0")
	}
	if o.NowSec != nil && !finite(*o.NowSec) {
		return nil, errors.New("fromTransactionToken: now must be a valid Date")
	}
	if _, err := AssertCanonicalCompactJWS(jwt, 3, 0, true); err != nil {
		return nil, err
	}
	if len(verifyKey) != ed25519.PublicKeySize {
		return nil, errors.New("fromTransactionToken: a raw Ed25519 public key must be 32 bytes")
	}
	key := &JOSEKey{Kty: "OKP", Crv: "Ed25519", Ed25519: ed25519.PublicKey(verifyKey)}
	vo := JWTVerifyOptions{Algorithms: []string{"EdDSA"}, Typ: TxnTokenTypLegacy, RequiredClaims: []string{"exp"}, ClockTolerance: o.ClockToleranceSec, NowSec: o.NowSec}
	if draft {
		vo.Typ, vo.RequiredClaims = TxnTokenTypDraft11, []string{"iat", "exp", "aud", "sub", "txn", "scope", "req_wl"}
	}
	if o.Audience != "" {
		vo.Audience = []string{o.Audience}
	}
	_, p, err := JWTVerify(jwt.(string), func(map[string]any) (*JOSEKey, error) { return key, nil }, vo, float64(time.Now().Unix()))
	if err != nil {
		return nil, err
	}
	if draft {
		for _, k := range []string{"txn", "scope", "req_wl"} {
			if s, ok := p[k].(string); !ok || s == "" {
				return nil, fmt.Errorf("transaction token: `%s` must be a non-empty string", k)
			}
		}
	}
	sub, ok := p["sub"].(string)
	if !ok || sub == "" {
		return nil, errors.New("transaction token: missing `sub` (root principal)")
	}
	tctx, ok := p["tctx"].(map[string]any)
	if !ok {
		return nil, errors.New("transaction token: missing or malformed `tctx`")
	}
	var action map[string]any
	_, h1 := tctx["verb"]
	_, h2 := tctx["resource"]
	_, h3 := tctx["aud"]
	if !draft || h1 || h2 || h3 {
		v, ok1 := tctx["verb"].(string)
		r, ok2 := tctx["resource"].(string)
		a, ok3 := tctx["aud"].(string)
		if !ok1 || !ok2 || !ok3 {
			return nil, errors.New("transaction token: missing or malformed `tctx`")
		}
		action = map[string]any{"verb": v, "resource": r, "aud": a}
	}
	if rc, has := p["rctx"]; draft && has {
		if _, ok := rc.(map[string]any); !ok {
			return nil, errors.New("transaction token: malformed `rctx`")
		}
	}
	av, hasAct := p["act"]
	act, err := txnNormalizeAct(av, hasAct)
	if err != nil {
		return nil, err
	}
	if o.SeenTxn != nil {
		idKey := "jti"
		if draft {
			idKey = "txn"
		}
		id, ok := p[idKey].(string)
		if !ok || id == "" {
			return nil, errors.New("transaction token: no transaction identifier to check for replay")
		}
		exp, _ := jsNum(p["exp"])
		seen, err := o.SeenTxn(id, exp)
		if err != nil {
			return nil, err
		}
		if seen {
			return nil, errors.New("transaction token: replayed (transaction identifier already seen)")
		}
	}
	chain := map[string]any{"sub": sub}
	if act != nil {
		chain["act"] = act
	}
	return &TxnTokenResult{Chain: chain, Action: action, Tctx: tctx, Claims: p}, nil
}
