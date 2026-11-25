package pca

// Agent payment network tokens (the reference @atlasauth/pca-payments network-token): a binding ties a PCA grant holder to an
// OPAQUE network-token reference (never a PAN) and carries the PCActn digest onto the charge so the card-network record joins the
// PCA ledger entry. Partner adapters (Visa Intelligent Commerce, Mastercard Agent Pay) are generic mappings over an injected
// transport; they make no network call of their own. Every check is exact; malformed input is a refusal.

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/url"
)

const NetworkTokenBindingKind = "pca.network_token_binding"

func payBindingBody(b any) (map[string]any, error) {
	body := map[string]any{"kind": NetworkTokenBindingKind, "v": jsNumber(1)}
	for _, k := range []string{"provider", "token_ref", "grant_digest", "issuer_nonce", "holder"} {
		v, err := payGet(b, k)
		if err != nil {
			return nil, err
		}
		if payIsU(v) {
			return nil, errors.New("canonicalize: unsupported type undefined")
		}
		body[k] = v
	}
	return body, nil
}

// NetworkTokenBindingMessage: the exact bytes the holder signs, the UTF-8 of the canonical-JSON digest of the binding body.
func NetworkTokenBindingMessage(b any) ([]byte, error) {
	body, err := payBindingBody(b)
	if err != nil {
		return nil, err
	}
	h, err := HashCanonical(body)
	if err != nil {
		return nil, err
	}
	return []byte(h), nil
}

// BindNetworkTokenOptions: HolderSecret is the grant holder's 32-byte Ed25519 seed, HolderPublic its 32-byte public key.
type BindNetworkTokenOptions struct {
	Provider     any
	TokenRef     any
	Grant        any
	IssuerNonce  any
	HolderSecret []byte
	HolderPublic []byte
}

// BindNetworkToken ties a grant holder to an opaque network-token reference and signs the binding with the holder key.
func BindNetworkToken(o BindNetworkTokenOptions) (map[string]any, error) {
	if e := TokenRefError(o.TokenRef); e != "" {
		return nil, fmt.Errorf("bindNetworkToken: %s", e)
	}
	n, err := payLength(o.IssuerNonce)
	if err != nil {
		return nil, err
	}
	if n < 16 {
		return nil, errors.New("bindNetworkToken: issuer nonce must be at least 16 chars")
	}
	gd, err := payHash(o.Grant)
	if err != nil {
		return nil, err
	}
	if len(o.HolderSecret) != ed25519.SeedSize {
		return nil, errors.New("bindNetworkToken: holderSecret must be a 32-byte Ed25519 seed")
	}
	core := map[string]any{"provider": o.Provider, "token_ref": o.TokenRef, "grant_digest": gd, "issuer_nonce": o.IssuerNonce, "holder": b64.EncodeToString(o.HolderPublic)}
	msg, err := NetworkTokenBindingMessage(core)
	if err != nil {
		return nil, err
	}
	out := paySpreadObj(core)
	out["kind"] = NetworkTokenBindingKind
	out["binding_proof"] = b64.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(o.HolderSecret), msg))
	return out, nil
}

// CheckNetworkTokenBinding is the reference verifyNetworkTokenBinding over an `expect` object (VerifyNetworkTokenBinding takes the
// same expectations as arguments). Total: "" = valid, else the refusal reason. expect: grant (the one the caller verified), holder (the
// key the caller expects, b64u), issuerNonce and an optional provider.
func CheckNetworkTokenBinding(b, expect any) (reason string) {
	defer func() {
		if recover() != nil {
			reason = "binding_malformed"
		}
	}()
	switch b.(type) {
	case map[string]any, []any:
	default:
		return "binding_malformed"
	}
	if k, _ := payGet(b, "kind"); k != NetworkTokenBindingKind {
		return "binding_malformed"
	}
	tr, _ := payGet(b, "token_ref")
	if e := TokenRefError(tr); e != "" {
		return e
	}
	prov, _ := payGet(b, "provider")
	if ps, ok := prov.(string); !ok || ps == "" {
		return "provider_mismatch"
	}
	ep, err := payGet(expect, "provider")
	if err != nil {
		return "binding_malformed"
	}
	if !payIsU(ep) && !payStrictEq(prov, ep) {
		return "provider_mismatch"
	}
	eg, _ := payGet(expect, "grant")
	gd, err := payHash(eg)
	if err != nil {
		return "binding_malformed"
	}
	if bg, _ := payGet(b, "grant_digest"); !payStrictEq(bg, gd) {
		return "grant_digest_mismatch"
	}
	eh, _ := payGet(expect, "holder")
	if bh, _ := payGet(b, "holder"); !payStrictEq(bh, eh) {
		return "holder_mismatch"
	}
	en, _ := payGet(expect, "issuerNonce")
	if bn, _ := payGet(b, "issuer_nonce"); !payStrictEq(bn, en) {
		return "issuer_nonce_mismatch"
	}
	hv, _ := payGet(b, "holder")
	pv, _ := payGet(b, "binding_proof")
	hs, ok1 := hv.(string)
	ps, ok2 := pv.(string)
	if !ok1 || !ok2 {
		return "binding_malformed"
	}
	pk, ok1 := DecodeB64uStrict(hs, -1)
	sig, ok2 := DecodeB64uStrict(ps, -1)
	if !ok1 || !ok2 || len(pk) != ed25519.PublicKeySize {
		return "binding_malformed"
	}
	msg, err := NetworkTokenBindingMessage(b)
	if err != nil {
		return "binding_malformed"
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(pk), msg, sig) {
		return "binding_proof_invalid"
	}
	return ""
}

// ControlsFromLimits: the network-side controls, always an upper-bounded copy of the rail limits, with the grant digest echoed on
// every network transaction record.
func ControlsFromLimits(limits map[string]any, grant any) (map[string]any, error) {
	gd, err := payHash(grant)
	if err != nil {
		return nil, err
	}
	cats, err := paySpreadList(limits["categories"])
	if err != nil {
		return nil, err
	}
	ms, err := paySpreadList(limits["merchants"])
	if err != nil {
		return nil, err
	}
	c := map[string]any{"currency": limits["currency"], "perAuthorizationMax": limits["perAuthorizationMax"], "totalMax": limits["totalMax"],
		"categories": cats, "merchants": ms, "metadata": map[string]any{"grant_digest": gd}}
	if e, has := limits["expiresAt"]; has {
		c["expiresAt"] = e
	}
	return c, nil
}

// SettlementMetadata: the metadata a charge / authorization carries (fixed keys, digest values: no PII, no PAN).
func SettlementMetadata(b map[string]any, pcactnDigest string) map[string]any {
	out := map[string]any{"pca_pcactn": pcactnDigest}
	paySet(out, "pca_grant", payOpt(b, "grant_digest"))
	paySet(out, "pca_token_ref", payOpt(b, "token_ref"))
	return out
}

// ReconcileNetworkSettlement: a network settlement record joins the ledger entry only if all three echoed values match exactly
// ({ok: true}); a record without the PCActn digest never joins.
func ReconcileNetworkSettlement(expected, record any) (map[string]any, error) {
	md := payOpt(record, "metadata")
	var m any = map[string]any{}
	if !payNullish(md) {
		m = md
	}
	reasons := []any{}
	ped, _ := payGet(m, "pca_pcactn")
	epd, err := payGet(expected, "pcactnDigest")
	if err != nil {
		return nil, err
	}
	if s, ok := ped.(string); !ok || s == "" {
		reasons = append(reasons, "pcactn_digest_missing")
	} else if n, err := payLength(epd); err != nil {
		return nil, err
	} else if n == 0 {
		reasons = append(reasons, "pcactn_digest_missing")
	}
	eg, _ := payGet(expected, "grantDigest")
	if g, _ := payGet(m, "pca_grant"); !payStrictEq(g, eg) {
		reasons = append(reasons, "grant_digest_mismatch")
	}
	if !payStrictEq(ped, epd) {
		reasons = append(reasons, "pcactn_digest_mismatch")
	}
	et, _ := payGet(expected, "tokenRef")
	if t, _ := payGet(m, "pca_token_ref"); !payStrictEq(t, et) {
		reasons = append(reasons, "token_ref_mismatch")
	}
	if len(reasons) == 0 {
		return map[string]any{"ok": true}, nil
	}
	return map[string]any{"ok": false, "reasons": reasons}, nil
}

// ChargeWithNetworkToken is the one way to start a network-token charge: it builds the signed PCActn for the charge and returns the
// network metadata derived from THAT PCActn's digest ({pcactn, node, metadata, pcactnDigest}).
func ChargeWithNetworkToken(binding map[string]any, mandate, charge any, opts map[string]any) (map[string]any, error) {
	if TokenRefError(payOpt(binding, "token_ref")) != "" {
		return nil, errors.New("chargeWithNetworkToken: bad binding")
	}
	mg, err := payGet(mandate, "grant")
	if err != nil {
		return nil, err
	}
	gd, err := payHash(mg)
	if err != nil {
		return nil, err
	}
	if !payStrictEq(payOpt(binding, "grant_digest"), gd) {
		return nil, errors.New("chargeWithNetworkToken: binding is for another grant")
	}
	built, err := ChargeToPCActn(mandate, charge, opts)
	if err != nil {
		return nil, err
	}
	digest, err := HashCanonical(built["pcactn"])
	if err != nil {
		return nil, err
	}
	return map[string]any{"pcactn": built["pcactn"], "node": built["node"], "metadata": SettlementMetadata(binding, digest), "pcactnDigest": digest}, nil
}

// ---- provider interface + partner-gated adapters ------------------------------------------------------------------------

// NetworkTokenProvider issues a token whose own controls equal the given controls (returning the opaque reference) and suspends
// it (idempotent).
type NetworkTokenProvider interface {
	ID() string
	Issue(controls map[string]any, agentID string) (tokenRef string, err error)
	Suspend(tokenRef, reason string) error
}

// PartnerTransport posts a JSON body to a partner path and returns the JSON reply.
type PartnerTransport func(path string, body map[string]any) (map[string]any, error)

type payPartner struct {
	id, scopeKey string
	post         PartnerTransport
}

func (p payPartner) ID() string { return p.id }

func (p payPartner) Issue(c map[string]any, agentID string) (string, error) {
	scope := map[string]any{"currency": c["currency"], "per_authorization_max": c["perAuthorizationMax"], "total_max": c["totalMax"],
		"merchant_categories": c["categories"], "merchants": c["merchants"]}
	if e, has := c["expiresAt"]; has {
		scope["expires_at"] = e
	}
	r, err := p.post("/tokens", map[string]any{"agent_id": agentID, p.scopeKey: scope, "metadata": c["metadata"]})
	if err != nil {
		return "", err
	}
	ref := r["token_ref"]
	if e := TokenRefError(ref); e != "" {
		return "", fmt.Errorf("%s: provider returned %s", p.id, e)
	}
	return ref.(string), nil
}

func (p payPartner) Suspend(tokenRef, reason string) error {
	_, err := p.post("/tokens/"+url.QueryEscape(tokenRef)+"/suspend", map[string]any{"reason": reason})
	return err
}

// VisaIntelligentCommerceAdapter / MastercardAgentPayAdapter: GENERIC mappings of PCA controls onto a neutral shape (the partner
// wire formats are access-gated; the paths and body names are placeholders, the control values are exact copies of PCA's limits).
func VisaIntelligentCommerceAdapter(post PartnerTransport) NetworkTokenProvider {
	return payPartner{"visa_ic", "instructions", post}
}

func MastercardAgentPayAdapter(post PartnerTransport) NetworkTokenProvider {
	return payPartner{"mastercard_agent_pay", "session_scope", post}
}

// IssueBoundNetworkToken is the issuance gate: a token whose controls equal the rail limits, bound to the grant holder.
func IssueBoundNetworkToken(provider NetworkTokenProvider, limits map[string]any, grant any, agentID string, holderSecret, holderPublic []byte, issuerNonce string) (binding, controls map[string]any, err error) {
	if controls, err = ControlsFromLimits(limits, grant); err != nil {
		return nil, nil, err
	}
	ref, err := provider.Issue(controls, agentID)
	if err != nil {
		return nil, nil, err
	}
	binding, err = BindNetworkToken(BindNetworkTokenOptions{Provider: provider.ID(), TokenRef: ref, Grant: grant, IssuerNonce: issuerNonce, HolderSecret: holderSecret, HolderPublic: holderPublic})
	return binding, controls, err
}

// SuspendOnRevoke: grant revoked => suspend. Provider errors propagate (a failed suspend is not a success).
func SuspendOnRevoke(provider NetworkTokenProvider, binding map[string]any) error {
	ref, _ := binding["token_ref"].(string)
	return provider.Suspend(ref, "grant_revoked")
}
