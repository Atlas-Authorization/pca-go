package pca

// AP2 mandate issuance, presentation and verification. Wire format: a mandate is the single object in an SD-JWT's delegate_payload
// array, itself an array-element disclosure. An OPEN mandate is signed by the issuer (the user's trusted surface / agent provider) and
// names the agent's key in cnf.jwk. A CLOSED mandate is a key-binding SD-JWT hop (typ kb+sd-jwt) signed by that agent key, carrying
// iat, aud, nonce and an sd_hash over the preceding hop. Hops are joined by "~~". No trailing RFC 9901 KB-JWT is used or accepted.

import (
	"math"
	"strconv"
	"strings"
	"time"
)

func ap2SafeInt(f float64) bool { return f == math.Trunc(f) && math.Abs(f) <= 9007199254740991 }

func ap2IsNegZero(f float64) bool { return f == 0 && math.Signbit(f) }

// Ap2Issuer is the signer of an open mandate: the user's trusted surface or agent provider (an ES256 key).
type Ap2Issuer struct {
	Key *Ap2KeyPair
	// Kid is the kid header (a verifier's key resolver maps it to the public key); nil = none.
	Kid *string
	// X5c is the optional x5c header (base64 DER certificates; chain validation is the resolver's job); nil = none.
	X5c []string
}

// Ap2OpenMandateCommon is what every open mandate carries.
type Ap2OpenMandateCommon struct {
	Issuer Ap2Issuer
	// AgentJwk is the agent's public key; it becomes cnf.jwk and is the only key that can sign the closed mandate.
	AgentJwk any
	// Iat and Exp are epoch seconds (an open mandate must be bounded in time); NaN = absent, which is refused.
	Iat, Exp float64
	// Pca is the x_pca claim (PCA's proof of the grant); nil = none.
	Pca any
	// SdAlg is the _sd_alg ("" = sha-256); Salt the salt source (nil = random); Typ the root typ header (nil = dc+sd-jwt).
	SdAlg string
	Salt  func() string
	Typ   *string
}

const ap2RootTyp = "dc+sd-jwt"

func ap2SignRoot(c Ap2OpenMandateCommon, mandate map[string]any, b *Ap2DisclosureBuilder) (string, error) {
	element, err := b.Element(mandate)
	if err != nil {
		return "", err
	}
	typ := ap2RootTyp
	if c.Typ != nil {
		typ = *c.Typ
	}
	header := ap2New().set("typ", typ)
	if c.Issuer.Kid != nil {
		header.set("kid", *c.Issuer.Kid)
	}
	if c.Issuer.X5c != nil {
		x5c := make([]any, len(c.Issuer.X5c))
		for i, s := range c.Issuer.X5c {
			x5c[i] = s
		}
		header.set("x5c", x5c)
	}
	alg := c.SdAlg
	if alg == "" {
		alg = "sha-256"
	}
	return Ap2SignSdJwt(header.done(), ap2Map("delegate_payload", []any{element}, "_sd_alg", alg), b.Disclosures, c.Issuer.Key)
}

func ap2CommonClaims(c Ap2OpenMandateCommon) (map[string]any, error) {
	jwk, err := Ap2AssertP256Jwk(c.AgentJwk, "agentJwk")
	if err != nil {
		return nil, err
	}
	if !ap2SafeInt(c.Iat) || !ap2SafeInt(c.Exp) || c.Exp <= c.Iat {
		return nil, ap2Fail("open mandate: need integer iat < exp (epoch seconds)")
	}
	b := ap2New().
		set("cnf", ap2Map("jwk", ap2Map("crv", "P-256", "kty", "EC", "x", jwk["x"], "y", jwk["y"]))).
		set("iat", ap2Num(c.Iat)).
		set("exp", ap2Num(c.Exp))
	if ap2Truthy(c.Pca) {
		b.set(Ap2PcaClaim, c.Pca)
	}
	return b.done(), nil
}

func ap2ElementList(v any, b *Ap2DisclosureBuilder) ([]any, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, ap2Fail("Cannot read properties of %s (reading 'map')", ap2Str(v))
	}
	out := make([]any, len(l))
	for i, x := range l {
		e, err := b.Element(x)
		if err != nil {
			return nil, err
		}
		out[i] = e
	}
	return out, nil
}

// ap2SdPaymentConstraint wraps the selectively-disclosable arrays of a payment constraint (allowed payees / instruments).
func ap2SdPaymentConstraint(c any, b *Ap2DisclosureBuilder) (any, error) {
	if c == nil {
		return nil, ap2Fail("Cannot read properties of null (reading 'type')")
	}
	t, _ := ap2Get(c, "type").(string)
	if t == "payment.allowed_payees" || t == "payment.allowed_payment_instruments" {
		allowed, err := ap2ElementList(ap2Get(c, "allowed"), b)
		if err != nil {
			return nil, err
		}
		return ap2Map("type", t, "allowed", allowed), nil
	}
	return c, nil
}

// ap2SdCheckoutConstraint wraps the allowed merchants, or (any other type) the acceptable items of each line-item requirement.
func ap2SdCheckoutConstraint(c any, b *Ap2DisclosureBuilder) (any, error) {
	if c == nil {
		return nil, ap2Fail("Cannot read properties of null (reading 'type')")
	}
	typ := ap2Get(c, "type")
	if ap2StrictEq(typ, "checkout.allowed_merchants") {
		allowed, err := ap2ElementList(ap2Get(c, "allowed"), b)
		if err != nil {
			return nil, err
		}
		return ap2Map("type", typ, "allowed", allowed), nil
	}
	items, ok := ap2Get(c, "items").([]any)
	if !ok {
		return nil, ap2Fail("Cannot read properties of %s (reading 'map')", ap2Str(ap2Get(c, "items")))
	}
	out := make([]any, len(items))
	for i, it := range items {
		if it == nil || ap2IsU(it) {
			return nil, ap2Fail("Cannot read properties of %s (reading 'id')", ap2Str(it))
		}
		els, err := ap2ElementList(ap2Get(it, "acceptable_items"), b)
		if err != nil {
			return nil, err
		}
		out[i] = ap2Map("id", ap2Get(it, "id"), "acceptable_items", els, "quantity", ap2Get(it, "quantity"))
	}
	return ap2Map("type", typ, "items", out), nil
}

func ap2WrapConstraints(constraints []any, b *Ap2DisclosureBuilder, checkout bool) ([]any, error) {
	out := make([]any, len(constraints))
	for i, c := range constraints {
		var x any
		var err error
		if checkout {
			x, err = ap2SdCheckoutConstraint(c, b)
		} else {
			x, err = ap2SdPaymentConstraint(c, b)
		}
		if err != nil {
			return nil, err
		}
		out[i] = x
	}
	return out, nil
}

// Ap2OpenPaymentMandateInput is an open payment mandate to issue.
type Ap2OpenPaymentMandateInput struct {
	Ap2OpenMandateCommon
	Constraints []any
	// Payee, PaymentAmount, PaymentInstrument and Pisp are the optional pre-set claims (nil = none); ExecutionDate likewise.
	Payee, PaymentAmount, PaymentInstrument, Pisp any
	ExecutionDate                                 *string
}

func ap2AssertWellFormed(wrapped map[string]any, problems func(any) []string, what string, plain []any) error {
	p := problems(ap2New().spread(wrapped).set("constraints", plain).done())
	if len(p) > 0 {
		return ap2Fail("%s: %s", what, strings.Join(p, "; "))
	}
	return nil
}

// Ap2IssueOpenPaymentMandate issues an open payment mandate (mandate.payment.open.1) as a signed SD-JWT.
func Ap2IssueOpenPaymentMandate(in Ap2OpenPaymentMandateInput) (string, error) {
	b := Ap2NewDisclosureBuilder(in.SdAlg, in.Salt)
	wrapped, err := ap2WrapConstraints(in.Constraints, b, false)
	if err != nil {
		return "", err
	}
	m := ap2New().set("vct", Ap2VctPaymentOpen).set("constraints", wrapped)
	if ap2Truthy(in.Payee) {
		m.set("payee", in.Payee)
	}
	if ap2Truthy(in.PaymentAmount) {
		m.set("payment_amount", in.PaymentAmount)
	}
	if ap2Truthy(in.PaymentInstrument) {
		m.set("payment_instrument", in.PaymentInstrument)
	}
	if ap2Truthy(in.Pisp) {
		m.set("pisp", in.Pisp)
	}
	if in.ExecutionDate != nil {
		m.set("execution_date", *in.ExecutionDate)
	}
	common, err := ap2CommonClaims(in.Ap2OpenMandateCommon)
	if err != nil {
		return "", err
	}
	mandate := m.spread(common).done()
	if err := ap2AssertWellFormed(mandate, Ap2OpenPaymentMandateProblems, "open payment mandate", in.Constraints); err != nil {
		return "", err
	}
	return ap2SignRoot(in.Ap2OpenMandateCommon, mandate, b)
}

// Ap2OpenCheckoutMandateInput is an open checkout mandate to issue.
type Ap2OpenCheckoutMandateInput struct {
	Ap2OpenMandateCommon
	Constraints []any
}

// Ap2IssueOpenCheckoutMandate issues an open checkout mandate (mandate.checkout.open.1) as a signed SD-JWT.
func Ap2IssueOpenCheckoutMandate(in Ap2OpenCheckoutMandateInput) (string, error) {
	b := Ap2NewDisclosureBuilder(in.SdAlg, in.Salt)
	wrapped, err := ap2WrapConstraints(in.Constraints, b, true)
	if err != nil {
		return "", err
	}
	common, err := ap2CommonClaims(in.Ap2OpenMandateCommon)
	if err != nil {
		return "", err
	}
	mandate := ap2New().set("vct", Ap2VctCheckoutOpen).set("constraints", wrapped).spread(common).done()
	if err := ap2AssertWellFormed(mandate, Ap2OpenCheckoutMandateProblems, "open checkout mandate", in.Constraints); err != nil {
		return "", err
	}
	return ap2SignRoot(in.Ap2OpenMandateCommon, mandate, b)
}

// ---- presenting closed mandates (KB-SD-JWT hops) -----------------------------------------------------------------------

// Ap2ClosedHopCommon is what every closed mandate hop carries.
type Ap2ClosedHopCommon struct {
	// Open is the preceding token (an open mandate, or a chain ending in an intermediate hop).
	Open string
	// AgentKey is the agent's key pair: its public key must be the open mandate's cnf.jwk.
	AgentKey *Ap2KeyPair
	// Aud is the audience of this hop (the merchant for a checkout, the credential provider for a payment); Nonce the verifier's.
	Aud, Nonce string
	// Iat is epoch seconds; Exp the optional mandate-level expiry (nil = none).
	Iat float64
	Exp *float64
	Pca any
	// HashMode is the binding claim: "sd_hash" (default; pins the preceding hop's disclosures) or "issuer_jwt_hash".
	HashMode string
	Salt     func() string
}

func ap2PresentHop(c Ap2ClosedHopCommon, build func(b *Ap2DisclosureBuilder, prev *Ap2SdJwtHop) (map[string]any, error)) (string, error) {
	if c.Aud == "" || c.Nonce == "" {
		return "", ap2Fail("closed mandate: aud and nonce are required")
	}
	if !ap2SafeInt(c.Iat) {
		return "", ap2Fail("closed mandate: iat must be an integer")
	}
	prev, err := Ap2ParseSdJwtHop(c.Open)
	if err != nil {
		return "", err
	}
	b := Ap2NewDisclosureBuilder(prev.SdAlg, c.Salt)
	mandate, err := build(b, prev)
	if err != nil {
		return "", err
	}
	element, err := b.Element(mandate)
	if err != nil {
		return "", err
	}
	mode := c.HashMode
	if mode == "" {
		mode = "sd_hash"
	}
	var bind string
	if mode == "sd_hash" {
		bind, err = Ap2SdHashOf(prev, "")
	} else {
		bind, err = Ap2IssuerJwtHashOf(prev, "")
	}
	if err != nil {
		return "", err
	}
	payload := ap2New().set("delegate_payload", []any{element}).set("iat", ap2Num(c.Iat)).set("aud", c.Aud).set("nonce", c.Nonce).
		set(mode, bind).set("_sd_alg", prev.SdAlg).done()
	hop, err := Ap2SignSdJwt(ap2Map("typ", "kb+sd-jwt"), payload, b.Disclosures, c.AgentKey)
	if err != nil {
		return "", err
	}
	// Hops are joined by "~~": the preceding token's own trailing "~" plus one separator "~".
	return c.Open + "~" + hop, nil
}

// Ap2ClosedPaymentInput is a closed payment mandate to present on top of an open payment mandate.
type Ap2ClosedPaymentInput struct {
	Ap2ClosedHopCommon
	// TransactionID is the hash of the closed checkout's checkout_jwt (= the closed checkout mandate's checkout_hash).
	TransactionID                                 string
	Payee, PaymentAmount, PaymentInstrument, Pisp any
	ExecutionDate                                 *string
	RiskData                                      any
}

// Ap2PresentClosedPayment presents a closed payment mandate (mandate.payment.1) on top of an open payment mandate.
func Ap2PresentClosedPayment(in Ap2ClosedPaymentInput) (string, error) {
	return ap2PresentHop(in.Ap2ClosedHopCommon, func(b *Ap2DisclosureBuilder, _ *Ap2SdJwtHop) (map[string]any, error) {
		m := ap2New().set("vct", Ap2VctPayment).set("transaction_id", in.TransactionID).set("payee", in.Payee).set("payment_amount", in.PaymentAmount).
			set("payment_instrument", in.PaymentInstrument)
		if ap2Truthy(in.Pisp) {
			m.set("pisp", in.Pisp)
		}
		if in.ExecutionDate != nil {
			m.set("execution_date", *in.ExecutionDate)
		}
		if ap2Truthy(in.RiskData) {
			m.set("risk_data", in.RiskData)
		}
		if in.Exp != nil {
			m.set("exp", ap2Num(*in.Exp))
		}
		if ap2Truthy(in.Pca) {
			m.set(Ap2PcaClaim, in.Pca)
		}
		mandate := m.done()
		if p := Ap2PaymentMandateProblems(mandate); len(p) > 0 {
			return nil, ap2Fail("closed payment mandate: %s", strings.Join(p, "; "))
		}
		return mandate, nil
	})
}

// Ap2ClosedCheckoutInput is a closed checkout mandate to present on top of an open checkout mandate.
type Ap2ClosedCheckoutInput struct {
	Ap2ClosedHopCommon
	// CheckoutJwt is the merchant-signed checkout JWT (compact).
	CheckoutJwt string
}

// Ap2PresentClosedCheckout presents a closed checkout mandate (mandate.checkout.1) on top of an open checkout mandate.
func Ap2PresentClosedCheckout(in Ap2ClosedCheckoutInput) (string, error) {
	return ap2PresentHop(in.Ap2ClosedHopCommon, func(b *Ap2DisclosureBuilder, prev *Ap2SdJwtHop) (map[string]any, error) {
		sd, err := b.Property("checkout_jwt", in.CheckoutJwt)
		if err != nil {
			return nil, err
		}
		hash, err := Ap2SdDigest(in.CheckoutJwt, prev.SdAlg)
		if err != nil {
			return nil, err
		}
		m := ap2New().set("_sd", []any{sd}).set("vct", Ap2VctCheckout).set("checkout_hash", hash)
		if in.Exp != nil {
			m.set("exp", ap2Num(*in.Exp))
		}
		if ap2Truthy(in.Pca) {
			m.set(Ap2PcaClaim, in.Pca)
		}
		mandate := m.done()
		if p := Ap2CheckoutMandateProblems(ap2New().spread(mandate).set("checkout_jwt", in.CheckoutJwt).done()); len(p) > 0 {
			return nil, ap2Fail("closed checkout mandate: %s", strings.Join(p, "; "))
		}
		return mandate, nil
	})
}

// ---- verifying a delegation chain --------------------------------------------------------------------------------------

const ap2MaxHops = 8

// Ap2VerifiedHop is one verified hop: its kind, the hop-level claims after disclosure processing and the single mandate disclosed in
// delegate_payload.
type Ap2VerifiedHop struct {
	Index   int
	Kind    string // "root" | "intermediate" | "terminal"
	Hop     *Ap2SdJwtHop
	Claims  map[string]any
	Mandate map[string]any
}

// Ap2KeyResolver resolves a public key from a JWT header (kid / x5c); nil refuses.
type Ap2KeyResolver func(header map[string]any) map[string]any

// Ap2VerifyChainOptions are the verifier's expectations of a chain.
type Ap2VerifyChainOptions struct {
	// ResolveIssuerKey resolves the root hop's public key from its header.
	ResolveIssuerKey Ap2KeyResolver
	// ExpectedAudience and ExpectedNonce are what the terminal hop's aud / nonce must equal (both required: a verifier that does not
	// name itself cannot detect redirection, and the nonce is the replay defence).
	ExpectedAudience, ExpectedNonce string
	// Now is the verification time in epoch seconds (nil = the clock); ClockSkewSeconds the tolerated skew (nil = 60).
	Now, ClockSkewSeconds *float64
}

// Ap2ChainResult is the outcome of verifying a chain.
type Ap2ChainResult struct {
	OK     bool
	Reason string
	Hops   []Ap2VerifiedHop
}

// Ap2SplitChain splits a ~~-joined chain into hops, each restored to <jwt>~<d>...~.
func Ap2SplitChain(token string) ([]string, error) {
	if len(token) == 0 {
		return nil, ap2Fail("chain: empty")
	}
	parts := strings.Split(token, "~~")
	if len(parts) > ap2MaxHops {
		return nil, ap2Fail("chain: more than %d hops", ap2MaxHops)
	}
	out := make([]string, len(parts))
	for i, p := range parts {
		if i == len(parts)-1 {
			out[i] = p
		} else {
			out[i] = p + "~"
		}
	}
	return out, nil
}

func ap2CheckTimes(label string, o map[string]any, now, skew float64) error {
	if exp := ap2Get(o, "exp"); !ap2IsU(exp) {
		f, _ := jsNum(exp)
		if !jsIsSafeInteger(exp) || ap2IsNegZero(f) {
			return ap2Fail("%s: exp must be an integer", label)
		}
		if !(finite(now) && finite(skew) && now <= f+skew) {
			return ap2Fail("%s: expired at %s", label, ap2Str(exp))
		}
	}
	if iat := ap2Get(o, "iat"); !ap2IsU(iat) {
		f, _ := jsNum(iat)
		if !jsIsSafeInteger(iat) || ap2IsNegZero(f) {
			return ap2Fail("%s: iat must be an integer", label)
		}
		if !(finite(now) && finite(skew) && f <= now+skew) {
			return ap2Fail("%s: iat is in the future", label)
		}
	}
	return nil
}

func ap2DelegateMandate(claims map[string]any, label string) (map[string]any, error) {
	dp, ok := ap2Get(claims, "delegate_payload").([]any)
	if !ok {
		return nil, ap2Fail("%s: delegate_payload missing", label)
	}
	if len(dp) != 1 {
		return nil, ap2Fail("%s: delegate_payload must disclose exactly one mandate (got %d)", label, len(dp))
	}
	m, ok := ap2Obj(dp[0])
	if !ok {
		return nil, ap2Fail("%s: delegate_payload must disclose exactly one mandate (got %d)", label, len(dp))
	}
	return m, nil
}

func ap2CnfJwk(mandate map[string]any, label string) (map[string]any, error) {
	cnf, ok := ap2Obj(ap2Get(mandate, "cnf"))
	if !ok {
		return nil, ap2Fail("%s: no cnf.jwk to delegate to", label)
	}
	jwk, ok := ap2Obj(ap2Get(cnf, "jwk"))
	if !ok {
		return nil, ap2Fail("%s: no cnf.jwk to delegate to", label)
	}
	return Ap2AssertP256Jwk(jwk, label+" cnf.jwk")
}

// Ap2PrevHop is the already verified hop a key-binding hop is checked against.
type Ap2PrevHop struct {
	Hop     *Ap2SdJwtHop
	Mandate map[string]any
}

// Ap2KbOptions are the per-hop expectations of Ap2VerifyKbHop.
type Ap2KbOptions struct {
	Terminal bool
	// ExpectedAudience / ExpectedNonce are required of a terminal hop (nil = unset, which refuses).
	ExpectedAudience, ExpectedNonce *string
	Now, Skew                       float64
}

// Ap2VerifyKbHop verifies one key-binding hop against its predecessor (signature, typ, binding hash, times, aud / nonce).
func Ap2VerifyKbHop(hop *Ap2SdJwtHop, prev Ap2PrevHop, o Ap2KbOptions, label string) (Ap2VerifiedHop, error) {
	allowed := Ap2TypIntermediate
	if o.Terminal {
		allowed = Ap2TypTerminal
	}
	if !ap2OneOf(allowed, ap2Get(hop.Header, "typ")) {
		return Ap2VerifiedHop{}, ap2Fail("%s: typ must be one of %s", label, strings.Join(allowed, ", "))
	}
	if ap2Has(hop.Header, "crit") {
		return Ap2VerifiedHop{}, ap2Fail("%s: crit headers are not supported", label)
	}
	key, err := ap2CnfJwk(prev.Mandate, "preceding mandate")
	if err != nil {
		return Ap2VerifiedHop{}, err
	}
	okSig, err := Ap2VerifyHopSignature(hop, key)
	if err != nil {
		return Ap2VerifiedHop{}, err
	}
	if !okSig {
		return Ap2VerifiedHop{}, ap2Fail("%s: signature does not verify under the preceding mandate's cnf.jwk", label)
	}
	claims, err := Ap2ProcessDisclosures(hop.Payload, hop.Disclosures, hop.SdAlg)
	if err != nil {
		return Ap2VerifiedHop{}, err
	}
	hasSd, hasIss := ap2Has(claims, "sd_hash"), ap2Has(claims, "issuer_jwt_hash")
	if hasSd == hasIss {
		return Ap2VerifiedHop{}, ap2Fail("%s: exactly one of sd_hash / issuer_jwt_hash is required", label)
	}
	var expected string
	var actual any
	name := "issuer_jwt_hash"
	if hasSd {
		name = "sd_hash"
		expected, err = Ap2SdHashOf(prev.Hop, "")
		actual = claims["sd_hash"]
	} else {
		expected, err = Ap2IssuerJwtHashOf(prev.Hop, "")
		actual = claims["issuer_jwt_hash"]
	}
	if err != nil {
		return Ap2VerifiedHop{}, err
	}
	if !ap2StrictEq(actual, expected) {
		return Ap2VerifiedHop{}, ap2Fail("%s: %s does not match the preceding hop", label, name)
	}
	if !ap2Has(claims, "iat") {
		return Ap2VerifiedHop{}, ap2Fail("%s: iat is required", label)
	}
	if err := ap2CheckTimes(label, claims, o.Now, o.Skew); err != nil {
		return Ap2VerifiedHop{}, err
	}
	mandate, err := ap2DelegateMandate(claims, label)
	if err != nil {
		return Ap2VerifiedHop{}, err
	}
	if err := ap2CheckTimes(label+" mandate", mandate, o.Now, o.Skew); err != nil {
		return Ap2VerifiedHop{}, err
	}
	_, hasCnf := ap2Obj(ap2Get(mandate, "cnf"))
	if o.Terminal && hasCnf {
		return Ap2VerifiedHop{}, ap2Fail("%s: a terminal hop must not carry cnf", label)
	}
	if !o.Terminal && !hasCnf {
		return Ap2VerifiedHop{}, ap2Fail("%s: an intermediate hop requires cnf", label)
	}
	kind := "intermediate"
	if o.Terminal {
		kind = "terminal"
		if o.ExpectedAudience == nil || !ap2StrictEq(ap2Get(claims, "aud"), *o.ExpectedAudience) {
			return Ap2VerifiedHop{}, ap2Fail("%s: aud mismatch", label)
		}
		if o.ExpectedNonce == nil || !ap2StrictEq(ap2Get(claims, "nonce"), *o.ExpectedNonce) {
			return Ap2VerifiedHop{}, ap2Fail("%s: nonce mismatch", label)
		}
	}
	return Ap2VerifiedHop{Index: -1, Kind: kind, Hop: hop, Claims: claims, Mandate: mandate}, nil
}

func ap2Now(p *float64) float64 {
	if p != nil {
		return *p
	}
	return float64(time.Now().Unix())
}

func ap2ErrReason(err error) string { return err.Error() }

// Ap2VerifyDelegationChain verifies a whole chain: the root signature, then every hop in order. It never errors; it reports the reason.
func Ap2VerifyDelegationChain(token string, o Ap2VerifyChainOptions) Ap2ChainResult {
	hops, err := ap2VerifyChain(token, o)
	if err != nil {
		return Ap2ChainResult{Reason: ap2ErrReason(err)}
	}
	return Ap2ChainResult{OK: true, Hops: hops}
}

func ap2VerifyChain(token string, o Ap2VerifyChainOptions) ([]Ap2VerifiedHop, error) {
	if o.ExpectedAudience == "" || o.ExpectedNonce == "" {
		return nil, ap2Fail("verify: expectedAudience and expectedNonce are required")
	}
	now := ap2Now(o.Now)
	skew := 60.0
	if o.ClockSkewSeconds != nil {
		skew = *o.ClockSkewSeconds
	}
	parts, err := Ap2SplitChain(token)
	if err != nil {
		return nil, err
	}
	segments := make([]*Ap2SdJwtHop, len(parts))
	for i, p := range parts {
		if segments[i], err = Ap2ParseSdJwtHop(p); err != nil {
			return nil, err
		}
	}
	root := segments[0]
	if ap2Has(root.Header, "crit") {
		return nil, ap2Fail("root: crit headers are not supported")
	}
	var issuerKey map[string]any
	if o.ResolveIssuerKey != nil {
		issuerKey = o.ResolveIssuerKey(root.Header)
	}
	if issuerKey == nil {
		return nil, ap2Fail("root: no issuer key for this header")
	}
	okSig, err := Ap2VerifyHopSignature(root, issuerKey)
	if err != nil {
		return nil, err
	}
	if !okSig {
		return nil, ap2Fail("root: signature does not verify under the issuer key")
	}
	rootClaims, err := Ap2ProcessDisclosures(root.Payload, root.Disclosures, root.SdAlg)
	if err != nil {
		return nil, err
	}
	if err := ap2CheckTimes("root", rootClaims, now, skew); err != nil {
		return nil, err
	}
	rootMandate, err := ap2DelegateMandate(rootClaims, "root")
	if err != nil {
		return nil, err
	}
	if err := ap2CheckTimes("root mandate", rootMandate, now, skew); err != nil {
		return nil, err
	}
	hops := []Ap2VerifiedHop{{Index: 0, Kind: "root", Hop: root, Claims: rootClaims, Mandate: rootMandate}}
	aud, nonce := o.ExpectedAudience, o.ExpectedNonce
	for i := 1; i < len(segments); i++ {
		prev := hops[i-1]
		v, err := Ap2VerifyKbHop(segments[i], Ap2PrevHop{Hop: prev.Hop, Mandate: prev.Mandate},
			Ap2KbOptions{Terminal: i == len(segments)-1, ExpectedAudience: &aud, ExpectedNonce: &nonce, Now: now, Skew: skew}, "hop "+strconv.Itoa(i))
		if err != nil {
			return nil, err
		}
		v.Index = i
		hops = append(hops, v)
	}
	return hops, nil
}

// ---- typed chains ------------------------------------------------------------------------------------------------------

func ap2Pair(hops []Ap2VerifiedHop) (Ap2VerifiedHop, Ap2VerifiedHop, error) {
	if len(hops) != 2 {
		return Ap2VerifiedHop{}, Ap2VerifiedHop{}, ap2Fail("expected an open mandate followed by one closed mandate, got %d hop(s)", len(hops))
	}
	return hops[0], hops[1], nil
}

func ap2RequireOpenExpiry(m map[string]any, label string) error {
	if !jsIsSafeInteger(ap2Get(m, "exp")) {
		return ap2Fail("%s: an open mandate must carry exp", label)
	}
	return nil
}

// Ap2CheckoutChainResult is the outcome of verifying a checkout chain.
type Ap2CheckoutChainResult struct {
	OK          bool
	Reason      string
	Violations  []string
	Open        map[string]any
	Closed      map[string]any
	CheckoutJwt string
	Checkout    map[string]any
	// OpenHash is the sd_hash of the open checkout mandate token: the value an open payment mandate's payment.reference must hold.
	OpenHash string
	Hops     []Ap2VerifiedHop
}

// Ap2VerifyCheckoutOptions adds the merchant key resolver to the chain options.
type Ap2VerifyCheckoutOptions struct {
	Ap2VerifyChainOptions
	// ResolveMerchantKey resolves the merchant's key for the checkout_jwt signature.
	ResolveMerchantKey Ap2KeyResolver
}

// Ap2VerifyCheckoutChain verifies an open + closed checkout chain, the merchant-signed checkout, its hash, and the open constraints.
func Ap2VerifyCheckoutChain(token string, o Ap2VerifyCheckoutOptions) Ap2CheckoutChainResult {
	hops, err := ap2VerifyChain(token, o.Ap2VerifyChainOptions)
	if err != nil {
		return Ap2CheckoutChainResult{Reason: ap2ErrReason(err)}
	}
	fail := func(err error) Ap2CheckoutChainResult { return Ap2CheckoutChainResult{Reason: ap2ErrReason(err)} }
	openHop, closedHop, err := ap2Pair(hops)
	if err != nil {
		return fail(err)
	}
	open, closed := openHop.Mandate, closedHop.Mandate
	if op := Ap2OpenCheckoutMandateProblems(open); len(op) > 0 {
		return fail(ap2Fail("open checkout mandate: %s", strings.Join(op, "; ")))
	}
	if err := ap2RequireOpenExpiry(open, "open checkout mandate"); err != nil {
		return fail(err)
	}
	if cp := Ap2CheckoutMandateProblems(closed); len(cp) > 0 {
		return fail(ap2Fail("closed checkout mandate: %s", strings.Join(cp, "; ")))
	}
	checkoutJwt := closed["checkout_jwt"].(string)
	digest, err := Ap2SdDigest(checkoutJwt, closedHop.Hop.SdAlg)
	if err != nil {
		return fail(err)
	}
	if !ap2StrictEq(digest, closed["checkout_hash"]) {
		return fail(ap2Fail("checkout_hash does not match checkout_jwt"))
	}
	jwt, err := Ap2ParseJwt(checkoutJwt, "checkout_jwt")
	if err != nil {
		return fail(err)
	}
	var key map[string]any
	if o.ResolveMerchantKey != nil {
		key = o.ResolveMerchantKey(jwt.Header)
	}
	if key == nil {
		return fail(ap2Fail("checkout_jwt: no merchant key for this header"))
	}
	okSig, err := Ap2VerifyJwtEs256(jwt, key)
	if err != nil {
		return fail(err)
	}
	if !okSig {
		return fail(ap2Fail("checkout_jwt: merchant signature does not verify"))
	}
	checkout, err := Ap2ProjectCheckout(jwt.Payload)
	if err != nil {
		return fail(err)
	}
	if violations := Ap2CheckCheckoutConstraints(open, checkout); len(violations) > 0 {
		return Ap2CheckoutChainResult{Reason: "open checkout constraints violated: " + strings.Join(violations, "; "), Violations: violations}
	}
	openHash, err := Ap2SdHashOf(openHop.Hop, "")
	if err != nil {
		return fail(err)
	}
	return Ap2CheckoutChainResult{OK: true, Open: open, Closed: closed, CheckoutJwt: checkoutJwt, Checkout: checkout, OpenHash: openHash, Hops: hops}
}

// Ap2PaymentChainResult is the outcome of verifying a payment chain.
type Ap2PaymentChainResult struct {
	OK         bool
	Reason     string
	Violations []string
	Open       map[string]any
	Closed     map[string]any
	OpenHash   string
	Hops       []Ap2VerifiedHop
}

// Ap2VerifyPaymentOptions adds the payment-side expectations to the chain options.
type Ap2VerifyPaymentOptions struct {
	Ap2VerifyChainOptions
	// OpenCheckoutHash is the sd_hash of the open checkout mandate (Ap2CheckoutChainResult.OpenHash); checked against payment.reference.
	OpenCheckoutHash string
	// Context is the usage state under this open mandate (needed for payment.budget and recurrence); nil = none.
	Context map[string]any
	// ExpectedTransactionID is the checkout_hash this payment must settle; nil = unchecked.
	ExpectedTransactionID *string
}

// Ap2VerifyPaymentChain verifies an open + closed payment chain and every open payment constraint.
func Ap2VerifyPaymentChain(token string, o Ap2VerifyPaymentOptions) Ap2PaymentChainResult {
	hops, err := ap2VerifyChain(token, o.Ap2VerifyChainOptions)
	if err != nil {
		return Ap2PaymentChainResult{Reason: ap2ErrReason(err)}
	}
	fail := func(err error) Ap2PaymentChainResult { return Ap2PaymentChainResult{Reason: ap2ErrReason(err)} }
	openHop, closedHop, err := ap2Pair(hops)
	if err != nil {
		return fail(err)
	}
	open, closed := openHop.Mandate, closedHop.Mandate
	if op := Ap2OpenPaymentMandateProblems(open); len(op) > 0 {
		return fail(ap2Fail("open payment mandate: %s", strings.Join(op, "; ")))
	}
	if err := ap2RequireOpenExpiry(open, "open payment mandate"); err != nil {
		return fail(err)
	}
	if cp := Ap2PaymentMandateProblems(closed); len(cp) > 0 {
		return fail(ap2Fail("closed payment mandate: %s", strings.Join(cp, "; ")))
	}
	if o.ExpectedTransactionID != nil && !ap2StrictEq(closed["transaction_id"], *o.ExpectedTransactionID) {
		return fail(ap2Fail("transaction_id does not match the checkout being settled"))
	}
	violations := Ap2CheckPaymentConstraints(open, closed, Ap2PaymentCheckOptions{OpenCheckoutHash: o.OpenCheckoutHash, Context: o.Context, Now: ap2Now(o.Now)})
	if len(violations) > 0 {
		return Ap2PaymentChainResult{Reason: "open payment constraints violated: " + strings.Join(violations, "; "), Violations: violations}
	}
	openHash, err := Ap2SdHashOf(openHop.Hop, "")
	if err != nil {
		return fail(err)
	}
	return Ap2PaymentChainResult{OK: true, Open: open, Closed: closed, OpenHash: openHash, Hops: hops}
}

// Ap2PurchaseOptions are the verifier's expectations of a whole purchase.
type Ap2PurchaseOptions struct {
	ResolveIssuerKey, ResolveMerchantKey Ap2KeyResolver
	// CheckoutAudience / CheckoutNonce and PaymentAudience / PaymentNonce are the terminal hops' expected aud / nonce.
	CheckoutAudience, CheckoutNonce, PaymentAudience, PaymentNonce string
	// Context is the usage state under the open payment mandate (nil = none).
	Context               map[string]any
	Now, ClockSkewSeconds *float64
}

// Ap2PurchaseResult is the outcome of verifying (or redeeming) a purchase.
type Ap2PurchaseResult struct {
	OK       bool
	Reason   string
	Checkout Ap2CheckoutChainResult
	Payment  Ap2PaymentChainResult
}

// Ap2VerifyPurchase verifies a complete purchase: the checkout chain, then the payment chain bound to it (the payment's
// payment.reference is the open checkout hash; its transaction_id is the closed checkout's checkout_hash), and that the payment
// settles what the merchant quoted (payee, currency, total).
func Ap2VerifyPurchase(checkoutToken, paymentToken string, o Ap2PurchaseOptions) Ap2PurchaseResult {
	co := Ap2VerifyCheckoutChain(checkoutToken, Ap2VerifyCheckoutOptions{
		Ap2VerifyChainOptions: Ap2VerifyChainOptions{ResolveIssuerKey: o.ResolveIssuerKey, ExpectedAudience: o.CheckoutAudience, ExpectedNonce: o.CheckoutNonce,
			Now: o.Now, ClockSkewSeconds: o.ClockSkewSeconds},
		ResolveMerchantKey: o.ResolveMerchantKey})
	if !co.OK {
		return Ap2PurchaseResult{Reason: "checkout: " + co.Reason}
	}
	txid, _ := co.Closed["checkout_hash"].(string)
	pay := Ap2VerifyPaymentChain(paymentToken, Ap2VerifyPaymentOptions{
		Ap2VerifyChainOptions: Ap2VerifyChainOptions{ResolveIssuerKey: o.ResolveIssuerKey, ExpectedAudience: o.PaymentAudience, ExpectedNonce: o.PaymentNonce,
			Now: o.Now, ClockSkewSeconds: o.ClockSkewSeconds},
		OpenCheckoutHash: co.OpenHash, ExpectedTransactionID: &txid, Context: o.Context})
	if !pay.OK {
		return Ap2PurchaseResult{Reason: "payment: " + pay.Reason}
	}
	total, ok := Ap2CheckoutTotal(co.Checkout)
	if !ok {
		return Ap2PurchaseResult{Reason: "checkout: needs exactly one total entry"}
	}
	amt := ap2Get(pay.Closed, "payment_amount")
	if !ap2StrictEq(ap2Get(amt, "currency"), ap2Get(co.Checkout, "currency")) {
		return Ap2PurchaseResult{Reason: "payment currency differs from the checkout currency"}
	}
	if !ap2StrictEq(ap2Get(amt, "amount"), total) {
		return Ap2PurchaseResult{Reason: "payment amount " + ap2Str(ap2Get(amt, "amount")) + " differs from the checkout total " + ap2Str(total)}
	}
	merchant := ap2Get(co.Checkout, "merchant")
	if !ap2Truthy(merchant) {
		return Ap2PurchaseResult{Reason: "checkout: no merchant to compare the payee with"}
	}
	if !ap2StrictEq(ap2Get(merchant, "id"), ap2Get(ap2Get(pay.Closed, "payee"), "id")) {
		return Ap2PurchaseResult{Reason: "payee differs from the checkout merchant"}
	}
	return Ap2PurchaseResult{OK: true, Checkout: co, Payment: pay}
}
