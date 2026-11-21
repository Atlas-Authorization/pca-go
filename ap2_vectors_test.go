package pca

// Replays the AP2 reference corpus: SD-JWT parsing and disclosure processing, ES256, mandate validators and minor units, open-mandate
// constraint evaluation, delegation chains, purchases and the redeem ledger, the PCA terms bridge, settlement payloads and the PCA
// payment binding. Keys are derived from labels (d = SHA-256 of "atlas-pca-conformance/ap2/<label>", the corpus carries no key
// material); ECDSA signatures are randomized, so every signing function is compared with each signature segment replaced by "SIG".
// A function argument that is a key is a LABEL string. Corpus arguments are loaded WITHOUT normalisation so member order survives.

import (
	"compress/gzip"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"regexp"
	"strings"
	"testing"
)

const ap2T0 = 1_800_000_000

func ap2Each(t *testing.T, file string, f func(c *baseCase)) {
	t.Helper()
	fh, err := os.Open("testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	zr, err := gzip.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(zr)
	tok := func() json.Token {
		x, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	if d, _ := tok().(json.Delim); d != '{' {
		t.Fatal("ap2: not an object")
	}
	n := 0
	for dec.More() {
		key, _ := tok().(string)
		if key != "cases" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if d, _ := tok().(json.Delim); d != '[' {
			t.Fatal("ap2: cases is not an array")
		}
		for dec.More() {
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				t.Fatal(err)
			}
			v, err := ParseJSONLenient(raw)
			if err != nil {
				t.Fatalf("ap2 case %d: %v", n, err)
			}
			m := v.(map[string]any)
			args, _ := m["args"].([]any)
			f(&baseCase{Fn: m["fn"].(string), Name: m["name"].(string), Args: args, Out: m["out"], C: m})
			n++
		}
		tok()
	}
	if n == 0 {
		t.Fatalf("ap2: no cases in %s", file)
	}
}

// ap2VecJSON is the canonical JSON value of a result (a lone surrogate stays a surrogate, which encoding/json would replace).
func ap2VecJSON(v any) any {
	s, err := ap2Stringify(v)
	if err != nil {
		return fmt.Sprintf("<unserializable %T: %v>", v, err)
	}
	x, err := ParseJSONLenient([]byte(s))
	if err != nil {
		return fmt.Sprintf("<unparsable %s>", s)
	}
	return normalizeJSON(x)
}

func ap2Replay(t *testing.T, file string, fns map[string]vecFn) {
	t.Helper()
	var k baseTally
	ap2Each(t, file, func(c *baseCase) {
		f, ok := fns[c.Fn]
		if !ok {
			k.fail(c, "no Go entry point for %s", c.Fn)
			return
		}
		k.run(c.Fn)
		var got any
		var err error
		if p := baseCall(func() { got, err = f(c.Args) }); p != "" {
			k.fail(c, "panic: %s", p)
			return
		}
		var skip vecSkip
		if errors.As(err, &skip) {
			k.skip(c.Fn, string(skip))
			return
		}
		if throws, _ := baseThrows(c.Out); throws {
			if err == nil && !(vecEngineCrash(c.Out) && vecRefusalValue(ap2VecJSON(got))) {
				k.fail(c, "reference refuses (%v), Go returned %s", c.Out, baseCanon(ap2VecJSON(got)))
			}
			return
		}
		if err != nil {
			k.fail(c, "Go refuses (%v), reference returned %s", err, baseCanon(c.Out))
			return
		}
		if w, g := baseCanon(c.Out), baseCanon(ap2VecJSON(got)); w != g {
			k.fail(c, "want %s got %s", w, g)
		}
	})
	k.finish(t)
}

// ---- keys and salts ----------------------------------------------------------------------------------------------------

func ap2LabelPriv(label string) map[string]any {
	d := sha256.Sum256([]byte("atlas-pca-conformance/ap2/" + label))
	k, err := ecdh.P256().NewPrivateKey(d[:])
	if err != nil {
		panic(err)
	}
	pub := k.PublicKey().Bytes()
	return ap2Map("kty", "EC", "crv", "P-256", "d", ap2B64uEnc(d[:]), "x", ap2B64uEnc(pub[1:33]), "y", ap2B64uEnc(pub[33:65]), "kid", label)
}

var ap2KeyCache = map[string]*Ap2KeyPair{}

func ap2KeyFor(label string) *Ap2KeyPair {
	if k, ok := ap2KeyCache[label]; ok {
		return k
	}
	k, err := Ap2KeyPairFromPrivateJwk(ap2LabelPriv(label))
	if err != nil {
		panic(err)
	}
	ap2KeyCache[label] = k
	return k
}

func ap2PubOf(label string) map[string]any {
	k := ap2KeyFor(label)
	return ap2Map("kty", "EC", "crv", "P-256", "x", k.PublicJwk["x"], "y", k.PublicJwk["y"])
}

func ap2CounterSalt() func() string {
	n := 0
	return func() string {
		n++
		return Ap2B64uEncode(fmt.Sprintf("salt-%012d", n))
	}
}

var ap2JWTSeg = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
var ap2SigTail = regexp.MustCompile(`\.[A-Za-z0-9_-]+$`)
var ap2JSONDetail = regexp.MustCompile(`(?s)invalid JSON \(.*\)$`)

func ap2StripSig(t string) string {
	parts := strings.Split(t, "~")
	for i, s := range parts {
		if ap2JWTSeg.MatchString(s) {
			parts[i] = ap2SigTail.ReplaceAllString(s, ".SIG")
		}
	}
	return strings.Join(parts, "~")
}

func ap2Mask(s string) string { return ap2JSONDetail.ReplaceAllString(s, "invalid JSON (*)") }

func ap2List(l []string) []any {
	out := make([]any, len(l))
	for i, s := range l {
		out[i] = s
	}
	return out
}

func ap2Bytes(b []byte) any { return ap2Map("$bytes", ap2B64uEnc(b)) }

// ---- option adapters ---------------------------------------------------------------------------------------------------

func ap2Resolver(m any) Ap2KeyResolver {
	mm, _ := m.(map[string]any)
	return func(h map[string]any) map[string]any {
		kid, ok := h["kid"].(string)
		if !ok || mm == nil {
			return nil
		}
		e, has := mm[kid]
		if !has {
			return nil
		}
		em, _ := e.(map[string]any)
		return em
	}
}

func ap2OptF(m map[string]any, k string) *float64 {
	v, ok := m[k]
	if !ok || v == nil {
		return nil
	}
	f, ok := jsNum(v)
	if !ok {
		return nil
	}
	return &f
}

func ap2OptS(m map[string]any, k string) *string {
	s, ok := m[k].(string)
	if !ok {
		return nil
	}
	return &s
}

func ap2Num0(v any) float64 {
	f, ok := jsNum(v)
	if !ok {
		return math.NaN()
	}
	return f
}

func ap2ChainOpts(c map[string]any) Ap2VerifyChainOptions {
	aud, _ := c["expectedAudience"].(string)
	nonce, _ := c["expectedNonce"].(string)
	return Ap2VerifyChainOptions{ResolveIssuerKey: ap2Resolver(c["issuerKeys"]), ExpectedAudience: aud, ExpectedNonce: nonce, Now: ap2OptF(c, "now"), ClockSkewSeconds: ap2OptF(c, "clockSkewSeconds")}
}

func ap2HopOut(h Ap2VerifiedHop) any {
	return ap2Map("index", ap2Num(float64(h.Index)), "kind", h.Kind, "claims", h.Claims, "mandate", h.Mandate)
}

func ap2HopsOut(hs []Ap2VerifiedHop) any {
	out := make([]any, len(hs))
	for i, h := range hs {
		out[i] = ap2HopOut(h)
	}
	return out
}

func ap2ProjChain(r Ap2ChainResult) any {
	if !r.OK {
		return ap2Map("ok", false, "reason", ap2Mask(r.Reason))
	}
	return ap2Map("ok", true, "hops", ap2HopsOut(r.Hops))
}

func ap2ProjCheckout(r Ap2CheckoutChainResult) any {
	if !r.OK {
		b := ap2New().set("ok", false).set("reason", ap2Mask(r.Reason))
		if len(r.Violations) > 0 {
			b.set("violations", ap2List(r.Violations))
		}
		return b.done()
	}
	return ap2Map("ok", true, "hops", ap2HopsOut(r.Hops), "open", r.Open, "closed", r.Closed, "checkoutJwt", r.CheckoutJwt, "checkout", r.Checkout, "openHash", r.OpenHash)
}

func ap2ProjPayment(r Ap2PaymentChainResult) any {
	if !r.OK {
		b := ap2New().set("ok", false).set("reason", ap2Mask(r.Reason))
		if len(r.Violations) > 0 {
			b.set("violations", ap2List(r.Violations))
		}
		return b.done()
	}
	return ap2Map("ok", true, "hops", ap2HopsOut(r.Hops), "open", r.Open, "closed", r.Closed, "openHash", r.OpenHash)
}

func ap2ProjPurchase(r Ap2PurchaseResult) any {
	if !r.OK {
		return ap2Map("ok", false, "reason", ap2Mask(r.Reason))
	}
	return ap2Map("ok", true, "checkout", ap2ProjCheckout(r.Checkout), "payment", ap2ProjPayment(r.Payment))
}

func ap2PurchaseOpts(c map[string]any) Ap2PurchaseOptions {
	co, _ := c["checkout"].(map[string]any)
	pa, _ := c["payment"].(map[string]any)
	o := Ap2PurchaseOptions{ResolveIssuerKey: ap2Resolver(c["issuerKeys"]), ResolveMerchantKey: ap2Resolver(c["merchantKeys"]), Now: ap2OptF(c, "now"), ClockSkewSeconds: ap2OptF(c, "clockSkewSeconds")}
	o.CheckoutAudience, _ = co["expectedAudience"].(string)
	o.CheckoutNonce, _ = co["expectedNonce"].(string)
	o.PaymentAudience, _ = pa["expectedAudience"].(string)
	o.PaymentNonce, _ = pa["expectedNonce"].(string)
	o.Context, _ = c["context"].(map[string]any)
	return o
}

type ap2SpecLedger struct {
	spec  map[string]any
	calls []any
}

func (l *ap2SpecLedger) Reserve(h, tx string, amount float64) (map[string]any, bool, error) {
	l.calls = append(l.calls, []any{"reserve", h, tx, ap2Num(amount)})
	switch l.spec["mode"] {
	case "throw":
		return nil, false, errors.New("down")
	case "replayed":
		return nil, true, nil
	case "undefined":
		return nil, false, nil
	}
	if c, ok := l.spec["ctx"].(map[string]any); ok {
		return c, false, nil
	}
	return ap2Map("totalAmount", ap2Num(0), "totalUses", ap2Num(0)), false, nil
}

func (l *ap2SpecLedger) Release(h, tx string) error {
	l.calls = append(l.calls, []any{"release", h, tx})
	if l.spec["releaseThrows"] == true {
		return errors.New("release failed")
	}
	return nil
}

// ---- issuing adapters --------------------------------------------------------------------------------------------------

func ap2Str0(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func ap2OpenCommon(a map[string]any) Ap2OpenMandateCommon {
	label := "issuer"
	if s, ok := a["issuerKey"].(string); ok {
		label = s
	}
	c := Ap2OpenMandateCommon{Issuer: Ap2Issuer{Key: ap2KeyFor(label), Kid: ap2OptS(a, "kid")}, Iat: ap2Num0(a["iat"]), Exp: ap2Num0(a["exp"]),
		Pca: a["pca"], SdAlg: ap2Str0(a, "sdAlg"), Salt: ap2CounterSalt(), Typ: ap2OptS(a, "typ")}
	if l, ok := a["x5c"].([]any); ok {
		c.Issuer.X5c = []string{}
		for _, x := range l {
			s, _ := x.(string)
			c.Issuer.X5c = append(c.Issuer.X5c, s)
		}
	}
	if j, ok := a["agentJwk"]; ok && j != nil {
		c.AgentJwk = j
	} else {
		label := "agent"
		if s, ok := a["agentKey"].(string); ok {
			label = s
		}
		c.AgentJwk = ap2PubOf(label)
	}
	return c
}

func ap2ClosedCommon(a map[string]any) Ap2ClosedHopCommon {
	label := "agent"
	if s, ok := a["agentKey"].(string); ok {
		label = s
	}
	return Ap2ClosedHopCommon{Open: ap2Str0(a, "open"), AgentKey: ap2KeyFor(label), Aud: ap2Str0(a, "aud"), Nonce: ap2Str0(a, "nonce"), Iat: ap2Num0(a["iat"]),
		Exp: ap2OptF(a, "exp"), Pca: a["pca"], HashMode: ap2Str0(a, "hashMode"), Salt: ap2CounterSalt()}
}

func ap2FromTermsOpts(a map[string]any) Ap2FromTermsOptions {
	merchants := []any{ap2Map("id", "merchant_1", "name", "Demo Merchant", "website", "https://demo-merchant.example"), ap2Map("id", "merchant_2", "name", "Other Merchant")}
	if l, ok := a["merchants"].([]any); ok {
		merchants = l
	}
	kid := "issuer-1"
	iat := float64(ap2T0)
	if f := ap2OptF(a, "iat"); f != nil {
		iat = *f
	}
	return Ap2FromTermsOptions{Issuer: Ap2Issuer{Key: ap2KeyFor("issuer"), Kid: &kid}, AgentJwk: ap2PubOf("agent"), Merchants: merchants, Iat: iat,
		Exp: ap2OptF(a, "exp"), Salt: ap2CounterSalt()}
}

func ap2Problems(f func(any) []string) vecFn {
	return func(args []any) (any, error) { return ap2List(f(vecArg(args, 0))), nil }
}

func ap2Arg(args []any, i int) any { return vecArg(args, i) }

func ap2StrArg(args []any, i int) (string, error) {
	s, ok := vecArg(args, i).(string)
	if !ok {
		return "", errors.New("argument is not a string")
	}
	return s, nil
}

func ap2HopArg(args []any, i int) (*Ap2SdJwtHop, error) {
	s, err := ap2StrArg(args, i)
	if err != nil {
		return nil, err
	}
	return Ap2ParseSdJwtHop(s)
}

func ap2MapArg(args []any, i int) map[string]any { m, _ := vecArg(args, i).(map[string]any); return m }

func ap2SettleCtx(args []any) map[string]any { return ap2MapArg(args, 1) }

func TestAp2Vectors(t *testing.T) {
	problems := map[string]func(any) []string{"openPaymentMandateProblems": Ap2OpenPaymentMandateProblems, "paymentMandateProblems": Ap2PaymentMandateProblems,
		"openCheckoutMandateProblems": Ap2OpenCheckoutMandateProblems, "checkoutMandateProblems": Ap2CheckoutMandateProblems}
	fns := map[string]vecFn{
		"b64uEncode": func(a []any) (any, error) { s, err := ap2StrArg(a, 0); return Ap2B64uEncode(s), err },
		"b64uDecode": func(a []any) (any, error) {
			s, _ := ap2StrArg(a, 0)
			w, _ := ap2StrArg(a, 1)
			b, err := Ap2B64uDecode(s, w)
			return ap2Bytes(b), err
		},
		"parseJson": func(a []any) (any, error) {
			s, _ := ap2StrArg(a, 0)
			w, _ := ap2StrArg(a, 1)
			return Ap2ParseJson(s, w)
		},
		"isSdAlg": func(a []any) (any, error) { return Ap2IsSdAlg(ap2Arg(a, 0)), nil },
		"sdDigest": func(a []any) (any, error) {
			s, err := ap2StrArg(a, 0)
			if err != nil {
				return nil, err
			}
			alg := "sha-256"
			if len(a) > 1 {
				alg, _ = a[1].(string)
			}
			return Ap2SdDigest(s, alg)
		},
		"assertP256Jwk": func(a []any) (any, error) { w, _ := ap2StrArg(a, 1); return Ap2AssertP256Jwk(ap2Arg(a, 0), w) },
		"jwkThumbprint": func(a []any) (any, error) { return Ap2JwkThumbprint(ap2Arg(a, 0)) },
		"ap2KeyPairFromPrivateJwk": func(a []any) (any, error) {
			label, _ := ap2StrArg(a, 0)
			jwk := ap2New().spread(ap2LabelPriv(label))
			for k, v := range ap2MapArg(a, 1) {
				jwk.set(k, v)
			}
			kp, err := Ap2KeyPairFromPrivateJwk(jwk.done())
			if err != nil {
				return nil, err
			}
			return kp.PublicJwk, nil
		},
		"parseSdJwtHop": func(a []any) (any, error) {
			h, err := ap2HopArg(a, 0)
			if err != nil {
				return nil, err
			}
			return ap2Map("raw", h.Raw, "jwt", h.Jwt, "header", h.Header, "payload", h.Payload, "disclosures", ap2List(h.Disclosures), "sdAlg", h.SdAlg,
				"signingInput", h.SigningInput, "signature", ap2Bytes(h.Signature)), nil
		},
		"hopSdJwt": func(a []any) (any, error) {
			h, err := ap2HopArg(a, 0)
			if err != nil {
				return nil, err
			}
			return Ap2HopSdJwt(h.Jwt, h.Disclosures), nil
		},
		"sdHashOf": func(a []any) (any, error) {
			h, err := ap2HopArg(a, 0)
			if err != nil {
				return nil, err
			}
			alg, _ := ap2Arg(a, 1).(string)
			return Ap2SdHashOf(h, alg)
		},
		"issuerJwtHashOf": func(a []any) (any, error) {
			h, err := ap2HopArg(a, 0)
			if err != nil {
				return nil, err
			}
			alg, _ := ap2Arg(a, 1).(string)
			return Ap2IssuerJwtHashOf(h, alg)
		},
		"processDisclosures": func(a []any) (any, error) {
			if _, isStr := ap2Arg(a, 0).(string); isStr {
				h, err := ap2HopArg(a, 0)
				if err != nil {
					return nil, err
				}
				return Ap2ProcessDisclosures(h.Payload, h.Disclosures, h.SdAlg)
			}
			ds := []string{}
			for _, d := range ap2Arg(a, 1).([]any) {
				s, _ := d.(string)
				ds = append(ds, s)
			}
			alg, _ := ap2Arg(a, 2).(string)
			return Ap2ProcessDisclosures(ap2MapArg(a, 0), ds, alg)
		},
		"splitChain": func(a []any) (any, error) {
			s, err := ap2StrArg(a, 0)
			if err != nil {
				return nil, err
			}
			parts, err := Ap2SplitChain(s)
			return ap2List(parts), err
		},
		"disclosureBuilder": func(a []any) (any, error) {
			alg, _ := ap2Arg(a, 0).(string)
			b := Ap2NewDisclosureBuilder(alg, ap2CounterSalt())
			results := []any{}
			for _, o := range ap2Arg(a, 1).([]any) {
				op := o.(map[string]any)
				if op["kind"] == "element" {
					r, err := b.Element(op["value"])
					if err != nil {
						return nil, err
					}
					results = append(results, r)
				} else {
					r, err := b.Property(op["name"].(string), op["value"])
					if err != nil {
						return nil, err
					}
					results = append(results, r)
				}
			}
			return ap2Map("results", results, "disclosures", ap2List(b.Disclosures)), nil
		},
		"parseJwt": func(a []any) (any, error) {
			s, _ := ap2StrArg(a, 0)
			w, _ := ap2StrArg(a, 1)
			p, err := Ap2ParseJwt(s, w)
			if err != nil {
				return nil, err
			}
			return ap2Map("header", p.Header, "payload", p.Payload, "signingInput", p.SigningInput, "signature", ap2Bytes(p.Signature)), nil
		},
		"verifyJwtEs256": func(a []any) (any, error) {
			s, _ := ap2StrArg(a, 0)
			p, err := Ap2ParseJwt(s, "jwt")
			if err != nil {
				return nil, err
			}
			return Ap2VerifyJwtEs256(p, ap2Arg(a, 1))
		},
		"verifyHopSignature": func(a []any) (any, error) {
			h, err := ap2HopArg(a, 0)
			if err != nil {
				return nil, err
			}
			return Ap2VerifyHopSignature(h, ap2Arg(a, 1))
		},
		"signSdJwt": func(a []any) (any, error) {
			m := ap2MapArg(a, 0)
			ds := []string{}
			for _, d := range m["disclosures"].([]any) {
				s, _ := d.(string)
				ds = append(ds, s)
			}
			tok, err := Ap2SignSdJwt(m["header"].(map[string]any), m["payload"].(map[string]any), ds, ap2KeyFor(m["key"].(string)))
			return ap2StripSig(tok), err
		},
		"signJwtEs256": func(a []any) (any, error) {
			m := ap2MapArg(a, 0)
			tok, err := Ap2SignJwtEs256(m["header"].(map[string]any), m["payload"].(map[string]any), ap2KeyFor(m["key"].(string)))
			return ap2StripSig(tok), err
		},
		"currencyExponent": func(a []any) (any, error) {
			e, err := Ap2CurrencyExponent(ap2Arg(a, 0))
			return ap2Num(float64(e)), err
		},
		"toMinorUnits": func(a []any) (any, error) {
			f, err := Ap2ToMinorUnits(ap2Arg(a, 0), ap2Arg(a, 1))
			return ap2Num(f), err
		},
		"fromMinorUnits": func(a []any) (any, error) {
			f, err := Ap2FromMinorUnits(ap2Arg(a, 0), ap2Arg(a, 1))
			return ap2Num(f), err
		},
		"assertValid": func(a []any) (any, error) {
			k, _ := ap2StrArg(a, 0)
			w, _ := ap2StrArg(a, 2)
			return Ap2AssertValid(ap2Arg(a, 1), problems[k], w)
		},
		"constants": func(a []any) (any, error) {
			return ap2Map("VCT_CHECKOUT", Ap2VctCheckout, "VCT_CHECKOUT_OPEN", Ap2VctCheckoutOpen, "VCT_PAYMENT", Ap2VctPayment, "VCT_PAYMENT_OPEN", Ap2VctPaymentOpen,
				"PCA_CLAIM", Ap2PcaClaim, "FREQUENCIES", ap2List(Ap2Frequencies), "AP2_COMMIT", Ap2Commit, "PCA_BINDING_VERSION", ap2Num(Ap2PcaBindingVersion),
				"TYP_TERMINAL", ap2List(Ap2TypTerminal), "TYP_INTERMEDIATE", ap2List(Ap2TypIntermediate)), nil
		},
		"merchantMatches": func(a []any) (any, error) { return Ap2MerchantMatches(ap2Arg(a, 0), ap2Arg(a, 1)), nil },
		"checkPaymentConstraints": func(a []any) (any, error) {
			o := ap2MapArg(a, 2)
			opts := Ap2PaymentCheckOptions{OpenCheckoutHash: ap2Str0(o, "openCheckoutHash"), Now: ap2Num0(o["now"])}
			opts.Context, _ = o["context"].(map[string]any)
			return ap2List(Ap2CheckPaymentConstraints(ap2MapArg(a, 0), ap2MapArg(a, 1), opts)), nil
		},
		"projectCheckout": func(a []any) (any, error) { return Ap2ProjectCheckout(ap2MapArg(a, 0)) },
		"checkoutTotal": func(a []any) (any, error) {
			v, ok := Ap2CheckoutTotal(ap2MapArg(a, 0))
			if !ok {
				return nil, nil
			}
			return v, nil
		},
		"checkCheckoutConstraints": func(a []any) (any, error) {
			return ap2List(Ap2CheckCheckoutConstraints(ap2MapArg(a, 0), ap2MapArg(a, 1))), nil
		},
		"verifyDelegationChain": func(a []any) (any, error) {
			t, err := ap2StrArg(a, 0)
			if err != nil {
				return nil, err
			}
			return ap2ProjChain(Ap2VerifyDelegationChain(t, ap2ChainOpts(ap2MapArg(a, 1)))), nil
		},
		"verifyKbHop": func(a []any) (any, error) {
			h, err := ap2HopArg(a, 0)
			if err != nil {
				return nil, err
			}
			prev, err := ap2HopArg(a, 1)
			if err != nil {
				return nil, err
			}
			o := ap2MapArg(a, 3)
			terminal, _ := o["terminal"].(bool)
			label, _ := ap2StrArg(a, 4)
			v, err := Ap2VerifyKbHop(h, Ap2PrevHop{Hop: prev, Mandate: ap2MapArg(a, 2)},
				Ap2KbOptions{Terminal: terminal, ExpectedAudience: ap2OptS(o, "expectedAudience"), ExpectedNonce: ap2OptS(o, "expectedNonce"), Now: ap2Num0(o["now"]), Skew: ap2Num0(o["skew"])}, label)
			if err != nil {
				return nil, err
			}
			return ap2Map("index", ap2Num(float64(v.Index)), "kind", v.Kind, "claims", v.Claims, "mandate", v.Mandate), nil
		},
		"verifyCheckoutChain": func(a []any) (any, error) {
			t, err := ap2StrArg(a, 0)
			if err != nil {
				return nil, err
			}
			c := ap2MapArg(a, 1)
			return ap2ProjCheckout(Ap2VerifyCheckoutChain(t, Ap2VerifyCheckoutOptions{Ap2VerifyChainOptions: ap2ChainOpts(c), ResolveMerchantKey: ap2Resolver(c["merchantKeys"])})), nil
		},
		"verifyPaymentChain": func(a []any) (any, error) {
			t, err := ap2StrArg(a, 0)
			if err != nil {
				return nil, err
			}
			c := ap2MapArg(a, 1)
			o := Ap2VerifyPaymentOptions{Ap2VerifyChainOptions: ap2ChainOpts(c), OpenCheckoutHash: ap2Str0(c, "openCheckoutHash"), ExpectedTransactionID: ap2OptS(c, "expectedTransactionId")}
			o.Context, _ = c["context"].(map[string]any)
			return ap2ProjPayment(Ap2VerifyPaymentChain(t, o)), nil
		},
		"verifyPurchase": func(a []any) (any, error) {
			x, err := ap2StrArg(a, 0)
			if err != nil {
				return nil, err
			}
			y, err := ap2StrArg(a, 1)
			if err != nil {
				return nil, err
			}
			return ap2ProjPurchase(Ap2VerifyPurchase(x, y, ap2PurchaseOpts(ap2MapArg(a, 2)))), nil
		},
		"redeemPurchase": func(a []any) (any, error) {
			x, err := ap2StrArg(a, 0)
			if err != nil {
				return nil, err
			}
			y, err := ap2StrArg(a, 1)
			if err != nil {
				return nil, err
			}
			var ledger Ap2PurchaseLedger
			spec := &ap2SpecLedger{spec: ap2MapArg(a, 3)}
			if s, isStr := ap2Arg(a, 3).(string); !(isStr && s == "none") {
				ledger = spec
			}
			r := Ap2RedeemPurchase(x, y, ap2PurchaseOpts(ap2MapArg(a, 2)), ledger)
			return ap2Map("result", ap2ProjPurchase(r), "calls", append([]any{}, spec.calls...)), nil
		},
		"issueOpenPaymentMandate": func(a []any) (any, error) {
			m := ap2MapArg(a, 0)
			in := Ap2OpenPaymentMandateInput{Ap2OpenMandateCommon: ap2OpenCommon(m), Payee: m["payee"], PaymentAmount: m["paymentAmount"],
				PaymentInstrument: m["paymentInstrument"], Pisp: m["pisp"], ExecutionDate: ap2OptS(m, "executionDate")}
			in.Constraints, _ = m["constraints"].([]any)
			tok, err := Ap2IssueOpenPaymentMandate(in)
			return ap2StripSig(tok), err
		},
		"issueOpenCheckoutMandate": func(a []any) (any, error) {
			m := ap2MapArg(a, 0)
			in := Ap2OpenCheckoutMandateInput{Ap2OpenMandateCommon: ap2OpenCommon(m)}
			in.Constraints, _ = m["constraints"].([]any)
			tok, err := Ap2IssueOpenCheckoutMandate(in)
			return ap2StripSig(tok), err
		},
		"presentClosedPayment": func(a []any) (any, error) {
			m := ap2MapArg(a, 0)
			in := Ap2ClosedPaymentInput{Ap2ClosedHopCommon: ap2ClosedCommon(m), TransactionID: ap2Str0(m, "transactionId"), Payee: m["payee"], PaymentAmount: m["paymentAmount"],
				PaymentInstrument: m["paymentInstrument"], Pisp: m["pisp"], ExecutionDate: ap2OptS(m, "executionDate"), RiskData: m["riskData"]}
			tok, err := Ap2PresentClosedPayment(in)
			return ap2StripSig(tok), err
		},
		"presentClosedCheckout": func(a []any) (any, error) {
			m := ap2MapArg(a, 0)
			tok, err := Ap2PresentClosedCheckout(Ap2ClosedCheckoutInput{Ap2ClosedHopCommon: ap2ClosedCommon(m), CheckoutJwt: ap2Str0(m, "checkoutJwt")})
			return ap2StripSig(tok), err
		},
		"ap2BudgetMax": func(a []any) (any, error) { f, err := Ap2BudgetMax(ap2Arg(a, 0), ap2Arg(a, 1)); return ap2Num(f), err },
		"ap2BudgetReads": func(a []any) (any, error) {
			sdk, major, err := Ap2BudgetReads(ap2Arg(a, 0), ap2Arg(a, 1))
			if err != nil {
				return nil, err
			}
			return ap2Map("sdk", ap2Num(sdk), "major", ap2Num(major)), nil
		},
		"riskRatio": func(a []any) (any, error) {
			return ap2Num(Ap2RiskRatio(ap2Num0(ap2Arg(a, 0)), ap2Num0(ap2Arg(a, 1)))), nil
		},
		"pcaBindingNonce": func(a []any) (any, error) { return Ap2PcaBindingNonce(ap2MapArg(a, 0)) },
		"paymentConstraintsFromTerms": func(a []any) (any, error) {
			ref, _ := ap2StrArg(a, 2)
			return Ap2PaymentConstraintsFromTerms(ap2Arg(a, 0), ap2Arg(a, 1), ref)
		},
		"pcaOpenClaim": func(a []any) (any, error) { return Ap2PcaOpenClaim(ap2Arg(a, 0)) },
		"openPaymentMandateFromPca": func(a []any) (any, error) {
			x := ap2MapArg(a, 0)
			ref := "REF"
			if s, ok := x["checkoutReference"].(string); ok {
				ref = s
			}
			tok, err := Ap2OpenPaymentMandateFromPca(x["mandate"], ap2FromTermsOpts(x), ref)
			return ap2StripSig(tok), err
		},
		"openCheckoutMandateFromPca": func(a []any) (any, error) {
			x := ap2MapArg(a, 0)
			var items any = []any{ap2Map("id", "line_1", "acceptable_items", []any{ap2Map("id", "sku-1", "title", "Widget")}, "quantity", ap2Num(2))}
			if l, ok := x["lineItems"]; ok && l != nil {
				items = l
			}
			tok, err := Ap2OpenCheckoutMandateFromPca(x["mandate"], ap2FromTermsOpts(x), items)
			return ap2StripSig(tok), err
		},
		"toAtomicUnits": func(a []any) (any, error) { return Ap2ToAtomicUnits(ap2Arg(a, 0), ap2Arg(a, 1)) },
		"x402Settlement": func(a []any) (any, error) {
			return Ap2X402Settlement(ap2MapArg(a, 0), ap2SettleCtx(a))
		},
		"stripeSptSettlement": func(a []any) (any, error) {
			return Ap2StripeSptSettlement(ap2MapArg(a, 0), ap2SettleCtx(a))
		},
		"buildPcaPaymentBinding": func(a []any) (any, error) {
			m := ap2MapArg(a, 0)
			label, _ := m["agentSeed"].(string)
			secret := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
			counter, _ := jsNum(m["counter"])
			in := Ap2PcaPaymentBindingInput{Mandate: ap2MapOf(m["mandate"]), Open: ap2Str0(m, "open"), AgentJwk: ap2PubOf("agent"), AgentSecret: secret[:],
				Audience: ap2Str0(m, "audience"), Counter: int64(counter), TransactionID: ap2Str0(m, "transactionId"), Payee: ap2MapOf(m["payee"]),
				Amount: ap2MapOf(m["amount"]), InstrumentID: ap2Str0(m, "instrumentId"), Category: ap2OptS(m, "category"), Now: ap2OptF(m, "now")}
			if c, has := m["cosign"]; has {
				in.Cosign = func(map[string]any) any { return c }
			}
			return Ap2BuildPcaPaymentBinding(in)
		},
	}
	for name, f := range problems {
		fns[name] = ap2Problems(f)
	}
	ap2Replay(t, "ref-ap2.json.gz", fns)
}

func ap2MapOf(v any) map[string]any { m, _ := v.(map[string]any); return m }
