package pca

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"strings"
	"testing"
)

// A clock, age, spend, remaining or amount that is NaN or infinite never admits: every site below reads as the
// negation of its positive condition and checks the finite operands explicitly.

var infKillNonFinite = []float64{math.NaN(), math.Inf(1), math.Inf(-1)}

func TestInfKillCibaClockNeverKeepsASessionLive(t *testing.T) {
	for _, kind := range []string{"memory", "durable"} {
		for _, bad := range infKillNonFinite {
			clock := 1000.0
			now := func() float64 { return clock }
			var b CibaBroker
			if kind == "memory" {
				b = NewCibaBroker(now, func(CibaSession) {})
			} else {
				ttl := 100.0
				var err error
				if b, err = NewDurableCibaBroker(NewMemoryApprovalStore(), now, &ttl, nil); err != nil {
					t.Fatal(err)
				}
			}
			req, err := b.Start(cibaSU(), CibaRequestOptions{})
			if err != nil {
				t.Fatal(err)
			}
			clock = bad
			// -Infinity < expiresAt is true, so the old `now >= expiresAt` kept the session pending
			if st, err := b.Poll(req.AuthReqID); err != nil || st != "expired" {
				t.Fatalf("%s clock %v: status %q err %v, want expired", kind, bad, st, err)
			}
		}
	}
}

func TestInfKillAcpBoundNeverAdmitsANonFiniteValue(t *testing.T) {
	for _, bad := range infKillNonFinite {
		if !acpGt(bad, 5.0) {
			t.Errorf("acpGt(%v, 5) admitted", bad)
		}
	}
	if !acpGt(3, acpU) { // an undefined bound is NaN: it never admits
		t.Error("acpGt against an undefined bound admitted")
	}
	if acpGt(3, 5.0) || acpGt(3, math.Inf(1)) { // a finite value under a (possibly unbounded) cap stays admitted
		t.Error("acpGt refused a finite value under its cap")
	}
}

func TestInfKillAp2(t *testing.T) {
	for _, bad := range infKillNonFinite {
		if err := ap2CheckTimes("root", map[string]any{"exp": 1000.0}, bad, 60); err == nil {
			t.Errorf("exp admitted under clock %v", bad)
		}
		// +Infinity: `1000 > Inf+60` is false, so the old iat check admitted it
		if err := ap2CheckTimes("root", map[string]any{"iat": 1000.0}, bad, 60); err == nil {
			t.Errorf("iat admitted under clock %v", bad)
		}
		if err := ap2CheckTimes("root", map[string]any{"exp": 1000.0}, 1000, bad); err == nil {
			t.Errorf("exp admitted under skew %v", bad)
		}
	}
	for _, bad := range infKillNonFinite {
		if !ap2Gt(bad, jsNumber(5)) {
			t.Errorf("ap2Gt(%v, 5) admitted", bad)
		}
	}
	if !ap2Gt("x", jsNumber(5)) {
		t.Error("ap2Gt admitted a non-number")
	}
	if ap2Gt(3.0, jsNumber(5)) {
		t.Error("ap2Gt refused a value under the cap")
	}
	c := map[string]any{"type": "payment.budget", "currency": "USD", "max": 1.0}
	for _, bad := range infKillNonFinite {
		closed := map[string]any{"payment_amount": map[string]any{"currency": "USD", "amount": bad}}
		o := Ap2PaymentCheckOptions{Context: map[string]any{"totalAmount": 0.0, "totalUses": 0.0}}
		// a -Infinity cumulative spend passed `spend > maxMinor`
		if v := ap2EvaluatePayment(c, closed, o); len(v) == 0 {
			t.Errorf("budget admitted a spend of %v", bad)
		}
	}
	for _, bad := range infKillNonFinite {
		if _, err := ap2OpenExpiry(map[string]any{"periodEnd": 100000.0}, Ap2FromTermsOptions{Exp: &bad}); err == nil {
			t.Errorf("open expiry %v admitted", bad)
		}
	}
}

func TestInfKillReplayStoresRefuseANonFiniteClock(t *testing.T) {
	for _, bad := range []float64{math.NaN(), math.Inf(1)} {
		d, _ := NewInMemoryDpopReplayStore(10)
		if ok, _ := d.AddIfAbsent("k", 100, 50); !ok {
			t.Fatal("first use refused")
		}
		if ok, _ := d.AddIfAbsent("k", 100, bad); ok { // `nowSec < held` is false for NaN and +Inf: the replay was admitted
			t.Errorf("dpop replay admitted under clock %v", bad)
		}
		s, _ := NewInMemorySetReplayStore(nil)
		s.AddIfAbsent("k", 100, 50)
		if ok, _ := s.AddIfAbsent("k", 100, bad); ok {
			t.Errorf("SET replay admitted under clock %v", bad)
		}
		w := NewWebBotAuthMemoryReplayCache()
		w.Claim("k", 100, 50)
		if ok, _ := w.Claim("k", 100, bad); ok {
			t.Errorf("web bot auth replay admitted under clock %v", bad)
		}
	}
}

func TestInfKillReadAccumulatorRefusesANonFiniteCharge(t *testing.T) {
	for _, bad := range infKillNonFinite {
		a := NewWindowReadAccumulator(10, 1000)
		if a.Charge("k", 1, bad) { // a fresh window opened at the bad time and charged within the cap
			t.Errorf("charge admitted at clock %v", bad)
		}
		if a.Charge("k", bad, 5) {
			t.Errorf("charge admitted for %v units", bad)
		}
	}
}

func TestInfKillSlidingWindowRefusesANonFiniteClock(t *testing.T) {
	for _, bad := range infKillNonFinite {
		w, err := NewWalletSlidingWindow(1000)
		if err != nil {
			t.Fatal(err)
		}
		if ok, _ := w.TryAdd(bad, 5); ok { // an empty window refuses without an error, as the reference does
			t.Errorf("event recorded at clock %v", bad)
		}
		if ok, _ := w.TryAdd(10, 5); !ok {
			t.Fatal("a finite event refused")
		}
		if n := w.Count(bad); n != 1 { // +Infinity must not forget the recorded event
			t.Errorf("count under clock %v = %d, want 1", bad, n)
		}
	}
}

func TestInfKillSlidingWindowNonEmptyClocks(t *testing.T) {
	fill := func(t *testing.T) *WalletSlidingWindow {
		w, err := NewWalletSlidingWindow(1000)
		if err != nil {
			t.Fatal(err)
		}
		for _, at := range []float64{10, 20} {
			if ok, err := w.TryAdd(at, 5); !ok || err != nil {
				t.Fatalf("finite event at %v refused: %v %v", at, ok, err)
			}
		}
		return w
	}
	// A NaN or -Infinity clock on a window that already holds events is the "time went backwards" error; nothing is recorded.
	for _, bad := range []float64{math.NaN(), math.Inf(-1)} {
		w := fill(t)
		ok, err := w.TryAdd(bad, 5)
		if ok || err == nil || err.Error() != "SlidingWindowCounter: time went backwards" {
			t.Errorf("clock %v: got (%v, %v)", bad, ok, err)
		}
		if n := w.Count(15); n != 2 {
			t.Errorf("clock %v changed the window: count %d, want 2", bad, n)
		}
	}
	// +Infinity: no error, nothing recorded, nothing pruned.
	w := fill(t)
	if ok, err := w.TryAdd(math.Inf(1), 5); ok || err != nil {
		t.Errorf("+Inf clock: got (%v, %v), want (false, nil)", ok, err)
	}
	if n := w.Count(math.Inf(1)); n != 2 {
		t.Errorf("+Inf clock pruned the window: count %d, want 2", n)
	}
	// A full window refuses before the clock is examined, as in the reference.
	if ok, err := w.TryAdd(math.NaN(), 2); ok || err != nil {
		t.Errorf("full window, NaN clock: got (%v, %v), want (false, nil)", ok, err)
	}
	// A NaN cap is refused (stricter than the reference, which would admit it).
	if ok, err := fill(t).TryAdd(30, math.NaN()); ok || err != nil {
		t.Errorf("NaN cap: got (%v, %v), want (false, nil)", ok, err)
	}
}

func TestInfKillMeshCapability(t *testing.T) {
	exp := meshAuthority{hasExp: true, expiresAt: 100}
	amt := meshAuthority{hasAmount: true, maxAmount: 100}
	for _, bad := range infKillNonFinite {
		if got := meshAdmits(exp, map[string]any{}, bad, 1); !strings.Contains(got, "expired") {
			t.Errorf("capability admitted under clock %v: %q", bad, got)
		}
		if got := meshAdmits(amt, map[string]any{"amount": bad}, 0, 1); got == "" {
			t.Errorf("capability admitted an amount of %v", bad)
		}
		if meshNarrows(meshAuthority{hasAmount: true, maxAmount: bad}, amt) && !math.IsInf(bad, -1) {
			t.Errorf("a ceiling of %v narrows a ceiling of 100", bad)
		}
	}
}

func TestInfKillBudgetsNeverAdmitAnInfiniteRemaining(t *testing.T) {
	inf := TrustBudget{B: math.Inf(1)}
	if _, err := SubBudget(inf, 5); err == nil {
		t.Error("SubBudget admitted an infinite parent")
	}
	if _, _, err := DebitConsolidated(inf, TrustBudget{B: 10}, 5); err == nil {
		t.Error("DebitConsolidated admitted an infinite parent")
	}
	if _, _, err := DebitConsolidated(TrustBudget{B: 10}, inf, 5); err == nil {
		t.Error("DebitConsolidated admitted an infinite sub-agent budget")
	}
	if _, err := DebitConsolidatedPath([]TrustBudget{{B: 10}, inf}, 5); err == nil {
		t.Error("DebitConsolidatedPath admitted an infinite node")
	}
	p := RiskPolicy{Theta1: 0.3, Theta2: 0.6, Kappa: 1}
	if a := Admit(0.1, inf, p); a.Admit {
		t.Error("Admit metered an infinite budget")
	}
}

func TestInfKillStripeSignatureRefusesANonFiniteClock(t *testing.T) {
	mac := hmac.New(sha256.New, []byte("whsec"))
	mac.Write([]byte("1000.body"))
	header := "t=1000,v1=" + hex.EncodeToString(mac.Sum(nil))
	if !VerifyStripeSignature("body", header, "whsec", 1000, 300) {
		t.Fatal("a valid signature was refused")
	}
	// Abs(NaN) > tolerance is false: the old check skipped the tolerance entirely
	if VerifyStripeSignature("body", header, "whsec", math.NaN(), 300) {
		t.Error("signature admitted under a NaN clock")
	}
}

func TestInfKillExplainReportsTheEnforcedVerdict(t *testing.T) {
	p := map[string]any{"exp": 2000.0, "iat": 1000.0}
	// a NaN clock fails the enforced iat check; the old pinpoint skipped both branches and said nothing specific
	if pin := xpValidityPinpoint(p, math.NaN()); !strings.Contains(pin.detail, "in the future") {
		t.Errorf("pinpoint under a NaN clock: %q", pin.detail)
	}
}

func TestInfKillSharedPaymentTokenLimitsRefusesANonFinitePeriodEnd(t *testing.T) {
	for _, bad := range infKillNonFinite {
		m := map[string]any{
			"budget": map[string]any{"B": 1000.0},
			"terms":  map[string]any{"autoApproveThreshold": 500.0, "currency": "USD", "periodEnd": bad},
		}
		// +Infinity was emitted as expires_at: null, read as no expiry
		if _, err := SharedPaymentTokenLimits(m, 1000.0); err == nil || !strings.Contains(err.Error(), "periodEnd must be an epoch-ms time") {
			t.Errorf("periodEnd %v: err %v", bad, err)
		}
	}
}

func TestInfKillAcpSpendCapMustBeANonNegativeInteger(t *testing.T) {
	req := map[string]any{"amount": 5.0, "currency": "USD", "merchant": "m"}
	for _, bad := range []any{math.NaN(), math.Inf(1), math.Inf(-1), -1.0, math.Copysign(0, -1)} {
		// +Infinity and -Infinity (and a negative cap) were admitted as an unbounded or ill-formed cap
		r, err := AcpCheckPaymentAuthority(map[string]any{"maxAmount": bad}, req)
		if err != nil || r["ok"] != false || r["reason"] != "authorized spend cap is not a non-negative integer (fail closed)" {
			t.Errorf("cap %v: %v %v", bad, r, err)
		}
	}
	// a payment authority names its allowlists (null = unrestricted): an authority without them throws in the reference
	if r, err := AcpCheckPaymentAuthority(map[string]any{"merchants": nil, "categories": nil}, req); err != nil || r["ok"] != true {
		t.Errorf("an absent cap must stay unbounded: %v %v", r, err)
	}
	if r, _ := AcpCheckPaymentAuthority(map[string]any{"maxAmount": 5.0, "merchants": nil, "categories": nil}, req); r["ok"] != true {
		t.Errorf("a cap equal to the amount must admit: %v", r)
	}
}

func TestInfKillAp2UnknownRecurrenceFrequencyIsAViolation(t *testing.T) {
	c := map[string]any{"type": "payment.agent_recurrence", "frequency": "FORTNIGHTLY"}
	// without a last-used date the old code produced no violation
	v := ap2EvaluatePayment(c, map[string]any{}, Ap2PaymentCheckOptions{Context: map[string]any{"totalAmount": 0.0, "totalUses": 0.0}})
	if len(v) != 1 || v[0] != "unknown recurrence frequency" {
		t.Errorf("violations %v", v)
	}
}
