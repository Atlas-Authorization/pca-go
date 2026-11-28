package pca

import (
	"math"
	"math/big"
	"strings"
	"testing"
)

// Kill tests for the sites that follow the reference's final non-finite behaviour: the server layer (stale operation
// settlement, execution recheck, undo effect timeout), the agent envelope, bonds, DLP, calibration, stream health,
// revocation age, sandbox handles, ACP and AP2 caps, and the clock and tolerance options of the token verifiers.

func TestInfKillSettleStaleNegativeTimeoutNeverSettles(t *testing.T) {
	rec := OperationRecord{ID: "op", State: OpPending, StartedAt: 0}
	// a negative timeout used to age every record (and write to the store); it now leaves the record untouched
	got, err := settleStale(nil, rec, 1_000_000, -1)
	if err != nil || got.State != OpPending {
		t.Fatalf("a negative timeout settled the record: %+v %v", got, err)
	}
}

func TestInfKillExecuteAuthorizedRecheckRefusesANonFinitePCActnExpiry(t *testing.T) {
	for _, bad := range infKillNonFinite {
		az := AuthorizeResult{Allow: true,
			Operation: &AuthorizedOperation{ID: "op1", Verb: "v", Resource: "r", ParamsDigest: "d"},
			PCActn:    map[string]any{"exp": bad}}
		ran := false
		o := ExecuteAuthorized(az, func(ExecutionHandle) (any, error) { ran = true; return "x", nil }, ExecuteOptions{
			Store:      NewMemoryOperationStore(),
			RecheckFor: "always",
			Recheck:    func(ExecutionHandle) (RecheckResult, error) { return RecheckResult{OK: true}, nil },
			Now:        func() int64 { return 1000 },
		})
		// +Infinity and NaN never compared as expired: the operation ran
		if ran || o.Status != "aborted" || !strings.Contains(o.Reason, "the PCActn expired at") {
			t.Errorf("exp %v: ran=%v %+v", bad, ran, o)
		}
	}
}

type infKillEngine struct{ UndoEngine }

type infKillNotifier struct{}

func (infKillNotifier) Notify(UndoNotice) (bool, string) { return true, "" }

func TestInfKillUndoCoordinatorRefusesANegativeEffectTimeout(t *testing.T) {
	mk := func(timeout int64) error {
		_, err := CreateUndoCoordinator(UndoCoordinatorOptions{
			Store: NewMemoryUndoStore(), InsecureVolatileStore: true, Engine: infKillEngine{},
			SignerSecret: make([]byte, 32), Audience: "a",
			ResolveGrant: func(string, map[string]any) (map[string]any, error) { return nil, nil },
			Compensate:   func(UndoCompensationCall) (any, error) { return nil, nil },
			Operations:   NewMemoryOperationStore(), Notifier: infKillNotifier{}, Alert: func(UndoAlert) {},
			EffectTimeoutMs: timeout,
		})
		return err
	}
	if err := mk(-1); err == nil || !strings.Contains(err.Error(), "effectTimeoutMs must be a non-negative number") {
		t.Fatalf("a negative effect timeout was accepted: %v", err)
	}
	if err := mk(0); err != nil {
		t.Fatalf("the default timeout was refused: %v", err)
	}
	if err := mk(1000); err != nil {
		t.Fatalf("a positive timeout was refused: %v", err)
	}
}

func TestInfKillEnvelopePermitsRefusesAHintThatIsNotFinite(t *testing.T) {
	env := func(k string, v any) map[string]any {
		return map[string]any{"ok": true, "unsatisfiable": []any{}, "remainingBudgetHints": map[string]any{k: v}}
	}
	now := 1000.0
	params := map[string]any{"amount": 5.0}
	for _, bad := range infKillNonFinite {
		// a present hint that is not a finite number used to be skipped, so the envelope permitted the action
		if EnvelopePermits(env("delegationDepthRemaining", bad), "v", "r", &now, nil) {
			t.Errorf("delegationDepthRemaining %v permitted", bad)
		}
		if EnvelopePermits(env("expiresAt", bad), "v", "r", &now, nil) {
			t.Errorf("expiresAt %v permitted", bad)
		}
		if EnvelopePermits(env("notBefore", bad), "v", "r", &now, nil) {
			t.Errorf("notBefore %v permitted", bad)
		}
	}
	if EnvelopePermits(env("maxSpendUsd", math.NaN()), "v", "r", &now, params) {
		t.Error("a NaN spend ceiling permitted")
	}
	if !EnvelopePermits(env("maxSpendUsd", math.Inf(1)), "v", "r", &now, params) { // an infinite ceiling is the unbounded one
		t.Error("an unbounded spend ceiling refused")
	}
	if !EnvelopePermits(env("expiresAt", 2000.0), "v", "r", &now, nil) {
		t.Error("a live envelope refused")
	}
}

type infKillBondView struct{ bal, count, sum float64 }

func (infKillBondView) Bond(string) map[string]any            { return nil }
func (v infKillBondView) BalanceOf(string) float64            { return v.bal }
func (v infKillBondView) OpenTotals(string) (float64, float64) { return v.count, v.sum }

func TestInfKillBondsRefuseNonFiniteBalancesAndTotals(t *testing.T) {
	for _, bad := range infKillNonFinite {
		for _, op := range []string{"credit", "debit"} {
			_, err := ApplyBondMoves(func(string) float64 { return bad }, []BondMove{{Account: "a", Op: op, Amount: 1}})
			// an infinite or NaN balance was carried through a credit and compared false on a debit
			if err == nil || !strings.Contains(err.Error(), "balance of a is not finite") {
				t.Errorf("%s over balance %v: %v", op, bad, err)
			}
		}
	}
	key, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pl, err := NewBondSettlementPlanner(BondPlannerOptions{Guardian: key})
	if err != nil {
		t.Fatal(err)
	}
	win := &BondRegistration{RegisteredAt: 0, WindowMs: 1000, ClaimDigest: "d"}
	for _, bad := range infKillNonFinite {
		// balance: +Infinity and NaN compared as enough
		if _, err := pl.PlanOpen(infKillBondView{bal: bad}, "c1", 10, "dep", 0, 0, win); err == nil || !strings.Contains(err.Error(), "insufficient balance") {
			t.Errorf("balance %v: %v", bad, err)
		}
		// open claims: NaN compared as under the cap
		if _, err := pl.PlanOpen(infKillBondView{bal: 100, count: bad}, "c1", 10, "dep", 0, 0, win); err == nil || !strings.Contains(err.Error(), "open-claim cap") {
			t.Errorf("count %v: %v", bad, err)
		}
		// open amount: the default policy has an infinite cap, and Infinity <= Infinity admitted an infinite total
		if _, err := pl.PlanOpen(infKillBondView{bal: 100, sum: bad}, "c1", 10, "dep", 0, 0, win); err == nil || !strings.Contains(err.Error(), "aggregate open-bond cap") {
			t.Errorf("sum %v: %v", bad, err)
		}
	}
}

func TestInfKillDlpRefusesANonFiniteTaintUnderAnUnboundedCeiling(t *testing.T) {
	policy := map[string]any{"classes": []any{map[string]any{"name": "pii", "resource": "db:*", "maxTaintForAuto": math.Inf(1), "hardDenyAbove": math.Inf(1)}}}
	for _, bad := range infKillNonFinite {
		// the taint reads as +Infinity, and Infinity > Infinity is false: the flow was allowed
		r, err := EvaluateDlp(policy, map[string]any{"verb": "read", "resource": "db:users", "taint": bad})
		if err != nil || r["outcome"] != "deny" {
			t.Errorf("taint %v: %v %v", bad, r, err)
		}
	}
	r, _ := EvaluateDlp(policy, map[string]any{"verb": "read", "resource": "db:users", "taint": 3.0})
	if r["outcome"] != "allow" {
		t.Errorf("a finite taint under an unbounded ceiling: %v", r)
	}
}

func TestInfKillVdfCalibrationRefusesANonFiniteClockReading(t *testing.T) {
	n := big.NewInt(1000003)
	for _, bad := range infKillNonFinite {
		for _, at := range []int{0, 1} {
			calls := 0
			clock := func() float64 {
				calls++
				if calls-1 == at {
					return bad
				}
				return 5
			}
			// a NaN gave NaN steps; an infinite elapsed time gave one step
			if _, err := VdfCalibrateSteps(n, 1, 10, 1, clock); err == nil || !strings.Contains(err.Error(), "finite times") {
				t.Errorf("reading %d = %v: %v", at, bad, err)
			}
		}
	}
}

func TestInfKillFhePlaintextVerdictAdmitsNothingUnderANonFiniteBudget(t *testing.T) {
	inputs := map[string]any{"semanticDistance": 0.5, "reversibility": 0.5, "blastRadius": 0.5, "taint": 0.5, "confidence": 0.5, "age": 0.5}
	core := map[string]any{"weights": map[string]any{"alpha": 1.0, "beta": 1.0, "gamma": 1.0, "delta": 1.0, "epsilon": 1.0, "zeta": 1.0}, "kappa": 1.0}
	for _, bad := range infKillNonFinite {
		r, err := FhePlaintextVerdict(inputs, core, bad)
		if err != nil || r["admit"] != false {
			t.Errorf("budget %v: %v %v", bad, r, err)
		}
	}
	if r, err := FhePlaintextVerdict(inputs, core, 10.0); err != nil || r["admit"] != true {
		t.Errorf("a finite budget refused: %v %v", r, err)
	}
}

func TestInfKillMcpStepUpGivesUpOnANonFiniteAttemptCount(t *testing.T) {
	for _, bad := range infKillNonFinite {
		// -Infinity and NaN compared as under the limit: the step-up retried forever
		r, err := McpPlanStepUp(403, `Bearer error="insufficient_scope", scope="read"`, map[string]any{"requested": []any{}, "attempts": bad})
		if err != nil || r["action"] != "give_up" || r["reason"] != "retry_limit" {
			t.Errorf("attempts %v: %v %v", bad, r, err)
		}
	}
}

func TestInfKillOptimisticWindowPolicyBoundsReadAsTheNegation(t *testing.T) {
	ok := ChallengeWindowPolicy{MinWindowMs: 1, MaxWindowMs: 100000, MaxSkewMs: 5000}
	if why := ValidateWindow(1000, 1000, 1000, ok); why != "" {
		t.Fatalf("control refused: %q", why)
	}
	for name, p := range map[string]ChallengeWindowPolicy{
		"skew": {MinWindowMs: 1, MaxWindowMs: 100000, MaxSkewMs: math.NaN()},
		"min":  {MinWindowMs: math.NaN(), MaxWindowMs: 100000, MaxSkewMs: 5000},
		"max":  {MinWindowMs: 1, MaxWindowMs: math.NaN(), MaxSkewMs: 5000},
	} {
		// a NaN bound compared false on the refusing side and admitted any window
		if why := ValidateWindow(1000, 1000, 1000, p); why == "" {
			t.Errorf("a NaN %s bound admitted the window", name)
		}
	}
	if why := ValidateWindow(1000, 1000, 1000, ChallengeWindowPolicy{MinWindowMs: 1, MaxWindowMs: math.Inf(1), MaxSkewMs: math.Inf(1)}); why != "" {
		t.Errorf("an unbounded policy refused: %q", why)
	}
}

func TestInfKillStreamHealthRefusesANonFiniteClockOrTimeout(t *testing.T) {
	for _, bad := range infKillNonFinite {
		h := NewStreamHealth(map[string]any{}, nil)
		if st := h.RequestVerification(bad); st != "" {
			t.Errorf("verification requested at clock %v", bad)
		}
		state := h.RequestVerification(100)
		if state == "" {
			t.Fatal("a finite clock was refused")
		}
		if h.AckVerification(state, bad) { // NaN expired nothing, so the state acknowledged
			t.Errorf("verification acknowledged at clock %v", bad)
		}
		if !h.AckVerification(state, 100) {
			t.Fatal("a finite acknowledgement was refused")
		}
		if r := h.Report(bad); r.State == "healthy" { // -Infinity and NaN never aged the last round trip
			t.Errorf("healthy at clock %v", bad)
		}
		if h.RevocationFreshWithin(300, bad) {
			t.Errorf("revocation fresh at clock %v", bad)
		}
	}
	// an infinite timeout would leave the request pending forever
	h := NewStreamHealth(map[string]any{}, &StreamHealthOptions{VerifyTimeoutSec: math.Inf(1)})
	if st := h.RequestVerification(100); st != "" {
		t.Error("a verification with an infinite timeout was issued")
	}
}

func TestInfKillRevocationAgeRefusesANonFiniteClock(t *testing.T) {
	issued := 1000.0
	for _, bad := range infKillNonFinite {
		// +Infinity under an unbounded maximum age passed both comparisons
		r := CheckRevocationAge(&issued, bad, math.Inf(1), "")
		if r.OK || !strings.Contains(r.Reason, "cannot be aged: the clock is not a finite number") {
			t.Errorf("clock %v: %+v", bad, r)
		}
	}
	if r := CheckRevocationAge(&issued, 2000, 5000, ""); !r.OK {
		t.Errorf("a fresh state refused: %+v", r)
	}
}

func TestInfKillSandboxHandleRefusesANonFiniteClock(t *testing.T) {
	clock := 0.0
	log := NewSandboxReceiptLog(func() float64 { return 0 }, nil)
	table := NewHandleTable("wasi_no_ambient", log, nil, func() float64 { return clock })
	params := map[string]any{"url": "https://example.com/a"}
	d, _ := HashCanonical(params)
	op := map[string]any{"verb": "http.get", "resource": "r", "params": params}
	res := map[string]any{"allow": true, "operation": map[string]any{"verb": "http.get", "resource": "r", "params_digest": d, "id": "op1"}}
	idx, err := table.Mint(res, op, map[string]any{"uses": 5})
	if err != nil {
		t.Fatal(err)
	}
	if table.live(idx) == nil {
		t.Fatal("a live handle was refused")
	}
	for _, bad := range infKillNonFinite {
		clock = bad
		if table.live(idx) != nil { // -Infinity is before every expiry
			t.Errorf("handle live at clock %v", bad)
		}
	}
}

func TestInfKillGatewayReplayGuardRefusesANonFiniteClockOrExpiry(t *testing.T) {
	for _, bad := range infKillNonFinite {
		g := GatewayMemoryReplayGuard(10, nil)
		now := 1000.0
		if ok, err := g.Claim("k", 2000, &now); !ok || err != nil {
			t.Fatalf("a first claim was refused: %v %v", ok, err)
		}
		if ok, err := g.Claim("k2", bad, &now); ok || err == nil { // an infinite expiry never lapses
			t.Errorf("claim with expiry %v: %v %v", bad, ok, err)
		}
		if ok, err := g.Claim("k3", 2000, &bad); ok || err == nil { // -Infinity never reads as past the first claim's expiry
			t.Errorf("claim at clock %v: %v %v", bad, ok, err)
		}
	}
}

func TestInfKillAcpSptWithinClaimsNeedsFiniteDelegatedLimits(t *testing.T) {
	tok := func() map[string]any {
		return map[string]any{"object": AcpStripeSptObject, "id": "spt_abc", "created": 1.0, "livemode": false, "deactivated_at": nil, "deactivated_reason": nil,
			"usage_limits": map[string]any{"currency": "usd", "max_amount": 5.0, "expires_at": 100.0}}
	}
	if r, err := AcpStripeSptWithinClaims(tok(), map[string]any{"amount": 10.0, "currency": "usd", "exp": 200000.0}); err != nil || r["ok"] != true {
		t.Fatalf("control refused: %v %v", r, err)
	}
	for _, bad := range infKillNonFinite {
		// an infinite delegated amount or expiry used to be an unbounded bound that every token fit under
		for name, claims := range map[string]map[string]any{
			"amount": {"amount": bad, "currency": "usd", "exp": 200000.0},
			"exp":    {"amount": 10.0, "currency": "usd", "exp": bad},
		} {
			if r, err := AcpStripeSptWithinClaims(tok(), claims); err != nil || r["ok"] != false {
				t.Errorf("delegated %s %v: %v %v", name, bad, r, err)
			}
		}
	}
}

func TestInfKillAcpNullSpendCapIsPresentAndRefused(t *testing.T) {
	req := map[string]any{"amount": 5.0, "currency": "USD", "merchant": "m"}
	// null is a present cap that is not a number: refused with the cap message, not read as zero
	r, err := AcpCheckPaymentAuthority(map[string]any{"maxAmount": nil}, req)
	if err != nil || r["ok"] != false || r["reason"] != "authorized spend cap is not a non-negative integer (fail closed)" {
		t.Errorf("a null cap: %v %v", r, err)
	}
}

func TestInfKillAp2AmountRangeRefusesANonFiniteAmount(t *testing.T) {
	c := map[string]any{"type": "payment.amount_range", "currency": "USD", "min": 1.0, "max": 100.0}
	for _, bad := range infKillNonFinite {
		closed := map[string]any{"payment_amount": map[string]any{"currency": "USD", "amount": bad}}
		// NaN compared false against both bounds
		v := ap2EvaluatePayment(c, closed, Ap2PaymentCheckOptions{})
		found := false
		for _, m := range v {
			found = found || strings.HasSuffix(m, "is not finite")
		}
		if !found {
			t.Errorf("amount %v: %v", bad, v)
		}
	}
}

func TestInfKillIntentProfileAppliesNeedsAFiniteClockAndExpiry(t *testing.T) {
	// an infinite expiry or a -Infinity clock used to satisfy `now < expires_at` and fall through to the scope checks
	for _, bad := range infKillNonFinite {
		if ixProfileApplies(map[string]any{"expires_at": bad}, map[string]any{"now": 1000.0}) {
			t.Errorf("profile applied with expiry %v", bad)
		}
		if ixProfileApplies(map[string]any{"expires_at": 5000.0}, map[string]any{"now": bad}) {
			t.Errorf("profile applied at clock %v", bad)
		}
	}
}

func TestInfKillCaveatDeriveCountNeedsASafeIntegerClock(t *testing.T) {
	d := map[string]any{"window_ms": 1000.0}
	for _, bad := range []float64{1e300, 1.5, math.NaN(), math.Inf(1), math.Inf(-1)} {
		// a finite clock that is not a safe integer counted as zero events and allowed the rate
		if n := clCount(d, DeriveInput{History: []any{}, Now: bad}); n != nil {
			t.Errorf("clock %v counted: %v", bad, n)
		}
	}
	if n := clCount(d, DeriveInput{History: []any{}, Now: 5000}); n != 0.0 {
		t.Errorf("a safe clock did not count: %v", n)
	}
}

func TestInfKillSpiffeJwtSvidRefusesANonFiniteClockTolerance(t *testing.T) {
	for _, bad := range append(infKillNonFinite, -1.0) {
		_, err := VerifyJwtSvid("a.b.c", VerifyJwtSvidOptions{TrustDomain: "example.org", Audience: []string{"aud"}, ClockTolerance: bad})
		if err == nil || !strings.Contains(err.Error(), "clockTolerance must be a finite number >= 0") {
			t.Errorf("tolerance %v: %v", bad, err)
		}
	}
}

func TestInfKillTxnTokenRefusesANonFiniteToleranceOrClock(t *testing.T) {
	key := make([]byte, 32)
	for _, bad := range append(infKillNonFinite, -1.0) {
		_, err := FromTransactionToken("a.b.c", key, TxnVerifyOptions{Profile: "legacy", ReplayUnchecked: true, ClockToleranceSec: bad})
		if err == nil || !strings.Contains(err.Error(), "clockToleranceSec must be a finite number >= 0") {
			t.Errorf("tolerance %v: %v", bad, err)
		}
	}
	for _, bad := range infKillNonFinite {
		now := bad
		_, err := FromTransactionToken("a.b.c", key, TxnVerifyOptions{Profile: "legacy", ReplayUnchecked: true, NowSec: &now})
		if err == nil || !strings.Contains(err.Error(), "now must be a valid Date") {
			t.Errorf("clock %v: %v", bad, err)
		}
	}
}

func TestInfKillOidcOptionsRefuseANonFiniteToleranceAndAcceptAnUnboundedAge(t *testing.T) {
	aud := "client"
	for _, bad := range append(infKillNonFinite, -1.0) {
		v := bad
		_, err := VerifyIdToken("x", VerifyIdTokenOptions{Issuer: "https://i", Audience: &aud, ClockToleranceSec: &v})
		if err == nil || !strings.Contains(err.Error(), "clockToleranceSec must be a finite number >= 0") {
			t.Errorf("tolerance %v: %v", bad, err)
		}
	}
	for _, bad := range []float64{math.NaN(), -1} {
		v := bad
		_, err := VerifyIdToken("x", VerifyIdTokenOptions{Issuer: "https://i", Audience: &aud, MaxTokenAgeSec: &v})
		if err == nil || !strings.Contains(err.Error(), "maxTokenAgeSec must be a number >= 0") {
			t.Errorf("age limit %v: %v", bad, err)
		}
	}
	inf := math.Inf(1) // an infinite age limit is the unbounded one: the option is accepted and the token fails later
	if _, err := VerifyIdToken("x", VerifyIdTokenOptions{Issuer: "https://i", Audience: &aud, MaxTokenAgeSec: &inf}); err == nil || strings.Contains(err.Error(), "maxTokenAgeSec must be") {
		t.Errorf("an infinite age limit was refused as configuration: %v", err)
	}
}
