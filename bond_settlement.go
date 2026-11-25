package pca

// Bond settlement: the money side of the optimistic path. A bond is collateral moved into escrow when a claim opens; it is
// released back after the challenge window or slashed on verified fraud, and every movement is a guardian-signed SettlementRecord.
// This file holds the exact money arithmetic (micro-unit grid), the slash split, bond sizing, the evidence digests, the record
// checks and commitments, the planner that turns a request into a signed plan, and the insurance capital pool. Records, splits,
// plans and verdicts are JSON objects (map[string]any) with the reference's member names, so they cross the wire unchanged.

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
)

const (
	// EscrowAccount is the default account open bonds are held in.
	EscrowAccount = "escrow"
	// CompensationPoolAccount is the default account the victim share of a slash is paid to.
	CompensationPoolAccount = "pca:pool:compensation"
	// MicrosPerUnit is the money grid: amounts with at most six decimals are computed exactly in micro-units.
	MicrosPerUnit = 1_000_000
	// SettlementLeafDomain separates a settlement record's ledger leaf digest.
	SettlementLeafDomain = "atlas-pca/settlement-leaf/v1"

	bsMaxSafeMicros   = 1e15
	bsMinShareQuantum = 1.0 / (1 << 30)
)

// SlashSplitPolicy is how a slashed bond is shared, in basis points: the challenger's reward and the victim's compensation; the
// rest goes to the treasury. Each is an integer in [0, 10000] and their sum is at most 10000.
type SlashSplitPolicy struct{ ChallengerBps, VictimBps float64 }

// DefaultSlashSplitPolicy is 50% to the challenger, 40% to the victim pool, 10% to the treasury.
var DefaultSlashSplitPolicy = SlashSplitPolicy{ChallengerBps: 5000, VictimBps: 4000}

func bsFinite(x float64) bool { return !math.IsNaN(x) && !math.IsInf(x, 0) }

func bsIsInt(x float64) bool { return bsFinite(x) && x == math.Trunc(x) }

func bsNum(f float64) any { return rsN(f) }

func (p SlashSplitPolicy) check() error {
	for _, kv := range []struct {
		k string
		v float64
	}{{"challengerBps", p.ChallengerBps}, {"victimBps", p.VictimBps}} {
		if !bsIsInt(kv.v) || kv.v < 0 || kv.v > 10_000 {
			return fmt.Errorf("slash split: %s must be an integer in [0,10000]", kv.k)
		}
	}
	if p.ChallengerBps+p.VictimBps > 10_000 {
		return errors.New("slash split: challengerBps + victimBps must not exceed 10000")
	}
	return nil
}

// ToMicros converts an amount to whole micro-units; ok is false for a negative, non-finite, too large or genuinely sub-micro
// amount (one that is not on the micro grid).
func ToMicros(x float64) (micros int64, ok bool) {
	if !bsFinite(x) || x < 0 {
		return 0, false
	}
	scaled := float64(x * MicrosPerUnit)
	if scaled > bsMaxSafeMicros {
		return 0, false
	}
	r := math.Round(scaled)
	if r/MicrosPerUnit != x && math.Abs(scaled-r) > 1e-3 {
		return 0, false
	}
	return int64(r), true
}

// FromMicros converts micro-units back to an amount.
func FromMicros(m int64) float64 { return float64(m) / MicrosPerUnit }

// QuantizeUp rounds a positive amount up to the micro grid (an amount already on the grid is unchanged); a non-positive,
// non-finite or too large amount is returned as it is.
func QuantizeUp(x float64) float64 {
	if !bsFinite(x) || x <= 0 {
		return x
	}
	scaled := float64(x * MicrosPerUnit)
	if scaled > bsMaxSafeMicros {
		return x
	}
	r := math.Round(scaled)
	m := math.Ceil(scaled)
	if r/MicrosPerUnit == x || math.Abs(scaled-r) <= 1e-3 {
		m = r
	}
	return m / MicrosPerUnit
}

func bsShareMicros(micros int64, bps float64) int64 {
	v := new(big.Int).Mul(big.NewInt(micros), big.NewInt(int64(bps)))
	return v.Div(v, big.NewInt(10_000)).Int64()
}

func bsUlpOf(x float64) float64 {
	e := math.Floor(math.Log2(x))
	if math.Ldexp(1, int(e)) > x {
		e--
	} else if math.Ldexp(1, int(e)+1) <= x {
		e++
	}
	return math.Ldexp(1, int(math.Max(e-52, -1074)))
}

func bsShareQuantum(amount float64) float64 {
	u := bsUlpOf(amount)
	if bsIsInt(amount) {
		return math.Max(1, u)
	}
	return math.Max(bsMinShareQuantum, u)
}

func bsShareOf(amount, bps, quantum float64) float64 {
	return math.Floor((amount*bps)/10_000/quantum) * quantum
}

// ComputeSlashSplit shares a slashed bond between the challenger, the victim pool and the treasury: {amount, challengerReward,
// victimCompensation, treasuryRemainder, challengerAccount, victimAccount, treasuryAccount}. The three shares always sum to the
// amount exactly (the treasury takes the remainder and the rounding dust). With no challenger (nil) the whole bond goes to the
// treasury. A fractional amount on the micro grid is split in exact micro-units; a whole amount keeps whole-unit shares.
func ComputeSlashSplit(amount float64, policy SlashSplitPolicy, challengerAccount *string, victimAccount, treasuryAccount string) (map[string]any, error) {
	if !bsFinite(amount) || amount <= 0 {
		return nil, errors.New("computeSlashSplit: amount must be a positive finite number")
	}
	if err := policy.check(); err != nil {
		return nil, err
	}
	if victimAccount == "" {
		return nil, errors.New("computeSlashSplit: victimAccount is required")
	}
	if treasuryAccount == "" {
		return nil, errors.New("computeSlashSplit: treasuryAccount is required")
	}
	out := func(a, c, v, t float64) map[string]any {
		m := map[string]any{"amount": bsNum(a), "challengerReward": bsNum(c), "victimCompensation": bsNum(v), "treasuryRemainder": bsNum(t),
			"challengerAccount": nil, "victimAccount": victimAccount, "treasuryAccount": treasuryAccount}
		if challengerAccount != nil {
			m["challengerAccount"] = *challengerAccount
		}
		return m
	}
	if challengerAccount == nil {
		return out(amount, 0, 0, amount), nil
	}
	if !bsIsInt(amount) { // whole bonds keep whole-unit shares (already exact)
		if micros, ok := ToMicros(amount); ok {
			c := bsShareMicros(micros, policy.ChallengerBps)
			v := bsShareMicros(micros, policy.VictimBps)
			return out(FromMicros(micros), FromMicros(c), FromMicros(v), FromMicros(micros-c-v)), nil
		}
	}
	q := bsShareQuantum(amount)
	c := math.Min(bsShareOf(amount, policy.ChallengerBps, q), amount)
	v := math.Min(bsShareOf(amount, policy.VictimBps, q), amount-c)
	return out(amount, c, v, amount-c-v), nil
}

// bsPut copies src[from] to dst[to] when it is present (an absent member stays absent, as in the reference's canonical form).
func bsPut(dst map[string]any, to string, src map[string]any, from string) {
	if v, ok := src[from]; ok {
		dst[to] = v
	}
}

func bsOrNull(m map[string]any, k string) any { return m[k] }

// SettlementEvidenceDigest binds a fraud slash to its evidence: the claim, the verdict and the verdict's reason.
func SettlementEvidenceDigest(claim, fraudVerdict map[string]any) (string, error) {
	b := map[string]any{"slashBondRef": bsOrNull(fraudVerdict, "slashBondRef")}
	bsPut(b, "claimDigest", claim, "pcactn_digest")
	bsPut(b, "bond_ref", claim, "bond_ref")
	bsPut(b, "fraudulent", fraudVerdict, "fraudulent")
	bsPut(b, "reason", fraudVerdict, "reason")
	return HashCanonicalLenient(b)
}

// RevocationEvidenceDigest binds a slash to the revoked capability that caused it.
func RevocationEvidenceDigest(claim map[string]any, revokedCapID string) (string, error) {
	b := map[string]any{"kind": "revocation", "revokedCapId": revokedCapID}
	bsPut(b, "claimDigest", claim, "pcactn_digest")
	bsPut(b, "bond_ref", claim, "bond_ref")
	return HashCanonicalLenient(b)
}

// DisputeEvidenceDigest binds a slash to an adjudicated dispute verdict.
func DisputeEvidenceDigest(claim, verdict map[string]any) (string, error) {
	b := map[string]any{"kind": "dispute", "agentValue": bsOrNull(verdict, "agentValue"), "oracleValue": bsOrNull(verdict, "oracleValue"),
		"slashBondRef": bsOrNull(verdict, "slashBondRef")}
	bsPut(b, "claimDigest", claim, "pcactn_digest")
	bsPut(b, "bond_ref", claim, "bond_ref")
	bsPut(b, "outcome", verdict, "outcome")
	bsPut(b, "input", verdict, "input")
	bsPut(b, "reason", verdict, "reason")
	return HashCanonicalLenient(b)
}

// VerifySettlement checks the guardian signature of a settlement record (over the record without sig / pq_sig). A post-quantum or
// hybrid record needs a pin {guardian: pq public key} equal to its pq_pk. Never panics; anything malformed is false.
func VerifySettlement(record any, guardianPublic string, pins ...map[string]string) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	r, isMap := record.(map[string]any)
	if !isMap {
		return false
	}
	if _, isStr := r["sig"].(string); !isStr {
		return false
	}
	_, hasAlg := r["alg"]
	su, known := resolveSigAlg(r["alg"], hasAlg)
	if !known {
		return false
	}
	body := make(map[string]any, len(r))
	for k, v := range r {
		if k != "sig" && k != "pq_sig" {
			body[k] = v
		}
	}
	if !su.needsPqPk {
		good, _ := extSignedLenient(guardianPublic, settlementDomain, body, r["sig"])
		return good
	}
	c, canon := canonicalLenient(body)
	pk, isStr := r["pq_pk"].(string)
	pin, pinned := extPinsOf(pins).m[guardianPublic]
	if !canon || !isStr || pk == "" || !pinned || pin != pk {
		return false
	}
	return verifyLeafSuite(r["alg"], true, guardianPublic, callerVouchedPqKey(pk), append([]byte(settlementDomain), c...), r["sig"], r["pq_sig"])
}

// SettlementRecordDigest is the domain-separated digest of a settlement record (signature included).
func SettlementRecordDigest(record map[string]any) (string, error) {
	return HashCanonicalLenient(map[string]any{"t": SettlementLeafDomain, "record": record})
}

// SettlementCommit is the salted ledger commitment of a settlement record; the salt must not be empty.
func SettlementCommit(salt string, record map[string]any) (string, error) {
	if salt == "" {
		return "", errors.New("settlementCommit: salt must be a non-empty string")
	}
	d, err := SettlementRecordDigest(record)
	if err != nil {
		return "", err
	}
	return HashCanonicalLenient(map[string]any{"salt": salt, "settlement_digest": d})
}

// VerifySettlementCommit reports whether commit opens to record under salt.
func VerifySettlementCommit(commit, salt string, record map[string]any) bool {
	c, err := SettlementCommit(salt, record)
	return err == nil && c == commit
}

// SettlementLog is the append side of a transparency log (MerkleLog and StoredLedger's anchor form satisfy it).
type SettlementLog interface {
	AppendCommitment(commit string) (int, error)
}

// SettlementAnchor is where a settlement record was anchored: the leaf index, the commitment and the salt that opens it.
type SettlementAnchor struct {
	Index  int
	Commit string
	Salt   string
}

// AppendSettlement anchors a settlement record in a transparency log as a salted commitment (salt "" draws 16 random bytes), so
// the log proves the settlement happened without revealing it.
func AppendSettlement(log SettlementLog, record map[string]any, salt string) (SettlementAnchor, error) {
	if salt == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return SettlementAnchor{}, err
		}
		salt = b64.EncodeToString(b)
	}
	commit, err := SettlementCommit(salt, record)
	if err != nil {
		return SettlementAnchor{}, err
	}
	i, err := log.AppendCommitment(commit)
	if err != nil {
		return SettlementAnchor{}, err
	}
	return SettlementAnchor{Index: i, Commit: commit, Salt: salt}, nil
}

// BondTier is one tier of a piecewise bond curve: exposure up to UpTo is charged at MarginalK.
type BondTier struct{ UpTo, MarginalK float64 }

// BondCurve shapes the exposure component of the required bond: Kind "linear" (k*e), "power" (k*e^Gamma, Gamma >= 1) or
// "piecewise" (convex tiers with non-decreasing marginal rates).
type BondCurve struct {
	Kind  string
	Gamma float64
	Tiers []BondTier
}

// BondPolicy sizes and caps bonds: the required bond is max(Floor, curve(K, exposure)) rounded up to the micro grid; a depositor
// may hold at most MaxOpenClaims open bonds worth MaxOpenAmount in total.
type BondPolicy struct {
	Floor, K                     float64
	MaxOpenClaims, MaxOpenAmount float64
	Curve                        *BondCurve
}

// DefaultBondPolicy is a floor of 1, linear in the exposure, at most 100 open claims and no aggregate cap.
var DefaultBondPolicy = BondPolicy{Floor: 1, K: 1, MaxOpenClaims: 100, MaxOpenAmount: math.Inf(1)}

func bsCurve(curve *BondCurve, k, e float64) (float64, error) {
	if curve == nil || curve.Kind == "linear" {
		return k * e, nil
	}
	if curve.Kind == "power" {
		if !(bsFinite(curve.Gamma) && curve.Gamma >= 1) {
			return 0, errors.New("bondAmount: power curve requires finite gamma >= 1")
		}
		r, err := bsPowEighths(e, curve.Gamma)
		if err != nil {
			return 0, err
		}
		return float64(k * r), nil
	}
	if len(curve.Tiers) == 0 {
		return 0, errors.New("bondAmount: piecewise curve requires at least one tier")
	}
	acc, prevUpTo, prevMarginal := 0.0, 0.0, 0.0
	for _, tier := range curve.Tiers {
		if !(bsFinite(tier.UpTo) && tier.UpTo > prevUpTo) && !math.IsInf(tier.UpTo, 1) {
			return 0, errors.New("bondAmount: piecewise tier `upTo` must be strictly increasing")
		}
		if !(bsFinite(tier.MarginalK) && tier.MarginalK >= 0) {
			return 0, errors.New("bondAmount: piecewise `marginalK` must be a finite number >= 0")
		}
		if tier.MarginalK < prevMarginal {
			return 0, errors.New("bondAmount: piecewise marginal rates must be non-decreasing (convex)")
		}
		if width := math.Min(e, tier.UpTo) - prevUpTo; width > 0 {
			acc += float64(width * tier.MarginalK)
		}
		prevUpTo, prevMarginal = tier.UpTo, tier.MarginalK
		if e <= tier.UpTo {
			break
		}
	}
	if e > prevUpTo { // beyond the last tier: extend its marginal rate
		acc += float64((e - prevUpTo) * prevMarginal)
	}
	return k * acc, nil
}

// BondAmount is the bond a policy requires for an exposure (a non-finite or negative exposure counts as 0).
func BondAmount(policy BondPolicy, exposure float64) (float64, error) {
	e := 0.0
	if bsFinite(exposure) && exposure > 0 {
		e = exposure
	}
	c, err := bsCurve(policy.Curve, policy.K, e)
	if err != nil {
		return 0, err
	}
	return QuantizeUp(bsJsMax(policy.Floor, c)), nil
}

// bsJsMax is Math.max of two numbers (NaN if either is NaN).
func bsJsMax(a, b float64) float64 {
	if math.IsNaN(a) || math.IsNaN(b) {
		return math.NaN()
	}
	return math.Max(a, b)
}

// ExactAdd is a + sign*b (sign 1 or -1) computed in exact micro-units when both amounts are on the micro grid, in floating point
// otherwise.
func ExactAdd(a, b float64, sign int) float64 {
	ma, okA := ToMicros(a)
	mb, okB := ToMicros(b)
	if !okA || !okB {
		return a + float64(float64(sign)*b)
	}
	if sign == 1 {
		return FromMicros(ma + mb)
	}
	return FromMicros(ma - mb)
}

// BondMove is one balance movement of a plan: Op is "debit" or "credit".
type BondMove struct {
	Account, Op string
	Amount      float64
}

func bsMovesJSON(moves []BondMove) []any {
	out := make([]any, len(moves))
	for i, m := range moves {
		out[i] = map[string]any{"account": m.Account, "op": m.Op, "amount": bsNum(m.Amount)}
	}
	return out
}

// bsMovesOf reads the moves of a plan (a JSON array of {account, op, amount}); a malformed amount is NaN and is refused when applied.
func bsMovesOf(v any) []BondMove {
	list, _ := v.([]any)
	out := make([]BondMove, 0, len(list))
	for _, x := range list {
		m, _ := x.(map[string]any)
		acct, _ := m["account"].(string)
		op, _ := m["op"].(string)
		out = append(out, BondMove{Account: acct, Op: op, Amount: jsF(m["amount"])})
	}
	return out
}

// ApplyBondMoves applies moves in order over the balances balanceOf reports and returns the new balance of every touched account.
// A negative or non-finite amount, or a debit beyond the balance, is an error and nothing is applied.
func ApplyBondMoves(balanceOf func(account string) float64, moves []BondMove) (map[string]float64, error) {
	out := map[string]float64{}
	bal := func(a string) float64 {
		if v, ok := out[a]; ok {
			return v
		}
		return balanceOf(a)
	}
	for _, m := range moves {
		if !bsFinite(m.Amount) || m.Amount < 0 {
			return nil, fmt.Errorf("%s: invalid amount", m.Op)
		}
		if !bsFinite(bal(m.Account)) {
			return nil, fmt.Errorf("%s: balance of %s is not finite", m.Op, m.Account)
		}
		sign := 1
		if m.Op == "debit" {
			if !(bal(m.Account) >= m.Amount) {
				return nil, fmt.Errorf("debit: insufficient balance for %s", m.Account)
			}
			sign = -1
		}
		out[m.Account] = ExactAdd(bal(m.Account), m.Amount, sign)
	}
	return out, nil
}

// BondView is the read side a planner decides on: one bond's head ({claimId, amount, depositor, status}; nil when there is none),
// an account balance and a depositor's open totals.
type BondView interface {
	Bond(claimID string) map[string]any
	BalanceOf(account string) float64
	OpenTotals(depositor string) (count, sum float64)
}

// BondPlannerOptions configure a BondSettlementPlanner. Guardian signs every record; GuardianEpoch (optional) is bound into them;
// Suite chooses a post-quantum or hybrid signature; empty EscrowAccount, nil BondPolicy and nil SlashSplitPolicy are the defaults.
type BondPlannerOptions struct {
	Guardian         *KeyPair
	GuardianEpoch    *int64
	Suite            *SuiteOpts
	EscrowAccount    string
	BondPolicy       *BondPolicy
	SlashSplitPolicy *SlashSplitPolicy
}

// BondSettlementPlanner turns a settlement request into a signed plan {claimId, expect, next, open?, moves, record} over a
// BondView. It holds no state: a store commits the plan atomically (KvBondStore, StoreBondLedger).
type BondSettlementPlanner struct {
	// GuardianPublicKey is the key every record verifies under.
	GuardianPublicKey string
	// Escrow is the escrow account.
	Escrow string
	// BondPolicy and SlashSplitPolicy are the policies in force.
	BondPolicy       BondPolicy
	SlashSplitPolicy SlashSplitPolicy
	o                BondPlannerOptions
}

// NewBondSettlementPlanner validates the options and returns a planner.
func NewBondSettlementPlanner(o BondPlannerOptions) (*BondSettlementPlanner, error) {
	if o.Guardian == nil || o.Guardian.Public == "" {
		return nil, errors.New("BondLedger: a guardian key is required")
	}
	if o.GuardianEpoch != nil && (*o.GuardianEpoch < 0 || *o.GuardianEpoch > maxSafeInt) {
		return nil, errors.New("BondLedger: guardianEpoch must be a non-negative safe integer")
	}
	if _, known := resolveSigAlg(o.Suite.alg(), true); !known {
		return nil, fmt.Errorf("BondLedger: unknown signature alg '%s'", o.Suite.alg())
	}
	p := &BondSettlementPlanner{GuardianPublicKey: o.Guardian.Public, Escrow: EscrowAccount, BondPolicy: DefaultBondPolicy,
		SlashSplitPolicy: DefaultSlashSplitPolicy, o: o}
	if o.EscrowAccount != "" {
		p.Escrow = o.EscrowAccount
	}
	if o.BondPolicy != nil {
		p.BondPolicy = *o.BondPolicy
	}
	if o.SlashSplitPolicy != nil {
		p.SlashSplitPolicy = *o.SlashSplitPolicy
	}
	return p, nil
}

func (p *BondSettlementPlanner) signRecord(base map[string]any) (map[string]any, error) {
	if p.o.GuardianEpoch != nil {
		base["guardian_epoch"] = jsNumber(float64(*p.o.GuardianEpoch))
	}
	body, err := bindSuite(base, p.o.Suite)
	if err != nil {
		return nil, err
	}
	c, ok := canonicalLenient(body)
	if !ok {
		return nil, errors.New("settlement record is not canonicalizable")
	}
	sig, pqSig, err := signWithSuite(p.o.Suite, p.o.Guardian, append([]byte(settlementDomain), c...))
	if err != nil {
		return nil, err
	}
	body["sig"] = sig
	if pqSig != "" {
		body["pq_sig"] = pqSig
	}
	return body, nil
}

func bsRecord(claimID, action string, amount float64, from, to string, at float64, evidence string) map[string]any {
	return map[string]any{"claimId": claimID, "action": action, "amount": bsNum(amount), "from": from, "to": to, "at": bsNum(at), "evidenceDigest": evidence}
}

// BondRegistration is the claim a bond backs: when it was registered, its challenge window and the digest of the claim.
type BondRegistration struct {
	RegisteredAt, WindowMs float64
	ClaimDigest            string
}

func (w *BondRegistration) json() map[string]any {
	return map[string]any{"registeredAt": bsNum(w.RegisteredAt), "windowMs": bsNum(w.WindowMs), "claimDigest": w.ClaimDigest}
}

// PlanOpen plans opening a bond: the collateral moves from the depositor to escrow. It refuses a missing id / depositor, a
// non-positive amount, an existing bond, an amount below the required bond for the exposure, a depositor over its open-claim or
// aggregate cap, and an insufficient balance.
func (p *BondSettlementPlanner) PlanOpen(view BondView, claimID string, amount float64, depositor string, exposure float64, now float64, window *BondRegistration) (map[string]any, error) {
	if claimID == "" {
		return nil, errors.New("openBond: claimId is required")
	}
	if !bsFinite(amount) || amount <= 0 {
		return nil, errors.New("openBond: amount must be a positive finite number")
	}
	if depositor == "" {
		return nil, errors.New("openBond: depositor is required")
	}
	if view.Bond(claimID) != nil {
		return nil, fmt.Errorf("openBond: bond %s already exists (double-open refused)", claimID)
	}
	required, err := BondAmount(p.BondPolicy, exposure)
	if err != nil {
		return nil, err
	}
	if !(amount >= required) {
		return nil, fmt.Errorf("openBond: amount %s is below the required bond %s", rsNumStr(amount), rsNumStr(required))
	}
	count, sum := view.OpenTotals(depositor)
	if !(bsFinite(count) && count+1 <= p.BondPolicy.MaxOpenClaims) {
		return nil, errors.New("openBond: depositor open-claim cap reached")
	}
	if !(bsFinite(sum+amount) && sum+amount <= p.BondPolicy.MaxOpenAmount) { // an infinite cap is the unbounded one
		return nil, errors.New("openBond: depositor aggregate open-bond cap exceeded")
	}
	if bal := view.BalanceOf(depositor); !(bsFinite(bal) && bal >= amount) {
		return nil, errors.New("openBond: insufficient balance for the bond")
	}
	record, err := p.signRecord(bsRecord(claimID, "open", amount, depositor, p.Escrow, now, ""))
	if err != nil {
		return nil, err
	}
	open := map[string]any{"amount": bsNum(amount), "depositor": depositor, "maxOpenClaims": bsNum(p.BondPolicy.MaxOpenClaims), "maxOpenAmount": bsNum(p.BondPolicy.MaxOpenAmount)}
	if window != nil {
		open["window"] = window.json()
	}
	return map[string]any{"claimId": claimID, "expect": "none", "next": "open", "open": open,
		"moves": bsMovesJSON([]BondMove{{depositor, "debit", amount}, {p.Escrow, "credit", amount}}), "record": record}, nil
}

func bsOpenBond(view BondView, who, noun, claimID string) (amount float64, depositor string, err error) {
	bond := view.Bond(claimID)
	if bond == nil {
		return 0, "", fmt.Errorf("%s: no %s for %s", who, noun, claimID)
	}
	if st, _ := bond["status"].(string); st != "open" {
		return 0, "", fmt.Errorf("%s: %s %s is already %s (double-settle refused)", who, noun, claimID, st)
	}
	depositor, _ = bond["depositor"].(string)
	return jsF(bond["amount"]), depositor, nil
}

// PlanRelease plans returning an open bond from escrow to its depositor.
func (p *BondSettlementPlanner) PlanRelease(view BondView, claimID string, now float64) (map[string]any, error) {
	amount, depositor, err := bsOpenBond(view, "releaseBond", "bond", claimID)
	if err != nil {
		return nil, err
	}
	record, err := p.signRecord(bsRecord(claimID, "release", amount, p.Escrow, depositor, now, ""))
	if err != nil {
		return nil, err
	}
	return map[string]any{"claimId": claimID, "expect": "open", "next": "released",
		"moves": bsMovesJSON([]BondMove{{p.Escrow, "debit", amount}, {depositor, "credit", amount}}), "record": record}, nil
}

// SlashParams are the inputs of a slash. ClaimID is the bond to slash (for a counter-bond slash: the counter-bond). Claim is the
// bonded claim; Treasury receives the remainder; ChallengerAccount (nil: none) the reward; CompensationAccount ("": the pool) the
// victim share; SplitPolicy overrides the planner's. A fraud slash needs FraudProof, Grant and OpenSnapshot; a dispute or
// counter-bond slash needs Dispute, Grant, OpenSnapshot and Oracle (RMargin optional); a revocation slash needs RevokedCapID.
type SlashParams struct {
	ClaimID             string
	Claim               map[string]any
	Treasury            string
	ChallengerAccount   *string
	CompensationAccount string
	SplitPolicy         *SlashSplitPolicy
	FraudProof          any
	Grant               map[string]any
	OpenSnapshot        any
	Dispute             any
	Oracle              ObjectiveOracle
	RMargin             *float64
	RevokedCapID        string
}

func (p *BondSettlementPlanner) slashPlan(amount float64, claimID string, now float64, evidence string, q SlashParams) (map[string]any, error) {
	policy := p.SlashSplitPolicy
	if q.SplitPolicy != nil {
		policy = *q.SplitPolicy
	}
	victim := q.CompensationAccount
	if victim == "" {
		victim = CompensationPoolAccount
	}
	split, err := ComputeSlashSplit(amount, policy, q.ChallengerAccount, victim, q.Treasury)
	if err != nil {
		return nil, err
	}
	moves := []BondMove{{p.Escrow, "debit", amount}} // the full bond leaves escrow
	if c := jsF(split["challengerReward"]); q.ChallengerAccount != nil && *q.ChallengerAccount != "" && c > 0 {
		moves = append(moves, BondMove{*q.ChallengerAccount, "credit", c})
	}
	if v := jsF(split["victimCompensation"]); v > 0 {
		moves = append(moves, BondMove{victim, "credit", v})
	}
	if t := jsF(split["treasuryRemainder"]); t > 0 {
		moves = append(moves, BondMove{q.Treasury, "credit", t})
	}
	base := bsRecord(claimID, "slash", amount, p.Escrow, q.Treasury, now, evidence)
	base["split"] = split
	record, err := p.signRecord(base)
	if err != nil {
		return nil, err
	}
	return map[string]any{"claimId": claimID, "expect": "open", "next": "slashed", "moves": bsMovesJSON(moves), "record": record}, nil
}

func bsClaimIsFor(claim map[string]any, claimID string) bool {
	ref, ok := claim["bond_ref"].(string)
	return ok && ref == claimID
}

// PlanSlash plans slashing a bond on a fraud proof: the proof must verify by independent recomputation and name this bond.
func (p *BondSettlementPlanner) PlanSlash(view BondView, q SlashParams, now float64) (map[string]any, error) {
	amount, _, err := bsOpenBond(view, "slashBond", "bond", q.ClaimID)
	if err != nil {
		return nil, err
	}
	if q.Treasury == "" {
		return nil, errors.New("slashBond: treasury is required")
	}
	if !bsClaimIsFor(q.Claim, q.ClaimID) {
		return nil, errors.New("slashBond: claim.bond_ref does not match claimId")
	}
	verdict := VerifyFraudProof(q.Claim, q.FraudProof, q.Grant, q.OpenSnapshot)
	if ref, _ := verdict["slashBondRef"].(string); verdict["fraudulent"] != true || ref != q.ClaimID {
		return nil, fmt.Errorf("slashBond: refused, no verified fraud verdict slashing %s (%v)", q.ClaimID, verdict["reason"])
	}
	ev, err := SettlementEvidenceDigest(q.Claim, verdict)
	if err != nil {
		return nil, err
	}
	return p.slashPlan(amount, q.ClaimID, now, ev, q)
}

// PlanSlashOnRevocation plans slashing a bond because the capability behind the claim was revoked.
func (p *BondSettlementPlanner) PlanSlashOnRevocation(view BondView, q SlashParams, now float64) (map[string]any, error) {
	amount, _, err := bsOpenBond(view, "slashBondOnRevocation", "bond", q.ClaimID)
	if err != nil {
		return nil, err
	}
	if q.Treasury == "" {
		return nil, errors.New("slashBondOnRevocation: treasury is required")
	}
	if !bsClaimIsFor(q.Claim, q.ClaimID) {
		return nil, errors.New("slashBondOnRevocation: claim.bond_ref does not match claimId")
	}
	if q.RevokedCapID == "" {
		return nil, errors.New("slashBondOnRevocation: revokedCapId is required")
	}
	ev, err := RevocationEvidenceDigest(q.Claim, q.RevokedCapID)
	if err != nil {
		return nil, err
	}
	return p.slashPlan(amount, q.ClaimID, now, ev, q)
}

// PlanSlashOnDispute plans slashing a bond on an adjudicated dispute: the oracle's value must refute the fast-path admission.
func (p *BondSettlementPlanner) PlanSlashOnDispute(view BondView, q SlashParams, now float64) (map[string]any, error) {
	amount, _, err := bsOpenBond(view, "slashBondOnDispute", "bond", q.ClaimID)
	if err != nil {
		return nil, err
	}
	if q.Treasury == "" {
		return nil, errors.New("slashBondOnDispute: treasury is required")
	}
	if !bsClaimIsFor(q.Claim, q.ClaimID) {
		return nil, errors.New("slashBondOnDispute: claim.bond_ref does not match claimId")
	}
	verdict := AdjudicateDispute(q.Claim, q.Dispute, q.Grant, q.OpenSnapshot, q.Oracle, q.RMargin)
	if ref, _ := verdict["slashBondRef"].(string); verdict["outcome"] != "agent-fraud" || verdict["fraudulent"] != true || ref != q.ClaimID {
		return nil, fmt.Errorf("slashBondOnDispute: refused, no verified agent-fraud verdict slashing %s (%v: %v)", q.ClaimID, verdict["outcome"], verdict["reason"])
	}
	ev, err := DisputeEvidenceDigest(q.Claim, verdict)
	if err != nil {
		return nil, err
	}
	return p.slashPlan(amount, q.ClaimID, now, ev, q)
}

// PlanSlashCounterBond plans slashing a challenger's counter-bond because the dispute was frivolous (the oracle upheld the claim).
// The whole counter-bond goes to the victim pool and the treasury: there is no challenger reward.
func (p *BondSettlementPlanner) PlanSlashCounterBond(view BondView, q SlashParams, now float64) (map[string]any, error) {
	amount, _, err := bsOpenBond(view, "slashCounterBond", "counter-bond", q.ClaimID)
	if err != nil {
		return nil, err
	}
	if q.Treasury == "" {
		return nil, errors.New("slashCounterBond: treasury is required")
	}
	verdict := AdjudicateDispute(q.Claim, q.Dispute, q.Grant, q.OpenSnapshot, q.Oracle, q.RMargin)
	if verdict["outcome"] != "claim-upheld" || verdict["slashCounterBond"] != true {
		return nil, fmt.Errorf("slashCounterBond: refused, the dispute is not frivolous (%v: %v)", verdict["outcome"], verdict["reason"])
	}
	ev, err := DisputeEvidenceDigest(q.Claim, verdict)
	if err != nil {
		return nil, err
	}
	q.ChallengerAccount = nil
	return p.slashPlan(amount, q.ClaimID, now, ev, q)
}

// InsuranceCapitalPool is the capital behind coverage quotes: premiums in, claim payouts out, never below zero.
type InsuranceCapitalPool struct {
	initial, premiumsIn, payoutsOut float64
}

// NewInsuranceCapitalPool returns a pool with the given initial capital (non-negative and finite).
func NewInsuranceCapitalPool(initial float64) (*InsuranceCapitalPool, error) {
	if !bsFinite(initial) || initial < 0 {
		return nil, errors.New("InsuranceCapitalPool: initial capital must be a non-negative finite number")
	}
	return &InsuranceCapitalPool{initial: initial}, nil
}

// Balance is initial + premiums - payouts.
func (p *InsuranceCapitalPool) Balance() float64 { return p.initial + p.premiumsIn - p.payoutsOut }

// PremiumsIn is the total of collected premiums.
func (p *InsuranceCapitalPool) PremiumsIn() float64 { return p.premiumsIn }

// PayoutsOut is the total of paid claims.
func (p *InsuranceCapitalPool) PayoutsOut() float64 { return p.payoutsOut }

// State is {initial, premiumsIn, payoutsOut, balance}.
func (p *InsuranceCapitalPool) State() map[string]any {
	return map[string]any{"initial": bsNum(p.initial), "premiumsIn": bsNum(p.premiumsIn), "payoutsOut": bsNum(p.payoutsOut), "balance": bsNum(p.Balance())}
}

// Quote prices coverage of exposure for a reputation score (PriceCoverage); it moves no money.
func (p *InsuranceCapitalPool) Quote(score *float64, exposure float64, opts map[string]any) map[string]any {
	return PriceCoverage(score, exposure, opts)
}

// CollectPremium prices the coverage and, unless it is declined, adds the premium to the pool: {pricing, state}.
func (p *InsuranceCapitalPool) CollectPremium(score *float64, exposure float64, opts map[string]any) (map[string]any, error) {
	pricing := p.Quote(score, exposure, opts)
	if premium := jsF(pricing["premium"]); pricing["declined"] != true && premium > 0 {
		if !bsFinite(premium) {
			return nil, errors.New("collectPremium: priced premium is not a non-negative finite number")
		}
		p.premiumsIn += premium
	}
	return map[string]any{"pricing": pricing, "state": p.State()}, nil
}

// CanCover reports whether the pool can pay amount.
func (p *InsuranceCapitalPool) CanCover(amount float64) bool {
	return bsFinite(amount) && amount >= 0 && p.Balance() >= amount
}

// PayClaim pays amount out of the pool and returns the new state; an amount above the balance is refused.
func (p *InsuranceCapitalPool) PayClaim(amount float64) (map[string]any, error) {
	if !bsFinite(amount) || amount <= 0 {
		return nil, errors.New("payClaim: amount must be a positive finite number")
	}
	if !(bsFinite(p.Balance()) && amount <= p.Balance()) {
		return nil, fmt.Errorf("payClaim: insufficient pool capital (need %s, have %s)", rsNumStr(amount), rsNumStr(p.Balance()))
	}
	p.payoutsOut += amount
	return p.State(), nil
}

// bsQuote is JSON.stringify of a string (no HTML escaping).
func bsQuote(s string) string {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	_ = e.Encode(s)
	return string(bytes.TrimRight(buf.Bytes(), "\n"))
}

// bsPowEighths is e^gamma for gamma a multiple of 1/8 in [1, 64] using only exactly rounded multiplications and square roots, so
// every platform yields identical bits (no pow, no fused multiply-add).
func bsPowEighths(e, gamma float64) (float64, error) {
	n := gamma * 8
	if !(n == math.Floor(n) && gamma <= 64) {
		return 0, errors.New("bondAmount: power curve gamma must be a multiple of 1/8 and at most 64")
	}
	r := 1.0
	for i := 0; i < int(n)/8; i++ {
		r = float64(r * e)
	}
	f := int(n) % 8
	s1 := math.Sqrt(e)
	s2 := math.Sqrt(s1)
	s3 := math.Sqrt(s2)
	if f&4 != 0 {
		r = float64(r * s1)
	}
	if f&2 != 0 {
		r = float64(r * s2)
	}
	if f&1 != 0 {
		r = float64(r * s3)
	}
	return r, nil
}
