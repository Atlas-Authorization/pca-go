package pca

// The DISTRIBUTED malicious-with-abort (SPDZ-style) composition protocol over the TLS mesh: the native twin of the reference
// networked runner. Same circuit and semantics as MpcComposeSecureMalicious (allow = AND, t = MAX, r = MAX via thermometers;
// authenticated Beaver multiplication; batched MAC-check before any output), but each party is its own goroutine or process
// holding only its own shares, and every opening is a real message over the mesh. Rounds (n parties, C = 1 + 3 + Q chains):
//
//	prep      dealer -> party: key shares, sacrificed-triple material, input masks, pairwise tags (trusted-dealer offline phase)
//	coin1-*   all-to-all: commit/open of a random seed -> public challenges for the triple sacrifice
//	sac-rho   all-to-all: value shares of rho = e*a - a-hat for every triple and sacrifice partner
//	sac-tau   all-to-all: value shares of tau = e*c - c-hat - rho*b; every tau must be 0
//	inputs    all-to-all: the owner broadcasts x - r (r is its dealer-given mask)
//	mul0..    all-to-all: value shares of d = x-a, e = y-b for all chains at once (n-1 rounds)
//	out       all-to-all: value shares of the output bits
//	<rd>.t    all-to-all: after every opening the pairwise tags; each receiver verifies the sender's share at once
//	coin-*    commit/open of a random seed -> public MAC-check challenges
//	sig-c/o   commit/open of each party's MAC residual shares; the sums must be 0
//	digest    hash of the whole broadcast transcript; any disagreement aborts
//	blame     only after a failed MAC-check: every party opens its combined MAC shares and key shares with their tags
//
// No output is decoded until the MAC-check and the transcript echo pass. Only the trusted-dealer offline phase is available in
// this library: the dealer sees every share and MAC key, so it needs an explicit InsecureTrustedDealer opt-in. There is no
// security proof; the echo is a hash exchange, not Byzantine agreement.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// MpcChainCount is the number of independent circuit chains (= output bits = input bits per owner).
func MpcChainCount(Q int) int { return 1 + mpcTM + Q }

const mpcPrepChunk = 30000

var mpcHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// MpcNetPrep is the offline material one party holds when the online phase starts.
type MpcNetPrep struct {
	Mode    string // "trusted-dealer" or "no-dealer"
	Tagged  bool
	Delta   *big.Int
	Alpha   []MpcPA
	Triples [][]MpcAW
	Inputs  []MpcAW
	MyPlain []*big.Int
	// CheckMask is the authenticated random mask of the input-consistency check (no-dealer material only).
	CheckMask *MpcAW
	// Forensics is the OT transcript for attributing a failed sacrifice (no-dealer material only).
	Forensics *MpcNetForensics
}

// MpcRoundStat is the cost of one round at this party.
type MpcRoundStat struct {
	Rd                string
	Ms                float64
	BytesOut, BytesIn int
}

// MpcPartyResult is one party's verdict.
type MpcPartyResult struct {
	ID, N, Q          int
	Composed          MpcComposedDecision
	Rounds            []MpcRoundStat
	TranscriptDigest  string
	WallMs            float64
	Multiplications   int
	Opens             int
	OfflineMode       string
	MacKeys           int
	SacrificedTriples int
	SacrificePartners int
	IdentifiableAbort bool
}

func mpcAbortF(kind string, blamed *int, reporter int, detail string, reason string) *MpcNetAbort {
	var r *string
	if reason != "" {
		r = &reason
	}
	return NewMpcNetAbort(kind, blamed, reporter, detail, nil, nil, r, nil, nil)
}

func mpcIntP(i int) *int { return &i }

func mpcSha(parts ...any) []byte {
	h := sha256.New()
	for _, p := range parts {
		switch t := p.(type) {
		case string:
			h.Write([]byte(t))
		case []byte:
			h.Write(t)
		}
		h.Write([]byte{0})
	}
	return h.Sum(nil)
}

// mpcChallenge is the uniform non-zero field element j of the public challenge stream label derived from seed.
func mpcChallenge(seed []byte, label string, j int) *big.Int {
	for ctr := 0; ; ctr++ {
		h := mpcSha("chal", seed, label+":"+strconv.Itoa(j)+":"+strconv.Itoa(ctr))
		x := binary.BigEndian.Uint64(h[:8]) & (uint64(1)<<61 - 1)
		if x < mpcPrimeU64 && x != 0 {
			return new(big.Int).SetUint64(x)
		}
	}
}

func mpcFlatHex(nums []*big.Int) []any {
	out := make([]any, len(nums))
	for i, x := range nums {
		out[i] = MpcHx(x)
	}
	return out
}

// ---------------------------------------------------------------------------------------------------------------- dealer

// MpcDealerConfig configures the trusted dealer role.
type MpcDealerConfig struct {
	// InsecureTrustedDealer must be true: the dealer sees every share and key.
	InsecureTrustedDealer bool
	N, Q                  int
	Mesh                  *MpcMesh
	// Seed gives a reproducible stream for tests; nil means the CSPRNG.
	Seed *big.Int
	// Fault is TEST ONLY: a LYING dealer that authenticates a wrong product.
	Fault *MpcDealerFault
	// MacFaultAtInput is TEST ONLY: deal party 0 a MAC share of input mask number i that does not match its value (nil = none).
	MacFaultAtInput *int
}

// MpcRunDealer samples the MAC keys, the verification keys, sacrifice-certified authenticated triples and authenticated input
// masks and ships each party only its own slice. It never sees an input bit (inputs are masked by r) but it knows every key and
// share, so it can break privacy and integrity if it colludes: the stated trust assumption of this mode.
func MpcRunDealer(cfg MpcDealerConfig) error {
	if !cfg.InsecureTrustedDealer {
		return errors.New("MpcRunDealer requires InsecureTrustedDealer: a dealer sees every share and MAC key; the default offline phase has no dealer")
	}
	n, mesh := cfg.N, cfg.Mesh
	Q := cfg.Q
	if Q == 0 {
		Q = MpcDefaultQ
	}
	rng := MpcFieldRandom(cfg.Seed)
	C := MpcChainCount(Q)
	ctx, err := MpcSetupMac(n, rng, MpcMacKeys)
	if err != nil {
		return err
	}
	keys := MpcMacKeysOf(ctx)
	deltas := make([]*big.Int, n)
	for i := range deltas {
		d := rng.Next()
		for d.Sign() == 0 {
			d = rng.Next()
		}
		deltas[i] = d
	}
	// the pairwise tags/keys for one sharing x_0..x_{n-1}: T_ij = K_ij + delta_j * x_i
	dealPA := func(x []*big.Int) []MpcPA {
		K := make([][]*big.Int, len(x))
		for i := range x {
			K[i] = make([]*big.Int, len(x))
			for j := range x {
				if i == j {
					K[i][j] = new(big.Int)
				} else {
					K[i][j] = rng.Next()
				}
			}
		}
		out := make([]MpcPA, len(x))
		for p, xp := range x {
			tag, key := make([]*big.Int, len(x)), make([]*big.Int, len(x))
			for j := range x {
				if j == p {
					tag[j], key[j] = new(big.Int), new(big.Int)
					continue
				}
				tag[j] = MpcFAdd(K[p][j], MpcFMul(deltas[j], xp))
				key[j] = K[j][p]
			}
			out[p] = MpcPA{xp, tag, key}
		}
		return out
	}
	dealAW := func(sv MpcAuthSV) []MpcAW {
		comps := [][]MpcPA{dealPA(sv.Value), dealPA(sv.Mac)}
		for _, e := range sv.ExtraMac {
			comps = append(comps, dealPA(e))
		}
		out := make([]MpcAW, n)
		for p := range out {
			m := make([]MpcPA, 0, len(comps)-1)
			for _, c := range comps[1:] {
				m = append(m, c[p])
			}
			out[p] = MpcAW{comps[0][p], m}
		}
		return out
	}

	perParty := make([][]*big.Int, n)
	for p := range perParty {
		perParty[p] = []*big.Int{deltas[p]}
	}
	alphaPA := make([][]MpcPA, len(keys))
	for l, k := range keys {
		alphaPA[l] = dealPA(k.AlphaShares)
	}
	for p := 0; p < n; p++ {
		for _, a := range alphaPA {
			perParty[p] = append(perParty[p], MpcPaFlat(a[p], p, n, true)...)
		}
	}
	for t := 0; t < (n-1)*C; t++ {
		tr, err := MpcGenTripleWithPartners(ctx, rng, MpcSacrificeParts, cfg.Fault)
		if err != nil {
			return err
		}
		sharings := []MpcAuthSV{tr.Keep.A, tr.Keep.B, tr.Keep.C}
		for _, q := range tr.Partners {
			sharings = append(sharings, q.A, q.C)
		}
		for _, sv := range sharings {
			aws := dealAW(sv)
			for p := 0; p < n; p++ {
				perParty[p] = append(perParty[p], MpcAwFlat(aws[p], p, n, true)...)
			}
		}
	}
	masks := make([][]*big.Int, n)
	for q := 0; q < n*C; q++ {
		owner := q / C
		r := rng.Next()
		masks[owner] = append(masks[owner], r)
		sv, err := MpcAuthShare(r, ctx, rng)
		if err != nil {
			return err
		}
		if cfg.MacFaultAtInput != nil && *cfg.MacFaultAtInput == q {
			sv.Mac[0] = MpcFAdd(sv.Mac[0], big.NewInt(1))
		}
		aws := dealAW(sv)
		for p := 0; p < n; p++ {
			perParty[p] = append(perParty[p], MpcAwFlat(aws[p], p, n, true)...)
		}
	}
	for p := 0; p < n; p++ {
		perParty[p] = append(perParty[p], masks[p]...)
	}
	for p := 0; p < n; p++ {
		nums := mpcFlatHex(perParty[p])
		chunks := max(1, (len(nums)+mpcPrepChunk-1)/mpcPrepChunk)
		if err := mesh.Send(p, "prep", map[string]any{"total": len(nums), "chunks": chunks, "nums": nums[:min(mpcPrepChunk, len(nums))]}); err != nil {
			return err
		}
		for c := 1; c < chunks; c++ {
			if err := mesh.Send(p, "prep."+strconv.Itoa(c), nums[c*mpcPrepChunk:min((c+1)*mpcPrepChunk, len(nums))]); err != nil {
				return err
			}
		}
	}
	mesh.Finish()
	return nil
}

// ---------------------------------------------------------------------------------------------------------------- party

// MpcPartyConfig configures one party.
type MpcPartyConfig struct {
	ID, N int
	Q     int // 0 = MpcDefaultQ
	Input MpcDecisionVector
	Mesh  *MpcMesh
	// DealerID is the node id of the dealer (nil = n).
	DealerID *int
	// Offline is "no-dealer" (the default: the parties derive everything from OT) or "trusted-dealer" (needs InsecureTrustedDealer).
	// ForensicDeadlineMs is the window every party has to commit to and open its forensic disclosure (0 = the default).
	Offline               string
	InsecureTrustedDealer bool
	SessionID             string
	ForensicDeadlineMs    int
	// Behavior is TEST ONLY and needs UnsafeTestHooks: a malicious party's misbehaviour. Offline (no-dealer): "offline-lie", "ot-u-lie",
	// "ot-proof-lie". Online, in BehaviorRound: "open-lie" (a wrong value share), "mac-lie" (a wrong MAC share in the check), "bad-tag"
	// (a wrong pairwise tag), "crash" (exit the process with status 7 on reaching the round), "silent" (stop participating, sockets
	// open). "equivocate" (different value shares to the first other party), "short-array" and "noncanonical" (a wrong-length array / a field element >= p) act in BehaviorRound. "sigma-lie" (a MAC residual off by one, consistent with its commitment), "bad-coin-open" (the final coin seed opens to a value that does not match its commitment) and "bad-sigma-open" (the residual opens off by one) need no round.
	Behavior        string
	BehaviorRound   string
	UnsafeTestHooks bool
}

// ErrMpcSilentParty is returned by a party running the test-only "silent" behaviour: the host process should idle with its
// sockets open so the peers time out.
var ErrMpcSilentParty = errors.New("silent party (test-only behavior)")

// mpcExit ends the process for the test-only "crash" behavior (replaced in-process tests).
var mpcExit = os.Exit

type mpcOpened struct {
	val *big.Int
	mac []MpcPA
}

type mpcParse func(p int, raw any) (any, error)

// MpcRunParty runs one party to completion: its composed decision, or an abort that names a culprit only when the evidence does.
func MpcRunParty(cfg MpcPartyConfig) (*MpcPartyResult, error) {
	id, n, mesh, sessionID := cfg.ID, cfg.N, cfg.Mesh, cfg.SessionID
	Q := cfg.Q
	if Q == 0 {
		Q = MpcDefaultQ
	}
	dealerID := n
	if cfg.DealerID != nil {
		dealerID = *cfg.DealerID
	}
	mode := cfg.Offline
	if mode == "" {
		mode = "no-dealer"
	}
	local := func(d string) error { return mpcAbortF("local", nil, id, d, "") }
	switch {
	case mode != "trusted-dealer" && mode != "no-dealer":
		return nil, local("unknown offline mode")
	case mode == "trusted-dealer" && !cfg.InsecureTrustedDealer:
		return nil, local("offline 'trusted-dealer' requires InsecureTrustedDealer (the dealer sees every share and key); the default is 'no-dealer'")
	}
	if cfg.Behavior != "" && !cfg.UnsafeTestHooks {
		return nil, local("the behavior test hook requires UnsafeTestHooks (test-only)")
	}
	if n < 1 {
		return nil, local("n must be >= 1")
	}
	v := cfg.Input
	if (v.Allow != 0 && v.Allow != 1) || v.T < 1 || v.T > 3 || v.RQuant < 0 || v.RQuant > Q {
		return nil, local("invalid decision vector")
	}
	C, K, P := MpcChainCount(Q), MpcMacKeys, MpcSacrificeParts
	t0 := time.Now()
	var rounds []MpcRoundStat
	transcript := sha256.New()
	var others []int
	for i := 0; i < n; i++ {
		if i != id {
			others = append(others, i)
		}
	}
	totals := func() (o, i int) {
		for _, s := range mesh.Stats() {
			o += s.AppBytesOut
			i += s.AppBytesIn
		}
		return
	}
	abort := func(e *MpcNetAbort) error {
		mesh.Fail(e)
		return e
	}
	bad := func(p int, what string) error { return mpcAbortF("malformed", mpcIntP(p), id, what, "") }
	arr := func(p int, raw any, ln int) ([]*big.Int, error) {
		if a := MpcUnhxArray(raw, ln); a != nil {
			return a, nil
		}
		return nil, bad(p, fmt.Sprintf("expected %d canonical field elements", ln))
	}
	asArr := func(x any) []*big.Int { a, _ := x.([]*big.Int); return a }
	beh, behRound := cfg.Behavior, cfg.BehaviorRound
	crashIf := func(rd string) error {
		if beh == "crash" && behRound == rd {
			mpcExit(7)
		}
		if beh == "silent" && behRound == rd {
			return ErrMpcSilentParty
		}
		return nil
	}

	// one all-to-all round: send mine(peer) to each peer, collect and validate theirs. hashed=false keeps the round (the
	// peer-specific pairwise tags) out of the echoed transcript; canon renders a received value for the transcript.
	exchangeT := func(rd string, mine func(peer int) any, parse mpcParse, common any, hashed bool, canon func(any) string, timeout time.Duration) (map[int]any, error) {
		if err := crashIf(rd); err != nil {
			return nil, err
		}
		oa, ia := totals()
		s := time.Now()
		for _, p := range others {
			if err := mesh.Send(p, rd, mine(p)); err != nil {
				return nil, err
			}
		}
		raw, err := mesh.Collect(rd, others, timeout)
		if err != nil {
			return nil, err
		}
		parsed := map[int]any{}
		for _, p := range others {
			pv, err := parse(p, raw[p])
			if err != nil {
				var ne *MpcNetAbort
				if !errors.As(err, &ne) {
					ne = mpcAbortF("malformed", mpcIntP(p), id, fmt.Sprintf("round '%s': %v", rd, err), "")
				}
				return nil, abort(ne)
			}
			parsed[p] = pv
		}
		if hashed {
			transcript.Write([]byte(rd))
			for p := 0; p < n; p++ {
				transcript.Write([]byte("|" + strconv.Itoa(p) + ":"))
				src := raw[p]
				if p == id {
					src = common
				}
				var txt string
				if canon != nil {
					txt = canon(src)
				} else if txt, err = MpcStringify(src); err != nil {
					return nil, abort(mpcAbortF("local", nil, id, err.Error(), ""))
				}
				transcript.Write([]byte(txt))
			}
		}
		ob, ib := totals()
		rounds = append(rounds, MpcRoundStat{Rd: rd, Ms: float64(time.Since(s).Microseconds()) / 1000, BytesOut: ob - oa, BytesIn: ib - ia})
		return parsed, nil
	}
	exchange := func(rd string, mine func(peer int) any, parse mpcParse, common any, hashed bool, canon func(any) string) (map[int]any, error) {
		return exchangeT(rd, mine, parse, common, hashed, canon, 0)
	}
	arrParse := func(ln int) mpcParse {
		return func(p int, raw any) (any, error) { return arr(p, raw, ln) }
	}
	hex64Parse := func(what string) mpcParse {
		return func(p int, raw any) (any, error) {
			if s, ok := raw.(string); ok && mpcHex64.MatchString(s) {
				return s, nil
			}
			return nil, bad(p, what)
		}
	}

	// ---- offline phase: prep from the trusted dealer ----
	if err := crashIf("prep"); err != nil {
		return nil, err
	}
	prepStart := time.Now()
	ob0, ib0 := totals()
	recvDealer := func() (*MpcNetPrep, error) {
		lay := struct{ nums, triples, inputs int }{}
		aw := MpcAwWidth(n, K, true)
		lay.triples, lay.inputs = (n-1)*C, n*C
		lay.nums = 1 + K*MpcPaWidth(n, true) + lay.triples*MpcSharingsPerTriple(P)*aw + lay.inputs*aw + C
		fv, err := mesh.Recv(dealerID, "prep", 0)
		if err != nil {
			return nil, err
		}
		first, _ := fv.(map[string]any)
		total, okT := jsNum(first["total"])
		chunks, okC := jsNum(first["chunks"])
		var nums []*big.Int
		fail := func(e error) (*MpcNetPrep, error) {
			var ne *MpcNetAbort
			if !errors.As(e, &ne) {
				ne = mpcAbortF("malformed", mpcIntP(dealerID), id, e.Error(), "")
			}
			return nil, abort(ne)
		}
		if !okT || int(total) != lay.nums || total != float64(lay.nums) {
			return fail(bad(dealerID, "bad prep size"))
		}
		wantChunks := max(1, (lay.nums+mpcPrepChunk-1)/mpcPrepChunk)
		if !okC || chunks != float64(wantChunks) {
			return fail(bad(dealerID, "bad prep chunk count"))
		}
		take := func(raw any, ln int) ([]*big.Int, error) {
			if a := MpcUnhxArray(raw, ln); a != nil {
				return a, nil
			}
			return nil, bad(dealerID, "bad prep numbers")
		}
		part, err := take(first["nums"], min(mpcPrepChunk, lay.nums))
		if err != nil {
			return fail(err)
		}
		nums = part
		for c := 1; c < wantChunks; c++ {
			raw, err := mesh.Recv(dealerID, "prep."+strconv.Itoa(c), 0)
			if err != nil {
				return nil, err
			}
			if part, err = take(raw, min(mpcPrepChunk, lay.nums-c*mpcPrepChunk)); err != nil {
				return fail(err)
			}
			nums = append(nums, part...)
		}
		o := 0
		delta := nums[o]
		o++
		if delta.Sign() == 0 {
			return nil, abort(mpcAbortF("dealer", mpcIntP(dealerID), id, "the dealer gave me a zero verification key", ""))
		}
		pr := &MpcNetPrep{Mode: "trusted-dealer", Tagged: true, Delta: delta}
		w := MpcPaWidth(n, true)
		for l := 0; l < K; l++ {
			a, err := MpcPaParse(nums, o, id, n, true)
			if err != nil {
				return fail(err)
			}
			pr.Alpha = append(pr.Alpha, a)
			o += w
		}
		for t := 0; t < lay.triples; t++ {
			var sh []MpcAW
			for s := 0; s < MpcSharingsPerTriple(P); s++ {
				a, err := MpcAwParse(nums, o, id, n, K, true)
				if err != nil {
					return fail(err)
				}
				sh = append(sh, a)
				o += aw
			}
			pr.Triples = append(pr.Triples, sh)
		}
		for q := 0; q < lay.inputs; q++ {
			a, err := MpcAwParse(nums, o, id, n, K, true)
			if err != nil {
				return fail(err)
			}
			pr.Inputs = append(pr.Inputs, a)
			o += aw
		}
		pr.MyPlain = nums[o : o+C]
		return pr, nil
	}
	var prep *MpcNetPrep
	var err error
	if mode == "trusted-dealer" {
		prep, err = recvDealer()
	} else {
		prep, err = mpcRunOfflineNet(mpcOfflineArgs{mesh: mesh, id: id, n: n, C: C, keys: K, partners: P, sessionID: sessionID, input: v, Q: Q, behavior: cfg.Behavior,
			exchange: func(rd string, mine func(int) any, parse mpcParse, to time.Duration) (map[int]any, error) {
				return exchangeT(rd, mine, parse, nil, false, nil, to)
			},
			bad: bad, arr: arr, fail: abort})
	}
	if err != nil {
		return nil, err
	}
	ob1, ib1 := totals()
	rounds = append(rounds, MpcRoundStat{Rd: "prep", Ms: float64(time.Since(prepStart).Microseconds()) / 1000, BytesOut: ob1 - ob0, BytesIn: ib1 - ib0})

	env := MpcPaEnv{ID: id, N: n, Delta: prep.Delta, Tagged: prep.Tagged}
	one := big.NewInt(1)
	addPub := func(x MpcAW, c *big.Int) MpcAW { return MpcWAddPublic(env, x, c, prep.Alpha) }
	not := func(x MpcAW) MpcAW { return addPub(MpcWNeg(x), one) }
	var opened []mpcOpened

	// open authenticated values: broadcast value shares, verify the pairwise tags, record for the MAC-check
	openMany := func(rd string, ws []MpcAW) ([]*big.Int, error) {
		sendVals := make([]*big.Int, len(ws))
		macs := make([][]MpcPA, len(ws))
		for i, x := range ws {
			sendVals[i] = x.V.X
			macs[i] = x.M
		}
		if behRound == rd {
			switch beh {
			case "open-lie":
				sendVals[0] = MpcFAdd(sendVals[0], one)
			case "mac-lie":
				lied := append([]MpcPA(nil), macs[0]...)
				lied[0].X = MpcFAdd(lied[0].X, one)
				macs[0] = lied
			}
		}
		common := mpcFlatHex(sendVals)
		mineFn := func(peer int) any {
			if behRound == rd {
				switch beh {
				case "equivocate":
					if peer == others[0] {
						out := append([]any(nil), common...)
						out[0] = MpcHx(MpcFAdd(sendVals[0], one))
						return out
					}
				case "short-array":
					return common[1:]
				case "noncanonical":
					out := append([]any(nil), common...)
					out[0] = MpcHx(MpcPrime)
					return out
				}
			}
			return common
		}
		got, err := exchange(rd, mineFn, arrParse(len(ws)), common, true, nil)
		if err != nil {
			return nil, err
		}
		tags, err := exchange(rd+".t", func(peer int) any {
			ts := make([]*big.Int, len(ws))
			for i, x := range ws {
				ts[i] = x.V.Tag[peer]
				if beh == "bad-tag" && behRound == rd && i == 0 {
					ts[i] = MpcFAdd(ts[i], one)
				}
			}
			return mpcFlatHex(ts)
		}, arrParse(len(ws)), nil, false, nil)
		if err != nil {
			return nil, err
		}
		for _, p := range others {
			for i := range ws {
				if !MpcPaVerify(env, ws[i].V, p, asArr(got[p])[i], asArr(tags[p])[i]) {
					return nil, abort(mpcAbortF("mac-check", mpcIntP(p), id,
						fmt.Sprintf("pairwise MAC on party %d's opened share failed in round '%s' (index %d): the share or its tag is not what the dealer issued", p, rd, i), ""))
				}
			}
		}
		out := make([]*big.Int, len(ws))
		for i := range ws {
			sum := sendVals[i]
			for _, p := range others {
				sum = MpcFAdd(sum, asArr(got[p])[i])
			}
			out[i] = sum
			opened = append(opened, mpcOpened{sum, macs[i]})
		}
		return out, nil
	}

	// coin flip (commit / open of a random seed) -> a joint public seed
	coin := func(label string, tamperOpen bool) ([]byte, error) {
		mySeed := make([]byte, 32)
		if _, err := rand.Read(mySeed); err != nil {
			return nil, abort(mpcAbortF("local", nil, id, "no randomness: "+err.Error(), ""))
		}
		commitOf := func(p int, sd []byte) string {
			return hex.EncodeToString(mpcSha("seed", sessionID, label, strconv.Itoa(p), sd))
		}
		mine := commitOf(id, mySeed)
		commits, err := exchange(label+"-c", func(int) any { return mine }, hex64Parse("bad commitment"), mine, true, nil)
		if err != nil {
			return nil, err
		}
		seeds, err := exchange(label+"-o", func(int) any {
			if tamperOpen && beh == "bad-coin-open" {
				junk := make([]byte, 32)
				_, _ = rand.Read(junk)
				return hex.EncodeToString(junk)
			}
			return hex.EncodeToString(mySeed)
		}, func(p int, raw any) (any, error) {
			s, ok := raw.(string)
			if !ok || !mpcHex64.MatchString(s) {
				return nil, bad(p, "bad seed")
			}
			sd, _ := hex.DecodeString(s)
			if commitOf(p, sd) != commits[p].(string) {
				return nil, mpcAbortF("commitment", mpcIntP(p), id, fmt.Sprintf("party %d opened a coin seed that does not match its commitment", p), "")
			}
			return sd, nil
		}, hex.EncodeToString(mySeed), true, nil)
		if err != nil {
			return nil, err
		}
		parts := []any{"joint", sessionID, label}
		for p := 0; p < n; p++ {
			if p == id {
				parts = append(parts, mySeed)
			} else {
				parts = append(parts, seeds[p].([]byte))
			}
		}
		return mpcSha(parts...), nil
	}

	// ---- sacrifice: certify every triple against its partners before it is used ----
	nT := len(prep.Triples)
	if nT > 0 {
		joint1, err := coin("coin1", false)
		if err != nil {
			return nil, err
		}
		idx := func(t, r int) int { return t*P + r }
		var rhoW []MpcAW
		for t := 0; t < nT; t++ {
			tr := prep.Triples[t]
			a, parts := tr[0], tr[3:]
			for r := 0; r < P; r++ {
				rhoW = append(rhoW, MpcWSub(MpcWScale(a, mpcChallenge(joint1, "sac", idx(t, r))), parts[2*r]))
			}
		}
		rho, err := openMany("sac-rho", rhoW)
		if err != nil {
			return nil, err
		}
		var tauW []MpcAW
		for t := 0; t < nT; t++ {
			tr := prep.Triples[t]
			b, c, parts := tr[1], tr[2], tr[3:]
			for r := 0; r < P; r++ {
				e := mpcChallenge(joint1, "sac", idx(t, r))
				tauW = append(tauW, MpcWSub(MpcWSub(MpcWScale(c, e), parts[2*r+1]), MpcWScale(b, rho[idx(t, r)])))
			}
		}
		tau, err := openMany("sac-tau", tauW)
		if err != nil {
			return nil, err
		}
		for badAt, x := range tau {
			if x.Sign() == 0 {
				continue
			}
			// Dealer-free mode: the triple is discarded, so its OT transcript can be disclosed and audited to name a party that fed
			// a wrong operand into a triple product. Every honest party reaches this point together.
			var attributed *int
			note := ""
			if fx := prep.Forensics; prep.Mode == "no-dealer" && fx != nil {
				bt := badAt / P
				mine := fx.Disclose(bt)
				dl := cfg.ForensicDeadlineMs
				if dl <= 0 {
					dl = MpcDefaultForensicDeadlineMs
				}
				got, err := mpcExchangeDisclosures(sessionID, id, n, bt, mine, fx.Slots, fx.Rows, dl,
					func(rd string, m func(int) any, parse mpcParse, to time.Duration) (map[int]any, error) {
						return exchangeT(rd, m, parse, nil, false, nil, to)
					}, bad)
				if err != nil {
					return nil, err
				}
				all := map[int][]MpcSlotDisclosure{id: mine}
				for p, d := range got {
					all[p] = d
				}
				res, err := MpcAuditDisclosures(all, fx.Gadget)
				if err != nil {
					return nil, abort(mpcAbortF("local", nil, id, err.Error(), ""))
				}
				if b, ok := MpcBlameFrom(id, res); ok {
					attributed = &b
					note = fmt.Sprintf(" (OT transcript audit names party %d)", b)
				} else {
					note = fmt.Sprintf(" (OT transcript audit: %d inconsistent pair(s), no party can be named from this view: a pair failure between two other parties is not evidence against either of them to me)", len(res.PairBad))
				}
			}
			detail := fmt.Sprintf("triple sacrifice FAILED at triple %d (partner %d): c != a*b in the offline material; aborting with no output%s", badAt/P, badAt%P, note)
			if prep.Mode == "trusted-dealer" {
				return nil, abort(mpcAbortF("dealer", mpcIntP(dealerID), id, detail, ""))
			}
			blamed := attributed
			if blamed == nil && n == 2 {
				blamed = mpcIntP(1 - id)
			}
			return nil, abort(mpcAbortF("mac-check", blamed, id, detail, "the triple sacrifice failed in dealer-free mode and the OT transcript audit of this party's own view names no one (a failing pair that does not involve me is not evidence I can use, and an accusation is never accepted against a third party)"))
		}
	}

	// ---- inputs: bit k of owner o is the C-vector [allow, t-therm(3), r-therm(Q)] ----
	tb, _ := MpcThermometerEncode(float64(v.T), mpcTM)
	rb, _ := MpcThermometerEncode(float64(v.RQuant), Q)
	myBits := append(append([]int{v.Allow}, tb...), rb...)
	var bitShare func(owner, k int) MpcAW
	if prep.Mode == "trusted-dealer" {
		masked := make([]*big.Int, C)
		for k, b := range myBits {
			masked[k] = MpcFSub(big.NewInt(int64(b)), prep.MyPlain[k])
		}
		maskedMsg := mpcFlatHex(masked)
		gotMasked, err := exchange("inputs", func(int) any { return maskedMsg }, arrParse(C), maskedMsg, true, nil)
		if err != nil {
			return nil, err
		}
		bitShare = func(owner, k int) MpcAW {
			pub := masked[k]
			if owner != id {
				pub = asArr(gotMasked[owner])[k]
			}
			return addPub(prep.Inputs[owner*C+k], pub)
		}
	} else {
		// No dealer: the inputs are already authenticated sharings of the bits. Run the input-consistency check: open a random
		// masked combination (the opening joins the batched MAC-check below).
		bitShare = func(owner, k int) MpcAW { return prep.Inputs[owner*C+k] }
		jointIn, err := coin("coin-in", false)
		if err != nil {
			return nil, err
		}
		w := *prep.CheckMask
		for q := 0; q < n*C; q++ {
			w = MpcWAdd(w, MpcWScale(prep.Inputs[q], mpcChallenge(jointIn, "in", q)))
		}
		if _, err := openMany("in-check", []MpcAW{w}); err != nil {
			return nil, err
		}
	}

	// ---- chains: acc_c over owners; allow uses AND, the others OR (= NOT AND NOT) ----
	isOr := func(c int) bool { return c != 0 }
	acc := make([]MpcAW, C)
	for c := range acc {
		b0 := bitShare(0, c)
		if isOr(c) {
			b0 = not(b0)
		}
		acc[c] = b0
	}
	mults := 0
	for s := 1; s < n; s++ {
		trs := prep.Triples[(s-1)*C : s*C]
		ds, es := make([]MpcAW, C), make([]MpcAW, C)
		for c := 0; c < C; c++ {
			y := bitShare(s, c)
			if isOr(c) {
				y = not(y)
			}
			ds[c] = MpcWSub(acc[c], trs[c][0])
			es[c] = MpcWSub(y, trs[c][1])
		}
		pub, err := openMany("mul"+strconv.Itoa(s-1), append(ds, es...))
		if err != nil {
			return nil, err
		}
		next := make([]MpcAW, C)
		for c := range next {
			d, e := pub[c], pub[C+c]
			ta, tb2, tc := trs[c][0], trs[c][1], trs[c][2]
			z := MpcWAdd(tc, MpcWAdd(MpcWScale(tb2, d), MpcWScale(ta, e)))
			next[c] = addPub(z, MpcFMul(d, e))
		}
		acc = next
		mults += C
	}

	// ---- outputs: allow as-is; the or-chains are NOT of the product ----
	outShares := make([]MpcAW, C)
	for c, x := range acc {
		outShares[c] = x
		if isOr(c) {
			outShares[c] = not(x)
		}
	}
	outVals, err := openMany("out", outShares)
	if err != nil {
		return nil, err
	}

	// ---- MAC-check: coin flip for the challenges, one independent challenge vector per key ----
	joint, err := coin("coin", true)
	if err != nil {
		return nil, err
	}
	chal := func(l, j int) *big.Int { return mpcChallenge(joint, "mac"+strconv.Itoa(l), j) }
	combo := func(l int, pick func(o mpcOpened) *big.Int) *big.Int {
		g := new(big.Int)
		for j, o := range opened {
			g = MpcFAdd(g, MpcFMul(chal(l, j), pick(o)))
		}
		return g
	}
	aPub, Gamma, sigma := make([]*big.Int, K), make([]*big.Int, K), make([]*big.Int, K)
	for l := 0; l < K; l++ {
		aPub[l] = combo(l, func(o mpcOpened) *big.Int { return o.val })
		Gamma[l] = combo(l, func(o mpcOpened) *big.Int { return o.mac[l].X })
		sigma[l] = MpcFSub(Gamma[l], MpcFMul(prep.Alpha[l].X, aPub[l]))
	}
	sigNonce := make([]byte, 32)
	if _, err := rand.Read(sigNonce); err != nil {
		return nil, abort(mpcAbortF("local", nil, id, "no randomness: "+err.Error(), ""))
	}
	sigCommit := func(p int, s []*big.Int, nonce []byte) string {
		hs := make([]string, len(s))
		for i, x := range s {
			hs[i] = MpcHx(x)
		}
		return hex.EncodeToString(mpcSha("sigma", sessionID, strconv.Itoa(p), strings.Join(hs, ","), nonce))
	}
	sigmaSent := sigma
	if beh == "sigma-lie" {
		sigmaSent = append([]*big.Int(nil), sigma...)
		sigmaSent[0] = MpcFAdd(sigmaSent[0], one)
	}
	mySigCommit := sigCommit(id, sigmaSent, sigNonce)
	sigCommits, err := exchange("sig-c", func(int) any { return mySigCommit }, hex64Parse("bad commitment"), mySigCommit, true, nil)
	if err != nil {
		return nil, err
	}
	mySigOpen := map[string]any{"s": mpcFlatHex(sigmaSent), "nonce": hex.EncodeToString(sigNonce)}
	sigCanon := func(x any) string { // the reference member order (s, nonce), so every implementation hashes the same text
		m, _ := x.(map[string]any)
		s, _ := MpcStringify(m["s"])
		nn, _ := MpcStringify(m["nonce"])
		return `{"s":` + s + `,"nonce":` + nn + `}`
	}
	sigOpens, err := exchange("sig-o", func(int) any {
		if beh == "bad-sigma-open" {
			lied := append([]*big.Int(nil), sigmaSent...)
			lied[0] = MpcFAdd(lied[0], one)
			return map[string]any{"s": mpcFlatHex(lied), "nonce": mySigOpen["nonce"]}
		}
		return mySigOpen
	}, func(p int, raw any) (any, error) {
		o, _ := raw.(map[string]any)
		sv := MpcUnhxArray(o["s"], K)
		nonce, _ := o["nonce"].(string)
		if sv == nil || !mpcHex64.MatchString(nonce) {
			return nil, bad(p, "bad sigma opening")
		}
		nb, _ := hex.DecodeString(nonce)
		if sigCommit(p, sv, nb) != sigCommits[p].(string) {
			return nil, mpcAbortF("commitment", mpcIntP(p), id, fmt.Sprintf("party %d opened a MAC residual that does not match its commitment", p), "")
		}
		return sv, nil
	}, mySigOpen, true, sigCanon)
	if err != nil {
		return nil, err
	}
	macFailed := false
	for l := 0; l < K; l++ {
		r := sigmaSent[l]
		for _, p := range others {
			r = MpcFAdd(r, asArr(sigOpens[p])[l])
		}
		if r.Sign() != 0 {
			macFailed = true
		}
	}

	// ---- transcript echo: everyone must have seen the same broadcasts ----
	digest := hex.EncodeToString(transcript.Sum(nil))
	digests, err := exchange("digest", func(int) any { return digest }, hex64Parse("bad digest"), digest, true, nil)
	if err != nil {
		return nil, err
	}
	for _, p := range others {
		if digests[p].(string) != digest {
			return nil, abort(mpcAbortF("equivocation", mpcIntP(p), id, fmt.Sprintf("transcript digest of party %d differs from mine (a broadcast was inconsistent)", p), ""))
		}
	}

	if macFailed {
		msg := "MAC-check FAILED: an opened value or MAC share was inconsistent; aborting with no output"
		// every party opens its combined MAC shares with their pairwise tags; each verifier checks them. Abort claims that arrive
		// during this round are read in link order so the cheater's own abort cannot pre-empt an honest party.
		mesh.SetDeferAborts(true)
		blames, err := exchange("blame", func(peer int) any {
			gt, at, a := make([]*big.Int, K), make([]*big.Int, K), make([]*big.Int, K)
			for l := 0; l < K; l++ {
				gt[l] = combo(l, func(o mpcOpened) *big.Int { return o.mac[l].Tag[peer] })
				a[l], at[l] = prep.Alpha[l].X, prep.Alpha[l].Tag[peer]
			}
			return map[string]any{"g": mpcFlatHex(Gamma), "gt": mpcFlatHex(gt), "a": mpcFlatHex(a), "at": mpcFlatHex(at)}
		}, func(p int, raw any) (any, error) {
			o, _ := raw.(map[string]any)
			var out [4][]*big.Int
			for i, k := range []string{"g", "gt", "a", "at"} {
				a, err := arr(p, o[k], K)
				if err != nil {
					return nil, err
				}
				out[i] = a
			}
			return out, nil
		}, nil, false, nil)
		mesh.SetDeferAborts(false)
		if err != nil {
			return nil, err
		}
		for _, p := range others {
			b := blames[p].([4][]*big.Int)
			for l := 0; l < K; l++ {
				keyCombo := combo(l, func(o mpcOpened) *big.Int { return o.mac[l].Key[p] })
				if MpcFAdd(keyCombo, MpcFMul(env.Delta, b[0][l])).Cmp(b[1][l]) != 0 {
					return nil, abort(mpcAbortF("mac-check", mpcIntP(p), id, fmt.Sprintf("%s - party %d's MAC share (key %d) does not match its pairwise tag", msg, p, l), ""))
				}
				if MpcFAdd(prep.Alpha[l].Key[p], MpcFMul(env.Delta, b[2][l])).Cmp(b[3][l]) != 0 {
					return nil, abort(mpcAbortF("mac-check", mpcIntP(p), id, fmt.Sprintf("%s - party %d's key share (key %d) does not match its pairwise tag", msg, p, l), ""))
				}
				if MpcFSub(b[0][l], MpcFMul(b[2][l], aPub[l])).Cmp(asArr(sigOpens[p])[l]) != 0 {
					return nil, abort(mpcAbortF("mac-check", mpcIntP(p), id, fmt.Sprintf("%s - party %d's opened MAC residual (key %d) is not what its authenticated shares give", msg, p, l), ""))
				}
			}
		}
		// every other party's data is consistent with its pairwise tags, and so is mine: the offline material disagrees
		if prep.Mode == "trusted-dealer" {
			return nil, abort(mpcAbortF("dealer", mpcIntP(dealerID), id, msg+" - every party's shares verify, so the trusted dealer's MACs are inconsistent with its values", ""))
		}
		var blamed *int
		if n == 2 {
			blamed = mpcIntP(1 - id)
		}
		return nil, abort(mpcAbortF("mac-check", blamed, id, msg+" - every party's shares verify under its pairwise tags, so the offline material is inconsistent (a wrong OT operand): not attributable",
			"every party's shares verify under its pairwise tags, so the failure is in the offline OT material and no party can be named"))
	}

	// ---- only now decode ----
	bit := func(x *big.Int) int {
		if x.Cmp(one) == 0 {
			return 1
		}
		return 0
	}
	bits := make([]int, len(outVals))
	for i, x := range outVals {
		bits[i] = bit(x)
	}
	tDec := min(3, max(1, MpcThermometerDecode(bits[1:1+mpcTM])))
	composed := MpcComposedDecision{Allow: bits[0], T: tDec, RQuant: MpcThermometerDecode(bits[1+mpcTM:])}
	mesh.Finish()
	return &MpcPartyResult{ID: id, N: n, Q: Q, Composed: composed, Rounds: rounds, TranscriptDigest: digest,
		WallMs: float64(time.Since(t0).Microseconds()) / 1000, Multiplications: mults, Opens: len(opened), OfflineMode: prep.Mode,
		MacKeys: K, SacrificedTriples: nT, SacrificePartners: P, IdentifiableAbort: prep.Tagged}, nil
}
