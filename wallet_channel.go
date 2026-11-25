package pca

// The trusted question channel of the wallet (PCA Intent Layer v2): one instance per session. SELECTION belongs to the verifier
// (questions enter only as a site-signed intent_required, re-derived by the wallet, or as a structured agent clarification whose
// cell the wallet picks itself); RENDERING and ORDERING belong to the wallet; friction scales with harm; canaries are inserted with
// probability rho and update only the noise counts; caps and a freeze on the estimated false-yes rate bound the questions; a cell
// is asked at most once per session; under estimated noise an irreversible cell needs two confirmations.
//
// A channel is not safe for concurrent use.

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
)

const walletB64uAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// WalletSite is the site as verified from its discovery document (origin and signing keys) and the wallet's own directory (name).
type WalletSite struct {
	Origin string
	Name   string
	Keys   any // the site's discovery keys: [{kid, alg, pk, pq_pk?}]
}

// WalletDevice is the principal's registered security keys: credential id -> public key (a JWK object), the relying party and the
// allowed origins; SignCounts holds the last signature counter of each credential and is updated on every verified assertion.
type WalletDevice struct {
	RPID        string
	Origins     []string
	Credentials map[string]any
	SignCounts  map[string]float64
}

// WalletChannelOptions configure a channel.
type WalletChannelOptions struct {
	Omega         *WalletOmega
	Session       string
	MapDigest     func() string
	PrincipalSeed []byte
	Site          WalletSite
	View          WalletView
	Hourly        *WalletSlidingWindow
	Noise         func() WalletNoiseCounts
	OnNoise       func(WalletNoiseCounts)
	Rand          WalletRand
	Now           func() float64

	// Lift maps the attempted action to its outcome; nil is the default projection (resource and scalar params).
	Lift func(action any) (any, error)
	// LiftCandidate maps an agent clarification candidate to its outcome; nil is the candidate itself.
	LiftCandidate func(cand any) (any, error)
	// Reversibility is the value-dependent reversibility of a cell; nil is the verb's.
	Reversibility func(vs *WalletVerb, box [][]int) string
	Harm          *WalletHarm

	StatementText *string
	Units         any
	Sensitivity   map[string]string
	IdentityPaths []string
	PerSession    *float64 // default 6
	PerHour       *float64 // default 12
	Rho           *float64
	Fatigue       *WalletFatigue
	MaxPerScreen  *float64 // default 3
	MaxBoxCells   *float64 // default 4096
	Friction      map[string]any
	Device        *WalletDevice
}

type walletItem struct {
	id, kind, source, verb string
	box                    [][]int
	coords                 map[string]any
	card                   map[string]any
	action                 any
	actionDigest           string
	irreversible           bool
	expected               int
	weight                 float64
	expiresAt              *float64
	jit                    bool
	vs                     *WalletVerb
	flat                   int
	shownOn                int // 0: not shown yet
	notBefore              int // 0: any screen
	first                  map[string]any
}

// WalletChannel is the trusted question channel of one session.
type WalletChannel struct {
	o                  WalletChannelOptions
	pending            map[string]*walletItem
	asked              map[string]bool
	canaryUsed         map[string]bool
	knownYes           []WalletCellRef
	confirmations      map[string][]WalletConfirmation
	refusedWhileFrozen []any
	sessionQuestions   int
	canaries           int
	screenNo           int
}

// NewWalletChannel builds the channel of a session.
func NewWalletChannel(o WalletChannelOptions) *WalletChannel {
	return &WalletChannel{o: o, pending: map[string]*walletItem{}, asked: map[string]bool{}, canaryUsed: map[string]bool{},
		confirmations: map[string][]WalletConfirmation{}}
}

func (c *WalletChannel) perSession() float64 {
	if c.o.PerSession != nil {
		return *c.o.PerSession
	}
	return 6
}

func (c *WalletChannel) perHour() float64 {
	if c.o.PerHour != nil {
		return *c.o.PerHour
	}
	return 12
}

func (c *WalletChannel) fatigue() WalletFatigue {
	if c.o.Fatigue != nil {
		return *c.o.Fatigue
	}
	return WalletDefaultFatigue
}

func (c *WalletChannel) harm() *WalletHarm {
	if c.o.Harm != nil {
		return c.o.Harm
	}
	return WalletDefaultHarm
}

// Noise is the current noise state (eta+ under load, frozen?).
func (c *WalletChannel) Noise() (WalletNoiseState, error) {
	return WalletComputeNoiseState(c.o.Noise(), float64(c.o.Hourly.Count(c.o.Now())), c.fatigue())
}

// Admission is the admission policy the learner should use now (tau, eta+, eta-; double confirmation).
func (c *WalletChannel) Admission() (WalletAdmission, error) {
	st, err := c.Noise()
	if err != nil {
		return WalletAdmission{}, err
	}
	return WalletAdmissionPolicy(st, c.fatigue())
}

// QuestionsAsked is the number of questions this session has asked.
func (c *WalletChannel) QuestionsAsked() int { return c.sessionQuestions }

func (c *WalletChannel) newID() (string, error) {
	for {
		var sb strings.Builder
		sb.WriteString("q_")
		for i := 0; i < 10; i++ {
			r, err := c.o.Rand()
			if err != nil {
				return "", err
			}
			sb.WriteByte(walletB64uAlphabet[int(math.Floor(r*64))%64])
		}
		if c.pending[sb.String()] == nil {
			return sb.String(), nil
		}
	}
}

type walletBoxStats struct{ weight, meanHarm float64 }

func (c *WalletChannel) boxStats(vs *WalletVerb, box [][]int) *walletBoxStats {
	cells := WalletBoxCells(box)
	mx := 4096.0
	if c.o.MaxBoxCells != nil {
		mx = *c.o.MaxBoxCells
	}
	if float64(len(cells)) > mx {
		return nil
	}
	m, mh := 0.0, 0.0
	for _, idx := range cells {
		mass, h := WalletCellStats(vs, idx, c.harm())
		m += mass
		mh += float64(mass * h)
	}
	st := &walletBoxStats{weight: mh}
	if m > 0 {
		st.meanHarm = mh / m
	}
	return st
}

func (c *WalletChannel) reversibilityOf(vs *WalletVerb, box [][]int) string {
	if c.o.Reversibility != nil {
		return c.o.Reversibility(vs, box)
	}
	return vs.Reversibility
}

func (c *WalletChannel) frictionOf(vs *WalletVerb, box [][]int, meanHarm float64, siteMin any, irreversible bool) (string, error) {
	provenance := []any{}
	widens := false
	for k := range vs.Dims {
		d := &vs.Dims[k]
		if strings.HasPrefix(d.Path, "env.prov.") && d.Kind == "cat" {
			param := strings.TrimPrefix(d.Path, "env.prov.")
			levels := []any{}
			for _, i := range box[k] {
				v := d.Values[i]
				text := v.Value
				if v.Kind == "prefix" {
					text += "*"
				}
				for _, p := range walletSplitLevels.Split(text, -1) {
					levels = append(levels, p)
				}
			}
			sens := c.o.Sensitivity[param]
			if sens == "" {
				sens = "material"
			}
			provenance = append(provenance, map[string]any{"path": param, "sensitivity": sens, "levels": levels})
		}
		if d.Kind == "cat" && walletIndexOf(c.o.IdentityPaths, d.Path) >= 0 {
			for _, i := range box[k] {
				if d.Values[i].Kind != "exact" {
					widens = true
				}
			}
		}
	}
	inp := map[string]any{"reversibility": c.reversibilityOf(vs, box), "expectedHarm": meanHarm, "provenance": provenance, "widensCriticalIdentity": widens}
	if jsTruthy(siteMin) {
		inp["siteMin"] = siteMin
	}
	th := c.o.Friction
	if len(th) == 0 {
		th = nil
	}
	f, err := WalletFrictionFor(walletNumbersToJSON(inp), th)
	if err != nil {
		return "", err
	}
	tier := f["tier"].(string)
	if irreversible {
		adm, err := c.Admission()
		if err != nil {
			return "", err
		}
		if adm.DoubleConfirmIrreversible {
			tier = WalletMaxFriction(tier, "typed")
		}
	}
	return tier, nil
}

// walletNumbersToJSON turns the float64 members of a constructed input into JSON numbers.
func walletNumbersToJSON(m map[string]any) map[string]any {
	if h, ok := m["expectedHarm"].(float64); ok {
		m["expectedHarm"] = jsNumber(h)
	}
	return m
}

type walletRendered struct {
	card     map[string]any
	friction string
}

func (c *WalletChannel) render(kind, verb string, coords map[string]any, friction string, action any, vs *WalletVerb, box [][]int, reason string) (*walletRendered, error) {
	base := map[string]any{"verb": verb, "coords": coords, "site": map[string]any{"origin": c.o.Site.Origin, "name": c.o.Site.Name}}
	if c.o.StatementText != nil {
		base["statementText"] = *c.o.StatementText
	}
	base["reversibility"] = c.reversibilityOf(vs, box)
	if jsTruthy(c.o.Units) {
		base["units"] = c.o.Units
	}
	if jsTruthy(action) {
		base["action"] = action
	}
	base["kind"] = kind
	if reason != "" {
		base["reason"] = reason
	}
	base["friction"] = friction
	r, err := WalletRenderCard(c.o.Omega, base, nil)
	if err != nil {
		return nil, err
	}
	// a typed question needs a value to type; with none on the card, the only stronger tier is the device
	if r["ok"] == true && WalletFrictionRank(friction) == WalletFrictionRank("typed") && !jsTruthy(r["card"].(map[string]any)["typed"]) {
		base["friction"] = "device"
		if r, err = WalletRenderCard(c.o.Omega, base, nil); err != nil {
			return nil, err
		}
	}
	if r["ok"] != true {
		return nil, nil
	}
	card := r["card"].(map[string]any)
	f, _ := card["friction"].(string)
	return &walletRendered{card: card, friction: f}, nil
}

func (c *WalletChannel) gate() (map[string]any, error) {
	st, err := c.Noise()
	if err != nil {
		return nil, err
	}
	if st.Frozen {
		return map[string]any{"ok": false, "code": "frozen", "reason": "the estimated false-yes rate is above η_stop: no more questions this session"}, nil
	}
	if !(float64(c.sessionQuestions) < c.perSession()) {
		return map[string]any{"ok": false, "code": "cap_session", "reason": "at most " + jsNumberString(c.perSession()) + " questions per session"}, nil
	}
	if now := c.o.Now(); !(finite(now) && float64(c.o.Hourly.Count(now)) < c.perHour()) {
		return map[string]any{"ok": false, "code": "cap_hour", "reason": "at most " + jsNumberString(c.perHour()) + " questions per hour"}, nil
	}
	return map[string]any{"ok": true}, nil
}

func (c *WalletChannel) enqueue(it *walletItem) {
	best := -1
	for _, idx := range WalletBoxCells(it.box) {
		if f := WalletFlatIndex(it.vs, idx); best < 0 || f < best {
			best = f
		}
	}
	it.flat = best
	c.pending[it.id] = it
}

func (c *WalletChannel) count() error {
	c.sessionQuestions++
	ok, err := c.o.Hourly.TryAdd(c.o.Now(), 9007199254740991)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("unreachable")
	}
	return nil
}

func (c *WalletChannel) maybeCanary() error {
	exclude := map[string]bool{}
	for k := range c.canaryUsed {
		exclude[k] = true
	}
	lowHarm := true
	for _, p := range c.pending {
		for _, idx := range WalletBoxCells(p.box) {
			exclude[WalletCellKey(p.verb, idx)] = true
		}
		if p.kind == "real" && !(WalletFrictionRank(p.card["friction"]) <= WalletFrictionRank("hold")) {
			lowHarm = false
		}
	}
	v := c.o.View
	ctx := WalletCanaryCtx{
		Omega: c.o.Omega, Confirmed: v.Confirmed(), KnownYes: c.knownYes, Exclude: exclude, Rand: c.o.Rand, Rho: c.o.Rho,
		LowHarmSession: lowHarm, CanariesSoFar: float64(c.canaries),
		KnownNo: func(verb string, idx []int) string {
			if v.OutsideCeiling(verb, idx) {
				return "ceiling"
			}
			if v.Vetoed(verb, idx) {
				return "veto"
			}
			return ""
		},
	}
	pick, err := WalletPickCanary(ctx)
	if err != nil || pick == nil {
		return err
	}
	vs := c.o.Omega.Verb(pick.Verb)
	box := make([][]int, len(pick.Idx))
	for i, x := range pick.Idx {
		box[i] = []int{x}
	}
	st := c.boxStats(vs, box)
	if st == nil {
		return nil
	}
	coords, err := WalletCoordsOfCell(vs, pick.Idx)
	if err != nil {
		return err
	}
	action := map[string]any{"verb": pick.Verb, "values": WalletCellRep(vs, pick.Idx)["values"]}
	friction, err := c.frictionOf(vs, box, st.meanHarm, nil, false)
	if err != nil {
		return err
	}
	r, err := c.render("question", pick.Verb, coords, friction, action, vs, box, "")
	if err != nil || r == nil {
		return err
	}
	c.canaries++
	c.canaryUsed[WalletCellKey(pick.Verb, pick.Idx)] = true
	id, err := c.newID()
	if err != nil {
		return err
	}
	c.enqueue(&walletItem{id: id, kind: "canary", source: "elicitation", verb: pick.Verb, box: box, coords: coords, card: r.card, action: action,
		expected: pick.Expected, weight: st.weight, vs: vs})
	return nil
}

func walletRefuse(code, reason string) map[string]any {
	return map[string]any{"ok": false, "code": code, "reason": reason}
}

// Receive takes a site-signed intent_required (delivered directly, or relayed unchanged by the agent) together with the action the
// agent attempted. Every check fails closed; an error is a refusal the reference throws.
func (c *WalletChannel) Receive(ir any, action any) (map[string]any, error) {
	now := c.o.Now()
	v := WalletVerifyIntentRequired(ir, c.o.Site.Keys, jsNumber(now))
	if v["ok"] != true {
		return walletRefuse("bad_site_signature", v["reason"].(string)), nil
	}
	irm := ir.(map[string]any)
	if irm["session"] != any(c.o.Session) {
		return walletRefuse("wrong_session", "the question is for another session"), nil
	}
	if irm["map_digest"] != any(c.o.MapDigest()) {
		return walletRefuse("stale_map", "the question names another map version"), nil
	}
	am, ok := action.(map[string]any)
	if !ok {
		return nil, errors.New("action is not an object")
	}
	cell := irm["cell"].(map[string]any)
	mismatch := am["verb"] != cell["verb"]
	if !mismatch {
		digest, err := WalletActionDigest(am)
		if err != nil {
			return nil, err
		}
		mismatch = digest != irm["action_digest"]
	}
	if mismatch {
		return walletRefuse("action_mismatch", "the action does not match the signed action digest"), nil
	}
	var lifted any
	var err error
	if c.o.Lift != nil {
		if lifted, err = c.o.Lift(action); err != nil {
			return nil, err
		}
	} else if lifted, err = WalletActionValues(action); err != nil {
		return nil, err
	}
	cellVerb, hasVerb := cell["verb"]
	if !hasVerb {
		cellVerb = jsUndefinedValue{}
	}
	r, err := WalletResolveCoords(c.o.Omega, cellVerb, cell["coords"])
	if err != nil {
		return nil, err
	}
	if !r.OK {
		return walletRefuse("cell_mismatch", r.Reason), nil
	}
	atVS, atIdx, err := WalletCellOfAction(c.o.Omega, lifted)
	if err != nil {
		return nil, err
	}
	if atVS == nil || !WalletCellInBox(r.Box, atIdx) {
		return walletRefuse("cell_mismatch", "the action's cell (re-derived by the wallet) is not the cell the site names"), nil
	}
	st := c.boxStats(r.VS, r.Box)
	if st == nil {
		return walletRefuse("cell_too_large", "the question covers too many cells"), nil
	}
	cells := WalletBoxCells(r.Box)
	view := c.o.View
	verb := r.VS.Verb
	for _, idx := range cells {
		if view.OutsideCeiling(verb, idx) {
			return walletRefuse("not_uncertain", "the cell is outside a ceiling: the principal cannot widen it"), nil
		}
		if view.Vetoed(verb, idx) {
			return walletRefuse("not_uncertain", "the cell was vetoed"), nil
		}
	}
	pa := view.P(verb, atIdx)
	if !(pa > 0 && pa < 1) {
		why := "the cell is already in the grant"
		if pa <= 0 {
			why = "the cell is denied"
		}
		return walletRefuse("not_uncertain", why), nil
	}
	for _, idx := range cells {
		if c.asked[WalletCellKey(verb, idx)] {
			return walletRefuse("already_asked", "a cell is asked at most once per session"), nil
		}
	}
	g, err := c.gate()
	if err != nil {
		return nil, err
	}
	if g["ok"] != true {
		if g["code"] == "frozen" {
			c.refusedWhileFrozen = append(c.refusedWhileFrozen, map[string]any{"verb": verb, "coords": cell["coords"]})
		}
		return g, nil
	}
	irreversible := c.reversibilityOf(r.VS, r.Box) == "irreversible"
	friction, err := c.frictionOf(r.VS, r.Box, st.meanHarm, irm["friction"], irreversible)
	if err != nil {
		return nil, err
	}
	coords, _ := cell["coords"].(map[string]any)
	rendered, err := c.render("question", cell["verb"].(string), coords, friction, lifted, r.VS, r.Box, "")
	if err != nil {
		return nil, err
	}
	if rendered == nil {
		return walletRefuse("render_failed", "the card could not be rendered"), nil
	}
	qid := irm["question_id"].(string)
	if c.pending[qid] != nil {
		return walletRefuse("already_asked", "duplicate question id"), nil
	}
	for _, idx := range cells {
		c.asked[WalletCellKey(verb, idx)] = true
	}
	if err := c.count(); err != nil {
		return nil, err
	}
	exp := jsF(irm["expires_at"])
	c.enqueue(&walletItem{id: qid, kind: "real", source: "elicitation", verb: cell["verb"].(string), box: r.Box, coords: coords, card: rendered.card, action: lifted,
		actionDigest: irm["action_digest"].(string), irreversible: irreversible, weight: st.weight, expiresAt: &exp, jit: true, vs: r.VS})
	if err := c.maybeCanary(); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "questionId": qid, "friction": rendered.friction}, nil
}

// Clarify is an agent clarification: {candidates: [<= 8 structured actions], reason}, no text. Certain cells are answered at once
// (dry run); among the uncertain ones the wallet picks the most informative and asks it. The result carries a status.
func (c *WalletChannel) Clarify(body any) (map[string]any, error) {
	parsed := WalletParseClarifyRequest(body)
	if parsed["ok"] != true {
		return map[string]any{"status": wN(400), "verdicts": []any{}, "error": parsed["error"]}, nil
	}
	req := parsed["request"].(map[string]any)
	st, err := c.Noise()
	if err != nil {
		return nil, err
	}
	cands := req["candidates"].([]any)
	plan, err := WalletPlanClarification(WalletPlanInput{
		Omega: c.o.Omega, View: c.o.View, Candidates: cands, Lift: c.o.LiftCandidate, Asked: c.asked,
		EtaPos: math.Min(walletBelowHalf, st.EtaPosBar), EtaNeg: math.Min(walletBelowHalf, st.EtaNegBar), Harm: c.harm()})
	if err != nil {
		return nil, err
	}
	verdicts := plan["verdicts"]
	if plan["ask"] == nil {
		return map[string]any{"status": wN(200), "verdicts": verdicts}, nil
	}
	g, err := c.gate()
	if err != nil {
		return nil, err
	}
	if g["ok"] != true {
		status := 429
		if g["code"] == "frozen" {
			status = 200
		}
		return map[string]any{"status": wN(status), "verdicts": verdicts, "refused": g["code"]}, nil
	}
	ask := plan["ask"].(map[string]any)
	vs := c.o.Omega.Verb(ask["verb"].(string))
	idxAny := ask["idx"].([]any)
	idx := make([]int, len(idxAny))
	box := make([][]int, len(idxAny))
	for i, x := range idxAny {
		f, _ := jsNum(x)
		idx[i] = int(f)
		box[i] = []int{idx[i]}
	}
	stats := c.boxStats(vs, box)
	if stats == nil {
		return nil, errors.New("clarify: the cell is larger than the box cap")
	}
	coords, err := WalletCoordsOfCell(vs, idx)
	if err != nil {
		return nil, err
	}
	fi, _ := jsNum(ask["index"])
	raw := cands[int(fi)]
	action := raw
	if c.o.LiftCandidate != nil {
		if action, err = c.o.LiftCandidate(raw); err != nil {
			return nil, err
		}
	}
	irreversible := c.reversibilityOf(vs, box) == "irreversible"
	friction, err := c.frictionOf(vs, box, stats.meanHarm, nil, irreversible)
	if err != nil {
		return nil, err
	}
	rendered, err := c.render("clarification", vs.Verb, coords, friction, action, vs, box, req["reason"].(string))
	if err != nil {
		return nil, err
	}
	if rendered == nil {
		return map[string]any{"status": wN(200), "verdicts": verdicts, "refused": "render_failed"}, nil
	}
	qid, err := c.newID()
	if err != nil {
		return nil, err
	}
	c.asked[WalletCellKey(vs.Verb, idx)] = true
	if err := c.count(); err != nil {
		return nil, err
	}
	c.enqueue(&walletItem{id: qid, kind: "real", source: "clarification", verb: vs.Verb, box: box, coords: coords, card: rendered.card, action: action,
		irreversible: irreversible, weight: stats.weight, vs: vs})
	if err := c.maybeCanary(); err != nil {
		return nil, err
	}
	return map[string]any{"status": wN(200), "verdicts": verdicts, "questionId": qid}, nil
}

// ordered lists the pending items in display order: friction desc, E[h|c]*mu(c) desc, cell index asc, id asc.
func (c *WalletChannel) ordered() []*walletItem {
	items := make([]*walletItem, 0, len(c.pending))
	for _, it := range c.pending {
		items = append(items, it)
	}
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if ra, rb := WalletFrictionRank(a.card["friction"]), WalletFrictionRank(b.card["friction"]); ra != rb {
			return ra > rb
		}
		if a.weight != b.weight {
			return a.weight > b.weight
		}
		if a.flat != b.flat {
			return a.flat < b.flat
		}
		return compareUnits(utf16Units(a.id), utf16Units(b.id)) < 0
	})
	return items
}

// NextScreen is the next screen, or nil when nothing is waiting. A typed or device question is always alone; tap and hold
// questions share up to maxPerScreen.
func (c *WalletChannel) NextScreen() map[string]any {
	now := c.o.Now()
	for id, it := range c.pending {
		if it.expiresAt != nil && !(finite(now) && now <= *it.expiresAt) {
			delete(c.pending, id)
		}
	}
	items := []*walletItem{}
	for _, it := range c.ordered() {
		if it.shownOn == 0 {
			items = append(items, it)
		}
	}
	if len(items) == 0 {
		return nil
	}
	nxt := c.screenNo + 1
	eligible := []*walletItem{}
	for _, it := range items {
		if it.notBefore == 0 || nxt >= it.notBefore {
			eligible = append(eligible, it)
		}
	}
	c.screenNo = nxt
	if len(eligible) == 0 {
		return map[string]any{"screen": wN(nxt), "kind": "interstitial", "questions": []any{}}
	}
	picked := []*walletItem{eligible[0]}
	hold := WalletFrictionRank("hold")
	if WalletFrictionRank(eligible[0].card["friction"]) <= hold {
		mx := 3.0
		if c.o.MaxPerScreen != nil {
			mx = *c.o.MaxPerScreen
		}
		for _, it := range eligible[1:] {
			if float64(len(picked)) >= mx {
				break
			}
			if WalletFrictionRank(it.card["friction"]) <= hold {
				picked = append(picked, it)
			}
		}
	}
	qs := make([]any, len(picked))
	for i, it := range picked {
		it.shownOn = nxt
		qs[i] = map[string]any{"questionId": it.id, "card": it.card}
	}
	return map[string]any{"screen": wN(nxt), "kind": "questions", "questions": qs}
}

func (c *WalletChannel) challengeFor(it *walletItem, questionID string) (string, error) {
	var ad any
	if it.jit && it.irreversible && it.actionDigest != "" {
		ad = it.actionDigest
	}
	return WalletDeviceChallenge(questionID, it.card["rendered_digest"].(string), 1, ad)
}

// Answer takes the principal's response to a shown question.
func (c *WalletChannel) Answer(questionID string, response any) (map[string]any, error) {
	it := c.pending[questionID]
	if it == nil {
		return walletRefuse("unknown_question", "no such pending question"), nil
	}
	if it.shownOn == 0 {
		return walletRefuse("not_shown", "the question was never shown"), nil
	}
	now := c.o.Now()
	if it.expiresAt != nil && !(finite(now) && now <= *it.expiresAt) {
		delete(c.pending, questionID)
		return walletRefuse("expired", "the question expired"), nil
	}
	resp, ok := response.(map[string]any)
	if !ok {
		return nil, errors.New("response is not an object")
	}
	var partial map[string]any
	y := 1
	switch resp["answer"] {
	case "no":
		y = 0
	case "partly":
		pm, ok := resp["partial"].(map[string]any)
		if !ok {
			return nil, errors.New("partial is not an object")
		}
		e, err := WalletPartialError(it.card, pm)
		if err != nil {
			return nil, err
		}
		if e != "" {
			return walletRefuse("bad_response", e), nil
		}
		partial = pm
	}
	ux := map[string]any{"tier": it.card["friction"], "rendered_digest": it.card["rendered_digest"], "canary": it.kind == "canary"}
	if y == 1 {
		ev, err := c.tierEvidence(it, resp, questionID)
		if err != nil {
			return nil, err
		}
		if ev["ok"] != true {
			return ev, nil
		}
		for k, v := range ev["ux"].(map[string]any) {
			ux[k] = v
		}
	}
	plainYes := y == 1 && partial == nil
	typedRank := WalletFrictionRank("typed")
	if it.kind != "canary" && it.jit && it.irreversible && plainYes && it.actionDigest != "" && WalletFrictionRank(it.card["friction"]) >= typedRank {
		ux["action_digest"], ux["consent_for_action"] = it.actionDigest, true
	}
	body := map[string]any{"map_digest": c.o.MapDigest(), "session": c.o.Session, "question_id": questionID, "verb": it.verb, "cell": it.coords, "y": wN(y)}
	if len(partial) > 0 {
		body["partial"] = partial
	}
	body["source"], body["observed_at"], body["ux"] = it.source, jsNumber(now), ux
	answer, err := WalletSignIntentAnswer(body, c.o.PrincipalSeed)
	if err != nil {
		return nil, err
	}
	delete(c.pending, questionID)
	if it.kind == "canary" {
		c.o.OnNoise(WalletRecordCanary(c.o.Noise(), it.expected, y))
		return map[string]any{"ok": true, "kind": "canary", "answer": answer}, nil
	}
	if y == 0 {
		return map[string]any{"ok": true, "kind": "veto", "answer": answer}, nil
	}
	single := true
	for _, ids := range it.box {
		single = single && len(ids) == 1
	}
	if plainYes && WalletFrictionRank(it.card["friction"]) >= typedRank && single {
		// a verified high-friction yes: a source of known-yes canaries
		idx := make([]int, len(it.box))
		for i, ids := range it.box {
			idx[i] = ids[0]
		}
		c.knownYes = append(c.knownYes, WalletCellRef{Verb: it.verb, Idx: idx})
	}
	if plainYes && it.irreversible {
		adm, err := c.Admission()
		if err != nil {
			return nil, err
		}
		if adm.DoubleConfirmIrreversible {
			ck, _ := canonicalLenient(it.coords)
			key := it.verb + "|" + ck
			recs := append(append([]WalletConfirmation{}, c.confirmations[key]...), WalletConfirmation{Screen: float64(it.shownOn), Tier: it.card["friction"].(string)})
			c.confirmations[key] = recs
			if it.kind == "confirmation" && it.first != nil && WalletDoubleConfirmed(recs) {
				return map[string]any{"ok": true, "kind": "confirmed", "answers": []any{it.first, answer}}, nil
			}
			if it.kind == "confirmation" {
				return map[string]any{"ok": true, "kind": "pending_confirmation", "answer": answer}, nil
			}
			// schedule the second, independent confirmation: at least one other screen in between
			second := *it
			if second.id, err = c.newID(); err != nil {
				return nil, err
			}
			second.kind, second.first, second.notBefore, second.shownOn = "confirmation", answer, it.shownOn+2, 0
			c.pending[second.id] = &second
			return map[string]any{"ok": true, "kind": "pending_confirmation", "answer": answer}, nil
		}
	}
	return map[string]any{"ok": true, "kind": "answer", "answer": answer}, nil
}

func (c *WalletChannel) tierEvidence(it *walletItem, response map[string]any, questionID string) (map[string]any, error) {
	r := response
	if response["answer"] == "no" {
		r = map[string]any{}
	}
	evidence := func(code, reason string) map[string]any { return walletRefuse(code, reason) }
	switch tier := it.card["friction"]; tier {
	case "tap":
		return map[string]any{"ok": true, "ux": map[string]any{}}, nil
	case "hold":
		hm := r["holdMs"]
		f, isNum := jsNum(hm)
		if !(isNum && !math.IsNaN(f) && !math.IsInf(f, 0) && f == math.Floor(f) && f >= WalletMinHoldMs) {
			return evidence("tier_evidence", fmt.Sprintf("hold for at least %d ms", WalletMinHoldMs)), nil
		}
		return map[string]any{"ok": true, "ux": map[string]any{"hold_ms": hm}}, nil
	case "typed":
		t, _ := it.card["typed"].(map[string]any)
		am, _ := it.action.(map[string]any)
		typedIn, isStr := r["typed"].(string)
		if len(t) == 0 || !jsTruthy(it.action) || !isStr {
			return evidence("tier_evidence", "type the value shown on the card"), nil
		}
		want, wantOK, err := WalletExpectedTyped(it.card, am)
		if err != nil {
			return nil, err
		}
		var unit any
		if um, isMap := c.o.Units.(map[string]any); isMap {
			unit = um[t["path"].(string)]
		}
		mode, _ := t["mode"].(string)
		got, gotOK, err := WalletNormalizeTyped(typedIn, mode, unit)
		if err != nil {
			return nil, err
		}
		if !wantOK || !gotOK || got != want {
			return evidence("typed_mismatch", "the typed value does not match the card"), nil
		}
		td, err := WalletTypedDigest(questionID, got)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "ux": map[string]any{"typed_digest": td}}, nil
	case "device":
		wa, _ := r["webauthn"].(map[string]any)
		dev := c.o.Device
		if !jsTruthy(r["webauthn"]) || dev == nil {
			return evidence("tier_evidence", "a security-key assertion is required"), nil
		}
		cred, credOK := wa["credential_id"].(string)
		var pk any
		if credOK {
			pk = dev.Credentials[cred]
		}
		dec := func(k string) []byte {
			s, ok := wa[k].(string)
			if !ok {
				return nil
			}
			b, ok := DecodeB64uStrict(s, -1)
			if !ok {
				return nil
			}
			if b == nil {
				b = []byte{}
			}
			return b
		}
		ad, cd, sg := dec("authenticator_data"), dec("client_data_json"), dec("signature")
		if !jsTruthy(pk) || ad == nil || cd == nil || sg == nil {
			return evidence("tier_evidence", "unknown credential or malformed assertion"), nil
		}
		challenge, err := c.challengeFor(it, questionID)
		if err != nil {
			return nil, err
		}
		stored := 0.0
		if dev.SignCounts != nil {
			stored = dev.SignCounts[cred]
		}
		res := VerifyAssertion(Assertion{AuthenticatorData: ad, ClientDataJSON: cd, Signature: sg, PublicKey: pk},
			WebAuthnExpectations{ExpectedChallenge: challenge, RPID: dev.RPID, Origins: dev.Origins, RequireUV: true, StoredSignCount: &stored})
		if !res.OK {
			return evidence("tier_evidence", "security key: "+res.Reason), nil
		}
		if dev.SignCounts != nil {
			dev.SignCounts[cred] = float64(res.SignCount)
		}
		return map[string]any{"ok": true, "ux": map[string]any{"webauthn": withoutKeys(wa)}}, nil
	}
	return nil, errors.New("unknown friction tier")
}

// DeviceChallengeFor is the WebAuthn challenge the wallet UI passes to navigator.credentials.get for a shown device-tier question
// ("" for any other question).
func (c *WalletChannel) DeviceChallengeFor(questionID string) (string, error) {
	it := c.pending[questionID]
	if it == nil || it.shownOn == 0 || it.card["friction"] != "device" {
		return "", nil
	}
	return c.challengeFor(it, questionID)
}

// Summary is the end-of-session summary shown instead of questions once the session froze.
func (c *WalletChannel) Summary() (map[string]any, error) {
	st, err := c.Noise()
	if err != nil {
		return nil, err
	}
	return map[string]any{"frozen": st.Frozen, "refused": append([]any{}, c.refusedWhileFrozen...), "asked": wN(c.sessionQuestions), "canaries": wN(c.canaries)}, nil
}

// StateDigest is a stable digest of the channel's pending state (for tests and audit logs).
func (c *WalletChannel) StateDigest() (string, error) {
	pend := []any{}
	for _, it := range c.ordered() {
		pend = append(pend, map[string]any{"id": it.id, "k": it.kind, "d": it.card["rendered_digest"]})
	}
	asked := make([]string, 0, len(c.asked))
	for k := range c.asked {
		asked = append(asked, k)
	}
	walletSortUTF16(asked)
	as := make([]any, len(asked))
	for i, k := range asked {
		as[i] = k
	}
	return HashCanonical(map[string]any{"d": "atlas-pca/wallet-channel-state/v1", "p": pend, "a": as, "n": wN(c.sessionQuestions)})
}

// ---- framework-neutral handlers -------------------------------------------------------------------------------------------------

var walletStatusOfRefusal = map[string]int{
	"bad_site_signature": 401, "wrong_session": 409, "stale_map": 409, "action_mismatch": 422, "cell_mismatch": 422, "not_uncertain": 409,
	"already_asked": 409, "frozen": 429, "cap_session": 429, "cap_hour": 429, "cell_too_large": 422, "bad_request": 400, "render_failed": 422,
}

func walletActionOf(v any) map[string]any {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	for _, k := range []string{"verb", "resource", "reversibility_class"} {
		if _, isS := m[k].(string); !isS {
			return nil
		}
	}
	if _, isObj := m["params"].(map[string]any); !isObj {
		return nil
	}
	for k := range m {
		if k != "verb" && k != "resource" && k != "params" && k != "reversibility_class" {
			return nil
		}
	}
	return map[string]any{"verb": m["verb"], "resource": m["resource"], "params": m["params"], "reversibility_class": m["reversibility_class"]}
}

// WalletQuestionHandler is the question endpoint (a site delivers, or an agent relays unchanged, a site-signed intent_required plus
// the raw action): resolve maps a session id to its channel (nil when unknown). The result is {status, body}.
func WalletQuestionHandler(resolve func(sessionID string) *WalletChannel) func(sessionID string, body any) (map[string]any, error) {
	return func(sessionID string, body any) (map[string]any, error) {
		reply := func(status int, b map[string]any) map[string]any {
			return map[string]any{"status": wN(status), "body": b}
		}
		ch := resolve(sessionID)
		if ch == nil {
			return reply(404, map[string]any{"error": "unknown_session"}), nil
		}
		bm, ok := body.(map[string]any)
		if !ok {
			return reply(400, map[string]any{"error": "bad_request"}), nil
		}
		for _, k := range wKeysOf(bm) {
			if k != "intent_required" && k != "action" {
				return reply(400, map[string]any{"error": "bad_request", "detail": fmt.Sprintf("unknown member \"%s\"", k)}), nil
			}
		}
		action := walletActionOf(bm["action"])
		if action == nil || !WalletIsObj(bm["intent_required"]) {
			return reply(400, map[string]any{"error": "bad_request"}), nil
		}
		r, err := ch.Receive(bm["intent_required"], action)
		if err != nil {
			return nil, err
		}
		if r["ok"] == true {
			return reply(202, map[string]any{"question_id": r["questionId"], "friction": r["friction"]}), nil
		}
		status, known := walletStatusOfRefusal[r["code"].(string)]
		if !known {
			status = 400
		}
		return reply(status, map[string]any{"error": r["code"]}), nil
	}
}

// WalletClarifyHandler is the clarification endpoint: resolve maps a session id to its channel (nil when unknown).
func WalletClarifyHandler(resolve func(sessionID string) *WalletChannel) func(sessionID string, body any) (map[string]any, error) {
	return func(sessionID string, body any) (map[string]any, error) {
		ch := resolve(sessionID)
		if ch == nil {
			return map[string]any{"status": wN(404), "body": map[string]any{"error": "unknown_session"}}, nil
		}
		r, err := ch.Clarify(body)
		if err != nil {
			return nil, err
		}
		if e, has := r["error"]; has && e != nil {
			return map[string]any{"status": wN(400), "body": map[string]any{"error": "bad_request", "detail": e}}, nil
		}
		out := map[string]any{"verdicts": r["verdicts"]}
		if q, has := r["questionId"]; has && q != nil {
			out["question_id"] = q
		}
		if f, has := r["refused"]; has && f != nil {
			out["refused"] = f
		}
		return map[string]any{"status": r["status"], "body": out}, nil
	}
}
