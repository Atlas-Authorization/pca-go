package pca

// Replays the signals reference corpus: SET build / verify, revocation state, replay store, receiver, authorize() adapters, stream
// health, verification, poll queue, push response, CAEP builders and the SSF management API. Scenario fns replay the reference's
// scripted operations over the native API. Keys cross as JWK objects derived from seeds (test keys only); a SET built with a
// random jti and the wall-clock iat is compared after decoding (jti -> "<uuid>", an iat within two minutes of now -> "<now>").

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	sigK1Seed = func() []byte { h := sha256.Sum256([]byte("atlas-pca-conformance/ref-signals/tx")); return h[:] }()
	sigK1Pub  = ed25519.NewKeyFromSeed(sigK1Seed).Public().(ed25519.PublicKey)
	sigUUIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

func sigB64(v any) ([]byte, bool) {
	s, ok := v.(string)
	if !ok {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	return b, err == nil
}

// sigPub imports a public JWK as the platform does (anything else is refused, as there).
func sigPub(jwk any) (ed25519.PublicKey, error) {
	m, ok := jwk.(map[string]any)
	if !ok || m["kty"] != "OKP" || m["crv"] != "Ed25519" {
		return nil, errors.New("Invalid JWK")
	}
	x, ok := sigB64(m["x"])
	if !ok || len(x) != 32 {
		return nil, errors.New("Invalid JWK")
	}
	return ed25519.PublicKey(x), nil
}

// sigPriv imports a private JWK; null passes through as no key (the builder then refuses).
func sigPriv(jwk any) ([]byte, error) {
	if jwk == nil {
		return nil, nil
	}
	m, ok := jwk.(map[string]any)
	if !ok || m["kty"] != "OKP" {
		return nil, errors.New("JWK does not contain private key material")
	}
	// The committed corpus carries no private key material: the JWK "d" is a seed label, resolved by vecSeeded to base64url.
	d, ok := sigB64(m["d"])
	if !ok {
		return nil, errors.New("JWK does not contain private key material")
	}
	return d, nil
}

func sigShape(set string) any {
	parts := strings.Split(set, ".")
	if len(parts) != 3 {
		return map[string]any{"$bad": set}
	}
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	pb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	header, _ := ParseJSONLenient(hb)
	pv, _ := ParseJSONLenient(pb)
	payload, _ := pv.(map[string]any)
	if iat, ok := sigNumber(payload["iat"]); ok && math.Abs(iat*1000-vecOracleNow()) < 120_000 {
		payload["iat"] = "<now>"
	}
	if j, ok := payload["jti"].(string); ok && sigUUIDRe.MatchString(j) {
		payload["jti"] = "<uuid>"
	}
	return map[string]any{"header": header, "payload": payload, "sigOk": ed25519.Verify(sigK1Pub, []byte(parts[0]+"."+parts[1]), sig)}
}

func sigErrOut(err error) any {
	out := map[string]any{"$err": true}
	var ce *CodedError
	if errors.As(err, &ce) && ce.Code != "" && !strings.HasPrefix(ce.Code, "ERR_") && !strings.HasPrefix(ce.Code, "N") {
		out["code"] = ce.Code
	}
	return out
}

func sigStateOut(st *SignalsRevocationState) any {
	var intents any
	if l := st.RevokedIntentIDs(); l != nil {
		intents = l
	}
	return map[string]any{"grants": st.RevokedGrants(), "agents": st.KilledAgents(), "intents": intents}
}

// sigParsed is a ParsedSet-shaped JSON value as the native type: a member access the reference would throw on is an error
// here or (events / payload null or missing) a nil the native API refuses; a primitive events / payload has no members.
func sigParsed(v any) (*ParsedSET, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("Cannot read properties of a non-object (reading 'events')")
	}
	p := &ParsedSET{}
	switch e := m["events"].(type) {
	case nil:
	case map[string]any:
		p.Events = e
	default:
		p.Events = map[string]any{}
	}
	switch pl := m["payload"].(type) {
	case nil:
	case map[string]any:
		p.Payload = pl
	default:
		p.Payload = map[string]any{}
	}
	p.Iss, _ = m["iss"].(string)
	p.Jti, _ = m["jti"].(string)
	return p, nil
}

func sigStrList(v any) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		return []string{t}
	}
	l, _ := v.([]any)
	out := []string{}
	for _, x := range l {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

func sigNumPtr(m map[string]any, k string) *float64 {
	v, has := m[k]
	if !has || v == nil {
		return nil
	}
	f, ok := sigNumber(v)
	if !ok {
		f = math.NaN()
	}
	return &f
}

var sigMappers = map[string]func(map[string]any) (string, error){
	"email": func(s map[string]any) (string, error) {
		if e, ok := s["email"].(string); ok && s["format"] == "email" {
			return e, nil
		}
		return "", nil
	},
	"throws": func(map[string]any) (string, error) { return "", errors.New("x") },
	"empty":  func(map[string]any) (string, error) { return "", nil },
	"num":    func(map[string]any) (string, error) { return "", nil }, // the reference's mapper returns 5: not a string, unmapped
	"id": func(s map[string]any) (string, error) {
		id, _ := s["id"].(string)
		return id, nil
	},
	"prefixed": func(s map[string]any) (string, error) {
		if id, ok := s["id"].(string); ok {
			return "agent:" + id, nil
		}
		return "", nil
	},
}

func sigStdOpts(v any) *StandardRevocationOptions {
	sp, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	o := &StandardRevocationOptions{FailOnUnmapped: sp["fail"] == true}
	if mp, _ := sp["mapper"].(string); mp != "" && mp != "default" {
		o.SubjectToAgent = sigMappers[mp]
	}
	return o
}

func sigAgentOf(v any) *RevocationAdapterOptions {
	name, _ := v.(string)
	var f func(pcactn, grant any) (string, error)
	switch {
	case name == "" || name == "leaf":
		return nil
	case strings.HasPrefix(name, "const:"):
		f = func(any, any) (string, error) { return name[6:], nil }
	case name == "throws":
		f = func(any, any) (string, error) { return "", errors.New("x") }
	case name == "empty", name == "num":
		f = func(any, any) (string, error) { return "", nil }
	case name == "grantId":
		f = func(_, g any) (string, error) { id, _ := sigField(g, "id").(string); return id, nil }
	}
	return &RevocationAdapterOptions{AgentOf: f}
}

func sigStateScenario(spec map[string]any) any {
	st := NewRevocationState()
	out := []any{}
	ops, _ := spec["ops"].([]any)
	for _, ov := range ops {
		s := vecObj(ov)
		res, err := func() (any, error) {
			target := st
			if jsTruthy(s["badState"]) {
				target = nil // the native API refuses a missing state; it cannot be handed a non-state
			}
			switch s["op"] {
			case "apply":
				p, err := sigParsed(s["parsed"])
				if err != nil {
					return nil, err
				}
				if _, err := ApplySET(st, p); err != nil {
					return nil, err
				}
				return sigStateOut(st), nil
			case "applyStd":
				p, err := sigParsed(s["parsed"])
				if err != nil {
					return nil, err
				}
				plan, err := ApplyStandardRevocations(target, p, sigStdOpts(s["std"]))
				if err != nil {
					return nil, err
				}
				return map[string]any{"plan": plan, "state": sigStateOut(st)}, nil
			case "plan":
				p, err := sigParsed(s["parsed"])
				if err != nil {
					return nil, err
				}
				return PlanStandardRevocations(p, sigStdOpts(s["std"]))
			case "isRevoked":
				g, _ := s["grant"].(string)
				a, _ := s["agent"].(string)
				return IsRevoked(st, g, a), nil
			case "isIntentRevoked":
				id, _ := s["id"].(string)
				return IsIntentRevoked(st, id), nil
			case "stream":
				l, ok := s["sets"].([]any)
				if !ok {
					return nil, errors.New("parsedSets is not iterable")
				}
				sets := make([]*ParsedSET, len(l))
				for i, x := range l {
					p, err := sigParsed(x)
					if err != nil {
						return nil, err
					}
					sets[i] = p
				}
				var into *SignalsRevocationState
				if jsTruthy(s["useState"]) {
					into = st
				}
				r, err := StreamProcessor(sets, into)
				if err != nil {
					return nil, err
				}
				return sigStateOut(r), nil
			case "snapshot":
				return SnapshotRevocationState(target)
			case "restore":
				var into *SignalsRevocationState // nil: the native default (a fresh state)
				if !jsTruthy(s["fresh"]) {
					if jsTruthy(s["nullInto"]) || target == nil {
						// a null / non-state `into` has no Go spelling (nil is the default): the reference refuses it as misconfigured
						return nil, signalsErr("misconfigured", "state must come from createRevocationState()")
					}
					into = target
				}
				r, err := RestoreRevocationState(s["snapshot"], into)
				if err != nil {
					return nil, err
				}
				return sigStateOut(r), nil
			}
			return nil, errors.New("bad op")
		}()
		if err != nil {
			out = append(out, sigErrOut(err))
		} else {
			out = append(out, vecJSON(res))
		}
	}
	return append(out, sigStateOut(st))
}

type sigConstStore bool

func (s sigConstStore) AddIfAbsent(string, float64, float64) (bool, error) { return bool(s), nil }

type sigThrowStore struct{}

func (sigThrowStore) AddIfAbsent(string, float64, float64) (bool, error) {
	return false, errors.New("boom")
}

type sigNoExpiryStore struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (s *sigNoExpiryStore) AddIfAbsent(jti string, _, _ float64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen[jti] {
		return false, nil
	}
	s.seen[jti] = true
	return true, nil
}

// sigMaxEntries is the replay store option; a non-number has no Go spelling.
func sigMaxEntries(opts any) (*float64, error) {
	m, _ := opts.(map[string]any)
	v, has := m["maxEntries"]
	if !has || v == nil {
		return nil, nil
	}
	f, ok := sigNumber(v)
	if !ok {
		return nil, vecSkip("a non-number maxEntries cannot be passed to the Go API")
	}
	return &f, nil
}

func sigReceiveOpts(d map[string]any, store SetReplayStore, st *SignalsRevocationState) *ReceiveSETOptions {
	if jsTruthy(d["noOpts"]) {
		return nil
	}
	m := vecObj(d["opts"])
	o := &ReceiveSETOptions{Issuer: sigStrList(m["issuer"]), Audience: sigStrList(m["audience"]), ReplayStore: store, State: st,
		ClockSkewSec: sigNumPtr(m, "clockSkewSec"), NowSec: sigNumPtr(m, "nowSec")}
	if v, has := m["maxAgeSec"]; has {
		o.MaxAgeSec = math.NaN()
		if f, ok := sigNumber(v); ok {
			o.MaxAgeSec = f
		}
	}
	if f := sigNumPtr(m, "maxBytes"); f != nil {
		n := int(*f)
		o.MaxBytes = &n
	}
	if jsTruthy(d["noStore"]) {
		o.ReplayStore = nil
	}
	if jsTruthy(d["noState"]) {
		o.State = nil
	}
	if _, has := d["std"]; has {
		o.StandardRevocations = sigStdOpts(d["std"])
	}
	return o
}

func sigReceiveScenario(spec map[string]any) (any, error) {
	st := NewRevocationState()
	var store SetReplayStore
	switch spec["store"] {
	case "throws":
		store = sigThrowStore{}
	case "false":
		store = sigConstStore(false)
	case "mem1":
		one := 1.0
		store, _ = NewInMemorySetReplayStore(&one)
	default:
		store, _ = NewInMemorySetReplayStore(nil)
	}
	out := []any{}
	ds, _ := spec["deliveries"].([]any)
	for _, dv := range ds {
		d := vecObj(dv)
		key := sigK1Pub
		if k, has := d["key"]; has {
			p, err := sigPub(k)
			if err != nil {
				out = append(out, map[string]any{"$err": true})
				continue
			}
			key = p
		}
		r := ReceiveSET(d["set"], key, sigReceiveOpts(d, store, st))
		if !r.OK && r.Code == "verify_failed" && !strings.HasPrefix(r.Reason, "SET invalid:") {
			r.Reason = "<jose>"
		}
		out = append(out, vecJSON(r.Map()))
	}
	return append(out, sigStateOut(st)), nil
}

func sigAdapterScenario(spec map[string]any) any {
	var st *SignalsRevocationState
	if _, bad := spec["badState"]; !bad {
		grants, has := spec["grants"]
		if !has {
			grants = []any{}
		}
		agents, has := spec["agents"]
		if !has {
			agents = []any{}
		}
		var err error
		if st, err = RestoreRevocationState(map[string]any{"v": 1, "grants": grants, "agents": agents, "intents": []any{}}, nil); err != nil {
			return []any{sigErrOut(err)}
		}
	}
	o := sigAgentOf(spec["agentOf"])
	hook, err := CreateRevocationHook(st, o)
	if err != nil {
		return []any{sigErrOut(err)}
	}
	isRev, err := createIsRevokedAny(st, o)
	if err != nil {
		return []any{sigErrOut(err)}
	}
	out := []any{}
	calls, _ := spec["calls"].([]any)
	for _, cv := range calls {
		c := vecObj(cv)
		out = append(out, map[string]any{"hook": vecJSON(hook(c["pcactn"], c["grant"])), "isRevoked": isRev(c["pcactn"], c["grant"])})
	}
	return out
}

var sigCFG = map[string]any{"stream_id": "s1", "iss": "https://tx.example", "aud": "rx",
	"events_supported": []any{SetEventTypes["grantRevoked"], SetEventTypes["killSwitch"]}, "events_delivered": []any{SetEventTypes["grantRevoked"]},
	"delivery": map[string]any{"method": DeliveryPoll, "endpoint_url": "https://tx.example/poll/s1"}, "min_verification_interval": 30.0, "description": "d"}

func sigHealthScenario(spec map[string]any) any {
	cfg, ok := spec["config"].(map[string]any)
	if !ok {
		cfg = sigCFG
	}
	om := vecObj(spec["opts"])
	num := func(k string) float64 { f, _ := sigNumber(om[k]); return f }
	h := NewStreamHealth(cfg, &StreamHealthOptions{VerifyTimeoutSec: num("verifyTimeoutSec"), VerifiedWithinSec: num("verifiedWithinSec"),
		FailAfter: num("failAfter"), MaxPending: num("maxPending")})
	issued := []string{}
	out := []any{}
	ops, _ := spec["ops"].([]any)
	for _, ov := range ops {
		s := vecObj(ov)
		now, _ := sigNumber(s["now"])
		var r any
		var err error
		switch s["op"] {
		case "status":
			v, _ := s["v"].(string) // a non-string status has no Go spelling; "" is refused the same way
			err = h.SetStatus(v)
		case "event":
			h.RecordEvent(now)
		case "request":
			if st := h.RequestVerification(now); st != "" {
				issued = append(issued, st)
				r = "<state:" + jsNumberString(float64(len(issued)-1)) + ">"
			}
		case "ack":
			state := ""
			if ref, has := s["ref"]; has {
				if i, ok := sigNumber(ref); ok && i >= 0 && int(i) < len(issued) {
					state = issued[int(i)]
				}
			} else {
				state, _ = s["state"].(string)
			}
			r = h.AckVerification(state, now)
		case "report":
			r = h.Report(now)
		case "fresh":
			mx, _ := sigNumber(s["max"])
			r = h.RevocationFreshWithin(mx, now)
		default:
			err = errors.New("bad op")
		}
		if err != nil {
			out = append(out, map[string]any{"$err": true})
		} else {
			out = append(out, vecJSON(r))
		}
	}
	return out
}

func sigVerificationScenario(spec map[string]any) any {
	streams := map[string]*VerificationStream{}
	for id, v := range vecObj(spec["streams"]) {
		m := vecObj(v)
		s := &VerificationStream{}
		s.Config, _ = vecJSON(m["config"]).(map[string]any)
		s.LastVerification = sigNumPtr(m, "lastVerification")
		streams[id] = s
	}
	out := []any{}
	ops, _ := spec["ops"].([]any)
	for _, ov := range ops {
		s := vecObj(ov)
		now, _ := sigNumber(s["now"])
		key := sigK1Seed
		if jsTruthy(s["noKey"]) {
			key = nil
		}
		r, err := HandleVerificationRequestAt(streams, s["req"], now, key, int64(vecOracleNow()/1000)) // the generator's frozen clock
		switch {
		case err != nil:
			out = append(out, map[string]any{"$err": true})
		case r.Status == 204:
			out = append(out, map[string]any{"status": 204, "set": sigShape(r.SET)})
		default:
			out = append(out, vecJSON(r))
		}
	}
	last := map[string]any{}
	for id, s := range streams {
		last[id] = nil
		if s.LastVerification != nil {
			last[id] = *s.LastVerification
		}
	}
	return append(out, vecJSON(last))
}

func sigPollScenario(spec map[string]any) any {
	q := NewPollQueue()
	out := []any{}
	ops, _ := spec["ops"].([]any)
	for _, ov := range ops {
		s := vecObj(ov)
		if e, ok := s["enqueue"].([]any); ok {
			j, _ := vecArg(e, 0).(string)
			v, _ := vecArg(e, 1).(string)
			q.Enqueue(j, v)
			out = append(out, nil)
		} else if jsTruthy(s["depth"]) {
			out = append(out, q.Depth())
		} else if r, err := q.Poll(s["poll"]); err != nil {
			out = append(out, map[string]any{"$err": true})
		} else {
			out = append(out, vecJSON(r))
		}
	}
	return append(out, vecJSON(map[string]any{"depth": q.Depth(), "errors": q.Errors()}))
}

func sigCaep(a map[string]any) (any, error) {
	key, err := sigPriv(a["keyJwk"])
	if err != nil {
		return nil, err
	}
	iss, _ := a["issuer"].(string)
	ev, _ := a["event"].(map[string]any)
	args := CaepSETArgs{Issuer: iss, Audience: a["audience"], Key: key, Event: ev, Now: int64(vecOracleNow() / 1000)}
	if _, has := a["order"]; has {
		args.Order = sigStrList(a["order"])
	}
	var set string
	if a["kind"] == "risk" {
		set, err = RiskLevelChangeSET(args)
	} else {
		set, err = AssuranceLevelChangeSET(args)
	}
	if err != nil {
		return nil, err
	}
	return sigShape(set), nil
}

func sigManageScenario(spec map[string]any) any {
	store := NewMemoryStreamStore()
	delivered := []any{}
	ids := 0
	var curNow float64
	var curRcv any
	supported := []string{SetEventTypes["grantRevoked"], SetEventTypes["killSwitch"], SetEventTypes["sessionRevoked"]}
	if _, has := spec["eventsSupported"]; has {
		supported = sigStrList(spec["eventsSupported"])
	}
	o := SsfManageOptions{Store: store, Issuer: "https://tx.example", EventsSupported: supported,
		PollEndpoint: func(id string) string { return "https://tx.example/poll/" + id }, SigningKey: sigK1Seed,
		Deliver: func(s *StreamRecord, set string) error {
			delivered = append(delivered, map[string]any{"stream": vecJSON(s.Clone()), "set": sigShape(set)})
			return nil
		},
		Now:      func() float64 { return curNow },
		IssuedAt: func() int64 { return int64(vecOracleNow() / 1000) },
		NewID:    func() string { ids++; return "s" + jsNumberString(float64(ids)) }}
	so := vecObj(spec["options"])
	if f, ok := sigNumber(so["maxStreamsPerReceiver"]); ok {
		o.MaxStreamsPerReceiver = int(f)
	}
	if f, ok := sigNumber(so["maxSubjectsPerStream"]); ok {
		o.MaxSubjectsPerStream = int(f)
	}
	if _, has := so["deliveryMethods"]; has {
		o.DeliveryMethods = sigStrList(so["deliveryMethods"])
	}
	h := SsfManagementHandler(o, func(SsfRequest) (*SsfReceiver, error) {
		switch r := curRcv.(type) {
		case string:
			return nil, errors.New("auth")
		case map[string]any:
			id, _ := r["id"].(string)
			return &SsfReceiver{ID: id, Aud: r["aud"]}, nil
		}
		return nil, nil
	})
	out := []any{}
	steps, _ := spec["steps"].([]any)
	for _, sv := range steps {
		st := vecObj(sv)
		curNow = 1000
		if f, ok := sigNumber(st["now"]); ok {
			curNow = f
		}
		curRcv = map[string]any{"id": "rx1", "aud": "rx"}
		if r, has := st["rcv"]; has {
			curRcv = r
		}
		out = append(out, vecJSON(h.Handle(st["req"])))
	}
	dump := map[string]any{}
	rcvs := []string{"rx1", "rx2"}
	if _, has := spec["receivers"]; has {
		rcvs = sigStrList(spec["receivers"])
	}
	for _, rid := range rcvs {
		l, _ := store.ListByReceiver(rid)
		dump[rid] = vecJSON(l)
	}
	return append(out, map[string]any{"delivered": vecJSON(delivered), "store": dump})
}

func TestSignalsVectors(t *testing.T) {
	fns := map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{"SET_TYP": SetTyp, "SET_ALG": SetAlg, "EVENT_TYPES": SetEventTypes, "RISC_EVENT_TYPES": RiscEventTypes,
				"SET_INMEMORY_MAX_ENTRIES": SetInMemoryMaxEntries, "DELIVERY_PUSH": DeliveryPush, "DELIVERY_POLL": DeliveryPoll,
				"STREAM_STATUSES": StreamStatuses}, nil
		},
		"verifySET": func(a []any) (any, error) {
			if len(a) > 2 && a[2] == nil {
				return nil, vecSkip("null options (the reference's TypeError) have no Go spelling: nil options are the defaults")
			}
			key, err := sigPub(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			// the reference oracle runs under a fixed wall clock: without a currentDate the check uses that clock
			o := &VerifySETOptions{CurrentDate: time.UnixMilli(int64(vecOracleNow()))}
			if m, ok := vecArg(a, 2).(map[string]any); ok {
				o = &VerifySETOptions{CurrentDate: o.CurrentDate, Issuer: sigStrList(m["issuer"]), Audience: sigStrList(m["audience"]), ClockTolerance: m["clockTolerance"],
					SkipTyp: m["requireTyp"] == false}
				if ms, ok := sigNumber(m["currentDate"]); ok {
					o.CurrentDate = time.UnixMilli(int64(ms))
				}
				if typ, ok := m["typ"].(string); ok {
					o.Typ = &typ
				}
			}
			p, err := VerifySET(vecArg(a, 0), key, o)
			if err != nil {
				return nil, err
			}
			return p.Map(), nil
		},
		"buildSETShape": func(a []any) (any, error) {
			m := vecObj(vecArg(a, 0))
			key, err := sigPriv(m["keyJwk"])
			if err != nil {
				return nil, err
			}
			ev, ok := m["events"].(map[string]any)
			if !ok {
				return nil, errors.New("buildSET: at least one event is required in the `events` map (RFC 8417 §2.2)")
			}
			args := BuildSETArgs{Events: ev, Audience: m["audience"], Key: key, Now: int64(vecOracleNow() / 1000)} // the generator's frozen clock
			args.Issuer, _ = m["issuer"].(string)
			if s, ok := m["subject"].(string); ok {
				args.Subject = &s
			}
			set, err := BuildSET(args)
			if err != nil {
				return nil, err
			}
			return sigShape(set), nil
		},
		"stateScenario": func(a []any) (any, error) { return sigStateScenario(vecObj(vecArg(a, 0))), nil },
		"replayScenario": func(a []any) (any, error) {
			spec := vecObj(vecArg(a, 0))
			mx, err := sigMaxEntries(spec["opts"])
			if err != nil {
				return nil, err
			}
			store, err := NewInMemorySetReplayStore(mx)
			if err != nil {
				return []any{sigErrOut(err)}, nil
			}
			out := []any{}
			ops, _ := spec["ops"].([]any)
			for _, ov := range ops {
				op, _ := ov.([]any)
				jti, _ := vecArg(op, 0).(string)
				exp, _ := sigNumber(vecArg(op, 1))
				now, _ := sigNumber(vecArg(op, 2))
				if ok, err := store.AddIfAbsent(jti, exp, now); err != nil {
					out = append(out, map[string]any{"$err": true})
				} else {
					out = append(out, ok)
				}
			}
			return out, nil
		},
		"replayConformance": func(a []any) (any, error) {
			spec := vecObj(vecArg(a, 0))
			mx, err := sigMaxEntries(spec["opts"])
			if err != nil {
				return nil, err
			}
			return RunSetReplayStoreConformance(func() SetReplayStore {
				switch spec["store"] {
				case "alwaysTrue":
					return sigConstStore(true)
				case "alwaysFalse":
					return sigConstStore(false)
				case "noExpiry":
					return &sigNoExpiryStore{seen: map[string]bool{}}
				}
				s, _ := NewInMemorySetReplayStore(mx)
				return s
			})
		},
		"receiveScenario":      func(a []any) (any, error) { return sigReceiveScenario(vecObj(vecArg(a, 0))) },
		"adapterScenario":      func(a []any) (any, error) { return sigAdapterScenario(vecObj(vecArg(a, 0))), nil },
		"validateStreamConfig": func(a []any) (any, error) { return ValidateStreamConfig(vecArg(a, 0)), nil },
		"healthScenario":       func(a []any) (any, error) { return sigHealthScenario(vecObj(vecArg(a, 0))), nil },
		"verificationScenario": func(a []any) (any, error) { return sigVerificationScenario(vecObj(vecArg(a, 0))), nil },
		"pollScenario":         func(a []any) (any, error) { return sigPollScenario(vecObj(vecArg(a, 0))), nil },
		"pushResponse":         func(a []any) (any, error) { return PushResponse(vecArg(a, 0)) },
		"caepSET":              func(a []any) (any, error) { return sigCaep(vecObj(vecArg(a, 0))) },
		"manageScenario":       func(a []any) (any, error) { return sigManageScenario(vecObj(vecArg(a, 0))), nil },
		"transmitterMetadata": func(a []any) (any, error) {
			o := vecObj(vecArg(a, 0))
			iss, _ := o["issuer"].(string)
			var dm []string
			if _, has := o["deliveryMethods"]; has {
				dm = sigStrList(o["deliveryMethods"])
			}
			base, _ := vecArg(a, 1).(string)
			jw, _ := vecArg(a, 2).(string)
			return TransmitterMetadata(iss, dm, base, jw), nil
		},
	}
	replayVectors(t, "ref-signals.json.gz", vecSeeded(fns))
}

// A SET built here verifies, and the receiver accepts it exactly once.
func TestSignalsBuiltSETIsSingleUse(t *testing.T) {
	st := NewRevocationState()
	store, _ := NewInMemorySetReplayStore(nil)
	now := float64(time.Now().Unix())
	set, err := BuildSET(BuildSETArgs{Events: map[string]any{SetEventTypes["grantRevoked"]: map[string]any{"grant_ref": "g", "event_timestamp": now}},
		Issuer: "iss", Audience: "aud", Key: sigK1Seed})
	if err != nil {
		t.Fatal(err)
	}
	o := &ReceiveSETOptions{Issuer: []string{"iss"}, Audience: []string{"aud"}, ReplayStore: store, State: st, MaxAgeSec: 300}
	if r := ReceiveSET(set, sigK1Pub, o); !r.OK || !IsRevoked(st, "g", "") {
		t.Fatalf("first delivery: %+v", r)
	}
	if r := ReceiveSET(set, sigK1Pub, o); r.OK || r.Code != "replay" {
		t.Fatalf("second delivery: %+v", r)
	}
}
