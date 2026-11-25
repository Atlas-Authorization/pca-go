package pca

// The rest of the testing kit: TestAgent / MakePCActn factories and the adapter acceptance matrix. Every resource-server adapter
// (the net/http RequirePCA guard, the Gin and Echo middleware, or your own) runs the SAME scenarios through its own request /
// response plumbing with the Operation option (the Authorize pipeline), and must produce AdapterAcceptanceExpected exactly.
//
// The routes: POST /payments executes payments.send, POST /refunds executes payments.refund, both on resource payments with the
// JSON body as params. The grant permits both verbs up to $100 per call; the operation mapping reads the request's method and
// URL, so the adapter must pass them through. Scenarios (each on a fresh adapter unless noted): over_limit_predicate (a validly
// signed $400 payment under a `where amount <= 100` grant), over_limit_max_spend (the same under a max_spend: 100 caveat),
// body_differs (a proof signed for $50, the body says $400), other_operation (a proof for payments.send presented to POST
// /refunds), escalate_unanswered (a payment the grant's tighten[] escalates, with no principal answer), missing_revocation /
// missing_store (no IsRevoked / no StateStore), then valid_first and replay_second on one adapter. Every refusal must happen
// before the handler runs; an allowed call must carry the bound operation.

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
)

// TestAgentOverrides are the human-level overrides of TestAgent; anything omitted falls back to a test default.
type TestAgentOverrides struct {
	Permissions any               // connector -> allowed actions; default {stripe: [refund]}
	Limits      map[string]string // per-action limits; default {refund: "$500/day"}; an empty non-nil map = no limits
	Goal        string            // default "test"
	Aud         string            // default "ins_test"
	Principal   *KeyPair          // a fresh pair when nil
	Holder      *KeyPair          // a fresh pair when nil
}

// TestAgent mints a REAL agent with test defaults: the returned handle holds a real signed grant, so a PCActn it builds verifies
// against FakeVerify out of the box.
func TestAgent(o TestAgentOverrides) (*FacadeAgent, error) {
	principal := o.Principal
	if principal == nil {
		var err error
		if principal, err = NewKeyPair(); err != nil {
			return nil, err
		}
	}
	perms := o.Permissions
	if perms == nil {
		perms = map[string]any{"stripe": []any{"refund"}}
	}
	limits := o.Limits
	if limits == nil {
		limits = map[string]string{"refund": "$500/day"}
	}
	goal, aud := o.Goal, o.Aud
	if goal == "" {
		goal = "test"
	}
	if aud == "" {
		aud = "ins_test"
	}
	return CreateAgent(AgentOptions{Principal: principal, Goal: goal, Permissions: perms, Limits: limits, Holder: o.Holder, Aud: aud})
}

// MakePCActn builds a PCActn for one action: the PCActn and its wire encoding (the local dry run is dropped; use Act directly
// if you need it). A nil counter auto-increments per holder.
func MakePCActn(a *FacadeAgent, verb, resource string, params map[string]any, counter *int64, now int64) (map[string]any, string, error) {
	res, err := a.Act(verb, resource, params, &ActOptions{Counter: counter, Now: now})
	if err != nil {
		return nil, "", err
	}
	return res.PCActn, res.Encoded, nil
}

// AcceptanceRequest is one request as the adapter's framework would receive it (always POST).
type AcceptanceRequest struct {
	Path    string // path only (/payments)
	Headers map[string]string
	Body    map[string]any
}

// AcceptanceObservation is what the harness saw for one request.
type AcceptanceObservation struct {
	Status     int
	HandlerRan bool
	Operation  *AuthorizedOperation // the operation the adapter attached for the handler (allowed calls only)
}

// AcceptanceOutcome is one row of the matrix.
type AcceptanceOutcome struct {
	Status     int
	HandlerRan bool
	Bound      bool // whether an attached operation matches what ran
}

// AcceptanceHarness builds the adapter ONCE from the options (passed to the adapter unchanged, Operation included) with a handler
// spy, and returns a function that sends one request through it.
type AcceptanceHarness func(opts RequirePCAOptions) func(req AcceptanceRequest) AcceptanceObservation

func acceptanceOperationOf(method, url string, body []byte) (*Operation, error) {
	var parsed any
	if len(body) > 0 {
		v, err := StrictParse(string(body))
		if err != nil {
			return nil, nil
		}
		parsed = v
	}
	m, err := AcceptanceOperation(map[string]any{"method": method, "url": url, "body": parsed})
	if err != nil || m == nil {
		return nil, err
	}
	return &Operation{Verb: m["verb"].(string), Resource: m["resource"].(string), Params: m["params"].(map[string]any)}, nil
}

// WithAcceptanceOperation returns opts with the authorize-mode Operation callback set to the matrix's route table, so a framework
// harness can reuse the same mapping.
func WithAcceptanceOperation(opts RequirePCAOptions) RequirePCAOptions {
	if opts.Authorize != nil {
		a := *opts.Authorize
		a.Operation = func(r *http.Request, body []byte) (*Operation, error) {
			return acceptanceOperationOf(r.Method, r.URL.RequestURI(), body)
		}
		opts.Authorize = &a
	}
	return opts
}

// NetHTTPAcceptanceHarness runs the matrix through the native net/http guard (RequirePCA) over an in-process recorder.
func NetHTTPAcceptanceHarness(opts RequirePCAOptions) func(req AcceptanceRequest) AcceptanceObservation {
	opts = WithAcceptanceOperation(opts)
	var ran bool
	var authorized *AuthorizedOperation
	h := RequirePCA(opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran = true
		if res, ok := AuthorizationFromContext(r.Context()); ok {
			authorized = res.Operation
		}
		w.WriteHeader(http.StatusOK)
	}))
	return func(req AcceptanceRequest) AcceptanceObservation {
		ran, authorized = false, nil
		text, err := Canonicalize(req.Body)
		if err != nil {
			return AcceptanceObservation{Status: 400}
		}
		r := httptest.NewRequest(http.MethodPost, req.Path, bytes.NewReader([]byte(text)))
		for k, v := range req.Headers {
			r.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return AcceptanceObservation{Status: rec.Code, HandlerRan: ran, Operation: authorized}
	}
}

type acceptanceFixture struct {
	request func(verb string, signed float64, path string, sent float64) (AcceptanceRequest, error)
	options func(over func(*RequirePCAOptions)) RequirePCAOptions
}

func acceptanceRecorder() (*ProvenanceRecorder, error) {
	seed := bytes.Repeat([]byte{3}, 32)
	key, err := KeyPairFromSeed(seed)
	if err != nil {
		return nil, err
	}
	return NewProvenanceRecorder(ProvenanceRecorderOptions{Mediator: "adapter-acceptance", Kid: "k1", Key: key})
}

func acceptanceNums(fs ...float64) []any {
	out := make([]any, len(fs))
	for i, f := range fs {
		out[i] = jsNumber(f)
	}
	return out
}

func newAcceptanceFixture(limit string) (*acceptanceFixture, error) {
	principal, err := NewKeyPair()
	if err != nil {
		return nil, err
	}
	holder, err := NewKeyPair()
	if err != nil {
		return nil, err
	}
	var where []any
	if limit == "predicate" || limit == "escalate" {
		where = []any{map[string]any{"field": "action.params.amount", "op": "lte", "value": jsNumber(100)}}
	} else {
		where = []any{}
	}
	envelope := map[string]any{
		"predicates":    []any{map[string]any{"verb": []any{"payments.send", "payments.refund"}, "resource": "payments", "where": where}},
		"caveats":       []any{},
		"agent_binding": map[string]any{},
		// "spend = risk": each call is priced at amount / 100 and debits the amount from a far-away budget
		"risk_policy": map[string]any{
			"weights": map[string]any{"alpha": jsNumber(0), "beta": jsNumber(0), "gamma": jsNumber(1), "delta": jsNumber(0), "epsilon": jsNumber(0), "zeta": jsNumber(0)},
			"theta1":  jsNumber(1), "theta2": jsNumber(1), "kappa": jsNumber(100), "lambda": jsNumber(0), "rho": jsNumber(0.5), "bMax": jsNumber(1_000_000),
		},
	}
	if limit == "escalate" { // a payment over 50 asks the principal; with no answer it is refused
		envelope["tighten"] = []any{map[string]any{"id": "big_payment", "signal": "escalate",
			"when": map[string]any{"field": "action.params.amount", "op": "gt", "value": jsNumber(50)}}}
	}
	minted, err := MintGrant(principal, holder.Public, envelope, "pay invoices", "", "", nil)
	if err != nil {
		return nil, err
	}
	grant := minted.Grant
	if limit == "max_spend" { // a ROOT caveat outside the envelope, enforced like a delegated one
		var caveats []any
		switch c := grant["caveats"].(type) {
		case []any:
			caveats = append(caveats, c...)
		case []map[string]any:
			for _, x := range c {
				caveats = append(caveats, x)
			}
		}
		caveats = append(caveats, map[string]any{"type": "max_spend", "usd": jsNumber(100)})
		if grant, err = MintRoot(principal, holder.Public, caveats, "", nil); err != nil {
			return nil, err
		}
	}
	rec, err := acceptanceRecorder()
	if err != nil {
		return nil, err
	}
	var counter int64
	request := func(verb string, signed float64, path string, sent float64) (AcceptanceRequest, error) {
		params := map[string]any{"payee": "acme", "amount": jsNumber(signed)}
		digest, err := ParamsDigest(params)
		if err != nil {
			return AcceptanceRequest{}, err
		}
		node := map[string]any{"id": "n1", "verb": verb, "resource": "payments", "params_digest": digest, "reversibility_class": "irreversible"}
		counter++
		p, err := BuildPCActn(PCActnInput{Grant: grant, Chain: []map[string]any{grant}, Plan: []map[string]any{node}, NodeID: "n1",
			Params: params, Counter: counter, Signer: holder, Aud: AdapterAcceptanceAudience})
		if err != nil {
			return AcceptanceRequest{}, err
		}
		prov, err := PrincipalDirectProvenance(rec, Operation{Verb: verb, Resource: "payments", Params: params})
		if err != nil {
			return AcceptanceRequest{}, err
		}
		headers, err := PCAHeaders(p, nil, nil, nil)
		if err != nil {
			return AcceptanceRequest{}, err
		}
		ph, err := AdapterProvenanceHeaders(prov)
		if err != nil {
			return AcceptanceRequest{}, err
		}
		for k, v := range ph {
			headers[k] = v
		}
		headers["content-type"] = "application/json"
		return AcceptanceRequest{Path: path, Headers: headers, Body: map[string]any{"payee": "acme", "amount": jsNumber(sent)}}, nil
	}
	grantID, _ := grant["id"].(string)
	options := func(over func(*RequirePCAOptions)) RequirePCAOptions {
		o := RequirePCAOptions{
			Audience: AdapterAcceptanceAudience,
			ResolveGrant: func(ref string) (map[string]any, error) {
				if ref == grantID {
					return grant, nil
				}
				return nil, errors.New("unknown grant")
			},
			Authorize: &AuthorizeOptions{
				StateStore: NewMemoryStateStore(),
				IsRevoked:  func(_, _ map[string]any) (bool, error) { return false, nil },
				Plan:       PlanSingleStep,
				Risk: func(op *Operation, _, _ map[string]any) (map[string]any, error) {
					amount, _ := jsNum(op.Params["amount"])
					if amount > 100 {
						amount = 100
					}
					return map[string]any{"blastRadius": jsNumber(amount / 100), "semanticDistance": jsNumber(0), "reversibility": jsNumber(0),
						"taint": jsNumber(0), "confidence": jsNumber(1), "age": jsNumber(0)}, nil
				},
				ArgProvenance: &ArgProvenanceOptions{Mediators: []ProvMediatorPin{rec.Pin}},
			},
		}
		if over != nil {
			over(&o)
		}
		return o
	}
	return &acceptanceFixture{request: request, options: options}, nil
}

// RunAdapterAcceptance runs the matrix through harness and returns the observed outcome per scenario; compare it with
// AdapterAcceptanceExpected. The adapter derives the operation with the same route table (AcceptanceOperation), takes the proof
// from the PCA-Action header and the bundle from PCA-Provenance.
func RunAdapterAcceptance(harness AcceptanceHarness) (map[string]AcceptanceOutcome, error) {
	out := map[string]AcceptanceOutcome{}
	settle := func(req AcceptanceRequest, o AcceptanceObservation) AcceptanceOutcome {
		ran, _ := acceptanceOperationOf("POST", req.Path, mustCanonical(req.Body))
		bound := o.Operation != nil && ran != nil &&
			IsAuthorizedFor(AuthorizeResult{Allow: true, Status: 200, Operation: o.Operation, Decision: "allow"}, ran)
		return AcceptanceOutcome{Status: o.Status, HandlerRan: o.HandlerRan, Bound: bound}
	}
	var firstErr error
	fixtures := map[string]*acceptanceFixture{}
	for _, k := range []string{"predicate", "max_spend", "escalate"} {
		f, err := newAcceptanceFixture(k)
		if err != nil {
			return nil, err
		}
		fixtures[k] = f
	}
	once := func(name, fx, verb string, signed float64, path string, sent float64, over func(*RequirePCAOptions)) {
		f := fixtures[fx]
		req, err := f.request(verb, signed, path, sent)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		out[name] = settle(req, harness(f.options(over))(req))
	}
	once("over_limit_predicate", "predicate", "payments.send", 400, "/payments", 400, nil)
	once("over_limit_max_spend", "max_spend", "payments.send", 400, "/payments", 400, nil)
	once("body_differs", "predicate", "payments.send", 50, "/payments", 400, nil)
	once("other_operation", "predicate", "payments.send", 50, "/refunds", 50, nil)
	once("escalate_unanswered", "escalate", "payments.send", 70, "/payments", 70, nil)
	once("missing_revocation", "predicate", "payments.send", 50, "/payments", 50, func(o *RequirePCAOptions) { o.Authorize.IsRevoked = nil })
	once("missing_store", "predicate", "payments.send", 50, "/payments", 50, func(o *RequirePCAOptions) { o.Authorize.StateStore = nil })
	pred := fixtures["predicate"]
	send := harness(pred.options(nil))
	valid, err := pred.request("payments.send", 50, "/payments", 50)
	if err != nil {
		return nil, err
	}
	out["valid_first"] = settle(valid, send(valid))
	out["replay_second"] = settle(valid, send(valid))
	return out, firstErr
}

func mustCanonical(v any) []byte {
	s, err := Canonicalize(v)
	if err != nil {
		return nil
	}
	return []byte(s)
}

// AcceptanceDiff lists the scenarios whose observed outcome differs from AdapterAcceptanceExpected (empty = the adapter is accepted).
func AcceptanceDiff(got map[string]AcceptanceOutcome) []string {
	var bad []string
	for name, want := range AdapterAcceptanceExpected() {
		w := want.(map[string]any)
		g, ok := got[name]
		if !ok || g.Status != w["status"] || g.HandlerRan != w["handlerRan"] || g.Bound != w["bound"] {
			bad = append(bad, name)
		}
	}
	for name := range got {
		if _, ok := AdapterAcceptanceExpected()[name]; !ok {
			bad = append(bad, name)
		}
	}
	return bad
}
