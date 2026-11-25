package pca

// The grant management resource: list / inspect / amend / revoke and incremental authorization for principals, nothing widening in
// place. GrantService runs over a GrantStore (MemoryGrantStore is for tests and single-process use); GrantResourceHandler turns it
// into a framework-neutral handler over a plain request. The pure verdicts (amendment, revoke and need approval) are VerifyAmendment,
// VerifyRevokeSignature and VerifyNeedApproval in k3.go; this file adds the stateful service. Grant and need records are parsed JSON
// objects (map[string]any, numbers as json.Number). The authority comparison is the default one (no custom comparator).

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
)

const (
	// NeedRequestDomain: the holder (agent) signs the needs it files, so a server can attribute a request without a shared secret.
	NeedRequestDomain = "atlas-pca/need-request/v1\x00"
	// GrantStepUpDomain: the single-use challenge the principal signs on its own device, the step-up that gates a widening.
	GrantStepUpDomain = "atlas-pca/grant-stepup/v1\x00"
	// GrantsPath, NeedsPath and LeasesPath are the resource paths advertised in the discovery document.
	GrantsPath = "/pca/grants"
	NeedsPath  = "/pca/needs"
	LeasesPath = "/pca/leases"
)

// GrantAmendMessage is what an amendment signature covers: {grant, rev, action, authority digest}.
func GrantAmendMessage(grantID, rev, action, authority any) (map[string]any, error) {
	d, ok := AuthorityDigest(authority)
	if !ok {
		return nil, errors.New("authorityDigest: malformed authority")
	}
	return map[string]any{"grant": grantID, "rev": rev, "action": action, "authority": d}, nil
}

// GrantRevokeMessage is what a revocation signature covers: {grant, scope}.
func GrantRevokeMessage(id, scope any) map[string]any {
	return map[string]any{"grant": id, "scope": scope}
}

// NeedApproveMessage is what a needs approval signature covers: {need, grant, rev, approved}.
func NeedApproveMessage(needID, grantID, rev, approved any) map[string]any {
	return map[string]any{"need": needID, "grant": grantID, "rev": rev, "approved": approved}
}

// NeedRequestMessage is what the holder signs when it files needs: {grant, rev, needs}.
func NeedRequestMessage(grantID, rev, needs any) map[string]any {
	return map[string]any{"grant": grantID, "rev": rev, "needs": needs}
}

// GrantStepUpMessage is what the principal signs to satisfy a step-up: {grant, challenge, nonce}.
func GrantStepUpMessage(grantID, challengeID, nonce any) map[string]any {
	return map[string]any{"grant": grantID, "challenge": challengeID, "nonce": nonce}
}

// GrantError is a refusal with a stable Code: not_found, conflict, bad_request, not_narrower, signature_required, bad_signature,
// step_up_required, not_active, need_not_lowered_only, need_not_adjustable or forbidden.
type GrantError struct{ Code, Message string }

func (e *GrantError) Error() string { return e.Message }

var grantFailMessage = map[string]string{
	"not_found": "no such grant", "conflict": "conflict", "bad_request": "malformed request", "not_narrower": "a narrow amendment must be strictly narrower",
	"signature_required": "the amendment is signed (by the principal when it widens)", "bad_signature": "the signature does not verify for this grant revision",
	"step_up_required": "widening needs a satisfied step-up", "not_active": "grant is not active",
	"need_not_lowered_only": "an approval may only lower amounts of the requested needs", "need_not_adjustable": "the need is not adjustable", "forbidden": "not authorised",
}

var grantStatus = map[string]int{
	"not_found": 404, "conflict": 409, "bad_request": 400, "not_narrower": 422, "signature_required": 401, "bad_signature": 401, "step_up_required": 403,
	"not_active": 409, "need_not_lowered_only": 422, "need_not_adjustable": 422, "forbidden": 403,
}

func grantFail(code string) error { return &GrantError{code, grantFailMessage[code]} }

// GrantStore keeps grants and need requests. A missing record is nil. Implementations must return copies.
type GrantStore interface {
	Get(id string) (map[string]any, error)
	Put(g map[string]any) error
	List() ([]map[string]any, error)
	GetNeed(id string) (map[string]any, error)
	PutNeed(n map[string]any) error
	ListNeeds(grantID string) ([]map[string]any, error)
}

// MemoryGrantStore is the in-process store (it forgets everything on restart); records keep their insertion order.
type MemoryGrantStore struct {
	g, n   map[string]map[string]any
	gOrder []string
	nOrder []string
}

// NewMemoryGrantStore returns an empty in-memory store.
func NewMemoryGrantStore() *MemoryGrantStore {
	return &MemoryGrantStore{g: map[string]map[string]any{}, n: map[string]map[string]any{}}
}

func (s *MemoryGrantStore) Get(id string) (map[string]any, error) {
	return grantsCloneMap(s.g[id]), nil
}

func (s *MemoryGrantStore) Put(g map[string]any) error {
	id, ok := g["id"].(string)
	if !ok {
		return errors.New("grant store: a grant needs a string id")
	}
	if _, has := s.g[id]; !has {
		s.gOrder = append(s.gOrder, id)
	}
	s.g[id] = grantsCloneMap(g)
	return nil
}

func (s *MemoryGrantStore) List() ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(s.gOrder))
	for _, id := range s.gOrder {
		out = append(out, grantsCloneMap(s.g[id]))
	}
	return out, nil
}

func (s *MemoryGrantStore) GetNeed(id string) (map[string]any, error) {
	return grantsCloneMap(s.n[id]), nil
}

func (s *MemoryGrantStore) PutNeed(n map[string]any) error {
	id, ok := n["id"].(string)
	if !ok {
		return errors.New("grant store: a need request needs a string id")
	}
	if _, has := s.n[id]; !has {
		s.nOrder = append(s.nOrder, id)
	}
	s.n[id] = grantsCloneMap(n)
	return nil
}

func (s *MemoryGrantStore) ListNeeds(grantID string) ([]map[string]any, error) {
	out := []map[string]any{}
	for _, id := range s.nOrder {
		if s.n[id]["grant_id"] == grantID {
			out = append(out, grantsCloneMap(s.n[id]))
		}
	}
	return out, nil
}

// GrantProviders fill the optional members of a grant view (a nil provider adds nothing).
type GrantProviders struct {
	Usage, RemainingBudget, PolicyCard, Residual func(g map[string]any) any
}

// GrantServiceOptions configure a GrantService. Now (epoch ms) and NewID (kind "grant" or "need") are required.
type GrantServiceOptions struct {
	Store     GrantStore
	Now       func() int64
	NewID     func(kind string) string
	Providers *GrantProviders
	// VerifyStepUp confirms a satisfied step-up for a widening change. nil: widening is refused (fail closed).
	VerifyStepUp func(ref any, grant map[string]any) bool
	// OnRevoke is called with every grant id revoked (registry and event hook).
	OnRevoke func(ids []string, scope string, root map[string]any)
	// OnChange is called on every state change: kind is amend, revoke, supersede or need.
	OnChange func(kind string, g map[string]any)
	// ValidateNeed is the optional typed validation of a need: a non-empty string refuses it.
	ValidateNeed func(n map[string]any) string
}

// GrantListFilter filters GrantService.List. A nil member is absent; Limit defaults to 50 (clamped to 1..200).
type GrantListFilter struct {
	Principal any
	Agent     *string
	Status    *string
	Limit     *float64
	Cursor    *string
}

// GrantService is the grant management service.
type GrantService struct{ o GrantServiceOptions }

// NewGrantService builds a service over the options.
func NewGrantService(o GrantServiceOptions) *GrantService { return &GrantService{o} }

func grantsNumNow(n int64) any { return jsNumber(float64(n)) }

// Register creates a grant record (the host calls this when a grant is registered).
func (s *GrantService) Register(g map[string]any) (map[string]any, error) {
	if _, ok := parseAuthority(g["authority"]); !ok {
		return nil, &GrantError{"bad_request", "malformed authority"}
	}
	id, ok := g["id"].(string)
	if !ok {
		return nil, grantFail("bad_request")
	}
	prev, err := s.o.Store.Get(id)
	if err != nil {
		return nil, err
	}
	if prev != nil {
		return nil, &GrantError{"conflict", "grant id exists"}
	}
	now := grantsNumNow(s.o.Now())
	d, ok := AuthorityDigest(g["authority"])
	if !ok {
		return nil, grantFail("bad_request")
	}
	rec := grantsCloneMap(g)
	if rec["status"] == nil {
		rec["status"] = "active"
	}
	rec["rev"], rec["created_at"] = json.Number("1"), now
	rec["history"] = []any{map[string]any{"rev": json.Number("1"), "authority_digest": d, "at": now, "action": "create"}}
	if err := s.o.Store.Put(rec); err != nil {
		return nil, err
	}
	return rec, nil
}

// List is one page of grant views (without their rich members), ordered by id; next_cursor is set when more follow.
func (s *GrantService) List(f GrantListFilter) (map[string]any, error) {
	lim := 50.0
	if f.Limit != nil {
		lim = *f.Limit
	}
	limit := math.Min(math.Max(lim, 1), 200)
	all, err := s.o.Store.List()
	if err != nil {
		return nil, err
	}
	kept := []map[string]any{}
	for _, g := range all {
		if (f.Principal == nil || grantsEq(g["principal"], f.Principal)) && (f.Agent == nil || grantsEq(g["agent"], *f.Agent)) && (f.Status == nil || grantsEq(g["status"], *f.Status)) {
			kept = append(kept, g)
		}
	}
	grantsSortByID(kept)
	if f.Cursor != nil {
		after := []map[string]any{}
		for _, g := range kept {
			if id, _ := g["id"].(string); grantsU16Less(*f.Cursor, id) {
				after = append(after, g)
			}
		}
		kept = after
	}
	n := 0
	if limit > 0 { // a NaN limit slices nothing
		n = int(limit)
	}
	if n > len(kept) {
		n = len(kept)
	}
	page := kept[:n]
	views := make([]any, 0, len(page))
	for _, g := range page {
		v, err := s.view(g, false)
		if err != nil {
			return nil, err
		}
		views = append(views, v)
	}
	out := map[string]any{"grants": views}
	if float64(len(kept)) > limit {
		out["next_cursor"] = page[len(page)-1]["id"]
	}
	return out, nil
}

func grantsSortByID(l []map[string]any) {
	for i := 1; i < len(l); i++ {
		for j := i; j > 0; j-- {
			a, _ := l[j-1]["id"].(string)
			b, _ := l[j]["id"].(string)
			if !grantsU16Less(b, a) {
				break
			}
			l[j-1], l[j] = l[j], l[j-1]
		}
	}
}

// Inspect is the rich view of one grant (usage, budget, policy card and residual when the providers supply them).
func (s *GrantService) Inspect(id string) (map[string]any, error) {
	g, err := s.must(id)
	if err != nil {
		return nil, err
	}
	return s.view(g, true)
}

func (s *GrantService) view(g map[string]any, rich bool) (map[string]any, error) {
	view := withoutKeys(g, "history")
	d, ok := AuthorityDigest(g["authority"])
	if !ok {
		return nil, errors.New("authorityDigest: malformed authority")
	}
	view["authority_digest"] = d
	id, _ := g["id"].(string)
	needs, err := s.o.Store.ListNeeds(id)
	if err != nil {
		return nil, err
	}
	pending := []any{}
	for _, n := range needs {
		if n["status"] == "pending" {
			pending = append(pending, n["id"])
		}
	}
	view["pending_needs"] = pending
	if p := s.o.Providers; rich && p != nil {
		for _, e := range []struct {
			k string
			f func(map[string]any) any
		}{{"usage", p.Usage}, {"remaining_budget", p.RemainingBudget}, {"policy_card", p.PolicyCard}, {"residual", p.Residual}} {
			if e.f != nil {
				view[e.k] = e.f(g)
			}
		}
	}
	return view, nil
}

func (s *GrantService) must(id string) (map[string]any, error) {
	g, err := s.o.Store.Get(id)
	if err != nil {
		return nil, err
	}
	if g == nil {
		return nil, &GrantError{"not_found", "no such grant"}
	}
	return g, nil
}

func (s *GrantService) changed(kind string, g map[string]any) {
	if s.o.OnChange != nil {
		s.o.OnChange(kind, g)
	}
}

func grantsHistoryAppend(g map[string]any, e map[string]any) {
	h, _ := g["history"].([]any)
	g["history"] = append(h, e)
}

func grantsDigestOf(a any) (string, error) {
	d, ok := AuthorityDigest(a)
	if !ok {
		return "", errors.New("authorityDigest: malformed authority")
	}
	return d, nil
}

// GrantResult is the outcome of an amendment or a needs approval: the grant view and whether a new grant id was created.
type GrantResult struct {
	Grant   map[string]any
	Created bool
}

// grantSupersede builds the fresh grant that replaces cur (a widening) and marks cur superseded; the caller stores both.
func grantSupersede(cur map[string]any, nid string, authority any, now any, action string, digest string) map[string]any {
	fresh := grantsCloneMap(cur)
	fresh["id"], fresh["authority"], fresh["rev"], fresh["status"] = nid, grantsClone(authority), json.Number("1"), "active"
	fresh["supersedes"], fresh["created_at"] = cur["id"], now
	fresh["history"] = []any{map[string]any{"rev": json.Number("1"), "authority_digest": digest, "at": now, "action": action}}
	delete(fresh, "superseded_by")
	cur["status"], cur["superseded_by"] = "superseded", nid
	return fresh
}

// Amend applies an amendment request ({action, authority, sig, signed_by, step_up_ref?}). A change that is not wider revises the
// grant in place; a widening creates a new grant id with `supersedes` and marks the old grant superseded.
func (s *GrantService) Amend(id string, req any) (*GrantResult, error) {
	cur, err := s.must(id)
	if err != nil {
		return nil, err
	}
	v := VerifyAmendment(cur, req, false)
	// evaluate the (possibly consuming) step-up only when everything else already passed
	if !v.OK && v.Code == "step_up_required" {
		if r, ok := req.(map[string]any); ok && jsTruthy(r["step_up_ref"]) && s.o.VerifyStepUp != nil && s.o.VerifyStepUp(r["step_up_ref"], cur) {
			v = VerifyAmendment(cur, req, true)
		}
	}
	if !v.OK {
		return nil, grantFail(v.Code)
	}
	action := req.(map[string]any)["action"]
	now := grantsNumNow(s.o.Now())
	if !v.Widens {
		cur["authority"] = grantsClone(v.Next)
		cur["rev"] = jsNumber(jsF(cur["rev"]) + 1)
		grantsHistoryAppend(cur, map[string]any{"rev": cur["rev"], "authority_digest": v.NextDigest, "at": now, "action": action})
		if err := s.o.Store.Put(cur); err != nil {
			return nil, err
		}
		s.changed("amend", cur)
		view, err := s.view(cur, true)
		return &GrantResult{view, false}, err
	}
	nid := s.o.NewID("grant")
	curID, _ := cur["id"].(string)
	fresh := grantSupersede(cur, nid, v.Next, now, "supersedes:"+curID, v.NextDigest)
	if err := s.o.Store.Put(fresh); err != nil {
		return nil, err
	}
	if err := s.o.Store.Put(cur); err != nil {
		return nil, err
	}
	s.changed("supersede", fresh)
	view, err := s.view(fresh, true)
	return &GrantResult{view, true}, err
}

// Revoke is authorised by the principal's signature over {grant id, scope} (auth has "sig") or by a host-authenticated admin
// (auth has admin: true; the host has already checked its own credential). "agent" revokes every grant of the grant's agent and
// principal; "subtree" the grant and every descendant by `parent`. The result is {revoked: [ids]}.
func (s *GrantService) Revoke(id string, scope any, auth map[string]any) (map[string]any, error) {
	sc, _ := scope.(string)
	if sc != "grant" && sc != "agent" && sc != "subtree" {
		return nil, &GrantError{"bad_request", "unknown scope"}
	}
	root, err := s.must(id)
	if err != nil {
		return nil, err
	}
	if sig, has := auth["sig"]; has {
		if rv := VerifyRevokeSignature(root, sc, sig); !rv.OK {
			return nil, grantFail(rv.Code)
		}
	} else if auth["admin"] != true {
		return nil, &GrantError{"forbidden", "not authorised"}
	}
	all, err := s.o.Store.List()
	if err != nil {
		return nil, err
	}
	var hit []map[string]any
	switch sc {
	case "grant":
		hit = []map[string]any{root}
	case "agent":
		for _, g := range all {
			if grantsEq(g["agent"], root["agent"]) && grantsEq(g["principal"], root["principal"]) {
				hit = append(hit, g)
			}
		}
	default:
		ids := map[string]bool{id: true}
		for grew := true; grew; {
			grew = false
			for _, g := range all {
				gid, _ := g["id"].(string)
				if p, ok := g["parent"].(string); ok && ids[p] && !ids[gid] {
					ids[gid], grew = true, true
				}
			}
		}
		for _, g := range all {
			if gid, _ := g["id"].(string); ids[gid] {
				hit = append(hit, g)
			}
		}
	}
	revoked := []string{}
	for _, g := range hit {
		if g["status"] == "revoked" {
			continue
		}
		g["status"] = "revoked"
		d, err := grantsDigestOf(g["authority"])
		if err != nil {
			return nil, err
		}
		grantsHistoryAppend(g, map[string]any{"rev": g["rev"], "authority_digest": d, "at": grantsNumNow(s.o.Now()), "action": "revoke:" + sc})
		if err := s.o.Store.Put(g); err != nil {
			return nil, err
		}
		gid, _ := g["id"].(string)
		revoked = append(revoked, gid)
	}
	if s.o.OnRevoke != nil {
		s.o.OnRevoke(revoked, sc, root)
	}
	s.changed("revoke", root)
	out := make([]any, len(revoked))
	for i, r := range revoked {
		out[i] = r
	}
	return map[string]any{"revoked": out}, nil
}

func grantsNeedsOK(n any) bool {
	m, ok := n.(map[string]any)
	if !ok || !k3Str(m["verb"], 128) || !k3Str(m["resource"], 512) {
		return false
	}
	lv, has := m["limits"]
	if !has {
		return true
	}
	lm, ok := lv.(map[string]any)
	if !ok {
		return false
	}
	for _, v := range lm {
		f, isNum := jsNum(v)
		if !isNum || math.IsInf(f, 0) || math.IsNaN(f) || f < 0 {
			return false
		}
	}
	return true
}

// RequestNeeds is the agent side: ask for more. Typed needs only (1 to 32, validated); no authority changes until the principal approves.
func (s *GrantService) RequestNeeds(grantID string, needs any) (map[string]any, error) {
	g, err := s.must(grantID)
	if err != nil {
		return nil, err
	}
	if g["status"] != "active" {
		return nil, &GrantError{"not_active", "grant is " + jsValueString(g["status"])}
	}
	l, ok := needs.([]any)
	if !ok || len(l) < 1 || len(l) > 32 {
		return nil, &GrantError{"bad_request", "1..32 needs"}
	}
	for _, n := range l {
		if !grantsNeedsOK(n) {
			return nil, &GrantError{"bad_request", "malformed need"}
		}
		if s.o.ValidateNeed != nil {
			if e := s.o.ValidateNeed(n.(map[string]any)); e != "" {
				return nil, &GrantError{"bad_request", e}
			}
		}
	}
	nr := map[string]any{"id": s.o.NewID("need"), "grant_id": grantID, "needs": grantsClone(needs), "status": "pending", "created_at": grantsNumNow(s.o.Now())}
	if err := s.o.Store.PutNeed(nr); err != nil {
		return nil, err
	}
	s.changed("need", g)
	return nr, nil
}

// ApproveNeeds is the principal side: approve the delta (amounts may only be LOWERED, and only when the need is adjustable). The
// principal signs NeedApproveMessage; the result is a widening merge into a new grant id.
func (s *GrantService) ApproveNeeds(needID string, approved any, sig any, stepUpRef any) (*GrantResult, error) {
	nr, err := s.o.Store.GetNeed(needID)
	if err != nil {
		return nil, err
	}
	if nr == nil {
		return nil, &GrantError{"not_found", "no such need request"}
	}
	if nr["status"] != "pending" {
		return nil, &GrantError{"conflict", "need request is " + jsValueString(nr["status"])}
	}
	gid, _ := nr["grant_id"].(string)
	g, err := s.must(gid)
	if err != nil {
		return nil, err
	}
	v := VerifyNeedApproval(nr, g, approved, sig, false)
	if !v.OK && v.Code == "step_up_required" && jsTruthy(stepUpRef) && s.o.VerifyStepUp != nil && s.o.VerifyStepUp(stepUpRef, g) {
		v = VerifyNeedApproval(nr, g, approved, sig, true)
	}
	if !v.OK {
		return nil, grantFail(v.Code)
	}
	nid := s.o.NewID("grant")
	fresh := grantSupersede(g, nid, v.Authority, grantsNumNow(s.o.Now()), "needs:"+needID, v.AuthorityDigest)
	nr["status"], nr["result_grant_id"] = "approved", nid
	if err := s.o.Store.Put(fresh); err != nil {
		return nil, err
	}
	if err := s.o.Store.Put(g); err != nil {
		return nil, err
	}
	if err := s.o.Store.PutNeed(nr); err != nil {
		return nil, err
	}
	s.changed("supersede", fresh)
	view, err := s.view(fresh, true)
	return &GrantResult{view, true}, err
}

// NeedGrantID is the grant a need request belongs to (the HTTP binding uses it to scope a caller to its own grants).
func (s *GrantService) NeedGrantID(needID string) (string, error) {
	nr, err := s.o.Store.GetNeed(needID)
	if err != nil {
		return "", err
	}
	if nr == nil {
		return "", &GrantError{"not_found", "no such need request"}
	}
	id, _ := nr["grant_id"].(string)
	return id, nil
}

// DenyNeeds refuses a pending need request.
func (s *GrantService) DenyNeeds(needID string) error {
	nr, err := s.o.Store.GetNeed(needID)
	if err != nil {
		return err
	}
	if nr == nil {
		return &GrantError{"not_found", "no such need request"}
	}
	if nr["status"] != "pending" {
		return &GrantError{"conflict", "need request is " + jsValueString(nr["status"])}
	}
	nr["status"] = "denied"
	return s.o.Store.PutNeed(nr)
}

// ---- HTTP binding ----------------------------------------------------------------------------------------------------

// GrantsHTTPRequest is a framework-neutral request: Path is the path below the mount point (e.g. /pca/grants/g_1/amend). Who is
// whatever the host's Authenticate wants to read from the request.
type GrantsHTTPRequest struct {
	Method, Path string
	Query        map[string]string
	Body         any
	Who          any
}

// GrantsHTTPResponse is a status and a JSON body.
type GrantsHTTPResponse struct {
	Status int
	Body   any
}

// GrantsHTTPOptions: Authenticate returns who is calling as the host authenticated them ({principal?, admin?}), or nil. A principal
// limits every read and write to that principal's grants.
type GrantsHTTPOptions struct {
	Authenticate func(req *GrantsHTTPRequest) map[string]any
}

// GrantManagementMetadata is the discovery fragment for /.well-known/pca-configuration.
func GrantManagementMetadata(base string) map[string]any {
	return map[string]any{"grant_management": map[string]any{
		"grants_endpoint": base + GrantsPath, "needs_endpoint": base + NeedsPath,
		"amend_actions": []any{"narrow", "merge", "replace"}, "revoke_scopes": []any{"grant", "agent", "subtree"}, "widening": "new_grant_id_with_supersedes"}}
}

func grantsErrResponse(e error) GrantsHTTPResponse {
	var ge *GrantError
	if errors.As(e, &ge) {
		return GrantsHTTPResponse{grantStatus[ge.Code], map[string]any{"error": ge.Code, "message": ge.Message}}
	}
	return GrantsHTTPResponse{500, map[string]any{"error": "server_error"}}
}

func grantsSegments(p string) []string {
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func grantsSeg(seg []string, i int) string {
	if i < len(seg) {
		return seg[i]
	}
	return ""
}

var grantsNotFound = GrantsHTTPResponse{404, map[string]any{"error": "not_found"}}

// GrantResourceHandler is the HTTP binding of the grant management resource:
//
//	GET /pca/grants, GET /pca/grants/{id}, DELETE /pca/grants/{id}, POST /pca/grants/{id}/amend, POST /pca/grants/{id}/needs,
//	POST /pca/needs/{id}/approve, POST /pca/needs/{id}/deny
func GrantResourceHandler(svc *GrantService, o GrantsHTTPOptions) func(req *GrantsHTTPRequest) GrantsHTTPResponse {
	return func(req *GrantsHTTPRequest) (resp GrantsHTTPResponse) {
		defer func() {
			if recover() != nil {
				resp = GrantsHTTPResponse{500, map[string]any{"error": "server_error"}}
			}
		}()
		var who map[string]any
		if o.Authenticate != nil {
			who = o.Authenticate(req)
		}
		if who == nil || (!jsTruthy(who["admin"]) && !jsTruthy(who["principal"])) {
			return GrantsHTTPResponse{401, map[string]any{"error": "unauthenticated"}}
		}
		admin := jsTruthy(who["admin"])
		seg := grantsSegments(req.Path)
		q := req.Query
		b, _ := req.Body.(map[string]any)
		// a principal-scoped caller may only see and touch its own grants
		own := func(id string) error {
			g, err := svc.Inspect(id)
			if err != nil {
				return err
			}
			if !admin && !grantsEq(g["principal"], who["principal"]) {
				return &GrantError{"not_found", "no such grant"}
			}
			return nil
		}
		fail := func(e error) GrantsHTTPResponse { return grantsErrResponse(e) }
		if grantsSeg(seg, 0) != "pca" {
			return grantsNotFound
		}
		kind, method := grantsSeg(seg, 1), req.Method
		if kind == "grants" {
			if len(seg) == 2 && method == "GET" {
				st, hasStatus := q["status"]
				if hasStatus && st != "active" && st != "revoked" && st != "superseded" {
					return fail(&GrantError{"bad_request", "bad status"})
				}
				var principal any
				if admin {
					if p, ok := q["principal"]; ok {
						principal = p
					}
				} else {
					principal = who["principal"]
				}
				var f GrantListFilter
				if jsTruthy(principal) {
					f.Principal = principal
				}
				if a := q["agent"]; a != "" {
					f.Agent = &a
				}
				if hasStatus && st != "" {
					f.Status = &st
				}
				if ls, ok := q["limit"]; ok {
					if n := jsStringToNumber(ls); !math.IsNaN(n) && !math.IsInf(n, 0) {
						f.Limit = &n
					}
				}
				if c := q["cursor"]; c != "" {
					f.Cursor = &c
				}
				r, err := svc.List(f)
				if err != nil {
					return fail(err)
				}
				return GrantsHTTPResponse{200, r}
			}
			id := grantsSeg(seg, 2)
			if id == "" {
				return grantsNotFound
			}
			if err := own(id); err != nil {
				return fail(err)
			}
			if len(seg) == 3 && method == "GET" {
				r, err := svc.Inspect(id)
				if err != nil {
					return fail(err)
				}
				return GrantsHTTPResponse{200, r}
			}
			if len(seg) == 3 && method == "DELETE" {
				scope := "grant"
				if sc, ok := q["scope"]; ok {
					scope = sc
				}
				sig, _ := b["sig"].(string)
				auth := map[string]any{"sig": sig}
				// a principal-scoped caller must still sign; only an admin may revoke without a principal signature
				if admin && sig == "" {
					auth = map[string]any{"admin": true}
				}
				r, err := svc.Revoke(id, scope, auth)
				if err != nil {
					return fail(err)
				}
				return GrantsHTTPResponse{200, r}
			}
			if len(seg) == 4 && seg[3] == "amend" && method == "POST" {
				r, err := svc.Amend(id, req.Body)
				if err != nil {
					return fail(err)
				}
				if r.Created {
					return GrantsHTTPResponse{201, r.Grant}
				}
				return GrantsHTTPResponse{200, r.Grant}
			}
			if len(seg) == 4 && seg[3] == "needs" && method == "POST" {
				r, err := svc.RequestNeeds(id, b["needs"])
				if err != nil {
					return fail(err)
				}
				return GrantsHTTPResponse{201, r}
			}
		}
		if kind == "needs" && grantsSeg(seg, 2) != "" && grantsSeg(seg, 3) == "approve" && method == "POST" {
			gid, err := svc.NeedGrantID(seg[2])
			if err == nil {
				err = own(gid)
			}
			if err != nil {
				return fail(err)
			}
			sig, isStr := b["sig"].(string)
			approved, isArr := b["approved"].([]any)
			if !isStr || !isArr {
				return fail(&GrantError{"bad_request", "sig and approved are required"})
			}
			var step any
			if s, ok := b["step_up_ref"].(string); ok {
				step = s
			}
			r, err := svc.ApproveNeeds(seg[2], approved, sig, step)
			if err != nil {
				return fail(err)
			}
			return GrantsHTTPResponse{201, r.Grant}
		}
		if kind == "needs" && grantsSeg(seg, 2) != "" && grantsSeg(seg, 3) == "deny" && method == "POST" {
			gid, err := svc.NeedGrantID(seg[2])
			if err == nil {
				err = own(gid)
			}
			if err == nil {
				err = svc.DenyNeeds(seg[2])
			}
			if err != nil {
				return fail(err)
			}
			return GrantsHTTPResponse{200, map[string]any{"status": "denied"}}
		}
		return grantsNotFound
	}
}
