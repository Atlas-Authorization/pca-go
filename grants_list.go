package pca

// List-authorized: "which objects of this type may this agent touch?". Authority is capability AND relationship: Permits (the
// grant's own predicates) decides, a relation source can only NARROW. Every page is charged to a read accumulator (scanned AND
// returned objects), pages are bound by a signed cursor (changing subject, type, filter, policy, relation or limit between pages
// is refused) and the result carries a signed receipt. Verification of receipts and cursors is VerifyListReceipt / VerifyListCursor.

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxPageLimit is the largest page a list call may ask for.
const MaxPageLimit = 500

// ListError is a refusal of ListAuthorized. Code is read_budget_exhausted, bad_cursor or bad_limit.
type ListError struct{ Code, Message string }

func (e *ListError) Error() string { return e.Message }

// ListPageQuery is one candidate page request. Cursor nil: the first page. Subject and Relation are set when the page comes from a
// relation source (CandidatesFromRelation).
type ListPageQuery struct {
	Type              string
	Cursor            *string
	Limit             int
	Subject, Relation string
}

// ListCandidatePage is one page of candidate object ids. Next nil (or empty): the last page.
type ListCandidatePage struct {
	Objects []string
	Next    *string
}

// ListCandidates is a candidate source: the objects of a type, a page at a time.
type ListCandidates func(q ListPageQuery) (ListCandidatePage, error)

// ListRelation is a relation source: Check may only narrow; ListObjects (optional) enumerates objects directly.
type ListRelation struct {
	Name        string
	Check       func(subject, relation, object string) (bool, error)
	ListObjects func(q ListPageQuery) (ListCandidatePage, error)
}

// CandidatesFromRelation adapts a relation source's ListObjects into a candidate source for one subject and relation.
func CandidatesFromRelation(rel *ListRelation, subject, relation string) (ListCandidates, error) {
	if rel == nil || rel.ListObjects == nil {
		return nil, errors.New("candidatesFromRelation: the relation source has no listObjects")
	}
	return func(q ListPageQuery) (ListCandidatePage, error) {
		q.Subject, q.Relation = subject, relation
		return rel.ListObjects(q)
	}, nil
}

// ListReadAccumulator charges reads against a budget keyed by (subject, type); false when the charge would exceed the cap.
type ListReadAccumulator interface {
	Charge(key string, units, now float64) bool
}

// WindowReadAccumulator is the reference accumulator: cap units per window (ms) fixed window per key.
type WindowReadAccumulator struct {
	cap, window float64
	used        map[string]*[2]float64 // key -> {window start, units used}
}

// NewWindowReadAccumulator builds an accumulator allowing cap units per windowMs.
func NewWindowReadAccumulator(cap, windowMs float64) *WindowReadAccumulator {
	return &WindowReadAccumulator{cap: cap, window: windowMs, used: map[string]*[2]float64{}}
}

// Charge implements ListReadAccumulator.
func (a *WindowReadAccumulator) Charge(key string, units, now float64) bool {
	if !finite(units) || !finite(now) {
		return false
	}
	cur := a.used[key]
	if cur == nil || now-cur[0] >= a.window {
		cur = &[2]float64{now, 0}
	}
	if !(cur[1]+units <= a.cap) {
		return false
	}
	cur[1] += units
	a.used[key] = cur
	return true
}

// ListAuthorizedArgs are the inputs of ListAuthorized. Relation nil: no relation filter. Cursor nil: the first page. MaxScan nil:
// 4 times the limit (at most 1000).
type ListAuthorizedArgs struct {
	Subject, ResourceType  string
	Permits                func(object string) bool
	Candidates             ListCandidates
	Relation               *ListRelation
	FilterID, PolicyDigest string
	FreshAtDigest          string
	Cursor                 *string
	Limit                  int64
	Reads                  ListReadAccumulator
	Now                    any
	Signing                *KeyPair
	MaxScan                *int64
}

// ListAuthorizedResult is one page: the objects, the cursor of the next page (empty on the last) and the signed receipt.
type ListAuthorizedResult struct {
	Objects    []string       `json:"objects"`
	NextCursor string         `json:"next_cursor,omitempty"`
	Receipt    map[string]any `json:"receipt"`
}

// grantsJSONString is JSON.stringify of a string.
func grantsJSONString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		i += n
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20:
			b.WriteString(`\u00`)
			b.WriteString(string("0123456789abcdef"[r>>4]))
			b.WriteString(string("0123456789abcdef"[r&15]))
		case r == utf8.RuneError && n == 1:
			b.WriteString(`�`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func grantsEncCursor(inner *string, skip int, bind, signer string, k *KeyPair) (string, error) {
	c := map[string]any{"v": json.Number("1"), "skip": jsNumber(float64(skip)), "bind": bind, "signer": signer}
	var js strings.Builder
	js.WriteString(`{"v":1,`)
	if inner != nil {
		c["inner"] = *inner
		js.WriteString(`"inner":` + grantsJSONString(*inner) + ",")
	}
	js.WriteString(`"skip":` + strconv.Itoa(skip) + `,"bind":` + grantsJSONString(bind) + `,"signer":` + grantsJSONString(signer) + "}")
	sig, err := signBody(k, listCursorDomain, c)
	if err != nil {
		return "", err
	}
	return b64.EncodeToString([]byte(js.String())) + "." + sig, nil
}

// ListAuthorized returns one page of authorized objects with its receipt. It returns a *ListError (bad_limit, bad_cursor,
// read_budget_exhausted) for the refusals of the reference; a failing candidate, relation or accumulator is returned as is.
func ListAuthorized(a ListAuthorizedArgs) (*ListAuthorizedResult, error) {
	if a.Limit < 1 || a.Limit > MaxPageLimit {
		return nil, &ListError{"bad_limit", "limit must be 1.." + strconv.Itoa(MaxPageLimit)}
	}
	limit := int(a.Limit)
	signer := a.Signing.Public
	bi := ListBindInputs{Subject: a.Subject, ResourceType: a.ResourceType, FilterID: a.FilterID, PolicyDigest: a.PolicyDigest, Limit: limit}
	if a.Relation != nil {
		name := a.Relation.Name
		bi.Relation = &name
	}
	bind, ok := ListBind(bi)
	if !ok {
		return nil, errors.New("listBind: not canonicalizable")
	}
	var inner *string
	skipIn := 0
	if a.Cursor != nil {
		c := VerifyListCursor(*a.Cursor, signer, &bi)
		if !c.OK {
			msg := "the page cursor is malformed, forged or from another signer"
			if c.Reason == "bind" {
				msg = "subject, type, filter, policy or limit changed between pages"
			}
			return nil, &ListError{"bad_cursor", msg}
		}
		if c.HasInner {
			s := c.Inner
			inner = &s
		}
		skipIn = int(c.Skip)
	}
	maxScan := int64(limit) * 4
	if a.MaxScan != nil {
		maxScan = *a.MaxScan
	}
	if maxScan > 1000 {
		maxScan = 1000
	}
	key, err := HashCanonical(map[string]any{"s": a.Subject, "t": a.ResourceType})
	if err != nil {
		return nil, err
	}
	now := jsF(a.Now)
	out := []string{}
	scanned := int64(0)
	pageStart, skip := inner, skipIn
	var resumeInner *string
	resumeSkip, resumed := 0, false
	for {
		pg, err := a.Candidates(ListPageQuery{Type: a.ResourceType, Cursor: pageStart, Limit: limit})
		if err != nil {
			return nil, err
		}
		objs := pg.Objects
		if len(objs) > limit {
			objs = objs[:limit]
		}
		// charge what was SCANNED before anything is returned: enumeration by filter-heavy scans is the attack
		units := float64(len(objs) - skip)
		if units < 1 {
			units = 1
		}
		if !a.Reads.Charge(key, units, now) {
			return nil, &ListError{"read_budget_exhausted", "the read budget for this subject and type is exhausted"}
		}
		i := skip
		for ; i < len(objs) && len(out) < limit; i++ {
			scanned++
			o := objs[i]
			if !a.Permits(o) {
				continue
			}
			if a.Relation != nil {
				allowed, err := a.Relation.Check(a.Subject, a.Relation.Name, o)
				if err != nil {
					return nil, err
				}
				if !allowed {
					continue
				}
			}
			out = append(out, o)
		}
		if i < len(objs) {
			resumeInner, resumeSkip, resumed = pageStart, i, true
			break
		}
		if pg.Next == nil || *pg.Next == "" || len(objs) == 0 {
			break
		}
		pageStart, skip = pg.Next, 0
		if len(out) >= limit || scanned >= maxScan {
			resumeInner, resumeSkip, resumed = pg.Next, 0, true
			break
		}
	}
	od, ok := ObjectsDigest(out)
	if !ok {
		return nil, errors.New("objectsDigest: not canonicalizable")
	}
	receipt := map[string]any{"v": json.Number("1"), "subject": a.Subject, "resource_type": a.ResourceType, "policy_digest": a.PolicyDigest,
		"fresh_at": a.FreshAtDigest, "filter_digest": a.FilterID, "count": jsNumber(float64(len(out))), "objects_digest": od, "issued_at": a.Now, "signer": signer}
	res := &ListAuthorizedResult{Objects: out}
	if resumed {
		if res.NextCursor, err = grantsEncCursor(resumeInner, resumeSkip, bind, signer, a.Signing); err != nil {
			return nil, err
		}
	}
	sig, err := signBody(a.Signing, listReceiptDomain, receipt)
	if err != nil {
		return nil, err
	}
	receipt["sig"] = sig
	res.Receipt = receipt
	return res, nil
}
