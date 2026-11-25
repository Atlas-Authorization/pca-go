package pca

// FGA for RAG: retrieval-time, per-principal document filtering driven by the PCA policy evaluator (the pure core of the
// TypeScript pca-rag package).
//
// FAIL CLOSED: a document is admitted only when a permit predicate cleanly matches one of its ACL entries (verb = relation,
// resource = object) and no deny predicate matches. Anything unknown (no ACL, a malformed document, an incomplete policy
// translation, an evaluator error) drops the document. Every decision is recorded, with a content digest of the whole
// decision set.
//
// Values are JSON values (map[string]any, []any, string, bool, numbers). A principal is a string id or a map
// {id, attributes?, env?}. A policy is a []any of predicates, {openfga: {model, tuples}}, {predicates, denies?, report?} or an
// already-compiled policy (RagCompilePolicy).

import (
	"errors"
	"fmt"
)

func ragNonEmpty(v any) bool { s, ok := v.(string); return ok && s != "" }

func ragIsDocAcl(v any) bool {
	m, ok := v.(map[string]any)
	return ok && ragNonEmpty(m["relation"]) && ragNonEmpty(m["object"])
}

func ragAclArray(acl any) []any {
	out := []any{}
	if l, ok := acl.([]any); ok {
		for _, a := range l {
			if ragIsDocAcl(a) {
				out = append(out, a)
			}
		}
	} else if ragIsDocAcl(acl) {
		out = append(out, acl)
	}
	return out
}

// ragTagToAcl reads a `relation:object` tag; the split is at the FIRST colon, so an object id may itself contain colons.
func ragTagToAcl(tag any) map[string]any {
	t, ok := tag.(string)
	if !ok {
		return nil
	}
	for i := 0; i < len(t); i++ {
		if t[i] == ':' {
			if i == 0 || i == len(t)-1 {
				return nil
			}
			return map[string]any{"relation": t[:i], "object": t[i+1:]}
		}
	}
	return nil
}

// RagAclsFromMetadata collects ACL entries from freeform `acl` (one entry or a list) and `tags` (`relation:object` strings) metadata.
func RagAclsFromMetadata(acl, tags any) []any {
	out := ragAclArray(acl)
	if l, ok := tags.([]any); ok {
		for _, t := range l {
			if a := ragTagToAcl(t); a != nil {
				out = append(out, a)
			}
		}
	}
	return out
}

// RagPrincipalFromPCActn is the acting identity of a verified PCActn: its LEAF capability holder (map the key to the policy's
// identity with opts.id). opts is {id?, attributes?, env?} or nil. A PCActn with no leaf holder is an error.
func RagPrincipalFromPCActn(pcactn any, opts map[string]any) (map[string]any, error) {
	var holder any
	if p, ok := pcactn.(map[string]any); ok {
		if chain, ok := p["cap_chain"].([]any); ok && len(chain) > 0 {
			if leaf, ok := chain[len(chain)-1].(map[string]any); ok {
				holder = leaf["holder"]
			}
		}
	}
	if !ragNonEmpty(holder) {
		return nil, errors.New("principalFromPCActn: PCActn has no leaf capability holder")
	}
	out := map[string]any{"id": holder}
	if id := opts["id"]; id != nil {
		out["id"] = id
	}
	for _, k := range []string{"attributes", "env"} {
		if v, ok := opts[k]; ok {
			out[k] = v
		}
	}
	return out, nil
}

func ragToPrincipal(p any) map[string]any {
	switch t := p.(type) {
	case string:
		return map[string]any{"id": t}
	case map[string]any:
		return t
	case []any:
		return map[string]any{} // a JavaScript array is an object with no id
	}
	return map[string]any{"id": ""}
}

func ragIncomplete(reason string) map[string]any {
	return map[string]any{"predicates": []any{}, "denies": []any{}, "incomplete": true, "incompleteReason": reason}
}

// ragLengthPositive is JavaScript `x.length > 0` for a JSON value that is not null.
func ragLengthPositive(x any) bool {
	switch t := x.(type) {
	case []any:
		return len(t) > 0
	case string:
		return t != ""
	case map[string]any:
		f, ok := jsNum(t["length"])
		return ok && f > 0
	}
	return false
}

// RagCompilePolicy compiles any policy into {predicates, denies, incomplete, incompleteReason?, report?}; an already-compiled
// policy passes through. A value that is not a policy, or a translation with errors, is INCOMPLETE: nothing is admitted. A
// {predicates, report} whose report has no errors member is an error (the reference reads report.errors.length).
func RagCompilePolicy(policy any) (map[string]any, error) {
	switch t := policy.(type) {
	case []any:
		return map[string]any{"predicates": t, "denies": []any{}, "incomplete": false}, nil
	case map[string]any:
		if _, ok := t["incomplete"].(bool); ok {
			return t, nil
		}
		if _, has := t["openfga"]; has {
			var fga map[string]any
			switch f := t["openfga"].(type) {
			case map[string]any:
				fga = f
			case []any:
				fga = map[string]any{} // an array has no model or tuples
			default:
				return ragIncomplete("the OpenFGA policy has no model (fail closed)"), nil
			}
			var br map[string]any
			if tu, has := fga["tuples"]; has {
				br = OpenfgaToPca(fga["model"], tu)
			} else {
				br = OpenfgaToPca(fga["model"])
			}
			report, _ := br["report"].(map[string]any)
			errs, _ := report["errors"].([]any)
			return map[string]any{"predicates": br["predicates"], "denies": br["denies"], "report": report, "incomplete": len(errs) > 0}, nil
		}
		if _, ok := t["predicates"].([]any); !ok {
			return ragIncomplete("the policy has no predicates and is not an OpenFGA policy (fail closed)"), nil
		}
		denies, ok := t["denies"].([]any)
		if !ok {
			denies = []any{}
		}
		out := map[string]any{"predicates": t["predicates"], "denies": denies, "incomplete": false}
		if report, has := t["report"]; has {
			rm, ok := report.(map[string]any)
			if !ok || rm["errors"] == nil {
				return nil, errors.New("compilePolicy: report.errors is required")
			}
			out["report"] = rm
			out["incomplete"] = ragLengthPositive(rm["errors"])
		}
		return out, nil
	}
	return ragIncomplete("no usable policy was supplied (fail closed)"), nil
}

// ragSubject is `{...attributes, id}`: object spread of a map, an array (index keys) or a string (one key per UTF-16 unit).
func ragSubject(principal map[string]any) map[string]any {
	subject := map[string]any{}
	switch a := principal["attributes"].(type) {
	case map[string]any:
		for k, v := range a {
			subject[k] = v
		}
	case []any:
		for i, v := range a {
			subject[fmt.Sprint(i)] = v
		}
	case string:
		for i, u := range utf16Units(a) {
			subject[fmt.Sprint(i)] = string(rune(u))
		}
	}
	subject["id"] = principal["id"]
	return subject
}

// ragEvaluate runs the core decision; a panic or an error is an evaluator error (fail closed).
func ragEvaluate(pol, ctx map[string]any) (res map[string]any, ok bool) {
	defer func() {
		if recover() != nil {
			res, ok = nil, false
		}
	}()
	r, err := PolicyBridgeDecide(pol, ctx)
	if err != nil || r == nil {
		return nil, false
	}
	return r, true
}

func ragDecideDocument(id string, acls []any, principal, compiled map[string]any) map[string]any {
	if compiled["incomplete"] == true {
		why, ok := compiled["incompleteReason"].(string)
		if !ok {
			why = "policy translation incomplete (fail closed)"
		}
		return map[string]any{"id": id, "allowed": false, "reason": why}
	}
	if !ragNonEmpty(principal["id"]) {
		return map[string]any{"id": id, "allowed": false, "reason": "no principal identity (fail closed)"}
	}
	if len(acls) == 0 {
		return map[string]any{"id": id, "allowed": false, "reason": "no decidable ACL metadata (fail closed)"}
	}
	last := "no relation grants access (fail closed)"
	pol := map[string]any{}
	for _, k := range []string{"predicates", "denies"} {
		if v, has := compiled[k]; has {
			pol[k] = v
		}
	}
	subject := ragSubject(principal)
	for _, a := range acls {
		acl := a.(map[string]any)
		ctx := map[string]any{"action": map[string]any{"verb": acl["relation"], "resource": acl["object"]}, "subject": subject}
		if env, has := principal["env"]; has {
			ctx["env"] = env
		}
		res, ok := ragEvaluate(pol, ctx)
		if !ok {
			last = "evaluator error (fail closed)"
			continue
		}
		if res["allowed"] == true {
			d := map[string]any{"id": id, "allowed": true, "via": acl,
				"reason": fmt.Sprintf("granted: %s has %s on %s", principal["id"], acl["relation"], acl["object"])}
			if m := res["matched"]; m != nil {
				d["matched"] = m
			}
			return d
		}
		if r, ok := res["reason"].(string); ok {
			last = r
		}
	}
	return map[string]any{"id": id, "allowed": false, "reason": last}
}

// RagFilterOptions says how a document is read. GetID returns a candidate's id (empty: positional `doc#i`); GetAcls its ACL
// entries (anything that is not a list of {relation, object} entries yields none). Either returning an error marks the document
// unreadable (dropped). Recorder, when set, records every admitted document as UNTRUSTED retrieval content.
type RagFilterOptions struct {
	GetID    func(doc any, index int) (any, error)
	GetAcls  func(doc any) (any, error)
	Recorder *ProvenanceRecorder
}

func ragDefaultReaders(o *RagFilterOptions) (func(any, int) (any, error), func(any) (any, error)) {
	obj := func(doc any) (map[string]any, error) {
		if doc == nil {
			return nil, errors.New("null document")
		}
		m, _ := doc.(map[string]any)
		return m, nil // a non-object has no members
	}
	id := func(doc any, _ int) (any, error) {
		m, err := obj(doc)
		return m["id"], err
	}
	acls := func(doc any) (any, error) {
		m, err := obj(doc)
		if err != nil {
			return nil, err
		}
		return RagAclsFromMetadata(m["acl"], m["tags"]), nil
	}
	if o != nil && o.GetID != nil {
		id = o.GetID
	}
	if o != nil && o.GetAcls != nil {
		acls = o.GetAcls
	}
	return id, acls
}

// RagFilterDocuments filters candidates to the documents the principal may see under the policy, returning the admitted
// documents (candidate order) and the decision record (the proof trace: principal, considered, allowedIds, allowedIndexes,
// droppedIds, policyIncomplete, decisions, digest, report?). A non-list candidate set is empty. opts may be nil (default
// readers: doc.id, doc.acl + doc.tags).
func RagFilterDocuments(principal any, candidates any, policy any, opts *RagFilterOptions) ([]any, map[string]any, error) {
	pr := ragToPrincipal(principal)
	compiled, err := RagCompilePolicy(policy)
	if err != nil {
		return nil, nil, err
	}
	list, _ := candidates.([]any)
	getID, getAcls := ragDefaultReaders(opts)
	documents, decisions := []any{}, []any{}
	allowedIDs, droppedIDs, allowedIdx := []any{}, []any{}, []any{}
	seen := map[string]bool{}
	for i, doc := range list {
		rawID, err1 := getID(doc, i)
		raw, err2 := getAcls(doc)
		if err1 != nil || err2 != nil {
			fid := fmt.Sprintf("doc#%d", i)
			decisions = append(decisions, map[string]any{"id": fid, "allowed": false, "reason": "unreadable document metadata (fail closed)"})
			droppedIDs = append(droppedIDs, fid)
			continue
		}
		id, _ := rawID.(string)
		if id == "" {
			id = fmt.Sprintf("doc#%d", i)
		}
		if seen[id] {
			id = fmt.Sprintf("%s#dup%d", id, i)
		}
		seen[id] = true
		d := ragDecideDocument(id, ragAclArray(raw), pr, compiled)
		decisions = append(decisions, d)
		if d["allowed"] == true {
			documents = append(documents, doc)
			allowedIDs = append(allowedIDs, id)
			allowedIdx = append(allowedIdx, i)
		} else {
			droppedIDs = append(droppedIDs, id)
		}
	}
	pid, _ := pr["id"].(string)
	base := map[string]any{"principal": pid, "considered": len(list), "allowedIds": allowedIDs, "allowedIndexes": allowedIdx,
		"droppedIds": droppedIDs, "policyIncomplete": compiled["incomplete"] == true}
	hashed := map[string]any{"v": 1, "kind": "pca-rag/filter"}
	decision := map[string]any{"decisions": decisions}
	for k, v := range base {
		hashed[k], decision[k] = v, v
	}
	digest, err := HashCanonical(hashed)
	if err != nil {
		return nil, nil, err
	}
	decision["digest"] = digest
	if r := compiled["report"]; r != nil {
		decision["report"] = r
	}
	if opts != nil && opts.Recorder != nil {
		for i, doc := range documents {
			src := fmt.Sprintf("doc#%d", i)
			if id, err := getID(doc, i); err == nil {
				if s, ok := id.(string); ok && s != "" {
					src = s
				}
			}
			if _, err := opts.Recorder.Retrieval(src, doc); err != nil {
				return nil, nil, err
			}
		}
	}
	return documents, decision, nil
}

// RagRetriever returns candidate documents for a query.
type RagRetriever func(query string, k int) ([]any, error)

// RagFilteredRetriever is a retriever whose results are PCA-filtered before they reach the model.
type RagFilteredRetriever struct {
	retrieve          RagRetriever
	principal, policy any
	opts              *RagFilterOptions
	last              map[string]any
}

// RagWithPcaFilter wraps a retriever so every result set is filtered to what the principal may see. The policy is compiled
// once. A policy that does not compile is an error here rather than at retrieval.
func RagWithPcaFilter(retriever RagRetriever, principal, policy any, opts *RagFilterOptions) (*RagFilteredRetriever, error) {
	compiled, err := RagCompilePolicy(policy)
	if err != nil {
		return nil, err
	}
	return &RagFilteredRetriever{retrieve: retriever, principal: principal, policy: compiled, opts: opts}, nil
}

// Retrieve fetches candidates and returns only the admitted ones.
func (r *RagFilteredRetriever) Retrieve(query string, k int) ([]any, error) {
	docs, err := r.retrieve(query, k)
	if err != nil {
		return nil, err
	}
	out, decision, err := RagFilterDocuments(r.principal, docs, r.policy, r.opts)
	if err != nil {
		return nil, err
	}
	r.last = decision
	return out, nil
}

// LastDecision is the proof trace of the most recent Retrieve (nil before the first).
func (r *RagFilteredRetriever) LastDecision() map[string]any { return r.last }

// FilterCandidates filters an already-retrieved candidate set (for framework retrievers that fetch themselves) and records the
// decision as LastDecision.
func (r *RagFilteredRetriever) FilterCandidates(docs []any) ([]any, error) {
	out, decision, err := RagFilterDocuments(r.principal, docs, r.policy, r.opts)
	if err != nil {
		return nil, err
	}
	r.last = decision
	return out, nil
}
