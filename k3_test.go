package pca

import (
	"testing"
)

// Replays packages/pca/conformance/k3-vectors.json: each entry is {name, input, expect}; the result of the Go verifier is
// rendered in the vector's `expect` shape and compared as strict canonical JSON (key order and number spelling are irrelevant).

func k3Table(t *testing.T, kind string) []any {
	t.Helper()
	tbl, ok := load(t, "k3-vectors.json")["primitives"].(map[string]any)[kind].([]any)
	if !ok || len(tbl) == 0 {
		t.Fatalf("no %s vectors", kind)
	}
	return tbl
}

func k3Replay(t *testing.T, kind string, run func(in map[string]any) map[string]any) {
	t.Helper()
	for _, x := range k3Table(t, kind) {
		v := x.(map[string]any)
		t.Run(v["name"].(string), func(t *testing.T) {
			got, err := Canonicalize(run(v["input"].(map[string]any)))
			if err != nil {
				t.Fatal(err)
			}
			want, err := Canonicalize(v["expect"])
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("got  %s\nwant %s", got, want)
			}
		})
	}
}

func k3S(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func k3Num64(v any) int64 { f, _ := jsNum(v); return int64(f) }

func k3Digest(s string, ok bool) map[string]any {
	if !ok {
		return map[string]any{"digest": nil}
	}
	return map[string]any{"digest": s}
}

func TestK3FreshAtVectors(t *testing.T) {
	k3Replay(t, "fresh_at_verify", func(in map[string]any) map[string]any {
		return map[string]any{"valid": VerifyFreshAt(in["token"], k3S(in, "signer"))}
	})
	k3Replay(t, "fresh_at_digest", func(in map[string]any) map[string]any {
		return k3Digest(FreshAtDigest(in["token"]))
	})
	k3Replay(t, "fresh_at_check", func(in map[string]any) map[string]any {
		o := in["options"].(map[string]any)
		opts := FreshAtOptions{Signer: k3S(o, "signer"), Scope: k3S(o, "scope"), Now: k3Num64(o["now"])}
		if v, has := o["maxTokenAgeMs"]; has {
			n := k3Num64(v)
			opts.MaxTokenAgeMs = &n
		}
		v := CheckFreshAt(in["token"], FreshAtStateFromJSON(in["local"]), opts)
		out := map[string]any{"decision": v.Decision}
		if v.Code != "" {
			out["code"] = v.Code
		}
		if v.Behind != nil {
			b := []any{}
			for _, k := range v.Behind {
				b = append(b, k)
			}
			out["behind"] = b
		}
		return out
	})
}

func TestK3BundleVectors(t *testing.T) {
	k3Replay(t, "bundle_digest", func(in map[string]any) map[string]any {
		return k3Digest(BundleDigest(in["bundle"]))
	})
	k3Replay(t, "bundle_verify", func(in map[string]any) map[string]any {
		o := in["options"].(map[string]any)
		opts := BundleVerifyOptions{Threshold: k3Num64(o["threshold"]), VerifierVersion: k3S(o, "verifierVersion")}
		for _, s := range o["signers"].([]any) {
			opts.Signers = append(opts.Signers, s.(string))
		}
		if l, ok := o["last"].(map[string]any); ok {
			opts.Last = &BundleLast{Revision: k3Num64(l["revision"]), Digest: k3S(l, "digest")}
		}
		v := VerifyBundle(in["bundle"], opts)
		if !v.OK {
			return map[string]any{"ok": false, "code": v.Code, "reason": v.Reason}
		}
		s := []any{}
		for _, x := range v.Signers {
			s = append(s, x)
		}
		return map[string]any{"ok": true, "revision": jsNumber(float64(v.Revision)), "digest": v.Digest, "signers": s}
	})
}

func TestK3LogVectors(t *testing.T) {
	k3Replay(t, "log_commit", func(in map[string]any) map[string]any {
		c, ok := RecordCommit(in["record"])
		if !ok {
			return map[string]any{"commit": nil}
		}
		return map[string]any{"commit": c}
	})
	k3Replay(t, "log_head_verify", func(in map[string]any) map[string]any {
		return map[string]any{"valid": VerifyLogHead(in["head"], k3S(in, "signer"))}
	})
	k3Replay(t, "log_inclusion", func(in map[string]any) map[string]any {
		return map[string]any{"valid": VerifyRecordInclusion(in["record"], in["proof"], in["head"], k3S(in, "signer"))}
	})
	k3Replay(t, "log_batch_verify", func(in map[string]any) map[string]any {
		st := in["state"].(map[string]any)
		v := VerifyDecisionBatch(in["batch"], k3Num64(st["next"]), k3S(st, "lastCommit"), k3S(in, "signer"))
		if !v.OK {
			return map[string]any{"ok": false, "reason": v.Reason}
		}
		return map[string]any{"ok": true, "next": jsNumber(float64(v.Next)), "lastCommit": v.LastCommit}
	})
}

func k3Objects(v any) []string {
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	out := []string{}
	for _, x := range l {
		out = append(out, x.(string))
	}
	return out
}

func k3Bind(v any) *ListBindInputs {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	b := &ListBindInputs{Subject: k3S(m, "subject"), ResourceType: k3S(m, "resourceType"), FilterID: k3S(m, "filterId"), PolicyDigest: k3S(m, "policyDigest"), Limit: int(k3Num64(m["limit"]))}
	if r, ok := m["relation"].(map[string]any); ok {
		if s, ok := r["relation"].(string); ok {
			b.Relation = &s
		}
	}
	return b
}

func TestK3ListVectors(t *testing.T) {
	k3Replay(t, "list_objects_digest", func(in map[string]any) map[string]any {
		return k3Digest(ObjectsDigest(k3Objects(in["objects"])))
	})
	k3Replay(t, "list_receipt_verify", func(in map[string]any) map[string]any {
		return map[string]any{"valid": VerifyListReceipt(in["receipt"], k3S(in, "signer"), k3Objects(in["objects"]))}
	})
	k3Replay(t, "list_bind", func(in map[string]any) map[string]any {
		return k3Digest(ListBind(*k3Bind(in["bind"])))
	})
	k3Replay(t, "list_cursor_verify", func(in map[string]any) map[string]any {
		v := VerifyListCursor(in["cursor"], k3S(in, "signer"), k3Bind(in["bind"]))
		if !v.OK {
			return map[string]any{"ok": false, "reason": v.Reason}
		}
		out := map[string]any{"ok": true, "skip": jsNumber(float64(v.Skip))}
		if v.HasInner {
			out["inner"] = v.Inner
		}
		return out
	})
}

func TestK3GrantVectors(t *testing.T) {
	k3Replay(t, "authority_digest", func(in map[string]any) map[string]any {
		return k3Digest(AuthorityDigest(in["authority"]))
	})
	k3Replay(t, "authority_compare", func(in map[string]any) map[string]any {
		o, _ := CompareAuthority(in["old"], in["new"])
		return map[string]any{"order": o}
	})
	k3Replay(t, "amend_verify", func(in map[string]any) map[string]any {
		v := VerifyAmendment(in["grant"], in["request"], in["step_up_ok"] == true)
		if !v.OK {
			return map[string]any{"ok": false, "code": v.Code}
		}
		return map[string]any{"ok": true, "widens": v.Widens, "next_digest": v.NextDigest}
	})
	k3Replay(t, "revoke_verify", func(in map[string]any) map[string]any {
		v := VerifyRevokeSignature(in["root"], in["scope"], in["sig"])
		if !v.OK {
			return map[string]any{"ok": false, "code": v.Code}
		}
		return map[string]any{"ok": true, "scope": v.Scope}
	})
	k3Replay(t, "need_approve_verify", func(in map[string]any) map[string]any {
		v := VerifyNeedApproval(in["need_request"], in["grant"], in["approved"], in["sig"], in["step_up_ok"] == true)
		if !v.OK {
			return map[string]any{"ok": false, "code": v.Code}
		}
		return map[string]any{"ok": true, "authority_digest": v.AuthorityDigest}
	})
}
