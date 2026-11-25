package pca

// Replays the sandbox reference corpus: receipt chains, the OS policy and its seccomp / Landlock / macOS profiles, signed runtime
// claims, the capability handle table, the egress admission policy, the private-address rule and the reference tool builders.
// The corpus predates the strict private-address rule (only 2000::/3 public; mapped / compatible / NAT64 judged by the embedded
// IPv4 address; a zone id is private): the inputs that older rule read as public must be REFUSED here and are checked as such
// (sbxStricterPrivate) instead of being compared with the old answer.

import (
	"crypto/sha256"
	"strings"
	"testing"
)

var sbxStricterPrivate = map[string]bool{
	"0:0:0:0:0:0:0:1": true, "0:0:0:0:0:0:0:0": true, "::ffff:7f00:1": true, "::ffff:0:0": true, "::127.0.0.1": true,
	"::1%eth0": true, "::ffff:1.2.3.4%x": true,
}

func sbxTestSeed(label string) []byte {
	d := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
	return d[:]
}

func sbxBytesOut(b []byte) map[string]any { return map[string]any{"$bytes": b64.EncodeToString(b)} }

func sbxTestMkRes(allow any, bind any) map[string]any {
	r := map[string]any{"allow": allow}
	if b, ok := bind.(map[string]any); ok {
		d, _ := HashCanonical(b["params"])
		id := b["id"]
		if id == nil {
			id = "op"
		}
		r["operation"] = map[string]any{"verb": b["verb"], "resource": b["resource"], "params_digest": d, "id": id}
	}
	return r
}

// sbxStringify is JSON.stringify of a decoded value (member order from jsKeys, numbers as their lexemes).
func sbxStringify(v any) string {
	var sb strings.Builder
	var w func(x any)
	w = func(x any) {
		switch t := x.(type) {
		case nil:
			sb.WriteString("null")
		case bool:
			if t {
				sb.WriteString("true")
			} else {
				sb.WriteString("false")
			}
		case string:
			_ = jsString(&sb, t)
		case []any:
			sb.WriteByte('[')
			for i, e := range t {
				if i > 0 {
					sb.WriteByte(',')
				}
				w(e)
			}
			sb.WriteByte(']')
		case map[string]any:
			sb.WriteByte('{')
			for i, k := range jsKeys(t) {
				if i > 0 {
					sb.WriteByte(',')
				}
				_ = jsString(&sb, k)
				sb.WriteByte(':')
				w(t[k])
			}
			sb.WriteByte('}')
		default:
			sb.WriteString(jsValueString(x))
		}
	}
	w(v)
	return sb.String()
}

func sbxTestReceiptLog(spec map[string]any) any {
	t := 0.0
	var sign func(string) string
	if spec["sign"] == true {
		sign = func(d string) string { return "sig:" + d }
	}
	log := NewSandboxReceiptLog(func() float64 { return t }, sign)
	outs := []any{}
	for _, ai := range sliceOf(spec["appends"]) {
		a := vecObj(ai)
		t = connTestFloat(a["t"], 0)
		rc, _ := a["rc"].(string)
		r, err := log.Append(rc, vecObj(a["body"]))
		if err != nil {
			outs = append(outs, map[string]any{"$err": true})
		} else {
			outs = append(outs, r)
		}
	}
	return outs
}

func sbxTestCompile(spec map[string]any) (any, error) {
	items := []SandboxCompileItem{}
	for _, ii := range sliceOf(spec["items"]) {
		it := vecObj(ii)
		items = append(items, SandboxCompileItem{Result: sbxTestMkRes(it["allow"], it["bind"]), Operation: it["operation"]})
	}
	needs := vecObj(spec["needs"])
	return SandboxCompilePolicy(items, func(op any) any {
		verb, _ := sbxGet(op, "verb")
		res, _ := sbxGet(op, "resource")
		return needs[jsValueString(verb)+" "+jsValueString(res)]
	}, spec["proxyPort"])
}

func sbxTestEgress(spec map[string]any) any {
	t := 0.0
	p := NewEgressPolicy(func() float64 { return t })
	outs := []any{}
	for _, si := range sliceOf(spec["steps"]) {
		st := vecObj(si)
		switch st["op"] {
		case "now":
			t = connTestFloat(st["t"], 0)
			outs = append(outs, nil)
		case "admit":
			opts, _ := st["opts"].(map[string]any)
			tmpl := st["template"]
			if err := p.Admit(sbxTestMkRes(st["allow"], st["bind"]), st["operation"], func(any) any { return tmpl }, opts); err != nil {
				outs = append(outs, map[string]any{"$err": true})
			} else {
				outs = append(outs, "ok")
			}
		default:
			req := vecObj(st["req"])
			method, isStr := req["method"].(string)
			if !isStr {
				outs = append(outs, map[string]any{"$err": true})
				continue
			}
			outs = append(outs, p.Claim(method, sbxText(req["url"], hasKey(req, "url")), baseBytes(req["body"])))
		}
	}
	return outs
}

var sbxTestExecutors = map[string]HandleExecutor{
	"fs.read":     func(map[string]any) ([]byte, error) { return []byte{1, 2, 3}, nil },
	"fs.echo":     func(op map[string]any) ([]byte, error) { return []byte(sbxStringify(op)), nil },
	"fs.throw":    func(map[string]any) ([]byte, error) { return nil, errSbxBoom },
	"fs.notbytes": func(map[string]any) ([]byte, error) { return nil, errSbxBoom },
}

var errSbxBoom = &CodedError{Code: "boom", Msg: "boom"}

func sbxTestHandles(spec map[string]any) any {
	t := 0.0
	log := NewSandboxReceiptLog(func() float64 { return t }, nil)
	cls, _ := spec["cls"].(string)
	table := NewHandleTable(cls, log, sbxTestExecutors, func() float64 { return t })
	outs := []any{}
	errOut := map[string]any{"$err": true}
	for _, si := range sliceOf(spec["steps"]) {
		st := vecObj(si)
		opts, _ := st["opts"].(map[string]any)
		switch st["op"] {
		case "now":
			t = connTestFloat(st["t"], 0)
			outs = append(outs, nil)
		case "mint":
			allow := any(true)
			if a, has := st["allow"]; has && a != nil {
				allow = a
			}
			var res map[string]any
			if b, has := st["bind"]; has {
				res = sbxTestMkRes(allow, b)
			} else {
				bind := map[string]any{}
				if op, ok := st["operation"].(map[string]any); ok {
					for k, v := range op {
						bind[k] = v
					}
				}
				bind["id"] = st["id"]
				if st["id"] == nil {
					bind["id"] = "op-h"
				}
				res = sbxTestMkRes(allow, bind)
			}
			if i, err := table.Mint(res, st["operation"], opts); err != nil {
				outs = append(outs, errOut)
			} else {
				outs = append(outs, i)
			}
		case "attenuate":
			nar, _ := st["narrower"].(map[string]any)
			if i, err := table.Attenuate(st["index"], nar); err != nil {
				outs = append(outs, errOut)
			} else {
				outs = append(outs, i)
			}
		case "revoke":
			table.Revoke(st["index"])
			outs = append(outs, nil)
		case "use":
			r, err := table.Use(st["index"])
			switch {
			case err != nil:
				outs = append(outs, errOut)
			case r["ok"] == true:
				outs = append(outs, map[string]any{"ok": true, "result": sbxBytesOut(r["result"].([]byte))})
			default:
				outs = append(outs, r)
			}
		case "verbOf":
			if v, ok := table.VerbOf(st["index"]); ok {
				outs = append(outs, v)
			} else {
				outs = append(outs, nil)
			}
		case "size":
			outs = append(outs, table.Size())
		}
	}
	entries := make([]any, len(log.Entries))
	for i, e := range log.Entries {
		entries[i] = e
	}
	return map[string]any{"outs": outs, "log": entries}
}

func TestSandboxReferenceVectors(t *testing.T) {
	profile := func(f func(map[string]any) (map[string]any, error)) vecFn {
		return func(args []any) (any, error) { return f(vecObj(vecArg(args, 0))) }
	}
	replayVectors(t, "ref-sandbox.json.gz", map[string]vecFn{
		"moduleConsts": func(args []any) (any, error) {
			use := map[string]any{}
			for k, v := range SandboxUseErr {
				use[k] = v
			}
			return map[string]any{"IMPORT_MODULE": SandboxImportModule, "ALLOWED_IMPORTS": connAnyList(SandboxAllowedImports), "USE_ERR": use,
				"GENESIS": SandboxGenesis, "RUNTIME_CLASSES": connAnyList(RuntimeClasses), "DOMAIN": RuntimeClaimDomain}, nil
		},
		"satisfiesRuntimeClass": func(args []any) (any, error) { return SatisfiesRuntimeClass(vecArg(args, 0), vecArg(args, 1)), nil },
		"receiptLog":            func(args []any) (any, error) { return sbxTestReceiptLog(vecObj(vecArg(args, 0))), nil },
		"verifyReceiptChain": func(args []any) (any, error) {
			var verify func(string, any) bool
			if m, _ := vecArg(args, 1).(string); m == "tag" {
				verify = func(d string, s any) bool { x, ok := s.(string); return ok && x == "sig:"+d }
			}
			return VerifyReceiptChain(vecArg(args, 0), verify)
		},
		"policyFromNeeds": func(args []any) (any, error) { return PolicyFromNeeds(vecArg(args, 0), vecArg(args, 1)) },
		"compilePolicy":   func(args []any) (any, error) { return sbxTestCompile(vecObj(vecArg(args, 0))) },
		"seccompProfile":  profile(SeccompProfile),
		"landlockRuleset": profile(LandlockRuleset),
		"macosProfile":    func(args []any) (any, error) { return MacosProfile(vecObj(vecArg(args, 0))) },
		"confineArgs": func(args []any) (any, error) {
			l, err := ConfineArgs(vecObj(vecArg(args, 0)))
			if err != nil {
				return nil, err
			}
			return connAnyList(l), nil
		},
		"isPrivateAddress": func(args []any) (any, error) {
			if s, ok := vecArg(args, 0).(string); ok && sbxStricterPrivate[s] {
				if !IsPrivateAddress(s) {
					t.Errorf("isPrivateAddress(%q) must be refused (private)", s)
				}
				return nil, vecSkip("older reference read this input as public; the strict rule refuses it")
			}
			return IsPrivateAddress(vecArg(args, 0)), nil
		},
		"egress":  func(args []any) (any, error) { return sbxTestEgress(vecObj(vecArg(args, 0))), nil },
		"handles": func(args []any) (any, error) { return sbxTestHandles(vecObj(vecArg(args, 0))), nil },
		"signRuntimeClaim": func(args []any) (any, error) {
			var seed []byte
			switch k := vecArg(args, 0).(type) {
			case string:
				seed = sbxTestSeed(k)
			case map[string]any:
				seed = make([]byte, int(connTestFloat(k["short"], 0)))
			}
			pub := "x"
			if p, ok := vecArg(args, 1).(string); ok {
				pub = p
			}
			kp, err := KeyPairFromSeed(sbxTestSeed(pub))
			if err != nil {
				return nil, err
			}
			return SignRuntimeClaim(seed, kp.Public, vecObj(vecArg(args, 2)))
		},
		"verifiedRuntimeClass": func(args []any) (any, error) {
			return SandboxVerifiedRuntimeClass(vecArg(args, 0), vecArg(args, 1)), nil
		},
		"passportDigest": func(args []any) (any, error) { return PassportDigest(vecArg(args, 0)) },
		"evidenceDigest": func(args []any) (any, error) { return HashCanonical(vecArg(args, 0)) },
		"buildTool":      func(args []any) (any, error) { return sbxBytesOut(BuildTool(vecObj(vecArg(args, 0)))), nil },
		"buildProbeTool": func(args []any) (any, error) {
			return sbxBytesOut(BuildProbeTool(int64(connTestFloat(vecArg(args, 0), 64)))), nil
		},
		"referenceComponentWat": func(args []any) (any, error) { return ReferenceComponentWat(vecObj(vecArg(args, 0))), nil },
	})
}
