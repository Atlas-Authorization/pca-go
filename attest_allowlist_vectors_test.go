package pca

import (
	"errors"
	"math"
	"strings"
	"testing"
)

// Replay of the signed measurement-allowlist manifests and their transparency anchor against the reference (ref-attest-allowlist),
// every case: verify / durable verify, create / sign / revoke, the driver-version slot, the projection and its policy fields, the
// anchor commitment, the operator log and the anchored verification. A refusal is compared by its code AND its reason text; an
// acceptance by the whole result. The options of a case are JSON, so a time, version or tolerance that is not a number the typed
// options can carry is refused here with the reason the reference gives for that option.

func alvInt(v any) (int64, bool) {
	f, ok := v.(float64)
	if !ok {
		if f, ok = jsNum(v); !ok {
			return 0, false
		}
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) || math.Abs(f) > maxSafeInt {
		return 0, false
	}
	return int64(f), true
}

// alvOpts reads the options of a case; bad is the refusal reason of an option the typed options cannot carry ("" when all fit).
func alvOpts(v any) (o VerifyAllowlistOptions, bad string) {
	m, ok := v.(map[string]any)
	o = VerifyAllowlistOptions{IssuerKeys: map[string]AllowlistIssuerKey{}}
	if !ok {
		return o, "nowMs must be an integer"
	}
	if o.NowMs, ok = alvInt(m["nowMs"]); !ok {
		return o, "nowMs must be an integer"
	}
	keys, isMap := m["issuerKeys"].(map[string]any)
	if _, has := m["issuerKeys"]; has && !isMap {
		return o, "issuerKeys must be an object"
	}
	for id, kv := range keys {
		km, isObj := kv.(map[string]any)
		if !isObj {
			return o, "issuerKeys must hold objects"
		}
		alg, _ := km["alg"].(string)
		pubs := vecObj(km["keys"])
		k := AllowlistIssuerKey{Alg: alg, EdPub: vecStr(pubs, "edPub")}
		switch {
		case strings.Contains(alg, "ml-dsa-87"):
			k.PqPub = vecStr(pubs, "mlDsa87Pub")
		case strings.Contains(alg, "slh-dsa-sha2-256s"):
			k.PqPub = vecStr(pubs, "slhDsa256sPub")
		case strings.Contains(alg, "slh-dsa"):
			k.PqPub = vecStr(pubs, "slhDsaPub")
		case strings.Contains(alg, "ml-dsa"):
			k.PqPub = vecStr(pubs, "mlDsaPub")
		}
		if na, has := km["notAfter"]; has {
			n, isInt := alvInt(na)
			if !isInt {
				return o, "notAfter must be an integer"
			}
			k.NotAfter = &n
		}
		o.IssuerKeys[id] = k
	}
	// the reference checks clockSkewMs, maxLifetimeMs, minVersion, lastSeenVersion in this order
	for _, name := range []string{"clockSkewMs", "maxLifetimeMs"} {
		if x, has := m[name]; has {
			f, isF := x.(float64)
			if !isF {
				if f, isF = jsNum(x); !isF {
					return o, name + " must be a finite number"
				}
			}
			if name == "clockSkewMs" {
				o.ClockSkewMs = &f
			} else {
				o.MaxLifetimeMs = &f
			}
		}
	}
	for _, name := range []string{"minVersion", "lastSeenVersion"} {
		if x, has := m[name]; has {
			n, isInt := alvInt(x)
			if !isInt {
				return o, name + " must be an integer"
			}
			if name == "minVersion" {
				o.MinVersion = &n
			} else {
				o.LastSeenVersion = &n
			}
		}
	}
	if x, has := m["lastSeenDigest"]; has {
		s, isStr := x.(string)
		if !isStr {
			return o, "lastSeenDigest must be a string"
		}
		o.LastSeenDigest = &s
	}
	return o, ""
}

func alvResult(r AllowlistResult) map[string]any {
	if !r.OK {
		return map[string]any{"ok": false, "code": r.Code, "reason": r.Reason}
	}
	return map[string]any{"ok": true, "body": r.Body, "issuer": r.Issuer, "alg": r.Alg, "version": r.Version, "digest": r.Digest}
}

func alvMalformed(reason string) map[string]any {
	return map[string]any{"ok": false, "code": "malformed", "reason": reason}
}

// alvVerified reads the {ok: true, body, issuer, alg, version, digest} result of a verification back into its typed form.
func alvVerified(v any) AllowlistResult {
	m := vecObj(v)
	version, _ := alvInt(m["version"])
	return AllowlistResult{OK: m["ok"] == true, Body: vecObj(m["body"]), Issuer: vecStr(m, "issuer"), Alg: vecStr(m, "alg"), Version: version, Digest: vecStr(m, "digest")}
}

func alvDenied(v any) []AllowlistDeniedValue {
	l, _ := v.([]any)
	var out []AllowlistDeniedValue
	for _, x := range l {
		m := vecObj(x)
		out = append(out, AllowlistDeniedValue{Kind: vecStr(m, "kind"), Value: vecStr(m, "value"), Label: vecStr(m, "label")})
	}
	return out
}

// alvProjection reads the JSON form of a projection.
func alvProjection(v any) *AllowlistProjection {
	m := vecObj(v)
	p := &AllowlistProjection{TdxMrtds: vecStrs(m, "tdxMrtds"), TdxRtmrs: vecStrs(m, "tdxRtmrs"), SevSnpMeasurements: vecStrs(m, "sevSnpMeasurements"),
		ImageDigests: vecStrs(m, "imageDigests"), NvidiaMeasurements: vecStrs(m, "nvidiaMeasurements"), NvidiaDriverVersions: vecStrs(m, "nvidiaDriverVersions"),
		NvidiaCcDriverVersions: vecStrs(m, "nvidiaCcDriverVersions"), MaaSigningSpkis: map[string][]string{}, MaaChainRootSpkis: vecStrs(m, "maaChainRootSpkis"),
		MaaChainIntermediateSpkis: vecStrs(m, "maaChainIntermediateSpkis"), Corroboration: alvDenied(m["corroboration"]), Revoked: alvDenied(m["revoked"]),
		Expired: alvDenied(m["expired"])}
	spkis := vecObj(m["maaSigningSpkis"])
	for k := range spkis {
		p.MaaSigningSpkis[k] = vecStrs(spkis, k)
	}
	p.Version, _ = alvInt(m["version"])
	p.ManifestExpiresAt, _ = alvInt(m["manifestExpiresAt"])
	return p
}

// alvFields is the object form of a policy-field helper: a list the helper leaves out (nil) is an absent member.
func alvFields(always map[string][]string, optional map[string][]string) map[string]any {
	out := map[string]any{}
	for k, v := range always {
		out[k] = append([]string{}, v...)
	}
	for k, v := range optional {
		if len(v) > 0 {
			out[k] = v
		}
	}
	return out
}

// alvSigner builds the key material of a sign case: keySpec = {alg, edSecret?, seed?} (an Ed25519 seed, an ML-DSA key generation seed).
func alvSigner(spec map[string]any) (ed *KeyPair, pq *PqKeyPair, err error) {
	if s, has := spec["edSecret"].(string); has {
		if ed, err = KeyPairFromSeedB64u(s); err != nil {
			return nil, nil, err
		}
	}
	if s, has := spec["seed"].(string); has {
		seed, ok := DecodeB64uStrict(s, 32)
		if !ok {
			return nil, nil, errors.New("the key generation seed is 32 canonical base64url bytes")
		}
		family := "ML-DSA-65"
		if strings.Contains(vecStr(spec, "alg"), "ml-dsa-87") {
			family = "ML-DSA-87"
		}
		if pq, err = GeneratePqKeyPairFromSeed(family, seed); err != nil {
			return nil, nil, err
		}
	}
	return ed, pq, nil
}

func alvAnchorEntries(l []AnchorEntry) []any {
	out := make([]any, len(l))
	for i, e := range l {
		out[i] = map[string]any{"issuer": e.Issuer, "version": e.Version, "digest": e.Digest}
	}
	return out
}

// alvSame compares one result: a refusal by code and reason, an acceptance in full.
func alvSame(want, got any) bool {
	w, g := vecObj(want), vecObj(got)
	if w == nil || g == nil || w["ok"] != g["ok"] {
		return false
	}
	if w["ok"] != true {
		return w["code"] == g["code"] && w["reason"] == g["reason"]
	}
	return baseCanon(w) == baseCanon(g)
}

func TestAllowlistManifestMatchesTheReference(t *testing.T) {
	counts := map[string]int{}
	fns := map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{"ALLOWLIST_KINDS": AllowlistKinds, "DOMAIN": allowlistDomain}, nil
		},
		"verifyAllowlistManifest": func(a []any) (any, error) {
			o, bad := alvOpts(vecArg(a, 1))
			if m, isObj := a[0].(map[string]any); bad != "" {
				if !isObj || !alOnlyKeys(m, alManKey) { // the manifest shape is read before any option
					bad = "manifest has an unexpected shape"
				}
				return alvMalformed(bad), nil
			}
			return vecJSON(alvResult(VerifyAllowlistManifest(a[0], o))), nil
		},
		"verifyAllowlistDurable": func(a []any) (any, error) {
			in := vecObj(a[0])
			kv := CreateMemoryDurableKv()
			for k, v := range vecObj(in["initial"]) {
				if err := kv.Set(k, v); err != nil {
					return nil, err
				}
			}
			o, bad := alvOpts(in["opts"])
			results := []any{}
			steps, _ := in["steps"].([]any)
			for _, step := range steps {
				if bad != "" {
					results = append(results, alvMalformed(bad))
					continue
				}
				results = append(results, alvResult(VerifyAllowlistDurable(step, o, kv)))
			}
			return vecJSON(map[string]any{"results": results, "kv": kv.Snapshot()}), nil
		},
		"createAllowlistManifest": func(a []any) (any, error) {
			m, isObj := a[0].(map[string]any)
			if !isObj {
				return nil, errors.New("body must be an object with exactly version/issuedAt/notBefore/expiresAt/entries")
			}
			return CreateAllowlistManifest(m)
		},
		"signAllowlistManifest": func(a []any) (any, error) {
			o := vecObj(a[1])
			ed, pq, err := alvSigner(vecObj(o["keySpec"]))
			if err != nil {
				return nil, err
			}
			return SignAllowlistManifest(vecObj(a[0]), vecStr(o, "issuer"), vecStr(o, "alg"), ed, pq)
		},
		"revokeAllowlistEntry": func(a []any) (any, error) {
			rev, tm := vecObj(a[1]), vecObj(a[2])
			issued, ok1 := alvInt(tm["issuedAt"])
			nb, ok2 := alvInt(tm["notBefore"])
			exp, ok3 := alvInt(tm["expiresAt"])
			if !ok1 || !ok2 || !ok3 {
				return nil, errors.New("issuedAt/notBefore/expiresAt must be integer epoch ms")
			}
			return RevokeAllowlistEntry(vecObj(a[0]), vecStr(rev, "kind"), vecStr(rev, "value"), vecStr(rev, "label"), issued, nb, exp)
		},
		"driverVersionSlotHex": func(a []any) (any, error) {
			s, _ := a[0].(string)
			return DriverVersionSlotHex(s)
		},
		"projectAllowlist": func(a []any) (any, error) {
			now, _ := alvInt(vecObj(a[1])["nowMs"])
			p, err := ProjectAllowlist(alvVerified(a[0]), now)
			if err != nil {
				return nil, err
			}
			return p.JSON(), nil
		},
		"policyFields": func(a []any) (any, error) {
			p := alvProjection(a[1])
			switch name, _ := a[0].(string); name {
			case "azureMaaPolicyFields":
				mrtds, snp, rtmrs := AzureMaaPolicyFields(p)
				return alvFields(nil, map[string][]string{"tdxMrtds": mrtds, "sevSnpMeasurements": snp, "tdxRtmrs": rtmrs}), nil
			case "intelDcapPolicyFields":
				mrtds, rtmrs := IntelDcapPolicyFields(p)
				return alvFields(map[string][]string{"mrtds": mrtds}, map[string][]string{"rtmrs": rtmrs}), nil
			case "sevSnpPolicyFields":
				return alvFields(map[string][]string{"measurements": SevSnpPolicyFields(p)}, nil), nil
			case "gcpCsPolicyFields":
				return alvFields(map[string][]string{"imageDigests": GcpCsPolicyFields(p)}, nil), nil
			case "nvidiaCcPolicyFields":
				ms, drivers := NvidiaCcPolicyFields(p)
				return alvFields(map[string][]string{"measurements": ms}, map[string][]string{"driverVersions": drivers}), nil
			default:
				return nil, errors.New("unknown policy-field helper " + name)
			}
		},
		"anchorCommit": func(a []any) (any, error) {
			e, ok := AnchorEntryOf(a[0])
			if !ok {
				return nil, errors.New("malformed entry")
			}
			return AllowlistAnchorCommit(e)
		},
		"anchorEntryOf": func(a []any) (any, error) {
			e, ok := AnchorEntryOf(a[0])
			if !ok {
				return nil, errors.New("not a verified manifest")
			}
			return alvAnchorEntries([]AnchorEntry{e})[0], nil
		},
		"anchorOps": func(a []any) (any, error) {
			in := vecObj(a[0])
			guardian, err := KeyPairFromSeedB64u(vecStr(in, "secret"))
			if err != nil {
				return nil, err
			}
			log := CreateAllowlistAnchorLog(vecStr(in, "instanceId"), vecStr(in, "principal"))
			outs := []any{}
			ops, _ := in["ops"].([]any)
			for _, opv := range ops {
				op := vecObj(opv)
				has := func(k string) bool { _, ok := op[k]; return ok }
				var r any
				var err error
				switch {
				case has("anchor"):
					now, _ := alvInt(op["nowMs"])
					r, err = AnchorAllowlistHead(log, op["anchor"], AnchorSignOptions{Guardian: guardian, NowMs: now})
				case has("refresh"):
					now, _ := alvInt(op["refresh"])
					r, err = RefreshAnchorHead(log, AnchorSignOptions{Guardian: guardian, NowMs: now})
				case has("evidenceFor"):
					index, _ := alvInt(op["evidenceFor"])
					var cached *int
					if c, given := op["cached"].(map[string]any); given {
						n, _ := alvInt(c["size"])
						size := int(n)
						cached = &size
					}
					r, err = EvidenceFor(log, int(index), cached)
				case has("latest"):
					if h := log.Latest(); h != nil {
						r = h
					}
				default:
					r = alvAnchorEntries(log.Entries())
				}
				if err != nil {
					r = map[string]any{"$throws": err.Error()}
				}
				outs = append(outs, r)
			}
			return outs, nil
		},
		"verifyAnchored": func(a []any) (any, error) {
			in := vecObj(a[0])
			opts, trust := vecObj(in["opts"]), vecObj(vecObj(in["opts"])["trust"])
			mine, _ := AnchorEntryOf(in["verified"])
			o := AnchorOptions{Trust: AnchorTrust{LogKey: vecStr(trust, "logKey"), InstanceID: vecStr(trust, "instanceId"), Principal: vecStr(trust, "principal")},
				CachedHead: vecObj(opts["cachedHead"])}
			o.NowMs, _ = alvInt(opts["nowMs"])
			for name, dst := range map[string]**int64{"maxHeadAgeMs": &o.MaxHeadAgeMs, "clockSkewMs": &o.ClockSkewMs} {
				if n, given := alvInt(opts[name]); given {
					*dst = &n
				}
			}
			evidence := vecObj(in["evidence"])
			r := VerifyAllowlistAnchored(mine, evidence, o)
			if !r.Ok {
				return map[string]any{"ok": false, "code": r.Code, "reason": r.Reason}, nil
			}
			return map[string]any{"ok": true, "issuer": mine.Issuer, "version": mine.Version, "digest": mine.Digest,
				"highestAnchoredVersion": r.HighestAnchoredVersion, "head": evidence["head"]}, nil
		},
	}
	for name, f := range fns {
		fns[name] = func(a []any) (any, error) {
			counts[name]++
			return f(vecResolveSeeds(pdvIn(a)).([]any))
		}
	}
	durable := func(want, got any) bool {
		w, g := vecObj(want), vecObj(got)
		wr, _ := w["results"].([]any)
		gr, _ := g["results"].([]any)
		if len(wr) != len(gr) || baseCanon(w["kv"]) != baseCanon(g["kv"]) {
			return false
		}
		for i := range wr {
			if !alvSame(wr[i], gr[i]) {
				return false
			}
		}
		return true
	}
	// an operation the log refuses is recorded with its text; the text of a refusal the JavaScript runtime words itself ("Cannot ...")
	// is not part of the contract
	anchorOps := func(want, got any) bool {
		w, _ := want.([]any)
		g, _ := got.([]any)
		if len(w) != len(g) {
			return false
		}
		for i := range w {
			if text, refused := vecObj(w[i])["$throws"].(string); refused && strings.HasPrefix(text, "Cannot ") {
				if _, also := vecObj(g[i])["$throws"]; !also {
					return false
				}
				continue
			}
			if baseCanon(w[i]) != baseCanon(g[i]) {
				return false
			}
		}
		return true
	}
	// the signing seam words its own refusals (the key material is typed here), so signAllowlistManifest refusals compare as refusals
	replayAll(t, "ref-attest-allowlist.json.gz", 959, fns, map[string]func(want, got any) bool{
		"verifyAllowlistManifest": alvSame, "verifyAllowlistDurable": durable, "anchorOps": anchorOps, "verifyAnchored": alvSame,
	}, map[string]bool{"createAllowlistManifest": true, "revokeAllowlistEntry": true, "driverVersionSlotHex": true})
	for name, want := range map[string]int{"constants": 1, "verifyAllowlistManifest": 744, "verifyAllowlistDurable": 23, "createAllowlistManifest": 6,
		"signAllowlistManifest": 10, "revokeAllowlistEntry": 11, "driverVersionSlotHex": 13, "projectAllowlist": 9, "policyFields": 45, "anchorCommit": 4,
		"anchorEntryOf": 1, "anchorOps": 20, "verifyAnchored": 72} {
		if counts[name] != want {
			t.Errorf("%s: replayed %d cases, the corpus has %d", name, counts[name], want)
		}
	}
}
