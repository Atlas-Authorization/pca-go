package pca

// The one signer of the goal-to-decision flow (the TypeScript reference is @atlasauth/pca-goal `sign`): artifacts (approvals, test
// sets, policy pins, precedents) signed with the suite-agile signer under a per-kind domain over STRICT canonical bytes.
// Nothing here rolls a primitive.

// goalDomainOf is the domain separation of an artifact kind: an artifact of one kind never verifies as another kind. (The
// constant goalDomain is the unrelated commitment domain of the capability chain.)
func goalDomainOf(kind string) string { return "atlas-pca/goal/" + kind + "/v1\x00" }

// goalKp turns a signer secret (a 32-byte seed, its base64url form or a *KeyPair) into the key pair.
func goalKp(secret any) *KeyPair {
	switch t := secret.(type) {
	case *KeyPair:
		return t
	case string: // a canonical base64url seed
		kp, err := KeyPairFromSeedB64u(t)
		if err != nil {
			panic(err)
		}
		return kp
	case []byte:
		kp, err := KeyPairFromSeed(t)
		if err != nil {
			panic(err)
		}
		return kp
	}
	anlFail("signer secret must be a 32-byte seed or a KeyPair")
	return nil
}

// goalSignerId is the pinned public identity (b64u Ed25519) of a signer secret.
func goalSignerId(secret any) string { return goalKp(secret).Public }

// goalSuiteOf reads the optional suite arguments: nothing, one *SuiteOpts (nil = Ed25519), or the reference's (alg, pq) pair
// (alg a string or nil, pq a *PqKeyPair or nil).
func goalSuiteOf(rest []any) *SuiteOpts {
	switch len(rest) {
	case 0:
		return nil
	case 1:
		if s, ok := rest[0].(*SuiteOpts); ok {
			return s
		}
		if rest[0] == nil || anlIsUndef(rest[0]) {
			return nil
		}
	case 2:
		alg, _ := rest[0].(string)
		pq, _ := rest[1].(*PqKeyPair)
		if alg == "" && pq == nil {
			if rest[0] != nil && !anlIsUndef(rest[0]) || rest[1] != nil && !anlIsUndef(rest[1]) {
				anlFail("suite arguments must be an alg string and a PqKeyPair")
			}
			return nil
		}
		return &SuiteOpts{Alg: alg, Pq: pq}
	}
	anlFail("suite arguments must be a *SuiteOpts or an (alg, pq) pair")
	return nil
}

// goalSignGoalArtifact signs a flat artifact body (it must already carry its signer identity member); panics on a non-canonical
// body. The optional rest selects a non-default suite (see goalSuiteOf).
func goalSignGoalArtifact(kind string, body any, secret any, rest ...any) map[string]any {
	m, ok := body.(map[string]any)
	if !ok {
		anlFail("artifact body must be an object")
	}
	out, err := SignArtifact(goalDomainOf(kind), m, goalKp(secret), goalSuiteOf(rest))
	if err != nil {
		panic(err)
	}
	return out
}

// goalVerifyGoalArtifact verifies against the caller's PINNED signers: the pin whose `pk` equals the artifact's own signer member
// must verify. Total.
func goalVerifyGoalArtifact(kind string, artifact any, signerField string, pins []any) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	a, isMap := artifact.(map[string]any)
	if !isMap || artifactSuiteError(a) != "" {
		return false
	}
	who, isStr := a[signerField].(string)
	if !isStr {
		return false
	}
	var pinPq any
	found := false
	for _, p := range pins {
		var pk, pq any
		switch t := p.(type) {
		case nil: // a null pin makes the reference throw: refuse
			return false
		case string:
			pk = t
		case map[string]any:
			pk, pq = t["pk"], t["pq_pk"]
		}
		if s, isS := pk.(string); isS && s == who {
			pinPq, found = pq, true
			break
		}
	}
	if !found {
		return false
	}
	return verifyArtifactSig(goalDomainOf(kind), a, who, pinPq)
}

// goalSignPayload wraps a payload with its kind and signer: the envelope used by tests, pins and precedents.
func goalSignPayload(kind string, payload any, secret any, rest ...any) map[string]any {
	return goalSignGoalArtifact(kind, map[string]any{"v": goalNum(1), "kind": kind, "signer": goalSignerId(secret), "payload": payload}, secret, rest...)
}

func goalVerifyPayload(s any, kind string, pins []any) bool {
	m, ok := s.(map[string]any)
	if !ok {
		return false
	}
	v, isNum := jsNum(m["v"])
	return isNum && v == 1 && m["kind"] == kind && goalVerifyGoalArtifact(kind, m, "signer", pins)
}

// GoalDomain is the signing domain of an artifact kind.
func GoalDomain(kind string) string { return goalDomainOf(kind) }

// GoalSignerID is the b64u Ed25519 identity of a 32-byte signer seed.
func GoalSignerID(seed []byte) (string, error) {
	kp, err := KeyPairFromSeed(seed)
	if err != nil {
		return "", err
	}
	return kp.Public, nil
}

// GoalSignGoalArtifact signs an artifact body under the kind's domain (s nil = Ed25519).
func GoalSignGoalArtifact(kind string, body map[string]any, kp *KeyPair, s *SuiteOpts) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalSignGoalArtifact(kind, body, kp, s); return nil })
	return
}

// GoalVerifyGoalArtifact verifies an artifact against pinned signers (string keys or {pk, pq_pk?} objects). Total.
func GoalVerifyGoalArtifact(kind string, artifact any, signerField string, pins []any) bool {
	return goalVerifyGoalArtifact(kind, artifact, signerField, pins)
}

// GoalSignPayload signs a payload in the kind-and-signer envelope (s nil = Ed25519).
func GoalSignPayload(kind string, payload any, kp *KeyPair, s *SuiteOpts) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalSignPayload(kind, payload, kp, s); return nil })
	return
}

// GoalVerifyPayload verifies a signed payload envelope against pinned signers. Total.
func GoalVerifyPayload(s any, kind string, pins []any) bool { return goalVerifyPayload(s, kind, pins) }
