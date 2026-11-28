package pca

// Built-in, release-signed pins for the Azure MAA token-signing keys: the offline root of the first accepted key set. The signed
// manifest shipped with the package carries the self-signed per-instance MAA key pins, the SPKI pins of the Microsoft chain root
// and of the MAA intermediate, and a signed multi-vantage corroboration record. It is verified at load against the embedded release
// issuer key with the allowlist rules (expiry, version floor, bounded lifetime); pins expire (fail closed). The root is the release
// signing key plus the recorded corroboration, not a Microsoft-issued root, and no CRL or revocation is consulted.

import (
	"fmt"
	"regexp"
	"strconv"
	"sync"
)

// BuiltinChainLeafCn is the leaf CN Microsoft's MAA signing certificates carry.
var BuiltinChainLeafCn = []string{"Microsoft Azure Attestation 2020"}

// BuiltinMaaPinsIssuerKeys is where trust is rooted: the embedded release issuer key.
func BuiltinMaaPinsIssuerKeys() map[string]AllowlistIssuerKey {
	return map[string]AllowlistIssuerKey{builtinMaaPinsIssuerID: {Alg: builtinMaaPinsIssuerAlg, EdPub: builtinMaaPinsEdPub, PqPub: builtinMaaPinsMlDsaPub}}
}

// BuiltinMaaPinsSource is a substitute signed pin source (tests, or a fork that signs its own pins). MinVersion defaults to 1.
type BuiltinMaaPinsSource struct {
	Manifest   any
	IssuerKeys map[string]AllowlistIssuerKey
	MinVersion int64
}

// BuiltinMaaPins is a verified pin set.
type BuiltinMaaPins struct {
	Version   int64
	Digest    string
	ExpiresAt int64
	// MaaSigningSpkis are the self-signed instance key pins by issuer URL; RevokedSigningSpkis the tombstoned ones.
	MaaSigningSpkis, RevokedSigningSpkis         map[string][]string
	MaaChainRootSpkis, MaaChainIntermediateSpkis []string
	// Vantages is the number of independent vantages recorded in the signed corroboration entry; Method its signed text.
	Vantages int
	Method   string
}

const (
	maaPinsMaxLifetimeMs = int64(400 * 24 * 3_600_000)
	maaPinsMinVantages   = 3
)

var (
	maaCorrobLabel = regexp.MustCompile(`^vantages=([0-9]+);method=(.*)$`)
	maaPinsMemo    sync.Map // *BuiltinMaaPinsSource (nil source: the built-in set) to *maaPinsEval
)

type maaPinsEval struct {
	err                  string
	value                *BuiltinMaaPins
	notBefore, expiresAt int64
}

func evaluateMaaPins(src BuiltinMaaPinsSource, nowMs int64) *maaPinsEval {
	bad := func(r string) *maaPinsEval { return &maaPinsEval{err: r} }
	check := nowMs // signature and structure are checked at a time inside the window; the window is re-checked on every call
	if m, ok := src.Manifest.(map[string]any); ok {
		if b, ok := m["body"].(map[string]any); ok {
			if nb, ok := anySafeInt(b["notBefore"]); ok {
				check = nb
			}
		}
	}
	minV := src.MinVersion
	if minV == 0 {
		minV = 1
	}
	lifetime := float64(maaPinsMaxLifetimeMs)
	v0 := VerifyAllowlistManifest(src.Manifest, VerifyAllowlistOptions{IssuerKeys: src.IssuerKeys, NowMs: check, MinVersion: &minV, MaxLifetimeMs: &lifetime})
	if !v0.OK {
		return bad(v0.Code + ": " + v0.Reason)
	}
	nb, _ := anySafeInt(v0.Body["notBefore"])
	exp, _ := anySafeInt(v0.Body["expiresAt"])
	p, err := ProjectAllowlist(v0, nb)
	if err != nil {
		return bad(err.Error())
	}
	if len(p.Corroboration) != 1 {
		return bad("manifest must carry exactly one attest-corroboration entry")
	}
	m := maaCorrobLabel.FindStringSubmatch(p.Corroboration[0].Label)
	vantages := 0
	if m != nil {
		vantages, _ = strconv.Atoi(m[1])
	}
	if m == nil || vantages < maaPinsMinVantages {
		return bad(fmt.Sprintf("corroboration records %d vantages < required %d", vantages, maaPinsMinVantages))
	}
	if len(p.MaaSigningSpkis) == 0 {
		return bad("manifest pins no MAA signing key")
	}
	if len(p.MaaChainRootSpkis) == 0 || len(p.MaaChainIntermediateSpkis) == 0 {
		return bad("manifest lacks the Microsoft chain root / intermediate pins")
	}
	revoked := map[string][]string{}
	for _, r := range p.Revoked {
		if r.Kind == "maa-signing-spki" {
			revoked[r.Label] = append(revoked[r.Label], r.Value)
		}
	}
	return &maaPinsEval{notBefore: nb, expiresAt: exp, value: &BuiltinMaaPins{Version: v0.Version, Digest: v0.Digest, ExpiresAt: exp, MaaSigningSpkis: p.MaaSigningSpkis,
		RevokedSigningSpkis: revoked, MaaChainRootSpkis: p.MaaChainRootSpkis, MaaChainIntermediateSpkis: p.MaaChainIntermediateSpkis, Vantages: vantages, Method: m[2]}}
}

// LoadBuiltinMaaPins loads and verifies the built-in pin set (or source, when non-nil) at nowMs. Signature verification is memoised
// per source; the validity window is re-checked on every call. The error is the fail-closed reason.
func LoadBuiltinMaaPins(nowMs int64, source *BuiltinMaaPinsSource) (pins *BuiltinMaaPins, err error) {
	defer func() {
		if r := recover(); r != nil {
			pins, err = nil, fmt.Errorf("%v", r)
		}
	}()
	var src BuiltinMaaPinsSource
	if source != nil {
		src = *source
	} else {
		manifest, perr := ParseJSONLenient([]byte(builtinMaaPinsManifest))
		if perr != nil {
			return nil, perr
		}
		src = BuiltinMaaPinsSource{Manifest: manifest, IssuerKeys: BuiltinMaaPinsIssuerKeys(), MinVersion: builtinMaaPinsMinVersion}
	}
	r, ok := maaPinsMemo.Load(source)
	if !ok {
		r, _ = maaPinsMemo.LoadOrStore(source, evaluateMaaPins(src, nowMs))
	}
	e := r.(*maaPinsEval)
	switch {
	case e.err != "":
		return nil, fmt.Errorf("%s", e.err)
	case nowMs < e.notBefore:
		return nil, fmt.Errorf("built-in pins are not yet valid (clock behind the release)")
	case nowMs > e.expiresAt:
		return nil, fmt.Errorf("built-in pins expired; update the package or pass explicit initialPins")
	}
	return e.value, nil
}
