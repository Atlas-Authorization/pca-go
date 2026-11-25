package pca

import (
	"errors"
	"math"
	"time"
)

// defaultChallengeWindowMs is the window OpenOptimistic uses when none is requested (5 minutes).
const defaultChallengeWindowMs = 300_000

// ValidateWindow is the reason a claim's (issued_at, window) is not acceptable against server time and policy, or "" when it is.
func ValidateWindow(issuedAt, windowMs, serverNow float64, p ChallengeWindowPolicy) string {
	switch {
	case math.IsNaN(serverNow) || math.IsInf(serverNow, 0):
		return "server time is not finite"
	case math.IsNaN(issuedAt) || math.IsInf(issuedAt, 0) || math.IsNaN(windowMs) || math.IsInf(windowMs, 0):
		return "malformed challenge window"
	case !(math.Abs(issuedAt-serverNow) <= p.MaxSkewMs):
		return "issued_at is outside the allowed skew of server time"
	case !(windowMs >= p.MinWindowMs):
		return "challenge window is below the minimum"
	case !(windowMs <= p.MaxWindowMs):
		return "challenge window exceeds the maximum"
	}
	return ""
}

// OpenOptimisticOptions are the options of OpenOptimistic; a nil pointer takes the default (window policy default, server time =
// now, issued_at = server time).
type OpenOptimisticOptions struct {
	BondRef           string
	ClaimedR          float64
	ChallengeWindowMs *float64
	IssuedAt          *float64
	ServerNow         *float64
	WindowPolicy      *ChallengeWindowPolicy
}

func optFin(p *float64) (float64, bool) {
	if p == nil || math.IsNaN(*p) || math.IsInf(*p, 0) {
		return 0, false
	}
	return *p, true
}

// OpenOptimistic opens a bonded optimistic claim for pcactn, signed by the agent-leaf key. It REFUSES an irreversible action, a
// non-finite claimedR and a window outside the policy.
func OpenOptimistic(pcactn map[string]any, o OpenOptimisticOptions, signer *KeyPair) (map[string]any, error) {
	action, _ := pcactn["action"].(map[string]any)
	rc := action["reversibility_class"]
	if rc == irreversibleCls {
		return nil, errors.New("openOptimistic: irreversible actions cannot use the optimistic fast-path (§9A)")
	}
	if math.IsNaN(o.ClaimedR) || math.IsInf(o.ClaimedR, 0) {
		return nil, errors.New("openOptimistic: claimedR must be finite")
	}
	policy := DefaultChallengeWindowPolicy
	if o.WindowPolicy != nil {
		policy = *o.WindowPolicy
	}
	serverNow, ok := optFin(o.ServerNow)
	if !ok {
		serverNow = float64(time.Now().UnixMilli())
	}
	issuedAt, ok := optFin(o.IssuedAt)
	if !ok {
		issuedAt = serverNow
	}
	windowMs := float64(defaultChallengeWindowMs)
	if o.ChallengeWindowMs != nil {
		windowMs = *o.ChallengeWindowMs
	}
	if bad := ValidateWindow(issuedAt, windowMs, serverNow, policy); bad != "" {
		return nil, errors.New("openOptimistic: " + bad)
	}
	digest, err := HashCanonical(pcactn)
	if err != nil {
		return nil, err
	}
	class := "unknown"
	if s, ok := rc.(string); ok {
		class = s
	}
	body := map[string]any{
		"pcactn_digest":       digest,
		"bond_ref":            o.BondRef,
		"claimed_r":           jsNumber(o.ClaimedR),
		"reversibility_class": class,
		"issued_at":           jsNumber(issuedAt),
		"challenge_window_ms": jsNumber(windowMs),
	}
	cb, err := canonBytes(body)
	if err != nil {
		return nil, err
	}
	body["sig"] = b64.EncodeToString(signer.Sign(append([]byte(claimDomain), cb...)))
	return body, nil
}

// OpenChargeBond opens a challenge-windowed bonded claim for a charge's PCActn: if the charge is later disputed, a fraud proof
// slashes the bond and the charge is rolled back. A thin wrapper over OpenOptimistic; it REFUSES an irreversible charge.
func OpenChargeBond(pcactn map[string]any, o OpenOptimisticOptions, signer *KeyPair) (map[string]any, error) {
	return OpenOptimistic(pcactn, o, signer)
}
