package pca

// verifier_from_config: build a vendor attestation verifier from the language-neutral configuration documented in the
// conformance vector file (verifier_config_schema), and the default-verifier seam of VerifyPassport.

import (
	"fmt"
)

// AttestationVendors are the vendors VerifierFromConfig builds a verifier for.
var AttestationVendors = []string{"amd-sev-snp", "intel-tdx-dcap", "azure-maa", "gcp-confidential-space", "nvidia-gpu-spdm"}

type vendorImpl interface {
	verify(ev map[string]any, expected *AttestationBinding, nowMs int64) HardwareResult
}

// VendorVerifier verifies the hardware evidence of one vendor under a fixed configuration. It is safe for concurrent use.
type VendorVerifier struct {
	vendor    string
	impl      vendorImpl
	overrides map[string]any
}

// VerifierFromConfig builds the verifier for (vendor, config); the error is the constructor's refusal of the configuration
// (a missing allowlist, an absent trust anchor, a malformed pin: there is no accept-all). identity_overrides, if present,
// are merged over the measured identity of every successful verification.
func VerifierFromConfig(vendor string, config map[string]any) (*VendorVerifier, error) {
	// a nil config needs no default: every constructor (and identity_overrides below) only reads keys, and a nil map reads as empty
	var impl vendorImpl
	var err error
	switch vendor {
	case "amd-sev-snp":
		impl, err = newAmdVerifier(config) // on error impl is unused: the err check below returns first
	case "intel-tdx-dcap":
		impl, err = newDcapVerifier(config)
	case "azure-maa":
		impl, err = newMaaVerifier(config)
	case "gcp-confidential-space":
		impl, err = newGcpVerifier(config)
	case "nvidia-gpu-spdm":
		impl, err = newNvidiaVerifier(config)
	default:
		return nil, fmt.Errorf("unknown attestation vendor %q", vendor)
	}
	if err != nil {
		return nil, err
	}
	v := &VendorVerifier{vendor: vendor, impl: impl}
	if ov, ok := config["identity_overrides"].(map[string]any); ok {
		v.overrides = ov
	}
	return v, nil
}

// Vendor is the vendor this verifier was built for.
func (v *VendorVerifier) Vendor() string { return v.vendor }

var vendorErrorPrefix = map[string]string{
	"amd-sev-snp":            "amd-snp verification error (fail closed): ",
	"intel-tdx-dcap":         "intel-dcap verification error (fail closed): ",
	"azure-maa":              "azure-maa verification error (fail closed): ",
	"gcp-confidential-space": "gcp-confidential-space verification error (fail closed): ",
	"nvidia-gpu-spdm":        "nvidia-spdm verification error (fail closed): ",
}

// Verify verifies the vendor evidence (nil: none supplied for this action) against the expected binding at the clock nowMs
// (epoch milliseconds). It never panics: anything unexpected is a failed result.
func (v *VendorVerifier) Verify(evidence map[string]any, expected *AttestationBinding, nowMs int64) (res HardwareResult) {
	defer func() {
		if r := recover(); r != nil {
			res = hwFail(fmt.Sprintf("%s%v", vendorErrorPrefix[v.vendor], r))
		}
	}()
	res = v.impl.verify(evidence, expected, nowMs)
	if res.OK && res.Measured != nil && len(v.overrides) > 0 {
		res.Measured = mergeOverrides(res.Measured, v.overrides)
	}
	return res
}

// DefaultHardware is the built-in hardware verifier of VerifyPassport, used when no integrator Attest is given.
// Evidence returns the vendor evidence object (the wire form of the vendor, see verifier_config_schema) for the passport's
// evidence document; nil means none. When Evidence is nil the passport's evidence document itself is the vendor evidence.
type DefaultHardware struct {
	Verifier *VendorVerifier
	Evidence func(doc map[string]any) map[string]any
}

func (d *DefaultHardware) attest(nowMs int64) func(doc map[string]any, expected PassportBinding) (PassportAttestation, error) {
	return func(doc map[string]any, expected PassportBinding) (PassportAttestation, error) {
		ev := doc
		if d.Evidence != nil {
			ev = d.Evidence(doc)
		}
		b := &AttestationBinding{HolderPub: expected.HolderPub, GrantRef: expected.GrantRef, Epoch: float64(expected.Epoch), Nonce: expected.Nonce}
		r := d.Verifier.Verify(ev, b, nowMs)
		return PassportAttestation{OK: r.OK, Bound: r.Bound, Measured: r.Measured}, nil
	}
}
