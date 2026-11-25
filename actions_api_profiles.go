package pca

// The platform view of the canonical approval render: the Secure Payment Confirmation expectation and the CIBA / RAR
// authorization_details entry (PSD2 linking, minor units and batches are in approval.go).

import "fmt"

// ActionSpcExpectation is what a WebAuthn assertion verifier must find in the signed clientData.payment of a payment render. The
// payee parameter's value is the payee name (payeeAs "name", the default) or the payee origin ("origin") the browser shows. An
// unlinkable render is an error with code psd2_unlinkable.
func ActionSpcExpectation(r map[string]any, topOrigin string, payeeAs string) (map[string]any, error) {
	l, err := Psd2Linking(r)
	if err != nil {
		return nil, err
	}
	val, err := MinorToDecimal(int64(jsF(l["amount_minor"])), int64(jsF(l["exp"])))
	if err != nil {
		return nil, err
	}
	out := map[string]any{"topOrigin": topOrigin, "total": map[string]any{"currency": l["currency"], "value": val}}
	switch payeeAs {
	case "", "name":
		out["payeeName"] = l["payee"]
	case "origin":
		out["payeeOrigin"] = l["payee"]
	default:
		return nil, fmt.Errorf("spcExpectation: payeeAs must be name or origin")
	}
	return out, nil
}

// ActionCibaApprovalDetails is the RFC 9396 authorization_details entry carrying the canonical render, plus the speakable match code.
func ActionCibaApprovalDetails(r map[string]any) (map[string]any, error) {
	d, err := ApprovalRenderDigest(r)
	if err != nil {
		return nil, err
	}
	w, err := BindingWords(d)
	if err != nil {
		return nil, err
	}
	return map[string]any{"authorization_details": []any{map[string]any{"type": "pca_approval", "render": r, "render_digest": d}}, "match_code": w}, nil
}
