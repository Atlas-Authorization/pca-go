package blstkit

// PcaEncryptionError is the typed refusal of the attribute-based encryption layer: an invalid master key, an invalid or
// non-single-use policy, or a policy header outside the canonical JSON profile. Test with errors.As.
type PcaEncryptionError struct{ Msg string }

// Error is the refusal message.
func (e *PcaEncryptionError) Error() string { return e.Msg }

func abeErr(msg string) error { return &PcaEncryptionError{Msg: msg} }
