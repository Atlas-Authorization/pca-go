package pca

import "fmt"

// Error codes of a PcaAgentError.
const (
	PcaAgentNoPlan      = "no_plan"
	PcaAgentUnknownNode = "unknown_node"
	PcaAgentNoSecret    = "no_secret"
	PcaAgentNetwork     = "network"
	PcaAgentBadResponse = "bad_response"
	PcaAgentBuildFailed = "build_failed"
)

// PcaAgentError is the error of the plan-committing agent client: a stable code (one of the PcaAgent* constants), a message and, for a
// response the server gave, its HTTP status (0 otherwise). Test with errors.As.
type PcaAgentError struct {
	Code       string
	Msg        string
	HTTPStatus int
}

// Error is the message.
func (e *PcaAgentError) Error() string {
	if e.HTTPStatus != 0 {
		return fmt.Sprintf("%s (%d)", e.Msg, e.HTTPStatus)
	}
	return e.Msg
}

// MaxPqSignerEntries is the number of co-signature entries of a presented post-quantum quorum block that are examined (the rest are
// ignored).
const MaxPqSignerEntries = MaxPqQuorumEntries
