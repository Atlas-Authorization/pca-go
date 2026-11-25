package pca

// Replays the MCP adapter reference corpus: the WWW-Authenticate parser, the step-up planner, the RFC 9207 iss table, the
// tool-result proof meta, the PCA-Action header, the action-schema draft from an MCP tool list, the developer's decisions, and
// the closed-world check of a tool call. A reference throw requires an error.

import "testing"

func TestMcpReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-mcp.json.gz", map[string]vecFn{
		"constants": func(args []any) (any, error) {
			revs := make([]any, len(McpClientRevisions))
			for i, r := range McpClientRevisions {
				revs[i] = r
			}
			return map[string]any{"MCP_CLIENT_REVISIONS": revs, "MCP_AUTH_CLIENT_ROWS": McpAuthClientRows()}, nil
		},
		"parseChallenges": func(args []any) (any, error) { return McpParseChallenges(vecArg(args, 0)), nil },
		"pcaNeedProblem": func(args []any) (any, error) {
			if code := McpPcaNeedProblem(vecArg(args, 0)); code != "" {
				return code, nil
			}
			return nil, nil
		},
		"planStepUp": func(args []any) (any, error) {
			return McpPlanStepUp(vecArg(args, 0), vecArg(args, 1), vecArg(args, 2))
		},
		"checkAuthorizationResponseIss": func(args []any) (any, error) {
			return McpCheckAuthorizationResponseIss(vecArg(args, 0))
		},
		"guardToolResult": func(args []any) (any, error) {
			return McpGuardToolResult(vecArg(args, 0), vecArg(args, 1))
		},
		"pcaHeaders": func(args []any) (any, error) {
			s, _ := vecArg(args, 0).(string)
			return McpPcaHeaders(s), nil
		},
		"draftActionSchemaFromMcp": func(args []any) (any, error) {
			return McpDraftActionSchema(vecArg(args, 0), vecArg(args, 1))
		},
		"applySchemaDecisions": func(args []any) (any, error) {
			return McpApplySchemaDecisions(vecArg(args, 0), vecArg(args, 1))
		},
		"verbOfTool": func(args []any) (any, error) {
			tool, _ := vecArg(args, 1).(string)
			return McpVerbOfTool(vecArg(args, 0), tool)
		},
		"conformToolCall": func(args []any) (any, error) {
			tool, _ := vecArg(args, 1).(string)
			return McpConformToolCall(vecArg(args, 0), tool, vecArg(args, 2))
		},
	})
}
