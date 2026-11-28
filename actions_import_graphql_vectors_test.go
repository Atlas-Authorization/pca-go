package pca

// Replays the reference corpus for the GraphQL importer and its SDL / introspection parsers (the same corpus holds the gRPC half, wired in from
// actions_import_grpc_vectors_test.go).

import "testing"

func aimSDLFns() map[string]vecFn {
	return map[string]vecFn{
		"importGraphql": func(a []any) (any, error) {
			return aimTestReport(ActionImportGraphQL(vecArg(a, 0), aimTestOpts(vecArg(a, 1))))
		},
		"parseGraphqlSdl": func(a []any) (out any, err error) {
			defer aimRecover(&err)
			s, _ := vecArg(a, 0).(string)
			return aimGqlParseSDL(s, 2_000_000).toJSON(), nil
		},
		"fromIntrospection": func(a []any) (out any, err error) {
			defer aimRecover(&err)
			return aimGqlFromIntrospection(vecArg(a, 0)).toJSON(), nil
		},
	}
}

func TestActionImportSDLVectors(t *testing.T) {
	fns := aimSDLFns()
	for k, f := range aimGrpcFns() {
		fns[k] = f
	}
	replayVectors(t, "ref-actions-import-sdl.json.gz", fns)
}
