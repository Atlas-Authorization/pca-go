package pca

// The gRPC half of the importer corpus: the .proto text parser, the binary descriptor reader and the importer (replayed together with
// the GraphQL half by TestActionImportSDLVectors).

// aimBytesArg decodes a corpus `{"$bytes": base64url}` argument into the byte string.
func aimBytesArg(v any) any {
	if m, ok := v.(map[string]any); ok {
		if s, isS := m["$bytes"].(string); isS {
			return nodeB64(s)
		}
	}
	return v
}

func aimGrpcFns() map[string]vecFn {
	return map[string]vecFn{
		"importGrpc": func(a []any) (any, error) {
			return aimTestReport(ActionImportGRPC(aimBytesArg(vecArg(a, 0)), aimTestOpts(vecArg(a, 1))))
		},
		"parseProto": func(a []any) (out any, err error) {
			defer aimRecover(&err)
			s, _ := vecArg(a, 0).(string)
			return aimParseProto(s, 2_000_000).toJSON(), nil
		},
		"parseDescriptorSet": func(a []any) (out any, err error) {
			defer aimRecover(&err)
			b, _ := aimBytesArg(vecArg(a, 0)).([]byte)
			return aimParseDescriptorSet(b).toJSON(), nil
		},
	}
}
