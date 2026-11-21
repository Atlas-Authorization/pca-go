package pca

// Replays the schema reference corpus: the published wire schemas and the structural validator. The validate cases name a
// published schema by string (PCActn | Capability | PcaDiscoveryDocument) or give an ad-hoc schema object.

import "testing"

func TestSchemaReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-schema-dotnet.json.gz", map[string]vecFn{
		"schemas": func(args []any) (any, error) { return AllSchemas(), nil },
		"validate": func(args []any) (any, error) {
			schema := vecArg(args, 0)
			if name, ok := schema.(string); ok {
				schema = AllSchemas()[name]
			}
			return SchemaValidate(schema, vecArg(args, 1))
		},
	})
}
