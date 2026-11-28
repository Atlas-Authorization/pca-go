package pca

// GatewayDecodePCActn is the public form of the pca-gateway export decodePCActn.
func GatewayDecodePCActn(text string) (map[string]any, error) {
	return gwDecodePCActn(text)
}
