package pca

// VerifiedCoreIsTaintLevel is the public form of the pca-verified-core export isTaintLevel.
func VerifiedCoreIsTaintLevel(v any) bool {
	return isTaintLevel(v)
}
