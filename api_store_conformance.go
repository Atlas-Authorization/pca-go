package pca

// PcaStateFixture is the public name of pcaStateFixture.
type PcaStateFixture = pcaStateFixture

// StoreConformanceMakePcaStateFixture is the public form of the pca-store-conformance export makePcaStateFixture.
func StoreConformanceMakePcaStateFixture(n int) (*PcaStateFixture, error) {
	return makePcaStateFixture(n)
}
