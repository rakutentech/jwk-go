package okp

import (
	"crypto/rand"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Ed25519", func() {
	It("Test key generation", func() {
		key, err := GenerateEd25519(rand.Reader)
		Expect(err).To(Succeed())
		anyKey := interface{}(key)
		crv := anyKey.(CurveOctetKeyPair)
		Expect(crv.Curve()).To(Equal("Ed25519"))
	})
})

var _ = Describe("Curve25519", func() {
	It("Should do round-trip", func() {
		key, err := GenerateCurve25519(rand.Reader)
		Expect(err).To(Succeed())
		anyKey := interface{}(key)
		crv := anyKey.(CurveOctetKeyPair)
		Expect(crv.Curve()).To(Equal("X25519"))
	})
})
