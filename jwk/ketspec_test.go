package jwk

import (
	"encoding/json"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const keys = `{
  "keys": [
    {
      "kty": "OKP",
      "d": "90nsVfpAV2VNrrGt75mGLWg-RL4sQLWk7EKslfOrloo",
      "use": "enc",
      "crv": "X25519",
      "kid": "8a97d682-455a-4035-beae-f66f92854474",
      "x": "zK8ckoiw9cYsvgrQ-GXMgAqHVOq-I_l8uwlryLHMh3A"
    },
    {
      "kty": "EC",
      "d": "1GIXPYYL9igpx97XRsB8FKfFD5fLrSKx7yLzGO5MvnA",
      "crv": "P-256",
      "x": "kk9qrjU7wfrO6d3rY7F41aUvVLKdYLgf0m6TE1rQLSk",
"kid": "key1",
      "y": "vA5j-Kzy2qTtlyPeJ1apoc_7viZV-wq1Fw_BDCVcahk"
    },
    {
      "kty": "OKP",
      "d": "Du6aSH_9vKXrSZOj-kf4CuOdkX5Rla0RbURzQR5z1Co",
      "use": "sig",
      "crv": "Ed25519",
      "kid": "ba9091cf-8e19-4d9c-b5fe-8fb94d33f7d1",
      "x": "u4lAEsFy5rRrjJLVFfgerZZC0nsT1KDZV9FQ-_59ES0"
    }
  ]
}
`

var _ = Describe("Key spec set", func() {
	keySpecSet := new(KeySpecSet)
	BeforeEach(func() {
		err := json.Unmarshal([]byte(keys), keySpecSet)
		Expect(err).ShouldNot(HaveOccurred())
	})

	It("should return the primary Ed25519 key", func() {
		keySpec, keyPair := keySpecSet.PrimaryCurveOKP("Ed25519")
		Expect(keySpec.KeyID).To(Equal("ba9091cf-8e19-4d9c-b5fe-8fb94d33f7d1"))
		Expect(keyPair.Curve()).To(Equal("Ed25519"))
	})

	It("should return the primary key OKP key type", func() {
		keySpec := keySpecSet.PrimaryKey("OKP")
		Expect(keySpec.KeyID).To(Equal("8a97d682-455a-4035-beae-f66f92854474"))
	})

	It("should return the primary ECDSA private key", func() {
		keySpec, privateKey := keySpecSet.PrimaryECDSAPrivate()
		Expect(keySpec.KeyID).To(Equal("key1"))
		Expect(privateKey.Curve.Params().Name).To(Equal("P-256"))
	})
})
