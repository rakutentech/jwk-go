package jwk

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/rakutentech/jwk-go/internal/testutils"
	"github.com/rakutentech/jwk-go/okp"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	Ed25519x = "7Q8Rb_ZGckSnbkhTHAGm2u04xk2EbHLK-ruXVETi0zw"
	Ed25519d = "WLmYcWJCANPAQFWQD2NgA6wQkCsfV5AwxRPtO_1QO3g"
)

var Ed25519Example = okp.NewEd25519(
	testutils.MustDecodeBase64URL(Ed25519x),
	testutils.MustDecodeBase64URL(Ed25519d),
)

var _ = Describe("Ed25519", func() {
	It("Should decode a valid Ed25519 key (and ignore unknown fields)", func() {
		jwkStr := `{
			"kid": "my-ed25519",
			"kty": "OKP",
			"crv": "Ed25519",
            "alg": "EdDSA",
            "use": "sig",
			"x":   "` + Ed25519x + `",
			"d":   "` + Ed25519d + `"
		}`

		var k KeySpec
		Expect(json.Unmarshal([]byte(jwkStr), &k)).To(Succeed())
		verifyEd25519KeySpec(&k)
	})

	It("Should round-trip encode and parse correctly", func() {
		key, err := okp.GenerateEd25519(rand.Reader)
		Expect(err).To(Succeed())
		now := time.Now().Truncate(time.Second)
		testCurveOKP("Ed25519", key, false, time.Time{})
		testCurveOKP("Ed25519", key, true, time.Time{})
		testCurveOKP("Ed25519", key, false, now)
		testCurveOKP("Ed25519", key, true, now)
	})

	It("Extract public key", func() {
		key, err := okp.GenerateEd25519(rand.Reader)
		Expect(err).To(Succeed())
		testOKPPublicOnly(key)
	})
})

func verifyEd25519KeySpec(k *KeySpec) {
	verifyEd25519KeySpecWith(k, false)
}

func verifyEd25519KeySpecWith(k *KeySpec, publicOnly bool) {
	Expect(k.IsKeyType("OKP/Ed25519")).To(BeTrue())
	Expect(k.Algorithm).To(Equal("EdDSA"))
	Expect(k.Use).To(Equal("sig"))
	Expect(k.KeyID).To(Equal("my-ed25519"))
	Expect(k.IsPublic()).To(Equal(publicOnly))
	curveOKP, ok := k.Key.(okp.CurveOctetKeyPair)
	Expect(ok).To(BeTrue())
	Expect(curveOKP.Algorithm()).To(Equal("EdDSA"))
	Expect(curveOKP.Curve()).To(Equal("Ed25519"))
	Expect(base64.RawURLEncoding.EncodeToString(curveOKP.PublicKey())).To(Equal(Ed25519x))
	if publicOnly {
		Expect(curveOKP.PrivateKey()).To(BeNil())
	} else {
		Expect(base64.RawURLEncoding.EncodeToString(curveOKP.PrivateKey())).To(Equal(Ed25519d))
	}
}
