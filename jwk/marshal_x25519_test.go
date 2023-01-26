package jwk

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/rakutentech/jwk-go/internal/testutils"
	"github.com/rakutentech/jwk-go/okp"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const (
	X25519x = "clZuS2tYN30tAfpCQ3Ln3RpJXc9dZKei23RkEmZVHVo"
	X25519d = "JeYekQrtVwjGtGGQbj-zWhTLMrgTF5wsUnZYKQdy8yE"
)

var X25519Example = okp.NewCurve25519(
	testutils.MustDecodeBase64URL(X25519x),
	testutils.MustDecodeBase64URL(X25519d),
)

var _ = Describe("Curve25519", func() {
	It("Should decode a valid Ed25519 key (and ignore unknown fields)", func() {
		jwkStr := `{
			"kid": "my-x25519",
			"kty": "OKP",
			"crv": "X25519",
            "alg": "ECDH-ES",
            "use": "enc",
			"x":   "` + X25519x + `",
			"d":   "` + X25519d + `"
		}`

		var k KeySpec
		Expect(json.Unmarshal([]byte(jwkStr), &k)).To(Succeed())
		verifyX25519KeySpec(&k)
	})

	It("Should round-trip encode and parse correctly", func() {
		key, err := okp.GenerateCurve25519(rand.Reader)
		Expect(err).To(Succeed())
		testCurveOKP("X25519", key, false)
		testCurveOKP("X25519", key, true)
	})

	It("Extract public key", func() {
		key, err := okp.GenerateCurve25519(rand.Reader)
		Expect(err).To(Succeed())
		testOKPPublicOnly(key)
	})
})

func verifyX25519KeySpec(k *KeySpec) {
	verifyX25519KeySpecWith(k, false)
}

func verifyX25519KeySpecWith(k *KeySpec, publicOnly bool) {
	Expect(k.IsKeyType("OKP/X25519")).To(BeTrue())
	Expect(k.Algorithm).To(Equal("ECDH-ES"))
	Expect(k.Use).To(Equal("enc"))
	Expect(k.KeyID).To(Equal("my-x25519"))
	Expect(k.IsPublic()).To(Equal(publicOnly))
	curveOKP, ok := k.Key.(okp.CurveOctetKeyPair)
	Expect(ok).To(BeTrue())
	Expect(curveOKP.Algorithm()).To(Equal("ECDH-ES"))
	Expect(curveOKP.Curve()).To(Equal("X25519"))
	Expect(base64.RawURLEncoding.EncodeToString(curveOKP.PublicKey())).To(Equal(X25519x))
	if publicOnly {
		Expect(curveOKP.PrivateKey()).To(BeNil())
	} else {
		Expect(base64.RawURLEncoding.EncodeToString(curveOKP.PrivateKey())).To(Equal(X25519d))
	}
}
