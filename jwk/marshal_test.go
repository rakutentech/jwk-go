package jwk

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/rakutentech/jwk-go/internal/testutils"
	"github.com/rakutentech/jwk-go/okp"
)

var _ = Describe("KeySpecSet", func() {
	x25519Key, err := okp.GenerateCurve25519(rand.Reader)
	testutils.PanicOnError(err)
	x25519Key2, err := okp.GenerateCurve25519(rand.Reader)
	testutils.PanicOnError(err)
	x25519PubOnly := okp.NewCurve25519(x25519Key2.PublicKey(), nil)

	ed25519Key, err := okp.GenerateEd25519(rand.Reader)
	testutils.PanicOnError(err)
	ed25519Key2, err := okp.GenerateEd25519(rand.Reader)
	testutils.PanicOnError(err)
	ed25519PubOnly := okp.NewEd25519(ed25519Key2.PublicKey(), nil)

	keySpecFixture := KeySpecSet{
		Keys: []KeySpec{
			{
				Key:       X25519Example,
				KeyID:     "my-x25519",
				Algorithm: "ECDH-ES",
				Use:       "enc",
			}, {
				Key:   x25519Key,
				KeyID: "another-x25519",
			}, {
				Key:   x25519PubOnly,
				KeyID: "public-x25519",
			}, {
				Key:       Ed25519Example,
				KeyID:     "my-ed25519",
				Algorithm: "EdDSA",
				Use:       "sig",
			}, {
				Key:   ed25519Key,
				KeyID: "another-ed25519",
			}, {
				Key:   ed25519PubOnly,
				KeyID: "public-ed25519",
			},
		},
	}

	It("Should unmarshal JWKS", func() {
		jwksStr := `{"keys": [{
			"kid": "my-x25519",
			"kty": "OKP",
			"crv": "X25519",
            "alg": "ECDH-ES",
            "use": "enc",
			"x":   "` + X25519x + `",
			"d":   "` + X25519d + `"
		}, {
			"kid": "my-ed25519",
			"kty": "OKP",
			"crv": "Ed25519",
            "alg": "EdDSA",
            "use": "sig",
			"x":   "` + Ed25519x + `",
			"d":   "` + Ed25519d + `"
        }]}`

		var ks KeySpecSet
		Expect(json.Unmarshal([]byte(jwksStr), &ks)).To(Succeed())
		Expect(ks.Keys).To(HaveLen(2))
		verifyX25519KeySpec(&ks.Keys[0])
		verifyEd25519KeySpec(&ks.Keys[1])
	})

	It("Should round-trip encode and parse correctly", func() {
		b, err := json.Marshal(keySpecFixture)
		Expect(err).To(Succeed())
		var ks KeySpecSet
		err = json.Unmarshal(b, &ks)
		Expect(err).To(Succeed())
		Expect(ks.Keys).To(HaveLen(6))
		verifyX25519KeySpec(&ks.Keys[0])
		verifyEd25519KeySpec(&ks.Keys[3])
	})

	It("Should round-trip with long keys", func() {
		keySpecs := KeySpecSet{
			Keys: []KeySpec{
			},
		}

		for _, size := range []int{1024, 3123, 94973} {
			keySpecs.Keys = append(keySpecs.Keys, KeySpec{
				Key:       X25519Example,
				KeyID:     randomString(size),
				Algorithm: "ECDH-ES",
				Use:       "enc",
			})
			keySpecs.Keys = append(keySpecs.Keys, KeySpec{
				Key:       randomBytes(size),
				KeyID:     randomString(32),
				Algorithm: "Custom",
			})
		}

		b, err := json.Marshal(keySpecs)
		Expect(err).To(Succeed())
		var ks KeySpecSet
		err = json.Unmarshal(b, &ks)
		Expect(err).To(Succeed())
		Expect(ks).To(Equal(keySpecs))
	})

	It("Extract public key", func() {
		b, err := keySpecFixture.MarshalPublicJSON()
		Expect(err).To(Succeed())
		var ks KeySpecSet
		err = json.Unmarshal(b, &ks)
		Expect(err).To(Succeed())
		Expect(ks.Keys).To(HaveLen(6))
		verifyX25519KeySpecWith(&ks.Keys[0], true)
		verifyEd25519KeySpecWith(&ks.Keys[3], true)
	})

})

func publicOrPrivate(public bool) string {
	if public {
		return "public"
	}
	return "private"
}

func testCurveOKP(curve string, key okp.CurveOctetKeyPair, withPrivate bool) {
	var err error
	if !withPrivate {
		key, err = okp.NewCurveOKP(key.Curve(), key.PublicKey(), nil)
		Expect(err).To(Succeed())
	}
	k := KeySpec{
		Key:   key,
		KeyID: "foo",
	}

	// Marshal
	b, err := json.Marshal(&k)
	Expect(err).To(Succeed())
	m := make(map[string]interface{})
	Expect(json.Unmarshal(b, &m)).To(Succeed())
	Expect(m).To(HaveKeyWithValue("kid", "foo"))
	Expect(m).To(HaveKeyWithValue("kty", "OKP"))
	Expect(m).To(HaveKeyWithValue("crv", curve))
	Expect(m).To(HaveKeyWithValue("x", base64.RawURLEncoding.EncodeToString(key.PublicKey())))
	if withPrivate {
		Expect(m).To(HaveKeyWithValue("d", base64.RawURLEncoding.EncodeToString(key.PrivateKey())))
	} else {
		Expect(m).ToNot(HaveKey("d"))
	}

	// Unmarshal
	var k2 KeySpec
	err = json.Unmarshal(b, &k2)
	Expect(err).To(Succeed())
	Expect(k2).To(Equal(k))
	Expect(k2.IsPublic()).To(Equal(!withPrivate), "key should be "+publicOrPrivate(!withPrivate))
}

func testOKPPublicOnly(key okp.CurveOctetKeyPair) {
	k := KeySpec{
		Key:   key,
		KeyID: "foo",
	}
	publicOnly, err := k.PublicOnly()
	Expect(err).To(Succeed())
	Expect(publicOnly.IsPublic()).To(BeTrue())

	publicOKP, ok := publicOnly.Key.(okp.CurveOctetKeyPair)
	Expect(ok).To(BeTrue())
	Expect(publicOKP.PublicKey()).To(Equal(key.PublicKey()))
}

func randomBytes(size int) []byte {
	b := make([]byte, size)
	_, err := rand.Reader.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

func randomString(size int) string {
	return base64.RawStdEncoding.EncodeToString(randomBytes(size))
}
