package jwk

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	rsaN      = "23182597259473293261062929136004851743488715456325935339630929078301380557272542466644924713517480034309514786702657400871121758791339475177349574797554678127072284911468734260797149544305402362651745982006454339450698408043468455706880608337261890188634493660206038188725785669705785539361189343625654233905021821316159161376213940367753312352093994601963033404383328808980511829292172899726932067622350967994146509852891407626545379987200062978477698924329822574169694899934741860192810475120784030232688426853179473288556585697091524284649162459051478208092311952193485051471689882186858621688713540245586232849401"
	rsaD      = "3169447357139947016481130431032904643509145833478498873050233067451674165634099523950417709585678641186097204462453428014789370260622269826037996706991316600066644381139811998973747042387909198916026732971875900353666749104619945422183655808197911654335185669094497797747578308445059102990314730898360650255371270361335454582746528012686405047341592200216332284709101899531009067473578218723432022663563495847153125826120005506584376291625824926080125784619905594670607539482019490249619728735763618237058621084643675420150435993377978515055270064649964212477646882842605374044127590397566954177537657386434558405633"
	rsaJwkStr = `{
			"kty":"RSA",
			"kid":"my-rsa",
			"use":"sig",
            "alg":"RS256",
			"n":"t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRyO125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0XOC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q", 
            "e":"AQAB",
			"d":"GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTyWfSNkuaAwnOEbIQVy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdlPKXy9UvqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo4_PMaenNnPiQgO0xnuToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMqADC6p1M3h33tsurY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8C1EWmeRDkK2ahecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ",
            "p":"2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-PIHfQP0FkxXVrx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk31s0Q8UK96E3_OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws",
			"q":"1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6Iedis4S7B_coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYKrYl52ziqK0E_ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s",
			"dp":"KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_MOzqYAJMcLMZtbUtwKqvVDq3tbEo3ZIcohbDtt6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_lhqigI4y_kqS1wY52IwjUn5rgRrJ-yYo1h41KR-vz2pYhEAeYrhttWtxVqLCRViD6c",
			"dq":"AvfS0-gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkbN9GQTB9yqpDoYaN06H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3KRbBymXxkb5qwUpX5ELD5xFc6FeiafWYY63TmmEAu_lRFCOJ3xDea-ots",
			"qi":"lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmUqqabu9V0-Py4dQ57_bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm-Fp0oYu_neotgQ0hzbI5gry7ajdYy9-2lNx_76aBZoOUu9HCJ-UsfSOI8"
		}`

	rsaJwkPubStr = `{
			"kty":"RSA",
			"kid":"my-rsa",
			"use":"sig",
            "alg":"RS256",
			"n":"t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRyO125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0XOC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q", 
            "e":"AQAB"
		}`
)

var _ = Describe("RSA", func() {
	It("Should decode a valid RSA private key", func() {
		var k KeySpec
		Expect(json.Unmarshal([]byte(rsaJwkStr), &k)).To(Succeed())
		verifyRSAKeySpec(&k)
	})

	It("Should decode a valid RSA public key", func() {
		var k KeySpec
		Expect(json.Unmarshal([]byte(rsaJwkPubStr), &k)).To(Succeed())
		verifyRSAKeySpecWith(&k, true)
	})

	It("Should round-trip decode and parse correctly (fixed key)", func() {
		var k KeySpec
		Expect(json.Unmarshal([]byte(rsaJwkStr), &k)).To(Succeed())
		jwkBytes, err := k.MarshalJSON()
		Expect(err).To(Succeed())
		Expect(string(jwkBytes)).To(MatchJSON(rsaJwkStr))
	})

	It("Should round-trip encode and parse correctly (random key)", func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).To(Succeed())
		pub, priv, ok := rsaPubPriv(key)
		Expect(ok).To(BeTrue())
		testRSAKeyPair(pub, priv)
	})

	It("Extract public key (fixed)", func() {
		var k KeySpec
		Expect(json.Unmarshal([]byte(rsaJwkStr), &k)).To(Succeed())

		origPub, _, ok := rsaPubPriv(k.Key)
		Expect(ok).To(BeTrue())

		publicOnly, err := k.PublicOnly()
		Expect(err).To(Succeed())
		Expect(publicOnly.IsPublic()).To(BeTrue())

		publicRSA, ok := publicOnly.Key.(*rsa.PublicKey)
		Expect(ok).To(BeTrue())
		Expect(origPub).To(Equal(publicRSA))

		pubJson, err := k.MarshalPublicJSON()
		Expect(err).To(Succeed())

		Expect(string(pubJson)).To(MatchJSON(rsaJwkPubStr))
	})

	It("Extract public key (random)", func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).To(Succeed())

		k := KeySpec{
			Key:       key,
			KeyID:     "my-rsa",
			Use:       "sig",
			Algorithm: "RS256",
		}

		origPub, _, ok := rsaPubPriv(key)
		Expect(ok).To(BeTrue())

		publicOnly, err := k.PublicOnly()
		Expect(err).To(Succeed())
		Expect(publicOnly.IsPublic()).To(BeTrue())

		publicRSA, ok := publicOnly.Key.(*rsa.PublicKey)
		Expect(ok).To(BeTrue())
		Expect(origPub).To(Equal(publicRSA))

		pubJson, err := k.MarshalPublicJSON()
		Expect(err).To(Succeed())

		origPubSpec := KeySpec{
			Key:       origPub,
			KeyID:     k.KeyID,
			Algorithm: k.Algorithm,
			Use:       k.Use,
		}
		origPubBytes, err := origPubSpec.MarshalJSON()
		Expect(err).To(Succeed())

		Expect(string(pubJson)).To(MatchJSON(string(origPubBytes)))
	})
})

func verifyRSAKeySpec(k *KeySpec) {
	verifyRSAKeySpecWith(k, false)
}

func verifyRSAKeySpecWith(k *KeySpec, publicOnly bool) {
	Expect(k.IsKeyType("RSA")).To(BeTrue())
	Expect(k.Algorithm).To(Equal("RS256"))
	Expect(k.Use).To(Equal("sig"))
	Expect(k.KeyID).To(Equal("my-rsa"))
	Expect(k.IsPublic()).To(Equal(publicOnly))
	pub, priv, ok := rsaPubPriv(k.Key)
	Expect(ok).To(BeTrue())
	Expect(pub.N.String()).To(Equal(rsaN))
	Expect(pub.E).To(Equal(65537))
	if publicOnly {
		Expect(priv).To(BeNil())
	} else {
		Expect(priv).ToNot(BeNil())
		Expect(priv.D.String()).To(Equal(rsaD))
	}
}

func rsaPubPriv(key interface{}) (*rsa.PublicKey, *rsa.PrivateKey, bool) {
	if priv, ok := key.(*rsa.PrivateKey); ok {
		return &priv.PublicKey, priv, true
	} else if pub, ok := key.(*rsa.PublicKey); ok {
		return pub, nil, true
	} else {
		return nil, nil, false
	}
}

func testRSAKeyPair(pub *rsa.PublicKey, priv *rsa.PrivateKey) {
	var err error

	var key interface{}
	if priv != nil {
		key = priv
	} else {
		key = pub
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
	Expect(m).To(HaveKeyWithValue("kty", "RSA"))
	Expect(m).To(HaveKeyWithValue("e", "AQAB"))
	if priv != nil {
		Expect(m).To(HaveKey("d"))
		Expect(m).To(HaveKey("p"))
		Expect(m).To(HaveKey("q"))
		Expect(m).To(HaveKey("dp"))
		Expect(m).To(HaveKey("dq"))
		Expect(m).To(HaveKey("qi"))
	} else {
		Expect(m).ToNot(HaveKey("d"))
		Expect(m).ToNot(HaveKey("p"))
		Expect(m).ToNot(HaveKey("q"))
		Expect(m).ToNot(HaveKey("dp"))
		Expect(m).ToNot(HaveKey("dq"))
		Expect(m).ToNot(HaveKey("qi"))
	}

	// Unmarshal
	var k2 KeySpec
	err = json.Unmarshal(b, &k2)
	Expect(err).To(Succeed())

	_, k2priv, _ := rsaPubPriv(k2.Key)
	if k2priv != nil {
		k2priv.Precompute() // We need to pre-compute the key parameters to align the keys
	}

	Expect(k2).To(Equal(k))
	Expect(k2.IsPublic()).To(Equal(priv == nil), "key should be "+publicOrPrivate(priv == nil))
}
