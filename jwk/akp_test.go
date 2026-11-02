package jwk

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/rakutentech/jwk-go/akp"
	"github.com/rakutentech/jwk-go/jwktypes"
)

func readHex(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("decode hex %s: %v", name, err)
	}
	return b
}

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

var mldsaSets = []struct {
	alg     string
	pubFile string
	pubLen  int
}{
	{akp.MLDSA44, "ml-dsa-44-pub.hex", 1312},
	{akp.MLDSA65, "ml-dsa-65-pub.hex", 1952},
	{akp.MLDSA87, "ml-dsa-87-pub.hex", 2592},
}

// Public keys are the NIST ACVP FIPS 204 known answer public keys for each
// parameter set. We confirm an AKP JWK built from each one parses, round trips
// and thumbprints deterministically.
func TestAKPParsePublicNISTVectors(t *testing.T) {
	for _, tc := range mldsaSets {
		pub := readHex(t, tc.pubFile)
		if len(pub) != tc.pubLen {
			t.Fatalf("%s public key length %d, want %d", tc.alg, len(pub), tc.pubLen)
		}

		jwkJSON := `{"kty":"AKP","alg":"` + tc.alg + `","pub":"` + b64url(pub) + `"}`
		spec, err := Parse(jwkJSON)
		if err != nil {
			t.Fatalf("%s parse: %v", tc.alg, err)
		}

		key, ok := spec.Key.(akp.Key)
		if !ok {
			t.Fatalf("%s wrong key type %T", tc.alg, spec.Key)
		}
		if key.Algorithm() != tc.alg {
			t.Fatalf("%s algorithm %q, want %q", tc.alg, key.Algorithm(), tc.alg)
		}
		if !bytes.Equal(key.PublicKey(), pub) {
			t.Fatalf("%s public key mismatch after parse", tc.alg)
		}
		if key.PrivateKey() != nil {
			t.Fatalf("%s unexpected private key", tc.alg)
		}
		if !spec.IsPublic() {
			t.Fatalf("%s should be a public key", tc.alg)
		}

		kty, curve, private := spec.KeyType()
		if kty != jwktypes.AKP || curve != tc.alg || private {
			t.Fatalf("%s KeyType = %q/%q/%v", tc.alg, kty, curve, private)
		}

		out, err := spec.MarshalJSON()
		if err != nil {
			t.Fatalf("%s marshal: %v", tc.alg, err)
		}
		spec2, err := ParseBytes(out)
		if err != nil {
			t.Fatalf("%s reparse: %v", tc.alg, err)
		}
		key2 := spec2.Key.(akp.Key)
		if !bytes.Equal(key2.PublicKey(), pub) || key2.Algorithm() != tc.alg {
			t.Fatalf("%s round trip mismatch", tc.alg)
		}

		tp1, err := spec.Thumbprint()
		if err != nil {
			t.Fatalf("%s thumbprint: %v", tc.alg, err)
		}
		tp2, err := spec2.Thumbprint()
		if err != nil {
			t.Fatalf("%s thumbprint reparse: %v", tc.alg, err)
		}
		if len(tp1) == 0 || !bytes.Equal(tp1, tp2) {
			t.Fatalf("%s thumbprint not stable", tc.alg)
		}
	}
}

// The ML-DSA-65 key pair here was produced by OpenSSL 4.1. The private key is
// the raw 32 byte seed. We confirm a full private JWK round trips and that
// PublicOnly drops the private component.
func TestAKPPrivateRoundTrip(t *testing.T) {
	pub := readHex(t, "ml-dsa-65-keypair-pub.hex")
	seed := readHex(t, "ml-dsa-65-keypair-seed.hex")

	key, err := akp.NewKey(akp.MLDSA65, pub, seed)
	if err != nil {
		t.Fatalf("new key: %v", err)
	}

	spec := NewSpecWithID("ml-dsa-65-test", key)
	spec.Algorithm = akp.MLDSA65

	out, err := spec.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(out, []byte(`"priv"`)) {
		t.Fatal("private key missing from full JWK")
	}

	spec2, err := ParseBytes(out)
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	key2 := spec2.Key.(akp.Key)
	if !bytes.Equal(key2.PrivateKey(), seed) {
		t.Fatal("seed round trip mismatch")
	}
	if spec.IsPublic() {
		t.Fatal("private key reported as public")
	}

	pubSpec, err := spec.PublicOnly()
	if err != nil {
		t.Fatalf("public only: %v", err)
	}
	if !pubSpec.IsPublic() {
		t.Fatal("public only result is not public")
	}
	pubOut, err := pubSpec.MarshalJSON()
	if err != nil {
		t.Fatalf("public marshal: %v", err)
	}
	if bytes.Contains(pubOut, []byte(`"priv"`)) {
		t.Fatal("private key leaked into public JWK")
	}
	if !bytes.Equal(pubSpec.Key.(akp.Key).PublicKey(), pub) {
		t.Fatal("public only lost the public key")
	}
}

func TestAKPValidation(t *testing.T) {
	pub := readHex(t, "ml-dsa-65-pub.hex")

	if _, err := akp.NewKey(akp.MLDSA65, pub[:10], nil); err == nil {
		t.Fatal("expected error for short public key")
	}
	if _, err := akp.NewKey("ML-DSA-99", pub, nil); err == nil {
		t.Fatal("expected error for unknown algorithm")
	}
	if _, err := akp.NewKey(akp.MLDSA65, pub, []byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for bad private key length")
	}
	if _, err := Parse(`{"kty":"AKP","alg":"ML-DSA-65"}`); err == nil {
		t.Fatal("expected error for missing pub")
	}
	if _, err := Parse(`{"kty":"AKP","pub":"` + b64url(pub) + `"}`); err == nil {
		t.Fatal("expected error for missing alg")
	}
}
