package testutils

import "encoding/base64"

// PanicOnError panics on error
func PanicOnError(err error) {
	if err != nil {
		panic(err)
	}
}

// MustDecodeBase64URL decodes a raw base64 url string to a byte array and
// panics if any decoding error occurs.
func MustDecodeBase64URL(b64 string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(b64)
	PanicOnError(err)
	return b
}
