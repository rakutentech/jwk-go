package jwk

// JWK represents an unparsed JSON Web Key (JWK) in its wire format.
type JWK struct {
	Kid string `json:"kid,omitempty"`
	Kty string `json:"kty,omitempty"`
	Alg string `json:"alg,omitempty"`
	Crv string `json:"crv,omitempty"`
	Use string `json:"use,omitempty"`

	// Public Fields
	X *keyBytes `json:"x,omitempty"`
	Y *keyBytes `json:"y,omitempty"`
	N *keyBytes `json:"n,omitempty"`
	E *keyBytes `json:"e,omitempty"`

	// Private Fields
	D *keyBytes `json:"d,omitempty"`
	P *keyBytes `json:"p,omitempty"`
	Q *keyBytes `json:"q,omitempty"`

	// Symmetric Keys
	K *keyBytes `json:"k,omitempty"`
}
