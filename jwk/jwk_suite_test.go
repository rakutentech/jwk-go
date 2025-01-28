package jwk_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestJwk(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Jwk Suite")
}
