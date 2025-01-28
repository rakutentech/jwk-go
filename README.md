# jwk-go [![GoDoc](https://godoc.org/github.com/rakutentech/jwk-go?status.svg)](https://godoc.org/github.com/rakutentech/jwk-go) [![Build Status](https://github.com/rakutentech/jwk-go/actions/workflows/pull-request.yml/badge.svg)](https://github.com/rakutentech/jwk-go/actions/workflows/pull-request.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/rakutentech/jwk-go)](https://goreportcard.com/report/github.com/rakutentech/jwk-go)

## Overview

jwk-go is a library for parsing, encoding and generating JSON Web Keys in Go.
It supports the following key types:
* Raw Octets ('oct'): Used by most symmetric algorithms.
* RSA: Used for both signature and encryption
* EC: Used for both signature (ECDSA) and key exchange (ECDH) with the
    following curves:
  * P-256
  * P-384
  * P-521
* OKP: OctetKeyPair with the following curves:
  * Curve25519
  * Curve448
  * Ed25519
  * Ed448

