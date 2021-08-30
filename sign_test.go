package main

import (
	"RSA-CRT-Fault/rsa"
	"math/big"
	"testing"
)

func BenchmarkSign(b *testing.B) {
	keys := rsa.Generate()
	m := big.NewInt(32)

	for n := 0; n < b.N; n++ {
		keys.Sign(m)
	}
}

func BenchmarkDerivePrime(b *testing.B) {
	keys := rsa.Generate()
	publicKey := keys.GetPublicKey()
	m := big.NewInt(32)
	s := keys.BadSign(m)
	for n := 0; n < b.N; n++ {
		publicKey.DerivePrime(m, s)
	}
}
