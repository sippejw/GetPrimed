package main

import (
	"RSA-CRT-Fault/rsa"
	"math/big"
	"testing"
)

func BenchmarkSign(b *testing.B) {
	p := big.NewInt(73013)
	q := big.NewInt(85223)
	n := big.NewInt(6222386899)
	e := big.NewInt(1473)
	d := big.NewInt(71811193)
	keys := rsa.Generate(p, q, n, e, d)
	privateKey := keys.GetPrivateKey()
	m := big.NewInt(32)

	for n := 0; n < b.N; n++ {
		privateKey.Sign(m)
	}
}

func BenchmarkSignCRT(b *testing.B) {
	p := big.NewInt(1802519)
	q := big.NewInt(1796677)
	n := big.NewInt(3238544429363)
	e := big.NewInt(1117)
	d := big.NewInt(28993203493)
	keys := rsa.Generate(p, q, n, e, d)
	m := big.NewInt(32)

	for n := 0; n < b.N; n++ {
		keys.SignCRT(m)
	}
}
