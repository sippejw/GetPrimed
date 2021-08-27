package main

import (
	"RSA-CRT-Fault/rsa"
	"fmt"
	"math/big"
)

func main() {
	p := big.NewInt(1802519)
	q := big.NewInt(1796677)
	n := big.NewInt(3238544429363)
	e := big.NewInt(1117)
	d := big.NewInt(28993203493)
	m := big.NewInt(32)
	keys := rsa.Generate(p, q, n, e, d)
	publicKey := keys.GetPublicKey()
	fmt.Println("Important Values")
	fmt.Printf("p: %v\n", p)
	fmt.Printf("q: %v\n", q)
	fmt.Printf("N: %v\n", n)
	fmt.Printf("e: %v\n", e)
	fmt.Printf("d: %v\n", d)
	fmt.Printf("m: %v\n\n", m)

	signature := keys.Sign(m)
	fmt.Printf("S: %v\n", signature)
	check := publicKey.Verify(signature)
	fmt.Printf("Verified m: %v\n\n", check)

	faultySignature := keys.FaultySign(m)
	fmt.Printf("S': %v\n", faultySignature)
	failedCheck := publicKey.Verify(faultySignature)
	fmt.Printf("Invalid m: %v\n\n", failedCheck)
	privateExponent := publicKey.DerivePrivateExponent(m, faultySignature)
	fmt.Printf("Derived private exponent: %v\n", privateExponent)
}
