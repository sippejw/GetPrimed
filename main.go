package main

import (
	"RSA-CRT-Fault/rsa"
	"fmt"
	"math/big"
)

func main() {
	keys := rsa.Generate()
	publicKey := keys.GetPublicKey()
	primes := keys.GetPrimes()
	m := big.NewInt(32)

	fmt.Println("Private Exponents:")
	fmt.Printf("p: %v\n", primes.P)
	fmt.Printf("q: %v\n\n", primes.Q)

	signature := keys.Sign(m)
	fmt.Printf("S: %v\n", signature)
	check := publicKey.Verify(m, signature)
	fmt.Printf("Valid signature: %v\n\n", check)

	faultySignature := keys.FaultySign(m)
	fmt.Printf("S': %v\n", faultySignature)
	failedCheck := publicKey.Verify(m, faultySignature)
	fmt.Printf("Valid signature: %v\n\n", failedCheck)
	privateExponent := publicKey.DerivePrivateExponent(m, faultySignature)
	fmt.Printf("Derived private exponent: %v\n", privateExponent)
}
