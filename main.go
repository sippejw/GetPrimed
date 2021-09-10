package main

import (
	"GetPrimed/client"
	"GetPrimed/rsa"
	"GetPrimed/server"
	"fmt"
	"math/big"
)

func main() {
	serverStatus := make(chan int)
	go server.Server(serverStatus)
	client.Client(serverStatus)
}

func testKeys() {
	keys := rsa.Generate()
	publicKey := keys.GetPublicKey()
	primes := keys.GetPrimes()
	m := big.NewInt(32)

	fmt.Println("Private Exponents:")
	fmt.Printf("p: %v\n", primes.P)
	fmt.Printf("q: %v\n\n", primes.Q)

	fmt.Println("Signature generated with normal sign function:")
	signature := keys.Sign(m)
	fmt.Printf("S: %v\n", signature)
	check := publicKey.Verify(m, signature)
	fmt.Printf("Valid signature: %v\n\n", check)

	fmt.Println("Signature generated with bag sign function:")
	invalidSignature := keys.BadSign(m)
	fmt.Printf("S': %v\n", invalidSignature)
	failedCheck := publicKey.Verify(m, invalidSignature)
	fmt.Printf("Valid signature: %v\n\n", failedCheck)

	derivedPrime := publicKey.DerivePrime(m, invalidSignature)
	fmt.Printf("Derived prime: %v\n", derivedPrime)
}
