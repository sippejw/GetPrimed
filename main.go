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

	keys := rsa.Generate(p, q, n, e, d)
	publicKey := keys.GetPublicKey()
	privateKey := keys.GetPrivateKey()

	c := publicKey.Encrypt(big.NewInt(32))
	fmt.Println(c)
	m := privateKey.Decrypt(c)
	fmt.Println(m)

	cipher := publicKey.Encrypt(big.NewInt(32))
	fmt.Println(cipher)
	message := keys.DecryptCRT(cipher)
	fmt.Println(message)

	s := privateKey.Sign(big.NewInt(32))
	fmt.Println(s)
	ci := publicKey.Verify(s)
	fmt.Println(ci)

	signature := keys.SignCRT(big.NewInt(32))
	fmt.Println(signature)
	check := publicKey.Verify(signature)
	fmt.Println(check)
}
