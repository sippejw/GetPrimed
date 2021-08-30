package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
)

type RSA struct {
	p  *big.Int
	q  *big.Int
	n  *big.Int
	e  *big.Int
	d  *big.Int
	dp *big.Int
	dq *big.Int
	iq *big.Int
}

type Primes struct {
	P *big.Int
	Q *big.Int
}

type PublicKey struct {
	e *big.Int
	n *big.Int
}

type PrivateKey struct {
	d *big.Int
	n *big.Int
}

// Generate Create an RSA struct given precomputed values for p, q, n, e, and d.
func Generate() RSA {
	// Calculate and store values to be used in signature
	// A common optimization that increases setup time but reduces time to sign a message.
	// Storing these values on the disk opens the possibility to a potential error in dp or dq.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Cannot generate RSA key\n")
		os.Exit(1)
	}
	return RSA{p: key.Primes[0], q: key.Primes[1], n: key.N, e: big.NewInt(int64(key.E)), d: key.D, dp: key.Precomputed.Dp, dq: key.Precomputed.Dq, iq: key.Precomputed.Qinv}
}

// Verify Returns the expected value for the message to be verified.
func (key PublicKey) Verify(m, s *big.Int) bool {
	hashedM := hashM(m)
	result := new(big.Int).Exp(s, key.e, key.n)
	return result.Cmp(hashedM) == 0
}

// Sign Returns the signed value of the provided message.
func (keys RSA) Sign(m *big.Int) *big.Int {
	hashedM := hashM(m)
	sp := new(big.Int).Exp(hashedM, keys.dp, keys.p)
	sq := new(big.Int).Exp(hashedM, keys.dq, keys.q)
	result := new(big.Int).Sub(sp, sq)
	result.Mul(keys.iq, result)
	result.Mod(result, keys.p)
	result.Mul(keys.q, result)
	result.Add(sq, result)
	return result
}

// BadSign Returns an invalid signature of the provided message. Specifically for a value of dp' or dq'.
func (keys RSA) BadSign(m *big.Int) *big.Int {
	// Introduce an error to dp ultimately creating S'
	// GoLang pointers are hard to play with, so we just add 1.
	faultyDP := keys.dp
	faultyDP.Add(faultyDP, big.NewInt(1))

	// Everything else is calculated like normal except the introduction of dp'.
	hashedM := hashM(m)
	sp := new(big.Int).Exp(hashedM, faultyDP, keys.p)
	sq := new(big.Int).Exp(hashedM, keys.dq, keys.q)
	result := new(big.Int).Sub(sp, sq)
	result.Mul(keys.iq, result)
	result.Mod(result, keys.p)
	result.Mul(keys.q, result)
	result.Add(sq, result)
	return result
}

// DerivePrime Returns the calculated prime from the provided message and invalid signature.
func (key PublicKey) DerivePrime(m, s *big.Int) *big.Int {
	result := new(big.Int).Exp(s, key.e, nil)
	hashedM := hashM(m)
	result.Sub(hashedM, result)
	result.Mod(result, key.n)
	result.GCD(nil, nil, result, key.n)
	return result
}

// GetPublicKey Returns a PublicKey generated from the values of an RSA struct.
func (keys RSA) GetPublicKey() PublicKey {
	return PublicKey{e: keys.e, n: keys.n}
}

// GetPrivateKey Returns a PrivateKey generated from the values of an RSA struct.
func (keys RSA) GetPrivateKey() PrivateKey {
	return PrivateKey{d: keys.d, n: keys.n}
}

// GetPrimes Returns a Primes struct generated from the p and q values of an RSA struct.
func (keys RSA) GetPrimes() Primes {
	return Primes{P: keys.p, Q: keys.q}
}

// hashM Returns a sha256 hashed big.Int of the given message.
func hashM(m *big.Int) *big.Int {
	hashedM := sha256.New()
	_, err := hashedM.Write(m.Bytes())
	if err != nil {
		fmt.Printf("Cannot hash message\n")
		os.Exit(1)
	}
	return new(big.Int).SetBytes(hashedM.Sum(nil))
}
