package custom_rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
)

// Generate Create an RSA struct given precomputed values for p, q, n, e, and d.
func Generate() *rsa.PrivateKey {
	// Calculate and store values to be used in signature
	// A common optimization that increases setup time but reduces time to sign a message.
	// Storing these values on the disk opens the possibility to a potential error in dp or dq.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Cannot generate RSA key\n")
		os.Exit(1)
	}
	return key
}

// Verify Returns the expected value for the message to be verified.
func Verify(key *rsa.PublicKey, m, s *big.Int) bool {
	hashedM := hashM(m)
	result := new(big.Int).Exp(s, big.NewInt(int64(key.E)), key.N)
	return result.Cmp(hashedM) == 0
}

// Sign Returns the signed value of the provided message.
func Sign(keys *rsa.PrivateKey, m *big.Int) *big.Int {
	hashedM := hashM(m)
	sp := new(big.Int).Exp(hashedM, keys.Precomputed.Dp, keys.Primes[0])
	sq := new(big.Int).Exp(hashedM, keys.Precomputed.Dq, keys.Primes[1])
	result := new(big.Int).Sub(sp, sq)
	result.Mul(keys.Precomputed.Qinv, result)
	result.Mod(result, keys.Primes[0])
	result.Mul(keys.Primes[1], result)
	result.Add(sq, result)
	return result
}

// BadSign Returns an invalid signature of the provided message. Specifically for a value of dp' or dq'.
func BadSign(keys *rsa.PrivateKey, m *big.Int) *big.Int {
	// Introduce an error to dp ultimately creating S'
	// GoLang pointers are hard to play with, so we just add 1.
	faultyDP := keys.Precomputed.Dp
	faultyDP.Add(faultyDP, big.NewInt(1))

	// Everything else is calculated like normal except the introduction of dp'.
	hashedM := hashM(m)
	sp := new(big.Int).Exp(hashedM, faultyDP, keys.Primes[0])
	sq := new(big.Int).Exp(hashedM, keys.Precomputed.Dq, keys.Primes[1])
	result := new(big.Int).Sub(sp, sq)
	result.Mul(keys.Precomputed.Qinv, result)
	result.Mod(result, keys.Primes[0])
	result.Mul(keys.Primes[1], result)
	result.Add(sq, result)
	return result
}

// DerivePrime Returns the calculated prime from the provided message and invalid signature.
func DerivePrime(key *rsa.PublicKey, m, s *big.Int) *big.Int {
	result := new(big.Int).Exp(s, big.NewInt(int64(key.E)), nil)
	result.Sub(m, result)
	result.Mod(result, key.N)
	result.GCD(nil, nil, result, key.N)
	return result
}

// GetPublicKey Returns a PublicKey generated from the values of an RSA struct.
func GetPublicKey(keys *rsa.PrivateKey) *rsa.PublicKey {
	return &keys.PublicKey
}

// GetPrimes Returns a Primes struct generated from the p and q values of an RSA struct.
func GetPrimes(keys *rsa.PrivateKey) [2]*big.Int {
	return [2]*big.Int{keys.Primes[0], keys.Primes[1]}
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
