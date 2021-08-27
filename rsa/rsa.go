package rsa

import (
	"math/big"
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

type PublicKey struct {
	e *big.Int
	n *big.Int
}

type PrivateKey struct {
	d *big.Int
	n *big.Int
}

// Generate Create an RSA struct given precomputed values for p, q, n, e, and d.
func Generate(p, q, n, e, d *big.Int) RSA {
	// Calculate and store values to be used in signature
	// A common optimization that increases setup time but reduces time to sign a message.
	// Storing these values on the disk opens the possibility to a potential error in dp or dq.
	dp := new(big.Int).ModInverse(e, new(big.Int).Sub(p, big.NewInt(1)))
	dq := new(big.Int).ModInverse(e, new(big.Int).Sub(q, big.NewInt(1)))
	iq := new(big.Int).ModInverse(q, p)
	return RSA{p: p, q: q, n: n, e: e, d: d, dp: dp, dq: dq, iq: iq}
}

// Verify Returns the expected value for the message to be verified.
func (key PublicKey) Verify(s *big.Int) *big.Int {
	return new(big.Int).Exp(s, key.e, key.n)
}

// Sign Returns the signed value of the provided message.
func (keys RSA) Sign(m *big.Int) *big.Int {
	sp := new(big.Int).Exp(m, keys.dp, keys.p)
	sq := new(big.Int).Exp(m, keys.dq, keys.q)
	result := new(big.Int).Sub(sp, sq)
	result.Mul(keys.iq, result)
	result.Mod(result, keys.p)
	result.Mul(keys.q, result)
	result.Add(sq, result)
	return result
}

// FaultySign Returns a faulty signature of the provided message. Specifically for a value of dp' or dq'.
func (keys RSA) FaultySign(m *big.Int) *big.Int {
	// Introduce an error to dp ultimately creating S'
	// GoLang pointers are hard to play with, so we just add 1.
	faultyDP := keys.dp
	faultyDP.Add(faultyDP, big.NewInt(1))

	// Everything else is calculated like normal except the introduction of dp'.
	sp := new(big.Int).Exp(m, faultyDP, keys.p)
	sq := new(big.Int).Exp(m, keys.dq, keys.q)
	result := new(big.Int).Sub(sp, sq)
	result.Mul(keys.iq, result)
	result.Mod(result, keys.p)
	result.Mul(keys.q, result)
	result.Add(sq, result)
	return result
}

// DerivePrivateExponent Returns the calculated exponent from the provided message and faulty signature.
func (key PublicKey) DerivePrivateExponent(m, s *big.Int) *big.Int {
	result := new(big.Int).Exp(s, key.e, nil)
	result.Sub(m, result)
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
