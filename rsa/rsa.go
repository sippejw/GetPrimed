package rsa

import (
	"math/big"
)

type RSA struct {
	p *big.Int
	q *big.Int
	n *big.Int
	e *big.Int
	d *big.Int
}

type PublicKey struct {
	e *big.Int
	n *big.Int
}

type PrivateKey struct {
	d *big.Int
	n *big.Int
}

func Generate(p, q, n, e, d *big.Int) RSA {
	return RSA{p: p, q: q, n: n, e: e, d: d}
}

func (key PublicKey) Encrypt(m *big.Int) *big.Int {
	return m.Exp(m, key.e, key.n)
}

func (key PublicKey) Verify(s *big.Int) *big.Int {
	return s.Exp(s, key.e, key.n)
}

func (key PrivateKey) Decrypt(c *big.Int) *big.Int {
	return c.Exp(c, key.d, key.n)
}

func (keys RSA) DecryptCRT(c *big.Int) *big.Int {
	sp := new(big.Int).Exp(c, new(big.Int).Mod(keys.d, new(big.Int).Sub(keys.p, big.NewInt(1))), keys.p)
	sq := new(big.Int).Exp(c, new(big.Int).Mod(keys.d, new(big.Int).Sub(keys.q, big.NewInt(1))), keys.q)
	qModInverse := new(big.Int).ModInverse(keys.q, keys.p)
	qModInverseModP := new(big.Int).Mod(qModInverse, keys.p)
	result := new(big.Int).Sub(sp, sq)
	result.Mul(result, qModInverseModP)
	result.Mul(result, keys.q)
	result.Add(sq, result)
	return result
}

func (key PrivateKey) Sign(m *big.Int) *big.Int {
	return m.Exp(m, key.d, key.n)
}

func (keys RSA) SignCRT(m *big.Int) *big.Int {
	sp := new(big.Int).Exp(m, new(big.Int).Mod(keys.d, new(big.Int).Sub(keys.p, big.NewInt(1))), keys.p)
	sq := new(big.Int).Exp(m, new(big.Int).Mod(keys.d, new(big.Int).Sub(keys.q, big.NewInt(1))), keys.q)
	qModInverse := new(big.Int).ModInverse(keys.q, keys.p)
	qModInverseModP := new(big.Int).Mod(qModInverse, keys.p)
	result := new(big.Int).Sub(sp, sq)
	result.Mul(result, qModInverseModP)
	result.Mul(result, keys.q)
	result.Add(sq, result)
	return result
}

func (keys RSA) GetPublicKey() PublicKey {
	return PublicKey{e: keys.e, n: keys.n}
}

func (keys RSA) GetPrivateKey() PrivateKey {
	return PrivateKey{d: keys.d, n: keys.n}
}
