package rsa

import (
	"fmt"
)

type RSA struct {
	p       int64
	q       int64
	n       int64
	totient int64
	e       int64
	d       int64
}

type PublicKey struct {
	e int64
	n int64
}

type PrivateKey struct {
	d int64
	n int64
}

func Generate() RSA {
	var p, q int64

	fmt.Print("Enter a value for p: ")
	fmt.Scanln(&p)

	fmt.Print("Enter a value for q: ")
	fmt.Scanln(&q)

	keys := RSA{p: p, q: q, n: p * q}
	keys.generateTotient()
	keys.generateE()
	keys.generateD()

	return keys

}

func (key PublicKey) Encrypt() {

}

func (key PrivateKey) Decrypt() {

}

func (key PrivateKey) Sign() {

}

func (key PublicKey) Verify() {

}

func (keys RSA) GetPublicKey() PublicKey {
	return PublicKey{e: keys.e, n: keys.n}
}

func (keys RSA) GetPrivateKey() PrivateKey {
	return PrivateKey{d: keys.d, n: keys.n}
}

func (keys *RSA) generateTotient() {
	keys.totient = (keys.p-1) * (keys.q-1)
}

func (keys *RSA) generateE() {
	options := primeGenerator(keys.totient)
	var e int64
	fmt.Printf("%v\n", options)
	fmt.Print("Please select one of the above values: ")
	fmt.Scanln(&e)
	keys.e = e
}

func (keys *RSA) generateD() {
	var options []int64
	var i int64
	for i = 0;
}

// GCD function modified for int64 from
// https://play.golang.org/p/SmzvkDjYlb
func gcd(a, b int64) int64 {
	for b != 0 {
		t := b
		b = a % b
		a = t
	}
	return a
}

// LCM function modified for int64 from
// https://play.golang.org/p/SmzvkDjYlb
func lcm(a, b int64) int64 {
	result := a * b / gcd(a, b)
	return result
}

func primeGenerator(a int64) []int64 {
	var i int64
	var result []int64
	for i = 0; i < a; i++ {
		if gcd(a, i) == 1 {
			result = append(result, i)
		}
	}
	return result
}