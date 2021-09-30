package main

import (
	"GetPrimed/bad_rsa"
	"GetPrimed/client"
	"GetPrimed/custom_rsa"
	"GetPrimed/server"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
)

func main() {
	example := flag.Bool("example", false, "Generates an RSA key pair, creates an invalid signature, and derives one of the primes.")
	tls := flag.Bool("tls", false, "Runs a basic client and server tls handshake.")
	pathToPubKey := flag.String("pub", "", "Path to public key for -primed")
	pathToSig := flag.String("sig", "", "Path to signature for -primed")
	pathToMessage := flag.String("digest", "", "Path to hashed message for -primed")
	primed := flag.Bool("primed", false, "Expects a path to a public key, bad signature, and hashed message. Derives one of the primes for key pair.")
	flag.Parse()
	if *tls {
		serverClient()
	}
	if *example {
		exampleKeys()
	}
	if *primed {
		getPrimed(pathToPubKey, pathToSig, pathToMessage)
	}

}

func getPrimed(pathToPubKey *string, pathToSig *string, pathToMessage *string) {
	sigBytes, err := ioutil.ReadFile(*pathToSig)
	if err != nil {
		fmt.Println("Signature not found")
		os.Exit(1)
	}
	sig := new(big.Int)
	sig.SetBytes(sigBytes)

	messageBytes, err := ioutil.ReadFile(*pathToMessage)
	if err != nil {
		fmt.Println("Message not found")
		os.Exit(1)
	}
	message := new(big.Int)
	message.SetBytes(messageBytes)

	pub, err := ioutil.ReadFile(*pathToPubKey)
	if err != nil {
		fmt.Println("No RSA public key found")
		os.Exit(1)
	}
	pubPem, _ := pem.Decode(pub)

	if pubPem.Type != "PUBLIC KEY" {
		fmt.Printf("Please provide a public key. Provided: %v", pubPem.Type)
	}

	var parsedKey interface{}
	//PKCS1
	parsedKey, err = x509.ParsePKIXPublicKey(pubPem.Bytes)
	if err != nil {
		fmt.Println("Unable to parse key")
		os.Exit(1)
	}
	pubKey := parsedKey.(*rsa.PublicKey)
	publicKey := bad_rsa.BuildPubKey(pubKey.N, big.NewInt(int64(pubKey.E)))
	result := publicKey.DerivePrime(pubKey, sig, message)
	fmt.Printf("Prime: %x", result)
}

func serverClient() {
	serverStatus := make(chan int)
	go server.Server(serverStatus)
	client.Client(serverStatus)
}

func exampleKeys() {
	keys := custom_rsa.Generate()
	publicKey := custom_rsa.GetPublicKey(keys)
	primes := custom_rsa.GetPrimes(keys)
	m := big.NewInt(32)

	fmt.Println("Private Exponents:")
	fmt.Printf("p: %v\n", primes[0])
	fmt.Printf("q: %v\n\n", primes[1])

	fmt.Println("Signature generated with normal sign function:")
	signature := custom_rsa.Sign(keys, m)
	fmt.Printf("S: %v\n", signature)
	check := custom_rsa.Verify(publicKey, m, signature)
	fmt.Printf("Valid signature: %v\n\n", check)

	fmt.Println("Signature generated with bag sign function:")
	invalidSignature := custom_rsa.BadSign(keys, m)
	fmt.Printf("S': %v\n", invalidSignature)
	failedCheck := custom_rsa.Verify(publicKey, m, invalidSignature)
	fmt.Printf("Valid signature: %v\n\n", failedCheck)

	derivedPrime := custom_rsa.DerivePrime(publicKey, m, invalidSignature)
	fmt.Printf("Derived prime: %v\n", derivedPrime)
}
