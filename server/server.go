package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"time"
)

// Create a self signed certificate and RSA keypair for TLS connection
// Adapted from: https://eli.thegreenplace.net/2021/go-https-servers-with-tls/
func generateKeyAndCert() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Failed to generate RSA key: %V", err)
		os.Exit(1)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		fmt.Printf("Failed to generate certificate serial number: %v", err)
		os.Exit(1)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Get Primed Inc."},
		},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		fmt.Printf("Failed to create certificate: %v", err)
		os.Exit(1)
	}

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if pemCert == nil {
		fmt.Println("Failed to encode certificate")
		os.Exit(1)
	}
	if err := os.WriteFile("cert.pem", pemCert, 0644); err != nil {
		fmt.Printf("Failed to write certificate to file: %v", err)
		os.Exit(1)
	}
	fmt.Println("Created cert.pem")

	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		fmt.Printf("Unable to marshal key: %v", err)
	}

	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if pemKey == nil {
		fmt.Println("Failed to encode key")
	}
	if err := os.WriteFile("key.pem", pemKey, 0600); err != nil {
		fmt.Printf("Failed to write key to file: %v", err)
	}
	fmt.Println("Created key.pem")
}

// Create HTTPS server using TLS 1.2
// Adapted from: https://eli.thegreenplace.net/2021/go-https-servers-with-tls/
func Server(serverStatus chan int) {

	addr := flag.String("addr", "localhost:4000", "HTTPS network address")
	certFile := flag.String("certfile", "cert.pem", "certificate PEM file")
	keyFile := flag.String("keyfile", "key.pem", "key PEM file")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			http.NotFound(w, req)
			return
		}
		fmt.Fprintf(w, "Go Server")
	})

	srv := &http.Server{
		Addr:    *addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			// TLS 1.3 no longer uses RSA for key exchange.
			// Therefore our max version must be TLS 1.2
			MaxVersion: tls.VersionTLS12,
			// For now we only use one cipher spec to make signature recreation
			// simpler.
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		},
	}

	fmt.Printf("Starting a server on %s\n", *addr)
	serverStatus <- 1
	err := srv.ListenAndServeTLS(*certFile, *keyFile)
	fmt.Printf("Server error: %v", err)
}
