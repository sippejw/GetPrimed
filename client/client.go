package client

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
)

func Client(serverStatus chan int) {
	for serverReady := <-serverStatus; serverReady == 0; {
	}
	servAddr := flag.String("servAddr", "localhost:4000", "HTTPS server address")
	certFile := flag.String("certFile", "cert.pem", "CA certificated")
	flag.Parse()

	cert, err := os.ReadFile(*certFile)
	if err != nil {
		fmt.Printf("Error reading certificate from file: %v", err)
		os.Exit(1)
	}
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(cert); !ok {
		fmt.Printf("Unable to parse cert from %s", *certFile)
		os.Exit(1)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
	}

	r, err := client.Get("https://" + *servAddr)
	if err != nil {
		fmt.Printf("Error accessing %s: %v", *servAddr, err)
		os.Exit(1)
	}
	defer r.Body.Close()

	html, err := io.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("Error reading HTML: %v", err)
		os.Exit(1)
	}
	fmt.Printf("%v\n", r.Status)
	fmt.Print(string(html))
}
