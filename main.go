package main

import (
	"RSA-CRT-Fault/rsa"
	"fmt"
)

func main() {
	keys := rsa.Generate()
	fmt.Printf("%+v\n", keys)
}
