# GetPrimed
A basic RSA signing tool to explore the possibility of deriving one of the primes from an RSA
keypair given an invalid signature. This tool can create a standard, 2048-bit RSA keypair and sign messages with one of 
two signing methods:
#### `Sign`
This method produces a normal signature of the given message using the CRT optimization.
#### `BadSign`
This method also produces a signature of the given message using the CRT optimization, but has a flaw in that one of the
two precomputed values (`dp`, `dq`) has been corrupted. This causes `BadSign` to produce an invalid signature that can be 
used to derive one of the primes from the keypair.
