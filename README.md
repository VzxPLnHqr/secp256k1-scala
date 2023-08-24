## secp256k1-scala

An ~~(almost)~~ dependency-free scala implementation of ecc arithmetic for the
curve used by bitcoin (secp256k1).

### Usage
1. install `scala-cli` (if using [Nix](https://nixos.org) this is as easy as `nix-shell -p scala-cli`)
2. `scala-cli repl .`

```scala
import Secp256k1.*

// demonstrating ECDH whereby Alice and Bob calculate a shared secret

// a very secure private key chosen by Alice
// private keys are values in prime field Z_n
val a = Z_n(12345)

val pointA = a * G

// also a great choice of private key by Bob
val b = Z_n(54321)

val pointB = b * G

val sharedSecretB = b * pointA
val sharedSecretA = a * pointB

assert(sharedSecretB == sharedSecretA)

```

3. or you can run the tests: `scala-cli test .`

### Disclaimer - do not use with real funds

This implementation is for learning purposes. 
Use [bitcoin-core/secp256k1](/bitcoin-core/secp256k1) for any real-world needs.