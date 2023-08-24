## secp256k1-scala

An ~~(almost)~~ dependency-free scala implementation of ecc arithmetic for the
curve used by bitcoin (secp256k1).

### Usage
1. install `scala-cli` (if using [Nix](https://nixos.org) this is as easy as `nix-shell -p scala-cli`)
2. `scala-cli repl .`

```scala
import Secp256k1.*

// a very secure private key (scalar value in prime field Z_n)
val k = Z_n(12345)

// generator point for secp256k1
val G = Point.G

val point = k.multByPoint(G)

```

### Disclaimer - do not use with real funds

This implementation is for learning purposes. 
Use [bitcoin-core/secp256k1](/bitcoin-core/secp256k1) for any real-world needs.