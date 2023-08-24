
//> using lib "org.scalameta::munit::0.7.29"

import Secp256k1.*

class Secp256k1Test extends munit.FunSuite {
  test("ECDH") {
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

    assertEquals(sharedSecretB,sharedSecretA)
  }
}