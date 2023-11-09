import ecc.*
import Secp256k1.*
import cats.effect.*
import cats.effect.std.*
import cats.syntax.all.*
import cats.effect.unsafe.implicits.global
import scodec.bits.*

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
  test("encode/decode to/from bytes") {
    Random.scalaUtilRandom[IO].toResource.use {
      case given Random[IO] => for {
        _ <- (for {
          k <- Z_n.rand
          pointP <- IO(k*G)
          kBytes = k.bytes
          pointPbytes = pointP.bytes
          pointPprime = Point.fromValidHex(pointPbytes.toHex)
          kPrime = Z_n.fromValidHex(kBytes.toHex)
          _ <- IO(assertEquals(kPrime,k))
          _ <- IO(assertEquals(pointP,pointPprime))
        } yield ()).replicateA_(10)
      } yield ()
    }.unsafeRunSync()
  }
  
  test("coerceToPoint") {
    // a point with unkown dlog is H = (x,y) = (sha256(G),y) where G is
    // given in uncompressed form
    val H = Secp256k1.coerceToPoint(ByteVector.fromValidHex("04") ++ G.bytes)
    // check x-coordinate manually
    assert(H.x.bytes == ByteVector.fromValidHex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"))
    assert(H.isValid) // check x and y coordinates are on the curve
  }
}