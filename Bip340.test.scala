import ecc.*
import Secp256k1.*
import scodec.bits.*
import bips.Bip340.*

class Bip340Test extends munit.FunSuite {

  test("schnorr sig") {
    // schnorr sig test (just to check the above defined functions work)
    val priv_receiver = Z_n(77777)
    val (s,pointR) = sign(priv_receiver, message = ByteVector(1), nonce = Z_n(5555))
    assertEquals(verifySignature(s,pointR, message = ByteVector(1), publicKey = priv_receiver*G),true)
  }

  test("schnorr adaptor sig") {
    // adaptor sig test (just to check the above defined functions work)
    val priv_receiver = Z_n(77777)
    val (s,noncePoint,adaptorPoint) = adaptSign(priv_receiver, message = ByteVector(1), nonce = Z_n(5555), adaptorPoint = Z_n(4444)*G)
    assertEquals(verifyAdaptorSignature(s,message = ByteVector(1),noncePoint,adaptorPoint, publicKey = priv_receiver*G), true)
    // now complete the adaptor sig to get a valid full sig
    val (sPrime, pointRprime) = completeAdaptorSignature(s,noncePoint,adaptorPoint, dlogAdaptorPoint = Z_n(4444))
    assertEquals(verifySignature(sPrime,pointRprime, message = ByteVector(1), publicKey = priv_receiver*G), true)
  }
}