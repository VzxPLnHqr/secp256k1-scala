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

  test("schnorr deterministic signing") {
    // from https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
    // only the first test vector done here for now
    val sk = Z_n(3)
    assertEquals((sk*G).x.bytes, ByteVector.fromValidHex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"))
    val msg = ByteVector.fromValidHex("0000000000000000000000000000000000000000000000000000000000000000")
    val (s,pointR) = signDeterministic(sk,msg)
    assertEquals(verifySignature(s,pointR,msg,sk*G),true)
    val sig = ByteVector.fromValidHex("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")
    assertEquals(pointR.x.bytes, sig.take(32))
    assertEquals(s.bytes, sig.drop(32))
  }
}