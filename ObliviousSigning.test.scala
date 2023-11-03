import ecc.*
import Secp256k1.*
import cats.effect.*
import cats.effect.std.*
import cats.syntax.all.*
import cats.effect.unsafe.implicits.global
import scodec.bits.*
import bips.Bip340.*

class ObliviousSigning extends munit.FunSuite {
  // taken mostly from: https://telaviv2019.scalingbitcoin.org/files/scriptless-lotteries-on-bitcoin-from-oblivious-transfer.pdf
  /** Alice and Bob agree on 2 messages, m0 and m1.
   *  Alice obliviously signs both, but Bob can only complete the signature
   *  for one of them. Alice does not learn which one. 
   * */
  test("Oblivious Signing - one of two") {
    // Sender and Receiver agree on a second generator point H 
    // with unknown discrete log relative to G
    // (note: here we just cheat and act like we do not know it)
    val pointH = Z_n(1234567)*G

    // Sender and Receiver also agree on two messages, m0 and m1
    // Only one of these messages will ultimately be signed. Only the
    // Receiver will know which was signed.
    val m0 = ByteVector("message 0".getBytes)
    val m1 = ByteVector("message 1".getBytes)

    // Receiver chooses a private key
    val priv_receiver = Z_n(83838383)

    /*****************************************************************
     * Interlude -- building some helper functions **/

    // simple Pederson bit commitment
    def commit(bit: Boolean, privateKey: Z_n): Point = bit match {
      case false => privateKey*G
      case true => privateKey*G + pointH
    }

    /** end of Interlude -- done building helper functions, back to our protocol now
     * **************************************************************************************/

    // say Receiver wants to commit to b = 1
    val b = true

    // Receiver calculates and sends T to Sender (it is a simple Pedersen commitment)
    val pointT = commit(b,priv_receiver)

    // (ideally) Receiver also sends to Sender a proof that Receiver knows `b` 
    // and `priv_receiver` such that T = priv_receiver*G + b*H
    // Such a proof is basically a slightly more generalied schnorr signature
    // and we skip that here. In this case of oblivious signing, the Sender
    // may not actually care either.

    // Sender has a private key of its own
    val priv_sender = Z_n(727272727)
    val pub_sender = priv_sender * G

    // Sender creates adaptor sig for message m0 using adaptor point T
    val (s0, pointR0, pointT0) = adaptSign(priv_sender, message = m0, nonce = Z_n(1111), adaptorPoint = pointT)
    
    // Sender creates adaptor sig for message m1 using adaptor point (T - H)
    val (s1, pointR1, pointT1) = adaptSign(priv_sender, message = m1, nonce = Z_n(3333), adaptorPoint = pointT - pointH)

    // Sender sends both of the above adaptor signatures to Receiver
    // Receiver can try to complete both of them, but only the one
    // for the message matching Receivers choice of b will be valid.

    // check b = 0 case
    val (sPrime0, pointRprime0) = completeAdaptorSignature(s0,pointR0,pointT0, dlogAdaptorPoint = priv_receiver)
    assertEquals(verifySignature(sPrime0,pointRprime0,message = m0, publicKey = pub_sender), false)
    // ^^^^^^ if the above assertion passes, it means that Receiver could *not* verify Sender's sig for m0 ^^^^^^^^^

    // check b = 1 case
    val (sPrime1, pointRprime1) = completeAdaptorSignature(s1,pointR1,pointT1, dlogAdaptorPoint = priv_receiver)
    assertEquals(verifySignature(sPrime1,pointRprime1,message = m1, publicKey = pub_sender), true)
    // ^^^^^^ if above assertion passes, it means Receiver successfily verified Sender's sig for m1 ^^^^^^^^^^^
  }
}