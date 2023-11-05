import ecc.*
import Secp256k1.*
import scodec.bits.*
import bips.Bip340.*
import scala.util.chaining.*
import scala.util.Try

class ObliviousSigning extends munit.FunSuite {
  // taken mostly from: https://telaviv2019.scalingbitcoin.org/files/scriptless-lotteries-on-bitcoin-from-oblivious-transfer.pdf
  /** Alice and Bob agree on 2 messages, m0 and m1.
   *  Alice obliviously signs both, but Bob can only complete the signature
   *  for one of them. Alice does not learn which one. 
   * */
  test("oblivious signing - one of two") {
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

  test("oblivious transfer - one of two") {
    /**
      * "Simplest Oblivious Transfer Protocol" by T. Chou and C. Orlandi
      * source: https://inst.eecs.berkeley.edu/~cs294-171/fa20/readings/ot.pdf
      * 
      * - Sender has two input messages m0 and m1.
      * - Receiver has a choice bit c.
      * - At the end of the protocol the Receiver is supposed to learn the message
      *   corresponding to its choice bit, and learn nothing else. 
      * - The Sender is supposed to learn nothing.
      * 
      * Perhaps suprisingly, this extremely simple primitive is sufficient to
      * implement any cryptographic task [Kil88].
      */

      // Sender (Alice) chooses private key `a`
      val a = Z_n(25252)
      // Sender calculates and sends public key `A`
      val A = a*G

      // Sender has two equal-length messages of length a multiple of 16
      val m0 = ByteVector("stand up!".getBytes).padRight(16)
      val m1 = ByteVector("sit down!".getBytes).padRight(16)

      // Receiver has private key `b`
      val b = Z_n(98989)

      // Receiver chooses bit `c` and commits to point B as follows
      def commit(c: Boolean): Point = c match {
        case false => b*G
        case true => A + b*G
      }

      // Say Receiver commits to c = 1
      val B = commit(c = true)

      // Receiver also calculates bytevector k_c = sha256(b*A)
      val k_c = (b*A).bytes.sha256

      // Sender calculates two symmetric keys k0,k1
      val k0 = (a*B).bytes.sha256
      val k1 = (a*(B - A)).bytes.sha256

      // Notice that one of k0 or k1 will equal k_c.
      assert((k_c == k0) || (k_c == k1) && (k1 != k0))
      // Therefore Receiver will be able to decrypt message streams which use
      // only one of the keys. One of two oblivious transfer!

      /** symmetric encryption/decryption scheme (AES) **/
      /*def encrypt(key: ByteVector, message: ByteVector): Try[ByteVector] =
        val cipher = javax.crypto.Cipher.getInstance("AES/CBC/NoPadding")
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(key.toArray.take(16),"AES"))
        Try(cipher.doFinal(message.toArray).pipe(ByteVector(_)))

      def decrypt(key: ByteVector, ciphertext: ByteVector): Try[ByteVector] = 
        val cipher = javax.crypto.Cipher.getInstance("AES/CBC/NoPadding")
        cipher.getParameters()
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, new javax.crypto.spec.SecretKeySpec(key.toArray.take(16),"AES"), cipher.getParameters())
        Try(cipher.doFinal(ciphertext.toArray).pipe(ByteVector(_)))

      // Sender encrypts both messages with respective keys
      // and sends both to Receiver
      val e0 = encrypt(k0,m0)
      val e1 = encrypt(k1,m1)
      */
      // Receiver can only decrypt one of the messages using k_c
  }
}