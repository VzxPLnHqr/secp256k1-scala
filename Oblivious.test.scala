import ecc.*
import Secp256k1.*
import scodec.bits.*
import bips.Bip340.*
import scala.util.chaining.*
import scala.util.Try

class ObliviousTest extends munit.FunSuite {

  test("oblivious signing - one of two sigs") {
  // taken mostly from: https://telaviv2019.scalingbitcoin.org/files/scriptless-lotteries-on-bitcoin-from-oblivious-transfer.pdf
  /** Alice and Bob agree on 2 messages, m0 and m1.
   *  Alice obliviously signs both, but Bob can only complete the signature
   *  for one of them. Alice does not learn which one. 
   * */

    // Sender and Receiver agree on a second generator point H 
    // with unknown discrete log relative to G
    val H = Secp256k1.coerceToPoint(G.bytes)

    // Sender and Receiver also agree on two messages, m0 and m1
    // Only one of these messages will ultimately be signed. Only the
    // Receiver will know which was signed.
    val m0 = ByteVector("message 0".getBytes)
    val m1 = ByteVector("message 1".getBytes)

    // Receiver chooses a private key
    val b = Z_n(83838383)

    /*****************************************************************
     * Interlude -- building some helper functions **/

    // simple Pederson bit commitment
    def commit(choiceBit: Boolean, privateKey: Z_n): Point = choiceBit match {
      case false => privateKey*G
      case true => privateKey*G + H
    }

    /** end of Interlude -- done building helper functions, back to our protocol now
     * **************************************************************************************/

    // say Receiver wants to commit to c = 1 (choiceBit = true)
    // Receiver calculates and sends T to Sender (it is a simple Pedersen commitment)
    val T = commit(choiceBit = true, privateKey = b)

    // (ideally) Receiver also sends to Sender a proof that Receiver knows `c` 
    // and `b` such that T = b*G + c*H
    // Such a proof is basically a slightly more generalied schnorr signature
    // and we skip that here. In this case of oblivious signing, the Sender
    // may not actually care either.

    // Sender has a private key of its own
    val a = Z_n(727272727)
    val A = a * G

    // Sender creates adaptor sig for message m0 using adaptor point T
    val (s0, pointR0, pointT0) = adaptSign(privateKey = a, message = m0, nonce = Z_n(1111), adaptorPoint = T)
    
    // Sender creates adaptor sig for message m1 using adaptor point (T - H)
    val (s1, pointR1, pointT1) = adaptSign(privateKey = a, message = m1, nonce = Z_n(3333), adaptorPoint = T - H)

    // Sender sends both of the above adaptor signatures to Receiver
    // Receiver can try to complete both of them, but only the one
    // for the message matching Receivers choice of b will be valid.

    // check b = 0 case
    val (sPrime0, pointRprime0) = completeAdaptorSignature(s0,pointR0,pointT0, dlogAdaptorPoint = b)
    assertEquals(verifySignature(sPrime0,pointRprime0,message = m0, publicKey = A), false)
    // ^^^^^^ if the above assertion passes, it means that Receiver could *not* verify Sender's sig for m0 ^^^^^^^^^

    // check b = 1 case
    val (sPrime1, pointRprime1) = completeAdaptorSignature(s1,pointR1,pointT1, dlogAdaptorPoint = b)
    assertEquals(verifySignature(sPrime1,pointRprime1,message = m1, publicKey = A), true)
    // ^^^^^^ if above assertion passes, it means Receiver successfily verified Sender's sig for m1 ^^^^^^^^^^^
  }

  test("oblivious signing - 1 of n sigs") {
    // Generalizing the 1 of 2 case (see above) to 1 of n

    // Sender and Receiver agree on a second generator point H 
    // with unknown discrete log relative to G
    val H = Secp256k1.coerceToPoint(G.bytes)

    // Let n be the number of messages. Only one of them will end up with a
    // valid signature from Alice (Sender)
    val n = 10
    
    // Sender constructs `n` messages
    def m(index: Int): ByteVector = ByteVector(s"message $index".getBytes)

    // Sender sends list of all possible messages to Receiver
    val messages = List.range(0,n).map(m(_))

    // Receiver will choose `c` which is one of {0,1,2,...,n}
    // Receiver chooses a blinding factor `b` to hide choice `c`
    val b = Z_n(83838383)

    def commit(choice: Int, blindingFactor: Z_n): Point = choice match {
      case 0 => b*G
      case c => b*G + Z_n(c)*H
    }

    // Say Receiver commits to c = 7
    // Receiver calculates and sends point T
    val T = commit(choice = 7, blindingFactor = b)

    // Sender has a private key of its own
    val a = Z_n(727272727)
    val A = a * G

    // Sender calculates all possible adaptor points
    val adaptorPoints = List.range(0,n).map(Z_n(_)).map(c => T - c*H)

    // Sender prepares a PRNG so it can shuffle the list of messages.
    val PRNG = scala.util.Random(seed = 72324)

    // Sender creates and sends adaptor signatures
    // Notice how Sender shuffles the messages before signing!
    val adaptorSigs = PRNG.shuffle(messages).zip(adaptorPoints).zipWithIndex.map{
      case ((message,adaptorPoint), index) => 
        val nonce = ByteVector(s"super secure nonce $index".getBytes).sha256.pipe(Z_n.fromBytes)
        adaptSign(privateKey = a, message = message, nonce = nonce, adaptorPoint = adaptorPoint)
    }

    // Receiver tries to complete each adaptor signature. Only one such completion
    // will be a valid schnorr signature.
    val possibleSigs = adaptorSigs.map{
      case (s,pointR,pointT) => completeAdaptorSignature(s,pointR,pointT,dlogAdaptorPoint = b)
    }

    // check each "completed" signature for validity by checking each possible message
    // the number of checked sigs will be n^2 where n is the number of possible messages
    val verifiedSigs = possibleSigs.flatMap {
      case (s,pointR) => messages.map(msg => verifySignature(s,pointR,msg,publicKey = A))
    }

    assert(verifiedSigs.size == n*n)
    assert(verifiedSigs.filter(_ == true).size == 1)   
    // if the above assertion passed, then Receiver now has possession of a
    // single valid shnorr signature for a single one of the possible messages.
    // Due to Sender shuffling the list of messages before signing, the Receiver
    // was unable to predict ahead of time which message it will receive.
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

      // Sender has two messages.
      val m0 = ByteVector("stand up!".getBytes)
      val m1 = ByteVector("sit down!".getBytes)

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
      def encrypt(key: ByteVector, message: ByteVector): Try[ByteVector] =
        val cipher = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(key.toArray.take(16),"AES"))
        Try(cipher.doFinal(message.toArray).pipe(ByteVector(_)))

      def decrypt(key: ByteVector, ciphertext: ByteVector): Try[ByteVector] = 
        val cipher = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.getParameters()
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, new javax.crypto.spec.SecretKeySpec(key.toArray.take(16),"AES"))
        Try(cipher.doFinal(ciphertext.toArray).pipe(ByteVector(_)))

      // Sender encrypts both messages with respective keys
      // and sends both to Receiver
      val e0 = encrypt(k0,m0)
      val e1 = encrypt(k1,m1)
      
      // Receiver can only decrypt one of the messages using k_c
      assert(e0.flatMap(decrypt(k_c,_)).isFailure) // as expected!
      assert(e1.flatMap(decrypt(k_c,_)).map(_ == m1).isSuccess)
  }
}