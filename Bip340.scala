package bips

import ecc.*
import Secp256k1.*
import scodec.bits.*
import scala.util.chaining.*

/**
  * Note: this is not really a "compliant" implementation of Bip340
  * @see https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
  */
object Bip340:
  /** the "challenge" used when constructing schnoor sigs. Sometimes this
  * is called "e". Schnorr signature s = k + e*d where e is the challenge,
  * and k is the dlog of the nonce point R. The final signature is (s,R).
  */
  def challenge(bytes: ByteVector): Z_n = 
    taggedHash("BIP0340/challenge",bytes).pipe(Z_n.fromBytes)
  
  /**
    * Calculate schnorr signature.
    * Note: This method allows caller to specify the `nonce`. It is recommended
    * to use `signDeterministic` whenever possible as nonce reuse will leak the
    * private key.
    *
    * @param privateKey
    * @param message
    * @param nonce
    * @return (s:Z_n, noncePoint: Point)
    */
  def sign(privateKey: Z_n, message: ByteVector, nonce: Z_n): (Z_n,Point) =
    val (publicKey, noncePoint) = (privateKey*G, nonce*G)
    (nonce + (challenge(noncePoint.x.bytes ++ publicKey.x.bytes ++ message) * privateKey), nonce*G)

  /**
    * Calculate schnorr signature deterministically according to BIP340 spec.
    *
    * @param privateKey
    * @param message
    * @return (s:Z_n, noncePoint: Point)
    */
  def signDeterministic(privateKey: Z_n, message: ByteVector): (Z_n, Point) =
    require(privateKey != Z_n.zero)
    val P = privateKey*G
    val hashEvenY = P.y.bigInt % 2 == BigInt(0)
    val d = if(hashEvenY) privateKey else privateKey.negate
    val t = taggedHash("BIP0340/aux",ByteVector.fill(32)(0)).xor(d.bytes)
    val rand = taggedHash("BIP0340/nonce",t ++ P.x.bytes ++ message)
    val kPrime = Z_n.fromBytes(rand)
    require(kPrime != Z_n.zero)
    val R = kPrime*G
    val k = if(R.y.bigInt % 2 == BigInt(0)) kPrime else kPrime.negate
    val e = challenge(R.x.bytes ++ P.x.bytes ++ message)
    // note that R may not be the same point as k*G, so we return k*G as the nonce point
    // since k*G is guaranteed to have even y-coordinate and will thus pass BIP340 signature verification
    (k + e*d, k*G)

  /**
    * Verify a schnorr signature
    * note: this implementation is *very* naive and does not do many checks. It also
    *       does not check whether the nonce point R has even y-coordinate per BIP340
    * @param s
    * @param noncePoint
    * @param message
    * @param publicKey
    * @return
    */
  def verifySignature(s: Z_n, noncePoint: Point, message: ByteVector, publicKey: Point): Boolean =
    (s*G) == (noncePoint + (challenge(noncePoint.x.bytes ++ publicKey.x.bytes ++ message)*publicKey))


  /**
    * Create an adaptor signature.
    *
    * @param privateKey
    * @param message
    * @param nonce
    * @param adaptorPoint
    * @return (s: Z_n, noncePoint: Point, adaptorPoint: Point)
    */
  def adaptSign(privateKey: Z_n, message: ByteVector, nonce: Z_n, adaptorPoint: Point): (Z_n,Point,Point) = 
    val (publicKey, noncePoint) = (privateKey*G, nonce*G)
    (nonce + (challenge((noncePoint + adaptorPoint).x.bytes ++ publicKey.x.bytes ++ message)*privateKey), nonce*G, adaptorPoint)

  /** verify adaptor signature */
  def verifyAdaptorSignature(s: Z_n, message: ByteVector, noncePoint: Point, adaptorPoint: Point, publicKey: Point): Boolean =
    (s*G) == (noncePoint + (challenge((noncePoint + adaptorPoint).x.bytes ++ publicKey.x.bytes ++ message)*publicKey))
  
  /** repair adaptor signature with knowledge of the dlog of the adaptor point */
  def completeAdaptorSignature(s: Z_n, noncePoint: Point, adaptorPoint: Point, dlogAdaptorPoint: Z_n): (Z_n, Point) =
    (s + dlogAdaptorPoint, adaptorPoint + noncePoint)

  /**
    * @param name
    * @param x
    * @return 32-byte hash `sha256(sha256(tag) || sha256(tag) || x)` where
    *         tag is the utf-8 encoding of `name`
    */
  def taggedHash(name: String, x: ByteVector): ByteVector =
    val hashtag = ByteVector(name.getBytes("UTF-8")).sha256
    (hashtag ++ hashtag ++ x).sha256