package bips

import ecc.*
import Secp256k1.*
import scodec.bits.*

/**
  * Note: this is not really a "compliant" implementation of Bip340.
  * For example, it currently does not use tagged hashes, and just a single
  * round of sha256, rather than double.
  */
object Bip340:
  /** the "challenge" used when constructing schnoor sigs. Sometimes this
  * is called "e". Schnorr signature s = k + e*d where e is the challenge,
  * and k is the dlog of the nonce point R. The final signature is (s,R).
  */
  def challenge(bytes: ByteVector): Z_n = Z_n.fromBytes(bytes.sha256)
  
  /**
    * Calculate schnorr signature.
    *
    * @param privateKey
    * @param message
    * @param nonce
    * @return (s:Z_n, noncePoint: Point)
    */
  def sign(privateKey: Z_n, message: ByteVector, nonce: Z_n): (Z_n,Point) =
    val (publicKey, noncePoint) = (privateKey*G, nonce*G)
    (nonce + (challenge(publicKey.bytes ++ noncePoint.bytes ++ message) * privateKey), nonce*G)

  /**
    * Verify a schnorr signature
    *
    * @param s
    * @param noncePoint
    * @param message
    * @param publicKey
    * @return
    */
  def verifySignature(s: Z_n, noncePoint: Point, message: ByteVector, publicKey: Point): Boolean =
    (s*G) == (noncePoint + (challenge(publicKey.bytes ++ noncePoint.bytes ++ message)*publicKey))


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
    (nonce + (challenge(publicKey.bytes ++ (noncePoint + adaptorPoint).bytes ++ message)*privateKey), nonce*G, adaptorPoint)

  /** verify adaptor signature */
  def verifyAdaptorSignature(s: Z_n, message: ByteVector, noncePoint: Point, adaptorPoint: Point, publicKey: Point): Boolean =
    (s*G) == (noncePoint + (challenge(publicKey.bytes ++ (noncePoint + adaptorPoint).bytes ++ message)*publicKey))
  
  /** repair adaptor signature with knowledge of the dlog of the adaptor point */
  def completeAdaptorSignature(s: Z_n, noncePoint: Point, adaptorPoint: Point, dlogAdaptorPoint: Z_n): (Z_n, Point) =
    (s + dlogAdaptorPoint, adaptorPoint + noncePoint)