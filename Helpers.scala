//> using lib "org.typelevel::cats-effect:3.5.1"
//> using lib "org.scodec::scodec-bits::1.1.37"

package ecc

import ecc.Secp256k1.*
import cats.effect.*
import cats.effect.std.Random
import scodec.bits.*
import cats.syntax.all.*

/**
  * Some helper and/or syntactic convenience methods below which make the above
  * code slightly more readable.
  */

extension (k: Z_n)
  def bytes: ByteVector = ByteVector(k.bigInt.toByteArray.takeRight(32)).padLeft(32)

extension (pt: Point)
  def bytes: ByteVector = 
    ByteVector(pt.x.bigInt.toByteArray.takeRight(32)).padLeft(32) ++ ByteVector(pt.y.bigInt.toByteArray.takeRight(32)).padLeft(32)

extension (o: Z_n.type)
  /** random element of Z_n (a private key) **/
  def rand(using Random[IO]): IO[Z_n] = Random[IO].betweenBigInt(0,n).map(Z_n(_))
  def fromValidHex(hex: String): Z_n = Z_n(BigInt(hex,16))

extension (o: Z_p.type)
  def fromValidHex(hex: String): Z_p = Z_p(BigInt(hex,16))

extension (o: Point.type)
  /** random point on the curve. Not very useful since it forgets k **/
  def rand(using Random[IO]): IO[Point] = Z_n.rand.map(k => k * G)
  def fromBytes(bytes: ByteVector): Point = fromValidHex(bytes.toHex)
  def fromValidHex(hex: String): Point = {
    require(hex.length == 128,"invalid length of hex")
    CurvePoint(Z_p.fromValidHex(hex.take(64)), Z_p.fromValidHex(hex.drop(64)))
  }

extension (random: Random[IO])
      /**
      * select a random big integer
      * (currently uses scala.util.Random)
      *
      * @param minInclusive
      * @param maxExclusive
      * @param randomIO
      * @return
      */
    def betweenBigInt(minInclusive: BigInt, maxExclusive: BigInt)
        (implicit randomIO: std.Random[IO]): IO[BigInt] = for {
            range <- IO(maxExclusive - minInclusive)
            bitlength <- IO(range.bitLength)
            r <- IO(BigInt(bitlength,scala.util.Random)).iterateUntil(_ < range)
        } yield minInclusive + r

    def bitVectors(howMany: Int, minSizeBytes: Int = 5, maxSizeBytes: Int = 100): IO[List[BitVector]] = 
      List.range(0,howMany).parTraverse{ i => 
        for {
          size <-  random.betweenInt(minSizeBytes,maxSizeBytes)
          bits <-  random.nextBytes(size).map(BitVector(_))
        } yield bits
      }