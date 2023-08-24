
import spire.math._
//import spire.implicits._
import algebra.ring.Field

object Secp256k1 extends spire.syntax.AllSyntax:
  // some curve parameters:
  // y^2 = x^3 + 7 mod p
  val p = BigInt("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F".split(" ").mkString,16)
  val n = BigInt("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141".split(" ").mkString,16)

  object Z_n:
    opaque type Z_n = BigInt
    def apply(x: BigInt): Z_n = x.mod(n)
    extension(x: Z_n)
      def bigInt: BigInt = x
      def multByPoint(pt: Point): Point = Point.multiplyByScalar(pt,x)
  
    given Field[Z_n] with
      def zero: Z_n = BigInt(0)
      def one: Z_n = BigInt(1)
      def negate(x: Z_n): Z_n = (n - x)
      def plus(x: Z_n, y: Z_n): Z_n = (x + y).mod(n)
      def times(x: Z_n, y: Z_n): Z_n = (x * y).mod(n)
      def div(x: Z_n, y: Z_n): Z_n = times(x,y.modInverse(n))
  
  object Z_p:
    opaque type Z_p = BigInt
    def apply(x: BigInt): Z_p = x.mod(p)
    extension (x: Z_p)
      def bigInt: BigInt = x
  
    given Field[Z_p] with 
      def zero: Z_p = BigInt(0)
      def one: Z_p = BigInt(1)
      def negate(x: Z_p): Z_p = (p - x)
      def plus(x: Z_p, y: Z_p): Z_p = (x + y).mod(p)
      def times(x: Z_p, y: Z_p): Z_p = (x * y).mod(p)
      def div(x: Z_p, y: Z_p): Z_p = times(x,y.modInverse(p))

  // allows us to refer to the Z_p instead of having to do Z_p.Z_p
  type Z_p = Z_p.Z_p
  type Z_n = Z_n.Z_n

  sealed trait Point { def x: Z_p; def y: Z_p }
  case class CurvePoint(x: Z_p, y: Z_p) extends Point
  case object PointAtInfinity extends Point {
    def x: Z_p = throw new IllegalArgumentException("point at infinity!")
    def y: Z_p = throw new IllegalArgumentException("point at infinity!")
  }

  object Point: 
    // generator point G
    val G: CurvePoint = CurvePoint(
      x = Z_p(BigInt("79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798".split(" ").mkString ,16)),
      y = Z_p(BigInt("483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8".split(' ').mkString, 16))
    )

    def multiplyByScalar( pt: Point, k: Z_n): Point = {
      //recursive formula here: https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Double-and-add
      if( k == Field[Z_n.Z_n].zero )
        PointAtInfinity
      else if ( k == Field[Z_n.Z_n].one )
        pt
      else if ( k.bigInt.mod(2) == 1 )
        pt.add(multiplyByScalar(pt, k - Z_n(1))) // add when odd
      else
        multiplyByScalar(pt.double, k / 2) // double when even
    }

    extension (pt: Point)
      def isValid: Boolean = pt match {
        case CurvePoint(x, y) => y.pow(2) == x.pow(3) + Z_p(7)
        case PointAtInfinity => true
      }
      def double: Point = pt match {
        case PointAtInfinity => PointAtInfinity
        case CurvePoint(x, y) => {
          val three: Z_p  = Z_p(3)
          val two: Z_p = Z_p(2)
          val L = (three * x.pow(2)) * (two * y).reciprocal
          val xR = L.pow(2) - x - x
          val yR = L*(x - xR) - y
          CurvePoint(xR,yR)
        }
      }
      def add( rhs: Point): Point = (pt,rhs) match {
        case (PointAtInfinity,PointAtInfinity) => PointAtInfinity
        case (PointAtInfinity,b) => b
        case (a, PointAtInfinity) => a
        case (a,b) if (a == b) => a.double
        case (a: CurvePoint, b: CurvePoint) => {
          val L = ((b.y - a.y) * (b.x - a.x).reciprocal)
          val x = L.pow(2) - a.x - b.x
          val y = L*(a.x - x) - a.y
          CurvePoint(x,y)
        }
      }
      def multByScalar( k: Z_n): Point = multiplyByScalar(pt,k)
      def *( k: Z_n): Point = multiplyByScalar(pt,k)
  
  