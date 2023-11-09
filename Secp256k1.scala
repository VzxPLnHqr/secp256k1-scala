package ecc

object Secp256k1:
  // some curve parameters:
  // y^2 = x^3 + 7 mod p
  val p = BigInt("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F".split(" ").mkString,16)
  val n = BigInt("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141".split(" ").mkString,16)
  // generator point G
  val G: CurvePoint = CurvePoint(
    // x = 55066 263022 277343 669578 718895 168534 326250 603453 777594 175500 187360 389116 729240 (77 digits) = 2^3 × 3^3 × 5 × 7 × 11 × 59 × 257 × 19237 × 13 500903 156557 × 168 145721 921751 087215 475410 157071 114499 508276 061867 (51 digits)
    x = Z_p(BigInt("79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798".split(" ").mkString ,16)),
    // y = 32670 510020 758816 978083 085130 507043 184471 273380 659243 275938 904335 757337 482424 (77 digits) = 2^3 × 146 869158 660865 746577 × 1305 785116 654904 037923 × 21294 311662 755074 230987 030904 421293 (35 digits)
    y = Z_p(BigInt("483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8".split(' ').mkString, 16))
  )

  object Z_n:
    opaque type Z_n = BigInt
    def apply(x: BigInt): Z_n = x.mod(n)
    def zero: Z_n = BigInt(0)
    def one: Z_n = BigInt(1)
    def plus(x: Z_n, y: Z_n): Z_n = (x + y).mod(n)
    def times(x: Z_n, y: Z_n): Z_n = (x * y).mod(n)
    def div(x: Z_n, y: Z_n): Z_n = times(x,y.modInverse(n))
    extension(x: Z_n)
      def negate: Z_n = (n - x)
      def unary_- : Z_n = x.negate
      def +(y: Z_n): Z_n = plus(x,y)
      def -(y: Z_n): Z_n = plus(x,y.negate)
      def *(y: Z_n): Z_n = times(x,y)
      def /(y: Z_n): Z_n = div(x,y)
      def bigInt: BigInt = x
      def multByPoint(pt: Point): Point = Point.multiplyByScalar(pt,x)
      def *(pt: Point): Point = x.multByPoint(pt)
  
  object Z_p:
    opaque type Z_p = BigInt
    def apply(x: BigInt): Z_p = x.mod(p)
    def zero: Z_p = BigInt(0)
    def one: Z_p = BigInt(1)
    def plus(x: Z_p, y: Z_p): Z_p = (x + y).mod(p)
    def times(x: Z_p, y: Z_p): Z_p = (x * y).mod(p)
    def div(x: Z_p, y: Z_p): Z_p = times(x,y.modInverse(p))
    extension (x: Z_p)
      def negate: Z_p = (p - x)
      def unary_- : Z_p = x.negate
      def +(y: Z_p): Z_p = plus(x,y)
      def -(y: Z_p): Z_p = plus(x,y.negate)
      def *(y: Z_p): Z_p = times(x,y)
      def pow(exp: BigInt):Z_p = x.modPow(exp,p)
      def /(y: Z_p): Z_p = div(x,y)
      def reciprocal: Z_p = div(one,x)
      def sqrt: Option[(Z_p,Z_p)] = FiniteField.PrimeOrder.sqrt(p,x.bigInt).map{ case (r1,r2) => (Z_p(r1),Z_p(r2))}
      def bigInt: BigInt = x

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

    def multiplyByScalar( pt: Point, k: Z_n): Point = {
      //recursive formula here: https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Double-and-add
      if( k == Z_n.zero )
        PointAtInfinity
      else if ( k == Z_n.one )
        pt
      else if ( k.bigInt.mod(2) == 1 )
        pt.add(multiplyByScalar(pt, k - Z_n(1))) // add when odd
      else
        multiplyByScalar(pt.double, k / Z_n(2)) // double when even
    }

    /**
      * Given an x-coordinate, find the y-coordinate, if it exists.
      *
      * @param x, x-coordinate
      * @return +- y-coordinate, if it exists
      */
    def solveForY(x: Z_p): Option[(Z_p,Z_p)] = 
      FiniteField.PrimeOrder.sqrt(p, (x.pow(3) + Z_p(7)).bigInt)
        .map{ case (y1,y2) => (Z_p(y1), Z_p(y2))}

    extension (pt: Point)
      def isValid: Boolean = pt match {
        case CurvePoint(x, y) => y.pow(2) == (x.pow(3) + Z_p(7))
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
      def +( rhs: Point): Point = add(rhs)
      def negate: Point = pt match {
        case CurvePoint(x, y) => CurvePoint(x,y.negate)
        case PointAtInfinity => PointAtInfinity
      }
      def unary_- : Point = pt.negate
      def -( rhs: Point): Point = (pt + (-rhs))
      def multByScalar( k: Z_n): Point = multiplyByScalar(pt,k)
      def *( k: Z_n): Point = multiplyByScalar(pt,k)
  
  
