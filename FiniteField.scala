package ecc

/*trait FiniteField[A]:
  def zero: A
  def one: A
*/

object FiniteField:
  object PrimeOrder:
    /**
      * Tonelli-Shanks algorithm to find square root of elements of finite field
      * of prime order (if such roots exist)
      * @source: https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm
      *
      * @param p, a prime
      * @param n, an element of Z/pZ
      * @return +-r in Z/pZsuch that r^2 = n
      */
    def sqrt[A](p: BigInt, n: BigInt): Option[(BigInt,BigInt)] = {
      if(p % 4 == BigInt(3)) {
        // for primes such that p == 3 (mod 4), the square roots are easily calculated:
        // note: for secp256k1 points this is in fact the case, 
        // so we can use this to check if a point is on the elliptic curve.
        val r1 = n.modPow((p + 1) / 4, p)
        val r2 = -r1
        if( ((r1 * r1).mod(p)) == n && ((r2 * r2).mod(p) == n) )
          Some((r1,r2))
        else
          None
      } else {
        // for primes such that p != 3 (mod 4)

        // factor out powers of 2 and find q and s such that p-1 = q*(2^s) with q odd
        val (q,s) = {
          def factor(remaining: BigInt): (BigInt,BigInt) = ???
          factor(p - 1)
        }

        // search for z in Z/pZ which is a quadradic non-residue
        //  * half of the elements in the set will be
        //  * candidates can be tested with Euler's criterion:
        //  * `a` is a quadratic residue if a^((p-1) / 2 ) == 1 (mod p)
        val z: BigInt = (2 to 1000)
                          .map(a => (a,BigInt(a).modPow((p - 1)/2,p) == BigInt(1).mod(p)))
                            .dropWhile(_._2 == true) // we want the first non-residue
                              // unsafe, but since half the values are quadradic residues, 
                              // it is quite likely we will find one in the first 1000 tries
                              .map(_._1).map(BigInt(_)).head 
        // TODO: finish me.
        ???
      }
    }