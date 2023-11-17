import ecc.*
import Secp256k1.*
import scodec.bits.*
import bips.Bip340.*
import scala.util.chaining.*

class RangeProofTest extends munit.FunSuite {

  test("rangeproof - single bit - interactive") {
    // SIMPLE RANGEPROOF FOR SINGLE-BIT COMMITMENT
    // 
    // Much thanks to Liam Eagan for the helpful chats. Any errors here are not
    // his. This is an attempt to codify a simple range proof which proves
    // knowledge of a bit.
    // 
    // Suppose a prover P wants to convince a verifier V
    // that they know b and s such that:
    // C = b*G + s*H 
    // and also convince the verifier that b is either 0 or 1
    //
    // First, Prover and Verifier agree on some independent generator points.
    // For this protocol, we will need 3 independent generator points G, H, F.
    // G can be the usual point G in the secp256k1 specification, but 
    // H and F should be determined in NUMS fashion such that the discrete log 
    // of either is unknown.
    // Prover and Verifier previous agree on how to calculate such points.
    val G = Secp256k1.G
    val H = Secp256k1.coerceToPoint(G.bytes)
    val F = Secp256k1.coerceToPoint(H.bytes)

    // `b` is the value of the bit that the Prover is commiting to.
    // We represent b as an element of Z_n.
    // Say b = 1
    val b = Z_n(1)

    // First we will generate a proof of knowledge of b. This proof will only
    // convince the verifier that P knows the value of b, but it will not convince
    // the Verifier that b is a bit. In this proof, the Verifier will only be
    // convinced that b is an element of Z_n. Sometimes elements of Z_n are
    // called scalars.

    // Prover chooses random scalars s,x,y
    //    note: these are chosen very insecurely below, just for demonstration
    val s = ByteVector("s".getBytes).sha256.pipe(Z_n.fromBytes)
    val x = ByteVector("x".getBytes).sha256.pipe(Z_n.fromBytes)
    val y = ByteVector("y".getBytes).sha256.pipe(Z_n.fromBytes)

    // Prover sends to Verifier the following commitments. Prover will be able to
    // us its knowledge of b,s,x,y to construct two new scalars u,v as a function
    // of the challenge, e, which is provided by the Verifier.
    // Commit:
    val C = b*G + s*H
    val R1 = x*G + y*H

    // Send:
    // Given challenge e from Verifier
    // Prover calculates and sends u(e),v(e). 
    // Notice that these equations can be seen as simple polynomials in e. 
    def u(e: Z_n):Z_n = x + e*b
    def v(e: Z_n):Z_n = y + e*s

    // However, Verifier will not be convinced that b is a bit. Rather, b could be
    // any scalar. Prover will show that b is in fact a bit. 
    
    // Regardless of Prover's choice of b, so long as b = 0 or b = 1, 
    // the following "bit check identity" will hold:
    // `b (1 - b) = 0`

    // Here is the trick:
    // Prover constructs a polynomial f(z) such that the highest order term
    // has coefficient `b (1 - b)`. A simple way to do this is
    // f(z) = (x + z*b)(z - (x + z*b)) where x is the random value chosen above
    //      = [b (1-b)] z^2 +  [x (2 b - 1)] z + [-x^2]
    //
    // The square bracketed terms are the coefficients which Prover must generate
    // blinded commitments to. The highest order term has, by construction, a
    // coefficient which will evaluate to 0, so no commitment need be made to that
    // coefficient.
    // 
    //  
    // Prover chooses random scalars r2,r3 which will be blinding factors.
    val r2 = ByteVector("r2".getBytes).sha256.pipe(Z_n.fromBytes)
    val r3 = ByteVector("r3".getBytes).sha256.pipe(Z_n.fromBytes)

    // Prover commits to the coefficients:

    val R2 = -x*x*H + r2*F
    val R3 = x*(Z_n(1)-Z_n(2)*b)*H + r3*F

    // Send:
    // Given challenge e from Verifier
    // Prover calculates and sends r(e)
    def r(e: Z_n): Z_n = r2 + e*r3

    // Challenge:
    // By hashing everything the verifier depends on (Fiat-shamir),
    // Prover can use a single challenge value to complete and send the proofs.
    val e = Z_n.fromBytes((G.bytes ++ H.bytes ++ F.bytes ++ C.bytes ++ R1.bytes ++ R2.bytes ++ R3.bytes).sha256)

    // Check (proof of knowledge of b):
    // Verifier has received C,R1,u(e),v(e)
    // If the following assertion passes then Verifier is convinced 
    // Prover knows b. Prover has not leaked any information
    // about the value of b.
    assert( u(e)*G + v(e)*H == R1 + e*C )

    // Check (proof that b is a bit):
    // Verifier has received R2,R3,r(e) in addition to C1,R1,u(e),v(e)
    assert( u(e)*(e - u(e))*H + r(e)*F == R2 + e*R3 )

    // If above assertion passes, Verifier is now sufficiently convinced that
    // prover's choice of b is either 0 or 1
  }
}