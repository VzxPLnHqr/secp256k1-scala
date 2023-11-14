import ecc.*
import Secp256k1.*
import scodec.bits.*
import bips.Bip340.*
import scala.util.chaining.*

class PedersenCommitments extends munit.FunSuite {

  test("bit commitment") {
    // SIMPLE PEDERSEN BIT COMMITMENT
    //
    // Suppose a prover P wants to convince a verifier V
    // that they know b and s such that:
    // C = b*G + s*H and also convince the verifier that b is either 0 or 1
    //
    // G, H, F are independent generator points. G can be the usual point G 
    // in the secp256k1 specification, but H and F should be determined in NUMS
    // fashion such that the discrete log of either is unknown.
    // Prover and Verifier previous agree on how to calculate such points.
    val H = Secp256k1.coerceToPoint(G.bytes)
    val F = Secp256k1.coerceToPoint(H.bytes)

    // `b` is the value of the bit that the Prover is commiting to.
    // say b = 1
    val b = Z_n(1)
    // choose random scalars s,x,y,r2,r3
    //    note: these are chosen very insecurely below, just for demonstration
    val s = ByteVector("s".getBytes).sha256.pipe(Z_n.fromBytes)
    val x = ByteVector("x".getBytes).sha256.pipe(Z_n.fromBytes)
    val y = ByteVector("y".getBytes).sha256.pipe(Z_n.fromBytes)
    val r2 = ByteVector("r2".getBytes).sha256.pipe(Z_n.fromBytes)
    val r3 = ByteVector("r3".getBytes).sha256.pipe(Z_n.fromBytes)

    // Commit:
    val C = b*G + s*H
    val R1 = x*G + y*H
    val R2 = -x*x*H + r2*F
    val R3 = x*(Z_n(1)-Z_n(2)*b)*H + r3*F

    // Challenge:
    // hash everything the verifier depends on (Fiat-shamir)
    val e = Z_n.fromBytes((G.bytes ++ H.bytes ++ F.bytes ++ C.bytes ++ R1.bytes ++ R2.bytes ++ R3.bytes).sha256)

    // Send:
    val u = x + e*b
    val v = y + e*s
    val r = r2 + e*r3

    // Verifier receives (C,R1,R2,R3,u,v,r)
    // Check:
    assert( u*G + v*H == R1 + e*C )
    assert( u*(e - u)*H + r*F == R2 + e*R3 )

  }

  test("scalar commitment") {
    // SIMPLE PEDERSEN COMMITMENT
    // translated mostly from here: 
    //  https://gist.github.com/cmdruid/22a8da1e21a58b4d0c31dcba54c55e2e#file-pedersen-js-L16

    // Suppose a prover P wants to convince a verifier V 
    // that they know x and r such that: C = x*G + r*H 
    // G and H are independent generator points. G can be the usual point G
    // in the secp256k1 specification, and H should be determined in a NUMS fashion,
    // such that the discrete logarithm of H with respect to G is unknown.

    // First, generate our x and r values, represented as integers.
    val x = Z_n.fromBytes(ByteVector("deadbeef".repeat(4).getBytes))
    val r = Z_n.fromBytes(ByteVector("decafeed".repeat(4).getBytes))

    // Then, we need to compute point C.

    // We need a second point (H) to be used as generator. To ensure that H is of
    // unknown discrete logarithm and not related to G, we generate H as follows:
    // val H = coerceToPoint(sha256(G.value))

    val H = Z_n(1234567)*G // insecure hack for now

    // Now we can calculate C. This is the commitment.
    val C = x*G + r*H

    // We also need to compute a second point A, the nonce point.

    // Pick random values a,b. These serve as the scalars for the nonce point.
    // Choosing these deterministically if possible seems to make sense.
    val a = Z_n.fromBytes((C.bytes ++ x.bytes.sha256).sha256)
    val b = Z_n.fromBytes((C.bytes ++ r.bytes.sha256).sha256)

    // Compute A = a*G + b*H.
    val A = a*G + b*H

    // Verifier generates a challenge c
    val c = Z_n.fromBytes((C.bytes ++ A.bytes).sha256)
    // note: by choosing c deterministically, we can make the commitment scheme 
    // non-interactive, as the Prover is able to generate the same choice of
    // c that the Verify would have chosen.

    // The prover calculates responses z1 = a + cx and z2 = b + cr
    // Notice how z1,z2 have the structure of schnorr signatures.
    // Because there are two generators involved (G, H), there are two such
    // schnorr signatures. One for each generator point.
    val z1 = c*x + a
    val z2 = c*r + b

    // -------
    // Prover sends (A, z1, z2) to Verifier (and includes C if not yet sent)
    // -------

    // The verifier checks that z1*G + z2*H == c*C + A
    // Recall that both points C and a are each linear combinations of
    // G and H.
    val Z1 = G*z1
    val Z2 = H*z2
    val C_v = C*c
    val V_1 = Z1 + Z2
    val V_2 = C_v + A
    
    assert( V_1 == V_2 )

  }
}