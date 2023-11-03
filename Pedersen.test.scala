import ecc.*
import Secp256k1.*
import scodec.bits.*
import bips.Bip340.*

class PedersenCommitments extends munit.FunSuite {

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