
use subtle::Choice;
use subtle::ConstantTimeEq;

use crate::backend::serial::u64::constants;
use crate::edwards::EdwardsPoint;
use crate::field::FieldElement;
use crate::traits::Identity;

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct CompressedRistretto(pub [u8; 32]);

impl ConstantTimeEq for CompressedRistretto {
    fn ct_eq(&self, other: &CompressedRistretto) -> Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }
}

impl CompressedRistretto {
    /// Copy the bytes of this `CompressedRistretto`.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// View this `CompressedRistretto` as an array of bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Construct a `CompressedRistretto` from a slice of bytes.
    ///
    /// # Panics
    ///
    /// If the input `bytes` slice does not have a length of 32.
    pub fn from_slice(bytes: &[u8]) -> CompressedRistretto {
        let mut tmp = [0u8; 32];

        tmp.copy_from_slice(bytes);

        CompressedRistretto(tmp)
    }

    ///// Attempt to decompress to an `RistrettoPoint`.
    /////
    ///// # Return
    /////
    ///// - `Some(RistrettoPoint)` if `self` was the canonical encoding of a point;
    /////
    ///// - `None` if `self` was not the canonical encoding of a point.
    //pub fn decompress(&self) -> Option<RistrettoPoint> {
    //    // Step 1. Check s for validity:
    //    // 1.a) s must be 32 bytes (we get this from the type system)
    //    // 1.b) s < p
    //    // 1.c) s is nonnegative
    //    //
    //    // Our decoding routine ignores the high bit, so the only
    //    // possible failure for 1.b) is if someone encodes s in 0..18
    //    // as s+p in 2^255-19..2^255-1.  We can check this by
    //    // converting back to bytes, and checking that we get the
    //    // original input, since our encoding routine is canonical.

    //    let s = FieldElement::from_bytes(self.as_bytes());
    //    let s_bytes_check = s.to_bytes();
    //    let s_encoding_is_canonical =
    //        &s_bytes_check[..].ct_eq(self.as_bytes());
    //    let s_is_negative = s.is_negative();

    //    if s_encoding_is_canonical.unwrap_u8() == 0u8 || s_is_negative.unwrap_u8() == 1u8 {
    //        return None;
    //    }

    //    // Step 2.  Compute (X:Y:Z:T).
    //    let one = FieldElement::one();
    //    let ss = s.square();
    //    let u1 = &one - &ss;      //  1 + as²
    //    let u2 = &one + &ss;      //  1 - as²    where a=-1
    //    let u2_sqr = u2.square(); // (1 - as²)²

    //    // v == ad(1+as²)² - (1-as²)²            where d=-121665/121666
    //    let v = &(&(-&constants::EDWARDS_D) * &u1.square()) - &u2_sqr;

    //    let (ok, I) = (&v * &u2_sqr).invsqrt(); // 1/sqrt(v*u_2²)

    //    let Dx = &I * &u2;         // 1/sqrt(v)
    //    let Dy = &I * &(&Dx * &v); // 1/u2

    //    // x == | 2s/sqrt(v) | == + sqrt(4s²/(ad(1+as²)² - (1-as²)²))
    //    let mut x = &(&s + &s) * &Dx;
    //    let x_neg = x.is_negative();
    //    x.conditional_negate(x_neg);

    //    // y == (1-as²)/(1+as²)
    //    let y = &u1 * &Dy;

    //    // t == ((1+as²) sqrt(4s²/(ad(1+as²)² - (1-as²)²)))/(1-as²)
    //    let t = &x * &y;

    //    if ok.unwrap_u8() == 0u8 || t.is_negative().unwrap_u8() == 1u8 || y.is_zero().unwrap_u8() == 1u8 {
    //        None
    //    } else {
    //        Some(RistrettoPoint(EdwardsPoint{X: x, Y: y, Z: one, T: t}))
    //    }
    //}
}

impl Identity for CompressedRistretto {
    fn identity() -> CompressedRistretto {
        CompressedRistretto([0u8; 32])
    }
}

impl Default for CompressedRistretto {
    fn default() -> CompressedRistretto {
        CompressedRistretto::identity()
    }
}

// ------------------------------------------------------------------------
// Internal point representations
// ------------------------------------------------------------------------

/// A `RistrettoPoint` represents a point in the Ristretto group for
/// Curve25519.  Ristretto, a variant of Decaf, constructs a
/// prime-order group as a quotient group of a subgroup of (the
/// Edwards form of) Curve25519.
///
/// Internally, a `RistrettoPoint` is implemented as a wrapper type
/// around `EdwardsPoint`, with custom equality, compression, and
/// decompression routines to account for the quotient.  This means that
/// operations on `RistrettoPoint`s are exactly as fast as operations on
/// `EdwardsPoint`s.
///
#[derive(Copy, Clone)]
pub struct RistrettoPoint(pub(crate) EdwardsPoint);
