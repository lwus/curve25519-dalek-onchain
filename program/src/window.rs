#![allow(non_snake_case)]

use core::fmt::Debug;

use subtle::ConditionallyNegatable;
use subtle::ConditionallySelectable;
use subtle::ConstantTimeEq;
use subtle::Choice;

use crate::traits::Identity;

use crate::edwards::EdwardsPoint;
use crate::edwards::ProjectiveNielsPoint;

macro_rules! impl_lookup_table {
    (Name = $name:ident, Size = $size:expr, SizeNeg = $neg:expr, SizeRange = $range:expr, ConversionRange = $conv_range:expr) => {

/// A lookup table of precomputed multiples of a point \\(P\\), used to
/// compute \\( xP \\) for \\( -8 \leq x \leq 8 \\).
///
/// The computation of \\( xP \\) is done in constant time by the `select` function.
///
/// Since `LookupTable` does not implement `Index`, it's more difficult
/// to accidentally use the table directly.  Unfortunately the table is
/// only `pub(crate)` so that we can write hardcoded constants, so it's
/// still technically possible.  It would be nice to prevent direct
/// access to the table.
#[derive(Copy, Clone)]
pub struct $name<T>(pub(crate) [T; $size]);

impl<T> $name<T>
where
    T: Identity + ConditionallySelectable + ConditionallyNegatable,
{
    /// Given \\(-8 \leq x \leq 8\\), return \\(xP\\) in constant time.
    pub fn select(&self, x: i8) -> T {
        debug_assert!(x >= $neg);
        debug_assert!(x as i16 <= $size as i16); // XXX We have to convert to i16s here for the radix-256 case.. this is wrong.

        // Compute xabs = |x|
        let xmask = x  as i16 >> 7;
        let xabs = (x as i16 + xmask) ^ xmask;

        // Set t = 0 * P = identity
        let mut t = T::identity();
        for j in $range {
            // Copy `points[j-1] == j*P` onto `t` in constant time if `|x| == j`.
            let c = (xabs as u16).ct_eq(&(j as u16));
            t.conditional_assign(&self.0[j - 1], c);
        }
        // Now t == |x| * P.

        let neg_mask = Choice::from((xmask & 1) as u8);
        t.conditional_negate(neg_mask);
        // Now t == x * P.

        t
    }
}

impl<T: Copy + Default> Default for $name<T> {
    fn default() -> $name<T> {
        $name([T::default(); $size])
    }
}

impl<T: Debug> Debug for $name<T> {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "{:?}(", stringify!($name))?;

        for x in self.0.iter() {
            write!(f, "{:?}", x)?;
        }

        write!(f, ")")
    }
}

impl<'a> From<&'a EdwardsPoint> for $name<ProjectiveNielsPoint> {
    fn from(P: &'a EdwardsPoint) -> Self {
        let mut points = [P.to_projective_niels(); $size];
        for j in $conv_range {
            points[j + 1] = (P + &points[j]).to_extended().to_projective_niels();
        }
        $name(points)
    }
}

}}  // End macro_rules! impl_lookup_table

// The first one has to be named "LookupTable" because it's used as a constructor for consts.
impl_lookup_table! {Name = LookupTable,         Size =   8, SizeNeg =   -8, SizeRange = 1 ..   9, ConversionRange = 0 ..   7} // radix-16

