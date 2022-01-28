#![allow(non_snake_case)]

use core::ops::{Add, Neg};
use core::borrow::Borrow;
use core::fmt::Debug;

use subtle::Choice;
use subtle::ConditionallySelectable;

use zeroize::Zeroize;

use crate::backend::serial::scalar_mul;
use crate::backend::serial::u64::constants;
use crate::field::FieldElement;
use crate::scalar::Scalar;
use crate::traits::Identity;
use crate::traits::MultiscalarMul;

// ------------------------------------------------------------------------
// Internal point representations
// ------------------------------------------------------------------------

/// An `EdwardsPoint` represents a point on the Edwards form of Curve25519.
#[derive(Copy, Clone)]
#[allow(missing_docs)]
pub struct EdwardsPoint {
    pub(crate) X: FieldElement,
    pub(crate) Y: FieldElement,
    pub(crate) Z: FieldElement,
    pub(crate) T: FieldElement,
}

/// A pre-computed point on the \\( \mathbb P\^3 \\) model for the
/// curve, represented as \\((Y+X, Y-X, Z, 2dXY)\\) in "Niels coordinates".
///
/// More details on the relationships between the different curve models
/// can be found in the module-level documentation.
#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub struct ProjectiveNielsPoint {
    pub Y_plus_X:  FieldElement,
    pub Y_minus_X: FieldElement,
    pub Z:         FieldElement,
    pub T2d:       FieldElement,
}

/// A `ProjectivePoint` is a point \\((X:Y:Z)\\) on the \\(\mathbb
/// P\^2\\) model of the curve.
/// A point \\((x,y)\\) in the affine model corresponds to
/// \\((x:y:1)\\).
///
/// More details on the relationships between the different curve models
/// can be found in the module-level documentation.
#[derive(Copy, Clone)]
pub struct ProjectivePoint {
    pub X: FieldElement,
    pub Y: FieldElement,
    pub Z: FieldElement,
}

/// A `CompletedPoint` is a point \\(((X:Z), (Y:T))\\) on the \\(\mathbb
/// P\^1 \times \mathbb P\^1 \\) model of the curve.
/// A point (x,y) in the affine model corresponds to \\( ((x:1),(y:1))
/// \\).
///
/// More details on the relationships between the different curve models
/// can be found in the module-level documentation.
#[derive(Copy, Clone)]
#[allow(missing_docs)]
pub struct CompletedPoint {
    pub X: FieldElement,
    pub Y: FieldElement,
    pub Z: FieldElement,
    pub T: FieldElement,
}


// ------------------------------------------------------------------------
// Constructors
// ------------------------------------------------------------------------

impl Identity for EdwardsPoint {
    fn identity() -> EdwardsPoint {
        EdwardsPoint {
            X: FieldElement::zero(),
            Y: FieldElement::one(),
            Z: FieldElement::one(),
            T: FieldElement::zero(),
        }
    }
}

impl Identity for ProjectiveNielsPoint {
    fn identity() -> ProjectiveNielsPoint {
        ProjectiveNielsPoint{
            Y_plus_X:  FieldElement::one(),
            Y_minus_X: FieldElement::one(),
            Z:         FieldElement::one(),
            T2d:       FieldElement::zero(),
        }
    }
}

impl Zeroize for ProjectiveNielsPoint {
    fn zeroize(&mut self) {
        self.Y_plus_X.zeroize();
        self.Y_minus_X.zeroize();
        self.Z.zeroize();
        self.T2d.zeroize();
    }
}

impl Default for ProjectiveNielsPoint {
    fn default() -> ProjectiveNielsPoint {
        ProjectiveNielsPoint::identity()
    }
}

// ------------------------------------------------------------------------
// Point conversions
// ------------------------------------------------------------------------

impl EdwardsPoint {
    /// Convert to a ProjectiveNielsPoint
    pub(crate) fn to_projective_niels(&self) -> ProjectiveNielsPoint {
        ProjectiveNielsPoint{
            Y_plus_X:  &self.Y + &self.X,
            Y_minus_X: &self.Y - &self.X,
            Z:          self.Z,
            T2d:       &self.T * &constants::EDWARDS_D2,
        }
    }

    /// Convert the representation of this point from extended
    /// coordinates to projective coordinates.
    ///
    /// Free.
    pub(crate) fn to_projective(&self) -> ProjectivePoint {
        ProjectivePoint{
            X: self.X,
            Y: self.Y,
            Z: self.Z,
        }
    }

    /// Multiply by the cofactor: return \\([8]P\\).
    pub fn mul_by_cofactor(&self) -> EdwardsPoint {
        self.mul_by_pow_2(3)
    }

    /// Compute \\([2\^k] P \\) by successive doublings. Requires \\( k > 0 \\).
    pub(crate) fn mul_by_pow_2(&self, k: u32) -> EdwardsPoint {
        debug_assert!( k > 0 );
        let mut r: CompletedPoint;
        let mut s = self.to_projective();
        for _ in 0..(k-1) {
            r = s.double(); s = r.to_projective();
        }
        // Unroll last iteration so we can go directly to_extended()
        s.double().to_extended()
    }

    pub fn from_bytes(bytes: &[u8]) -> EdwardsPoint {
        let mut buffer: [u8; 32] = [0; 32];

        buffer.copy_from_slice(&bytes[..32]);
        let X = FieldElement::from_bytes(&buffer);

        buffer.copy_from_slice(&bytes[32..64]);
        let Y = FieldElement::from_bytes(&buffer);

        buffer.copy_from_slice(&bytes[64..96]);
        let Z = FieldElement::from_bytes(&buffer);

        buffer.copy_from_slice(&bytes[96..]);
        let T = FieldElement::from_bytes(&buffer);

        EdwardsPoint{ X, Y, Z, T }
    }

    pub fn to_bytes(&self) -> [u8; 128] {
        let mut buffer: [u8; 128] = [0; 128];

        buffer[..32].copy_from_slice(&self.X.to_bytes());
        buffer[32..64].copy_from_slice(&self.Y.to_bytes());
        buffer[64..96].copy_from_slice(&self.Z.to_bytes());
        buffer[96..].copy_from_slice(&self.T.to_bytes());

        buffer
    }
}

impl CompletedPoint {
    /// Convert this point from the \\( \mathbb P\^1 \times \mathbb P\^1
    /// \\) model to the \\( \mathbb P\^2 \\) model.
    ///
    /// This costs \\(3 \mathrm M \\).
    pub fn to_projective(&self) -> ProjectivePoint {
        ProjectivePoint {
            X: &self.X * &self.T,
            Y: &self.Y * &self.Z,
            Z: &self.Z * &self.T,
        }
    }

    /// Convert this point from the \\( \mathbb P\^1 \times \mathbb P\^1
    /// \\) model to the \\( \mathbb P\^3 \\) model.
    ///
    /// This costs \\(4 \mathrm M \\).
    pub fn to_extended(&self) -> EdwardsPoint {
        EdwardsPoint {
            X: &self.X * &self.T,
            Y: &self.Y * &self.Z,
            Z: &self.Z * &self.T,
            T: &self.X * &self.Y,
        }
    }
}

impl ProjectivePoint {
    /// Convert this point from the \\( \mathbb P\^2 \\) model to the
    /// \\( \mathbb P\^3 \\) model.
    ///
    /// This costs \\(3 \mathrm M + 1 \mathrm S\\).
    pub fn to_extended(&self) -> EdwardsPoint {
        EdwardsPoint {
            X: &self.X * &self.Z,
            Y: &self.Y * &self.Z,
            Z: self.Z.square(),
            T: &self.X * &self.Y,
        }
    }
}

// ------------------------------------------------------------------------
// Constant-time assignment
// ------------------------------------------------------------------------

impl ConditionallySelectable for ProjectiveNielsPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        ProjectiveNielsPoint {
            Y_plus_X: FieldElement::conditional_select(&a.Y_plus_X, &b.Y_plus_X, choice),
            Y_minus_X: FieldElement::conditional_select(&a.Y_minus_X, &b.Y_minus_X, choice),
            Z: FieldElement::conditional_select(&a.Z, &b.Z, choice),
            T2d: FieldElement::conditional_select(&a.T2d, &b.T2d, choice),
        }
    }

    fn conditional_assign(&mut self, other: &Self, choice: Choice) {
        self.Y_plus_X.conditional_assign(&other.Y_plus_X, choice);
        self.Y_minus_X.conditional_assign(&other.Y_minus_X, choice);
        self.Z.conditional_assign(&other.Z, choice);
        self.T2d.conditional_assign(&other.T2d, choice);
    }
}

// ------------------------------------------------------------------------
// Doubling
// ------------------------------------------------------------------------

impl ProjectivePoint {
    /// Double this point: return self + self
    pub fn double(&self) -> CompletedPoint { // Double()
        let XX          = self.X.square();
        let YY          = self.Y.square();
        let ZZ2         = self.Z.square2();
        let X_plus_Y    = &self.X + &self.Y;
        let X_plus_Y_sq = X_plus_Y.square();
        let YY_plus_XX  = &YY + &XX;
        let YY_minus_XX = &YY - &XX;

        CompletedPoint{
            X: &X_plus_Y_sq - &YY_plus_XX,
            Y: YY_plus_XX,
            Z: YY_minus_XX,
            T: &ZZ2 - &YY_minus_XX
        }
    }
}

impl<'a, 'b> Add<&'b ProjectiveNielsPoint> for &'a EdwardsPoint {
    type Output = CompletedPoint;

    fn add(self, other: &'b ProjectiveNielsPoint) -> CompletedPoint {
        let Y_plus_X  = &self.Y + &self.X;
        let Y_minus_X = &self.Y - &self.X;
        let PP = &Y_plus_X  * &other.Y_plus_X;
        let MM = &Y_minus_X * &other.Y_minus_X;
        let TT2d = &self.T * &other.T2d;
        let ZZ   = &self.Z * &other.Z;
        let ZZ2  = &ZZ + &ZZ;

        CompletedPoint{
            X: &PP - &MM,
            Y: &PP + &MM,
            Z: &ZZ2 + &TT2d,
            T: &ZZ2 - &TT2d
        }
    }
}

// used for ConditionallyNegatable?
impl<'a> Neg for &'a ProjectiveNielsPoint {
    type Output = ProjectiveNielsPoint;

    fn neg(self) -> ProjectiveNielsPoint {
        ProjectiveNielsPoint{
            Y_plus_X:   self.Y_minus_X,
            Y_minus_X:  self.Y_plus_X,
            Z:          self.Z,
            T2d:        -(&self.T2d),
        }
    }
}

impl<'a> Neg for &'a EdwardsPoint {
    type Output = EdwardsPoint;

    fn neg(self) -> EdwardsPoint {
        EdwardsPoint{
            X: -(&self.X),
            Y:  self.Y,
            Z:  self.Z,
            T: -(&self.T),
        }
    }
}

// ------------------------------------------------------------------------
// Multiscalar Multiplication impls
// ------------------------------------------------------------------------

// These use the iterator's size hint and the target settings to
// forward to a specific backend implementation.

impl MultiscalarMul for EdwardsPoint {
    type Point = EdwardsPoint;

    fn multiscalar_mul<I, J>(scalars: I, points: J) -> EdwardsPoint
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator,
        J::Item: Borrow<EdwardsPoint>,
    {
        // Sanity-check lengths of input iterators
        let mut scalars = scalars.into_iter();
        let mut points = points.into_iter();

        // Lower and upper bounds on iterators
        let (s_lo, s_hi) = scalars.by_ref().size_hint();
        let (p_lo, p_hi) = points.by_ref().size_hint();

        // They should all be equal
        assert_eq!(s_lo, p_lo);
        assert_eq!(s_hi, Some(s_lo));
        assert_eq!(p_hi, Some(p_lo));

        // Now we know there's a single size.  When we do
        // size-dependent algorithm dispatch, use this as the hint.
        let _size = s_lo;

        scalar_mul::straus::Straus::multiscalar_mul(scalars, points)
    }
}

// ------------------------------------------------------------------------
// Debug traits
// ------------------------------------------------------------------------

impl Debug for EdwardsPoint {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "EdwardsPoint{{\n\tX: {:?},\n\tY: {:?},\n\tZ: {:?},\n\tT: {:?}\n}}",
               &self.X, &self.Y, &self.Z, &self.T)
    }
}

impl Debug for ProjectiveNielsPoint {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "ProjectiveNielsPoint{{\n\tY_plus_X: {:?},\n\tY_minus_X: {:?},\n\tZ: {:?},\n\tT2d: {:?}\n}}",
               &self.Y_plus_X, &self.Y_minus_X, &self.Z, &self.T2d)
    }
}
