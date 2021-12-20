// -*- mode: rust; -*-
//
// This file is part of curve25519-dalek.
// Copyright (c) 2016-2021 isis lovecruft
// Copyright (c) 2016-2019 Henry de Valence
// Portions Copyright 2017 Brian Smith
// See LICENSE for licensing information.
//
// Authors:
// - Isis Agora Lovecruft <isis@patternsinthevoid.net>
// - Henry de Valence <hdevalence@hdevalence.ca>
// - Brian Smith <brian@briansmith.org>

//! Arithmetic on scalars (integers mod the group order).
//!
//! Both the Ristretto group and the Ed25519 basepoint have prime order
//! \\( \ell = 2\^{252} + 27742317777372353535851937790883648493 \\).
//!
//! This code is intended to be useful with both the Ristretto group
//! (where everything is done modulo \\( \ell \\)), and the X/Ed25519
//! setting, which mandates specific bit-twiddles that are not
//! well-defined modulo \\( \ell \\).
//!
//! All arithmetic on `Scalars` is done modulo \\( \ell \\).
//!
//! # Constructing a scalar
//!
//! To create a [`Scalar`](struct.Scalar.html) from a supposedly canonical encoding, use
//! [`Scalar::from_canonical_bytes`](struct.Scalar.html#method.from_canonical_bytes).
//!
//! This function does input validation, ensuring that the input bytes
//! are the canonical encoding of a `Scalar`.
//! If they are, we'll get
//! `Some(Scalar)` in return:
//!
//! ```
//! use curve25519_dalek::scalar::Scalar;
//!
//! let one_as_bytes: [u8; 32] = Scalar::one().to_bytes();
//! let a: Option<Scalar> = Scalar::from_canonical_bytes(one_as_bytes);
//!
//! assert!(a.is_some());
//! ```
//!
//! However, if we give it bytes representing a scalar larger than \\( \ell \\)
//! (in this case, \\( \ell + 2 \\)), we'll get `None` back:
//!
//! ```
//! use curve25519_dalek::scalar::Scalar;
//!
//! let l_plus_two_bytes: [u8; 32] = [
//!    0xef, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
//!    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
//!    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
//! ];
//! let a: Option<Scalar> = Scalar::from_canonical_bytes(l_plus_two_bytes);
//!
//! assert!(a.is_none());
//! ```
//!
//! Another way to create a `Scalar` is by reducing a \\(256\\)-bit integer mod
//! \\( \ell \\), for which one may use the
//! [`Scalar::from_bytes_mod_order`](struct.Scalar.html#method.from_bytes_mod_order)
//! method.  In the case of the second example above, this would reduce the
//! resultant scalar \\( \mod \ell \\), producing \\( 2 \\):
//!
//! ```
//! use curve25519_dalek::scalar::Scalar;
//!
//! let l_plus_two_bytes: [u8; 32] = [
//!    0xef, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
//!    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
//!    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
//! ];
//! let a: Scalar = Scalar::from_bytes_mod_order(l_plus_two_bytes);
//!
//! let two: Scalar = Scalar::one() + Scalar::one();
//!
//! assert!(a == two);
//! ```
//!
//! There is also a constructor that reduces a \\(512\\)-bit integer,
//! [`Scalar::from_bytes_mod_order_wide`](struct.Scalar.html#method.from_bytes_mod_order_wide).
//!
//! To construct a `Scalar` as the hash of some input data, use
//! [`Scalar::hash_from_bytes`](struct.Scalar.html#method.hash_from_bytes),
//! which takes a buffer, or
//! [`Scalar::from_hash`](struct.Scalar.html#method.from_hash),
//! which allows an IUF API.
//!
//! ```
//! # extern crate curve25519_dalek;
//! # extern crate sha2;
//! #
//! # fn main() {
//! use sha2::{Digest, Sha512};
//! use curve25519_dalek::scalar::Scalar;
//!
//! // Hashing a single byte slice
//! let a = Scalar::hash_from_bytes::<Sha512>(b"Abolish ICE");
//!
//! // Streaming data into a hash object
//! let mut hasher = Sha512::default();
//! hasher.update(b"Abolish ");
//! hasher.update(b"ICE");
//! let a2 = Scalar::from_hash(hasher);
//!
//! assert_eq!(a, a2);
//! # }
//! ```
//!
//! Finally, to create a `Scalar` with a specific bit-pattern
//! (e.g., for compatibility with X/Ed25519
//! ["clamping"](https://github.com/isislovecruft/ed25519-dalek/blob/f790bd2ce/src/ed25519.rs#L349)),
//! use [`Scalar::from_bits`](struct.Scalar.html#method.from_bits). This
//! constructs a scalar with exactly the bit pattern given, without any
//! assurances as to reduction modulo the group order:
//!
//! ```
//! use curve25519_dalek::scalar::Scalar;
//!
//! let l_plus_two_bytes: [u8; 32] = [
//!    0xef, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
//!    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
//!    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
//! ];
//! let a: Scalar = Scalar::from_bits(l_plus_two_bytes);
//!
//! let two: Scalar = Scalar::one() + Scalar::one();
//!
//! assert!(a != two);              // the scalar is not reduced (mod l)…
//! assert!(! a.is_canonical());    // …and therefore is not canonical.
//! assert!(a.reduce() == two);     // if we were to reduce it manually, it would be.
//! ```
//!
//! The resulting `Scalar` has exactly the specified bit pattern,
//! **except for the highest bit, which will be set to 0**.

use core::borrow::Borrow;
use core::cmp::{Eq, PartialEq};
use core::fmt::Debug;
use core::iter::{Product, Sum};
use core::ops::Index;
use core::ops::Neg;
use core::ops::{Add, AddAssign};
use core::ops::{Mul, MulAssign};
use core::ops::{Sub, SubAssign};

#[allow(unused_imports)]
use std::prelude::*;

#[cfg(not(target_arch = "bpf"))]
use rand_core::{CryptoRng, RngCore};

use digest::generic_array::typenum::U64;
use digest::Digest;

use subtle::Choice;
use subtle::ConditionallySelectable;
use subtle::ConstantTimeEq;

use zeroize::Zeroize;

use crate::backend;
use crate::backend::serial::u64::constants;

/// An `UnpackedScalar` represents an element of the field GF(l), optimized for speed.
///
/// This is a type alias for one of the scalar types in the `backend`
/// module.
type UnpackedScalar = backend::serial::u64::scalar::Scalar52;


/// The `Scalar` struct holds an integer \\(s < 2\^{255} \\) which
/// represents an element of \\(\mathbb Z / \ell\\).
#[derive(Copy, Clone, Hash)]
pub struct Scalar {
    /// `bytes` is a little-endian byte encoding of an integer representing a scalar modulo the
    /// group order.
    ///
    /// # Invariant
    ///
    /// The integer representing this scalar must be bounded above by \\(2\^{255}\\), or
    /// equivalently the high bit of `bytes[31]` must be zero.
    ///
    /// This ensures that there is room for a carry bit when computing a NAF representation.
    //
    // XXX This is pub(crate) so we can write literal constants.  If const fns were stable, we could
    //     make the Scalar constructors const fns and use those instead.
    pub bytes: [u8; 32],
}

impl Scalar {
    /// Construct a `Scalar` by reducing a 256-bit little-endian integer
    /// modulo the group order \\( \ell \\).
    pub fn from_bytes_mod_order(bytes: [u8; 32]) -> Scalar {
        // Temporarily allow s_unreduced.bytes > 2^255 ...
        let s_unreduced = Scalar{bytes};

        // Then reduce mod the group order and return the reduced representative.
        let s = s_unreduced.reduce();
        debug_assert_eq!(0u8, s[31] >> 7);

        s
    }

    /// Construct a `Scalar` by reducing a 512-bit little-endian integer
    /// modulo the group order \\( \ell \\).
    pub fn from_bytes_mod_order_wide(input: &[u8; 64]) -> Scalar {
        UnpackedScalar::from_bytes_wide(input).pack()
    }

    /// Attempt to construct a `Scalar` from a canonical byte representation.
    ///
    /// # Return
    ///
    /// - `Some(s)`, where `s` is the `Scalar` corresponding to `bytes`,
    ///   if `bytes` is a canonical byte representation;
    /// - `None` if `bytes` is not a canonical byte representation.
    pub fn from_canonical_bytes(bytes: [u8; 32]) -> Option<Scalar> {
        // Check that the high bit is not set
        if (bytes[31] >> 7) != 0u8 { return None; }
        let candidate = Scalar::from_bits(bytes);

        if candidate.is_canonical() {
            Some(candidate)
        } else {
            None
        }
    }

    /// Construct a `Scalar` from the low 255 bits of a 256-bit integer.
    ///
    /// This function is intended for applications like X25519 which
    /// require specific bit-patterns when performing scalar
    /// multiplication.
    pub const fn from_bits(bytes: [u8; 32]) -> Scalar {
        let mut s = Scalar{bytes};
        // Ensure that s < 2^255 by masking the high bit
        s.bytes[31] &= 0b0111_1111;

        s
    }
}

impl Debug for Scalar {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "Scalar{{\n\tbytes: {:?},\n}}", &self.bytes)
    }
}

impl Eq for Scalar {}
impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1u8
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl Index<usize> for Scalar {
    type Output = u8;

    /// Index the bytes of the representative for this `Scalar`.  Mutation is not permitted.
    fn index(&self, _index: usize) -> &u8 {
        &(self.bytes[_index])
    }
}

impl<'b> MulAssign<&'b Scalar> for Scalar {
    fn mul_assign(&mut self, _rhs: &'b Scalar) {
        *self = UnpackedScalar::mul(&self.unpack(), &_rhs.unpack()).pack();
    }
}

define_mul_assign_variants!(LHS = Scalar, RHS = Scalar);

impl<'a, 'b> Mul<&'b Scalar> for &'a Scalar {
    type Output = Scalar;
    fn mul(self, _rhs: &'b Scalar) -> Scalar {
        UnpackedScalar::mul(&self.unpack(), &_rhs.unpack()).pack()
    }
}

define_mul_variants!(LHS = Scalar, RHS = Scalar, Output = Scalar);

impl<'b> AddAssign<&'b Scalar> for Scalar {
    fn add_assign(&mut self, _rhs: &'b Scalar) {
        *self = *self + _rhs;
    }
}

define_add_assign_variants!(LHS = Scalar, RHS = Scalar);

impl<'a, 'b> Add<&'b Scalar> for &'a Scalar {
    type Output = Scalar;
    #[allow(non_snake_case)]
    fn add(self, _rhs: &'b Scalar) -> Scalar {
        // The UnpackedScalar::add function produces reduced outputs
        // if the inputs are reduced.  However, these inputs may not
        // be reduced -- they might come from Scalar::from_bits.  So
        // after computing the sum, we explicitly reduce it mod l
        // before repacking.
        let sum = UnpackedScalar::add(&self.unpack(), &_rhs.unpack());
        let sum_R = UnpackedScalar::mul_internal(&sum, &constants::R);
        let sum_mod_l = UnpackedScalar::montgomery_reduce(&sum_R);
        sum_mod_l.pack()
    }
}

define_add_variants!(LHS = Scalar, RHS = Scalar, Output = Scalar);

impl<'b> SubAssign<&'b Scalar> for Scalar {
    fn sub_assign(&mut self, _rhs: &'b Scalar) {
        *self = *self - _rhs;
    }
}

define_sub_assign_variants!(LHS = Scalar, RHS = Scalar);

impl<'a, 'b> Sub<&'b Scalar> for &'a Scalar {
    type Output = Scalar;
    #[allow(non_snake_case)]
    fn sub(self, rhs: &'b Scalar) -> Scalar {
        // The UnpackedScalar::sub function requires reduced inputs
        // and produces reduced output. However, these inputs may not
        // be reduced -- they might come from Scalar::from_bits.  So
        // we explicitly reduce the inputs.
        let self_R = UnpackedScalar::mul_internal(&self.unpack(), &constants::R);
        let self_mod_l = UnpackedScalar::montgomery_reduce(&self_R);
        let rhs_R = UnpackedScalar::mul_internal(&rhs.unpack(), &constants::R);
        let rhs_mod_l = UnpackedScalar::montgomery_reduce(&rhs_R);

        UnpackedScalar::sub(&self_mod_l, &rhs_mod_l).pack()
    }
}

define_sub_variants!(LHS = Scalar, RHS = Scalar, Output = Scalar);

impl<'a> Neg for &'a Scalar {
    type Output = Scalar;
    #[allow(non_snake_case)]
    fn neg(self) -> Scalar {
        let self_R = UnpackedScalar::mul_internal(&self.unpack(), &constants::R);
        let self_mod_l = UnpackedScalar::montgomery_reduce(&self_R);
        UnpackedScalar::sub(&UnpackedScalar::zero(), &self_mod_l).pack()
    }
}

impl<'a> Neg for Scalar {
    type Output = Scalar;
    fn neg(self) -> Scalar {
        -&self
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            bytes[i] = u8::conditional_select(&a.bytes[i], &b.bytes[i], choice);
        }
        Scalar { bytes }
    }
}

#[cfg(feature = "serde")]
use serde::{self, Serialize, Deserialize, Serializer, Deserializer};
#[cfg(feature = "serde")]
use serde::de::Visitor;

#[cfg(feature = "serde")]
impl Serialize for Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        use serde::ser::SerializeTuple;
        let mut tup = serializer.serialize_tuple(32)?;
        for byte in self.as_bytes().iter() {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        struct ScalarVisitor;

        impl<'de> Visitor<'de> for ScalarVisitor {
            type Value = Scalar;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a valid point in Edwards y + sign format")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Scalar, A::Error>
                where A: serde::de::SeqAccess<'de>
            {
                let mut bytes = [0u8; 32];
                for i in 0..32 {
                    bytes[i] = seq.next_element()?
                        .ok_or(serde::de::Error::invalid_length(i, &"expected 32 bytes"))?;
                }
                Scalar::from_canonical_bytes(bytes)
                    .ok_or(serde::de::Error::custom(
                        &"scalar was not canonically encoded"
                    ))
            }
        }

        deserializer.deserialize_tuple(32, ScalarVisitor)
    }
}

impl<T> Product<T> for Scalar
where
    T: Borrow<Scalar>
{
    fn product<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>
    {
        iter.fold(Scalar::one(), |acc, item| acc * item.borrow())
    }
}

impl<T> Sum<T> for Scalar
where
    T: Borrow<Scalar>
{
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>
    {
        iter.fold(Scalar::zero(), |acc, item| acc + item.borrow())
    }
}

impl Default for Scalar {
    fn default() -> Scalar {
        Scalar::zero()
    }
}

impl From<u8> for Scalar {
    fn from(x: u8) -> Scalar {
        let mut s_bytes = [0u8; 32];
        s_bytes[0] = x;
        Scalar{ bytes: s_bytes }
    }
}

impl From<u16> for Scalar {
    fn from(x: u16) -> Scalar {
        use byteorder::{ByteOrder, LittleEndian};
        let mut s_bytes = [0u8; 32];
        LittleEndian::write_u16(&mut s_bytes, x);
        Scalar{ bytes: s_bytes }
    }
}

impl From<u32> for Scalar {
    fn from(x: u32) -> Scalar {
        use byteorder::{ByteOrder, LittleEndian};
        let mut s_bytes = [0u8; 32];
        LittleEndian::write_u32(&mut s_bytes, x);
        Scalar{ bytes: s_bytes }
    }
}

impl From<u64> for Scalar {
    /// Construct a scalar from the given `u64`.
    ///
    /// # Inputs
    ///
    /// An `u64` to convert to a `Scalar`.
    ///
    /// # Returns
    ///
    /// A `Scalar` corresponding to the input `u64`.
    ///
    /// # Example
    ///
    /// ```
    /// use curve25519_dalek::scalar::Scalar;
    ///
    /// let fourtytwo = Scalar::from(42u64);
    /// let six = Scalar::from(6u64);
    /// let seven = Scalar::from(7u64);
    ///
    /// assert!(fourtytwo == six * seven);
    /// ```
    fn from(x: u64) -> Scalar {
        use byteorder::{ByteOrder, LittleEndian};
        let mut s_bytes = [0u8; 32];
        LittleEndian::write_u64(&mut s_bytes, x);
        Scalar{ bytes: s_bytes }
    }
}

impl From<u128> for Scalar {
    fn from(x: u128) -> Scalar {
        use byteorder::{ByteOrder, LittleEndian};
        let mut s_bytes = [0u8; 32];
        LittleEndian::write_u128(&mut s_bytes, x);
        Scalar{ bytes: s_bytes }
    }
}

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl Scalar {
    /// Return a `Scalar` chosen uniformly at random using a user-provided RNG.
    ///
    /// # Inputs
    ///
    /// * `rng`: any RNG which implements the `RngCore + CryptoRng` interface.
    ///
    /// # Returns
    ///
    /// A random scalar within ℤ/lℤ.
    ///
    /// # Example
    ///
    /// ```
    /// extern crate rand_core;
    /// # extern crate curve25519_dalek;
    /// #
    /// # fn main() {
    /// use curve25519_dalek::scalar::Scalar;
    ///
    /// use rand_core::OsRng;
    ///
    /// let mut csprng = OsRng;
    /// let a: Scalar = Scalar::random(&mut csprng);
    /// # }
    #[cfg(not(target_arch = "bpf"))]
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut scalar_bytes = [0u8; 64];
        rng.fill_bytes(&mut scalar_bytes);
        Scalar::from_bytes_mod_order_wide(&scalar_bytes)
    }

    /// Hash a slice of bytes into a scalar.
    ///
    /// Takes a type parameter `D`, which is any `Digest` producing 64
    /// bytes (512 bits) of output.
    ///
    /// Convenience wrapper around `from_hash`.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate curve25519_dalek;
    /// # use curve25519_dalek::scalar::Scalar;
    /// extern crate sha2;
    ///
    /// use sha2::Sha512;
    ///
    /// # // Need fn main() here in comment so the doctest compiles
    /// # // See https://doc.rust-lang.org/book/documentation.html#documentation-as-tests
    /// # fn main() {
    /// let msg = "To really appreciate architecture, you may even need to commit a murder";
    /// let s = Scalar::hash_from_bytes::<Sha512>(msg.as_bytes());
    /// # }
    /// ```
    pub fn hash_from_bytes<D>(input: &[u8]) -> Scalar
        where D: Digest<OutputSize = U64> + Default
    {
        let mut hash = D::default();
        hash.update(input);
        Scalar::from_hash(hash)
    }

    /// Construct a scalar from an existing `Digest` instance.
    ///
    /// Use this instead of `hash_from_bytes` if it is more convenient
    /// to stream data into the `Digest` than to pass a single byte
    /// slice.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate curve25519_dalek;
    /// # use curve25519_dalek::scalar::Scalar;
    /// extern crate sha2;
    ///
    /// use sha2::Digest;
    /// use sha2::Sha512;
    ///
    /// # fn main() {
    /// let mut h = Sha512::new()
    ///     .chain("To really appreciate architecture, you may even need to commit a murder.")
    ///     .chain("While the programs used for The Manhattan Transcripts are of the most extreme")
    ///     .chain("nature, they also parallel the most common formula plot: the archetype of")
    ///     .chain("murder. Other phantasms were occasionally used to underline the fact that")
    ///     .chain("perhaps all architecture, rather than being about functional standards, is")
    ///     .chain("about love and death.");
    ///
    /// let s = Scalar::from_hash(h);
    ///
    /// println!("{:?}", s.to_bytes());
    /// assert!(s == Scalar::from_bits([ 21,  88, 208, 252,  63, 122, 210, 152,
    ///                                 154,  38,  15,  23,  16, 167,  80, 150,
    ///                                 192, 221,  77, 226,  62,  25, 224, 148,
    ///                                 239,  48, 176,  10, 185,  69, 168,  11, ]));
    /// # }
    /// ```
    pub fn from_hash<D>(hash: D) -> Scalar
        where D: Digest<OutputSize = U64>
    {
        let mut output = [0u8; 64];
        output.copy_from_slice(hash.finalize().as_slice());
        Scalar::from_bytes_mod_order_wide(&output)
    }

    /// Convert this `Scalar` to its underlying sequence of bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use curve25519_dalek::scalar::Scalar;
    ///
    /// let s: Scalar = Scalar::zero();
    ///
    /// assert!(s.to_bytes() == [0u8; 32]);
    /// ```
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// View the little-endian byte encoding of the integer representing this Scalar.
    ///
    /// # Example
    ///
    /// ```
    /// use curve25519_dalek::scalar::Scalar;
    ///
    /// let s: Scalar = Scalar::zero();
    ///
    /// assert!(s.as_bytes() == &[0u8; 32]);
    /// ```
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Construct the scalar \\( 0 \\).
    pub fn zero() -> Self {
        Scalar { bytes: [0u8; 32]}
    }

    /// Construct the scalar \\( 1 \\).
    pub fn one() -> Self {
        Scalar {
            bytes: [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        }
    }

    /// Given a nonzero `Scalar`, compute its multiplicative inverse.
    ///
    /// # Warning
    ///
    /// `self` **MUST** be nonzero.  If you cannot
    /// *prove* that this is the case, you **SHOULD NOT USE THIS
    /// FUNCTION**.
    ///
    /// # Returns
    ///
    /// The multiplicative inverse of the this `Scalar`.
    ///
    /// # Example
    ///
    /// ```
    /// use curve25519_dalek::scalar::Scalar;
    ///
    /// // x = 2238329342913194256032495932344128051776374960164957527413114840482143558222
    /// let X: Scalar = Scalar::from_bytes_mod_order([
    ///         0x4e, 0x5a, 0xb4, 0x34, 0x5d, 0x47, 0x08, 0x84,
    ///         0x59, 0x13, 0xb4, 0x64, 0x1b, 0xc2, 0x7d, 0x52,
    ///         0x52, 0xa5, 0x85, 0x10, 0x1b, 0xcc, 0x42, 0x44,
    ///         0xd4, 0x49, 0xf4, 0xa8, 0x79, 0xd9, 0xf2, 0x04,
    ///     ]);
    /// // 1/x = 6859937278830797291664592131120606308688036382723378951768035303146619657244
    /// let XINV: Scalar = Scalar::from_bytes_mod_order([
    ///         0x1c, 0xdc, 0x17, 0xfc, 0xe0, 0xe9, 0xa5, 0xbb,
    ///         0xd9, 0x24, 0x7e, 0x56, 0xbb, 0x01, 0x63, 0x47,
    ///         0xbb, 0xba, 0x31, 0xed, 0xd5, 0xa9, 0xbb, 0x96,
    ///         0xd5, 0x0b, 0xcd, 0x7a, 0x3f, 0x96, 0x2a, 0x0f,
    ///     ]);
    ///
    /// let inv_X: Scalar = X.invert();
    /// assert!(XINV == inv_X);
    /// let should_be_one: Scalar = &inv_X * &X;
    /// assert!(should_be_one == Scalar::one());
    /// ```
    pub fn invert(&self) -> Scalar {
        self.unpack().invert().pack()
    }

    /// Given a slice of nonzero (possibly secret) `Scalar`s,
    /// compute their inverses in a batch.
    ///
    /// # Return
    ///
    /// Each element of `inputs` is replaced by its inverse.
    ///
    /// The product of all inverses is returned.
    ///
    /// # Warning
    ///
    /// All input `Scalars` **MUST** be nonzero.  If you cannot
    /// *prove* that this is the case, you **SHOULD NOT USE THIS
    /// FUNCTION**.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate curve25519_dalek;
    /// # use curve25519_dalek::scalar::Scalar;
    /// # fn main() {
    /// let mut scalars = [
    ///     Scalar::from(3u64),
    ///     Scalar::from(5u64),
    ///     Scalar::from(7u64),
    ///     Scalar::from(11u64),
    /// ];
    ///
    /// let allinv = Scalar::batch_invert(&mut scalars);
    ///
    /// assert_eq!(allinv, Scalar::from(3*5*7*11u64).invert());
    /// assert_eq!(scalars[0], Scalar::from(3u64).invert());
    /// assert_eq!(scalars[1], Scalar::from(5u64).invert());
    /// assert_eq!(scalars[2], Scalar::from(7u64).invert());
    /// assert_eq!(scalars[3], Scalar::from(11u64).invert());
    /// # }
    /// ```
    #[cfg(feature = "alloc")]
    pub fn batch_invert(inputs: &mut [Scalar]) -> Scalar {
        // This code is essentially identical to the FieldElement
        // implementation, and is documented there.  Unfortunately,
        // it's not easy to write it generically, since here we want
        // to use `UnpackedScalar`s internally, and `Scalar`s
        // externally, but there's no corresponding distinction for
        // field elements.

        use zeroize::Zeroizing;

        let n = inputs.len();
        let one: UnpackedScalar = Scalar::one().unpack().to_montgomery();

        // Place scratch storage in a Zeroizing wrapper to wipe it when
        // we pass out of scope.
        let scratch_vec = vec![one; n];
        let mut scratch = Zeroizing::new(scratch_vec);

        // Keep an accumulator of all of the previous products
        let mut acc = Scalar::one().unpack().to_montgomery();

        // Pass through the input vector, recording the previous
        // products in the scratch space
        for (input, scratch) in inputs.iter_mut().zip(scratch.iter_mut()) {
            *scratch = acc;

            // Avoid unnecessary Montgomery multiplication in second pass by
            // keeping inputs in Montgomery form
            let tmp = input.unpack().to_montgomery();
            *input = tmp.pack();
            acc = UnpackedScalar::montgomery_mul(&acc, &tmp);
        }

        // acc is nonzero iff all inputs are nonzero
        debug_assert!(acc.pack() != Scalar::zero());

        // Compute the inverse of all products
        acc = acc.montgomery_invert().from_montgomery();

        // We need to return the product of all inverses later
        let ret = acc.pack();

        // Pass through the vector backwards to compute the inverses
        // in place
        for (input, scratch) in inputs.iter_mut().rev().zip(scratch.iter().rev()) {
            let tmp = UnpackedScalar::montgomery_mul(&acc, &input.unpack());
            *input = UnpackedScalar::montgomery_mul(&acc, &scratch).pack();
            acc = tmp;
        }

        ret
    }

    /// Write this scalar in radix 16, with coefficients in \\([-8,8)\\),
    /// i.e., compute \\(a\_i\\) such that
    /// $$
    ///    a = a\_0 + a\_1 16\^1 + \cdots + a_{63} 16\^{63},
    /// $$
    /// with \\(-8 \leq a_i < 8\\) for \\(0 \leq i < 63\\) and \\(-8 \leq a_{63} \leq 8\\).
    pub(crate) fn to_radix_16(&self) -> [i8; 64] {
        debug_assert!(self[31] <= 127);
        let mut output = [0i8; 64];

        // Step 1: change radix.
        // Convert from radix 256 (bytes) to radix 16 (nibbles)
        #[inline(always)]
        fn bot_half(x: u8) -> u8 { (x >> 0) & 15 }
        #[inline(always)]
        fn top_half(x: u8) -> u8 { (x >> 4) & 15 }

        for i in 0..32 {
            output[2*i  ] = bot_half(self[i]) as i8;
            output[2*i+1] = top_half(self[i]) as i8;
        }
        // Precondition note: since self[31] <= 127, output[63] <= 7

        // Step 2: recenter coefficients from [0,16) to [-8,8)
        for i in 0..63 {
            let carry    = (output[i] + 8) >> 4;
            output[i  ] -= carry << 4;
            output[i+1] += carry;
        }
        // Precondition note: output[63] is not recentered.  It
        // increases by carry <= 1.  Thus output[63] <= 8.

        output
    }

    /// Unpack this `Scalar` to an `UnpackedScalar` for faster arithmetic.
    pub(crate) fn unpack(&self) -> UnpackedScalar {
        UnpackedScalar::from_bytes(&self.bytes)
    }

    /// Reduce this `Scalar` modulo \\(\ell\\).
    #[allow(non_snake_case)]
    pub fn reduce(&self) -> Scalar {
        let x = self.unpack();
        let xR = UnpackedScalar::mul_internal(&x, &constants::R);
        let x_mod_l = UnpackedScalar::montgomery_reduce(&xR);
        x_mod_l.pack()
    }

    /// Check whether this `Scalar` is the canonical representative mod \\(\ell\\).
    ///
    /// This is intended for uses like input validation, where variable-time code is acceptable.
    ///
    /// ```
    /// # extern crate curve25519_dalek;
    /// # extern crate subtle;
    /// # use curve25519_dalek::scalar::Scalar;
    /// # use subtle::ConditionallySelectable;
    /// # fn main() {
    /// // 2^255 - 1, since `from_bits` clears the high bit
    /// let _2_255_minus_1 = Scalar::from_bits([0xff;32]);
    /// assert!(!_2_255_minus_1.is_canonical());
    ///
    /// let reduced = _2_255_minus_1.reduce();
    /// assert!(reduced.is_canonical());
    /// # }
    /// ```
    pub fn is_canonical(&self) -> bool {
        *self == self.reduce()
    }
}

impl UnpackedScalar {
    /// Pack the limbs of this `UnpackedScalar` into a `Scalar`.
    fn pack(&self) -> Scalar {
        Scalar{ bytes: self.to_bytes() }
    }

    /// Inverts an UnpackedScalar in Montgomery form.
    pub fn montgomery_invert(&self) -> UnpackedScalar {
        // Uses the addition chain from
        // https://briansmith.org/ecc-inversion-addition-chains-01#curve25519_scalar_inversion
        let    _1 = self;
        let   _10 = _1.montgomery_square();
        let  _100 = _10.montgomery_square();
        let   _11 = UnpackedScalar::montgomery_mul(&_10,     &_1);
        let  _101 = UnpackedScalar::montgomery_mul(&_10,    &_11);
        let  _111 = UnpackedScalar::montgomery_mul(&_10,   &_101);
        let _1001 = UnpackedScalar::montgomery_mul(&_10,   &_111);
        let _1011 = UnpackedScalar::montgomery_mul(&_10,  &_1001);
        let _1111 = UnpackedScalar::montgomery_mul(&_100, &_1011);

        // _10000
        let mut y = UnpackedScalar::montgomery_mul(&_1111, &_1);

        #[inline]
        fn square_multiply(y: &mut UnpackedScalar, squarings: usize, x: &UnpackedScalar) {
            for _ in 0..squarings {
                *y = y.montgomery_square();
            }
            *y = UnpackedScalar::montgomery_mul(y, x);
        }

        square_multiply(&mut y, 123 + 3, &_101);
        square_multiply(&mut y,   2 + 2, &_11);
        square_multiply(&mut y,   1 + 4, &_1111);
        square_multiply(&mut y,   1 + 4, &_1111);
        square_multiply(&mut y,       4, &_1001);
        square_multiply(&mut y,       2, &_11);
        square_multiply(&mut y,   1 + 4, &_1111);
        square_multiply(&mut y,   1 + 3, &_101);
        square_multiply(&mut y,   3 + 3, &_101);
        square_multiply(&mut y,       3, &_111);
        square_multiply(&mut y,   1 + 4, &_1111);
        square_multiply(&mut y,   2 + 3, &_111);
        square_multiply(&mut y,   2 + 2, &_11);
        square_multiply(&mut y,   1 + 4, &_1011);
        square_multiply(&mut y,   2 + 4, &_1011);
        square_multiply(&mut y,   6 + 4, &_1001);
        square_multiply(&mut y,   2 + 2, &_11);
        square_multiply(&mut y,   3 + 2, &_11);
        square_multiply(&mut y,   3 + 2, &_11);
        square_multiply(&mut y,   1 + 4, &_1001);
        square_multiply(&mut y,   1 + 3, &_111);
        square_multiply(&mut y,   2 + 4, &_1111);
        square_multiply(&mut y,   1 + 4, &_1011);
        square_multiply(&mut y,       3, &_101);
        square_multiply(&mut y,   2 + 4, &_1111);
        square_multiply(&mut y,       3, &_101);
        square_multiply(&mut y,   1 + 2, &_11);

        y
    }

    /// Inverts an UnpackedScalar not in Montgomery form.
    pub fn invert(&self) -> UnpackedScalar {
        self.to_montgomery().montgomery_invert().from_montgomery()
    }
}
