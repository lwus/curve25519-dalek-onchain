// -*- mode: rust; -*-
//
// This file is part of curve25519-dalek.
// Copyright (c) 2016-2021 isis lovecruft
// Copyright (c) 2016-2019 Henry de Valence
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>
// - Henry de Valence <hdevalence@hdevalence.ca>

//! This module contains backend-specific constant values, such as the 64-bit limbs of curve constants.

// use backend::serial::curve_models::AffineNielsPoint;
use super::field::FieldElement51;
use super::scalar::Scalar52;
// use edwards::{EdwardsBasepointTable, EdwardsPoint};
// use window::{LookupTable, NafLookupTable8};

/// The value of minus one, equal to `-&FieldElement::one()`
pub const MINUS_ONE: FieldElement51 = FieldElement51([
    2251799813685228,
    2251799813685247,
    2251799813685247,
    2251799813685247,
    2251799813685247
]);

/// Edwards `d` value, equal to `-121665/121666 mod p`.
pub(crate) const EDWARDS_D: FieldElement51 = FieldElement51([
    929955233495203,
    466365720129213,
    1662059464998953,
    2033849074728123,
    1442794654840575,
]);

/// Edwards `2*d` value, equal to `2*(-121665/121666) mod p`.
pub(crate) const EDWARDS_D2: FieldElement51 = FieldElement51([
    1859910466990425,
    932731440258426,
    1072319116312658,
    1815898335770999,
    633789495995903,
]);

/// Precomputed value of one of the square roots of -1 (mod p)
pub(crate) const SQRT_M1: FieldElement51 = FieldElement51([
    1718705420411056,
    234908883556509,
    2233514472574048,
    2117202627021982,
    765476049583133,
]);

/// One minus edwards `d` value squared, equal to `(1 - (-121665/121666) mod p) pow 2`
pub(crate) const ONE_MINUS_EDWARDS_D_SQUARED: FieldElement51 = FieldElement51([
    1136626929484150,
    1998550399581263,
    496427632559748,
    118527312129759,
    45110755273534
]);

/// Edwards `d` value minus one squared, equal to `(((-121665/121666) mod p) - 1) pow 2`
pub(crate) const EDWARDS_D_MINUS_ONE_SQUARED: FieldElement51 = FieldElement51([
    1507062230895904,
    1572317787530805,
    683053064812840,
    317374165784489,
    1572899562415810
]);

/// `= sqrt(a*d - 1)`, where `a = -1 (mod p)`, `d` are the Edwards curve parameters.
pub const SQRT_AD_MINUS_ONE: FieldElement51 = FieldElement51([
    2241493124984347,
    425987919032274,
    2207028919301688,
    1220490630685848,
    974799131293748,
]);


/// `MONTGOMERY_A` is equal to 486662, which is a constant of the curve equation
/// for Curve25519 in its Montgomery form. (This is used internally within the
/// Elligator map.)
pub(crate) const MONTGOMERY_A: FieldElement51 = FieldElement51([486662, 0, 0, 0, 0]);

/// `MONTGOMERY_A_NEG` is equal to -486662. (This is used internally within the
/// Elligator map.)
pub(crate) const MONTGOMERY_A_NEG: FieldElement51 = FieldElement51([
    2251799813198567,
    2251799813685247,
    2251799813685247,
    2251799813685247,
    2251799813685247,
]);

/// `L` is the order of base point, i.e. 2^252 + 27742317777372353535851937790883648493
pub(crate) const L: Scalar52 = Scalar52([
    0x0002631a5cf5d3ed,
    0x000dea2f79cd6581,
    0x000000000014def9,
    0x0000000000000000,
    0x0000100000000000,
]);

/// `L` * `LFACTOR` = -1 (mod 2^52)
pub(crate) const LFACTOR: u64 = 0x51da312547e1b;

/// `R` = R % L where R = 2^260
pub(crate) const R: Scalar52 = Scalar52([
    0x000f48bd6721e6ed,
    0x0003bab5ac67e45a,
    0x000fffffeb35e51b,
    0x000fffffffffffff,
    0x00000fffffffffff,
]);

/// `RR` = (R^2) % L where R = 2^260
pub(crate) const RR: Scalar52 = Scalar52([
    0x0009d265e952d13b,
    0x000d63c715bea69f,
    0x0005be65cb687604,
    0x0003dceec73d217f,
    0x000009411b7c309a,
]);

