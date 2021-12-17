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
// use super::scalar::Scalar52;
// use edwards::{EdwardsBasepointTable, EdwardsPoint};
// use window::{LookupTable, NafLookupTable8};

/// The value of minus one, equal to `-&FieldElement::one()`
pub(crate) const MINUS_ONE: FieldElement51 = FieldElement51([
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
pub(crate) const SQRT_AD_MINUS_ONE: FieldElement51 = FieldElement51([
    2241493124984347,
    425987919032274,
    2207028919301688,
    1220490630685848,
    974799131293748,
]);

/// `= 1/sqrt(a-d)`, where `a = -1 (mod p)`, `d` are the Edwards curve parameters.
pub(crate) const INVSQRT_A_MINUS_D: FieldElement51 = FieldElement51([
    278908739862762,
    821645201101625,
    8113234426968,
    1777959178193151,
    2118520810568447,
]);

/// Precomputed value of one of the square roots of -1 (mod p)
pub(crate) const SQRT_M1: FieldElement51 = FieldElement51([
    1718705420411056,
    234908883556509,
    2233514472574048,
    2117202627021982,
    765476049583133,
]);

