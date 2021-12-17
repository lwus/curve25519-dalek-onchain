
use core::cmp::{Eq, PartialEq};

use subtle::Choice;
use subtle::ConstantTimeEq;

use crate::backend;

pub use backend::serial::u64::field::*;

pub type FieldElement = backend::serial::u64::field::FieldElement51;

impl Eq for FieldElement {}

impl PartialEq for FieldElement {
    fn eq(&self, other: &FieldElement) -> bool {
        self.ct_eq(other).unwrap_u8() == 1u8
    }
}

impl ConstantTimeEq for FieldElement {
    /// Test equality between two `FieldElement`s.  Since the
    /// internal representation is not canonical, the field elements
    /// are normalized to wire format before comparison.
    fn ct_eq(&self, other: &FieldElement) -> Choice {
        self.to_bytes().ct_eq(&other.to_bytes())
    }
}

impl FieldElement {
    /// Compute (x^(2^5-1), x^11)
    #[inline(never)]
    pub fn pow251(
        x: &FieldElement,
    ) -> (FieldElement, FieldElement) {
        // Temporary t_i                      Nonzero bits of e_i
        let t0  = x.square();              // 1         e_0 = 2^1
        let t1  = t0.square().square();    // 3         e_1 = 2^3
        let t2  = x * &t1;                 // 3,0       e_2 = 2^3 + 2^0
        let t3  = &t0 * &t2;               // 3,1,0
        let t4  = t3.square();             // 4,2,1
        let t5  = &t2 * &t4;               // 4,3,2,1,0

        (t5, t3)
    }

    /// Compute (x^(2^200-1), x^(2^50-1), x^11)
    #[inline(never)]
    pub fn pow22001(
        x: &FieldElement,
    ) -> (FieldElement, FieldElement, FieldElement) {
        let (t5, t3) = FieldElement::pow251(x);

        // Temporary t_i                      Nonzero bits of e_i
        let t6  = t5.pow2k(5);             // 9,8,7,6,5
        let t7  = &t6 * &t5;               // 9,8,7,6,5,4,3,2,1,0
        let t8  = t7.pow2k(10);            // 19..10
        let t9  = &t8 * &t7;               // 19..0
        let t10 = t9.pow2k(20);            // 39..20
        let t11 = &t10 * &t9;              // 39..0
        let t12 = t11.pow2k(10);           // 49..10
        let t13 = &t12 * &t7;              // 49..0
        let t14 = t13.pow2k(50);           // 99..50
        let t15 = &t14 * &t13;             // 99..0
        let t16 = t15.pow2k(100);          // 199..100
        let t17 = &t16 * &t15;             // 199..0

        (t17, t13, t3)
    }

    /// Compute x^(2^250-1) from (x^(2^200-1), x^(2^50-1))
    #[inline(never)]
    pub fn pow22501(
        t17: &FieldElement,
        t13: &FieldElement,
    ) -> FieldElement {
        // Temporary t_i                      Nonzero bits of e_i
        let t18 = t17.pow2k(50);           // 249..50
        let t19 = &t18 * &t13;             // 249..0

        t19
    }
}
