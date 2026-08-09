//! Range proof parameter selection.
//!
//! Port of `src/range-proof-params.ts`, which itself ports Veil Core's
//! `SelectRangeProofParameters` from `veil/ringct/blind.cpp`.
//!
//! Choosing an exponent and a bit width shrinks the proof, and randomizing both
//! keeps the proof size from leaking the exact value.
//!
//! The TypeScript original names its bit-counting helpers backwards: its
//! `countLeadingZeros` walks up from the least significant bit, which is a
//! trailing-zero count. This port uses the standard names and the same
//! arithmetic.

use rand::Rng;

/// Parameters controlling range proof generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeProofParams {
    /// Lower bound of the proven range.
    pub min_value: u64,
    /// Base-10 exponent applied before proving.
    pub exponent: i32,
    /// Minimum number of bits to prove.
    pub min_bits: i32,
}

impl Default for RangeProofParams {
    fn default() -> Self {
        standard_range_proof_params()
    }
}

/// Compute `base^exp`, saturating rather than overflowing.
fn ipow(base: u64, exp: u32) -> u64 {
    base.checked_pow(exp).unwrap_or(u64::MAX)
}

/// Pick proof parameters for `value`, randomizing within the safe range.
///
/// The randomization is deliberate: two proofs over the same value should not
/// be byte-identical, and proof size should not map cleanly back to magnitude.
pub fn select_range_proof_parameters(value: u64) -> RangeProofParams {
    let mut rng = rand::thread_rng();

    // A zero value carries no magnitude to hide, so pick freely.
    if value == 0 {
        let exponent = rng.gen_range(0..5);
        let mut min_bits = 32;

        // Occasionally pad the width for extra ambiguity.
        if rng.gen_range(0..10) == 0 {
            min_bits += rng.gen_range(0..5);
        }

        return RangeProofParams {
            min_value: 0,
            exponent,
            min_bits,
        };
    }

    let mut min_bits: i32 = 32;

    // How many times the value divides by 10 bounds the usable exponent.
    let mut n_test = value;
    let mut n_div10: u32 = 0;
    while n_test.is_multiple_of(10) {
        n_div10 += 1;
        n_test /= 10;
    }

    // Choose an exponent between half the maximum and the maximum.
    let e_min = n_div10 / 2;
    let exponent = e_min + rng.gen_range(0..(n_div10.saturating_sub(e_min)).max(1));

    // Recompute the bit width of the reduced value.
    let reduced = value / ipow(10, exponent);
    let bits_req = 64 - i32::try_from(reduced.leading_zeros()).unwrap_or(64);

    if bits_req > 32 {
        min_bits = bits_req;
    }

    // Borromean ring signatures pack most efficiently at a radix-4 boundary.
    while min_bits < 63 && min_bits % 4 != 0 {
        min_bits += 1;
    }

    RangeProofParams {
        min_value: 0,
        exponent: i32::try_from(exponent).unwrap_or(0),
        min_bits,
    }
}

/// The common fixed parameters, for when a deterministic proof is preferable.
pub fn standard_range_proof_params() -> RangeProofParams {
    RangeProofParams {
        min_value: 0,
        exponent: 2,
        min_bits: 32,
    }
}

/// Check that parameters fall within the ranges the proof system accepts.
pub fn validate_range_proof_params(params: &RangeProofParams) -> bool {
    (0..=18).contains(&params.exponent) && (0..=64).contains(&params.min_bits)
}

/// Estimate the size of a proof, in bytes, from its parameters.
///
/// This is a rough guide for fee estimation, not an exact figure.
pub fn estimate_proof_size(params: &RangeProofParams) -> usize {
    let mut size = 100usize;

    // Each Borromean ring contributes roughly 64 bytes.
    let rings = (params.min_bits as usize).div_ceil(2);
    size += rings * 64;

    if params.exponent > 0 {
        size += 10;
    }

    size
}

/// A breakdown of how a value will be represented in a proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValueAnalysis {
    /// The value analyzed.
    pub value: u64,
    /// How many times the value divides evenly by 10.
    pub divisible_by_10: u32,
    /// Trailing zero bits.
    pub trailing_zeros: u32,
    /// Leading zero bits.
    pub leading_zeros: u32,
    /// Significant bits between the outermost set bits.
    pub bits_required: i32,
    /// A parameter set suggested for this value.
    pub suggested_params: RangeProofParams,
}

/// Analyze a value's representation, for debugging and fee estimation.
pub fn analyze_value(value: u64) -> ValueAnalysis {
    let mut n_test = value;
    let mut div10 = 0u32;
    while n_test > 0 && n_test.is_multiple_of(10) {
        div10 += 1;
        n_test /= 10;
    }

    let trailing_zeros = if value == 0 { 64 } else { value.trailing_zeros() };
    let leading_zeros = if value == 0 { 64 } else { value.leading_zeros() };
    let bits_required = 64 - trailing_zeros as i32 - leading_zeros as i32;

    ValueAnalysis {
        value,
        divisible_by_10: div10,
        trailing_zeros,
        leading_zeros,
        bits_required,
        suggested_params: select_range_proof_parameters(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_value_uses_randomized_defaults() {
        for _ in 0..64 {
            let params = select_range_proof_parameters(0);
            assert_eq!(params.min_value, 0);
            assert!((0..5).contains(&params.exponent));
            assert!((32..37).contains(&params.min_bits));
            assert!(validate_range_proof_params(&params));
        }
    }

    #[test]
    fn selected_params_are_always_valid() {
        let values = [
            1,
            10,
            100,
            1_000,
            100_000_000,
            123_456_789,
            crate::types::MAX_MONEY,
            u64::MAX,
        ];

        for value in values {
            for _ in 0..16 {
                let params = select_range_proof_parameters(value);
                assert!(
                    validate_range_proof_params(&params),
                    "invalid params {params:?} for value {value}"
                );
                assert_eq!(params.min_value, 0);
            }
        }
    }

    #[test]
    fn min_bits_is_radix4_aligned_below_63() {
        for _ in 0..64 {
            let params = select_range_proof_parameters(123_456_789);
            if params.min_bits < 63 {
                assert_eq!(params.min_bits % 4, 0, "params: {params:?}");
            }
        }
    }

    #[test]
    fn exponent_never_exceeds_divisibility() {
        // 100_000_000 divides by 10 eight times, so the exponent stays under 8.
        for _ in 0..64 {
            let params = select_range_proof_parameters(100_000_000);
            assert!(params.exponent <= 8, "params: {params:?}");
            assert!(params.exponent >= 4, "params: {params:?}");
        }
    }

    #[test]
    fn indivisible_value_gets_zero_exponent() {
        // 7 does not divide by 10, so n_div10 is 0 and the exponent must be 0.
        for _ in 0..16 {
            assert_eq!(select_range_proof_parameters(7).exponent, 0);
        }
    }

    #[test]
    fn standard_params_are_the_documented_pair() {
        let params = standard_range_proof_params();
        assert_eq!(params.exponent, 2);
        assert_eq!(params.min_bits, 32);
        assert!(validate_range_proof_params(&params));
    }

    #[test]
    fn validation_rejects_out_of_range_params() {
        assert!(!validate_range_proof_params(&RangeProofParams {
            min_value: 0,
            exponent: 19,
            min_bits: 32,
        }));
        assert!(!validate_range_proof_params(&RangeProofParams {
            min_value: 0,
            exponent: -1,
            min_bits: 32,
        }));
        assert!(!validate_range_proof_params(&RangeProofParams {
            min_value: 0,
            exponent: 2,
            min_bits: 65,
        }));
    }

    #[test]
    fn analysis_reports_divisibility_and_width() {
        let analysis = analyze_value(1_000);
        assert_eq!(analysis.divisible_by_10, 3);
        assert_eq!(analysis.trailing_zeros, 3);
        assert_eq!(analysis.bits_required, 7);
    }

    #[test]
    fn ipow_saturates_instead_of_overflowing() {
        assert_eq!(ipow(10, 3), 1_000);
        assert_eq!(ipow(10, 64), u64::MAX);
    }

    #[test]
    fn estimated_size_grows_with_bit_width() {
        let narrow = estimate_proof_size(&RangeProofParams {
            min_value: 0,
            exponent: 0,
            min_bits: 32,
        });
        let wide = estimate_proof_size(&RangeProofParams {
            min_value: 0,
            exponent: 0,
            min_bits: 64,
        });
        assert!(wide > narrow);
    }
}
