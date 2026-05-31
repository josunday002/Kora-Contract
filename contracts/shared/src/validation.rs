use crate::errors::KoraError;
use soroban_sdk::{Bytes, Env, String};

/// OPT: Mark for inlining - simple single-comparison validation, no branches needed
#[inline]
pub fn require_non_zero_amount(amount: i128) -> Result<(), KoraError> {
    if amount <= 0 {
        return Err(KoraError::InvalidAmount);
    }
    Ok(())
}

/// OPT: Mark for inlining - simple single-comparison validation
#[inline]
pub fn require_positive_amount(amount: i128) -> Result<(), KoraError> {
    if amount < 0 {
        return Err(KoraError::InvalidAmount);
    }
    Ok(())
}

/// OPT: Mark for inlining - simple timestamp comparison
#[inline]
pub fn require_future_timestamp(env: &Env, ts: u64) -> Result<(), KoraError> {
    if ts <= env.ledger().timestamp() {
        return Err(KoraError::InvalidDueDate);
    }
    Ok(())
}

/// OPT: Mark for inlining - simple range check against constant
#[inline]
pub fn require_valid_risk_score(score: u32) -> Result<(), KoraError> {
    if score > 100 {
        return Err(KoraError::InvalidRiskScore);
    }
    Ok(())
}

/// OPT: Mark for inlining - string length check takes reference (no allocation)
#[inline]
pub fn require_non_empty_string(s: &String) -> Result<(), KoraError> {
    if s.len() == 0 {
        return Err(KoraError::EmptyString);
    }
    Ok(())
}

/// OPT: Mark for inlining - bytes length check takes reference (no allocation)
#[inline]
pub fn require_non_empty_bytes(b: &Bytes) -> Result<(), KoraError> {
    if b.len() == 0 {
        return Err(KoraError::EmptyString);
    }
    Ok(())
}

/// OPT: Mark for inlining - simple range check against constant
#[inline]
pub fn require_valid_fee_bps(bps: u32) -> Result<(), KoraError> {
    if bps > 10_000 {
        return Err(KoraError::InvalidFeeRate);
    }
    Ok(())
}

/// OPT: Consolidated range check in single comparison (0 <= amount <= max)
#[inline]
pub fn require_amount_within_bounds(amount: i128, max: i128) -> Result<(), KoraError> {
    // OPT: Early exit for negative amounts saves comparison if amount >= 0
    if amount < 0 || amount > max {
        return Err(KoraError::InvalidAmount);
    }
    Ok(())
}

/// Safe basis-point multiplication: (amount * bps) / 10_000
/// OPT: Mark for inlining - frequently called, minimal logic
#[inline]
pub fn bps_of(amount: i128, bps: u32) -> Result<i128, KoraError> {
    amount
        .checked_mul(bps as i128)
        .and_then(|v| v.checked_div(10_000))
        .ok_or(KoraError::ArithmeticOverflow)
}

/// Safe addition with overflow check
/// OPT: Mark for inlining - thin wrapper, lets compiler inline checked_add directly
#[inline]
pub fn safe_add(a: i128, b: i128) -> Result<i128, KoraError> {
    a.checked_add(b).ok_or(KoraError::ArithmeticOverflow)
}

/// Safe subtraction with underflow check
/// OPT: Mark for inlining - thin wrapper, lets compiler inline checked_sub directly
#[inline]
pub fn safe_sub(a: i128, b: i128) -> Result<i128, KoraError> {
    a.checked_sub(b).ok_or(KoraError::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    #[test]
    fn test_require_non_zero_amount() {
        assert!(require_non_zero_amount(0).is_err());
        assert!(require_non_zero_amount(-1).is_err());
        assert!(require_non_zero_amount(1).is_ok());
    }

    #[test]
    fn test_require_positive_amount() {
        assert!(require_positive_amount(-1).is_err());
        assert!(require_positive_amount(0).is_ok());
        assert!(require_positive_amount(1).is_ok());
    }

    #[test]
    fn test_bps_of_safe() {
        assert_eq!(bps_of(10_000, 100).unwrap(), 100);
        assert_eq!(bps_of(1_000_000, 50).unwrap(), 5_000);
        assert!(bps_of(i128::MAX, 10_000).is_err());
    }

    #[test]
    fn test_safe_add() {
        assert_eq!(safe_add(100, 200).unwrap(), 300);
        assert!(safe_add(i128::MAX, 1).is_err());
    }

    #[test]
    fn test_safe_sub() {
        assert_eq!(safe_sub(300, 100).unwrap(), 200);
        assert_eq!(safe_sub(100, 200).unwrap(), -100);
        assert!(safe_sub(i128::MIN, 1).is_err());
    }
}
