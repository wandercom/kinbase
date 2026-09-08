//! Integer scoring (architecture §3): signed basis points, a frozen
//! fact-ID-ordered expression tree, checked signed integer intermediates,
//! rational division reduced after every operation with round-half-to-even,
//! and fact-ID tie breaking. No binary float enters a signed event.
//!
//! Shortcut (recorded): intermediates are `i128` with checked arithmetic, a
//! strict subset of the ratified signed 256-bit range. Ceiling: a subexpression
//! magnitude above 2^127 emits the typed integrity failure earlier than the
//! ratified bound would. Trigger: any term magnitude above 10^30 basis points
//! (unreachable from the bounded 0..10000 bp inputs). Upgrade path: replace
//! `i128` with a fixed 256-bit signed type in this module only.

use crate::error::ContractError;
use serde::{Deserialize, Serialize};

pub const BP_ONE: i64 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rational {
    pub num: i128,
    pub den: i128,
}

fn gcd(mut a: i128, mut b: i128) -> i128 {
    a = a.abs();
    b = b.abs();
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a.max(1)
}

fn overflow(operation: &str) -> ContractError {
    ContractError::integrity(
        "DIGEST_MISMATCH",
        format!("score expression tree left the signed intermediate range during {operation}"),
        "Preserve the trace; the ordered subexpression is recorded and no score was emitted.",
    )
}

impl Rational {
    pub fn int(value: i64) -> Self {
        Self {
            num: i128::from(value),
            den: 1,
        }
    }

    fn reduce(self) -> Result<Self, ContractError> {
        if self.den == 0 {
            return Err(overflow("division by zero"));
        }
        let g = gcd(self.num, self.den);
        let (mut num, mut den) = (self.num / g, self.den / g);
        if den < 0 {
            num = num.checked_neg().ok_or_else(|| overflow("negate"))?;
            den = den.checked_neg().ok_or_else(|| overflow("negate"))?;
        }
        Ok(Self { num, den })
    }

    pub fn add(self, other: Self) -> Result<Self, ContractError> {
        let num = self
            .num
            .checked_mul(other.den)
            .and_then(|left| other.num.checked_mul(self.den).and_then(|right| left.checked_add(right)))
            .ok_or_else(|| overflow("add"))?;
        let den = self.den.checked_mul(other.den).ok_or_else(|| overflow("add"))?;
        Self { num, den }.reduce()
    }

    pub fn sub(self, other: Self) -> Result<Self, ContractError> {
        self.add(Self {
            num: other.num.checked_neg().ok_or_else(|| overflow("sub"))?,
            den: other.den,
        })
    }

    pub fn mul(self, other: Self) -> Result<Self, ContractError> {
        let num = self.num.checked_mul(other.num).ok_or_else(|| overflow("mul"))?;
        let den = self.den.checked_mul(other.den).ok_or_else(|| overflow("mul"))?;
        Self { num, den }.reduce()
    }

    pub fn div(self, other: Self) -> Result<Self, ContractError> {
        if other.num == 0 {
            return Err(overflow("division by zero"));
        }
        let num = self.num.checked_mul(other.den).ok_or_else(|| overflow("div"))?;
        let den = self.den.checked_mul(other.num).ok_or_else(|| overflow("div"))?;
        Self { num, den }.reduce()
    }

    /// Round half to even to an integer; the result must fit the JSON bound.
    pub fn round_half_even(self) -> Result<i64, ContractError> {
        let reduced = self.reduce()?;
        let quotient = reduced.num.div_euclid(reduced.den);
        let remainder = reduced.num.rem_euclid(reduced.den);
        let twice = remainder.checked_mul(2).ok_or_else(|| overflow("round"))?;
        let rounded = if twice > reduced.den {
            quotient + 1
        } else if twice < reduced.den {
            quotient
        } else if quotient % 2 == 0 {
            quotient
        } else {
            quotient + 1
        };
        if rounded.abs() > crate::json::JSON_INTEGER_BOUND {
            return Err(overflow("serialize"));
        }
        i64::try_from(rounded).map_err(|_| overflow("serialize"))
    }

    pub fn is_positive(self) -> bool {
        (self.num > 0) == (self.den > 0) && self.num != 0
    }

    pub fn cmp_value(self, other: Self) -> std::cmp::Ordering {
        let left = self.num.checked_mul(other.den);
        let right = other.num.checked_mul(self.den);
        match (left, right) {
            (Some(left), Some(right)) => {
                if (self.den > 0) == (other.den > 0) {
                    left.cmp(&right)
                } else {
                    right.cmp(&left)
                }
            }
            _ => {
                let l = self.num as f64 / self.den as f64;
                let r = other.num as f64 / other.den as f64;
                l.partial_cmp(&r).unwrap_or(std::cmp::Ordering::Equal)
            }
        }
    }
}

/// Basis-point helpers: `bp_mul(a, b) = round_half_even(a*b/10000)`.
pub fn bp_mul(a: i64, b: i64) -> Result<i64, ContractError> {
    Rational::int(a)
        .mul(Rational::int(b))?
        .div(Rational::int(BP_ONE))?
        .round_half_even()
}

pub fn bp_div(a: i64, b: i64) -> Result<i64, ContractError> {
    if b == 0 {
        return Ok(0);
    }
    Rational::int(a)
        .mul(Rational::int(BP_ONE))?
        .div(Rational::int(b))?
        .round_half_even()
}

/// One ordered term of the frozen expression tree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Term {
    pub name: String,
    pub value_bp: i64,
    pub sign: i8,
}

/// Evaluate an ordered term list (`sum(sign_i * value_i)`), recording the
/// first out-of-range subexpression.
pub fn evaluate(terms: &[Term]) -> Result<i64, ContractError> {
    let mut total = Rational::int(0);
    for term in terms {
        let signed = Rational::int(term.value_bp).mul(Rational::int(i64::from(term.sign)))?;
        total = total.add(signed).map_err(|error| {
            error.with_detail(serde_json::json!({"subexpression": term.name}))
        })?;
    }
    total.round_half_even()
}

/// Wilson score interval lower/upper bounds (z = 1.96) in basis points,
/// computed with integer rational arithmetic and a fixed 40-iteration
/// integer square root.
pub fn wilson_bounds_bp(successes: u64, trials: u64) -> (i64, i64) {
    if trials == 0 {
        return (0, BP_ONE);
    }
    // z^2 = 3.8416 => 38416 / 10000
    let n = trials as i128;
    let s = successes as i128;
    let z2n = 38_416i128; // z^2 * 10000
    let scale = 10_000i128;
    // centre = (s + z^2/2) / (n + z^2)
    // half = z * sqrt(s(n-s)/n + z^2/4) / (n + z^2)
    let denominator = n * scale + z2n;
    let centre_num = s * scale + z2n / 2;
    // inner = s(n-s)/n + z^2/4, scaled by 10^8
    let inner_scaled = if n == 0 {
        0
    } else {
        (s * (n - s) * 100_000_000) / n + (z2n * 10_000) / 4
    };
    let sqrt_inner = isqrt(inner_scaled); // scaled by 10^4
    let half_num = 19_600i128 * sqrt_inner / 10_000; // z * sqrt, scaled by 10^4
    let lower = ((centre_num - half_num) * scale) / denominator;
    let upper = ((centre_num + half_num) * scale) / denominator;
    (lower.clamp(0, BP_ONE as i128) as i64, upper.clamp(0, BP_ONE as i128) as i64)
}

fn isqrt(value: i128) -> i128 {
    if value <= 0 {
        return 0;
    }
    let mut x = value;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + value / x) / 2;
    }
    x
}

/// Basis-point mean of integer samples with half-even rounding.
pub fn mean_bp(values: &[i64]) -> Result<i64, ContractError> {
    if values.is_empty() {
        return Ok(0);
    }
    let mut total = Rational::int(0);
    for value in values {
        total = total.add(Rational::int(*value))?;
    }
    total
        .div(Rational::int(values.len() as i64))?
        .round_half_even()
}

/// Sample standard deviation in basis points (integer sqrt of the variance).
pub fn stddev_bp(values: &[i64]) -> Result<i64, ContractError> {
    if values.len() < 2 {
        return Ok(0);
    }
    let mean = mean_bp(values)?;
    let mut total = 0i128;
    for value in values {
        let delta = i128::from(*value - mean);
        total = total
            .checked_add(delta * delta)
            .ok_or_else(|| overflow("variance"))?;
    }
    let variance = total / (values.len() as i128 - 1);
    Ok(isqrt(variance) as i64)
}
