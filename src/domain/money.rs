//! Multi-currency monetary primitives with ISO 4217 minor-unit exponents and exact integer arithmetic.

use std::fmt;
use std::str::FromStr;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

/// Canonical 3-letter ISO 4217 currency code (`SGD`, `USD`, `EUR`, `GBP`, `JPY`, `HKD`, `AUD`, `CNY`, etc.).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CurrencyCode(String);

impl CurrencyCode {
    pub fn new(code: &str) -> Result<Self> {
        let upper = code.trim().to_ascii_uppercase();
        if upper.len() != 3 || !upper.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(anyhow!("invalid ISO 4217 currency code '{}'", code));
        }
        Ok(Self(upper))
    }

    pub fn sgd() -> Self {
        Self("SGD".into())
    }

    pub fn usd() -> Self {
        Self("USD".into())
    }

    pub fn eur() -> Self {
        Self("EUR".into())
    }

    pub fn jpy() -> Self {
        Self("JPY".into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Standard ISO 4217 minor-unit decimal places (`0` for JPY/KRW/VND, `3` for BHD/KWD/OMR, `2` default).
    pub fn minor_decimals(&self) -> u8 {
        match self.0.as_str() {
            "JPY" | "KRW" | "VND" | "CLP" | "ISK" => 0,
            "BHD" | "KWD" | "OMR" | "JOD" | "TND" => 3,
            _ => 2,
        }
    }

    /// Scale an integer minor-unit amount into 6-decimal micro-units (`1.00 SGD` = `100` cents -> `1_000_000` micros).
    pub fn minor_to_micros(&self, amount_minor: i128) -> Result<u64> {
        if amount_minor < 0 {
            return Err(anyhow!("cannot convert negative amount {} to unsigned HFS micros", amount_minor));
        }
        let scale: i128 = match self.minor_decimals() {
            0 => 1_000_000,
            2 => 10_000,
            3 => 1_000,
            d => 10i128.pow((6u8.saturating_sub(d)) as u32),
        };
        let scaled = amount_minor
            .checked_mul(scale)
            .ok_or_else(|| anyhow!("overflow scaling minor units to micros"))?;
        u64::try_from(scaled).map_err(|_| anyhow!("amount {} exceeds u64 HFS capacity", scaled))
    }

    /// Parse a decimal string such as `"1250.50"` or `"5000"` into exact integer minor units.
    pub fn parse_decimal_to_minor(&self, s: &str) -> Result<i128> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(anyhow!("empty monetary amount string"));
        }
        let (neg, rest) = if let Some(stripped) = trimmed.strip_prefix('-') {
            (true, stripped)
        } else if let Some(stripped) = trimmed.strip_prefix('+') {
            (false, stripped)
        } else {
            (false, trimmed)
        };

        let decimals = self.minor_decimals() as usize;
        let (whole_str, frac_str) = match rest.split_once('.') {
            Some((w, f)) => (w, f),
            None => (rest, ""),
        };

        let whole: i128 = if whole_str.is_empty() {
            0
        } else {
            whole_str
                .parse()
                .map_err(|_| anyhow!("invalid whole amount in '{}'", s))?
        };

        let frac_trimmed = frac_str.trim_end_matches('0');
        if frac_trimmed.len() > decimals {
            return Err(anyhow!(
                "amount '{}' exceeds {} minor decimal places for {}",
                s,
                decimals,
                self.0
            ));
        }
        let mut frac_padded = frac_trimmed.to_string();
        while frac_padded.len() < decimals {
            frac_padded.push('0');
        }
        let frac: i128 = if frac_padded.is_empty() {
            0
        } else {
            frac_padded
                .parse()
                .map_err(|_| anyhow!("invalid fractional amount in '{}'", s))?
        };

        let factor = 10i128.pow(decimals as u32);
        let total = whole
            .checked_mul(factor)
            .and_then(|v| v.checked_add(frac))
            .ok_or_else(|| anyhow!("monetary overflow parsing '{}'", s))?;

        Ok(if neg { -total } else { total })
    }
}

impl fmt::Debug for CurrencyCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for CurrencyCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for CurrencyCode {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

/// Exact integer minor-unit monetary value tagged with its ISO 4217 currency (`amount_minor` in cents/yen/fils).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Money {
    pub amount_minor: i128,
    pub currency: CurrencyCode,
}

impl Money {
    pub fn new(amount_minor: i128, currency: CurrencyCode) -> Self {
        Self {
            amount_minor,
            currency,
        }
    }

    pub fn from_decimal_str(amount_str: &str, currency_code: &str) -> Result<Self> {
        let ccy = CurrencyCode::new(currency_code)?;
        let minor = ccy.parse_decimal_to_minor(amount_str)?;
        Ok(Self::new(minor, ccy))
    }

    pub fn checked_add(&self, rhs: &Self) -> Result<Self> {
        self.ensure_same_currency(rhs)?;
        let sum = self
            .amount_minor
            .checked_add(rhs.amount_minor)
            .ok_or_else(|| anyhow!("monetary addition overflow"))?;
        Ok(Self::new(sum, self.currency.clone()))
    }

    pub fn checked_sub(&self, rhs: &Self) -> Result<Self> {
        self.ensure_same_currency(rhs)?;
        let diff = self
            .amount_minor
            .checked_sub(rhs.amount_minor)
            .ok_or_else(|| anyhow!("monetary subtraction overflow"))?;
        Ok(Self::new(diff, self.currency.clone()))
    }

    pub fn ensure_same_currency(&self, other: &Self) -> Result<()> {
        if self.currency != other.currency {
            return Err(anyhow!(
                "currency mismatch: {} vs {}",
                self.currency,
                other.currency
            ));
        }
        Ok(())
    }

    pub fn to_hfs_micros(&self) -> Result<u64> {
        self.currency.minor_to_micros(self.amount_minor)
    }
}
