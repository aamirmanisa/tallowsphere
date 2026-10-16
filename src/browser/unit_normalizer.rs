//! Unit price normalizer.
//!
//! Converts arbitrary (price, size, unit) tuples into normalized unit prices
//! so that products in different package sizes can be compared apples-to-apples.

use std::cmp::Ordering;

pub struct UnitNormalizer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitCategory {
    Weight,
    Volume,
    Count,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct NormalizedPrice {
    pub price_cents: i64,
    pub unit_value: f64,
    pub unit: String,
    pub price_per_oz_cents: Option<i64>,
    pub price_per_lb_cents: Option<i64>,
    pub price_per_gram_cents: Option<i64>,
    pub price_per_ml_cents: Option<i64>,
    pub price_per_liter_cents: Option<i64>,
    pub price_per_count_cents: Option<i64>,
}

// Conversion constants
pub const OZ_PER_LB: f64 = 16.0;
pub const GRAMS_PER_OZ: f64 = 28.3495;
pub const ML_PER_FLOZ: f64 = 29.5735;
pub const GAL_TO_FLOZ: f64 = 128.0;
pub const QT_TO_FLOZ: f64 = 32.0;
pub const PT_TO_FLOZ: f64 = 16.0;
pub const CUP_TO_FLOZ: f64 = 8.0;
pub const TBSP_TO_FLOZ: f64 = 0.5;
pub const TSP_TO_FLOZ: f64 = 1.0 / 6.0;
pub const ML_PER_LITER: f64 = 1000.0;
pub const GRAMS_PER_KG: f64 = 1000.0;

/// Canonicalize a raw unit string to a lowercase short form.
fn canon(unit: &str) -> String {
    let u = unit.trim().to_lowercase();
    let u = u.trim_end_matches('.').trim_end_matches('s').to_string();
    match u.as_str() {
        "ounce" | "oz" | "oz." => "oz".to_string(),
        "fluid ounce" | "fl oz" | "floz" | "fl.oz" | "fl-oz" => "fl oz".to_string(),
        "pound" | "lb" | "lbs" | "#" => "lb".to_string(),
        "gram" | "g" | "gr" | "gm" => "g".to_string(),
        "kilogram" | "kg" | "kilo" => "kg".to_string(),
        "milligram" | "mg" => "mg".to_string(),
        "milliliter" | "millilitre" | "ml" => "ml".to_string(),
        "liter" | "litre" | "l" | "ltr" => "l".to_string(),
        "gallon" | "gal" => "gal".to_string(),
        "quart" | "qt" => "qt".to_string(),
        "pint" | "pt" => "pt".to_string(),
        "cup" | "c" => "cup".to_string(),
        "tablespoon" | "tbsp" | "tbl" | "tbs" | "T" => "tbsp".to_string(),
        "teaspoon" | "tsp" | "t" => "tsp".to_string(),
        "count" | "ct" | "each" | "ea" | "pk" | "pack" | "pc" | "piece" => "ct".to_string(),
        other => other.to_string(),
    }
}

impl UnitNormalizer {
    /// Parse a size string like "12 fl oz" or "1.5 lb" or "24 ct"
    pub fn parse_size(size_text: &str) -> Option<(f64, String)> {
        let s = size_text.trim();
        if s.is_empty() {
            return None;
        }
        // Walk characters splitting number prefix from unit suffix.
        let bytes = s.as_bytes();
        let mut i = 0usize;
        // Skip leading non-numeric (except '.' or digit)
        while i < bytes.len() && !(bytes[i].is_ascii_digit() || bytes[i] == b'.') {
            i += 1;
        }
        let num_start = i;
        while i < bytes.len() {
            let c = bytes[i];
            if c.is_ascii_digit() || c == b'.' || c == b',' || c == b'/' || c == b' ' {
                // allow mixed fractions "1 1/2"
                if c == b' ' {
                    // peek next char; if digit and we've seen a digit, keep; else break
                    let next_digit = bytes
                        .get(i + 1)
                        .map(|b| b.is_ascii_digit())
                        .unwrap_or(false);
                    if !next_digit {
                        break;
                    }
                }
                i += 1;
            } else {
                break;
            }
        }
        let num_str = s[num_start..i].trim();
        if num_str.is_empty() {
            return None;
        }
        let value = parse_numeric(num_str)?;
        let unit_raw = s[i..].trim();
        let unit = canon(unit_raw);
        Some((value, unit))
    }

    /// Normalize a (price, size, unit) to all standard unit prices.
    pub fn normalize(price_cents: i64, size_value: f64, unit: &str) -> NormalizedPrice {
        let u = canon(unit);
        let cat = Self::category(&u);
        let mut np = NormalizedPrice {
            price_cents,
            unit_value: size_value,
            unit: u.clone(),
            price_per_oz_cents: None,
            price_per_lb_cents: None,
            price_per_gram_cents: None,
            price_per_ml_cents: None,
            price_per_liter_cents: None,
            price_per_count_cents: None,
        };

        if size_value <= 0.0 {
            return np;
        }
        let price = price_cents as f64;

        match cat {
            UnitCategory::Weight => {
                // Convert size to oz, g, lb, kg
                let oz = convert_same(size_value, &u, "oz").unwrap_or(0.0);
                let g = convert_same(size_value, &u, "g").unwrap_or(0.0);
                if oz > 0.0 {
                    np.price_per_oz_cents = Some((price / oz).round() as i64);
                    np.price_per_lb_cents = Some((price / (oz / OZ_PER_LB)).round() as i64);
                }
                if g > 0.0 {
                    np.price_per_gram_cents = Some((price / g).round() as i64);
                }
            }
            UnitCategory::Volume => {
                let floz = convert_same(size_value, &u, "fl oz").unwrap_or(0.0);
                let ml = convert_same(size_value, &u, "ml").unwrap_or(0.0);
                if floz > 0.0 {
                    np.price_per_oz_cents = Some((price / floz).round() as i64);
                }
                if ml > 0.0 {
                    np.price_per_ml_cents = Some((price / ml).round() as i64);
                    np.price_per_liter_cents = Some((price / (ml / ML_PER_LITER)).round() as i64);
                }
            }
            UnitCategory::Count => {
                np.price_per_count_cents = Some((price / size_value).round() as i64);
            }
            UnitCategory::Unknown => {}
        }
        np
    }

    /// Get the category of a unit.
    pub fn category(unit: &str) -> UnitCategory {
        match canon(unit).as_str() {
            "oz" | "lb" | "g" | "kg" | "mg" => UnitCategory::Weight,
            "fl oz" | "ml" | "l" | "gal" | "qt" | "pt" | "cup" | "tbsp" | "tsp" => {
                UnitCategory::Volume
            }
            "ct" => UnitCategory::Count,
            _ => UnitCategory::Unknown,
        }
    }

    /// Convert a value between units of the same category.
    pub fn convert(value: f64, from_unit: &str, to_unit: &str) -> Option<f64> {
        let f = canon(from_unit);
        let t = canon(to_unit);
        if Self::category(&f) != Self::category(&t) {
            return None;
        }
        convert_same(value, &f, &t)
    }

    /// Compare two normalized prices by their best-available shared unit price.
    pub fn compare(a: &NormalizedPrice, b: &NormalizedPrice) -> Ordering {
        // Try each unit dimension in priority order until both have a value.
        let pairs = [
            (a.price_per_oz_cents, b.price_per_oz_cents),
            (a.price_per_gram_cents, b.price_per_gram_cents),
            (a.price_per_ml_cents, b.price_per_ml_cents),
            (a.price_per_liter_cents, b.price_per_liter_cents),
            (a.price_per_lb_cents, b.price_per_lb_cents),
            (a.price_per_count_cents, b.price_per_count_cents),
        ];
        for (x, y) in pairs {
            if let (Some(xv), Some(yv)) = (x, y) {
                return xv.cmp(&yv);
            }
        }
        a.price_cents.cmp(&b.price_cents)
    }
}

/// Parse a numeric string supporting decimals and fractions.
fn parse_numeric(s: &str) -> Option<f64> {
    let s = s.replace(',', "").trim().to_string();
    if s.is_empty() {
        return None;
    }
    // Mixed fraction "1 1/2"
    if let Some(sp) = s.find(' ') {
        let (whole, frac) = s.split_at(sp);
        let w: f64 = whole.trim().parse().ok()?;
        let f = parse_fraction(frac.trim())?;
        return Some(w + f);
    }
    if s.contains('/') {
        return parse_fraction(&s);
    }
    s.parse::<f64>().ok()
}

fn parse_fraction(s: &str) -> Option<f64> {
    let mut parts = s.split('/');
    let num: f64 = parts.next()?.trim().parse().ok()?;
    let den: f64 = parts.next()?.trim().parse().ok()?;
    if den == 0.0 {
        return None;
    }
    Some(num / den)
}

/// Convert within the same category. Returns None if units are incompatible.
fn convert_same(value: f64, from: &str, to: &str) -> Option<f64> {
    if from == to {
        return Some(value);
    }
    // Weight -> normalize to grams first.
    let cat = UnitNormalizer::category(from);
    if cat != UnitNormalizer::category(to) {
        return None;
    }
    match cat {
        UnitCategory::Weight => {
            let g = match from {
                "oz" => value * GRAMS_PER_OZ,
                "lb" => value * OZ_PER_LB * GRAMS_PER_OZ,
                "g" => value,
                "kg" => value * GRAMS_PER_KG,
                "mg" => value / 1000.0,
                _ => return None,
            };
            match to {
                "oz" => Some(g / GRAMS_PER_OZ),
                "lb" => Some(g / (GRAMS_PER_OZ * OZ_PER_LB)),
                "g" => Some(g),
                "kg" => Some(g / GRAMS_PER_KG),
                "mg" => Some(g * 1000.0),
                _ => None,
            }
        }
        UnitCategory::Volume => {
            // Normalize to fl oz.
            let floz = match from {
                "fl oz" => value,
                "ml" => value / ML_PER_FLOZ,
                "l" => value * ML_PER_LITER / ML_PER_FLOZ,
                "gal" => value * GAL_TO_FLOZ,
                "qt" => value * QT_TO_FLOZ,
                "pt" => value * PT_TO_FLOZ,
                "cup" => value * CUP_TO_FLOZ,
                "tbsp" => value * TBSP_TO_FLOZ,
                "tsp" => value * TSP_TO_FLOZ,
                _ => return None,
            };
            match to {
                "fl oz" => Some(floz),
                "ml" => Some(floz * ML_PER_FLOZ),
                "l" => Some(floz * ML_PER_FLOZ / ML_PER_LITER),
                "gal" => Some(floz / GAL_TO_FLOZ),
                "qt" => Some(floz / QT_TO_FLOZ),
                "pt" => Some(floz / PT_TO_FLOZ),
                "cup" => Some(floz / CUP_TO_FLOZ),
                "tbsp" => Some(floz / TBSP_TO_FLOZ),
                "tsp" => Some(floz / TSP_TO_FLOZ),
                _ => None,
            }
        }
        UnitCategory::Count => {
            if from == "ct" && to == "ct" {
                Some(value)
            } else {
                None
            }
        }
        UnitCategory::Unknown => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sizes() {
        assert_eq!(
            UnitNormalizer::parse_size("12 fl oz"),
            Some((12.0, "fl oz".to_string()))
        );
        assert_eq!(
            UnitNormalizer::parse_size("1.5 lb"),
            Some((1.5, "lb".to_string()))
        );
        assert_eq!(
            UnitNormalizer::parse_size("24 ct"),
            Some((24.0, "ct".to_string()))
        );
        assert_eq!(
            UnitNormalizer::parse_size("500g"),
            Some((500.0, "g".to_string()))
        );
        assert_eq!(
            UnitNormalizer::parse_size("1 1/2 cups"),
            Some((1.5, "cup".to_string()))
        );
    }

    #[test]
    fn conversions() {
        let lb = UnitNormalizer::convert(16.0, "oz", "lb").unwrap();
        assert!((lb - 1.0).abs() < 1e-9);
        let floz = UnitNormalizer::convert(500.0, "ml", "fl oz").unwrap();
        assert!((floz - 16.9070).abs() < 0.01);
        let g = UnitNormalizer::convert(1.0, "kg", "g").unwrap();
        assert!((g - 1000.0).abs() < 1e-9);
    }

    #[test]
    fn normalize_weight() {
        // $4.99 for 16 oz -> $0.31/oz
        let np = UnitNormalizer::normalize(499, 16.0, "oz");
        assert_eq!(np.price_per_oz_cents, Some(31));
        assert_eq!(np.price_per_lb_cents, Some(499));
    }

    #[test]
    fn normalize_volume() {
        let np = UnitNormalizer::normalize(299, 12.0, "fl oz");
        assert_eq!(np.price_per_oz_cents, Some(25));
        assert!(np.price_per_ml_cents.is_some());
    }

    #[test]
    fn normalize_count() {
        let np = UnitNormalizer::normalize(600, 24.0, "ct");
        assert_eq!(np.price_per_count_cents, Some(25));
    }

    #[test]
    fn compare_cheaper_per_oz() {
        let a = UnitNormalizer::normalize(499, 16.0, "oz"); // 31c/oz
        let b = UnitNormalizer::normalize(899, 32.0, "oz"); // 28c/oz
        assert_eq!(UnitNormalizer::compare(&a, &b), Ordering::Greater);
    }
}
