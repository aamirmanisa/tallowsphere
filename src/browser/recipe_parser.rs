//! Recipe parser.
//!
//! Extracts structured Recipe objects from HTML (JSON-LD Schema.org or
//! microdata) and parses individual ingredient lines into quantity/unit/item.

pub struct RecipeParser;

#[derive(Debug, Clone)]
pub struct Recipe {
    pub title: String,
    pub servings: i32,
    pub prep_time_minutes: Option<i32>,
    pub cook_time_minutes: Option<i32>,
    pub ingredients: Vec<Ingredient>,
    pub instructions: Vec<String>,
    pub source_url: Option<String>,
    pub image_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Ingredient {
    pub raw_text: String,
    pub quantity: Option<f64>,
    pub unit: Option<String>,
    pub item: String,
    pub preparation: Option<String>,
    pub optional: bool,
}

const UNIT_WORDS: &[&str] = &[
    "cup", "cups", "c",
    "tablespoon", "tablespoons", "tbsp", "tbs", "tbl",
    "teaspoon", "teaspoons", "tsp",
    "ounce", "ounces", "oz",
    "fluid ounce", "fluid ounces", "fl oz", "floz",
    "pound", "pounds", "lb", "lbs",
    "gram", "grams", "g",
    "kilogram", "kilograms", "kg",
    "milligram", "milligrams", "mg",
    "milliliter", "milliliters", "ml",
    "liter", "liters", "litre", "litres", "l",
    "gallon", "gallons", "gal",
    "quart", "quarts", "qt",
    "pint", "pints", "pt",
    "clove", "cloves",
    "can", "cans",
    "package", "packages", "pkg",
    "stick", "sticks",
    "slice", "slices",
    "pinch", "pinches",
    "dash", "dashes",
    "bunch", "bunches",
    "head", "heads",
    "piece", "pieces",
];

impl RecipeParser {
    /// Parse from JSON-LD Schema.org Recipe embedded in the page.
    pub fn from_jsonld(html: &str) -> Option<Recipe> {
        // Find <script type="application/ld+json">...</script> blocks.
        let mut cursor = 0;
        while let Some(start) = html[cursor..].find("<script") {
            let abs_start = cursor + start;
            let tag_end = html[abs_start..].find('>')?;
            let content_start = abs_start + tag_end + 1;
            let tag = &html[abs_start..content_start];
            if !tag.contains("ld+json") {
                cursor = content_start;
                continue;
            }
            let rest = &html[content_start..];
            let end = rest.find("</script>")?;
            let body = &rest[..end];
            if let Some(recipe) = parse_jsonld_body(body) {
                return Some(recipe);
            }
            cursor = content_start + end;
        }
        None
    }

    /// Parse from HTML microdata (`itemtype="http://schema.org/Recipe"`).
    pub fn from_microdata(html: &str) -> Option<Recipe> {
        if !html.contains("schema.org/Recipe") {
            return None;
        }
        let title = extract_itemprop(html, "name").unwrap_or_default();
        let image_url = extract_itemprop(html, "image");
        let servings = extract_itemprop(html, "recipeYield")
            .and_then(|s| s.chars().filter(|c| c.is_ascii_digit()).collect::<String>().parse().ok())
            .unwrap_or(0);
        let ingredients: Vec<Ingredient> = extract_itemprop_all(html, "recipeIngredient")
            .into_iter()
            .chain(extract_itemprop_all(html, "ingredients"))
            .map(|t| Self::parse_ingredient(&t))
            .collect();
        let instructions = extract_itemprop_all(html, "recipeInstructions");
        if title.is_empty() && ingredients.is_empty() {
            return None;
        }
        Some(Recipe {
            title,
            servings,
            prep_time_minutes: None,
            cook_time_minutes: None,
            ingredients,
            instructions,
            source_url: None,
            image_url,
        })
    }

    /// Parse a single ingredient line like "2 cups all-purpose flour, sifted".
    pub fn parse_ingredient(line: &str) -> Ingredient {
        let raw = line.trim().to_string();
        let lower = raw.to_lowercase();
        let optional = lower.contains("optional") || lower.contains("to taste");

        // Split off preparation after comma.
        let (main, prep) = match raw.find(',') {
            Some(i) => (raw[..i].trim().to_string(), Some(raw[i + 1..].trim().to_string())),
            None => (raw.clone(), None),
        };

        // Handle parenthetical size specs like "1 (14 oz) can diced tomatoes"
        // — strip parentheses from main for item extraction.
        let main_clean = strip_parens(&main);

        let (quantity, unit, item) = Self::extract_quantity_unit(&main_clean);

        Ingredient {
            raw_text: raw,
            quantity,
            unit,
            item,
            preparation: prep,
            optional,
        }
    }

    /// Extract quantity + unit from ingredient text, returning the remaining item.
    pub fn extract_quantity_unit(text: &str) -> (Option<f64>, Option<String>, String) {
        let text = text.trim();
        if text.is_empty() {
            return (None, None, String::new());
        }

        // Tokenize by whitespace.
        let tokens: Vec<&str> = text.split_whitespace().collect();
        let mut idx = 0usize;

        // Collect numeric/fraction prefix.
        let mut num_str = String::new();
        while idx < tokens.len() {
            let t = tokens[idx];
            if is_numeric_token(t) {
                if !num_str.is_empty() {
                    num_str.push(' ');
                }
                num_str.push_str(t);
                idx += 1;
            } else {
                break;
            }
        }

        let quantity = if num_str.is_empty() {
            None
        } else {
            Self::parse_fraction(&num_str).or_else(|| num_str.parse::<f64>().ok())
        };

        // Unit: match the next 1-2 tokens against UNIT_WORDS.
        let mut unit: Option<String> = None;
        if idx < tokens.len() {
            // Try two-word unit first ("fluid ounce")
            if idx + 1 < tokens.len() {
                let two = format!("{} {}", tokens[idx].to_lowercase(), tokens[idx + 1].to_lowercase());
                let two_clean = two.trim_end_matches('.').to_string();
                if UNIT_WORDS.contains(&two_clean.as_str()) {
                    unit = Some(two_clean);
                    idx += 2;
                }
            }
            if unit.is_none() {
                let t = tokens[idx].to_lowercase();
                let t_clean = t.trim_end_matches('.').to_string();
                if UNIT_WORDS.contains(&t_clean.as_str()) {
                    unit = Some(t_clean);
                    idx += 1;
                }
            }
        }

        let item = tokens[idx..].join(" ");
        (quantity, unit, item.trim().to_string())
    }

    /// Normalize fraction strings like "1/2" or "1 1/4".
    pub fn parse_fraction(s: &str) -> Option<f64> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        if let Some(sp) = s.find(' ') {
            let (whole, frac) = s.split_at(sp);
            let w: f64 = whole.trim().parse().ok()?;
            let f = parse_simple_fraction(frac.trim())?;
            return Some(w + f);
        }
        if s.contains('/') {
            return parse_simple_fraction(s);
        }
        s.parse::<f64>().ok()
    }
}

fn parse_simple_fraction(s: &str) -> Option<f64> {
    let mut parts = s.split('/');
    let n: f64 = parts.next()?.trim().parse().ok()?;
    let d: f64 = parts.next()?.trim().parse().ok()?;
    if d == 0.0 {
        return None;
    }
    Some(n / d)
}

fn is_numeric_token(t: &str) -> bool {
    if t.is_empty() {
        return false;
    }
    t.chars().all(|c| c.is_ascii_digit() || c == '.' || c == '/' || c == ',')
}

fn strip_parens(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut depth = 0i32;
    for c in s.chars() {
        match c {
            '(' => depth += 1,
            ')' => {
                if depth > 0 {
                    depth -= 1;
                }
            }
            _ => {
                if depth == 0 {
                    out.push(c);
                }
            }
        }
    }
    // Collapse double spaces.
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Very small JSON-LD recipe body extractor.
/// We are not running a full JSON parser here — the goal is to pull out
/// the handful of fields we care about without adding a dep. The body may
/// be a single object or an array. We scan for the first object that has
/// `"@type"` set to `Recipe` (or an array containing `"Recipe"`).
fn parse_jsonld_body(body: &str) -> Option<Recipe> {
    let body = body.trim();
    // Must at least mention Recipe.
    if !body.contains("\"Recipe\"") {
        return None;
    }

    let title = json_string_field(body, "name").unwrap_or_default();
    let image_url = json_string_field(body, "image");
    let source_url = json_string_field(body, "url");
    let servings = json_string_field(body, "recipeYield")
        .and_then(|s| s.chars().filter(|c| c.is_ascii_digit()).collect::<String>().parse().ok())
        .unwrap_or(0);
    let prep_time_minutes = json_string_field(body, "prepTime").and_then(parse_iso_duration_minutes);
    let cook_time_minutes = json_string_field(body, "cookTime").and_then(parse_iso_duration_minutes);

    let ingredients_raw = json_string_array_field(body, "recipeIngredient")
        .or_else(|| json_string_array_field(body, "ingredients"))
        .unwrap_or_default();
    let ingredients: Vec<Ingredient> = ingredients_raw
        .iter()
        .map(|s| RecipeParser::parse_ingredient(s))
        .collect();

    let instructions = json_string_array_field(body, "recipeInstructions").unwrap_or_default();

    if title.is_empty() && ingredients.is_empty() {
        return None;
    }

    Some(Recipe {
        title,
        servings,
        prep_time_minutes,
        cook_time_minutes,
        ingredients,
        instructions,
        source_url,
        image_url,
    })
}

/// Find `"key": "value"` and return value. Handles simple escapes.
fn json_string_field(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let idx = body.find(&needle)?;
    let rest = &body[idx + needle.len()..];
    let colon = rest.find(':')?;
    let after = rest[colon + 1..].trim_start();
    if !after.starts_with('"') {
        return None;
    }
    let s = &after[1..];
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                match n {
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    '/' => out.push('/'),
                    _ => out.push(n),
                }
            }
        } else if c == '"' {
            return Some(out);
        } else {
            out.push(c);
        }
    }
    None
}

/// Extract an array of string values for a given key, e.g.
/// `"recipeIngredient": ["2 cups flour", "1 tsp salt"]`
fn json_string_array_field(body: &str, key: &str) -> Option<Vec<String>> {
    let needle = format!("\"{}\"", key);
    let idx = body.find(&needle)?;
    let rest = &body[idx + needle.len()..];
    let colon = rest.find(':')?;
    let after = rest[colon + 1..].trim_start();
    if !after.starts_with('[') {
        return None;
    }
    // Find matching closing bracket.
    let mut depth = 0i32;
    let mut end = 0usize;
    for (i, c) in after.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    end = i + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    if end == 0 {
        return None;
    }
    let arr = &after[1..end - 1];

    // Walk the array pulling out string literals (top-level only — objects like
    // HowToStep get their `text` field pulled out instead).
    let mut out = Vec::new();
    let bytes = arr.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'"' {
            // Read string until unescaped quote.
            let mut j = i + 1;
            let mut s = String::new();
            while j < bytes.len() {
                let ch = bytes[j] as char;
                if ch == '\\' && j + 1 < bytes.len() {
                    s.push(bytes[j + 1] as char);
                    j += 2;
                    continue;
                }
                if ch == '"' {
                    break;
                }
                s.push(ch);
                j += 1;
            }
            if !s.is_empty() {
                out.push(s);
            }
            i = j + 1;
        } else if c == b'{' {
            // Find object end and extract `text` field if present.
            let mut depth = 0i32;
            let mut k = i;
            while k < bytes.len() {
                match bytes[k] {
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                k += 1;
            }
            let obj = &arr[i..=k.min(bytes.len() - 1)];
            if let Some(txt) = json_string_field(obj, "text") {
                out.push(txt);
            } else if let Some(name) = json_string_field(obj, "name") {
                out.push(name);
            }
            i = k + 1;
        } else {
            i += 1;
        }
    }
    Some(out)
}

/// Parse an ISO-8601 duration like "PT15M" or "PT1H30M" to minutes.
fn parse_iso_duration_minutes(s: String) -> Option<i32> {
    let s = s.trim();
    if !s.starts_with("PT") {
        return None;
    }
    let body = &s[2..];
    let mut minutes = 0i32;
    let mut num = String::new();
    for c in body.chars() {
        if c.is_ascii_digit() {
            num.push(c);
        } else {
            let n: i32 = num.parse().unwrap_or(0);
            match c {
                'H' => minutes += n * 60,
                'M' => minutes += n,
                'S' => {}
                _ => {}
            }
            num.clear();
        }
    }
    Some(minutes)
}

/// Extract the first `itemprop="key"` content from an HTML snippet.
fn extract_itemprop(html: &str, key: &str) -> Option<String> {
    let needle = format!("itemprop=\"{}\"", key);
    let idx = html.find(&needle)?;
    // Look for a `content="..."` attribute on the same tag, then fall back to
    // the text content between > and the next <.
    let tag_end = html[idx..].find('>')?;
    let tag = &html[idx..idx + tag_end];
    if let Some(c_idx) = tag.find("content=\"") {
        let s = &tag[c_idx + 9..];
        if let Some(end) = s.find('"') {
            return Some(s[..end].to_string());
        }
    }
    let after = &html[idx + tag_end + 1..];
    let text_end = after.find('<')?;
    Some(after[..text_end].trim().to_string())
}

fn extract_itemprop_all(html: &str, key: &str) -> Vec<String> {
    let needle = format!("itemprop=\"{}\"", key);
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = html[cursor..].find(&needle) {
        let idx = cursor + rel;
        let tag_end = match html[idx..].find('>') {
            Some(i) => i,
            None => break,
        };
        let after = &html[idx + tag_end + 1..];
        if let Some(text_end) = after.find('<') {
            let t = after[..text_end].trim();
            if !t.is_empty() {
                out.push(t.to_string());
            }
        }
        cursor = idx + tag_end + 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_ingredient() {
        let i = RecipeParser::parse_ingredient("2 cups flour");
        assert_eq!(i.quantity, Some(2.0));
        assert_eq!(i.unit.as_deref(), Some("cups"));
        assert_eq!(i.item, "flour");
    }

    #[test]
    fn fractional_ingredient() {
        let i = RecipeParser::parse_ingredient("1/2 tsp salt");
        assert_eq!(i.quantity, Some(0.5));
        assert_eq!(i.unit.as_deref(), Some("tsp"));
        assert_eq!(i.item, "salt");
    }

    #[test]
    fn mixed_fraction() {
        let i = RecipeParser::parse_ingredient("1 1/4 lb ground beef");
        assert_eq!(i.quantity, Some(1.25));
        assert_eq!(i.unit.as_deref(), Some("lb"));
        assert_eq!(i.item, "ground beef");
    }

    #[test]
    fn with_preparation() {
        let i = RecipeParser::parse_ingredient("3 cloves garlic, minced");
        assert_eq!(i.quantity, Some(3.0));
        assert_eq!(i.unit.as_deref(), Some("cloves"));
        assert_eq!(i.item, "garlic");
        assert_eq!(i.preparation.as_deref(), Some("minced"));
    }

    #[test]
    fn parenthetical_can_size() {
        let i = RecipeParser::parse_ingredient("1 (14 oz) can diced tomatoes");
        assert_eq!(i.quantity, Some(1.0));
        assert_eq!(i.unit.as_deref(), Some("can"));
        assert!(i.item.contains("diced tomatoes"));
    }

    #[test]
    fn to_taste_is_optional() {
        let i = RecipeParser::parse_ingredient("Salt and pepper to taste");
        assert!(i.optional);
    }

    #[test]
    fn jsonld_recipe() {
        let html = r#"
        <html><head>
        <script type="application/ld+json">
        {
          "@context": "https://schema.org",
          "@type": "Recipe",
          "name": "Chili",
          "recipeYield": "4 servings",
          "prepTime": "PT15M",
          "cookTime": "PT45M",
          "recipeIngredient": ["1 lb ground beef", "1 (14 oz) can diced tomatoes", "2 tbsp chili powder"],
          "recipeInstructions": ["Brown beef", "Add tomatoes and simmer"]
        }
        </script>
        </head></html>
        "#;
        let r = RecipeParser::from_jsonld(html).expect("parsed");
        assert_eq!(r.title, "Chili");
        assert_eq!(r.servings, 4);
        assert_eq!(r.prep_time_minutes, Some(15));
        assert_eq!(r.cook_time_minutes, Some(45));
        assert_eq!(r.ingredients.len(), 3);
        assert_eq!(r.ingredients[0].item, "ground beef");
        assert_eq!(r.instructions.len(), 2);
    }
}
