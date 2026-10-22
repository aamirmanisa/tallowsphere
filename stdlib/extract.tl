// tallow.extract — structured data extraction from HTML/text.
//
// Extracts data using predefined schemas (product, article, profile, serp,
// job), custom regex patterns, and JSON-LD structured data.

// Extract using predefined schema (product, article, profile, serp, job)
fn Extract.schema(html: String, schema_name: String) -> Map

// Extract using custom regex pattern (returns array of matches)
fn Extract.pattern(html: String, pattern: String) -> []String

// Extract JSON-LD structured data (<script type="application/ld+json">)
fn Extract.jsonld(html: String) -> []Map

// Extract all known schemas at once + JSON-LD
fn Extract.all(html: String) -> Map
