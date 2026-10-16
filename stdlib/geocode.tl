// tallow.geocode — offline address normalization and join keys.
//
// Pure US-address utilities for joining or deduplicating records across
// sources without a geocoding service: canonical street/state expansion,
// house-number + street + ZIP5 parse keys, ZIP validation, and state
// name <-> abbreviation lookup. All offline and deterministic.

struct GeoParts {
    house: String,
    street: String,
    city: String,
    state: String,
    zip: String,
}

/// Canonical full address ("123 Main St #4" -> "123 main street apt 4").
native fn normalize_address(address: String) -> String

/// Parse a US-format address into house/street/city/state/zip parts.
native fn parse_address(address: String) -> GeoParts

/// "house|street|zip" join key from a raw address.
native fn address_key(address: String) -> String

/// Explicit "house|street|zip" join key from user-supplied parts.
native fn join_key(house: String, street: String, zip: String) -> String

/// First 5-digit run in the string, else "".
native fn zip5(s: String) -> String

/// True when the input is exactly 5 digits or ZIP+4 ("78701-1234").
native fn is_zip5(s: String) -> Bool

/// State name to abbreviation ("Texas" -> "TX"); "" if unknown.
native fn state_from_name(name: String) -> String

/// Abbreviation to state name ("TX" -> "Texas"); "" if unknown.
native fn state_from_abbrev(abbrev: String) -> String
