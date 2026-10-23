// tallow.json — JSON parse/serialize
//
// Type-safe JSON handling with privacy-aware serialization.
// Secret types cannot be serialized to JSON.

/// JSON value (dynamic)
enum JsonValue {
    Null,
    Bool(value: bool),
    Number(value: f64),
    Str(value: String),
    Array(items: []Box<JsonValue>),
    Object(fields: Map<String, Box<JsonValue>>),
}

/// Parse JSON string into typed value
// native: deserializes JSON into type T
native fn parse<T>(input: String) -> Result<T>

/// Parse JSON string into dynamic JsonValue
// native: parses JSON into JsonValue tree
native fn parse_value(input: String) -> Result<JsonValue>

/// Serialize value to JSON string
// native: serializes T to JSON string
// COMPILE ERROR if T contains secret types
native fn to_json<T>(value: T) -> Result<String>

/// Serialize value to pretty-printed JSON
// native: serializes with indentation
native fn to_json_pretty<T>(value: T) -> Result<String>

impl JsonValue {
    /// Get value at key (for objects)
    // returns value at key or nil
    native fn get(self, key: String) -> JsonValue?

    /// Get value at index (for arrays)
    // returns value at index or nil
    native fn at(self, index: usize) -> JsonValue?

    /// Convert to String
    fn as_string(self) -> String? {
        match self {
            Str(v) -> v
            _      -> nil
        }
    }

    /// Convert to f64
    fn as_number(self) -> f64? {
        match self {
            Number(v) -> v
            _         -> nil
        }
    }

    /// Convert to bool
    fn as_bool(self) -> bool? {
        match self {
            Bool(v) -> v
            _       -> nil
        }
    }

    /// Check if null
    fn is_null(self) -> bool {
        match self {
            Null -> true
            _    -> false
        }
    }

    /// Get array length
    fn len(self) -> usize {
        match self {
            Array(items)  -> items.len
            Object(fields) -> fields.len
            _              -> 0
        }
    }
}
