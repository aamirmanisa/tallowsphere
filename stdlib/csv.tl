/// CSV file reading and writing with auto-type detection.
module tallow.csv

/// Read CSV file with optional headers
native fn read(path: String, has_headers: Bool) -> [][]String
/// Write data to CSV
native fn write(path: String, rows: [][]String, headers: []String) -> Bool
/// Parse CSV string
native fn parse_string(text: String, has_headers: Bool) -> [][]String
