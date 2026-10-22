/// FRED economic data: GDP, CPI, unemployment, interest rates.
module tallow.fred

/// Get series metadata
native fn series(api_key: String, series_id: String) -> Map
/// Get observations for a series
native fn observations(api_key: String, series_id: String, limit: Int) -> []Observation
/// Search for economic data series
native fn search(api_key: String, query: String, limit: Int) -> []FREDSeries
/// Get series in a category
native fn category(api_key: String, category_id: String) -> Map

struct Observation {
    date: String,
    value: String,
}

struct FREDSeries {
    id: String,
    title: String,
    frequency: String,
    units: String,
}
