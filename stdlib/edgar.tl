/// SEC EDGAR API client for company filings.
module tallow.edgar

/// Company facts (XBRL-as-JSON)
native fn company_facts(cik: String) -> Map
/// Filing submission history
native fn submissions(cik: String) -> Map
/// Specific taxonomy concept data
native fn company_concept(cik: String, taxonomy: String, concept: String) -> Map
/// Lookup CIK by ticker symbol
native fn cik_lookup(ticker: String) -> {cik: String, ticker: String, title: String}
