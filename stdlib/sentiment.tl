/// Loughran-McDonald financial sentiment analysis.
module tallow.sentiment

/// Full sentiment analysis with all 7 LM categories
native fn analyze(text: String) -> SentimentResult
/// Sentiment score only: (positive - negative) / total_words
native fn score(text: String) -> Float

struct SentimentResult {
    total_words: Int,
    lm_hits: Int,
    negative: Int,
    positive: Int,
    uncertainty: Int,
    litigious: Int,
    strong_modal: Int,
    weak_modal: Int,
    constraining: Int,
    score: Float,
    sentiment: String,  // "bullish", "positive", "neutral", "negative", "bearish"
}
