// ═══════════════════════════════════════════════════════════════
// Tallow End-to-End Test: Scrape → Analyze → Export
// Tests: Yahoo Finance, SEC EDGAR, Portfolio Optimization,
//        Heston Pricing, Yield Curves, Sentiment, CSV Export
// ═══════════════════════════════════════════════════════════════

// ── 1. Market Data: Fetch quotes for Magnificent 7 ──

let tickers = ["AAPL", "MSFT", "GOOGL", "AMZN", "META", "NVDA", "TSLA"];

let quotes = tickers.map(|t| {
    let q = Yahoo.quote(t);
    print("${t}: ${q.price} (${q.change_pct}%)  Vol: ${q.volume}  P/E: ${q.pe_ratio}");
    (t, q)
}).to_map();

// ── 2. SEC EDGAR: Get Apple's latest filing ──

let aapl_cik = Edgar.cik_lookup("AAPL");
print("AAPL CIK: ${aapl_cik.cik} — ${aapl_cik.title}");

let facts = Edgar.company_facts(aapl_cik.cik);
print("SEC facts loaded for AAPL");

// ── 3. Portfolio Optimization: Build optimal weights ──

let returns = quotes.values().map(|q| q.change_pct).to_array();
let cov = Portfolio.covariance([returns]); // single-asset for demo
// Multi-asset: get history for each ticker
let prices = tickers.map(|t| {
    let bars = Yahoo.history(t, "1mo", "1d");
    bars.map(|b| b.close)
});

let asset_returns = Portfolio.returns(prices);
let cov_matrix = Portfolio.covariance(asset_returns);
let expected_rets = asset_returns.map(|r| r.mean());
let weights = Portfolio.markowitz(cov_matrix, expected_rets, 0.15);

print("Portfolio weights:");
weights.iter().enumerate().each(|(i, w)| {
    print("  ${tickers[i]}: ${(w * 100).round(1)}%");
});

// ── 4. Heston Pricing: Options on NVDA ──

let nvda = quotes["NVDA"];
let heston_price = Heston.price(
    "call",
    S: nvda.price,
    K: nvda.price * 1.05,  // 5% OTM
    T: 0.25,                // 3 months
    r: 0.05,
    kappa: 2.0, theta: 0.04, sigma: 0.35, v0: 0.05, rho: -0.7,
);
print("NVDA 5% OTM call (Heston): ${heston_price}");

// Also compute Greeks
let greeks = Options.greeks("call", nvda.price, nvda.price * 1.05, 0.25, 0.05, 0.35);
print("NVDA Greeks: delta=${greeks.delta} gamma=${greeks.gamma} vega=${greeks.vega} theta=${greeks.theta}");

// ── 5. Yield Curve: Current US Treasury curve ──

let curve = Curves.bootstrap([
    {tenor: 0.25, rate: 0.0525},
    {tenor: 0.5,  rate: 0.0510},
    {tenor: 1.0,  rate: 0.0480},
    {tenor: 2.0,  rate: 0.0440},
    {tenor: 5.0,  rate: 0.0410},
    {tenor: 10.0, rate: 0.0425},
    {tenor: 30.0, rate: 0.0440},
]);

let fwd_1y_5y = Curves.forward_rate(curve, 1.0, 5.0);
let df_10y = Curves.discount_factor(curve, 10.0);

print("Forward 1y→5y: ${(fwd_1y_5y * 100).round(2)}%");
print("10Y discount factor: ${df_10y.round(4)}");

// Also try Nelson-Siegel parameterization
let ns_curve = Curves.nelson_siegel(
    [0.25, 0.5, 1, 2, 3, 5, 7, 10, 20, 30],
    0.044, -0.015, -0.01, 2.0
);
print("Nelson-Siegel fitted curve: ${ns_curve.len()} points");

// ── 6. Sentiment: Analyze a mock SEC risk factors text ──

let risk_text = "The company faces significant risks including potential litigation, 
    regulatory uncertainty, competitive pressures, and macroeconomic headwinds. 
    However, our strong market position, innovative products, and robust balance 
    sheet provide substantial advantages and opportunities for growth.";

let sentiment = Sentiment.analyze(risk_text);
print("Sentiment: ${sentiment.sentiment} (score: ${sentiment.score.round(1)})");
print("  Negative: ${sentiment.negative}  Positive: ${sentiment.positive}");
print("  Uncertainty: ${sentiment.uncertainty}  Litigious: ${sentiment.litigious}");

// ── 7. Technical Analysis: NVDA momentum ──

let nvda_bars = Yahoo.history("NVDA", "3mo", "1d");
let closes = nvda_bars.map(|b| b.close);
let rsi = Technical.rsi(closes, 14);
let macd = Technical.macd(closes, 12, 26, 9);
let bb = Technical.bollinger(closes, 20, 2.0);

print("NVDA RSI(14): ${rsi.round(1)}");
print("NVDA MACD: line=${macd.0.round(2)} signal=${macd.1.round(2)} hist=${macd.2.round(2)}");
print("NVDA Bollinger: mid=${bb.0.round(2)} upper=${bb.1.round(2)} lower=${bb.2.round(2)}");

// ── 8. Backtest: Simple momentum strategy on NVDA ──

let signals = Algols.momentum(closes, 20);
let bt_result = Algols.backtest(closes, signals);

print("Backtest: return=${(bt_result.total_return * 100).round(1)}%");
print("  Sharpe: ${bt_result.sharpe_ratio.round(2)}");
print("  Max DD: ${(bt_result.max_drawdown * 100).round(1)}%");
print("  Trades: ${bt_result.trades}");

// ── 9. Export everything ──

export {
    quotes: quotes |> CSV.write("output/quotes.csv"),
    weights: weights |> JSON.write("output/weights.json"),
    sentiment: sentiment |> JSON.write("output/sentiment.json"),
    backtest: bt_result.equity_curve |> CSV.write("output/equity_curve.csv"),
    summary: {
        ticker_count: tickers.len(),
        portfolio_sharpe: Portfolios.sharpe(asset_returns[0], 0.05),
        nvda_rsi: rsi,
        market_sentiment: sentiment.sentiment,
        forward_rate: fwd_1y_5y,
    } |> JSON.write("output/summary.json"),
};

print("✅ End-to-end test complete. Output in output/");
