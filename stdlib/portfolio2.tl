/// Portfolio optimization: Markowitz, Black-Litterman, HRP, efficient frontier.
module tallow.portfolio2

/// Compute asset returns from price matrix
native fn returns(prices: [][]Float) -> [][]Float
/// Covariance matrix from returns
native fn covariance(returns: [][]Float) -> [][]Float
/// Markowitz mean-variance optimization
native fn markowitz(cov: [][]Float, expected_returns: []Float, target_return: Float) -> []Float
/// Black-Litterman posterior weights
native fn black_litterman(cov: [][]Float, prior: []Float, pick: [][]Float, views: []Float, tau: Float) -> []Float
/// Hierarchical Risk Parity
native fn hrp(cov: [][]Float) -> []Float
/// Efficient frontier points
native fn efficient_frontier(cov: [][]Float, returns: []Float, points: Int) -> []FrontierPoint

struct FrontierPoint {
    return: Float,
    risk: Float,
    weights: []Float,
}
