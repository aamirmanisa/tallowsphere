/// Yield curve construction: bootstrap, Nelson-Siegel, Svensson.
module tallow.curves

/// Bootstrap zero curve from par instruments
native fn bootstrap(instruments: []{{tenor: Float, rate: Float}}) -> []CurvePoint
/// Nelson-Siegel parametric curve
native fn nelson_siegel(tenors: []Float, b0: Float, b1: Float, b2: Float, tau: Float) -> []CurvePoint
/// Svensson extended curve
native fn svensson(tenors: []Float, b0: Float, b1: Float, b2: Float, b3: Float, tau1: Float, tau2: Float) -> []CurvePoint
/// Linear interpolation on curve
native fn interpolate(curve: []CurvePoint, t: Float) -> Float
/// Forward rate between T1 and T2
native fn forward_rate(curve: []CurvePoint, t1: Float, t2: Float) -> Float
/// Discount factor at tenor T
native fn discount_factor(curve: []CurvePoint, t: Float) -> Float

struct CurvePoint {
    tenor: Float,
    rate: Float,
}
