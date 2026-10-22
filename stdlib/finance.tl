/// Financial analysis: time value of money, ratios, valuation.
module tallow.finance

/// Present Value: PV = FV / (1 + r)^n
native fn pv(fv: Float, rate: Float, periods: Int) -> Float
/// Future Value: FV = PV * (1 + r)^n
native fn fv(pv: Float, rate: Float, periods: Int) -> Float
/// Net Present Value of cash flows
native fn npv(rate: Float, cashflows: []Float) -> Float
/// Internal Rate of Return (Newton solver)
native fn irr(cashflows: []Float) -> Float
/// Payment for loan/annuity
native fn pmt(principal: Float, rate: Float, periods: Int) -> Float

/// Financial ratios
native fn current_ratio(current_assets: Float, current_liabilities: Float) -> Float
native fn quick_ratio(cash: Float, receivables: Float, current_liabilities: Float) -> Float
native fn debt_to_equity(total_debt: Float, total_equity: Float) -> Float
native fn roe(net_income: Float, equity: Float) -> Float
native fn roa(net_income: Float, total_assets: Float) -> Float
native fn gross_margin(revenue: Float, cogs: Float) -> Float
native fn operating_margin(operating_income: Float, revenue: Float) -> Float
native fn net_margin(net_income: Float, revenue: Float) -> Float
native fn pe_ratio(price: Float, eps: Float) -> Float
native fn pb_ratio(price: Float, book_value_per_share: Float) -> Float
native fn dividend_yield(dividend: Float, price: Float) -> Float
native fn eps(earnings: Float, shares: Int) -> Float
native fn free_cash_flow_yield(fcf: Float, market_cap: Float) -> Float
native fn interest_coverage(ebit: Float, interest_expense: Float) -> Float
native fn asset_turnover(revenue: Float, total_assets: Float) -> Float
