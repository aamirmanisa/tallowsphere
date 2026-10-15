/// GAMA Ordering API — Full Access Module
///
/// Complete access to the GAMA ordering system at gamaapiapp5.azurewebsites.net.
/// Supports login via 4-digit MobileCode, JWT-authenticated API calls, product
/// catalog enumeration via order history, and account card extraction.
///
/// Three headers used:
///   LOGIN_HEADER (corp) -> LoginApi/Login
///   DATA_HEADER (ordering) -> all data endpoints
///
/// API Base: https://gamaapiapp5.azurewebsites.net/OrderingAppApi/VOne/

/// Login with 4-digit MobileCode. Returns JSON with token, Userid, Accountno, etc.
fn login(mobilecode: String) -> String

/// Brute force login over a numeric range. Returns {scanned, found, results[]}
fn brute_login(start_code: Int, end_code: Int) -> Map

/// Authenticated POST call. token + body (form-urlencoded params)
fn get_main_menu(token: String, body: String) -> String

/// Authenticated GET call
fn get_categories(token: String, body: String) -> String

/// Get existing order list
fn get_orders(token: String, body: String) -> String

/// Get order detail / cart items (use OrderID in body)
fn get_order_detail(token: String, body: String) -> String

/// Get account cards (member store network)
fn get_account_cards(token: String, body: String) -> String

/// Search product by barcode
fn search_product(token: String, body: String) -> String

/// Get sub-menu for a department
fn get_submenu(token: String, body: String) -> String

/// Get privacy policy
fn get_privacy(token: String, body: String) -> String

/// Get terms of service
fn get_terms(token: String, body: String) -> String

/// Enumerate all products from order history.
/// token, userid, accountno, max_orders
/// Returns {orders_scanned, products_found, products[]}
fn enumerate_products(token: String, userid: String, accountno: String, max_orders: Int) -> Map

/// Return full module configuration with all 40+ endpoints
fn get_config() -> Map
