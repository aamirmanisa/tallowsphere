// Tallow Deal Hunter — test script against local fixture.
// Run: tallow run examples/test_dealhunter.tl

import tallow.deals

fn main() {
    print("=== Tallow Deal Hunter Test ===")

    // Test 1: load_retailer_config
    print("Test 1: load_retailer_config(\"teststore\")")
    let config = deals.load_retailer_config("teststore")
    print("  name = " + config["name"] + " (expected: teststore)")
    print("  base_url = " + config["base_url"])

    // Test 2: compare_price — pure math
    print("Test 2: compare_price")
    let d1 = deals.compare_price(299.0, 520.0)
    print("  compare_price(299, 520) = " + d1.to_string() + " (expect ~0.425)")
    let d2 = deals.compare_price(460.0, 1799.0) 
    print("  compare_price(460, 1799) = " + d2.to_string() + " (expect ~0.744)")
    let d3 = deals.compare_price(4.0, 140.0)
    print("  compare_price(4, 140) = " + d3.to_string() + " (expect ~0.971)")

    // Test 3: detect_anomaly with empty list
    print("Test 3: detect_anomaly(299, [], 0.20)")
    var empty_list: List<String> = []
    let result = deals.detect_anomaly(299.0, empty_list, 0.20)
    print("  is_anomaly = " + result["is_anomaly"].to_string() + " (expect false)")
    print("  severity = " + result["severity"] + " (expect none)")
    print("  sample_count = " + result["sample_count"].to_string() + " (expect 0)")

    // Test 4: scrape_deals_page against local fixture
    print("Test 4: scrape_deals_page(\"teststore\")")
    let products = deals.scrape_deals_page("teststore")
    print("  products found: " + products.len.to_string())
    var idx = 0
    for product in products {
        idx = idx + 1
        print("  [" + idx.to_string() + "] title=" + product["title"] + " price=" + product["current_price"]["price"].to_string())
    }

    // Test 5: price_check against local fixture
    print("Test 5: price_check against local fixture")
    let pp = deals.price_check("http://127.0.0.1:18923/tallow_test_deals.html", "teststore")
    print("  price = " + pp["price"].to_string())
    print("  was_price = " + pp["was_price"].to_string())
    print("  discount_pct = " + pp["discount_pct"].to_string())
    print("  in_stock = " + pp["in_stock"].to_string())
    print("  title = " + pp["title"])

    print("=== All tests complete ===")
}
