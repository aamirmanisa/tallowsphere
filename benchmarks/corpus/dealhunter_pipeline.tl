// Tallow Deal Hunter — end-to-end deal discovery & alerting pipeline.
//
// 1. Scrapes retailer deals pages
// 2. Checks each product's price history
// 3. Detects anomalies and price errors
// 4. Outputs JSONL + Discord alerts for high-value finds
//
// Run: tallow run examples/dealhunter_pipeline.tl

fn classify(discount_pct: f64) -> String {
    if discount_pct > 0.98 { return "penny" }
    if discount_pct > 0.80 { return "price_error" }
    if discount_pct > 0.60 { return "clearance" }
    if discount_pct > 0.40 { return "sale" }
    if discount_pct > 0.20 { return "discount" }
    "regular"
}

fn main() {
    print("=== Tallow Deal Hunter Pipeline ===")
    print("")

    var all_deals = ""
    var deal_count = 0
    var alert_count = 0
    var high_value_count = 0

    // Scan configured retailers
    var retailers = ["teststore"]

    for retailer in retailers {
        print("Scanning " + retailer + "...")
        let config = deals.load_retailer_config(retailer)
        print("  base_url: " + config["base_url"])

        // Step 1: Scrape deals page
        let products = deals.scrape_deals_page(retailer)
        print("  Found " + products.len.to_string() + " products")

        for product in products {
            deal_count = deal_count + 1
            let title = product["title"]
            let price = product["current_price"]["price"]
            let was_price = product["was_price"]
            let discount_pct = product["discount_pct"]
            let deal_type = classify(discount_pct)

            // Step 2: Record price history (use title hash as SKU for fixture)
            var sku = title
            let _ = deals.price_history_add(retailer, sku, price, was_price, "")
            
            // Step 3: Check for anomalies against history
            let anomaly = deals.detect_anomaly_zscore(price, retailer, sku, 2.0)
            
            // Step 4: Multi-signal price error detection
            let error_check = deals.detect_price_error(price, was_price, was_price)

            print("  [" + deal_count.to_string() + "] " + title)
            print("      $" + price.to_string() + " (was $" + was_price.to_string() + ", " + 
                  discount_pct.to_string() + "% off)")
            print("      type=" + deal_type + 
                  " anomaly=" + anomaly["is_anomaly"].to_string() + 
                  " zscore=" + anomaly["z_score"].to_string())

            // Alert on high-value finds
            if error_check["is_price_error"] == "true" {
                alert_count = alert_count + 1
                print("      🚨 PRICE ERROR: confidence=" + error_check["confidence"].to_string())
            }

            if anomaly["is_anomaly"] == "true" && anomaly["severity"] == "critical" {
                high_value_count = high_value_count + 1
                print("      ⚡ CRITICAL ANOMALY: severity=" + anomaly["severity"] + 
                      " savings=" + anomaly["savings_pct"].to_string() + "%")
            }
        }

        // Step 5: Price history stats per retailer
        let stats = deals.price_history_stats(retailer, sku)
        print("")
        print("  Price stats: count=" + stats["count"].to_string() + 
              " avg=$" + stats["avg"].to_string() + 
              " trend=" + stats["trend"])
    }

    print("")
    print("=== Pipeline Complete ===")
    print("Deals scanned: " + deal_count.to_string())
    print("Price errors: " + alert_count.to_string())
    print("Critical anomalies: " + high_value_count.to_string())
    print("Output: artifacts/deals/price_history/")
}
