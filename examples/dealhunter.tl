// Tallow Deal Hunter — multi-retailer deal scraper.
//
// Scrapes deals pages, extracts product data, detects price anomalies.
// Output: dealhunter_products.jsonl + dealhunter_alerts.jsonl
//
// Run: tallow run examples/dealhunter.tl

import tallow.deals

struct ScrapedDeal {
    retailer: String,
    url: String,
    title: String,
    price: f64,
    was_price: f64,
    discount_pct: f64,
    image_url: String,
    deal_type: String,
    extracted_at: String,
}

fn json_escape(s: String) -> String {
    s.replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
}

fn classify_deal(discount_pct: f64, title: String) -> String {
    if title.contains("penny") || discount_pct > 0.98 { return "penny" }
    if discount_pct > 0.80 { return "price_error" }
    if discount_pct > 0.60 { return "clearance" }
    if discount_pct > 0.40 { return "sale" }
    if discount_pct > 0.20 { return "discount" }
    "regular"
}

fn deal_to_jsonl(deal: ScrapedDeal) -> String {
    var line = '{'
    line = line + '"retailer":"' + json_escape(deal.retailer) + '",'
    line = line + '"url":"' + json_escape(deal.url) + '",'
    line = line + '"title":"' + json_escape(deal.title) + '",'
    line = line + '"price":' + deal.price.to_string() + ","
    line = line + '"was_price":' + deal.was_price.to_string() + ","
    line = line + '"discount_pct":' + deal.discount_pct.to_string() + ","
    line = line + '"image_url":"' + json_escape(deal.image_url) + '",'
    line = line + '"deal_type":"' + json_escape(deal.deal_type) + '",'
    line = line + '"extracted_at":"' + json_escape(deal.extracted_at) + '"'
    line + "}\n"
}

@legal(basis: .public_data, purpose: "collect public deal data from retailer websites", personal_data: false, robots_txt: .respect, rate_limit: 1.per_second)
fn main() {
    var retailers = ["teststore"]

    var all_deals = ""
    var deal_count = 0
    var alert_count = 0

    for retailer in retailers {
        print("Scanning " + retailer + "...")

        let config = deals.load_retailer_config(retailer)
        let deals_url = config["deals_page_url"]

        let products = deals.scrape_deals_page(retailer)
        print("  Found " + products.len.to_string() + " products")

        for product in products {
            let discount_pct = product["discount_pct"]
            let title = product["title"]
            let price = product["current_price"]["price"]
            let was_price = product["was_price"]

            let deal_type = classify_deal(discount_pct, title)

            let deal = ScrapedDeal {
                retailer: retailer,
                url: deals_url,
                title: title,
                price: price,
                was_price: was_price,
                discount_pct: discount_pct,
                image_url: product["image_url"],
                deal_type: deal_type,
                extracted_at: "",
            }

            all_deals = all_deals + deal_to_jsonl(deal)
            deal_count = deal_count + 1

            if deal_type == "price_error" || deal_type == "penny" {
                print("  🚨 " + deal_type + ": " + title + " — $" + price.to_string() + " (" + discount_pct.to_string() + "% off)")
                alert_count = alert_count + 1
            }
        }
    }

    write_file("dealhunter_products.jsonl", all_deals)
    print("")
    print("Done. " + deal_count.to_string() + " deals found, " + alert_count.to_string() + " high-value alerts.")
}
