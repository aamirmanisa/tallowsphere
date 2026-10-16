// Tallow Deal Hunter — standalone CLI binary.
// Usage: cargo run --bin dealhunter -- [command] [args]
//
// Commands:
//   scrape <retailer>     — scrape deals page, print products
//   check <url> <retailer> — price check a specific URL
//   monitor              — watch teststore for price errors
//   history <retailer> <sku> — show price history

use tallow::Value;

fn call(fn_name: &str, args: Vec<Value>) -> Result<tallow::Value, String> {
    let opt = tallow::stdlib::deals::dispatch(fn_name, args);
    let result = opt.ok_or_else(|| format!("unknown function: {fn_name}"))?;
    result
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Tallow Deal Hunter v1.0");
        eprintln!("  dealhunter scrape <retailer>");
        eprintln!("  dealhunter check <url> <retailer>");
        eprintln!("  dealhunter monitor");
        eprintln!("  dealhunter history <retailer> <sku>");
        return;
    }

    let result = match args[1].as_str() {
        "scrape" => {
            let retailer = args.get(2).map(|s| s.as_str()).unwrap_or("teststore");
            call("scrape_deals_page", vec![Value::String(retailer.to_string())])
        }
        "check" => {
            let url = args.get(2).expect("URL required");
            let retailer = args.get(3).map(|s| s.as_str()).unwrap_or("teststore");
            call("price_check", vec![
                Value::String(url.to_string()),
                Value::String(retailer.to_string()),
            ])
        }
        "monitor" => {
            let source = r#"fn main() {
var products = deals.scrape_deals_page("teststore")
print(products.len().to_string())
var alerts = 0
for product in products {
    let price = product["current_price"]["price"]
    let was = product["was_price"]
    let disc = product["discount_pct"]
    let title = product["title"]
    let err = deals.detect_price_error(price, was, was)
    let is_err = err["is_price_error"]
    let conf = err["confidence"]
    print("---")
    print(title)
    print("$" + price.to_string())
    if was > 0.0 { print("was $" + was.to_string()) }
    print("discount: " + disc.to_string())
    if is_err {
        print("🚨 PRICE ERROR (conf: " + conf.to_string() + ")")
        alerts = alerts + 1
    }
}
print("---")
print(alerts.to_string() + " alerts")
}"#;

            let (tokens, errors) = tallow::lexer::tokenize(source);
            if !errors.is_empty() {
                for e in &errors {
                    eprintln!("lex error: {e}");
                }
                return;
            }
            let program = match tallow::parser::Parser::parse(tokens) {
                Ok(p) => p,
                Err(e) => { eprintln!("parse error: {e}"); return; }
            };
            let mut interp = tallow::interp::Interpreter::new();
            match interp.run(&program) {
                Ok(_v) => {}
                Err(e) => { eprintln!("run error: {e:?}"); return; }
            }
            for line in &interp.output {
                println!("{line}");
            }
            return;
        }
        "history" => {
            let retailer = args.get(2).map(|s| s.as_str()).unwrap_or("teststore");
            let sku = args.get(3).expect("SKU required");

            println!("=== Price Points ===");
            match call("price_history_get", vec![
                Value::String(retailer.to_string()),
                Value::String(sku.to_string()),
            ]) {
                Ok(v) => {
                    let json = tallow::stdlib::deals::value_to_json(&v)
                        .unwrap_or_else(|e| serde_json::Value::String(e));
                    println!("{}", serde_json::to_string_pretty(&json).unwrap_or_default());
                }
                Err(e) => eprintln!("history error: {e}"),
            }

            println!("\n=== Stats ===");
            match call("price_history_stats", vec![
                Value::String(retailer.to_string()),
                Value::String(sku.to_string()),
            ]) {
                Ok(v) => {
                    let json = tallow::stdlib::deals::value_to_json(&v)
                        .unwrap_or_else(|e| serde_json::Value::String(e));
                    println!("{}", serde_json::to_string_pretty(&json).unwrap_or_default());
                }
                Err(e) => eprintln!("stats error: {e}"),
            }
            return;
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            return;
        }
    };

    match result {
        Ok(v) => {
            let json = tallow::stdlib::deals::value_to_json(&v)
                .unwrap_or_else(|e| serde_json::Value::String(e));
            println!("{}", serde_json::to_string_pretty(&json).unwrap_or_default());
        }
        Err(e) => eprintln!("Error: {e}"),
    }
}
