// SMB Deal Hunter public max scraper.
//
// This is intentionally scoped to public, robots-allowed data:
//   - www.smbdealhunter.xyz/sitemap.xml
//   - public /p/new-deals... and /p/new-off-market-businesses... posts
//   - public app.smbdealhunter.xyz/item-detail?recordId=... links rendered in posts
//
// It does not bypass Beehiiv/Softr login, private Airtable APIs, paywalls,
// Turnstile, or member-only flows.
//
// Outputs:
//   smbdealhunter_public_businesses.jsonl
//   smbdealhunter_public_posts.jsonl
//   smbdealhunter_public_graph.jsonl
//
// The post worker is written for parallel_map. The interpreter currently runs
// parallel_map sequentially; the compiled backend can parallelize it.

fn find_from(s: String, needle: String, start: i64) -> i64 {
    if needle.len == 0 { return start }
    var i = start
    while i + needle.len <= s.len {
        if s.substring(i, i + needle.len) == needle { return i }
        i = i + 1
    }
    -1
}

fn between_from(s: String, left: String, right: String, start: i64) -> String {
    let a = find_from(s, left, start)
    if a < 0 { return "" }
    let body_start = a + left.len
    let b = find_from(s, right, body_start)
    if b < 0 { return "" }
    s.substring(body_start, b)
}

fn strip_tags(html: String) -> String {
    var out = ""
    var i = 0
    var in_tag = false
    while i < html.len {
        let c = html.substring(i, i + 1)
        if c == "<" {
            in_tag = true
            out = out + " "
        } else if c == ">" {
            in_tag = false
            out = out + " "
        } else if !in_tag {
            out = out + c
        }
        i = i + 1
    }
    out
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("\r", " ")
        .replace("\n", " ")
        .replace("\t", " ")
        .trim()
}

fn squeeze(s: String) -> String {
    var out = s
    var last = ""
    while out != last {
        last = out
        out = out.replace("  ", " ")
    }
    out.trim()
}

fn json_escape(s: String) -> String {
    s.replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
        .replace("\t", "\\t")
}

fn jf(name: String, value: String, comma: bool) -> String {
    let suffix = if comma { "," } else { "" }
    "\"{name}\":\"{json_escape(value)}\"{suffix}"
}

fn graph_node(id: String, label: String, kind: String) -> String {
    "\{" + jf("type", "node", true) + jf("id", id, true) + jf("kind", kind, true) + jf("label", label, false) + "\}\n"
}

fn graph_edge(from_id: String, to_id: String, rel: String) -> String {
    "\{" + jf("type", "edge", true) + jf("from", from_id, true) + jf("to", to_id, true) + jf("rel", rel, false) + "\}\n"
}

fn field_between(text: String, label: String, next1: String, next2: String, next3: String) -> String {
    let start = find_from(text, label, 0)
    if start < 0 { return "" }
    let body_start = start + label.len
    var end = text.len
    let a = find_from(text, next1, body_start)
    if a >= 0 && a < end { end = a }
    let b = find_from(text, next2, body_start)
    if b >= 0 && b < end { end = b }
    let c = find_from(text, next3, body_start)
    if c >= 0 && c < end { end = c }
    squeeze(text.substring(body_start, end))
}

fn clean_title(html: String) -> String {
    squeeze(strip_tags(between_from(html, "<title>", "</title>", 0)))
}

fn published_at(html: String) -> String {
    between_from(html, "\"datePublished\":\"", "\"", 0)
}

fn record_id_from_url(url: String) -> String {
    let marker = "recordId="
    let p = find_from(url, marker, 0)
    if p < 0 { return "" }
    url.substring(p + marker.len, url.len)
}

fn detail_name(post_html: String, detail_url: String) -> String {
    let pos = find_from(post_html, detail_url, 0)
    if pos < 0 { return "" }
    let a_close = find_from(post_html, ">", pos)
    if a_close < 0 { return "" }
    let a_end = find_from(post_html, "</a>", a_close)
    if a_end < 0 { return "" }
    squeeze(strip_tags(post_html.substring(a_close + 1, a_end)))
}

fn window_around(post_html: String, detail_url: String) -> String {
    let pos = find_from(post_html, detail_url, 0)
    if pos < 0 { return post_html }
    var start = 0
    if pos > 12000 { start = pos - 12000 }
    var end = pos + 26000
    if end > post_html.len { end = post_html.len }
    post_html.substring(start, end)
}

fn business_row(post_url: String, post_title: String, post_date: String, post_html: String, detail_url: String) -> String {
    let record_id = record_id_from_url(detail_url)
    let text = squeeze(strip_tags(window_around(post_html, detail_url)))
    let name = detail_name(post_html, detail_url)
    let location = field_between(text, "Location:", "Asking Price:", "EBITDA:", "Revenue:")
    let asking = field_between(text, "Asking Price:", "Cash Flow/EBITDA:", "EBITDA:", "Revenue:")
    let ebitda = field_between(text, "EBITDA:", "Revenue:", "Established:", "My 2 Cents:")
    let revenue = field_between(text, "Revenue:", "Established:", "Year Established:", "My 2 Cents:")
    let established = field_between(text, "Established:", "My 2 Cents:", "Helen's 2 Cents:", "View Listing")
    let commentary = field_between(text, "My 2 Cents:", "View Listing", "Source:", "Want more")

    var line = "\{"
    line = line + jf("record_id", record_id, true)
    line = line + jf("source_post_url", post_url, true)
    line = line + jf("detail_url", detail_url, true)
    line = line + jf("post_title", post_title, true)
    line = line + jf("published_at", post_date, true)
    line = line + jf("name", name, true)
    line = line + jf("location", location, true)
    line = line + jf("asking_price", asking, true)
    line = line + jf("cash_flow_ebitda", ebitda, true)
    line = line + jf("revenue", revenue, true)
    line = line + jf("year_established", established, true)
    line = line + jf("commentary", commentary, false)
    line + "\}\n"
}

fn post_row(post_url: String, post_title: String, post_date: String, deal_count: i64) -> String {
    var line = "\{"
    line = line + jf("url", post_url, true)
    line = line + jf("title", post_title, true)
    line = line + jf("published_at", post_date, true)
    line = line + "\"deal_count\":{deal_count}"
    line + "\}\n"
}

fn scrape_post(post_url: String) -> String {
    let response = fetch(post_url)
    let post_html = response.body
    let post_title = clean_title(post_html)
    let post_date = published_at(post_html)
    let links = HtmlParser.links(post_html)

    var seen = "|"
    var businesses = ""
    var graph = graph_node(post_url, post_title, "post")
    var count = 0

    for link in links {
        if link.contains("https://app.smbdealhunter.xyz/item-detail?recordId=") {
            let record_id = record_id_from_url(link)
            let key = "|{record_id}|"
            if record_id.len > 0 && !seen.contains(key) {
                seen = seen + record_id + "|"
                count = count + 1
                businesses = businesses + business_row(post_url, post_title, post_date, post_html, link)
                graph = graph + graph_node(record_id, detail_name(post_html, link), "business")
                graph = graph + graph_edge(post_url, record_id, "mentions")
            }
        }
    }

    post_row(post_url, post_title, post_date, count) + "----BUSINESSES----\n" + businesses + "----GRAPH----\n" + graph
}

@legal(basis: .public_data, purpose: "collect public SMB Deal Hunter business records", personal_data: false, robots_txt: .respect, rate_limit: 1.per_second)
fn main() {
    let sitemap = fetch("https://www.smbdealhunter.xyz/sitemap.xml").body
    let locs = HtmlParser.parse(sitemap, "loc")
    let post_urls = locs.filter { url: String ->
        url.contains("https://www.smbdealhunter.xyz/p/")
            && (url.contains("/new-deals") || url.contains("/new-off-market-businesses"))
    }

    print("public candidate posts: {post_urls.len}")

    let chunks = post_urls.parallel_map { url: String -> scrape_post(url) }
    let joined = chunks.join("\n")

    // Split markers are kept in the combined artifact for auditability.
    write_file("smbdealhunter_public_combined_graphjson.txt", joined)
    print("wrote smbdealhunter_public_combined_graphjson.txt")
    print("contains post JSONL sections, business JSONL sections, and graph JSONL sections")
}
