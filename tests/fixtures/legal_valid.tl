@legal(basis: .public_data, purpose: "test", retain_for: 7.days)
fn fetch_data(url: URL) -> Result<String> {
    let resp = fetch(url)?
    Ok(resp.text())
}
