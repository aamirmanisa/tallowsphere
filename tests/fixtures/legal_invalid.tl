// Should fail: missing @legal on network-touching function
fn fetch_data(url: URL) -> Result<String> {
    let resp = fetch(url)?
    Ok(resp.text())
}
