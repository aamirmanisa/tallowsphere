// Valid consent usage: access via .with_consent {}

fn process(data: Consent<String>) -> String {
    data.with_consent { val -> val }
}

fn get_consent_id(data: Consent<String>) -> String {
    data.consent_id()
}

fn revoke(data: Consent<String>) -> Consent<String> {
    data.withdraw()
}
