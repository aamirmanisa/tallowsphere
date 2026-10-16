// Invalid consent usage: direct access to Consent inner value

fn process_raw(data: String) -> String { data }

fn bad_direct_method(data: Consent<String>) -> i32 {
    data.len()
}

fn bad_pass_unwrapped(data: Consent<String>) -> String {
    process_raw(data)
}
