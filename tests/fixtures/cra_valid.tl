// Test fixture: CRA-annotated function with crypto usage
@cra_class(.class_i)
@legal(basis: .public_data, purpose: "product security monitoring")
fn monitor_security() -> Result<String> {
    let data = "test data"
    let encrypted = data.encrypt(algo: .aes_256_gcm)
    Ok("monitoring complete")
}

// NIS2 test: function using deprecated algorithm
@legal(basis: .legitimate_interest, purpose: "legacy system support", lia_completed: true)
fn legacy_hash(data: String) -> String {
    data.hash(algo: .sha1)
}

// DORA test: function using DoraCitIncident for incident logging
@legal(basis: .contract, purpose: "ICT incident management")
fn log_ict_incident(description: String) -> String {
    let incident = DoraCitIncident.new(description)
    let incident = DoraCitIncident.set_field(incident, "critical_function_impaired", true)
    let incident = DoraCitIncident.set_field(incident, "duration_hours", 25.0)
    let classified = DoraCitIncident.classify(incident)
    let report = DoraCitIncident.report(classified)
    report
}

fn main() {
    let result = log_ict_incident("server outage during peak hours")
    print(result)
}
