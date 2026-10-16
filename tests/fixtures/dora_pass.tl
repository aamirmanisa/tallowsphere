// Fixture: DORA pass case (cycle-02/08 §b test list).
// Art.17 (@legal traceability) + Art.19 (DoraCitIncident logging) both pass.
@legal(basis: .contract, purpose: "ICT incident management")
fn log_ict_incident(description: String) -> String {
    let incident = DoraCitIncident.new(description)
    let classified = DoraCitIncident.classify(incident)
    DoraCitIncident.report(classified)
}

fn main() {
    let report = log_ict_incident("server outage during peak hours")
    print(report)
}
