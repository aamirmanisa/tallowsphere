@agent_task(
    id:           task_id,
    timeout:      60.seconds,
    max_requests: 100,
    can_write:    false,
    can_store:    false,
    can_spawn:    false
)
@legal(basis: .research, purpose: "public data analysis")
fn research(query: String) -> String {
    let data = "results for: " + query
    data
}

fn main() {
    let result = research("test query")
    print(result)
}
