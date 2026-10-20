enum Status {
    Active,
    Pending(reason: String)
}

fn main() {
    print(Status.Pending(reason: "awaiting review"))
}
