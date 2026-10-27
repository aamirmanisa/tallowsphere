type Port = u16
newtype UserId = String

fn label(id: UserId) -> String {
    return "user:{id.inner}"
}

fn main() {
    let p: Port = 8443
    print("port {p}")
    let id = UserId("ada")
    print(label(id))
    print(id.inner)
}
