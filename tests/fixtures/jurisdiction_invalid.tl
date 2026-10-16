// Invalid jurisdiction usage: cross-border transfer violations

@jurisdiction(.eu)
type EUData = private String

@jurisdiction(.cn)
fn process_in_china(data: EUData) -> String {
    "processed in China"
}

@jurisdiction(.eu)
fn bad_transfer(data: EUData) -> String {
    process_in_china(data)
}
