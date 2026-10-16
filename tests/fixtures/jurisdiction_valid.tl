// Valid jurisdiction usage: EU data within adequate countries

@jurisdiction(.eu)
type EUPersonalData = private String

@jurisdiction(.eu)
fn process_in_eu(data: EUPersonalData) -> String {
    "processed in EU"
}

@jurisdiction(.uk)
fn process_in_uk(data: EUPersonalData) -> String {
    "processed in UK (adequate)"
}

@jurisdiction(.ch)
fn process_in_ch(data: EUPersonalData) -> String {
    "processed in Switzerland (adequate)"
}

@jurisdiction(.eu)
fn orchestrate(data: EUPersonalData) -> String {
    process_in_eu(data)
}
