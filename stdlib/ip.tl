// tallow.ip — offline IP intelligence, N33: ASN/prefix attribution.
//
// Nothing here opens a socket. `load` reads a table the caller or the
// environment names. A caller that wants a fresher answer fetches it itself,
// under its own grant, and hands it here — this module is the memory, not the
// fetch.
//
// An ASN is either measured or unknown, never 0 by default.
//
// `load` resolves its table in a fixed order, and the resolved path travels
// back in the result so every answer can name its own provenance:
//   1. the explicit `path` argument;
//   2. `TALLOW_IP2ASN` (the variable `topology` already honours);
//   3. `/usr/share/ip2asn/ip2asn-v4.tsv`.
// A missing or unreadable file is refused with `ip:table-missing`, naming the
// path and the step that chose it. An empty file is refused with
// `ip:table-empty`. A malformed line refuses the whole load with
// `ip:table-malformed` and names `source:line` — one bad line voids the table,
// because a partially-loaded routing table silently mislabels every prefix the
// lost line covered. Blank lines and `#` comments are skipped; a single leading
// header line is tolerated.
//
// `lookup` returns the **longest** matching prefix, not the first row that
// covers the address: a `/8` listed earlier cannot shadow a `/24` listed later.
// `prefix_len` is the number of leading bits the row's range covers (the exact
// prefix length for an aligned range). When nothing covers the address the
// refusal is `ip:not-in-table` — absence is not ASN 0. IPv6 is refused with
// `ip:unsupported-family` rather than answered from a v4 table.

// A loaded ASN table. `handle` is a process-local id, not data: it cannot be
// serialised, reconstructed, or forged into a table that was never loaded.
// `source` and `rows` are the provenance a caller needs to quote an answer.
struct IpAsnTable {
    handle: Int,
    source: String,
    rows:   Int,
}

// The longest matching entry for one address. `asn` is the ASN number
// (`64500`), not the string `AS64500`.
struct AsnMatch {
    asn:         Int,
    prefix_len:  Int,
    country:     String,
    description: String,
    source:      String,
}

// Load the ASN table: explicit path, then `TALLOW_IP2ASN`, then the default
// location. Refuses (`ip:table-missing`, `ip:table-empty`, `ip:table-malformed`)
// rather than returning a table that was never read.
native fn ip.load(path: String?) -> IpAsnTable

// Preflight a path: returns false when the file exists, and the same
// `ip:table-missing` refusal when it does not — without parsing a real table.
native fn ip.load_missing(path: String) -> Bool

// Longest-prefix IPv4 lookup. Refuses `ip:not-in-table`, `ip:bad-address`,
// `ip:unsupported-family`, or `ip:table-unknown` for a handle not issued here.
native fn ip.lookup(table: IpAsnTable, ip: String) -> AsnMatch
