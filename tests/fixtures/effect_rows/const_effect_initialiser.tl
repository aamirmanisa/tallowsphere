// G01 P0.3 (audit N-2 / F-14): a top-level initialiser has no signature to
// carry a row and no `main` for the trust-root exemption to point at, so it may
// not perform an effect at all. Before this, the initialiser was never walked:
// `check` exited 0 and the interpreter opened the socket at start-up.
const status: string = net.connect("127.0.0.1:18104")
