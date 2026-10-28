// User-path demonstration: the two network capabilities that have no backend
// in this build refuse in their return value. Run with:
//     tallow run tests/fixtures/unsupported_net.tl
// Expected: exit 70 and the refusal text on stderr naming the missing backend.

fn main() with Net(tunnel_wireguard) {
    let t = net.tunnel_wireguard("vpn.example.com:51820", "base64pubkey==")
    print("Tunnel status: {t.status}")
}
