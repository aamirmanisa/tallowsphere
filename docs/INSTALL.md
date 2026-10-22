# Installing Tallow

## Supported platforms

| Platform | Archive | Runtime requirement |
|---|---|---|
| Linux x86_64 | `tallow-linux-x86_64-<version>.tar.gz` | glibc ≥ 2.39 |
| Linux aarch64 | `tallow-linux-aarch64-<version>.tar.gz` | glibc ≥ 2.39 |
| macOS x86_64 | `tallow-macos-x86_64-<version>.tar.gz` | macOS 12+ |
| macOS arm64 | `tallow-macos-aarch64-<version>.tar.gz` | macOS 12+ |
| Windows x86_64 | `tallow-windows-x86_64-<version>.zip` | Windows 10+ |

The Linux floor is 2.39 because the archive is built on Ubuntu 24.04 and links
glibc symbols up to `GLIBC_2.39`. On an older distribution the binary loads and
dies on a symbol version; build from source instead. A static musl build is
tracked but blocked on a C++ musl toolchain (register #130).

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/aamirmanisa/tallowsphere/main/install.sh | sh
```

or, from a checkout:

```sh
./install.sh --prefix "$HOME/.local"        # user install
sudo ./install.sh --prefix /usr/local      # system install
./install.sh --from dist/tallow-linux-aarch64-1.1.5.tar.gz
```

The installer unpacks both files into `PREFIX/bin`, checks the published
sha256, and then compiles and runs a program that needs a runtime symbol. If
that probe fails, the install fails.

## What gets installed, and why two files

```
PREFIX/bin/tallow        the compiler
PREFIX/bin/libtallow.a   the runtime archive it links programs against
```

They must stay in the same directory — the compiler looks for the archive next
to its own executable first. Installing only `tallow` produces a compiler that
works until a program calls a runtime function, then fails at link with
`undefined reference to tallow_print_optional`. Download size is dominated by
the archive (~160 MB compressed), not the 45 MB compiler (row #132).

## First program

```sh
$ cat > hello.tl <<'TL'
fn main() {
    let name = "tallow"
    print("hello from " + name)
}
TL
$ tallow run hello.tl
hello from tallow
```

`tallow run` compiles and executes natively by default (a clang link per run,
~300 ms). `tallow run --interpret hello.tl` skips codegen: faster to start,
much slower per loop iteration. `tallow run --require-native` refuses the
interpreter fallback, which is how you prove the native path is the one that
ran.

## Verify a download

```sh
sha256sum -c tallow-linux-x86_64-1.1.5.tar.gz.sha256
cosign verify-blob --certificate tallow-linux-x86_64-1.1.5.tar.gz.pem \
  --signature tallow-linux-x86_64-1.1.5.tar.gz.sig \
  --certificate-identity-regexp 'https://github.com/aamirmanisa/tallowsphere/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  tallow-linux-x86_64-1.1.5.tar.gz
```

## Troubleshooting

- `undefined reference to tallow_*` — `libtallow.a` is missing, or is from a
  different build than the binary. Reinstall both from one archive.
- `version 'GLIBC_2.39' not found` — the distribution is older than Ubuntu
  24.04. Build from source.
- `native build unavailable` — clang is not installed; `tallow run
  --interpret` still works.
