# goodnet-link-udp

UDP datagram transport for GoodNet. Maps `udp://host:port` URIs to
per-source sockets and surfaces inbound datagrams through
`host_api->notify_inbound_bytes`. Datagram delivery is best-effort
and unordered — pair this transport with a security provider that
runs a frame-layer replay window (the v1 Noise XX provider does
not, hence noise + UDP is unsupported in v1).

**Kind**: link · **Artefact**: dynamic plugin (`.so` via dlopen)
· **License**: GPL-2.0 with Linking Exception (see `LICENSE`)

## Build

This plugin lives in its own git with a flake that pulls the
kernel SDK as a Nix input. From this checkout:

```sh
nix run .#build         # release build of libgoodnet_link_udp.so
nix run .#test          # vanilla ctest
nix run .#test-asan     # AddressSanitizer + UBSan
nix run .#test-tsan     # ThreadSanitizer
```

The kernel monorepo also builds this plugin in-tree through its
own `nix run .#build -- release` — operator install consumes
every bundled `.so` from there.

## Load

Manifest entry pins the SHA-256 digest; `gn_plugin_init` registers
the `udp` scheme. See `docs/install.en.md` and
`docs/contracts/plugin-manifest.en.md` in the kernel tree.

## Contract

- Kernel-side link contract: `docs/contracts/link.en.md`
- Datagram-class invariants: `docs/contracts/link.en.md` §8
  (capability bits, including `GN_LINK_CAP_RELIABLE`)
