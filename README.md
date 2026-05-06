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

In-tree, alongside the kernel:

```sh
nix build .#goodnet-link-udp
# result/lib/goodnet/plugins/libgoodnet_link_udp.so
```

Standalone, against an installed kernel SDK:

```sh
cd plugins/links/udp
cmake -B build -DCMAKE_PREFIX_PATH=/usr/local -DBUILD_TESTING=OFF
cmake --build build
```

## Load

Manifest entry pins the SHA-256 digest; `gn_plugin_init` registers
the `udp` scheme. See `docs/install.md` and
`docs/contracts/plugin-manifest.md` in the kernel tree.

## Contract

- Kernel-side link contract: `docs/contracts/link.md`
- Datagram-class invariants: `docs/contracts/link.md` §reliability
