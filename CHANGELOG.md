# Changelog — goodnet-link-udp

All notable changes to this plugin are listed here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions track the kernel ABI through `gn_link_vtable_t` and the
composer surface in `docs/contracts/link.en.md` §8.

## [Unreleased]

### Composer L2 surface

`composer_listen` / `connect` / `subscribe_data` expose the UDP
socket as a `LinkCarrier(udp)` to upper composers. The QUIC
link consumes this directly, and the ICE link routes
TURN-over-UDP and host-candidate sends through the same
carrier. Subscribers receive raw datagram payloads keyed by the
parent conn id; the carrier owns the socket lifecycle.

### Shared token-bucket rate limiter

The in-source rate limiter is migrated to
`sdk/cpp/token_bucket.hpp`. Behaviour is unchanged; the move
lets other plugins reuse the same implementation instead of
forking copies, and keeps the token semantics aligned across
the codebase.

## [1.0.0-rc1] — 2026-05-09

Initial release. Brings the legacy in-tree `links/udp` link
forward as a v1 GoodNet link plugin.

### Added

- UDP datagram transport with `udp://host:port` URI scheme.
  Per-source sockets surface inbound datagrams through
  `host_api->notify_inbound_bytes`. Delivery is best-effort and
  unordered; the link does not export `GN_LINK_CAP_RELIABLE`.
- Multi-threaded `io_context` worker pool sized to half
  `hardware_concurrency()`. Concurrent receivers run on
  independent strands.
- Composer L2 surface declared — the slots are filled in under
  Unreleased; the v1.0.0-rc1 cut establishes the ABI shape so
  upstream composers can link against it.
- Datagram-class invariants documented in
  `docs/contracts/link.en.md` §8 — security providers running
  on UDP must own their replay window. The v1 Noise XX provider
  is stream-only, so noise + UDP is unsupported in v1; a future
  Noise variant or a DTLS-style provider would lift the gate.
