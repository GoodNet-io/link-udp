// SPDX-License-Identifier: MIT
/// @file   plugins/links/udp/udp.cpp
/// @brief  UDP link plugin — connectionless datagram transport.

#include "udp.hpp"

#include <sdk/convenience.h>
#include <sdk/cpp/dns.hpp>
#include <sdk/cpp/uri.hpp>

#include <asio/bind_executor.hpp>
#include <asio/buffer.hpp>
#include <asio/dispatch.hpp>
#include <asio/ip/v6_only.hpp>
#include <system_error>

#include <algorithm>
#include <cstring>
#include <thread>
#include <utility>
#include <vector>

namespace gn::link::udp {

namespace asio_ip = asio::ip;

namespace {

/// Cap MTU at the IPv4/v6 datagram theoretical max so the receive
/// scratch buffer (`recv_buf_`, 64 KiB) is never under-sized for a
/// frame the configured limit accepts.
constexpr std::uint32_t kMtuCeiling = 65000;

}  // namespace

UdpLink::UdpLink()
    : ioc_(),
      work_(asio::make_work_guard(ioc_)),
      strand_(asio::make_strand(ioc_.get_executor())) {
    /// Match the worker-pool size of the other link plugins. UDP's
    /// own throughput stays bound by the single shared strand
    /// (`strand_`); the extra threads are kept for symmetry across
    /// the transport set rather than for a measurable speedup here.
    const unsigned hc = std::thread::hardware_concurrency();
    const unsigned n  = std::max(1u, hc / 2);
    workers_.reserve(n);
    for (unsigned i = 0; i < n; ++i) {
        workers_.emplace_back([this] { ioc_.run(); });
    }
}

UdpLink::~UdpLink() {
    shutdown();
}

/// Read `udp.new_conn_*` from config and reconfigure the
/// per-source-IP new-connection limiter. Idempotent: missing or
/// non-positive values fall back to the current defaults so a
/// reload that drops the section silently never disables the
/// limiter outright. Pulled out of `set_host_api` so the
/// `subscribe(GN_SUBSCRIBE_CONFIG_RELOAD)` callback can re-run it on every
/// kernel-fired reload.
namespace {
void apply_udp_config(::gn::link::udp::UdpLink* self,
                      const host_api_t*                   api) noexcept {
    if (api == nullptr || api->config_get == nullptr) return;
    double      rate    = ::gn::link::udp::kNewConnRate;
    double      burst   = ::gn::link::udp::kNewConnBurst;
    std::size_t lru_cap = 4096;
    std::int64_t v      = 0;
    if (gn_config_get_int64(api, "udp.new_conn_rate", &v) == GN_OK
        && v > 0) {
        rate = static_cast<double>(v);
    }
    if (gn_config_get_int64(api, "udp.new_conn_burst", &v) == GN_OK
        && v > 0) {
        burst = static_cast<double>(v);
    }
    if (gn_config_get_int64(api, "udp.new_conn_lru_cap", &v) == GN_OK
        && v > 0) {
        lru_cap = static_cast<std::size_t>(v);
    }
    self->reconfigure_new_conn_limiter(rate, burst, lru_cap);
}
}  // namespace

void UdpLink::set_host_api(const host_api_t* api) noexcept {
    /// Drop any prior reload subscription before swapping the api
    /// pointer — every install of a fresh api needs to subscribe
    /// against the new kernel, so the previous subscription
    /// against a (possibly different) kernel must go first.
    if (api_ != nullptr && api_->unsubscribe != nullptr
        && reload_sub_id_ != 0) {
        (void)api_->unsubscribe(api_->host_ctx, reload_sub_id_);
        reload_sub_id_ = 0;
    }

    api_ = api;
    apply_udp_config(this, api_);

    /// Subscribe to config-reload events so the limiter shape
    /// re-reads on every operator-initiated reload, not just at
    /// initial set_host_api time.
    if (api_ != nullptr && api_->subscribe_config_reload != nullptr) {
        gn_subscription_id_t token = GN_INVALID_SUBSCRIPTION_ID;
        const auto rc = api_->subscribe_config_reload(
            api_->host_ctx,
            +[](void* user_data) {
                auto* self =
                    static_cast<UdpLink*>(user_data);
                apply_udp_config(self, self->api_);
            },
            this,
            /*ud_destroy*/ nullptr,
            &token);
        if (rc == GN_OK) {
            reload_sub_id_ = token;
        }
    }
}

void UdpLink::reconfigure_new_conn_limiter(
    double rate, double burst, std::size_t lru_cap) noexcept {
    new_conn_limiter_.reconfigure(rate, burst, lru_cap);
}

std::size_t UdpLink::session_count() const noexcept {
    std::lock_guard lk(peers_mu_);
    return peers_.size();
}

UdpLink::Stats UdpLink::stats() const noexcept {
    Stats s{};
    s.bytes_in           = bytes_in_.load(std::memory_order_relaxed);
    s.bytes_out          = bytes_out_.load(std::memory_order_relaxed);
    s.frames_in          = frames_in_.load(std::memory_order_relaxed);
    s.frames_out         = frames_out_.load(std::memory_order_relaxed);
    s.active_connections = session_count();
    return s;
}

gn_link_caps_t UdpLink::capabilities() noexcept {
    gn_link_caps_t c{};
    c.flags       = GN_LINK_CAP_DATAGRAM;
    c.max_payload = kDefaultMtu;
    return c;
}

void UdpLink::set_mtu(std::uint32_t bytes) noexcept {
    if (bytes == 0)            bytes = kDefaultMtu;
    if (bytes > kMtuCeiling)   bytes = kMtuCeiling;
    mtu_.store(bytes, std::memory_order_relaxed);
}

gn_trust_class_t UdpLink::resolve_trust(
    const asio_ip::udp::endpoint& peer) const noexcept
{
    return peer.address().is_loopback() ? GN_TRUST_LOOPBACK
                                          : GN_TRUST_UNTRUSTED;
}

std::string UdpLink::endpoint_to_uri(
    const asio_ip::udp::endpoint& ep)
{
    std::string uri = "udp://";
    if (ep.address().is_v6()) {
        uri += '[';
        uri += ep.address().to_string();
        uri += ']';
    } else {
        uri += ep.address().to_string();
    }
    uri += ':';
    uri += std::to_string(ep.port());
    return uri;
}

gn_result_t UdpLink::listen(std::string_view uri_sv) {
    if (shutdown_.load(std::memory_order_acquire)) return GN_ERR_NULL_ARG;

    const auto parts = ::gn::parse_uri(uri_sv);
    if (!parts || parts->is_path_style()) return GN_ERR_INVALID_ENVELOPE;

    std::error_code ec;
    const auto addr = asio_ip::make_address(parts->host, ec);
    if (ec) return GN_ERR_NULL_ARG;

    asio_ip::udp::endpoint ep(addr, parts->port);

    try {
        asio_ip::udp::socket sock(ioc_);
        sock.open(ep.protocol());
        /// Same dual-stack treatment as TCP: IPv6 wildcard listens
        /// accept v4-mapped peers when `IPV6_V6ONLY` is off; specific
        /// v6 literals stay v6-only. `set_option` here is best-effort
        /// — pre-Linux-3.x kernels lack the option, v4-only fallback
        /// is the documented behaviour.
        if (addr.is_v6() && addr.is_unspecified()) {
            std::error_code v6_ec;
            if (sock.set_option(asio_ip::v6_only(false), v6_ec) &&
                api_) {
                gn_log_debug(api_,
                             "udp: v6_only(false) failed: %s",
                             v6_ec.message().c_str());
            }
        }
        sock.bind(ep);
        listen_port_.store(sock.local_endpoint().port(),
                            std::memory_order_release);
        socket_.emplace(std::move(sock));
    } catch (const std::exception&) {
        return GN_ERR_NULL_ARG;
    }

    start_receive();
    return GN_OK;
}

gn_result_t UdpLink::connect(std::string_view uri_sv) {
    if (shutdown_.load(std::memory_order_acquire)) return GN_ERR_NULL_ARG;

    /// Hostname → IP literal up-front per `dns.md` §1; IP-literal
    /// hosts short-circuit through the helper without a lookup.
    auto resolved = ::gn::sdk::resolve_uri_host(ioc_, uri_sv);
    if (!resolved) return GN_ERR_INVALID_ENVELOPE;

    const auto parts = ::gn::parse_uri(*resolved);
    if (!parts || parts->is_path_style()) return GN_ERR_INVALID_ENVELOPE;
    /// `connect`-side rejects port 0 per `uri.md` §5 — listen accepts
    /// it for ephemeral allocation, but a zero target port is never a
    /// real peer.
    if (parts->port == 0) return GN_ERR_INVALID_ENVELOPE;

    std::error_code ec;
    const auto addr = asio_ip::make_address(parts->host, ec);
    if (ec) return GN_ERR_NULL_ARG;
    asio_ip::udp::endpoint ep(addr, parts->port);

    /// A pure client (connect without listen) needs an outbound
    /// socket. Bind to the matching protocol family on an ephemeral
    /// port; v6 wildcards disable `IPV6_V6ONLY` so v4-mapped sends
    /// also work.
    bool socket_freshly_created = false;
    if (!socket_) {
        try {
            const auto family = addr.is_v6() ? asio_ip::udp::v6()
                                              : asio_ip::udp::v4();
            asio_ip::udp::socket sock(
                ioc_, asio_ip::udp::endpoint(family, 0));
            if (addr.is_v6()) {
                std::error_code v6_ec;
                if (sock.set_option(asio_ip::v6_only(false), v6_ec) &&
                    api_) {
                    gn_log_debug(api_,
                                 "udp: v6_only(false) failed: %s",
                                 v6_ec.message().c_str());
                }
            }
            socket_.emplace(std::move(sock));
            socket_freshly_created = true;
        } catch (const std::exception&) {
            return GN_ERR_NULL_ARG;
        }
    }

    if (!api_ || !api_->notify_connect) {
        if (socket_freshly_created) {
            /// Roll back the socket we just minted — without a host
            /// API there is nowhere for received bytes to flow.
            std::error_code close_ec;
            if (socket_->close(close_ec) && api_) {
                gn_log_debug(api_,
                             "udp: rollback close: %s",
                             close_ec.message().c_str());
            }
            socket_.reset();
        }
        return GN_ERR_NOT_IMPLEMENTED;
    }

    /// Hold `peers_mu_` across `notify_connect` so a concurrent
    /// inbound datagram from the same endpoint cannot race the
    /// kernel-allocated id and clobber the map. The kernel side of
    /// `notify_connect` only touches its own session registry;
    /// nothing in that path re-enters the transport, so the lock is
    /// safe to span.
    std::uint8_t remote_pk[GN_PUBLIC_KEY_BYTES] = {};
    gn_conn_id_t conn = GN_INVALID_ID;
    const std::string canonical = endpoint_to_uri(ep);
    {
        std::lock_guard lk(peers_mu_);
        if (auto it = endpoint_to_id_.find(ep);
            it != endpoint_to_id_.end()) {
            /// Endpoint already registered (a concurrent inbound
            /// datagram from the same peer raced ahead). Keep the
            /// existing id; refresh activity. `socket_freshly_created`
            /// is unreachable here — if we just minted the socket no
            /// recv could have populated the map yet — so no need to
            /// start a second receive loop.
            peers_[it->second].last_active =
                std::chrono::steady_clock::now();
            return GN_OK;
        }
        const gn_result_t rc = api_->notify_connect(
            api_->host_ctx, remote_pk, canonical.c_str(),
            resolve_trust(ep), GN_ROLE_INITIATOR, &conn);
        if (rc != GN_OK || conn == GN_INVALID_ID) {
            if (socket_freshly_created) {
                std::error_code close_ec;
                if (socket_->close(close_ec) && api_) {
                    gn_log_debug(api_,
                                 "udp: rollback close: %s",
                                 close_ec.message().c_str());
                }
                socket_.reset();
            }
            return rc;
        }
        peers_[conn] = {conn, ep, std::chrono::steady_clock::now()};
        endpoint_to_id_[ep] = conn;
    }

    if (socket_freshly_created) start_receive();

    if (api_->kick_handshake) {
        if (const auto rc = api_->kick_handshake(api_->host_ctx, conn);
            rc != GN_OK && api_) {
            gn_log_debug(api_,
                         "udp: kick_handshake rc=%d for conn=%llu",
                         rc, static_cast<unsigned long long>(conn));
        }
    }
    return GN_OK;
}

gn_result_t UdpLink::send(gn_conn_id_t conn,
                                std::span<const std::uint8_t> bytes) {
    if (shutdown_.load(std::memory_order_acquire)) return GN_ERR_NULL_ARG;
    if (!socket_) return GN_ERR_NULL_ARG;
    /// Reject oversized payloads up front — IP fragmentation in the
    /// hot path is never the desired behaviour and a fragmented frame
    /// almost always loses on the wire when one fragment drops.
    if (bytes.size() > mtu_.load(std::memory_order_relaxed)) {
        return GN_ERR_PAYLOAD_TOO_LARGE;
    }

    asio_ip::udp::endpoint target;
    if (conn & kComposerIdBit) {
        /// Composer-owned conn: lookup in the composer peer map, no
        /// `last_active` book-keeping (composers run their own
        /// liveness probes — STUN keepalives for ICE, DTLS-record
        /// stream framing for the rest).
        std::lock_guard lk(composer_mu_);
        auto it = composer_peers_.find(conn);
        if (it == composer_peers_.end()) return GN_ERR_NOT_FOUND;
        target = it->second;
    } else {
        std::lock_guard lk(peers_mu_);
        auto it = peers_.find(conn);
        if (it == peers_.end()) return GN_ERR_NOT_FOUND;
        target = it->second.endpoint;
        it->second.last_active = std::chrono::steady_clock::now();
    }

    /// Asio forbids overlapping ops on one socket; the strand is the
    /// only writer just like it is the only reader. The payload
    /// rides in `buf` so the caller's span can vanish before the
    /// syscall completes.
    auto buf = std::make_shared<std::vector<std::uint8_t>>(
        bytes.begin(), bytes.end());
    auto self = shared_from_this();
    asio::dispatch(strand_,
        [weak = std::weak_ptr<UdpLink>(self), buf, target] {
            auto t = weak.lock();
            if (!t || t->shutdown_.load(std::memory_order_acquire)) return;
            t->socket_->async_send_to(
                asio::buffer(*buf), target,
                asio::bind_executor(t->strand_,
                    [buf, weak](const std::error_code& send_ec,
                                std::size_t n) {
                        auto t2 = weak.lock();
                        if (!t2) return;
                        if (send_ec) {
                            if (t2->api_) {
                                gn_log_debug(t2->api_,
                                             "udp: send_to failed: %s",
                                             send_ec.message().c_str());
                            }
                            return;
                        }
                        t2->bytes_out_.fetch_add(n, std::memory_order_relaxed);
                        t2->frames_out_.fetch_add(1, std::memory_order_relaxed);
                    }));
        });
    return GN_OK;
}

gn_result_t UdpLink::send_batch(
    gn_conn_id_t conn,
    std::span<const std::span<const std::uint8_t>> frames)
{
    /// Datagram transports never coalesce — each frame keeps its
    /// boundary on the wire. Pre-validate every frame against MTU
    /// up front so a partial batch never lands on the wire when one
    /// frame is malformed; either every frame goes out or nothing.
    const auto cap = mtu_.load(std::memory_order_relaxed);
    for (const auto& f : frames) {
        if (f.size() > cap) return GN_ERR_PAYLOAD_TOO_LARGE;
    }
    for (const auto& f : frames) {
        if (const auto rc = send(conn, f); rc != GN_OK) return rc;
    }
    return GN_OK;
}

gn_result_t UdpLink::disconnect(gn_conn_id_t conn) {
    if (conn & kComposerIdBit) {
        /// Composer-owned conn: erase from both composer maps. No
        /// `notify_disconnect` — the kernel never saw this id, only
        /// the consumer plugin (ICE / DTLS / QUIC) holds it.
        std::lock_guard lk(composer_mu_);
        auto it = composer_peers_.find(conn);
        if (it == composer_peers_.end()) return GN_OK;  /// idempotent
        composer_endpoint_to_id_.erase(it->second);
        composer_peers_.erase(it);
        composer_data_subs_.erase(conn);
        return GN_OK;
    }

    bool erased = false;
    {
        std::lock_guard lk(peers_mu_);
        auto it = peers_.find(conn);
        if (it == peers_.end()) return GN_OK;  /// idempotent
        endpoint_to_id_.erase(it->second.endpoint);
        peers_.erase(it);
        erased = true;
    }
    /// Tell the kernel the conn is gone so its registry releases the
    /// id — without this the kernel leaks the record forever, since
    /// UDP has no in-band close signal.
    if (erased && api_ && api_->notify_disconnect) {
        if (const auto rc = api_->notify_disconnect(
                api_->host_ctx, conn, GN_OK);
            rc != GN_OK && api_) {
            gn_log_debug(api_,
                         "udp: notify_disconnect rc=%d for conn=%llu",
                         rc, static_cast<unsigned long long>(conn));
        }
    }
    return GN_OK;
}

// ── Composer L2 surface ─────────────────────────────────────────────────
//
// Implements `link.en.md` §8 datagram-mode composer contract. UDP has no
// L4 accept-semantics — composers (ICE) allocate peers explicitly through
// `composer_connect`. Inbound datagrams from a known composer endpoint
// dispatch via the per-conn `composer_subscribe_data` callback; unknown
// endpoints fall through to the kernel `notify_connect` path so the
// standalone-L1 use case keeps working unchanged. UDP shares one socket
// between both paths — segregation is by `kComposerIdBit` (bit 63).

gn_result_t UdpLink::composer_listen(std::string_view uri_sv) {
    if (shutdown_.load(std::memory_order_acquire)) {
        return GN_ERR_INVALID_STATE;
    }

    /// One-call scheme-checked parse via the SDK Tier-1 sugar
    /// `parse_uri_strict` — replaces the prior 3-line
    /// `parse_uri + is_path_style + scheme!=` pattern.
    const auto parts = ::gn::parse_uri_strict(uri_sv, "udp");
    if (!parts || parts->is_path_style()) return GN_ERR_INVALID_ENVELOPE;

    std::error_code ec;
    const auto addr = asio_ip::make_address(parts->host, ec);
    if (ec) return GN_ERR_NULL_ARG;

    /// If the kernel-side `listen()` already opened a socket on this
    /// plugin instance, composer reuses it — UDP has a single FD, and
    /// rebinding would tear down kernel reception. Capability flag
    /// `composer_bound_` records that the composer surface has work to
    /// do on the existing socket; `start_receive()` is already running.
    if (socket_) {
        composer_bound_.store(true, std::memory_order_release);
        return GN_OK;
    }

    asio_ip::udp::endpoint ep(addr, parts->port);
    try {
        asio_ip::udp::socket sock(ioc_);
        sock.open(ep.protocol());
        if (addr.is_v6() && addr.is_unspecified()) {
            std::error_code v6_ec;
            if (sock.set_option(asio_ip::v6_only(false), v6_ec) &&
                api_) {
                gn_log_debug(api_,
                             "udp: v6_only(false) failed: %s",
                             v6_ec.message().c_str());
            }
        }
        sock.bind(ep);
        listen_port_.store(sock.local_endpoint().port(),
                            std::memory_order_release);
        socket_.emplace(std::move(sock));
    } catch (const std::exception&) {
        return GN_ERR_NULL_ARG;
    }

    composer_bound_.store(true, std::memory_order_release);
    start_receive();
    return GN_OK;
}

gn_result_t UdpLink::composer_connect(std::string_view uri_sv,
                                       gn_conn_id_t* out_conn) {
    if (!out_conn) return GN_ERR_NULL_ARG;
    *out_conn = GN_INVALID_ID;
    if (shutdown_.load(std::memory_order_acquire)) {
        return GN_ERR_INVALID_STATE;
    }

    auto resolved = ::gn::sdk::resolve_uri_host(ioc_, uri_sv);
    if (!resolved) return GN_ERR_INVALID_ENVELOPE;

    const auto parts = ::gn::parse_uri_strict(*resolved, "udp");
    if (!parts || parts->is_path_style()) return GN_ERR_INVALID_ENVELOPE;
    if (parts->port == 0) return GN_ERR_INVALID_ENVELOPE;

    std::error_code ec;
    const auto addr = asio_ip::make_address(parts->host, ec);
    if (ec) return GN_ERR_NULL_ARG;
    asio_ip::udp::endpoint ep(addr, parts->port);

    /// Pure-composer (no kernel listen) needs the outbound socket —
    /// mirror the kernel `connect()` path. Ephemeral local port on
    /// the matching protocol family; v6 wildcards disable v6-only so
    /// v4-mapped sends also work.
    bool socket_freshly_created = false;
    if (!socket_) {
        try {
            const auto family = addr.is_v6() ? asio_ip::udp::v6()
                                              : asio_ip::udp::v4();
            asio_ip::udp::socket sock(
                ioc_, asio_ip::udp::endpoint(family, 0));
            if (addr.is_v6()) {
                std::error_code v6_ec;
                if (sock.set_option(asio_ip::v6_only(false), v6_ec) &&
                    api_) {
                    gn_log_debug(api_,
                                 "udp: v6_only(false) failed: %s",
                                 v6_ec.message().c_str());
                }
            }
            listen_port_.store(sock.local_endpoint().port(),
                                std::memory_order_release);
            socket_.emplace(std::move(sock));
            socket_freshly_created = true;
        } catch (const std::exception&) {
            return GN_ERR_NULL_ARG;
        }
    }

    composer_bound_.store(true, std::memory_order_release);

    const gn_conn_id_t id =
        next_composer_id_.fetch_add(1, std::memory_order_relaxed) |
        kComposerIdBit;
    {
        std::lock_guard lk(composer_mu_);
        composer_peers_[id]              = ep;
        composer_endpoint_to_id_[ep]     = id;
    }

    if (socket_freshly_created) start_receive();

    *out_conn = id;
    return GN_OK;
}

gn_result_t UdpLink::composer_subscribe_data(gn_conn_id_t conn,
                                              ::gn_link_data_cb_t cb,
                                              void* user_data) {
    if (!cb) return GN_ERR_NULL_ARG;
    if (!(conn & kComposerIdBit)) return GN_ERR_NOT_FOUND;
    std::lock_guard lk(composer_mu_);
    if (composer_peers_.find(conn) == composer_peers_.end()) {
        return GN_ERR_NOT_FOUND;
    }
    composer_data_subs_[conn] = ComposerDataSub{cb, user_data};
    return GN_OK;
}

gn_result_t UdpLink::composer_unsubscribe_data(gn_conn_id_t conn) {
    if (!(conn & kComposerIdBit)) return GN_OK;
    std::lock_guard lk(composer_mu_);
    composer_data_subs_.erase(conn);
    return GN_OK;
}

gn_result_t UdpLink::composer_subscribe_accept(
    ::gn_link_accept_cb_t cb,
    void* user_data,
    gn_subscription_id_t* out_token) {
    if (!cb || !out_token) return GN_ERR_NULL_ARG;
    const gn_subscription_id_t token =
        next_accept_token_.fetch_add(1, std::memory_order_relaxed);
    std::lock_guard lk(composer_mu_);
    composer_accept_subs_.push_back(
        ComposerAcceptSub{token, cb, user_data});
    *out_token = token;
    return GN_OK;
}

gn_result_t UdpLink::composer_unsubscribe_accept(
    gn_subscription_id_t token) {
    std::lock_guard lk(composer_mu_);
    auto it = std::remove_if(
        composer_accept_subs_.begin(), composer_accept_subs_.end(),
        [token](const ComposerAcceptSub& s) { return s.token == token; });
    composer_accept_subs_.erase(it, composer_accept_subs_.end());
    return GN_OK;
}

gn_result_t UdpLink::composer_listen_port(
    std::uint16_t* out_port) const noexcept {
    if (!out_port) return GN_ERR_NULL_ARG;
    *out_port = 0;
    if (!composer_bound_.load(std::memory_order_acquire)) {
        return GN_ERR_INVALID_STATE;
    }
    *out_port = listen_port_.load(std::memory_order_acquire);
    return GN_OK;
}

void UdpLink::start_receive() {
    if (!socket_ || shutdown_.load(std::memory_order_acquire)) return;

    /// Capture a weak observer, not a strong reference. A strong
    /// capture would close a cycle through `ioc_` (which owns the
    /// pending op) and leak the transport — `plugin-lifetime.md` §4.
    socket_->async_receive_from(
        asio::buffer(recv_buf_), recv_endpoint_,
        asio::bind_executor(strand_,
            [weak = weak_from_this()](
                const std::error_code& ec, std::size_t bytes) {
                auto self = weak.lock();
                if (!self || self->shutdown_.load(std::memory_order_acquire))
                    return;
                if (ec) {
                    if (ec == asio::error::operation_aborted) {
                        /// Shutdown path — stop quietly.
                        return;
                    }
                    /// Re-arm only on errors that are recoverable on
                    /// the next syscall: ICMP-driven `connection_refused`
                    /// (transient when a previous send hit a closed
                    /// remote port) and `message_size` (the runt
                    /// datagram is gone, the next read returns the
                    /// next frame). Anything else stops the loop —
                    /// the kernel observes the silence and the
                    /// operator sees the diagnostic.
                    if (ec == asio::error::connection_refused ||
                        ec == asio::error::message_size) {
                        self->start_receive();
                        return;
                    }
                    if (self->api_) {
                        gn_log_warn(self->api_,
                                    "udp: recv stopped: %s",
                                    ec.message().c_str());
                    }
                    return;
                }

                /// Composer-owned endpoints route directly to their
                /// per-conn subscriber, bypassing the kernel
                /// `notify_*` machinery. The composer map is checked
                /// first because composer peers are explicit allocations
                /// — a kernel-side mapping with the same endpoint would
                /// be a programming error (composer mode owns the wire).
                gn_conn_id_t                composer_id = GN_INVALID_ID;
                ComposerDataSub             composer_sub{};
                bool                        fresh_composer = false;
                std::vector<ComposerAcceptSub> accept_snapshot;
                {
                    std::lock_guard lk(self->composer_mu_);
                    if (auto it = self->composer_endpoint_to_id_.find(
                            self->recv_endpoint_);
                        it != self->composer_endpoint_to_id_.end()) {
                        composer_id = it->second;
                        if (auto sit = self->composer_data_subs_.find(
                                composer_id);
                            sit != self->composer_data_subs_.end()) {
                            composer_sub = sit->second;
                        }
                    } else if (!self->composer_accept_subs_.empty()) {
                        /// New endpoint + active accept-bus: allocate a
                        /// composer-owned conn id and let subscribers
                        /// install their per-conn data callback before
                        /// the triggering datagram is dispatched.
                        composer_id =
                            self->next_composer_id_.fetch_add(
                                1, std::memory_order_relaxed)
                            | kComposerIdBit;
                        self->composer_peers_[composer_id] =
                            self->recv_endpoint_;
                        self->composer_endpoint_to_id_[
                            self->recv_endpoint_] = composer_id;
                        accept_snapshot = self->composer_accept_subs_;
                        fresh_composer = true;
                    }
                }
                if (fresh_composer) {
                    /// Fire accept-bus BEFORE delivering the
                    /// triggering datagram so subscribers get a
                    /// chance to install their per-conn data
                    /// callback. Subscribers that omit the
                    /// installation simply lose the first frame —
                    /// same semantics as the TCP composer.
                    const std::string peer_uri =
                        endpoint_to_uri(self->recv_endpoint_);
                    for (const auto& s : accept_snapshot) {
                        if (s.cb) {
                            s.cb(s.user_data, composer_id,
                                  peer_uri.c_str());
                        }
                    }
                    /// Re-resolve the data sub — the accept callback
                    /// may have installed one.
                    {
                        std::lock_guard lk(self->composer_mu_);
                        auto sit = self->composer_data_subs_.find(
                            composer_id);
                        if (sit != self->composer_data_subs_.end()) {
                            composer_sub = sit->second;
                        }
                    }
                }
                if (composer_id != GN_INVALID_ID) {
                    self->bytes_in_.fetch_add(bytes,
                                              std::memory_order_relaxed);
                    self->frames_in_.fetch_add(1,
                                              std::memory_order_relaxed);
                    if (composer_sub.cb && bytes > 0) {
                        composer_sub.cb(composer_sub.user_data,
                                        composer_id,
                                        self->recv_buf_.data(), bytes);
                    }
                    self->start_receive();
                    return;
                }

                /// Both the existing-conn lookup and the new-conn
                /// allocation run inside `peers_mu_` so a concurrent
                /// `connect()` to the same endpoint cannot interleave
                /// — winner inserts, loser observes existing entry.
                gn_conn_id_t id = GN_INVALID_ID;
                bool fresh_conn = false;
                {
                    std::lock_guard lk(self->peers_mu_);
                    if (auto it = self->endpoint_to_id_.find(
                            self->recv_endpoint_);
                        it != self->endpoint_to_id_.end()) {
                        id = it->second;
                        self->peers_[id].last_active =
                            std::chrono::steady_clock::now();
                    } else if (self->api_ && self->api_->notify_connect) {
                        std::uint64_t ip_key = 0;
                        if (self->recv_endpoint_.address().is_v4()) {
                            ip_key = self->recv_endpoint_.address()
                                         .to_v4().to_uint();
                        } else {
                            const auto v6_bytes =
                                self->recv_endpoint_.address()
                                    .to_v6().to_bytes();
                            std::memcpy(&ip_key, v6_bytes.data(),
                                        sizeof(ip_key));
                        }
                        if (!self->new_conn_limiter_.allow(ip_key)) {
                            /// Drop, re-arm. No log spam — an
                            /// attacker can trivially fill any
                            /// rate-limited log channel.
                            self->start_receive();
                            return;
                        }
                        std::uint8_t remote_pk[GN_PUBLIC_KEY_BYTES] = {};
                        gn_conn_id_t conn = GN_INVALID_ID;
                        const std::string uri =
                            endpoint_to_uri(self->recv_endpoint_);
                        const auto rc = self->api_->notify_connect(
                            self->api_->host_ctx, remote_pk, uri.c_str(),
                            self->resolve_trust(self->recv_endpoint_),
                            GN_ROLE_RESPONDER, &conn);
                        if (rc == GN_OK && conn != GN_INVALID_ID) {
                            id = conn;
                            self->peers_[id] = {id, self->recv_endpoint_,
                                                std::chrono::steady_clock::now()};
                            self->endpoint_to_id_[self->recv_endpoint_] = id;
                            fresh_conn = true;
                        }
                    }
                }

                if (fresh_conn && self->api_ && self->api_->kick_handshake) {
                    /// Kick from outside the mutex — the kernel may
                    /// drive the responder side which will call back
                    /// into `host_api->send`, which re-acquires
                    /// `peers_mu_` to look up the target endpoint.
                    /// Holding the mutex would deadlock there.
                    if (const auto rc = self->api_->kick_handshake(
                            self->api_->host_ctx, id);
                        rc != GN_OK && self->api_) {
                        gn_log_debug(self->api_,
                                     "udp: kick_handshake rc=%d", rc);
                    }
                }

                if (bytes > 0) {
                    self->bytes_in_.fetch_add(bytes, std::memory_order_relaxed);
                    self->frames_in_.fetch_add(1, std::memory_order_relaxed);
                    if (id != GN_INVALID_ID && self->api_ &&
                        self->api_->notify_inbound_bytes) {
                        self->api_->notify_inbound_bytes(
                            self->api_->host_ctx, id,
                            self->recv_buf_.data(), bytes);
                    }
                }

                self->start_receive();
            }));
}

void UdpLink::shutdown() {
    if (shutdown_.exchange(true, std::memory_order_acq_rel)) return;

    /// Snapshot conn ids while holding the mutex, then release before
    /// firing `notify_disconnect` to avoid a re-entry deadlock if
    /// the kernel calls back into the transport.
    std::vector<gn_conn_id_t> closing;
    {
        std::lock_guard lk(peers_mu_);
        closing.reserve(peers_.size());
        for (const auto& [conn, _entry] : peers_) closing.push_back(conn);
        peers_.clear();
        endpoint_to_id_.clear();
    }
    /// Composer state has no kernel notify path — the consumer plugin
    /// (ICE / DTLS / QUIC) owns these ids and observes shutdown through
    /// its own carrier lifetime (LinkCarrier dtor cleans up). Just
    /// drop the maps so any in-flight send/disconnect fails cleanly.
    {
        std::lock_guard lk(composer_mu_);
        composer_peers_.clear();
        composer_endpoint_to_id_.clear();
        composer_data_subs_.clear();
        composer_accept_subs_.clear();
    }
    composer_bound_.store(false, std::memory_order_release);
    if (api_ && api_->notify_disconnect) {
        for (const auto conn : closing) {
            if (const auto rc = api_->notify_disconnect(
                    api_->host_ctx, conn, GN_OK);
                rc != GN_OK && api_) {
                gn_log_debug(api_,
                             "udp: notify_disconnect rc=%d for conn=%llu",
                             rc, static_cast<unsigned long long>(conn));
            }
        }
    }

    if (socket_) {
        std::error_code ec;
        if (socket_->close(ec) && api_) {
            gn_log_debug(api_,
                         "udp: close failed: %s", ec.message().c_str());
        }
        socket_.reset();
    }

    work_.reset();
    ioc_.stop();
    for (auto& w : workers_) {
        if (w.joinable()) w.join();
    }
    workers_.clear();
}

}  // namespace gn::link::udp
