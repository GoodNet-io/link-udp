// SPDX-License-Identifier: MIT
/// @file   plugins/links/udp/udp.hpp
/// @brief  Asio UDP datagram transport per `link.md` §3
///         (datagram-mode, single-socket, per-peer synthetic conn_id).
///
/// UDP is the first datagram transport in the tree, so the shape is
/// distinct from TCP/IPC: a single `udp::socket` both receives and
/// sends, without an acceptor. Every send / receive runs on a single
/// strand because Asio forbids concurrent ops on one socket — there
/// is no per-session strand to lean on. Frame == datagram by
/// construction (no length-prefix); the kernel sees one
/// `notify_inbound_bytes` per `recvfrom` and rejects any send larger
/// than the configured MTU. Per-source rate limiting on
/// new-connection allocation closes the spoofed-source amplification
/// path the audit class TR-S7 describes — without it an attacker
/// can mint connection records faster than the kernel reaps idle
/// ones.

#pragma once

#include <atomic>
#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <asio/strand.hpp>

#include <core/util/token_bucket.hpp>

#include <sdk/extensions/link.h>
#include <sdk/host_api.h>
#include <sdk/trust.h>
#include <sdk/types.h>

namespace gn::link::udp {

/// Conservative cap chosen so a default UDP send sits under any
/// reasonable path PMTU floor (1280 IPv6, 1200 typical IPv4 minus
/// tunnel overhead). Loopback can carry larger frames; raise via
/// `set_mtu` once the v1 extension surface lands.
inline constexpr std::uint32_t kDefaultMtu = 1200;

/// Per-source-IP rate limiter on new-connection allocations. An
/// attacker spraying spoofed source addresses at the listening port
/// would otherwise allocate one ConnectionRecord per packet and
/// exhaust `max_connections` in seconds. 10 new conns/sec/IP with
/// burst 50 is comfortably above any legitimate client churn.
inline constexpr double kNewConnRate  = 10.0;
inline constexpr double kNewConnBurst = 50.0;

class UdpLink : public std::enable_shared_from_this<UdpLink> {
public:
    UdpLink();
    ~UdpLink();

    UdpLink(const UdpLink&)            = delete;
    UdpLink& operator=(const UdpLink&) = delete;

    /// Bind the URI and start receiving. URI form
    /// `udp://host:port` per `uri.md`. Port 0 lets the OS pick;
    /// the actual bound port is available through `listen_port()`.
    [[nodiscard]] gn_result_t listen(std::string_view uri);

    /// Register a peer endpoint and synthesise a `gn_conn_id_t`.
    /// UDP has no real handshake; this allocates the conn record so
    /// subsequent sends can address it by id.
    [[nodiscard]] gn_result_t connect(std::string_view uri);

    /// Send a single datagram. Payload larger than `mtu()` is
    /// rejected before any syscall — IP fragmentation on the hot
    /// path is never the desired behaviour.
    [[nodiscard]] gn_result_t send(gn_conn_id_t conn,
                                    std::span<const std::uint8_t> bytes);

    /// Datagram transports don't coalesce: each frame becomes one
    /// `sendto`. Larger-than-MTU frames are rejected per-frame.
    [[nodiscard]] gn_result_t send_batch(
        gn_conn_id_t conn,
        std::span<const std::span<const std::uint8_t>> frames);

    [[nodiscard]] gn_result_t disconnect(gn_conn_id_t conn);

    void set_host_api(const host_api_t* api) noexcept;

    /// Reconfigure the per-source-IP new-connection limiter live.
    /// Public so the config-reload callback in the .cpp can call
    /// it from a free function without going through internals.
    void reconfigure_new_conn_limiter(double      rate,
                                       double      burst,
                                       std::size_t lru_cap) noexcept;
    void shutdown();

    [[nodiscard]] std::uint16_t listen_port() const noexcept {
        return listen_port_.load(std::memory_order_acquire);
    }
    [[nodiscard]] std::size_t  session_count() const noexcept;
    [[nodiscard]] std::uint32_t mtu() const noexcept {
        return mtu_.load(std::memory_order_relaxed);
    }
    void set_mtu(std::uint32_t bytes) noexcept;

    struct Stats {
        std::uint64_t bytes_in            = 0;
        std::uint64_t bytes_out           = 0;
        std::uint64_t frames_in           = 0;
        std::uint64_t frames_out          = 0;
        std::uint64_t active_connections  = 0;
    };
    [[nodiscard]] Stats stats() const noexcept;

    /// Static descriptor for the `gn.link.udp` extension.
    /// The kernel snapshots this once at register time.
    [[nodiscard]] static gn_link_caps_t capabilities() noexcept;

private:
    struct PeerEntry {
        gn_conn_id_t                              id;
        asio::ip::udp::endpoint            endpoint;
        std::chrono::steady_clock::time_point     last_active;
    };

    /// `hash_combine`-style mixing avoids the address-XOR collisions
    /// that hit `(host_str ^ (port << 16))` whenever two peers share
    /// an octet pattern that flips the same hash bits.
    struct EndpointHash {
        static constexpr std::size_t kMagic = 0x9e3779b9ULL;
        static void mix(std::size_t& h, std::size_t v) noexcept {
            h ^= v + kMagic + (h << 6) + (h >> 2);
        }
        std::size_t operator()(
            const asio::ip::udp::endpoint& ep) const noexcept {
            std::size_t h = 0;
            if (ep.address().is_v4()) {
                mix(h, std::hash<std::uint32_t>{}(
                            ep.address().to_v4().to_uint()));
            } else {
                const auto bytes = ep.address().to_v6().to_bytes();
                for (auto b : bytes) {
                    mix(h, std::hash<std::uint8_t>{}(b));
                }
            }
            mix(h, std::hash<std::uint16_t>{}(ep.port()));
            return h;
        }
    };

    void start_receive();
    [[nodiscard]] gn_trust_class_t resolve_trust(
        const asio::ip::udp::endpoint& peer) const noexcept;
    [[nodiscard]] static std::string endpoint_to_uri(
        const asio::ip::udp::endpoint& ep);

    asio::io_context                                          ioc_;
    asio::executor_work_guard<asio::io_context::executor_type> work_;
    std::thread                                                      worker_;

    /// One strand per *socket* — UDP has no per-session strand because
    /// every datagram crosses the same FD. Both `async_receive_from`
    /// and `async_send_to` bind to it.
    asio::strand<asio::io_context::executor_type> strand_;

    std::optional<asio::ip::udp::socket>                  socket_;
    std::atomic<std::uint16_t>                                   listen_port_{0};
    std::atomic<bool>                                            shutdown_{false};

    /// Receive scratch buffer. 64 KiB matches the IPv4/v6 datagram
    /// theoretical max so any legitimately-accepted payload fits.
    std::array<std::uint8_t, 65536>                              recv_buf_{};
    asio::ip::udp::endpoint                               recv_endpoint_;

    mutable std::mutex                                              peers_mu_;
    std::unordered_map<gn_conn_id_t, PeerEntry>                     peers_;
    std::unordered_map<asio::ip::udp::endpoint,
                       gn_conn_id_t,
                       EndpointHash>                                endpoint_to_id_;

    std::atomic<std::uint32_t>                                      mtu_{kDefaultMtu};
    ::gn::util::RateLimiterMap<>                                    new_conn_limiter_{
        kNewConnRate, kNewConnBurst};
    /// Token issued by `subscribe(GN_SUBSCRIBE_CONFIG_RELOAD)`; reset on
    /// `set_host_api(nullptr)` and on dtor so the kernel's
    /// signal channel doesn't fire into a freed `this`.
    std::uint64_t                                                   reload_sub_id_{0};

    std::atomic<std::uint64_t> bytes_in_{0};
    std::atomic<std::uint64_t> bytes_out_{0};
    std::atomic<std::uint64_t> frames_in_{0};
    std::atomic<std::uint64_t> frames_out_{0};

    const host_api_t* api_ = nullptr;
};

}  // namespace gn::link::udp
