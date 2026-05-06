// SPDX-License-Identifier: MIT
/// @file   plugins/links/udp/tests/test_udp.cpp
/// @brief  UdpLink — datagram-mode listen + connect + boundary
///         preservation, MTU enforcement, trust-class by address.

#include <gtest/gtest.h>

#include <plugins/links/udp/udp.hpp>

#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>

#include <sdk/host_api.h>
#include <sdk/trust.h>
#include <sdk/types.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace {

using namespace std::chrono_literals;
using gn::link::udp::UdpLink;

struct StubHost {
    std::atomic<int>                         connects{0};
    std::atomic<int>                         disconnects{0};
    std::atomic<int>                         inbound_calls{0};
    std::mutex                               mu;
    std::vector<gn_conn_id_t>                conns;
    std::vector<gn_handshake_role_t>         roles;
    std::vector<gn_trust_class_t>            trusts;
    std::vector<std::vector<std::uint8_t>>   inbound;
    std::vector<gn_conn_id_t>                inbound_owners;
    std::atomic<gn_conn_id_t>                next_id{1};

    static gn_result_t on_connect(void* host_ctx,
                                   const std::uint8_t /*remote_pk*/[GN_PUBLIC_KEY_BYTES],
                                   const char* /*uri*/,
                                   gn_trust_class_t trust,
                                   gn_handshake_role_t role,
                                   gn_conn_id_t* out_conn) {
        auto* h = static_cast<StubHost*>(host_ctx);
        const auto id = h->next_id.fetch_add(1);
        {
            std::lock_guard lk(h->mu);
            h->conns.push_back(id);
            h->roles.push_back(role);
            h->trusts.push_back(trust);
        }
        *out_conn = id;
        h->connects.fetch_add(1);
        return GN_OK;
    }

    static gn_result_t on_inbound(void* host_ctx, gn_conn_id_t conn,
                                   const std::uint8_t* bytes,
                                   std::size_t size) {
        auto* h = static_cast<StubHost*>(host_ctx);
        std::lock_guard lk(h->mu);
        h->inbound.emplace_back(bytes, bytes + size);
        h->inbound_owners.push_back(conn);
        h->inbound_calls.fetch_add(1);
        return GN_OK;
    }

    static gn_result_t on_disconnect(void* host_ctx, gn_conn_id_t /*conn*/,
                                      gn_result_t /*reason*/) {
        auto* h = static_cast<StubHost*>(host_ctx);
        h->disconnects.fetch_add(1);
        return GN_OK;
    }
};

host_api_t make_stub_api(StubHost& h) {
    host_api_t api{};
    api.api_size              = sizeof(host_api_t);
    api.host_ctx              = &h;
    api.notify_connect        = &StubHost::on_connect;
    api.notify_inbound_bytes  = &StubHost::on_inbound;
    api.notify_disconnect     = &StubHost::on_disconnect;
    return api;
}

void wait_for(const std::function<bool()>& pred,
              std::chrono::milliseconds timeout,
              const char* what) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return;
        std::this_thread::sleep_for(5ms);
    }
    FAIL() << "timeout waiting for: " << what;
}

/// Pre-flight: not every host wires up the IPv6 loopback. The Nix
/// build sandbox in particular leaves `[::1]` reachable for `bind`
/// but rejects `send_to` with `EPERM`. Probe with raw Asio so
/// the gtest body skips cleanly instead of timing out.
[[nodiscard]] bool host_supports_v6_loopback() {
    asio::io_context ioc;
    std::error_code ec;
    const auto v6 = asio::ip::make_address("::1", ec);
    if (ec) return false;
    asio::ip::udp::socket sock(ioc);
    if (sock.open(asio::ip::udp::v6(), ec) || ec) return false;
    if (sock.bind(
            asio::ip::udp::endpoint(asio::ip::udp::v6(), 0),
            ec) || ec) {
        return false;
    }
    const char probe[] = "x";
    asio::ip::udp::endpoint target(
        v6, sock.local_endpoint().port());
    if (sock.send_to(asio::buffer(probe, 1), target, 0, ec) == 0 ||
        ec) {
        return false;
    }
    return true;
}

}  // namespace

// ── listen ───────────────────────────────────────────────────────────────

TEST(UdpLink, ListenBindsEphemeralPort) {
    auto t = std::make_shared<UdpLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    ASSERT_EQ(t->listen("udp://127.0.0.1:0"), GN_OK);
    EXPECT_GT(t->listen_port(), 0u);
    t->shutdown();
}

TEST(UdpLink, ListenRejectsMalformedUri) {
    auto t = std::make_shared<UdpLink>();
    EXPECT_NE(t->listen("garbage"), GN_OK);
    EXPECT_NE(t->listen("ipc:///tmp/wrong"), GN_OK);
}

TEST(UdpLink, ShutdownIsIdempotent) {
    auto t = std::make_shared<UdpLink>();
    t->shutdown();
    t->shutdown();
}

// ── connect / send / receive ─────────────────────────────────────────────

TEST(UdpLink, LoopbackDatagramRoundTrip) {
    StubHost h_server;
    StubHost h_client;
    auto api_server = make_stub_api(h_server);
    auto api_client = make_stub_api(h_client);

    auto server = std::make_shared<UdpLink>();
    auto client = std::make_shared<UdpLink>();
    server->set_host_api(&api_server);
    client->set_host_api(&api_client);

    ASSERT_EQ(server->listen("udp://127.0.0.1:0"), GN_OK);
    const auto port = server->listen_port();
    ASSERT_GT(port, 0u);

    const std::string target_uri =
        "udp://127.0.0.1:" + std::to_string(port);
    ASSERT_EQ(client->connect(target_uri), GN_OK);

    wait_for([&] { return h_client.connects.load() == 1; }, 2s,
              "client notify_connect");
    {
        std::lock_guard lk(h_client.mu);
        ASSERT_EQ(h_client.roles.size(), 1u);
        EXPECT_EQ(h_client.roles[0], GN_ROLE_INITIATOR);
        EXPECT_EQ(h_client.trusts[0], GN_TRUST_LOOPBACK);
    }

    gn_conn_id_t client_conn = GN_INVALID_ID;
    {
        std::lock_guard lk(h_client.mu);
        client_conn = h_client.conns.front();
    }

    /// Boundary preservation: send three distinct datagrams; the
    /// server's `notify_inbound_bytes` must fire three times with the
    /// matching byte ranges, never a coalesced read.
    const std::vector<std::vector<std::uint8_t>> frames = {
        {0xAA, 0xBB, 0xCC},
        {0x01, 0x02, 0x03, 0x04, 0x05},
        {0x77},
    };
    for (const auto& f : frames) {
        ASSERT_EQ(client->send(client_conn,
                                std::span<const std::uint8_t>(f)),
                  GN_OK);
    }

    wait_for([&] {
        std::lock_guard lk(h_server.mu);
        return h_server.inbound.size() == frames.size();
    }, 2s, "three datagrams arrived at server");

    {
        std::lock_guard lk(h_server.mu);
        ASSERT_EQ(h_server.inbound.size(), frames.size());
        for (std::size_t i = 0; i < frames.size(); ++i) {
            EXPECT_EQ(h_server.inbound[i], frames[i])
                << "frame " << i << " corrupted or coalesced";
        }
        /// First datagram from a new sender allocates a conn record
        /// on the server.
        EXPECT_EQ(h_server.connects.load(), 1);
        EXPECT_EQ(h_server.roles.front(), GN_ROLE_RESPONDER);
        EXPECT_EQ(h_server.trusts.front(), GN_TRUST_LOOPBACK);
    }

    server->shutdown();
    client->shutdown();
}

TEST(UdpLink, SendOversizedPayloadIsRejected) {
    auto t = std::make_shared<UdpLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    ASSERT_EQ(t->listen("udp://127.0.0.1:0"), GN_OK);
    const std::string target =
        "udp://127.0.0.1:" + std::to_string(t->listen_port());
    ASSERT_EQ(t->connect(target), GN_OK);

    wait_for([&] { return h.connects.load() >= 1; }, 1s,
              "connect record allocated");

    gn_conn_id_t conn = GN_INVALID_ID;
    {
        std::lock_guard lk(h.mu);
        conn = h.conns.front();
    }

    std::vector<std::uint8_t> oversized(t->mtu() + 1, 0x55);
    EXPECT_EQ(t->send(conn,
                       std::span<const std::uint8_t>(oversized)),
              GN_ERR_PAYLOAD_TOO_LARGE);

    t->shutdown();
}

TEST(UdpLink, SendToUnknownConnRejected) {
    auto t = std::make_shared<UdpLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    ASSERT_EQ(t->listen("udp://127.0.0.1:0"), GN_OK);
    const std::uint8_t payload[] = {0x42};
    EXPECT_EQ(t->send(/*never registered*/ 99,
                       std::span<const std::uint8_t>(payload)),
              GN_ERR_NOT_FOUND);
    t->shutdown();
}

TEST(UdpLink, DisconnectIsIdempotent) {
    auto t = std::make_shared<UdpLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    ASSERT_EQ(t->listen("udp://127.0.0.1:0"), GN_OK);
    const std::string target =
        "udp://127.0.0.1:" + std::to_string(t->listen_port());
    ASSERT_EQ(t->connect(target), GN_OK);

    wait_for([&] { return h.connects.load() >= 1; }, 1s,
              "connect record");
    gn_conn_id_t conn = GN_INVALID_ID;
    {
        std::lock_guard lk(h.mu);
        conn = h.conns.front();
    }

    EXPECT_EQ(t->disconnect(conn), GN_OK);
    EXPECT_EQ(t->disconnect(conn), GN_OK);  /// no-op second time

    t->shutdown();
}

TEST(UdpLink, ConnectRejectsZeroPort) {
    auto t = std::make_shared<UdpLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    /// Listen accepts port 0 (ephemeral allocation); connect rejects
    /// it at the application layer per `uri.md` §5.
    EXPECT_NE(t->connect("udp://127.0.0.1:0"), GN_OK);
    t->shutdown();
}

TEST(UdpLink, BatchSendRejectsOversizedAtomically) {
    StubHost h_server;
    StubHost h_client;
    auto api_server = make_stub_api(h_server);
    auto api_client = make_stub_api(h_client);

    auto server = std::make_shared<UdpLink>();
    auto client = std::make_shared<UdpLink>();
    server->set_host_api(&api_server);
    client->set_host_api(&api_client);

    ASSERT_EQ(server->listen("udp://127.0.0.1:0"), GN_OK);
    ASSERT_EQ(client->connect(
                  "udp://127.0.0.1:" + std::to_string(server->listen_port())),
              GN_OK);
    wait_for([&] { return h_client.connects.load() == 1; }, 1s,
              "client connect");
    gn_conn_id_t conn = GN_INVALID_ID;
    {
        std::lock_guard lk(h_client.mu);
        conn = h_client.conns.front();
    }

    /// Mix one oversized frame in the middle. None should reach the
    /// wire — pre-validate fails the entire batch atomically so the
    /// caller never sees a half-written sequence.
    const std::vector<std::uint8_t> ok_a(64, 0x01);
    const std::vector<std::uint8_t> too_big(client->mtu() + 1, 0x02);
    const std::vector<std::uint8_t> ok_b(64, 0x03);
    const std::span<const std::uint8_t> spans[] = {
        std::span<const std::uint8_t>(ok_a),
        std::span<const std::uint8_t>(too_big),
        std::span<const std::uint8_t>(ok_b),
    };
    EXPECT_EQ(client->send_batch(conn,
                  std::span<const std::span<const std::uint8_t>>(spans)),
              GN_ERR_PAYLOAD_TOO_LARGE);

    /// Give the server some scheduling time; nothing must arrive.
    std::this_thread::sleep_for(50ms);
    {
        std::lock_guard lk(h_server.mu);
        EXPECT_EQ(h_server.inbound.size(), 0u)
            << "atomic batch must not partially deliver";
    }

    server->shutdown();
    client->shutdown();
}

TEST(UdpLink, DisconnectFiresNotifyDisconnect) {
    auto t = std::make_shared<UdpLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    ASSERT_EQ(t->listen("udp://127.0.0.1:0"), GN_OK);
    ASSERT_EQ(t->connect("udp://127.0.0.1:" +
                          std::to_string(t->listen_port())),
              GN_OK);
    wait_for([&] { return h.connects.load() >= 1; }, 1s, "connect");
    gn_conn_id_t conn = GN_INVALID_ID;
    {
        std::lock_guard lk(h.mu);
        conn = h.conns.front();
    }

    EXPECT_EQ(t->disconnect(conn), GN_OK);
    /// notify_disconnect MUST fire — otherwise the kernel's
    /// connection registry leaks the conn forever (UDP has no
    /// in-band close signal).
    EXPECT_EQ(h.disconnects.load(), 1);
    t->shutdown();
}

TEST(UdpLink, ShutdownNotifiesAllPeers) {
    StubHost h_server;
    StubHost h_client;
    auto api_server = make_stub_api(h_server);
    auto api_client = make_stub_api(h_client);

    auto server = std::make_shared<UdpLink>();
    auto client = std::make_shared<UdpLink>();
    server->set_host_api(&api_server);
    client->set_host_api(&api_client);

    ASSERT_EQ(server->listen("udp://127.0.0.1:0"), GN_OK);
    ASSERT_EQ(client->connect(
                  "udp://127.0.0.1:" + std::to_string(server->listen_port())),
              GN_OK);
    wait_for([&] { return h_client.connects.load() == 1; }, 1s,
              "client connect");

    /// Server-side: bounce one datagram so the server allocates a
    /// peer record on its end too.
    gn_conn_id_t client_conn = GN_INVALID_ID;
    {
        std::lock_guard lk(h_client.mu);
        client_conn = h_client.conns.front();
    }
    const std::uint8_t hello[] = {0x42};
    ASSERT_EQ(client->send(client_conn,
                            std::span<const std::uint8_t>(hello)),
              GN_OK);
    wait_for([&] { return h_server.connects.load() == 1; }, 1s,
              "server peer alloc");

    server->shutdown();
    /// One conn on the server side should fire one disconnect.
    EXPECT_EQ(h_server.disconnects.load(), 1);

    client->shutdown();
}

TEST(UdpLink, IPv6LoopbackRoundTrip) {
    if (!host_supports_v6_loopback()) {
        GTEST_SKIP() << "host kernel/sandbox blocks IPv6 loopback send";
    }

    StubHost h_server;
    StubHost h_client;
    auto api_server = make_stub_api(h_server);
    auto api_client = make_stub_api(h_client);

    auto server = std::make_shared<UdpLink>();
    auto client = std::make_shared<UdpLink>();
    server->set_host_api(&api_server);
    client->set_host_api(&api_client);

    ASSERT_EQ(server->listen("udp://[::1]:0"), GN_OK);
    const auto port = server->listen_port();
    ASSERT_GT(port, 0u);

    ASSERT_EQ(client->connect("udp://[::1]:" + std::to_string(port)),
              GN_OK);
    wait_for([&] { return h_client.connects.load() == 1; }, 2s,
              "v6 client connect");
    {
        std::lock_guard lk(h_client.mu);
        EXPECT_EQ(h_client.trusts.front(), GN_TRUST_LOOPBACK);
    }

    gn_conn_id_t client_conn = GN_INVALID_ID;
    {
        std::lock_guard lk(h_client.mu);
        client_conn = h_client.conns.front();
    }
    const std::vector<std::uint8_t> payload = {0xde, 0xad, 0xbe, 0xef};
    ASSERT_EQ(client->send(client_conn,
                            std::span<const std::uint8_t>(payload)),
              GN_OK);
    wait_for([&] {
        std::lock_guard lk(h_server.mu);
        return !h_server.inbound.empty();
    }, 2s, "v6 datagram arrived");
    {
        std::lock_guard lk(h_server.mu);
        EXPECT_EQ(h_server.inbound.front(), payload);
    }

    server->shutdown();
    client->shutdown();
}

TEST(UdpLink, BatchSendPreservesBoundaries) {
    StubHost h_server;
    StubHost h_client;
    auto api_server = make_stub_api(h_server);
    auto api_client = make_stub_api(h_client);

    auto server = std::make_shared<UdpLink>();
    auto client = std::make_shared<UdpLink>();
    server->set_host_api(&api_server);
    client->set_host_api(&api_client);

    ASSERT_EQ(server->listen("udp://127.0.0.1:0"), GN_OK);
    ASSERT_EQ(client->connect(
                  "udp://127.0.0.1:" + std::to_string(server->listen_port())),
              GN_OK);

    wait_for([&] { return h_client.connects.load() == 1; }, 1s,
              "client connect");
    gn_conn_id_t conn = GN_INVALID_ID;
    {
        std::lock_guard lk(h_client.mu);
        conn = h_client.conns.front();
    }

    /// Two-frame batch — must arrive as two separate datagrams, never
    /// concatenated. Stream transports coalesce; datagram transports
    /// preserve frame boundaries.
    const std::vector<std::uint8_t> a = {0x10, 0x11};
    const std::vector<std::uint8_t> b = {0x20, 0x21, 0x22};
    const std::span<const std::uint8_t> spans[] = {
        std::span<const std::uint8_t>(a),
        std::span<const std::uint8_t>(b),
    };
    ASSERT_EQ(client->send_batch(conn,
                  std::span<const std::span<const std::uint8_t>>(spans)),
              GN_OK);

    wait_for([&] {
        std::lock_guard lk(h_server.mu);
        return h_server.inbound.size() == 2;
    }, 2s, "two distinct datagrams");

    {
        std::lock_guard lk(h_server.mu);
        EXPECT_EQ(h_server.inbound[0], a);
        EXPECT_EQ(h_server.inbound[1], b);
    }

    server->shutdown();
    client->shutdown();
}
