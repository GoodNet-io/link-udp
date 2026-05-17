// SPDX-License-Identifier: MIT
/// @file   plugins/links/udp/tests/test_composer.cpp
/// @brief  UdpLink composer surface — datagram-mode L2 composition per
///         `link.en.md` §8. Covers composer_listen / composer_connect /
///         composer_subscribe_data and the bit-63 dispatch in send /
///         disconnect, plus coexistence with the kernel-managed path.

#include <gtest/gtest.h>

#include <udp.hpp>

#include <sdk/cpp/test/stub_host.hpp>
#include <sdk/host_api.h>
#include <sdk/types.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace {

using namespace std::chrono_literals;
using gn::link::udp::UdpLink;

/// Composer tests do not exercise the kernel `notify_*` machinery —
/// UDP composer mode bypasses the kernel inbound path entirely. The
/// stub host API is still attached so any reload-subscription side-
/// effects in `set_host_api` have something to bind to.
///
/// Uses the shared `gn::sdk::test::LinkStub` which tracks
/// `conns / roles / trusts` per call alongside the captured
/// payloads.
using StubHost = ::gn::sdk::test::LinkStub;
inline host_api_t make_stub_api(StubHost& h) noexcept {
    return ::gn::sdk::test::make_link_host_api(h);
}

/// Recorded data-callback payloads. The recorder is referenced from a
/// C-style thunk through a captured `this` pointer so the recorder
/// lifetime must outlive the UdpLink.
struct DataRecorder {
    mutable std::mutex                          mu;
    std::vector<std::vector<std::uint8_t>>      frames;
    std::vector<gn_conn_id_t>                   owners;
    std::atomic<std::size_t>                    count{0};

    static void thunk(void* user_data, gn_conn_id_t conn,
                      const std::uint8_t* bytes, std::size_t size) {
        auto* self = static_cast<DataRecorder*>(user_data);
        {
            std::lock_guard lk(self->mu);
            self->frames.emplace_back(bytes, bytes + size);
            self->owners.push_back(conn);
        }
        self->count.fetch_add(1, std::memory_order_relaxed);
    }
};

bool wait_until(const std::function<bool()>& pred,
                std::chrono::milliseconds timeout = 2s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(2ms);
    }
    return false;
}

}  // namespace

// ── basic plumbing ───────────────────────────────────────────────────────

TEST(UdpComposer, ConnectAndSubscribeData) {
    auto t = std::make_shared<UdpLink>();
    StubHost host;
    auto api = make_stub_api(host);
    t->set_host_api(&api);

    ASSERT_EQ(t->composer_listen("udp://127.0.0.1:0"), GN_OK);
    const auto port = [&] {
        std::uint16_t p = 0;
        EXPECT_EQ(t->composer_listen_port(&p), GN_OK);
        return p;
    }();
    ASSERT_GT(port, 0u);

    gn_conn_id_t cid = GN_INVALID_ID;
    auto target = std::string("udp://127.0.0.1:") + std::to_string(port);
    ASSERT_EQ(t->composer_connect(target, &cid), GN_OK);
    EXPECT_NE(cid, GN_INVALID_ID);
    EXPECT_TRUE(cid & (static_cast<gn_conn_id_t>(1ULL) << 63));

    DataRecorder rec;
    EXPECT_EQ(t->composer_subscribe_data(cid, &DataRecorder::thunk, &rec),
              GN_OK);

    t->shutdown();
}

TEST(UdpComposer, ComposerSubscribeRejectsKernelId) {
    auto t = std::make_shared<UdpLink>();
    StubHost host;
    auto api = make_stub_api(host);
    t->set_host_api(&api);

    DataRecorder rec;
    EXPECT_EQ(t->composer_subscribe_data(/*kernel id*/ 1,
                                          &DataRecorder::thunk, &rec),
              GN_ERR_NOT_FOUND);
    t->shutdown();
}

// ── data path ────────────────────────────────────────────────────────────

TEST(UdpComposer, DataRoundtripClientServer) {
    auto srv = std::make_shared<UdpLink>();
    auto cli = std::make_shared<UdpLink>();
    StubHost srv_host;
    StubHost cli_host;
    auto srv_api = make_stub_api(srv_host);
    auto cli_api = make_stub_api(cli_host);
    srv->set_host_api(&srv_api);
    cli->set_host_api(&cli_api);

    ASSERT_EQ(srv->composer_listen("udp://127.0.0.1:0"), GN_OK);
    std::uint16_t srv_port = 0;
    ASSERT_EQ(srv->composer_listen_port(&srv_port), GN_OK);
    ASSERT_GT(srv_port, 0u);

    gn_conn_id_t cli_to_srv = GN_INVALID_ID;
    auto target = std::string("udp://127.0.0.1:") + std::to_string(srv_port);
    ASSERT_EQ(cli->composer_connect(target, &cli_to_srv), GN_OK);

    DataRecorder cli_rec;
    ASSERT_EQ(cli->composer_subscribe_data(cli_to_srv,
                                            &DataRecorder::thunk, &cli_rec),
              GN_OK);

    /// Send first datagram client → server. The server learns the
    /// client endpoint on first arrival via its own composer_connect
    /// flow; we drive that allocation explicitly using `composer_connect`
    /// from the server side once the source URI is known. For this
    /// loopback test the server side bootstraps a peer record by
    /// connecting back to whatever ephemeral port the client picked —
    /// but we don't know it yet, so the client side sends first and
    /// the server learns the source endpoint through `recv_endpoint_`.
    ///
    /// Simpler path: explicitly allocate both directions through
    /// composer_connect to known ports. The client's listening port
    /// is available via `listen_port()` after composer_connect opens
    /// the outbound socket.
    const std::uint16_t cli_port = cli->listen_port();
    ASSERT_GT(cli_port, 0u);

    gn_conn_id_t srv_to_cli = GN_INVALID_ID;
    auto back = std::string("udp://127.0.0.1:") + std::to_string(cli_port);
    ASSERT_EQ(srv->composer_connect(back, &srv_to_cli), GN_OK);

    DataRecorder srv_rec;
    ASSERT_EQ(srv->composer_subscribe_data(srv_to_cli,
                                            &DataRecorder::thunk, &srv_rec),
              GN_OK);

    const std::uint8_t payload_c[] = {1, 2, 3, 4, 5};
    const std::uint8_t payload_s[] = {9, 8, 7};

    ASSERT_EQ(cli->send(cli_to_srv,
                         std::span<const std::uint8_t>(payload_c, 5)),
              GN_OK);
    ASSERT_EQ(srv->send(srv_to_cli,
                         std::span<const std::uint8_t>(payload_s, 3)),
              GN_OK);

    ASSERT_TRUE(wait_until([&] {
        return srv_rec.count.load() >= 1 && cli_rec.count.load() >= 1;
    }));

    {
        std::lock_guard lk(srv_rec.mu);
        ASSERT_FALSE(srv_rec.frames.empty());
        const auto& f = srv_rec.frames.front();
        EXPECT_EQ(f.size(), 5u);
        EXPECT_EQ(std::memcmp(f.data(), payload_c, 5), 0);
        EXPECT_EQ(srv_rec.owners.front(), srv_to_cli);
    }
    {
        std::lock_guard lk(cli_rec.mu);
        ASSERT_FALSE(cli_rec.frames.empty());
        const auto& f = cli_rec.frames.front();
        EXPECT_EQ(f.size(), 3u);
        EXPECT_EQ(std::memcmp(f.data(), payload_s, 3), 0);
        EXPECT_EQ(cli_rec.owners.front(), cli_to_srv);
    }

    /// Neither side should have called notify_inbound_bytes — composer
    /// path bypasses the kernel hook entirely.
    EXPECT_EQ(srv_host.inbound_calls.load(), 0);
    EXPECT_EQ(cli_host.inbound_calls.load(), 0);

    srv->shutdown();
    cli->shutdown();
}

TEST(UdpComposer, ListenPortReflectsBound) {
    auto t = std::make_shared<UdpLink>();
    StubHost host;
    auto api = make_stub_api(host);
    t->set_host_api(&api);

    /// Before any bind the slot returns INVALID_STATE so callers can
    /// distinguish «not opened yet» from «opened on port 0».
    std::uint16_t port = 1234;
    EXPECT_EQ(t->composer_listen_port(&port), GN_ERR_INVALID_STATE);
    EXPECT_EQ(port, 0u);

    ASSERT_EQ(t->composer_listen("udp://127.0.0.1:0"), GN_OK);
    EXPECT_EQ(t->composer_listen_port(&port), GN_OK);
    EXPECT_GT(port, 0u);

    t->shutdown();
}

// ── lifecycle ────────────────────────────────────────────────────────────

TEST(UdpComposer, UnsubscribeDataStopsCallbacks) {
    auto srv = std::make_shared<UdpLink>();
    auto cli = std::make_shared<UdpLink>();
    StubHost srv_host, cli_host;
    auto srv_api = make_stub_api(srv_host);
    auto cli_api = make_stub_api(cli_host);
    srv->set_host_api(&srv_api);
    cli->set_host_api(&cli_api);

    ASSERT_EQ(srv->composer_listen("udp://127.0.0.1:0"), GN_OK);
    std::uint16_t srv_port = 0;
    ASSERT_EQ(srv->composer_listen_port(&srv_port), GN_OK);

    gn_conn_id_t cli_to_srv = GN_INVALID_ID;
    auto target = std::string("udp://127.0.0.1:") + std::to_string(srv_port);
    ASSERT_EQ(cli->composer_connect(target, &cli_to_srv), GN_OK);

    const std::uint16_t cli_port = cli->listen_port();
    gn_conn_id_t srv_to_cli = GN_INVALID_ID;
    auto back = std::string("udp://127.0.0.1:") + std::to_string(cli_port);
    ASSERT_EQ(srv->composer_connect(back, &srv_to_cli), GN_OK);

    DataRecorder rec;
    ASSERT_EQ(srv->composer_subscribe_data(srv_to_cli,
                                            &DataRecorder::thunk, &rec),
              GN_OK);

    const std::uint8_t payload[] = {0xAA};
    ASSERT_EQ(cli->send(cli_to_srv,
                         std::span<const std::uint8_t>(payload, 1)),
              GN_OK);
    ASSERT_TRUE(wait_until([&] { return rec.count.load() >= 1; }));

    EXPECT_EQ(srv->composer_unsubscribe_data(srv_to_cli), GN_OK);

    ASSERT_EQ(cli->send(cli_to_srv,
                         std::span<const std::uint8_t>(payload, 1)),
              GN_OK);
    /// 200 ms is long enough for a loopback datagram to land but the
    /// callback should remain at 1 — no longer subscribed.
    std::this_thread::sleep_for(200ms);
    EXPECT_EQ(rec.count.load(), 1u);

    srv->shutdown();
    cli->shutdown();
}

TEST(UdpComposer, DisconnectIsIdempotent) {
    auto t = std::make_shared<UdpLink>();
    StubHost host;
    auto api = make_stub_api(host);
    t->set_host_api(&api);

    ASSERT_EQ(t->composer_listen("udp://127.0.0.1:0"), GN_OK);
    std::uint16_t port = 0;
    ASSERT_EQ(t->composer_listen_port(&port), GN_OK);

    gn_conn_id_t cid = GN_INVALID_ID;
    auto target = std::string("udp://127.0.0.1:") + std::to_string(port);
    ASSERT_EQ(t->composer_connect(target, &cid), GN_OK);

    EXPECT_EQ(t->disconnect(cid), GN_OK);
    EXPECT_EQ(t->disconnect(cid), GN_OK);  // second call → no-op
    /// kernel disconnects counter must remain zero — composer ids
    /// never thread through notify_disconnect.
    EXPECT_EQ(host.disconnects.load(), 0);

    t->shutdown();
}

TEST(UdpComposer, KernelAndComposerCoexistOnSameInstance) {
    auto t = std::make_shared<UdpLink>();
    StubHost host;
    auto api = make_stub_api(host);
    t->set_host_api(&api);

    /// Kernel-side listen and composer-side connect coexist on the
    /// same socket. The kernel listen accepts inbound from arbitrary
    /// sources via notify_connect; the composer connect carves out a
    /// specific endpoint that bypasses the kernel hook. Bit 63
    /// segregation keeps the two id spaces disjoint.
    ASSERT_EQ(t->listen("udp://127.0.0.1:0"), GN_OK);
    EXPECT_GT(t->listen_port(), 0u);

    /// Spawn a peer link that the composer side will talk to.
    auto peer = std::make_shared<UdpLink>();
    StubHost peer_host;
    auto peer_api = make_stub_api(peer_host);
    peer->set_host_api(&peer_api);
    ASSERT_EQ(peer->composer_listen("udp://127.0.0.1:0"), GN_OK);
    std::uint16_t peer_port = 0;
    ASSERT_EQ(peer->composer_listen_port(&peer_port), GN_OK);

    gn_conn_id_t composer_id = GN_INVALID_ID;
    auto peer_target =
        std::string("udp://127.0.0.1:") + std::to_string(peer_port);
    ASSERT_EQ(t->composer_connect(peer_target, &composer_id), GN_OK);
    EXPECT_TRUE(composer_id & (static_cast<gn_conn_id_t>(1ULL) << 63));

    gn_conn_id_t peer_back = GN_INVALID_ID;
    auto t_target =
        std::string("udp://127.0.0.1:") + std::to_string(t->listen_port());
    ASSERT_EQ(peer->composer_connect(t_target, &peer_back), GN_OK);

    DataRecorder rec;
    ASSERT_EQ(t->composer_subscribe_data(composer_id,
                                          &DataRecorder::thunk, &rec),
              GN_OK);

    const std::uint8_t payload[] = {1, 2, 3};
    ASSERT_EQ(peer->send(peer_back,
                          std::span<const std::uint8_t>(payload, 3)),
              GN_OK);

    ASSERT_TRUE(wait_until([&] { return rec.count.load() >= 1; }));
    /// Composer-path delivery must NOT have fired the kernel inbound
    /// hook on `t`. The kernel listen is still wired up — sending a
    /// datagram from an *unrelated* source would route to the kernel.
    EXPECT_EQ(host.inbound_calls.load(), 0);

    t->shutdown();
    peer->shutdown();
}

TEST(UdpComposer, ShutdownClearsComposerState) {
    auto t = std::make_shared<UdpLink>();
    StubHost host;
    auto api = make_stub_api(host);
    t->set_host_api(&api);

    ASSERT_EQ(t->composer_listen("udp://127.0.0.1:0"), GN_OK);
    std::uint16_t port = 0;
    ASSERT_EQ(t->composer_listen_port(&port), GN_OK);

    gn_conn_id_t cid = GN_INVALID_ID;
    auto target = std::string("udp://127.0.0.1:") + std::to_string(port);
    ASSERT_EQ(t->composer_connect(target, &cid), GN_OK);

    t->shutdown();

    /// After shutdown every composer surface must report invalid state.
    std::uint16_t post = 999;
    EXPECT_EQ(t->composer_listen_port(&post), GN_ERR_INVALID_STATE);
    EXPECT_EQ(post, 0u);
    EXPECT_EQ(t->composer_listen("udp://127.0.0.1:0"), GN_ERR_INVALID_STATE);
}
