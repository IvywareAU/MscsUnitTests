// Copyright © 2026 Khrustal & Mann
//              MELBOURNE, VICTORIA, AUSTRALIA, 3000
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.
//
// perf_floor.cpp -- B0 of p2p_performance.md §3.1: the physics of the box,
// with NO MSCS CODE IN IT. It links nothing from this tree on purpose; it is
// the denominator every other bench is read against, and the input to E-K
// (§7.6), the experiment that bounds what moving Targetcore into the kernel
// could buy.
//
//   (a) cross-thread handoff, one-way = round trip / 2:
//         spin    -- two threads ping-pong one atomic (the cache-line floor)
//         condvar -- mutex + condition_variable (what perf_ab's PERF_BLOCKWAIT
//                    waiter and most pump wakes look like)
//         iocp    -- Windows: PostQueuedCompletionStatus / GetQueuedCompletionStatus
//         eventfd -- Linux: blocking write/read on two eventfds
//   (b) loopback TCP ping-pong, TCP_NODELAY, blocking sockets, one-way = RTT/2,
//       at 64 B and at 4,048 B -- the second because a one-field Msgcore message
//       ships the whole 4,048-byte initial arena (§0 verdict 2), so 4 KB is what
//       Targetcore actually puts on loopback today.
//   (c) the cost of one kernel transition with nothing to do:
//         Windows: GetQueuedCompletionStatus(timeout 0) on an empty port,
//                  SwitchToThread() (NtYieldExecution) with nothing runnable
//         Linux:   getppid() via syscall(), sched_yield(),
//                  io_uring_enter(to_submit=0, min_complete=0) on an idle ring
//       That is t_sys in E-K. The IOCP/io_uring versions of (b) are not here
//       yet: blocking sockets are the stack's floor, and the async ones add the
//       (c) costs, which are measured separately.
//
// Usage:  perf_floor [iterations]        default 20000 round trips per case
//         PERF_JSON=0 to drop the machine-readable lines.
// Verdict = exit code: 0 ran, 1 setup failed. Never a timing verdict.

#include "perf_common.h"

#include <condition_variable>
#include <mutex>

#if defined(_WIN32)
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
   typedef SOCKET sock_t;
#  define CLOSESOCK closesocket
#else
#  include <arpa/inet.h>
#  include <linux/io_uring.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <sched.h>
#  include <sys/eventfd.h>
#  include <sys/socket.h>
#  include <sys/syscall.h>
   typedef int sock_t;
#  define INVALID_SOCKET (-1)
#  define CLOSESOCK ::close
#endif

static const char *kBench = "perf_floor";

// Round-trip samples -> one-way stats (RTT / 2), in microseconds.
static void ReportOneWay ( const char *kase, const std::string &param,
                           std::vector<double> rttNs, double cpuSec )
{
    for ( double &v : rttNs ) v = v / 2.0 / 1e3;
    size_t n = rttNs.size ( );
    perf::Stats s = perf::Summarise ( std::move ( rttNs ) );
    // CPU per one-way hop, both threads together (the honest cost of a hop).
    perf::Report ( kBench, kase, param, "us", s, n ? cpuSec * 1e6 / ( 2.0 * n ) : -1 );
}

// ---- (a) cross-thread handoff -------------------------------------------
static void HandoffSpin ( long iters )
{
    std::atomic<long> ball { 0 };
    std::thread t ( [&] {
        for ( long i = 0; i < iters + 100; ++i )
        {
            while ( ball.load ( std::memory_order_acquire ) != 2 * i + 1 ) { }
            ball.store ( 2 * i + 2, std::memory_order_release );
        }
    } );
    std::vector<double> rtt; rtt.reserve ( iters );
    double cpu0 = 0;
    for ( long i = 0; i < iters + 100; ++i )
    {
        if ( i == 100 ) cpu0 = perf::CpuNow ( );
        perf::clk::time_point t0 = perf::clk::now ( );
        ball.store ( 2 * i + 1, std::memory_order_release );
        while ( ball.load ( std::memory_order_acquire ) != 2 * i + 2 ) { }
        if ( i >= 100 ) rtt.push_back ( perf::NsSince ( t0 ) );
    }
    double cpu = perf::CpuNow ( ) - cpu0;
    t.join ( );
    ReportOneWay ( "handoff_spin", "", std::move ( rtt ), cpu );
}

static void HandoffCondvar ( long iters )
{
    std::mutex m; std::condition_variable cv;
    long turn = 0;                       // odd = worker's turn, even = main's
    std::thread t ( [&] {
        for ( long i = 0; i < iters + 100; ++i )
        {
            std::unique_lock<std::mutex> lk ( m );
            cv.wait ( lk, [&] { return turn == 2 * i + 1; } );
            turn = 2 * i + 2;
            cv.notify_all ( );
        }
    } );
    std::vector<double> rtt; rtt.reserve ( iters );
    double cpu0 = 0;
    for ( long i = 0; i < iters + 100; ++i )
    {
        if ( i == 100 ) cpu0 = perf::CpuNow ( );
        perf::clk::time_point t0 = perf::clk::now ( );
        {
            std::unique_lock<std::mutex> lk ( m );
            turn = 2 * i + 1;
            cv.notify_all ( );
            cv.wait ( lk, [&] { return turn == 2 * i + 2; } );
        }
        if ( i >= 100 ) rtt.push_back ( perf::NsSince ( t0 ) );
    }
    double cpu = perf::CpuNow ( ) - cpu0;
    t.join ( );
    ReportOneWay ( "handoff_condvar", "", std::move ( rtt ), cpu );
}

#if defined(_WIN32)
static bool HandoffIocp ( long iters )
{
    HANDLE a = CreateIoCompletionPort ( INVALID_HANDLE_VALUE, nullptr, 0, 1 );
    HANDLE b = CreateIoCompletionPort ( INVALID_HANDLE_VALUE, nullptr, 0, 1 );
    if ( !a || !b ) { std::printf ( "SETUP: CreateIoCompletionPort failed\n" ); return false; }
    std::thread t ( [&] {
        DWORD n; ULONG_PTR k; LPOVERLAPPED o;
        for ( long i = 0; i < iters + 100; ++i )
        {
            GetQueuedCompletionStatus ( a, &n, &k, &o, INFINITE );
            PostQueuedCompletionStatus ( b, 0, 0, nullptr );
        }
    } );
    std::vector<double> rtt; rtt.reserve ( iters );
    double cpu0 = 0;
    DWORD n; ULONG_PTR k; LPOVERLAPPED o;
    for ( long i = 0; i < iters + 100; ++i )
    {
        if ( i == 100 ) cpu0 = perf::CpuNow ( );
        perf::clk::time_point t0 = perf::clk::now ( );
        PostQueuedCompletionStatus ( a, 0, 0, nullptr );
        GetQueuedCompletionStatus ( b, &n, &k, &o, INFINITE );
        if ( i >= 100 ) rtt.push_back ( perf::NsSince ( t0 ) );
    }
    double cpu = perf::CpuNow ( ) - cpu0;
    t.join ( );
    CloseHandle ( a ); CloseHandle ( b );
    ReportOneWay ( "handoff_iocp", "", std::move ( rtt ), cpu );
    return true;
}
#else
static bool HandoffEventfd ( long iters )
{
    int a = eventfd ( 0, 0 ), b = eventfd ( 0, 0 );
    if ( a < 0 || b < 0 ) { std::printf ( "SETUP: eventfd failed\n" ); return false; }
    std::thread t ( [&] {
        uint64_t v;
        for ( long i = 0; i < iters + 100; ++i )
        {
            if ( read ( a, &v, 8 ) != 8 ) return;
            v = 1; if ( write ( b, &v, 8 ) != 8 ) return;
        }
    } );
    std::vector<double> rtt; rtt.reserve ( iters );
    double cpu0 = 0;
    uint64_t v;
    for ( long i = 0; i < iters + 100; ++i )
    {
        if ( i == 100 ) cpu0 = perf::CpuNow ( );
        perf::clk::time_point t0 = perf::clk::now ( );
        v = 1; if ( write ( a, &v, 8 ) != 8 ) break;
        if ( read ( b, &v, 8 ) != 8 ) break;
        if ( i >= 100 ) rtt.push_back ( perf::NsSince ( t0 ) );
    }
    double cpu = perf::CpuNow ( ) - cpu0;
    t.join ( );
    ::close ( a ); ::close ( b );
    ReportOneWay ( "handoff_eventfd", "", std::move ( rtt ), cpu );
    return true;
}
#endif

// ---- (b) loopback TCP ping-pong -----------------------------------------
static bool SendAll ( sock_t s, const char *p, int n )
{
    while ( n > 0 ) { int r = (int)send ( s, p, n, 0 ); if ( r <= 0 ) return false; p += r; n -= r; }
    return true;
}
static bool RecvAll ( sock_t s, char *p, int n )
{
    while ( n > 0 ) { int r = (int)recv ( s, p, n, 0 ); if ( r <= 0 ) return false; p += r; n -= r; }
    return true;
}
static void NoDelay ( sock_t s )
{ int one = 1; setsockopt ( s, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one ); }

static bool LoopbackTcp ( long iters, int cb )
{
    sock_t ls = socket ( AF_INET, SOCK_STREAM, IPPROTO_TCP );
    if ( ls == INVALID_SOCKET ) { std::printf ( "SETUP: socket failed\n" ); return false; }
    sockaddr_in sa {}; sa.sin_family = AF_INET; sa.sin_port = 0;          // ephemeral port:
    sa.sin_addr.s_addr = htonl ( INADDR_LOOPBACK );                       // no RESOURCE_LOCK
    if ( bind ( ls, (sockaddr *)&sa, sizeof sa ) != 0 || listen ( ls, 1 ) != 0 )
    { std::printf ( "SETUP: bind/listen failed\n" ); CLOSESOCK ( ls ); return false; }
    socklen_t sl = sizeof sa;
    getsockname ( ls, (sockaddr *)&sa, &sl );

    std::vector<char> buf ( cb, 'x' );
    std::thread echo ( [&] {
        sock_t s = accept ( ls, nullptr, nullptr );
        if ( s == INVALID_SOCKET ) return;
        NoDelay ( s );
        std::vector<char> b ( cb );
        for ( long i = 0; i < iters + 100; ++i )
            if ( !RecvAll ( s, b.data ( ), cb ) || !SendAll ( s, b.data ( ), cb ) ) break;
        CLOSESOCK ( s );
    } );

    sock_t c = socket ( AF_INET, SOCK_STREAM, IPPROTO_TCP );
    if ( c == INVALID_SOCKET || connect ( c, (sockaddr *)&sa, sizeof sa ) != 0 )
    { std::printf ( "SETUP: connect failed\n" ); CLOSESOCK ( ls ); echo.join ( ); return false; }
    NoDelay ( c );

    std::vector<double> rtt; rtt.reserve ( iters );
    double cpu0 = 0;
    bool ok = true;
    for ( long i = 0; i < iters + 100; ++i )
    {
        if ( i == 100 ) cpu0 = perf::CpuNow ( );
        perf::clk::time_point t0 = perf::clk::now ( );
        if ( !SendAll ( c, buf.data ( ), cb ) || !RecvAll ( c, buf.data ( ), cb ) )
        { ok = false; break; }
        if ( i >= 100 ) rtt.push_back ( perf::NsSince ( t0 ) );
    }
    double cpu = perf::CpuNow ( ) - cpu0;
    CLOSESOCK ( c );
    echo.join ( );
    CLOSESOCK ( ls );
    if ( !ok ) { std::printf ( "SETUP: loopback ping-pong broke\n" ); return false; }
    ReportOneWay ( "loopback_tcp", std::to_string ( cb ) + "B", std::move ( rtt ), cpu );
    return true;
}

// ---- (c) one kernel transition with nothing to do -----------------------
static bool NullSyscalls ( long iters )
{
    const long batch = 1000, reps = std::max<long> ( 10, iters / batch );
#if defined(_WIN32)
    HANDLE port = CreateIoCompletionPort ( INVALID_HANDLE_VALUE, nullptr, 0, 1 );
    if ( !port ) { std::printf ( "SETUP: CreateIoCompletionPort failed\n" ); return false; }
    auto r1 = perf::TimeOp ( [&] {
        DWORD n; ULONG_PTR k; LPOVERLAPPED o;
        GetQueuedCompletionStatus ( port, &n, &k, &o, 0 );   // empty -> WAIT_TIMEOUT
        return true; }, batch, reps );
    perf::Report ( kBench, "gqcs_empty", "", "ns/op", r1.ns, r1.cpuNsPerOp );
    CloseHandle ( port );
    auto r2 = perf::TimeOp ( [] { SwitchToThread ( ); return true; }, batch, reps );
    perf::Report ( kBench, "yield_syscall", "", "ns/op", r2.ns, r2.cpuNsPerOp,
                   -1, "SwitchToThread = NtYieldExecution" );
#else
    auto r1 = perf::TimeOp ( [] { syscall ( SYS_getppid ); return true; }, batch, reps );
    perf::Report ( kBench, "null_syscall", "", "ns/op", r1.ns, r1.cpuNsPerOp,
                   -1, "syscall(SYS_getppid)" );
    auto r2 = perf::TimeOp ( [] { sched_yield ( ); return true; }, batch, reps );
    perf::Report ( kBench, "yield_syscall", "", "ns/op", r2.ns, r2.cpuNsPerOp,
                   -1, "sched_yield" );

    // An idle io_uring: io_uring_enter(0, 0, 0) is the transition a pump pays
    // when it submits or waits with nothing new. Raw syscalls so this bench
    // needs no liburing - B0 links nothing it is measuring against.
    io_uring_params p {};
    int fd = (int)syscall ( __NR_io_uring_setup, 8, &p );
    if ( fd < 0 )
        std::printf ( "io_uring_enter_idle       skipped (io_uring_setup failed: "
                      "kernel or seccomp)\n" );
    else
    {
        auto r3 = perf::TimeOp ( [fd] {
            syscall ( __NR_io_uring_enter, fd, 0u, 0u, 0u, nullptr, 0 );
            return true; }, batch, reps );
        perf::Report ( kBench, "io_uring_enter_idle", "", "ns/op", r3.ns, r3.cpuNsPerOp );
        ::close ( fd );
    }
#endif
    return true;
}

int main ( int argc, char *argv[] )
{
    long iters = argc > 1 ? std::atol ( argv[1] ) : 20000;
    if ( iters < 100 ) iters = 100;

    perf::PrintBox ( kBench );
    std::printf ( "iterations=%ld round trips per case; one-way = RTT/2\n\n", iters );

#if defined(_WIN32)
    WSADATA w;
    if ( WSAStartup ( MAKEWORD ( 2, 2 ), &w ) != 0 ) { std::printf ( "SETUP: WSAStartup\n" ); return 1; }
#endif
    bool ok = true;

    std::printf ( "--- (a) cross-thread handoff, one-way ---\n" );
    HandoffSpin ( iters );
    HandoffCondvar ( iters );
#if defined(_WIN32)
    ok &= HandoffIocp ( iters );
#else
    ok &= HandoffEventfd ( iters );
#endif

    std::printf ( "\n--- (b) loopback TCP ping-pong, NODELAY, blocking, one-way ---\n" );
    ok &= LoopbackTcp ( iters, 64 );
    ok &= LoopbackTcp ( iters, 4048 );

    std::printf ( "\n--- (c) one kernel transition, nothing to do ---\n" );
    ok &= NullSyscalls ( iters * 10 );

#if defined(_WIN32)
    WSACleanup ( );
#endif
    std::printf ( "\nDone (exit=%d).\n", ok ? 0 : 1 );
    return ok ? 0 : 1;
}
