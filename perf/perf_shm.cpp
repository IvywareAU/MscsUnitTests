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
//  perf_shm -- B10, p2p_performance.md §6.3a step S1: the shared-memory transport's
//  primitives (Msgcore/Platform/p2pshm.h) measured THROUGH A PUMP'S COMPLETION PORT.
//
//  B0's section (d) (perf_floor) measured the floor: a raw sequence word, a reader parked
//  on a named event or a shared futex. A transport cannot park like that - its pump waits
//  on ONE completion port for everything. This is the same cross-process ping-pong with
//  the real pieces: two p2pshm rings in an unnamed (Windows) / sealed memfd (Linux)
//  mapping, length-prefixed frames copied out before use, and each side's wake delivered
//  as a completion on its own port (Windows: NtAssociateWaitCompletionPacket; Linux: an
//  eventfd as a one-shot POLLIN completion through the io_uring shim). So the difference
//  from (d)'s shm_park is the integration cost.
//
//  Cases, 64 B and 4,048 B payloads:
//    shm_pump_park   -- the reader parks as soon as its ring is empty (the worst case)
//    shm_pump_spin   -- the reader polls its ring up to a budget before it parks
//  Also printed per case: parks and wakes per message (parent side), so a lost-wake or
//  wake-storm bug shows as a number, not only as a hang.
//
//  Second process: Windows re-launches this exe with --shm-child and the mapping and both
//  events INHERITED; Linux forks. Every wait has a 10 s deadline: a dead peer fails the
//  case (exit 3), it does not hang the run.
//
//  Usage: perf_shm [round trips per case, default 20000]
//
#include "perf_common.h"
#include "p2pshm.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#if defined(_WIN32)
#  include <windows.h>
#else
#  include <signal.h>
#  include <sys/resource.h>
#  include <sys/wait.h>
#  include <unistd.h>
#  include "p2piocp.h"
#endif

static const char *kBench = "perf_shm";

static void ReportOneWay ( const char *kase, const std::string &param,
                           std::vector<double> rttNs, double cpuSec, const std::string &note )
{
    for ( double &v : rttNs ) v = v / 2.0 / 1e3;
    size_t n = rttNs.size ( );
    perf::Stats s = perf::Summarise ( std::move ( rttNs ) );
    perf::Report ( kBench, kase, param, "us", s, n ? cpuSec * 1e6 / ( 2.0 * n ) : -1, -1, note.c_str ( ) );
}

#if defined(_WIN32)
typedef HANDLE PeerWake;
#else
typedef int    PeerWake;
#endif

//  One side of the link: its rings, its own wake (armed on its own port), the peer's
//  wake to signal, and counters.
struct Side
{
    p2pshm::Ring *in   = nullptr;
    p2pshm::Ring *out  = nullptr;
    p2pshm::Wake  mine;
    PeerWake      peer {};
    HANDLE        port = nullptr;
    OVERLAPPED    ov {};
    long          spinBudget = 0;
    long          parks = 0, wakes = 0, signals = 0;
};

static void Signal ( Side &s ) { p2pshm::WakeSignal ( s.peer ); s.signals++; }

//  Arm this side's wake and wait for its completion. false on the deadline or a failure.
//  Failures by kind, printed when a case breaks, so a broken case says WHICH wait failed.
static long g_armFail = 0, g_gqcsFail = 0, g_wrongOv = 0;

static bool WaitWake ( Side &s )
{
    bool fired = false;
    if ( !p2pshm::WakeArm ( s.mine, s.port, 1, &s.ov, fired ) ) { g_armFail++; return false; }
    if ( !fired )
    {
        DWORD n = 0; ULONG_PTR k = 0; LPOVERLAPPED o = nullptr;
        if ( !GetQueuedCompletionStatus ( s.port, &n, &k, &o, 10000 ) ) { g_gqcsFail++; return false; }
        if ( o != &s.ov ) { g_wrongOv++; return false; }
    }
    p2pshm::WakeConsume ( s.mine );
    s.wakes++;
    return true;
}

//  Write all n bytes (the ring is a byte stream: writes may be short).
static bool Send ( Side &s, const void *p, uint32_t n )
{
    const uint8_t *q = static_cast<const uint8_t *> ( p );
    while ( n )
    {
        bool wakeReader = false;
        uint32_t k = 0;
        p2pshm::Put r = p2pshm::RingWrite ( *s.out, q, n, k, wakeReader );
        if ( r == p2pshm::Put::Bad ) return false;
        if ( r == p2pshm::Put::Ok ) { if ( wakeReader ) Signal ( s ); q += k; n -= k; continue; }
        if ( p2pshm::WriterPark ( *s.out ) ) { s.parks++; if ( !WaitWake ( s ) ) return false; }
    }
    return true;
}

//  Read exactly n bytes (reads may be short).
static bool Recv ( Side &s, void *buf, uint32_t n )
{
    uint8_t *q = static_cast<uint8_t *> ( buf );
    long spins = 0;
    while ( n )
    {
        bool wakeWriter = false;
        uint32_t k = 0;
        p2pshm::Get r = p2pshm::RingRead ( *s.in, q, n, k, wakeWriter );
        if ( r == p2pshm::Get::Bad ) return false;
        if ( r == p2pshm::Get::Ok ) { if ( wakeWriter ) Signal ( s ); q += k; n -= k; spins = 0; continue; }
        if ( spins++ < s.spinBudget ) continue;
        if ( p2pshm::ReaderPark ( *s.in ) ) { s.parks++; if ( !WaitWake ( s ) ) return false; }
        spins = 0;
    }
    return true;
}

//  The child: echo every message, copied out of one ring and into the other.
static int Child ( Side &s, long iters, int cb )
{
    std::vector<char> buf ( cb );
    for ( long i = 0; i < iters + 100; ++i )
    {
        if ( !Recv ( s, buf.data ( ), (uint32_t)cb ) ) return 1;
        if ( !Send ( s, buf.data ( ), (uint32_t)cb ) ) return 1;
    }
    return 0;
}

//  The parent: the timed loop.
static bool Parent ( Side &s, long iters, int cb, std::vector<double> &rtt, double &cpu )
{
    std::vector<char> ping ( cb, 'x' ), pong ( cb );
    rtt.reserve ( iters );
    double cpu0 = 0;
    for ( long i = 0; i < iters + 100; ++i )
    {
        if ( i == 100 ) { cpu0 = perf::CpuNow ( ); s.parks = s.wakes = s.signals = 0; }
        perf::clk::time_point t0 = perf::clk::now ( );
        if ( !Send ( s, ping.data ( ), (uint32_t)cb ) ||
             !Recv ( s, pong.data ( ), (uint32_t)cb ) ||
             std::memcmp ( ping.data ( ), pong.data ( ), cb ) )
        { std::printf ( "SETUP: shm ping-pong broke at %ld\n", i ); return false; }
        if ( i >= 100 ) rtt.push_back ( perf::NsSince ( t0 ) );
    }
    cpu = perf::CpuNow ( ) - cpu0;
    return true;
}

static std::string Note ( const Side &s, long iters )
{
    char b[160];
    std::snprintf ( b, sizeof b, "parent per round trip: parks %.2f wakes %.2f signals %.2f",
                    (double)s.parks / iters, (double)s.wakes / iters, (double)s.signals / iters );
    return b;
}

#if defined(_WIN32)
//  argv: --shm-child <hMap> <hEvChild> <hEvParent> <iters> <spin> <cb>
static int ChildMain ( int argc, char *argv[] )
{
    if ( argc < 8 ) return 1;
    HANDLE hMap   = (HANDLE)(uintptr_t)std::strtoull ( argv[2], nullptr, 10 );
    HANDLE hEvMe  = (HANDLE)(uintptr_t)std::strtoull ( argv[3], nullptr, 10 );
    HANDLE hEvPar = (HANDLE)(uintptr_t)std::strtoull ( argv[4], nullptr, 10 );
    long iters = std::atol ( argv[5] ), spin = std::atol ( argv[6] );
    int  cb    = std::atoi ( argv[7] );
    p2pshm::Mapping m;
    if ( !p2pshm::MappingOpen ( m, hMap ) ) return 2;
    Side s;
    s.in = &m.view->ring[0]; s.out = &m.view->ring[1];
    s.peer = hEvPar; s.spinBudget = spin;
    s.port = CreateIoCompletionPort ( INVALID_HANDLE_VALUE, nullptr, 0, 1 );
    if ( !s.port || !p2pshm::WakeAttach ( s.mine, hEvMe ) ) return 2;
    int rc = Child ( s, iters, cb );
    if ( rc ) std::fprintf ( stderr, "CHILD: armFail %ld gqcsFail %ld wrongOv %ld\n",
                             g_armFail, g_gqcsFail, g_wrongOv );
    p2pshm::WakeClose ( s.mine );
    CloseHandle ( s.port ); CloseHandle ( hEvPar );
    p2pshm::MappingClose ( m );
    return rc;
}

static double ChildCpu ( HANDLE hProc )
{
    FILETIME c, e, k, u;
    if ( !GetProcessTimes ( hProc, &c, &e, &k, &u ) ) return 0;
    auto t = [] ( FILETIME f ) { return ( (ULONGLONG)f.dwHighDateTime << 32 | f.dwLowDateTime ) / 1e7; };
    return t ( k ) + t ( u );
}

static bool Case ( long iters, long spin, int cb, const char *kase )
{
    p2pshm::Mapping m;
    if ( !p2pshm::MappingCreate ( m ) ) { std::printf ( "SETUP: MappingCreate failed\n" ); return false; }
    HANDLE evParent = CreateEventW ( nullptr, FALSE, FALSE, nullptr );
    HANDLE evChild  = CreateEventW ( nullptr, FALSE, FALSE, nullptr );
    SetHandleInformation ( m.h,      HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT );
    SetHandleInformation ( evChild,  HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT );
    SetHandleInformation ( evParent, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT );

    Side s;
    s.in = &m.view->ring[1]; s.out = &m.view->ring[0];
    s.peer = evChild; s.spinBudget = spin;
    s.port = CreateIoCompletionPort ( INVALID_HANDLE_VALUE, nullptr, 0, 1 );
    HANDLE evParentMine = nullptr;      // WakeAttach owns its event: give it a duplicate
    DuplicateHandle ( GetCurrentProcess ( ), evParent, GetCurrentProcess ( ), &evParentMine,
                      0, FALSE, DUPLICATE_SAME_ACCESS );
    if ( !s.port || !p2pshm::WakeAttach ( s.mine, evParentMine ) )
    { std::printf ( "SETUP: port / wake (NtAssociateWaitCompletionPacket %s)\n",
                    p2pshm::WakeSupported ( ) ? "present" : "MISSING" ); return false; }

    char exe[MAX_PATH];
    GetModuleFileNameA ( nullptr, exe, MAX_PATH );
    std::string cmd = std::string ( "\"" ) + exe + "\" --shm-child "
                    + std::to_string ( (uintptr_t)m.h ) + " " + std::to_string ( (uintptr_t)evChild ) + " "
                    + std::to_string ( (uintptr_t)evParent ) + " " + std::to_string ( iters ) + " "
                    + std::to_string ( spin ) + " " + std::to_string ( cb );
    STARTUPINFOA si {}; si.cb = sizeof si;
    PROCESS_INFORMATION pi {};
    std::vector<char> cmdBuf ( cmd.begin ( ), cmd.end ( ) ); cmdBuf.push_back ( 0 );
    if ( !CreateProcessA ( nullptr, cmdBuf.data ( ), nullptr, nullptr, TRUE, 0,
                           nullptr, nullptr, &si, &pi ) )
    { std::printf ( "SETUP: CreateProcess failed (%lu)\n", GetLastError ( ) ); return false; }

    std::vector<double> rtt; double cpu = 0;
    bool ok = Parent ( s, iters, cb, rtt, cpu );
    if ( !ok ) std::printf ( "SETUP: parent armFail %ld gqcsFail %ld wrongOv %ld\n",
                             g_armFail, g_gqcsFail, g_wrongOv );
    DWORD code = 1;
    if ( WaitForSingleObject ( pi.hProcess, 30000 ) != WAIT_OBJECT_0 )
    { TerminateProcess ( pi.hProcess, 1 ); ok = false; }
    else if ( !GetExitCodeProcess ( pi.hProcess, &code ) || code != 0 ) ok = false;
    double childCpu = ChildCpu ( pi.hProcess );
    CloseHandle ( pi.hThread ); CloseHandle ( pi.hProcess );
    p2pshm::WakeClose ( s.mine );
    CloseHandle ( s.port ); CloseHandle ( evChild ); CloseHandle ( evParent );
    p2pshm::MappingClose ( m );
    if ( !ok ) { std::printf ( "SETUP: %s failed (child exit %lu)\n", kase, code ); return false; }
    ReportOneWay ( kase, std::to_string ( cb ) + "B", std::move ( rtt ), cpu + childCpu, Note ( s, iters ) );
    return true;
}
#else
static double ChildrenCpu ( )
{
    rusage r {};
    getrusage ( RUSAGE_CHILDREN, &r );
    return r.ru_utime.tv_sec + r.ru_utime.tv_usec / 1e6 + r.ru_stime.tv_sec + r.ru_stime.tv_usec / 1e6;
}

static bool Case ( long iters, long spin, int cb, const char *kase )
{
    if ( !p2pshm::WakeSupported ( ) ) { std::printf ( "SETUP: p2p_iocp_poll not linked\n" ); return false; }
    p2pshm::Mapping m;
    if ( !p2pshm::MappingCreate ( m ) ) { std::printf ( "SETUP: MappingCreate failed\n" ); return false; }
    int efdParent = eventfd ( 0, EFD_NONBLOCK | EFD_CLOEXEC );
    int efdChild  = eventfd ( 0, EFD_NONBLOCK | EFD_CLOEXEC );
    if ( efdParent < 0 || efdChild < 0 ) { std::printf ( "SETUP: eventfd failed\n" ); return false; }
    double before = ChildrenCpu ( );
    std::fflush ( stdout );
    pid_t pid = fork ( );
    if ( pid < 0 ) { std::printf ( "SETUP: fork failed\n" ); return false; }
    if ( pid == 0 )
    {
        Side c;
        c.in = &m.view->ring[0]; c.out = &m.view->ring[1];
        c.peer = efdParent; c.spinBudget = spin;
        c.port = CreateIoCompletionPort ( INVALID_HANDLE_VALUE, nullptr, 0, 1 );
        if ( !c.port || !p2pshm::WakeAttach ( c.mine, efdChild ) ) _exit ( 2 );
        _exit ( Child ( c, iters, cb ) );
    }
    Side s;
    s.in = &m.view->ring[1]; s.out = &m.view->ring[0];
    s.peer = efdChild; s.spinBudget = spin;
    s.port = CreateIoCompletionPort ( INVALID_HANDLE_VALUE, nullptr, 0, 1 );
    bool ok = s.port && p2pshm::WakeAttach ( s.mine, efdParent );
    std::vector<double> rtt; double cpu = 0;
    if ( ok ) ok = Parent ( s, iters, cb, rtt, cpu );
    if ( !ok ) kill ( pid, SIGKILL );
    int st = 0;
    if ( waitpid ( pid, &st, 0 ) != pid || !WIFEXITED ( st ) || WEXITSTATUS ( st ) != 0 ) ok = false;
    double childCpu = ChildrenCpu ( ) - before;
    p2pshm::WakeClose ( s.mine );
    if ( s.port ) CloseHandle ( s.port );
    close ( efdChild );
    p2pshm::MappingClose ( m );
    if ( !ok ) { std::printf ( "SETUP: %s failed\n", kase ); return false; }
    ReportOneWay ( kase, std::to_string ( cb ) + "B", std::move ( rtt ), cpu + childCpu, Note ( s, iters ) );
    return true;
}
#endif

int main ( int argc, char *argv[] )
{
#if defined(_WIN32)
    if ( argc > 1 && std::strcmp ( argv[1], "--shm-child" ) == 0 )
      return ChildMain ( argc, argv );          // prints nothing
#endif
    long iters = argc > 1 ? std::atol ( argv[1] ) : 20000;
    if ( iters < 100 ) iters = 100;
    perf::PrintBox ( kBench );
    std::printf ( "iterations=%ld round trips per case; one-way = RTT/2; CPU = both processes\n\n", iters );
    bool ok = true;
    for ( int cb : { 64, 4048 } )
    {
        ok &= Case ( iters, 0,    cb, "shm_pump_park" );
        ok &= Case ( iters, 2000, cb, "shm_pump_spin" );
    }
    //  A message three times the ring: every send is several short writes with the
    //  writer parked on a full ring - the path a ping-pong of small messages never takes.
    //  The parent checks every byte echoed back
    ok &= Case ( iters / 20 < 100 ? 100 : iters / 20, 0, 200000, "shm_pump_bulk" );
    std::printf ( "\nDone (exit=%d).\n", ok ? 0 : 3 );
    return ok ? 0 : 3;
}
