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
// perf_common.h -- the one measurement shape every P0 bench shares
// (p2p_performance.md §3). Header-only, no MSCS dependency, so B0 (which must
// contain no MSCS code at all) can use it too.
//
// What it gives a bench:
//
//   * Stats      -- a sample vector reported as min / p50 / avg / p99 / MAX,
//                   never p50 alone (§3.2: the Nagle stall was 41,833 us MAX
//                   under an unmoved median).
//   * CpuNow()   -- process CPU seconds, so a number can be read as CPU us/op as
//                   well as wall time: wall time alone hides a spinning waiter.
//                   Windows: GetProcessTimes, which accumulates on the scheduler
//                   tick (15.625 ms), so CPU/op is only meaningful for phases
//                   that run for >= ~1 s. Linux: CLOCK_PROCESS_CPUTIME_ID (ns).
//   * allocation counting -- define PERF_COUNT_ALLOCS in exactly ONE translation
//                   unit before including this header, and operator new is
//                   replaced with a counting one. LIMIT, AND IT IS A REAL ONE:
//                   on Windows each DLL carries its own operator new, so this
//                   counts allocations made by code compiled INTO the bench exe
//                   only - not those inside Msgcore.dll / Targetcore.dll. On
//                   Linux the replacement interposes over the shared objects
//                   too, so there the count is the whole process. A bench that
//                   reports allocs/op says which of the two it measured.
//   * Report()   -- one human line in the perf_ab dialect plus one
//                   `PERFJSON {...}` line, so tools/perf/perf_run.py parses
//                   every bench with one regex.
//   * PrintBox() -- the run's identity (§3.2: "every run records box, OS,
//                   compiler, config, cores, commit").
//
// Timing is never a verdict here. Exit codes stay the tree's: 0 ran, 1 a
// correctness check inside the bench failed (a bench that measured a broken
// operation would post the best number in the table), 3 timeout.

#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#else
#  include <sys/utsname.h>
#  include <time.h>
#  include <unistd.h>
#endif

namespace perf
{
    using clk = std::chrono::steady_clock;

    inline double NsSince ( clk::time_point t0 )
    {
        return (double)std::chrono::duration_cast<std::chrono::nanoseconds> (
                   clk::now ( ) - t0 ).count ( );
    }

    // ---- process CPU time, seconds ------------------------------------
    inline double CpuNow ( )
    {
#if defined(_WIN32)
        FILETIME c, e, k, u;
        if ( !GetProcessTimes ( GetCurrentProcess ( ), &c, &e, &k, &u ) ) return 0;
        auto f = [] ( const FILETIME &t )
        { return ( (unsigned long long)t.dwHighDateTime << 32 ) | t.dwLowDateTime; };
        return ( f ( k ) + f ( u ) ) * 100e-9;
#else
        timespec ts;
        clock_gettime ( CLOCK_PROCESS_CPUTIME_ID, &ts );
        return ts.tv_sec + ts.tv_nsec * 1e-9;
#endif
    }

    // ---- allocation counter (see header) ------------------------------
    inline std::atomic<unsigned long long> &AllocCount ( )
    {
        static std::atomic<unsigned long long> n { 0 };
        return n;
    }
    inline unsigned long long Allocs ( )
    { return AllocCount ( ).load ( std::memory_order_relaxed ); }

#if defined(PERF_COUNT_ALLOCS)
    inline bool AllocsCounted ( ) { return true; }
#else
    inline bool AllocsCounted ( ) { return false; }
#endif

    // ---- environment knobs --------------------------------------------
    inline long EnvLong ( const char *name, long def )
    {
        const char *v = std::getenv ( name );
        return ( v && *v ) ? std::atol ( v ) : def;
    }
    inline bool JsonOn ( )
    {
        // On by default: the JSON line is one extra line per case and the
        // driver needs it. PERF_JSON=0 silences it for a human-only run.
        const char *v = std::getenv ( "PERF_JSON" );
        return !( v && v[0] == '0' );
    }

    // ---- statistics ----------------------------------------------------
    struct Stats
    {
        size_t n = 0;
        double min = 0, p50 = 0, avg = 0, p99 = 0, max = 0;
    };

    inline Stats Summarise ( std::vector<double> v )
    {
        Stats s;
        if ( v.empty ( ) ) return s;
        std::sort ( v.begin ( ), v.end ( ) );
        double sum = 0;
        for ( double x : v ) sum += x;
        auto pct = [&] ( double p )
        { return v[ std::min<size_t> ( v.size ( ) - 1, (size_t)( p * v.size ( ) ) ) ]; };
        s.n   = v.size ( );
        s.min = v.front ( );
        s.p50 = pct ( 0.50 );
        s.avg = sum / v.size ( );
        s.p99 = pct ( 0.99 );
        s.max = v.back ( );
        return s;
    }

    // ---- reporting -----------------------------------------------------
    //  bench   the executable name, e.g. "crypto_bench"
    //  kase    the case, e.g. "aes_gcm_seal"
    //  param   the swept parameter as text, e.g. "4048B" ("" if none)
    //  unit    of the stats, e.g. "ns/op", "us"
    //  cpuPerOp / allocsPerOp: < 0 means "not measured" and is printed as null
    inline void Report ( const char *bench, const char *kase, const std::string &param,
                         const char *unit, const Stats &s,
                         double cpuPerOp = -1, double allocsPerOp = -1,
                         const char *note = nullptr, const char *cpuUnit = nullptr )
    {
        // The CPU figure is per op in the stats' unit unless told otherwise:
        // a throughput row's stats are msgs/s but its CPU is us per message.
        if ( !cpuUnit ) cpuUnit = unit;
        std::printf ( "%-22s %-10s n=%-6zu min=%-10.1f p50=%-10.1f avg=%-10.1f "
                      "p99=%-10.1f max=%-10.1f %s",
                      kase, param.c_str ( ), s.n, s.min, s.p50, s.avg, s.p99, s.max, unit );
        if ( cpuPerOp >= 0 )    std::printf ( "  cpu=%.2f %s", cpuPerOp, cpuUnit );
        if ( allocsPerOp >= 0 ) std::printf ( "  allocs/op=%.2f", allocsPerOp );
        if ( note )             std::printf ( "  (%s)", note );
        std::printf ( "\n" );

        if ( JsonOn ( ) )
        {
            auto num = [] ( double d, char *buf, size_t cb )
            {
                if ( d < 0 ) std::snprintf ( buf, cb, "null" );
                else         std::snprintf ( buf, cb, "%.3f", d );
                return buf;
            };
            char c1[32], c2[32];
            std::printf ( "PERFJSON {\"bench\":\"%s\",\"case\":\"%s\",\"param\":\"%s\","
                          "\"unit\":\"%s\",\"n\":%zu,\"min\":%.3f,\"p50\":%.3f,"
                          "\"avg\":%.3f,\"p99\":%.3f,\"max\":%.3f,"
                          "\"cpu_per_op\":%s,\"cpu_unit\":\"%s\",\"allocs_per_op\":%s}\n",
                          bench, kase, param.c_str ( ), unit, s.n, s.min, s.p50, s.avg,
                          s.p99, s.max, num ( cpuPerOp, c1, sizeof c1 ), cpuUnit,
                          num ( allocsPerOp, c2, sizeof c2 ) );
        }
        std::fflush ( stdout );
    }

    // ---- micro-op timing ----------------------------------------------
    //  Runs `op` in `reps` batches of `batch` calls and returns per-op ns
    //  stats over the batches, plus CPU ns/op and allocations/op over the
    //  whole measured run. A warm-up batch is run first and discarded.
    //  `op` returns false on a correctness failure; the first one aborts the
    //  case and sets *pOk = false.
    struct OpResult
    {
        Stats  ns;
        double cpuNsPerOp    = -1;
        double allocsPerOp   = -1;
        bool   ok            = true;
    };

    template <class F>
    OpResult TimeOp ( F &&op, long batch, long reps )
    {
        OpResult r;
        for ( long i = 0; i < batch; ++i )                    // warm-up
            if ( !op ( ) ) { r.ok = false; return r; }

        std::vector<double> perOp;
        perOp.reserve ( (size_t)reps );
        double             cpu0 = CpuNow ( );
        unsigned long long a0   = Allocs ( );
        clk::time_point    tAll = clk::now ( );
        for ( long rep = 0; rep < reps; ++rep )
        {
            clk::time_point t0 = clk::now ( );
            for ( long i = 0; i < batch; ++i )
                if ( !op ( ) ) { r.ok = false; return r; }
            perOp.push_back ( NsSince ( t0 ) / batch );
        }
        double total = (double)batch * reps;
        r.ns          = Summarise ( std::move ( perOp ) );
        (void)tAll;
#if defined(_WIN32)
        // GetProcessTimes moves in 15.625 ms ticks: under ~1 s of wall time
        // the CPU figure is tick noise (0 or a multiple of a tick), so it is
        // reported as not measured rather than as a number.
        if ( NsSince ( tAll ) < 1e9 ) r.cpuNsPerOp = -1;
        else
#endif
        r.cpuNsPerOp  = ( CpuNow ( ) - cpu0 ) * 1e9 / total;
        if ( AllocsCounted ( ) )
            r.allocsPerOp = ( Allocs ( ) - a0 ) / total;
        return r;
    }

    // ---- run identity ---------------------------------------------------
    inline void PrintBox ( const char *bench )
    {
        std::string os, host;
#if defined(_WIN32)
        {
            char h[256] = { 0 };
            DWORD cb = sizeof h;
            if ( GetComputerNameA ( h, &cb ) ) host = h;
            // RtlGetVersion reports the real build; GetVersionEx lies to an
            // unmanifested exe.
            typedef LONG ( WINAPI *RtlGetVersion_t ) ( OSVERSIONINFOW * );
            OSVERSIONINFOW vi = { sizeof vi };
            HMODULE hNt = GetModuleHandleW ( L"ntdll.dll" );
            auto pf = hNt ? (RtlGetVersion_t)(void *)GetProcAddress ( hNt, "RtlGetVersion" )
                          : nullptr;
            char b[96];
            if ( pf && pf ( &vi ) == 0 )
                std::snprintf ( b, sizeof b, "Windows %lu.%lu.%lu",
                                vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber );
            else
                std::snprintf ( b, sizeof b, "Windows (version unknown)" );
            os = b;
        }
#else
        {
            utsname u;
            if ( uname ( &u ) == 0 )
            { os = std::string ( u.sysname ) + " " + u.release; host = u.nodename; }
            else os = "Linux (uname failed)";
        }
#endif
#if defined(_MSC_VER)
        char comp[64]; std::snprintf ( comp, sizeof comp, "MSVC %d", _MSC_FULL_VER );
#elif defined(__clang__)
        char comp[64]; std::snprintf ( comp, sizeof comp, "clang %d.%d.%d",
                                       __clang_major__, __clang_minor__, __clang_patchlevel__ );
#elif defined(__GNUC__)
        char comp[64]; std::snprintf ( comp, sizeof comp, "gcc %d.%d.%d",
                                       __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__ );
#else
        const char *comp = "unknown compiler";
#endif
#if defined(NDEBUG)
        const char *cfg = "Release";
#else
        const char *cfg = "Debug";
#endif
        const char *commit = std::getenv ( "MSCS_COMMIT" );   // set by perf_run.py
        std::printf ( "=== %s ===\n", bench );
        std::printf ( "box: host=%s  os=%s  cores=%u  compiler=%s  config=%s  commit=%s\n",
                      host.c_str ( ), os.c_str ( ), std::thread::hardware_concurrency ( ),
                      comp, cfg, commit ? commit : "(unset)" );
        if ( JsonOn ( ) )
            std::printf ( "PERFBOX {\"bench\":\"%s\",\"host\":\"%s\",\"os\":\"%s\","
                          "\"cores\":%u,\"compiler\":\"%s\",\"config\":\"%s\","
                          "\"commit\":\"%s\"}\n",
                          bench, host.c_str ( ), os.c_str ( ),
                          std::thread::hardware_concurrency ( ), comp, cfg,
                          commit ? commit : "" );
        if ( !std::strcmp ( cfg, "Debug" ) )
            std::printf ( "WARNING: Debug build. Report it, never quote it as a floor "
                          "(p2p_performance.md §3.2).\n" );
        std::fflush ( stdout );
    }
}

// ---- counting operator new (one TU only) --------------------------------
#if defined(PERF_COUNT_ALLOCS)
void *operator new ( std::size_t n )
{
    perf::AllocCount ( ).fetch_add ( 1, std::memory_order_relaxed );
    if ( n == 0 ) n = 1;
    if ( void *p = std::malloc ( n ) ) return p;
    throw std::bad_alloc ( );
}
void *operator new[] ( std::size_t n ) { return ::operator new ( n ); }
void *operator new ( std::size_t n, const std::nothrow_t & ) noexcept
{
    perf::AllocCount ( ).fetch_add ( 1, std::memory_order_relaxed );
    return std::malloc ( n ? n : 1 );
}
void *operator new[] ( std::size_t n, const std::nothrow_t &t ) noexcept
{ return ::operator new ( n, t ); }
void operator delete ( void *p ) noexcept                         { std::free ( p ); }
void operator delete[] ( void *p ) noexcept                       { std::free ( p ); }
void operator delete ( void *p, std::size_t ) noexcept            { std::free ( p ); }
void operator delete[] ( void *p, std::size_t ) noexcept          { std::free ( p ); }
void operator delete ( void *p, const std::nothrow_t & ) noexcept { std::free ( p ); }
void operator delete[] ( void *p, const std::nothrow_t & ) noexcept { std::free ( p ); }
#endif
