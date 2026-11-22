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
// msgcore_bench.cpp -- B2 of p2p_performance.md §3.1: Msgcore with NO
// transport. Before this there was no Msgcore micro-bench at all, so M2-M6
// had no curve to move. It answers, per operation and against the field
// count N (1, 8, 64, 512):
//
//   build_flat      a message (P3PmsgBSTR32, the heap a P2PeerMsg is) with N
//                   INT32 fields DeclareItem'd under its MSG item. M3 says this
//                   is O(n^2) per parent (DeclareItem = Goto miss + copy +
//                   PushBack + copy + Goto); the curve vs N is the test.
//   build_nested    depth D (1, 4, 16) of single-child nesting.
//   serialize       PrepareP2Piomage(~0) + P2PiomageSize + copy-out, the
//                   send path with the default interface mask (full replica).
//                   The note carries the FRAME BYTES next to the logical
//                   payload: the frame is the whole heap arena (§2), which is
//                   what M1 trims.
//   recv_adopt      the receive path: new char[n+4] + copy + the length-
//                   validated P3PmsgBSTR(VBListIOmage*, n), which walks the
//                   image for real in every build (P2Peerio.cpp:660). M2's
//                   "trusted bit" moves this one.
//   msg_new         the empty message: the fixed cost under build_flat.
//   growth          the arena growth alone: build to 64 KB / 1 MB from 8 KB
//                   fields, reporting regrows, bytes memcpy'd and slack (M6).
//   lookup_repeat / lookup_alt / lookup_miss
//                   SelectItem / Exists on a RECEIVED (adopted) message, the
//                   heap every handler reads. lookup_repeat asks for the same
//                   name again and hits the cursor (flat in N -- measured
//                   2026-11-18, first run, which is why it is split out);
//                   lookup_alt alternates first/last so every call walks.
//   fieldref_read / fieldref_write
//                   MsgFieldRef on the last field: re-resolves the path per op
//                   (M5's target).
//   vect_walk       P3PmsgVect r_data(i) over 0..N-1, ns per ELEMENT.
//   capi_mgr        msgcore_mgr_create_nn + msgcore_mgr_destroy (the flat C
//                   ABI every non-C++ consumer enters through).
//
// NOT HERE, on purpose: the plan's "FacadeStore op" lives in MsgFacade, a
// separate library this tree does not link (MscsUnitTests links msgcore +
// targetcore + p2pplatform only, CLAUDE.md). It belongs with the facade
// example trees' own bench when M5 starts.
//
// Allocations/op: Linux counts the whole process (the replacement operator
// new interposes over libmsgcore.so). Windows reports null -- Msgcore.dll has
// its own operator new and MFC supplies the exe's (perf_common.h).
//
// Usage: msgcore_bench [scale]   scale multiplies every batch (default 1).
//        msgcore_bench --profile [local_]lookup_alt|lookup_miss|fieldref_read [seconds] [n]
//        msgcore_bench --profile msg_new|heap_only [seconds]
//        (local_: on the message as built, not as received -- the trusted-bit heap)
//                                one case in a loop, for a profiler.
// Exit: 0 ran, 1 a correctness check failed. Never a timing verdict.

#include "stdafx.h"

#if !defined(_WIN32)
#  define PERF_COUNT_ALLOCS
#endif
#include "perf_common.h"

#include "P2Pmsg.h"
#include "P2PmsgBSTR.h"
#include "MsgVect.h"
#include "Msgexception.h"
#include "MsgFieldRef.hpp"
#include "Msgcore_c.h"

#include <cwchar>
#include <memory>
#include <string>
#include <vector>

namespace
{
    const char *kBench = "msgcore_bench";
    long        g_scale = 1;
    bool        g_fail  = false;

    std::vector<std::wstring> g_names;          // L"f0000" .. ; built once

    const std::wstring &Name ( int i ) { return g_names[ (size_t)i ]; }

    // A P2Pevent is the library's exception; a bench must never let one
    // escape as a pass, nor print a dialog.
    template <class F> bool Guard ( F &&f )
    {
        try { return f ( ); }
        catch ( P2Pevent *pEVT )
        {
            if ( pEVT ) pEVT->Cancel ( false );
            return false;
        }
    }

    void Emit ( const char *kase, const std::string &param, const perf::OpResult &r,
                const char *unit = "ns/op", const char *note = nullptr )
    {
        if ( !r.ok )
        {
            std::printf ( "%-22s %-10s FAILED (correctness)\n", kase, param.c_str ( ) );
            g_fail = true;
            return;
        }
        perf::Report ( kBench, kase, param, unit, r.ns,
                       r.cpuNsPerOp, r.allocsPerOp, note );
    }

    // ---- the message under test -----------------------------------------
    //  A P3PmsgBSTR32 with a MSG item, which is what P2PeerMsg's constructor
    //  builds (P2PeerMsg.cpp:146) minus the addressing prefix.
    struct Msg
    {
        std::unique_ptr<P3PmsgBSTR32> bstr;
        P3PmsgItem                   *root = nullptr;
    };

    Msg NewMsg ( )
    {
        Msg m;
        m.bstr.reset ( new P3PmsgBSTR32 ( ) );
        m.root = &m.bstr->InitItem ( VBLockBSTR_MSG, P3PmsgData ( ) );
        return m;
    }

    void Fill ( P3PmsgItem &root, int n )
    {
        for ( int i = 0; i < n; ++i )
            root.DeclareItem ( Name ( i ).c_str ( ), P3PmsgData ( (int)i ) );
    }

    // Copy a prepared message's image out, as the send path hands it to the
    // socket. Returns the frame bytes.
    std::vector<char> Image ( P3PmsgBSTR &b )
    {
        b.PrepareP2Piomage ( ~(DWORD)0 );
        UINT n = b.P2PiomageSize ( );
        const char *p = (const char *)b.P2Piomage ( );
        std::vector<char> v ( p, p + n );
        b.ReleaseP2Piomage ( );
        return v;
    }

    // The receive path's adoption. On success the buffer belongs to the heap.
    std::unique_ptr<P3PmsgBSTR> Adopt ( const std::vector<char> &img )
    {
        char *buf = new char[ img.size ( ) + 4 ];
        std::memcpy ( buf, img.data ( ), img.size ( ) );
        try
        {
            return std::unique_ptr<P3PmsgBSTR> (
                new P3PmsgBSTR ( (VBListIOmage *)buf, (VBLsize)img.size ( ) ) );
        }
        catch ( ... ) { delete[] buf; throw; }   // a refused image stays ours
    }

    long Batch ( long base ) { long b = base * g_scale; return b < 1 ? 1 : b; }

    const int  kN[]    = { 1, 8, 64, 512 };
    const int  kDepth[] = { 1, 4, 16 };
    const long kReps   = 15;

    // ---------------------------------------------------------------------
    void BenchBuild ( )
    {
        // The fixed cost under every build_flat row: heap create, root item,
        // MSG item, destroy.
        auto r0 = perf::TimeOp ( [&] {
            return Guard ( [&] { Msg m = NewMsg ( ); return m.root != nullptr; } );
        }, Batch ( 2000 ), kReps );
        Emit ( "msg_new", "empty", r0, "ns/msg" );
        //  M7: the same without the MSG item - the heap and its root alone, so
        //  the item's share of msg_new is the difference
        auto r0h = perf::TimeOp ( [&] {
            return Guard ( [&] { P3PmsgBSTR32 b; return b.Sizeof ( ) > 0; } );
        }, Batch ( 2000 ), kReps );
        Emit ( "msg_new", "heap_only", r0h, "ns/msg" );

        for ( int n : kN )
        {
            long batch = n <= 8 ? 1000 : n <= 64 ? 100 : 4;
            auto r = perf::TimeOp ( [&] {
                return Guard ( [&] {
                    Msg m = NewMsg ( );
                    Fill ( *m.root, n );
                    return m.root->SelectItem ( Name ( n - 1 ).c_str ( ) ).c_int ( ) == n - 1;
                } );
            }, Batch ( batch ), kReps );
            char note[64];
            std::snprintf ( note, sizeof note, "%.1f ns/field",
                            r.ok ? r.ns.p50 / n : 0.0 );
            Emit ( "build_flat", std::to_string ( n ), r, "ns/msg", note );
        }

        for ( int d : kDepth )
        {
            std::wstring path;
            for ( int i = 0; i < d; ++i ) path += ( i ? L".n" : L"n" );
            auto r = perf::TimeOp ( [&] {
                return Guard ( [&] {
                    Msg m = NewMsg ( );
                    P3PmsgItem *cur = m.root;
                    for ( int i = 0; i < d; ++i )
                        cur = &cur->DeclareItem ( L"n", P3PmsgData ( (int)i ) );
                    return !m.root->SelectObject ( path.c_str ( ) ).IsVoid ( );
                } );
            }, Batch ( 500 ), kReps );
            Emit ( "build_nested", "D" + std::to_string ( d ), r, "ns/msg" );
        }
    }

    // ---------------------------------------------------------------------
    void BenchWire ( )
    {
        for ( int n : kN )
        {
            Msg m = NewMsg ( );
            bool built = Guard ( [&] { Fill ( *m.root, n ); return true; } );
            if ( !built ) { Emit ( "serialize", std::to_string ( n ), { {}, -1, -1, false } ); continue; }

            // Logical payload: what the fields would cost packed -- name in
            // UTF-16 (5 units) + an INT32. A floor for the ratio, not a format.
            const size_t logical = (size_t)n * ( 5 * 2 + 4 );
            std::vector<char> out ( 1 << 20 );
            size_t frame = 0;

            auto rs = perf::TimeOp ( [&] {
                return Guard ( [&] {
                    m.bstr->PrepareP2Piomage ( ~(DWORD)0 );
                    frame = m.bstr->P2PiomageSize ( );
                    if ( frame == 0 || frame > out.size ( ) ) return false;
                    std::memcpy ( out.data ( ), m.bstr->P2Piomage ( ), frame );
                    m.bstr->ReleaseP2Piomage ( );
                    return true;
                } );
            }, Batch ( 2000 ), kReps );
            char note[96];
            std::snprintf ( note, sizeof note, "frame=%zu B, logical=%zu B, %.1fx",
                            frame, logical, logical ? (double)frame / logical : 0.0 );
            Emit ( "serialize", std::to_string ( n ), rs, "ns/msg", note );

            std::vector<char> img;
            if ( !Guard ( [&] { img = Image ( *m.bstr ); return true; } ) )
            { Emit ( "recv_adopt", std::to_string ( n ), { {}, -1, -1, false } ); continue; }

            const std::wstring last = Name ( n - 1 );
            auto ra = perf::TimeOp ( [&] {
                return Guard ( [&] {
                    auto in = Adopt ( img );
                    return in->Sizeof ( ) > 0;
                } );
            }, Batch ( n <= 64 ? 2000 : 200 ), kReps );
            Emit ( "recv_adopt", std::to_string ( n ), ra, "ns/msg" );

            // Lookups on the RECEIVED heap.
            std::unique_ptr<P3PmsgBSTR> in;
            P3PmsgItem *root = nullptr;
            bool okIn = Guard ( [&] {
                in   = Adopt ( img );
                root = &in->r_item ( VBLockBSTR_MSG );
                return root->SelectItem ( last.c_str ( ) ).c_int ( ) == n - 1
                    && root->SelectItem ( Name ( 0 ).c_str ( ) ).c_int ( ) == 0;
            } );
            if ( !okIn )
            {
                std::printf ( "%-22s %-10s FAILED (received message did not read back)\n",
                              "lookup", std::to_string ( n ).c_str ( ) );
                g_fail = true;
                continue;
            }
            long lb = Batch ( n <= 64 ? 20000 : 2000 );
            // The SAME name again: Msgcore's cursor still sits on it, so this
            // is the cursor-hit floor, flat in N. A handler that reads one
            // field twice gets this; one that reads several fields does not.
            auto r1 = perf::TimeOp ( [&] { return Guard ( [&] {
                return root->SelectItem ( last.c_str ( ) ).c_int ( ) == n - 1; } ); }, lb, kReps );
            Emit ( "lookup_repeat", std::to_string ( n ), r1 );
            // Alternating first / last: every lookup moves the cursor across
            // the sibling list -- the walk M3 targets.
            bool flip = false;
            auto r2 = perf::TimeOp ( [&] { return Guard ( [&] {
                flip = !flip;
                return flip ? root->SelectItem ( Name ( 0 ).c_str ( ) ).c_int ( ) == 0
                            : root->SelectItem ( last.c_str ( ) ).c_int ( ) == n - 1; } ); },
                lb, kReps );
            Emit ( "lookup_alt", std::to_string ( n ), r2 );
            auto r3 = perf::TimeOp ( [&] { return Guard ( [&] {
                return !root->Exists ( L"absent" ); } ); }, lb, kReps );
            Emit ( "lookup_miss", std::to_string ( n ), r3 );

            // MsgFieldRef on the last field: one full path resolution per op.
            auto rr = perf::TimeOp ( [&] { return Guard ( [&] {
                return Field ( *root, last.c_str ( ) ).AsInt ( ) == n - 1; } ); }, lb, kReps );
            Emit ( "fieldref_read", std::to_string ( n ), rr );
            int v = n - 1;
            auto rw = perf::TimeOp ( [&] { return Guard ( [&] {
                Field ( *root, last.c_str ( ) ) = ++v;      // a real change each op
                return true; } ); }, lb, kReps );
            Emit ( "fieldref_write", std::to_string ( n ), rw );
            if ( !Guard ( [&] { return Field ( *root, last.c_str ( ) ).AsInt ( ) == v; } ) )
            {
                std::printf ( "fieldref_write: value did not read back\n" );
                g_fail = true;
            }
        }
    }

    // ---------------------------------------------------------------------
    //  growth: the arena growth on its own (B2x "growth isolated", plan
    //  §3.1a, which M6 is sized from). Few fields of 8 KB each, so the O(n^2)
    //  sibling insert build_flat measures stays out of it: 8 fields to 64 KB,
    //  128 to 1 MB. The arena is read through the full-replica image, which is
    //  the heap itself (no copy), after every field; a grow is the arena
    //  getting bigger, and what it memcpy'd is the arena it left. A single
    //  allocation that grows twice (F10's bound) counts once - the probe sees
    //  the result, not the passes. Timed separately, without the probe.
    size_t ArenaBytes ( P3PmsgBSTR &b )
    {
        b.PrepareP2Piomage ( ~(DWORD)0 );
        size_t n = b.P2PiomageSize ( );
        b.ReleaseP2Piomage ( );
        return n;
    }

    void BenchGrowth ( )
    {
        const std::wstring big ( 4096, L'x' );      // 8 KB of UTF-16 a field
        const struct { const char *label; int fields; } kCase[] = {
            { "64KB", 8 }, { "1MB", 128 } };
        for ( const auto &c : kCase )
        {
            size_t regrows = 0, copied = 0, arena = 0, used = 0;
            bool ok = Guard ( [&] {
                Msg m = NewMsg ( );
                size_t prev = ArenaBytes ( *m.bstr );
                for ( int i = 0; i < c.fields; ++i )
                {
                    m.root->DeclareItem ( Name ( i ).c_str ( ), P3PmsgData ( big.c_str ( ) ) );
                    size_t now = ArenaBytes ( *m.bstr );
                    if ( now > prev ) { ++regrows; copied += prev; }
                    prev = now;
                }
                arena = prev;
                used  = m.bstr->Sizeof ( );
                return m.root->SelectItem ( Name ( c.fields - 1 ).c_str ( ) ).c_wstr ( ) == big;
            } );
            if ( !ok ) { Emit ( "growth", c.label, { {}, -1, -1, false } ); continue; }

            auto r = perf::TimeOp ( [&] {
                return Guard ( [&] {
                    Msg m = NewMsg ( );
                    for ( int i = 0; i < c.fields; ++i )
                        m.root->DeclareItem ( Name ( i ).c_str ( ), P3PmsgData ( big.c_str ( ) ) );
                    return m.bstr->Sizeof ( ) > 0;
                } );
            }, Batch ( c.fields <= 8 ? 200 : 4 ), kReps );
            char note[160];
            std::snprintf ( note, sizeof note,
                            "regrows=%zu copied=%zu B (%.1fx used) arena=%zu used=%zu (%.0f%% slack)",
                            regrows, copied, used ? (double)copied / used : 0.0, arena, used,
                            arena ? 100.0 * ( arena - used ) / arena : 0.0 );
            Emit ( "growth", c.label, r, "ns/msg", note );
        }
    }

    // ---------------------------------------------------------------------
    void BenchVect ( )
    {
        for ( int n : kN )
        {
            std::unique_ptr<P3PmsgVect> v;
            bool ok = Guard ( [&] {
                v.reset ( new P3PmsgVect ( n, L"V", P3PmsgData ( (int)0 ) ) );
                for ( int i = 0; i < n; ++i ) v->r_data ( i ).c_int ( i );
                return (int)v->GetCount ( ) == n;
            } );
            if ( !ok ) { Emit ( "vect_walk", std::to_string ( n ), { {}, -1, -1, false } ); continue; }
            const long long want = (long long)n * ( n - 1 ) / 2;
            auto r = perf::TimeOp ( [&] { return Guard ( [&] {
                long long s = 0;
                for ( int i = 0; i < n; ++i ) s += v->r_data ( i ).c_int ( );
                return s == want; } ); }, Batch ( n <= 64 ? 2000 : 100 ), kReps );
            // Per ELEMENT, so an O(n) walk is a flat line and O(n^2) is not.
            if ( r.ok )
            {
                r.ns.min /= n; r.ns.p50 /= n; r.ns.avg /= n; r.ns.p99 /= n; r.ns.max /= n;
                if ( r.cpuNsPerOp  >= 0 ) r.cpuNsPerOp  /= n;
                if ( r.allocsPerOp >= 0 ) r.allocsPerOp /= n;
            }
            Emit ( "vect_walk", std::to_string ( n ), r, "ns/elem" );
        }
    }

    // ---------------------------------------------------------------------
    void BenchCApi ( )
    {
        auto r = perf::TimeOp ( [&] {
            MsgMgrHandle h = msgcore_mgr_create_nn ( 2 /*Addr32*/, 2048, 0 );
            if ( !h ) return false;
            msgcore_mgr_destroy ( h );
            return true;
        }, Batch ( 5000 ), kReps );
        Emit ( "capi_mgr", "create+destroy", r );
    }

    // ---------------------------------------------------------------------
    //  --profile <case> [seconds] [n]: ONE lookup case in a tight loop on a
    //  received n-field heap (default 512), for `perf record` / VS profiler.
    //  Added 2026-11-20 for M2's question (plan §M2): how much of a lookup
    //  walk is re-checking and how much is handle Connect + compare. Times
    //  nothing; prints the op count so the profile can be normalised.
    //  A "local_" prefix (local_lookup_alt, ...) runs the same case on the
    //  message as BUILT, not as received: the heap M2's trusted bit covers
    //  (Msgcore 3.4.7), where a Release build skips the per-access name
    //  bounds. Without the prefix the heap is adopted and keeps every check.
    int Profile ( const char *kase, double seconds, int n )
    {
        //  M7: the empty message on its own, create + destroy per op
        if ( std::strcmp ( kase, "msg_new" ) == 0 || std::strcmp ( kase, "heap_only" ) == 0 )
        {
            const bool bItem = std::strcmp ( kase, "msg_new" ) == 0;
            auto t0 = std::chrono::steady_clock::now ( );
            long long ops = 0;
            bool ok = true;
            while ( std::chrono::duration<double> ( std::chrono::steady_clock::now ( ) - t0 ).count ( ) < seconds )
                for ( int i = 0; i < 64; ++i, ++ops )
                {
                    if ( bItem ) { Msg m = NewMsg ( ); ok &= m.root != nullptr; }
                    else         { P3PmsgBSTR32 b; ok &= b.Sizeof ( ) > 0; }
                }
            double s = std::chrono::duration<double> ( std::chrono::steady_clock::now ( ) - t0 ).count ( );
            std::printf ( "profile %s: %lld ops in %.2f s = %.0f ns/op\n", kase, ops, s, s * 1e9 / (double)ops );
            return ok ? 0 : 1;
        }

        Msg m = NewMsg ( );
        Fill ( *m.root, n );
        std::vector<char> img = Image ( *m.bstr );
        std::unique_ptr<P3PmsgBSTR> in = Adopt ( img );
        std::string k = kase;
        const bool bLocal = k.rfind ( "local_", 0 ) == 0;
        if ( bLocal ) k = k.substr ( 6 );
        P3PmsgItem &root = bLocal ? *m.root : in->r_item ( VBLockBSTR_MSG );
        const std::wstring first = Name ( 0 ), last = Name ( n - 1 );

        auto t0 = std::chrono::steady_clock::now ( );
        long long ops = 0;
        bool flip = false, ok = true;
        while ( std::chrono::duration<double> ( std::chrono::steady_clock::now ( ) - t0 ).count ( ) < seconds )
        {
            for ( int i = 0; i < 64; ++i, ++ops )
            {
                if ( k == "lookup_alt" )
                {
                    flip = !flip;
                    ok &= flip ? root.SelectItem ( first.c_str ( ) ).c_int ( ) == 0
                               : root.SelectItem ( last.c_str ( ) ).c_int ( ) == n - 1;
                }
                else if ( k == "lookup_miss" )
                    ok &= !root.Exists ( L"absent" );
                else if ( k == "fieldref_read" )
                    ok &= Field ( root, last.c_str ( ) ).AsInt ( ) == n - 1;
                else
                {
                    std::printf ( "unknown profile case %s\n", kase );
                    return 1;
                }
            }
        }
        double s = std::chrono::duration<double> ( std::chrono::steady_clock::now ( ) - t0 ).count ( );
        std::printf ( "profile %s n=%d: %lld ops in %.2f s = %.0f ns/op%s\n",
                      kase, n, ops, s, s * 1e9 / (double)ops, ok ? "" : "  (READBACK FAILED)" );
        return ok ? 0 : 1;
    }
}

int main ( int argc, char **argv )
{
    if ( argc > 2 && std::strcmp ( argv[1], "--profile" ) == 0 )
    {
        for ( int i = 0; i < 512; ++i )
        {
            wchar_t b[16];
            std::swprintf ( b, 16, L"f%04d", i );
            g_names.emplace_back ( b );
        }
        double secs = argc > 3 ? std::atof ( argv[3] ) : 10.0;
        int    n    = argc > 4 ? std::atoi ( argv[4] ) : 512;
        if ( n < 2 || n > 512 ) n = 512;
        int rc = 1;
        Guard ( [&] { rc = Profile ( argv[2], secs, n ); return true; } );
        return rc;
    }
    if ( argc > 1 ) g_scale = std::atol ( argv[1] );
    if ( g_scale < 1 ) g_scale = 1;

    for ( int i = 0; i < 512; ++i )
    {
        wchar_t b[16];
        std::swprintf ( b, 16, L"f%04d", i );
        g_names.emplace_back ( b );
    }

    perf::PrintBox ( kBench );
    if ( !perf::AllocsCounted ( ) )
        std::printf ( "note: allocs/op not counted on this platform (Msgcore.dll has its "
                      "own operator new)\n" );

    BenchBuild ( );
    BenchWire ( );
    BenchGrowth ( );
    BenchVect ( );
    BenchCApi ( );

    std::printf ( "%s: %s\n", kBench, g_fail ? "FAIL (a correctness check failed)" : "done" );
    return g_fail ? 1 : 0;
}
