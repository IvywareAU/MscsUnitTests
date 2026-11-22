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
// ---------------------------------------------------------------------------
// msgstore_bench -- B8 of p2p_performance.md §3.1a (phase P0b): Msgcore as a
// STORE, a P2PmsgMgr with no transport, at S = 64 KB, 1 MB and 16 MB.
//
// THE STORE UNDER TEST. A root named "Store" holding groups g0000.. of 64
// records r00..r63, each record 8 fields: 4 ints, 2 short strings, a double and
// a 32-byte blob. Two levels keep every sibling list at 64 (records, fields) or
// at the group count (S / ~40 KB: 2, 26, 400), so the build is not M3's flat
// O(n^2) case. Beside them one chain d01.d02..d16 for the depth sweeps. S is
// the ARENA size the populate stops at (P2PmsgMgr::Sizeof, which is also the
// file size Save writes), not a count of payload bytes.
//
// CASES, per S (the plan's B8 row, M8 and M9's evidence):
//   populate         build the store from empty to S          ns per store
//   populate_presized the same into a heap created at its final size; the
//                    difference is the cost of arena regrowth (M8 (b))
//   save             Save(path): scrub + lock + temp + write + flush + rename
//   save_1change     one int written, then Save -- the "whole image every
//                    time" case (§2.4): identical work to save, by design
//   save_defrag      Save(path, true): the deep copy into a 2,024 B heap, of
//                    the append-only store (nothing to reclaim)
//   save_defrag_holes the same after every odd record is deleted, on a fresh
//                    store per rep; the note has the bytes reclaimed
//   load             P2PmsgMgr::Load: read + validating create
//   load_read        the read alone (fopen/fread of the same file), so
//                    load - load_read is the validating create
//   rootpath         RootPath2Object at depth 1 / 4 / 16, and to the LAST
//                    group's last record's last field (depth 4, the store-size
//                    case: the group list is walked)
//   pos2path         P2Pos2Path of the same objects
//   write_trig       one int write + TriggerUPDATE, with 0 triggers armed,
//                    64 armed on other records, and 1 armed on the written one
// The note on each save / load row carries file bytes; save_defrag also the
// file bytes after defragment.
//
// Files go to ./msgstore_bench_tmp (ctest runs in the build tree) and are
// removed at the end. Allocations/op: Linux only, as msgcore_bench.
//
// Usage: msgstore_bench [maxKB]   largest S to run, in KB (default 16384).
// Exit: 0 ran, 1 a correctness check failed. Never a timing verdict.
// ---------------------------------------------------------------------------

#include "stdafx.h"

#if !defined(_WIN32)
#  define PERF_COUNT_ALLOCS
#endif
#include "perf_common.h"

#include "P2Pmsg.h"
#include "P2PmsgMgr.h"
#include "Msgexception.h"

#include <cstdio>
#include <cwchar>
#include <filesystem>
#include <string>
#include <vector>

namespace
{
    const char *kBench = "msgstore_bench";
    bool        g_fail = false;

    template <class F> bool Guard ( F &&f )
    {
        try { return f ( ); }
        catch ( P2Pevent *pEVT )
        {
            if ( pEVT ) pEVT->Cancel ( false );
            return false;
        }
    }

    //  One op per call, timed alone: these ops are milliseconds, not
    //  nanoseconds, so there is no batch. A warm-up call is discarded.
    template <class F>
    perf::OpResult Repeat ( F &&op, long reps )
    {
        perf::OpResult r;
        if ( !Guard ( op ) ) { r.ok = false; return r; }
        std::vector<double> v;
        double             cpu0 = perf::CpuNow ( );
        unsigned long long a0   = perf::Allocs ( );
        for ( long i = 0; i < reps; ++i )
        {
            auto t0 = std::chrono::steady_clock::now ( );
            if ( !Guard ( op ) ) { r.ok = false; return r; }
            v.push_back ( perf::NsSince ( t0 ) );
        }
        r.ns         = perf::Summarise ( std::move ( v ) );
        r.cpuNsPerOp = ( perf::CpuNow ( ) - cpu0 ) * 1e9 / (double)reps;
        if ( perf::AllocsCounted ( ) )
            r.allocsPerOp = (double)( perf::Allocs ( ) - a0 ) / (double)reps;
        return r;
    }

    void Emit ( const char *kase, const std::string &param, const perf::OpResult &r,
                const char *unit, const char *note = nullptr )
    {
        if ( !r.ok )
        {
            std::printf ( "%-22s %-10s FAILED (correctness)\n", kase, param.c_str ( ) );
            g_fail = true;
            return;
        }
        perf::Report ( kBench, kase, param, unit, r.ns, r.cpuNsPerOp, r.allocsPerOp, note );
    }

    // ---- the store --------------------------------------------------------
    const int kRecs   = 64;
    const int kFields = 8;
    const int kDepth  = 16;

    std::wstring NameN ( const wchar_t *p, int i, int w )
    {
        wchar_t b[32];
        std::swprintf ( b, 32, L"%ls%0*d", p, w, i );
        return b;
    }

    //  Builds one group of kRecs records. Every handle is the REFERENCE
    //  DeclareItem returns, never a copy: P3PmsgField's copy constructor is its
    //  operator=, which copies the content into a detached field, so a copied
    //  parent takes the children declared under it out of the store (found the
    //  first run: 79,552 records "fitted" a 77 KB arena). The reference lives
    //  in its parent's cursor and stays valid until that parent declares again,
    //  which is the order the loops below use it in.
    void AddGroup ( P2PmsgMgr &m, int g )
    {
        static unsigned char aBlob [ 32 ];
        P3PmsgField &oGroup = m.DeclareItem ( NameN ( L"g", g, 4 ).c_str ( ), P3PmsgData ( ) );
        for ( int r = 0; r < kRecs; ++r )
        {
            P3PmsgField &oRec = oGroup.DeclareItem ( NameN ( L"r", r, 2 ).c_str ( ), P3PmsgData ( ) );
            oRec.DeclareItem ( L"f0", P3PmsgData ( (int)( g * kRecs + r ) ) );
            oRec.DeclareItem ( L"f1", P3PmsgData ( (int)r ) );
            oRec.DeclareItem ( L"f2", P3PmsgData ( (int)g ) );
            oRec.DeclareItem ( L"f3", P3PmsgData ( (int)-1 ) );
            oRec.DeclareItem ( L"f4", P3PmsgData ( L"name-of-record" ) );
            oRec.DeclareItem ( L"f5", P3PmsgData ( L"a.b.c" ) );
            oRec.DeclareItem ( L"f6", P3PmsgData ( 2.5 ) );
            oRec.DeclareItem ( L"f7", P3PmsgData ( (const void *)aBlob, sizeof aBlob, VBLockData_BLOB08 ) );
        }
    }

    void AddDeepChain ( P2PmsgMgr &m )
    {
        P3PmsgField *o = &m.DeclareItem ( L"d01", P3PmsgData ( ) );
        for ( int d = 2; d <= kDepth; ++d )
            o = &o->DeclareItem ( NameN ( L"d", d, 2 ).c_str ( ), P3PmsgData ( d == kDepth ? 16 : 0 ) );
    }

    //  Fills a fresh store to at least nBytes of arena; answers the groups.
    int Populate ( P2PmsgMgr &m, size_t nBytes )
    {
        m.r_name ( ) = L"Store";
        AddDeepChain ( m );
        int g = 0;
        while ( (size_t)m.Sizeof ( ) < nBytes )
            AddGroup ( m, g++ );
        return g;
    }

    //  The same store by group count, for a heap that starts at its final
    //  size (whose arena is "full" before anything is in it).
    void PopulateN ( P2PmsgMgr &m, int nGroups )
    {
        m.r_name ( ) = L"Store";
        AddDeepChain ( m );
        for ( int g = 0; g < nGroups; ++g )
            AddGroup ( m, g );
    }

    std::wstring DeepPath ( int depth )
    {
        std::wstring s = L".Store";
        for ( int d = 1; d <= depth; ++d )
            s += L"." + NameN ( L"d", d, 2 );
        return s;
    }

    long long FileBytes ( const std::filesystem::path &p )
    {
        std::error_code ec;
        auto n = std::filesystem::file_size ( p, ec );
        return ec ? -1 : (long long)n;
    }

#if defined(_WIN32)
    //  A trigger posts to its HWND; armed with none it posts to this thread's
    //  queue (PostMessage(NULL, ...)), which a real consumer would pump. Drain
    //  it, or the queue fills at 10,000 and the post starts failing -- a
    //  different and cheaper cost than the one being measured.
    void DrainQueue ( )
    {
        MSG msg;
        while ( PeekMessageW ( &msg, NULL, 0, 0, PM_REMOVE ) ) { }
    }
#else
    void DrainQueue ( ) { }
#endif

    // ---- one S ------------------------------------------------------------
    void RunSize ( size_t nKB, const std::filesystem::path &dir )
    {
        const std::string sz   = nKB >= 1024 ? std::to_string ( nKB / 1024 ) + "MB"
                                             : std::to_string ( nKB ) + "KB";
        const long        reps = nKB <= 64 ? 15 : nKB <= 1024 ? 7 : 3;
        const std::filesystem::path file = dir / ( "store_" + sz + ".p2p" );
        const std::wstring          wfile = file.wstring ( );
        char note [ 128 ];

        // populate
        int nGroups = 0;
        VBLsize nArena = 0;
        auto rp = Repeat ( [&] {
            P2PmsgMgr m;
            nGroups = Populate ( m, nKB * 1024 );
            nArena  = m.Sizeof ( );
            return nGroups > 0;
        }, reps );
        std::snprintf ( note, sizeof note, "arena=%llu B, %d groups, %d records",
                        (unsigned long long)nArena, nGroups, nGroups * kRecs );
        Emit ( "populate", sz, rp, "ns/store", note );

        // the same build into a heap created at its final size: the difference
        // is what arena regrowth costs a store (M8 (b)'s ceiling)
        auto rpp = Repeat ( [&] {
            P2PmsgMgr m ( VBLock_Addr32, (UINT)( nArena + 65536 ), 0 );
            PopulateN ( m, nGroups );
            const VBLsize n0 = nArena + 65536;           // never regrew (a step is +20%)
            return m.Sizeof ( ) < n0 + n0 / 10;
        }, reps );
        Emit ( "populate_presized", sz, rpp, "ns/store" );

        // One store for every case below
        P2PmsgMgr m;
        Populate ( m, nKB * 1024 );
        const std::wstring lastField = L".Store." + NameN ( L"g", nGroups - 1, 4 )
                                     + L"." + NameN ( L"r", kRecs - 1, 2 ) + L".f3";

        // save, save after one change
        auto rs = Repeat ( [&] { return m.Save ( wfile.c_str ( ) ) ? true : false; }, reps );
        std::snprintf ( note, sizeof note, "file=%lld B", FileBytes ( file ) );
        Emit ( "save", sz, rs, "ns/save", note );

        int nWrite = 0;
        auto rs1 = Repeat ( [&] {
            P3PmsgField f ( m.RootPath2Object ( lastField.c_str ( ) ) );
            f.r_data ( ) = P3PmsgData ( ++nWrite );
            return m.Save ( wfile.c_str ( ) ) ? true : false;
        }, reps );
        Emit ( "save_1change", sz, rs1, "ns/save", note );

        // load, and the read alone
        auto rl = Repeat ( [&] {
            P2PmsgMgr l;
            if ( !l.Load ( wfile.c_str ( ) ) ) return false;
            return P3PmsgField ( l.RootPath2Object ( lastField.c_str ( ) ) ).c_int ( ) == nWrite;
        }, reps );
        Emit ( "load", sz, rl, "ns/load", note );

        std::vector<char> buf ( (size_t)FileBytes ( file ) + 1 );
        auto rr = Repeat ( [&] {
            FILE *fp = std::fopen ( file.string ( ).c_str ( ), "rb" );
            if ( !fp ) return false;
            size_t n = std::fread ( buf.data ( ), 1, buf.size ( ), fp );
            std::fclose ( fp );
            return (long long)n == FileBytes ( file );
        }, reps );
        Emit ( "load_read", sz, rr, "ns/load", note );

        // lookups: depth 1 / 4 / 16, and the last record (store-size case)
        const long kLook = 2000;
        struct Target { const char *label; std::wstring path; };
        const Target kTargets[] = {
            { "depth1",  DeepPath ( 1 ) },
            { "depth4",  DeepPath ( 4 ) },
            { "depth16", DeepPath ( 16 ) },
            { "lastrec", lastField },
        };
        for ( const Target &t : kTargets )
        {
            auto r = perf::TimeOp ( [&] {
                return Guard ( [&] { return !m.RootPath2Object ( t.path.c_str ( ) ).IsEmpty ( ); } );
            }, kLook / ( nKB >= 1024 ? 10 : 1 ), 7 );
            Emit ( "rootpath", sz + "/" + t.label, r, "ns/op" );

            P2Pos pos = 0;
            Guard ( [&] { pos = m.RootPath2Object ( t.path.c_str ( ) ).GetP2Pos ( ); return true; } );
            auto rq = perf::TimeOp ( [&] {
                return Guard ( [&] { return !m.P2Pos2Path ( pos ).IsEmpty ( ); } );
            }, kLook, 7 );
            Emit ( "pos2path", sz + "/" + t.label, rq, "ns/op" );
        }

        // one write with 0 / 64-elsewhere / 1-on-it triggers armed
        {
            P3PmsgField fTarget ( m.RootPath2Object ( lastField.c_str ( ) ) );
            auto write = [&] {
                return Guard ( [&] {
                    fTarget.r_data ( ) = P3PmsgData ( ++nWrite );
                    m.TriggerUPDATE ( fTarget );
                    DrainQueue ( );
                    return true;
                } );
            };
            auto r0 = perf::TimeOp ( write, 2000, 7 );
            Emit ( "write_trig", sz + "/none", r0, "ns/op" );

            for ( int r = 0; r < 64; ++r )
            {
                std::wstring p = L".Store.g0000." + NameN ( L"r", r, 2 ) + L".f0";
                m.CreateTrigger ( TRIGGER_UPDATE, NULL, m.RootPath2Object ( p.c_str ( ) ).GetP2Pos ( ) );
            }
            auto r64 = perf::TimeOp ( write, 2000, 7 );
            Emit ( "write_trig", sz + "/64else", r64, "ns/op" );

            m.CreateTrigger ( TRIGGER_UPDATE, NULL, fTarget.GetP2Pos ( ) );
            auto r1 = perf::TimeOp ( write, 2000, 7 );
            Emit ( "write_trig", sz + "/1on", r1, "ns/op" );
            m.DropTriggers ( TRIGGER_ALL, NULL );
            DrainQueue ( );
        }

        // defragment last: it replaces the store's heap
        long long nBefore = FileBytes ( file );
        auto rd = Repeat ( [&] { return m.Save ( wfile.c_str ( ), true ) ? true : false; }, reps );
        std::snprintf ( note, sizeof note, "file=%lld B before, %lld B after",
                        nBefore, FileBytes ( file ) );
        Emit ( "save_defrag", sz, rd, "ns/save", note );
        if ( P3PmsgField ( m.RootPath2Object ( lastField.c_str ( ) ) ).c_int ( ) != nWrite )
        {
            std::printf ( "save_defrag %s FAILED (store did not read back)\n", sz.c_str ( ) );
            g_fail = true;
        }

        // defragment a store that HAS holes: every odd record deleted, half the
        // records gone from every group. What the save above could not show,
        // since an append-only store has nothing to reclaim.
        //  Each timed defragment gets its own freshly holed store, built
        //  outside the timing: a second defragment of the same store would
        //  measure a compacted one.
        {
            const std::wstring keep = L".Store." + NameN ( L"g", nGroups - 1, 4 )
                                    + L"." + NameN ( L"r", kRecs - 2, 2 ) + L".f0";
            const int nKeep = ( nGroups - 1 ) * kRecs + kRecs - 2;
            long long nHoley = -1, nAfter = -1;
            std::vector<double> v;
            double cpu = 0;
            bool ok = true;
            for ( long rep = 0; rep < reps && ok; ++rep )
            {
                P2PmsgMgr f;
                ok = Guard ( [&] {
                    Populate ( f, nKB * 1024 );
                    for ( int g = 0; g < nGroups; ++g )
                    {
                        P3PmsgField oGroup ( f.RootPath2Object ( ( L".Store." + NameN ( L"g", g, 4 ) ).c_str ( ) ) );
                        for ( int r = 1; r < kRecs; r += 2 )
                            oGroup.Delete ( NameN ( L"r", r, 2 ).c_str ( ) );
                    }
                    return f.Save ( wfile.c_str ( ) ) ? true : false;
                } );
                nHoley = FileBytes ( file );
                double c0 = perf::CpuNow ( );
                auto   t0 = std::chrono::steady_clock::now ( );
                ok = ok && Guard ( [&] { return f.Save ( wfile.c_str ( ), true ) ? true : false; } );
                v.push_back ( perf::NsSince ( t0 ) );
                cpu += perf::CpuNow ( ) - c0;
                nAfter = FileBytes ( file );
                ok = ok && Guard ( [&] {
                    return P3PmsgField ( f.RootPath2Object ( keep.c_str ( ) ) ).c_int ( ) == nKeep;
                } );
            }
            perf::OpResult rh;
            rh.ok         = ok;
            rh.ns         = perf::Summarise ( std::move ( v ) );
            rh.cpuNsPerOp = cpu * 1e9 / (double)reps;
            std::snprintf ( note, sizeof note, "half the records deleted: file=%lld B before, %lld B after",
                            nHoley, nAfter );
            Emit ( "save_defrag_holes", sz, rh, "ns/save", note );
        }
    }
}

int main ( int argc, char *argv[] )
{
    long maxKB = argc > 1 ? std::atol ( argv[1] ) : 16384;

    perf::PrintBox ( kBench );
    if ( !perf::AllocsCounted ( ) )
        std::printf ( "note: allocs/op not counted on this platform (Msgcore.dll has its "
                      "own operator new)\n" );

    std::filesystem::path dir = std::filesystem::current_path ( ) / "msgstore_bench_tmp";
    std::error_code ec;
    std::filesystem::create_directories ( dir, ec );

    for ( size_t kb : { (size_t)64, (size_t)1024, (size_t)16384 } )
        if ( (long)kb <= maxKB )
            RunSize ( kb, dir );

    std::filesystem::remove_all ( dir, ec );
    std::printf ( "%s: %s\n", kBench, g_fail ? "FAIL (a correctness check failed)" : "done" );
    return g_fail ? 1 : 0;
}
