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
// p2p_fuzzframe.cpp — FUZZ HARNESS for the Targetcore FRAMING PATH.
//
//   Ahtung_Disaster.md, Part 5 Track B item 5 / "Order after that" item 5:
//   "Fuzz the framing path (RecvP2PeerMsg stages 1-3) — the C1-class bug lived
//    exactly there, and one lower-bound check closing four findings is a sign
//    the parser deserves systematic coverage rather than another point fix."
//
//   The four findings that one check closed (SECURITY_REVIEW C1/C2 and the two
//   sizing defects behind them) all came in through the SAME eight bytes: the
//   wire length field in VBListIOmage::oSync. Those eight bytes are the first
//   thing this library reads from an unauthenticated stranger, and everything
//   downstream — an allocation size, a memcpy length, a block walk — is derived
//   from them. This harness attacks them systematically.
//
// ***************************************************************************
// *** THE ASSERT POPULATION IS CLOSED, AND THE BUDGET IS NOW ZERO.         ***
// ***                                                                      ***
// *** 2026-08-21. ctest registers this with --strict-assert: ONE assert is ***
// *** a failure. It was a tracked baseline of 89,901 on Windows and 1,044  ***
// *** on Linux, and before that a permanent red of 7,082.                  ***
// ***                                                                      ***
// *** WHAT CLOSED IT WAS NOT SILENCING. Two changes, and the second is the ***
// *** one that matters:                                                    ***
// ***                                                                      ***
// ***  1. P2Peerio.cpp stage 4 now passes the RECEIVED LENGTH into the     ***
// ***     P2PeerMsg constructor, so the image takes                        ***
// ***     P2PmsgHeap_CreateIOMAGE(pIOmage,nBufferLen) instead of the       ***
// ***     pointer-only overload. The pointer-only one ends in              ***
// ***         ASSERT(P2PmsgHeap_AssertValidIOMAGE(pHandle));               ***
// ***         ASSERT(P2PmsgHeap_AssertVBlocksIOMAGE(pHandle));             ***
// ***     - both block walks INSIDE the assertion - so a Release build did ***
// ***     not run a reduced check, it ran none, and adopted a forged block ***
// ***     chain unwalked. The length-validated one walks the image for     ***
// ***     real in every build and REFUSES on the answer.                   ***
// ***                                                                      ***
// ***  2. The walks now distinguish the two jobs they do. Over a heap this ***
// ***     process built, a violated invariant is a bug here and ASSERT is  ***
// ***     right. Over an image a stranger sent it is the ORDINARY case and ***
// ***     the answer is to refuse. MsgVBHeap's untrusted gate says which,  ***
// ***     and inside one the walks refuse quietly, stop at the first bad   ***
// ***     block, and do not write the image's root back into agreement     ***
// ***     with itself on the way past.                                     ***
// ***                                                                      ***
// *** THE NUMBER THAT SHOWS IT IS NOT SILENCING: message went 550 -> 246   ***
// *** and refused 1,817 -> 2,140 on the same 3,618 frames. 304 forged      ***
// *** frames that a RELEASE build used to turn into P2PeerMsg objects are  ***
// *** now refused. And Debug and Release now agree to the frame - 246 /    ***
// *** 2,140 / 1,174 in both - where before the two builds differed by two  ***
// *** frames because the Debug-only fixups WROTE to the image they were    ***
// *** judging.                                                             ***
// ***                                                                      ***
// *** ProductionPlan.md Stage 1 step 4.                                    ***
// ***                                                                      ***
// *** The two defects below, found on this harness's first run, ARE fixed: ***
// ***   stalled=0 is the non-terminating walk bounded, and the documented  ***
// ***   repro `--replay 9 1` now refuses cleanly with asserts=0.           ***
// ***************************************************************************
//
//   Both were in the IOMAGE validators in Msgcore/MsgVBHeap.cpp, both are
//   reached from the PRE-AUTH framing path, and both take their step sizes and
//   link addresses straight from wire bytes:
//
//   (1) NON-TERMINATING BLOCK WALK.  P2PmsgHeap_AssertVBlocksIOMAGE walks the
//       image block by block, advancing by a size read from the block header:
//           aVBLock += VBHeap_Sizenn(pVBLock);        // MsgVBHeap.cpp:1591
//       A forged header declaring size 0 never advances, so
//           while ( aVBLock < pHandle->nSizeofAlloc ) // :1572
//       never ends. Observed directly: six assertion sites each trip EXACTLY
//       the same number of times (3227 and climbing) — one loop, going round.
//
//   (2) ACCESS VIOLATION.  The free-list walk in P2PmsgHeap_AssertValidIOMAGE
//       converts a wire-supplied link and dereferences it:
//           VBHeap *pVBLock = VBList2PhysVBHeap(hP2PmsgHeap,aVBLockFree);
//           ASSERT((pVBLock->oHdr.uVBLockDefs&...)   // :1322-1323  <-- FAULTS
//       before any range check. P2PmsgHeap_AssertValidFree DOES range-check
//       (:1367), but only after its caller has already dereferenced.
//       Reproduce:  p2p_fuzzframe 0x5EEDF00D --replay 9 1
//
//   IMPORTANT QUALIFICATION, so nobody over-reads this: both validators are
//   called from P2PmsgHeap_CreateIOMAGE inside ASSERT() (MsgVBHeap.cpp:2415-
//   2416), and ASSERT compiles out of a Release build. So a Release build does
//   not take these two paths from here — it instead accepts a forged block
//   chain WITHOUT walking it at all, and what happens downstream of that has
//   NOT been established. Do not read "Debug-only" as "harmless"; read it as
//   "the only code that inspects the chain is absent in production".
//   MsgVBHeap.cpp:2373-2377 already records this validator family as unfixed.
//
//   Fixing that is Msgcore surgery on the message heap and is deliberately NOT
//   attempted from this harness. Per the house rule used by the p2p_auth*
//   tests: no WILL_FAIL. A red result here is the finding, not a broken test.
//
// ---------------------------------------------------------------------------
// WHAT IS UNDER TEST — P2Peerio::RecvP2PeerMsg, by stage
//
//   Stage 0  P2Peerio.cpp:380-391   dual-buffer init (pUserDB1 = 13 bytes)
//   Stage 1  P2Peerio.cpp:396-412   fetch the 8-byte oSync header
//   Stage 2  P2Peerio.cpp:417-458   VALIDATE it, size the body, allocate:
//              :420   complement gate   (uiSync1 + uiSync2) == ~0
//              :423   UPPER bound       nSizeof > m_dwMaxRecvSize (32768)  -> refuse
//              :433   LOWER bound       nSizeof < sizeof(VBListIOmage) (9) -> refuse
//                     *** THIS IS THE C1 FIX. Cases c1_* below are its pin. ***
//              :439   pUserDB2 = new char[nSizeof+4]; memcpy of a FIXED 8 bytes
//              :444-457 re-synchronisation: memmove slide-by-one + goto STAGE1
//                     (the LOW finding; memcpy -> memmove, P2Peerio.cpp:454)
//   Stage 3  P2Peerio.cpp:460-486   fetch the body:
//              :466   overrun guard     dwBytes > dwBytesMax -> refuse
//              :475   Recv into &pUserDB2[dwBytes], nSizeof-dwBytes
//   Stage 4  P2Peerio.cpp:488-536   decrypt passthrough + new P2PeerMsg(image),
//                     i.e. the VBHeap block walk in Msgcore/MsgVBHeap.cpp.
//                     Driven here because stages 1-3 exist to hand it a buffer,
//                     and it is where a length that survived stage 2 gets USED.
//
// ---------------------------------------------------------------------------
// HOW IT RUNS WITH NO SOCKET AND NO CONNECTION
//
//   P2Peerio::Recv is NOT virtual (P2Peerio.h:165), so it cannot be overridden
//   to feed the parser from a byte string — that is what would otherwise force
//   the multi-read cases onto a real connection. There is, however, an existing
//   seam that does the same job without touching shipping source:
//
//       P2Peerio::Recv (P2Peerio.cpp:575-579) tests pOVERLAPPEDrecv->bQueued
//       FIRST, before it touches m_pCon or ReadFile, and THROWS if it is set.
//
//   So with bQueued pre-set, every Recv the parser issues becomes a pure,
//   side-effect-free "I would read N bytes into P now" marker: no socket, no
//   m_pCon, no ReadFile, no IOCP. The harness catches that throw, performs the
//   copy ITSELF — into the exact buffer and at the exact offset the parser
//   chose, and never more bytes than it asked for — bumps dwBytes exactly as
//   P2PeerCon.cpp:398 does on a completion, and calls back in. That is the IOCP
//   completion loop, faithfully, minus the OS.
//
//   Deliver() re-derives the request the same way the parser does:
//       stage 1  &pUserDB1[dwBytes], sizeof(oSync)-dwBytes   (P2Peerio.cpp:400-404)
//       stage 3  &pUserDB2[dwBytes], nSizeof-dwBytes         (P2Peerio.cpp:473-477)
//   with nSizeof read from pUserDB1, because that is where stage 3 reads it
//   (P2Peerio.cpp:461). Delivering a short count models a split TCP read; the
//   parser accumulating dwBytes across turns models a coalesced stream.
//
//   NOTHING IS STUBBED. The parser under test is the shipping one, unmodified.
//   The positive control (case 0) is what proves the mechanism is real: it
//   needs at least two of these turns to complete, and it must produce exactly
//   one P2PeerMsg. If the seam were misclassifying reads as refusals, case 0
//   would go red before anything else did.
//
// ---------------------------------------------------------------------------
// PASS / FAIL — the distinction this harness exists to make
//
//   A CLEAN REFUSAL IS A PASS. The library refuses by throwing a P2Pevent, and
//   its caller drops the connection. That is the designed answer to a hostile
//   frame and it is counted as success, however many thousand times it happens.
//
//   A FAILURE is any of:
//     * a crash / access violation / abort   -> the process dies; the crash
//       handlers below print the exact case, iteration and seed first
//     * an exception that is NOT a P2Pevent escaping the parser (OUT_ESCAPED)
//     * a seed-corpus expectation violated — most importantly a frame that is
//       SHORTER than it claims becoming a P2PeerMsg anyway
//
//   A HANG is a failure too, and a WATCHDOG THREAD catches it. The drive loop
//   below is provably finite (every turn either terminates or consumes at least
//   one wire byte, so it cannot spin), which means a hang can only be INSIDE
//   the parser on this very thread — so it is watched from another one. The
//   watchdog samples a progress counter bumped once per input and, after
//   kHangSeconds of no movement, prints the offending case/iteration/seed and
//   kills the process. Leave the ctest TIMEOUT in place as the backstop, but
//   the watchdog is what turns "Timeout" into a named input.
//
//   THIS IS NOT HYPOTHETICAL - the hang above is a defect this harness found.
//
//   ASSERT trips are counted separately from findings and gated on a BUDGET:
//   --assert-baseline <N> passes at or under N and fails over it. The budget is
//   now ZERO (--strict-assert), so any trip at all is a failure; every trip is
//   printed with its case + iteration + seed. Read one as a REGRESSION rather
//   than as a known population: an assert reached from here means wire data has
//   found its way to a check meant for this library's own heaps, which is what
//   the untrusted gate exists to stop. See the banner at the top.
//
// ---------------------------------------------------------------------------
// DETERMINISM — non-negotiable here
//
//   Sessions 20-22 of Ahtung_Disaster_progress.md were spent on a failure that
//   would not reproduce. A fuzz harness that cannot replay its own failure is
//   worse than no fuzz harness, so:
//     * the seed is a fixed constant or argv[1] — NEVER the clock
//     * it is printed on every run, pass or fail
//     * each iteration's RNG is derived by splitmix64 from (seed, case, iter)
//       alone, so iterations are independent and any one of them replays
//       exactly, on either platform:  p2p_fuzzframe <seed> --replay <case> <iter>
//     * the RNG is written out here rather than taken from <random>, whose
//       distributions are implementation-defined and would not agree between
//       MSVC and libstdc++
//
// USAGE
//   p2p_fuzzframe [seed] [itersPerCase] [--replay <case> <iter>]
//                 [--assert-baseline <N>] [--strict-assert] [--verbose]
//
//   --assert-baseline <N>  gate the assert tally: <= N green, > N a regression.
//                          Omit it and the tally is reported without gating,
//                          which is what a developer running this wants.
//   --strict-assert        the same thing with N = 0.
//
//   Verdict = process EXIT CODE:
//     0  PASS   every hostile frame was refused, or parsed without incident,
//               and the assert tally is within its budget
//     1  FAIL   see the FINDING lines, or the assert budget was exceeded
//     2  SETUP  startup / frame-construction failure (test inconclusive)
//
// Build (Linux):
//   g++ -std=c++23 -fpermissive -D_UNICODE -DUNICODE -I. -I../Msgcore \
//       -I../Targetcore -I../Msgcore/Platform -I../Msgcore/Platform/win-compat p2p_fuzzframe.cpp \
//       -L../build/Targetcore -ltargetcore -L../build/Msgcore -lmsgcore -luring \
//       -Wl,-rpath,../build/Targetcore -Wl,-rpath,../build/Msgcore -o p2p_fuzzframe

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2Peerio.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"

#include "fuzz_corpus.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>

#ifdef _WIN32
#  include <crtdbg.h>          // _CrtSetReportHook — the headless assert trap
#else
#  include <csignal>
#  include <unistd.h>
#  include <pthread.h>         // the hang watchdog runs on its own thread
#endif

// ===========================================================================
//  Fixed parameters
// ===========================================================================

// The registered ctest run uses this seed unless argv overrides it, so a CI
// failure is reproducible from the printed line alone.
static const unsigned kDefaultSeed    = 0x5EEDF00Du;
static const int      kDefaultIters   = 200;      // per case; 18 cases -> 3600 runs

// The wire buffer.  RAISED from 16384 for ProductionPlan.md Stage 6 step 16,
// which names the gap in one clause: "~2 KB frames, and nothing fuzzes AT THE
// SIZE LIMITS".  That was true and it mattered - the 30 KB defect of session 33
// was found by LOOKING, not by fuzzing, because no input this harness produced
// ever came near m_dwMaxRecvSize (32768).  A parser whose accumulation
// arithmetic is only ever exercised over a couple of hundred bytes has not been
// asked the question a 16-bit truncation or an off-by-one at the ceiling
// answers.
//
// 66560 = room for TWO frames at the ceiling (2 x 32768 = 65536) plus slack,
// because the coalesced case needs both in one stream.  Wire is passed by value
// in the drive loop, so this is also a 65 KB copy per iteration; measured
// against 3600 iterations that is a fraction of a second, and the alternative -
// a separate buffer for the big cases - would give the mutator two shapes to
// know about instead of one.
//
// IT IS SIZED TO WHAT IS NEEDED AND NOT ROUNDED UP, and that is not tidiness.
// The first attempt used 98304 and the harness died on its own startup with
// STATUS_STACK_OVERFLOW (0xC00000FD) before the first input: Wire is a
// by-value struct, and main holds two of them while BuildCorpus holds a third
// plus a by-value temporary from HeaderOnly - four copies live at once against
// a 1 MB default stack, with MSVC Debug's frame padding on top.  The crash
// filter caught it and reported "case 0 iteration 0, wire 0 bytes", which is
// what a fuzzer that has not started yet looks like when it falls over.  Worth
// recording rather than quietly halving: the number that makes this file work
// is bounded ABOVE by the stack, not just below by the frame size.
static const unsigned kMaxWire        = 66560u;

// Turn budget per drive. This is a RUNTIME bound, not a correctness one — the
// drive loop cannot spin (see the banner). It matters because the re-sync path
// consumes exactly ONE byte per turn and raises a P2Pevent each time, so a
// mutant that breaks the complement on a 2 KB frame would otherwise cost 2000
// event constructions, and roughly a quarter of all mutants are that mutant.
// 96 turns still slides the window 88 times, which exercises the memmove path
// as thoroughly as 2000 would. Raise it with --iters-style soak runs if the
// deep tail is ever wanted; the registered test must stay short.
static const unsigned kMaxTurns       = 96u;

static const P2PaddrSTR kSrcAddr = L"Fuzz.Client";
static const P2PaddrSTR kDstAddr = L"Fuzz.Server";

// ===========================================================================
//  Small utilities (no std:: containers: the MSCS headers #define new DEBUG_NEW,
//  so template-heavy standard headers pulled in after them are a hazard here)
// ===========================================================================

struct Wire
{
    unsigned char b[kMaxWire];
    unsigned      n;
};

static void Log(const char* msg)
{
    std::printf("[fuzz] %s\n", msg);
    std::fflush(stdout);
}

static unsigned RdU32(const unsigned char* p)
{
    unsigned v = 0; std::memcpy(&v, p, 4); return v;
}
static void WrU32(unsigned char* p, unsigned v)
{
    std::memcpy(p, &v, 4);
}

// sizeof(oSync) == 8 and sizeof(VBListIOmage) == 9 (packed, P2PmsgBSTR.h:54-69).
// Taken from the types rather than written as literals, because stage 2's lower
// bound is expressed in exactly these terms (P2Peerio.cpp:433).
static unsigned SyncSizeof()
{
    static const VBListIOmage s_oProbe = { { 0, 0 }, 0 };
    return (unsigned)sizeof(s_oProbe.oSync);
}
static unsigned HdrSizeof()
{
    return (unsigned)sizeof(VBListIOmage);
}

// The declared frame size, read the way stage 2 and stage 3 read it
// (P2Peerio.cpp:422 / :461) — low 24 bits of uiSync1, no validation.
static unsigned DeclaredOf(const unsigned char* pHdr)
{
    return RdU32(pHdr) & 0x00FFFFFFu;
}

static void StampSync(Wire& w, unsigned nSizeof, unsigned char uAddrType)
{
    if (w.n < 8) return;
    unsigned s1 = VBLock_SyncMake(nSizeof, uAddrType);
    WrU32(w.b + 0, s1);
    WrU32(w.b + 4, ~s1);
}

// The complement is a CHECKSUM, not a signature: MsgVBHeap.cpp:2373-2377 says so
// in as many words ("trivially forgeable"). Repairing it is what an attacker
// does, and what carries a mutant past stage 2's gate into the code that matters.
static void RepairComplement(Wire& w)
{
    if (w.n >= 8) WrU32(w.b + 4, ~RdU32(w.b));
}

// ---------------------------------------------------------------------------
//  Deterministic RNG: splitmix64 finaliser to derive a per-iteration state,
//  xorshift64* to draw from it. Reproducible bit-for-bit on both toolchains.
// ---------------------------------------------------------------------------
struct Rng
{
    unsigned long long s;
    void Seed(unsigned long long x) { s = x ? x : 0x9E3779B97F4A7C15ull; }
    unsigned long long Next()
    {
        s ^= s >> 12; s ^= s << 25; s ^= s >> 27;
        return s * 2685821657736338717ull;
    }
    unsigned U32()            { return (unsigned)(Next() >> 32); }
    unsigned Below(unsigned n){ return n ? (U32() % n) : 0u; }
};

static unsigned long long SplitMix(unsigned long long x)
{
    x += 0x9E3779B97F4A7C15ull;
    x  = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
    x  = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
    return x ^ (x >> 31);
}

// (seed, case, iteration) -> state. Iterations are INDEPENDENT: replaying one
// does not require replaying the ones before it.
static unsigned long long IterState(unsigned nSeed, int nCase, int nIter)
{
    return SplitMix( ((unsigned long long)nSeed << 32)
                   ^ ((unsigned long long)(unsigned)nCase * 0x100000001B3ull)
                   ^ ((unsigned long long)(unsigned)(nIter + 1) * 0x9E3779B1ull) );
}

// ===========================================================================
//  The cursor — what the crash handlers print
//  A hard death (SIGSEGV / abort / access violation) is a legitimate result of
//  this test, so the ONE thing that must survive it is the identity of the
//  input that caused it.
// ===========================================================================
struct Cursor
{
    const char   *pszCase;
    int           nCase;
    int           nIter;          // -1 == the unmutated seed vector
    unsigned      nSeed;
    unsigned      nWire;
    unsigned char aHead[48];
    unsigned      nHead;
};
static Cursor g_cur;

//  THE WHOLE INPUT, not just the 48-byte head above.  ProductionPlan.md Stage 6
//  step 16's exit criterion is that "a new finding arrives as a REPRODUCER
//  rather than as a report", and 48 bytes of hex in a log is a report.  It is a
//  global because the crash filter and the watchdog both need it and neither
//  runs on a stack that still carries it - an input that KILLS the process must
//  still leave its bytes behind, or the worst findings are the ones that leave
//  the least evidence.
static Wire g_oCurWire;
static char g_szReproDir[512] = { 0 };

//  Write the current input out and say where it went.  Silent when no repro
//  directory was given, which is what a developer running this by hand gets.
static void EmitRepro ( const char *pszWhy )
{
    if ( !g_szReproDir[0] || g_oCurWire.n == 0 ) return;
    char szTag[96];
    std::snprintf ( szTag, sizeof(szTag), "%s-%s",
                    g_cur.pszCase ? g_cur.pszCase : "case", pszWhy );
    char szPath[1024];
    if ( FuzzWriteRepro ( g_szReproDir, szTag, g_oCurWire.b, g_oCurWire.n,
                          szPath, sizeof(szPath) ) )
    {
        std::fflush ( stdout );
        std::fprintf ( stderr, "[fuzz] REPRODUCER: %s (%u bytes)\n",
                       szPath, g_oCurWire.n );
        std::fprintf ( stderr, "[fuzz] replay it with:  --corpus <the directory "
                               "holding it>\n" );
        std::fprintf ( stderr, "[fuzz] promote it with: copy it into "
                               "MscsUnitTests/fuzz/corpus/ and commit\n" );
        std::fflush ( stderr );
    }
    else
        std::fprintf ( stderr, "[fuzz] could NOT write a reproducer into '%s' - "
                               "the finding above is a report, not a repro\n",
                       g_szReproDir );
}

static void DumpCursor(FILE* fp)
{
    std::fprintf(fp,
        "\n"
        "  *** OFFENDING INPUT ***\n"
        "      case      : %d (%s)\n"
        "      iteration : %d   (-1 = unmutated seed vector)\n"
        "      seed      : 0x%08X\n"
        "      wire      : %u bytes\n"
        "      replay    : p2p_fuzzframe 0x%08X --replay %d %d\n"
        "      head      : ",
        g_cur.nCase, g_cur.pszCase ? g_cur.pszCase : "?",
        g_cur.nIter, g_cur.nSeed, g_cur.nWire,
        g_cur.nSeed, g_cur.nCase, g_cur.nIter);
    for (unsigned i = 0; i < g_cur.nHead; ++i)
        std::fprintf(fp, "%02X ", (unsigned)g_cur.aHead[i]);
    std::fprintf(fp, "\n\n");
    std::fflush(fp);
}

// Bumped once per input. The watchdog below watches ONLY this: it is the
// difference between "the parser is working" and "the parser is not coming
// back", and it needs no cooperation from inside the parser to say so.
static volatile unsigned long g_nProgress      = 0;
static int                    g_nAssertsThisIn = 0;

static void SetCursor(const char* pszCase, int nCase, int nIter,
                      unsigned nSeed, const Wire& w)
{
    g_cur.pszCase = pszCase;
    g_cur.nCase   = nCase;
    g_cur.nIter   = nIter;
    g_cur.nSeed   = nSeed;
    g_cur.nWire   = w.n;
    g_oCurWire    = w;                 // the reproducer's payload - see EmitRepro
    g_cur.nHead   = w.n < sizeof(g_cur.aHead) ? w.n : (unsigned)sizeof(g_cur.aHead);
    std::memcpy(g_cur.aHead, w.b, g_cur.nHead);
    g_nAssertsThisIn = 0;
    ++g_nProgress;
}

// ---------------------------------------------------------------------------
//  Crash and assert traps
// ---------------------------------------------------------------------------
static int  g_nAsserts     = 0;

//  The assert BUDGET (ProductionPlan.md Stage 1 step 4). NOW ZERO.
//
//  The three states this has been in, in order, because the middle one is the
//  interesting one and deleting it would leave the gate looking as though it
//  had always pointed here:
//
//    --strict-assert, PERMANENTLY RED. 7,082 on Windows. A suite with a
//    standing red trains people to stop reading red, and the gate could not
//    answer the only useful question about a number that size -- "same known
//    population, or did someone just make it worse?"
//
//    A TRACKED BASELINE (2026-08-18 to 2026-08-21). 7,082 then 89,901 on
//    Windows, 796 then 1,044 on Linux; at or under is green, over is a
//    regression. It answered that question and nothing more, and it said so on
//    every green pass, because the finding was open and a tick that reads as a
//    fix is worse than a red.
//
//    ZERO (2026-08-21). The finding is closed -- see the banner at the top of
//    this file for what closed it -- so the baseline is 0 and the mechanism is
//    unchanged: at or under is green, over is a regression. The gate did not
//    get weaker when the number got smaller; it got as strong as it can be.
//
//  The per-platform machinery stays. Both baselines are 0 now, but they are
//  still two numbers set separately in CMakeLists.txt, because the platforms do
//  not reach the same depth (glibc's assert aborts, so Linux abandons the input
//  where Windows continues past the violated invariant -- see the POSIX trap
//  below and ProductionPlan.md Stage 2 step 7), and the day one of them moves
//  the other must not move with it by accident.
//
//  -1 means no baseline was given: the count is reported and does not gate,
//  which is the right default for a developer running the binary by hand.
static int  g_nAssertBase  = -1;
// Inputs abandoned at an assert (POSIX only - see the trap below). Counted
// separately from g_nAsserts because one input can trip several asserts but is
// abandoned exactly once.
static int  g_nAbandoned   = 0;

// How many ASSERT blocks to print per input before suppressing (see the hook).
static const int kMaxAssertPrints = 3;

// Seconds one input may spend inside the parser before it is called a hang.
// A normal input takes single-digit milliseconds, so this is three orders of
// magnitude of headroom - it fires only for "not coming back", never for slow.
static const unsigned kHangSeconds = 10;

#ifdef _WIN32
// Fold a debug ASSERT into a counted diagnostic and CONTINUE (TRUE + retVal 0 =
// "handled, do not break"). Continuing is deliberate: past a violated invariant
// is exactly where the Release build goes, so if the next step is a real
// overflow this harness gets to see it. Without the hook a single ASSERT pops a
// modal dialog on a headless ctest run and the test "hangs" (session 22).
static int __cdecl AssertReportHook(int nReportType, char* szMsg, int* pnRet)
{
    if (nReportType == _CRT_ASSERT)
    {
        ++g_nAsserts;
        ++g_nAssertsThisIn;
        // Cap the PRINTING, not the counting. A validator that walks a forged
        // block chain can trip the same assert unboundedly (MsgVBHeap.cpp:1591
        // advances by a wire-supplied size, and a declared 0 never advances at
        // all), which produced a 9 MB stderr before this cap existed. The full
        // block is worth having for the first few; after that it is the same
        // input repeated and only the count carries information.
        if (g_nAssertsThisIn <= kMaxAssertPrints)
        {
            std::fflush(stdout);
            std::fprintf(stderr, "[fuzz] ASSERT: %s", szMsg ? szMsg : "(no message)");
            DumpCursor(stderr);
        }
        else if (g_nAssertsThisIn == kMaxAssertPrints + 1)
        {
            std::fprintf(stderr, "[fuzz] ... further ASSERTs for THIS input "
                                 "suppressed (still counted)\n");
            std::fflush(stderr);
        }
        if (pnRet) *pnRet = 0;      // do not launch the debugger
        return TRUE;                // handled -> execution continues
    }
    return FALSE;
}

static LONG WINAPI CrashFilter(EXCEPTION_POINTERS* pEP)
{
    std::fflush(stdout);
    std::fprintf(stderr,
        "\n[fuzz] *** CRASH: unhandled exception 0x%08X at %p ***\n",
        (unsigned)pEP->ExceptionRecord->ExceptionCode,
        (void*)pEP->ExceptionRecord->ExceptionAddress);
    DumpCursor(stderr);
    std::fprintf(stderr,
        "RESULT: FAIL - the framing path crashed on the input above.\n");
    std::fflush(stderr);
    EmitRepro("crash");
    return EXCEPTION_EXECUTE_HANDLER;   // -> process exits, ctest sees failure
}
#else
// ---------------------------------------------------------------------------
//  The POSIX assert trap - why this exists, and what it costs
//
//  Until this landed the harness had NO assert trap off Windows: the hook above
//  is _CrtSetReportHook and there is no POSIX equivalent, so glibc's assert()
//  called abort(), the SIGABRT handler below printed a CRASH and _exit(1)ed, and
//  the run died on the FIRST ASSERT any input tripped. It always died at case 0
//  iteration 0, and had never advanced past it - so every "Linux 41/42, sole red
//  p2p_fuzzframe" reported this and NOT a code defect, and Linux fuzz coverage
//  was zero. The same run on Windows trips ~7,900 asserts and completes ~2,800
//  frames.
//
//  WHY AN ASM LABEL rather than defining __assert_fail directly: glibc declares
//  it __THROW, which in C++ is noexcept(true), and a definition matching that
//  declaration is wrapped in terminate-on-throw. Naming the function something
//  else and giving it the symbol with asm("__assert_fail") makes it OWN the
//  symbol without inheriting the declaration. The executable's definition then
//  wins for calls made inside libmsgcore.so / libtargetcore.so.
//
//  WHY IT THROWS rather than counting and continuing like the Windows hook:
//  __assert_fail is noreturn, and GCC emits no code after the call, so there is
//  nothing to return to. Throwing is the only way back.
//
//  WHAT THAT COSTS, measured rather than assumed. glibc's declaration also
//  carries __LEAF, so at every assert call site inside the libraries GCC emits
//  NO exception edges - and the unwind therefore skips those frames' cleanups.
//  A standalone probe on the build host confirmed it: the throw is caught with
//  the right type every time and the library keeps working afterwards, but 0 of
//  3 destructors in the asserting frame ran. So an input abandoned this way may
//  LEAK. The harness already leaks a bounded buffer per affected iteration by
//  design (see Drive), and a lock left held would wedge the next input, which
//  the watchdog reports loudly rather than silently - so the failure mode is
//  visible. Closing the gap properly means routing Platform's ASSERT macro
//  through a function this side declares as potentially-throwing, which is a
//  tree-wide change and not this one.
//
//  WHAT IT MEANS FOR THE TEST, stated plainly: on Windows an assert is COUNTED
//  and execution CONTINUES past the violated invariant, which is where a Release
//  build goes. On Linux the input is ABANDONED at the assert. Those are not the
//  same test. An abandoned input is counted as OUT_ASSERT - not a pass, not a
//  failure - and a seed vector that ends that way has its expectation reported
//  as untestable rather than silently passed or failed.
// ---------------------------------------------------------------------------
struct FuzzAssertTrap
{
    const char* pszExpr;
    const char* pszFile;
    unsigned    nLine;
};

//  TWO things are needed for the interposition to take effect, and MEASURED:
//  with neither, `nm -D` showed no __assert_fail in the executable's dynamic
//  symbol table and `nm` showed it as `t` - a LOCAL text symbol - so the
//  libraries went on binding libc's, the first ASSERT abort()ed, and the run
//  died at case 0 iteration 0 exactly as it always had.
//    * default VISIBILITY, because the tree builds -fvisibility=hidden
//      (top-level CMakeLists.txt), which made this symbol local. It has to sit
//      INSIDE the extern "C", after it: written before, GCC answers "attributes
//      are not permitted in this position" and carries on, so the symbol stays
//      local and the only sign is a warning in a build nobody reads.
//    * -rdynamic on the LINK, so it reaches .dynsym at all; that is
//      ENABLE_EXPORTS on the target in MscsUnitTests/CMakeLists.txt
extern "C" __attribute__((visibility("default")))
void FuzzAssertFail(const char* pszExpr, const char* pszFile,
                    unsigned nLine, const char* pszFunc) asm("__assert_fail");

extern "C" __attribute__((visibility("default")))
void FuzzAssertFail(const char* pszExpr, const char* pszFile,
                    unsigned nLine, const char* pszFunc)
{
    ++g_nAsserts;
    ++g_nAssertsThisIn;
    // Cap the PRINTING, not the counting - same rule as the Windows hook.
    if (g_nAssertsThisIn <= kMaxAssertPrints)
    {
        std::fflush(stdout);
        std::fprintf(stderr, "[fuzz] ASSERT: %s at %s:%u (%s)\n",
                     pszExpr ? pszExpr : "(no expression)",
                     pszFile ? pszFile : "?", nLine,
                     pszFunc ? pszFunc : "?");
        DumpCursor(stderr);
    }
    else if (g_nAssertsThisIn == kMaxAssertPrints + 1)
    {
        std::fprintf(stderr, "[fuzz] ... further ASSERTs for THIS input "
                             "suppressed (still counted)\n");
        std::fflush(stderr);
    }
    FuzzAssertTrap oTrap;
    oTrap.pszExpr = pszExpr;
    oTrap.pszFile = pszFile;
    oTrap.nLine   = nLine;
    throw oTrap;
}

extern "C" void CrashSignal(int nSig)
{
    std::fflush(stdout);
    std::fprintf(stderr, "\n[fuzz] *** CRASH: signal %d ***\n", nSig);
    DumpCursor(stderr);
    std::fprintf(stderr,
        "RESULT: FAIL - the framing path crashed on the input above.\n");
    std::fflush(stderr);
    EmitRepro("crash");
    _exit(1);
}
#endif

// ---------------------------------------------------------------------------
//  Hang watchdog
//
//  A crash reports itself; a HANG does not. Without this the process simply
//  stops making progress and ctest kills it at TIMEOUT with the single word
//  "Timeout" - which names neither the input nor the defect, and reads like a
//  slow test rather than a non-terminating loop in the library. That is not a
//  hypothetical: MsgVBHeap.cpp:1591 advances a block walk by a size read from
//  the wire, so a declared size of 0 never advances and the walk never ends.
//
//  It watches g_nProgress ONLY. It asks nothing of the parser, holds no lock
//  the parser could be inside, and allocates nothing - so it stays truthful
//  even when the thread it is watching is wedged inside the allocator.
// ---------------------------------------------------------------------------
static void WatchdogFired()
{
    std::fflush(stdout);
    std::fprintf(stderr,
        "\n[fuzz] *** HANG: no progress for %u seconds ***\n", kHangSeconds);
    DumpCursor(stderr);
    std::fprintf(stderr,
        "RESULT: FAIL - the framing path did not return on the input above.\n"
        "  This is a NON-TERMINATING LOOP inside the parser, not a slow test:\n"
        "  a normal input completes in single-digit milliseconds. Replay the\n"
        "  case above under a debugger and look at the block/free-list walks in\n"
        "  Msgcore/MsgVBHeap.cpp, whose step sizes come from the wire.\n");
    std::fflush(stderr);
    EmitRepro("hang");
    _exit(1);
}

#ifdef _WIN32
static DWORD WINAPI WatchdogThread(LPVOID)
{
    unsigned long nLast = g_nProgress;
    unsigned      nIdle = 0;
    for (;;)
    {
        ::Sleep(250);
        if (g_nProgress != nLast) { nLast = g_nProgress; nIdle = 0; continue; }
        if (++nIdle >= kHangSeconds * 4) WatchdogFired();
    }
}
static void StartWatchdog()
{
    ::CreateThread(0, 0, &WatchdogThread, 0, 0, 0);
}
#else
static void* WatchdogThread(void*)
{
    unsigned long nLast = g_nProgress;
    unsigned      nIdle = 0;
    for (;;)
    {
        ::usleep(250 * 1000);
        if (g_nProgress != nLast) { nLast = g_nProgress; nIdle = 0; continue; }
        if (++nIdle >= kHangSeconds * 4) WatchdogFired();
    }
    return 0;
}
static void StartWatchdog()
{
    pthread_t tid;
    pthread_create(&tid, 0, &WatchdogThread, 0);
    pthread_detach(tid);
}
#endif

// ===========================================================================
//  Classifying the P2Pevent that comes back out of the parser
// ===========================================================================

// Is this the "I would read now" marker from P2Peerio::Recv (P2Peerio.cpp:575),
// as opposed to a refusal raised by RecvP2PeerMsg or by the VBHeap parser?
//
// Module() carries __FUNCTION__: "P2Peerio::Recv" on MSVC, "Recv" on GCC — so
// the discriminator is the tail after the last ':', compared EXACTLY. That
// keeps it distinct from "P2Peerio::RecvP2PeerMsg", which is a refusal.
// A false positive here would feed data after a genuine refusal and mask a
// finding; a false negative would end the drive early. Case 0 (the positive
// control) fails loudly on either, which is why it is asserted, not merely run.
static bool IsRecvRequest(P2Pevent* pEVT)
{
    if (!pEVT) return false;
    LPCTSTR lpszModule = pEVT->GetModule();
    if (!lpszModule) return false;

    LPCTSTR lpszTail = lpszModule;
    for (LPCTSTR p = lpszModule; *p; ++p)
        if (*p == (TCHAR)':') lpszTail = p + 1;

    static const TCHAR szRecv[] = { (TCHAR)'R', (TCHAR)'e', (TCHAR)'c',
                                    (TCHAR)'v', (TCHAR)0 };
    const TCHAR *a = lpszTail, *b = szRecv;
    while (*a && *b && *a == *b) { ++a; ++b; }
    return (*a == 0 && *b == 0);
}

// ===========================================================================
//  The driver
// ===========================================================================
enum Outcome
{
    OUT_MSG = 0,      // a P2PeerMsg was built and the wire was consumed
    OUT_REFUSED,      // a P2Pevent refusal - the designed answer. PASS.
    OUT_STARVED,      // the parser wanted more bytes than the peer sent. PASS.
    OUT_STALLED,      // returned nullptr without asking for data. PASS.
    OUT_ESCAPED,      // a NON-P2Pevent exception escaped the parser. FAIL.
    OUT_BUDGET,       // kMaxTurns reached - the drive was cut short. PASS.
    OUT_ASSERT,       // POSIX only: an ASSERT abandoned the input. NEITHER.
    OUT__COUNT
};
static const char* kOutcomeName[OUT__COUNT] =
{ "message", "refused", "starved", "stalled", "ESCAPED", "budget", "assert" };

// ---------------------------------------------------------------------------
//  THE DEPTH MODEL, and why every reported figure is tagged with it.
//  ProductionPlan.md Stage 2 step 7.
//
//  The two platforms do not run the same test, and the difference is not a
//  tuning parameter - it is what happens when an input violates an invariant:
//
//    win-crt-continue    _CrtSetReportHook returns 0, execution CONTINUES past
//                        the violated invariant, and the input runs to the end
//                        of the parse. This is where a Release build goes.
//    posix-assert-trap   glibc's __assert_fail is noreturn, so the interposed
//                        trap can only THROW. The input is ABANDONED at the
//                        first assert it trips and never finishes the parse.
//
//  The same seed therefore built 315 messages with 0 abandoned on Windows
//  against 136 with 796 abandoned on Linux - roughly half the depth - while
//  BOTH printed ESCAPED=0, which reads as parity and is not.
//
//  The step offered two ways out: route Platform's ASSERT through something
//  that can continue, or stop reporting a comparable figure. The first is
//  declined for the reason session 29 gave and this file's assert-trap banner
//  repeats - the macro is one line but its 944 call sites are a tree-wide
//  behavioural change, and it is not this test's to make.
//
//  So: the model NAME is part of every key this harness prints. It is a
//  property of the BUILD, not of the run, which is the point - two runs that
//  happened to produce identical counts still carry different tags, so the
//  figures cannot be lined up even by accident, and a script grepping for the
//  old bare `[fuzz] totals:` finds nothing and has to choose a model.
// ---------------------------------------------------------------------------
#if defined(_WIN32)
#  define FUZZ_DEPTH_MODEL "win-crt-continue"
#else
#  define FUZZ_DEPTH_MODEL "posix-assert-trap"
#endif

struct DriveResult
{
    int      eOutcome;
    int      nMsgs;
    unsigned nTurns;
    unsigned nFed;
};

// Reproduce the completion the parser just asked for. Returns false when the
// peer has nothing left to send (which, on a real connection, is a stalled or
// closed socket - not an error).
static bool Deliver(OVERLAPPEDcon* pOv, const Wire& oWire, unsigned* pnFed,
                    Rng& oRng, bool bSplit)
{
    const unsigned nSync = SyncSizeof();
    char    *pDst;
    unsigned nWant;

    if ((unsigned)pOv->dwBytes < nSync)
    {   // stage 1 - P2Peerio.cpp:400-404
        if (!pOv->pUserDB1) return false;
        pDst  = pOv->pUserDB1 + pOv->dwBytes;
        nWant = nSync - (unsigned)pOv->dwBytes;
    }
    else
    {   // stage 3 - P2Peerio.cpp:461, :473-477. nSizeof comes from pUserDB1.
        if (!pOv->pUserDB1 || !pOv->pUserDB2) return false;
        unsigned nSizeof = DeclaredOf((const unsigned char*)pOv->pUserDB1);
        if (nSizeof <= (unsigned)pOv->dwBytes) return false;
        pDst  = pOv->pUserDB2 + pOv->dwBytes;
        nWant = nSizeof - (unsigned)pOv->dwBytes;
    }

    unsigned nLeft = oWire.n - *pnFed;
    if (nLeft == 0) return false;

    unsigned n = (nWant < nLeft) ? nWant : nLeft;
    if (bSplit && n > 1) n = 1 + oRng.Below(n);   // a completion may be short

    std::memcpy(pDst, oWire.b + *pnFed, n);
    pOv->dwBytes += n;                            // exactly P2PeerCon.cpp:398
    *pnFed       += n;
    return true;
}

static void Drive(const Wire& oWire, Rng& oRng, bool bSplit, DriveResult* pRes)
{
    P2Peerio      oIo;                 // m_pCon stays nullptr: nothing is registered,
                                       // and SetP2PeventFParams (P2Peerio.cpp:1042)
                                       // guards on it, so refusals format cleanly.
    OVERLAPPEDcon oOv;
    std::memset(&oOv, 0, sizeof(oOv));
    oOv.bQueued = true;                // -> P2Peerio::Recv is a marker, see banner

    unsigned       nFed   = 0;
    unsigned       nTurn  = 0;

    pRes->nMsgs    = 0;
    pRes->eOutcome = OUT_STALLED;

    // Every turn either breaks out or consumes at least one wire byte (Deliver
    // always has nWant >= 1, and returns false when the wire is empty), so this
    // loop terminates on its own; kMaxTurns is a RUNTIME budget, not a guard.
    for (; nTurn < kMaxTurns; ++nTurn)
    {
        // Could THIS call reach stage 4? Computed before the call, because a
        // throw out of `new P2PeerMsg(image)` (P2Peerio.cpp:528) is the one
        // place where ownership of pUserDB2 is ambiguous: the image is freed
        // if P2PmsgHeap_CreateIOMAGE succeeded and a later step threw, and NOT
        // freed if CreateIOMAGE itself threw (the common case). Undecidable
        // from out here, so the harness LEAKS that buffer rather than risk a
        // double free being mistaken for a fuzz finding. Bounded: one frame
        // per affected iteration.
        bool bStage4 = (oOv.pUserDB1 && oOv.pUserDB2 &&
                        (unsigned)oOv.dwBytes >= SyncSizeof() &&
                        (unsigned)oOv.dwBytes >=
                            DeclaredOf((const unsigned char*)oOv.pUserDB1));

        P2PeerMsg* pMsg = 0;
        try
        {
            pMsg = oIo.RecvP2PeerMsg(INVALID_HANDLE_VALUE, &oOv);
        }
        catch (P2Pevent* pEVT)
        {
            bool bRead = IsRecvRequest(pEVT);
            pEVT->Cancel(false);       // silent dispose: no Display(), no dialog
            if (!bRead)
            {
                pRes->eOutcome = OUT_REFUSED;
                if (bStage4) oOv.pUserDB2 = 0;      // deliberate leak, see above
                break;
            }
            if (!Deliver(&oOv, oWire, &nFed, oRng, bSplit))
            {
                pRes->eOutcome = OUT_STARVED;
                break;
            }
            continue;
        }
#ifndef _WIN32
        // Ahead of catch (...) deliberately: that one means OUT_ESCAPED, which
        // is a hard FAILURE, and an ASSERT is not one - it is compiled out of a
        // Release build. Without this arm every assert on Linux would be
        // reported as an escaped exception.
        catch (const FuzzAssertTrap&)
        {
            ++g_nAbandoned;
            pRes->eOutcome = OUT_ASSERT;
            if (bStage4) oOv.pUserDB2 = 0;      // same ownership rule as above
            break;
        }
#endif
        catch (...)
        {
            pRes->eOutcome = OUT_ESCAPED;
            if (bStage4) oOv.pUserDB2 = 0;
            break;
        }

        if (pMsg)
        {
            ++pRes->nMsgs;
            delete pMsg;               // frees the image through P2PmsgHeap_Close
            if (nFed >= oWire.n) { pRes->eOutcome = OUT_MSG; break; }
            continue;                  // more bytes on the wire -> next frame
        }

        // nullptr with no read requested: the parser is done with what it has.
        pRes->eOutcome = OUT_STALLED;
        break;
    }
    if (nTurn >= kMaxTurns) pRes->eOutcome = OUT_BUDGET;

    pRes->nTurns = nTurn;
    pRes->nFed   = nFed;

    delete [] oOv.pUserDB1; oOv.pUserDB1 = 0;
    delete [] oOv.pUserDB2; oOv.pUserDB2 = 0;
}

// ===========================================================================
//  THE SEED CORPUS — 14 cases. The corpus is the point; the mutation loop is
//  the amplifier. Every case says what it targets and what it must produce.
// ===========================================================================
enum Expect
{
    EXP_ANY = 0,      // any non-failing outcome; here to be mutated, not asserted
    EXP_MSG1,         // must produce exactly one P2PeerMsg
    EXP_MSG2,         // must produce exactly two
    EXP_REFUSE,       // must be refused outright
    EXP_NOMSG         // must NOT produce a message (refuse or starve, either way)
};

struct Case
{
    const char *pszName;
    const char *pszTargets;
    int         eExpect;
    bool        bSplit;       // deliver in RNG-sized short reads
    Wire        oWire;
};

static const int kCases = 18;
static Case      g_aCases[kCases];

static void AddCase(int i, const char* pszName, const char* pszTargets,
                    int eExpect, bool bSplit, const Wire& w)
{
    g_aCases[i].pszName    = pszName;
    g_aCases[i].pszTargets = pszTargets;
    g_aCases[i].eExpect    = eExpect;
    g_aCases[i].bSplit     = bSplit;
    g_aCases[i].oWire      = w;
}

// A header-only vector: 8 bytes claiming nSizeof, complement correct. This is
// the shape of the C1 input — the length field is the whole attack.
static Wire HeaderOnly(unsigned nSizeof, unsigned char uAddrType)
{
    Wire w; std::memset(&w, 0, sizeof(w)); w.n = 8;
    StampSync(w, nSizeof, uAddrType);
    return w;
}

static bool BuildCorpus(const Wire& oBase, const Wire& oBig)
{
    //  static for the same reason main's two are - refer kMaxWire.  Safe here
    //  because every use below ASSIGNS before it reads (w = oBase, or a
    //  memset), so nothing carries over between cases.
    static Wire w;

    // ---- 0 --------------------------------------------------------------
    // The POSITIVE CONTROL. A frame produced by the library's own serializer,
    // byte-identical to what P2Peerio::SendP2PeerMsg puts on the wire
    // (P2Peerio.cpp:242-265), delivered whole. It must parse into exactly one
    // P2PeerMsg. Exit 0 means nothing without this: a parser that refused
    // everything would "pass" every other case in the file.
    AddCase(0, "valid",
            "stages 0-4 end to end; proves the drive mechanism is real",
            EXP_MSG1, false, oBase);

    // ---- 1 --------------------------------------------------------------
    // THE LITERAL C1 INPUT. nSizeof = 4, complement valid. Before the fix this
    // allocated new char[4+4] and then memcpy'd a FIXED sizeof(oSync) = 8 bytes
    // into it (P2Peerio.cpp:439-442) — a pre-auth heap overflow reachable by
    // anyone who can complete a TCP connection — and later underflowed
    // IOmage_Sizeof in the decrypt path (that was C2). The lower bound at
    // P2Peerio.cpp:433 must refuse it. THIS CASE IS THE REGRESSION PIN.
    AddCase(1, "c1_undersized_4",
            "P2Peerio.cpp:433 lower bound - the SECURITY_REVIEW C1 input",
            EXP_REFUSE, false, HeaderOnly(4, (unsigned char)VBLock_Addr32));

    // ---- 2 --------------------------------------------------------------
    // The degenerate end of the same class: a zero-length frame. new char[4],
    // memcpy 8. Same check, and the value most likely to survive a rewrite of
    // it as `!nSizeof`.
    AddCase(2, "c1_zero",
            "P2Peerio.cpp:433 - nSizeof == 0",
            EXP_REFUSE, false, HeaderOnly(0, (unsigned char)VBLock_Addr32));

    // ---- 3 --------------------------------------------------------------
    // The off-by-one twin: nSizeof == sizeof(oSync) == 8. The fixed memcpy now
    // FITS, so the naive bound ("must cover the bytes we copy") would let this
    // through — and IOmage_Sizeof (P2PmsgBSTR.cpp:433) would then compute
    // 8 - 9 + 1 = 0 and the block walk would run on nothing. The shipping check
    // is against sizeof(VBListIOmage) == 9, so 8 must still be refused. This is
    // the case that fails if anyone "simplifies" the constant.
    AddCase(3, "c1_boundary_8",
            "P2Peerio.cpp:433 - one BELOW the minimum; == the memcpy length",
            EXP_REFUSE, false, HeaderOnly(8, (unsigned char)VBLock_Addr32));

    // ---- 4 --------------------------------------------------------------
    // The smallest value stage 2 ACCEPTS: nSizeof == sizeof(VBListIOmage) == 9.
    // It gets past the gate with a one-byte body, so it drives stage 3 and the
    // body parser with the most degenerate image the framing layer permits.
    // Header only on the wire, so the body never arrives: starve, no message.
    AddCase(4, "c1_boundary_9",
            "P2Peerio.cpp:433 - the smallest ACCEPTED size; then stage 3",
            EXP_NOMSG, false, HeaderOnly(9, (unsigned char)VBLock_Addr32));

    // ---- 5 --------------------------------------------------------------
    // The upper bound: m_dwMaxRecvSize + 1 (32769). Must be refused at
    // P2Peerio.cpp:423 BEFORE new char[nSizeof+4] runs — the difference between
    // a refusal and an attacker-chosen allocation on a pre-auth path. The
    // 24-bit ceiling (0x00FFFFFF, a 16 MB allocation) is in the mutator's
    // interesting-value table and is reached from here by mutation.
    AddCase(5, "oversize_edge",
            "P2Peerio.cpp:423 upper bound - m_dwMaxRecvSize + 1",
            EXP_REFUSE, false, HeaderOnly(32769, (unsigned char)VBLock_Addr32));

    // ---- 6 --------------------------------------------------------------
    // Complement broken: (uiSync1 + uiSync2) != ~0, so stage 2 takes the
    // RE-SYNCHRONISATION path (P2Peerio.cpp:444-457): the overlapping
    // slide-by-one that had to become memmove, plus pBuffer[dwBytes] = 0 and
    // goto STAGE1. The bytes behind it are a valid frame's, but shifted, so it
    // slides to exhaustion and must never produce a message.
    //   Trimmed to 80 bytes on purpose: the slide consumes exactly one byte and
    //   raises one P2Pevent per turn, so a full 2 KB frame would spend 2000
    //   event constructions proving what 72 slides prove. This vector runs the
    //   path to genuine EXHAUSTION rather than to the turn budget.
    w = oBase; WrU32(w.b + 4, RdU32(w.b + 4) ^ 0x00A50000u);
    if (w.n > 80) w.n = 80;
    AddCase(6, "sync_broken",
            "P2Peerio.cpp:444-457 memmove re-sync, driven to exhaustion",
            EXP_NOMSG, false, w);

    // ---- 7 --------------------------------------------------------------
    // Stream desync with RECOVERY: seven junk bytes, then a whole valid frame.
    // The parser must slide the 8-byte window one byte at a time (seven turns
    // of memmove + refill), land exactly on the real header, and then parse the
    // frame normally. This is the case that answers the TODO at P2Peerio.cpp:445
    // ("Why is this required?") with a yes: it is required, and it works.
    std::memset(&w, 0, sizeof(w));
    for (unsigned i = 0; i < 7; ++i) w.b[i] = (unsigned char)(0x5A + i);
    std::memcpy(w.b + 7, oBase.b, oBase.n);
    w.n = 7 + oBase.n;
    AddCase(7, "sync_slide",
            "P2Peerio.cpp:444-457 - slide through 7 junk bytes and RECOVER",
            EXP_MSG1, false, w);

    // ---- 8 --------------------------------------------------------------
    // A byte-swapped sync word: the frame a big-endian peer would write. The
    // complement relation SURVIVES a byte swap (complement is per-bit, swap is
    // a bit permutation, and the two commute - byte_order.md section 4), so
    // stage 2's checksum gate passes and hands the size logic a length built
    // from the WRONG bytes. Where that length lands decides which layer catches
    // it: out of range -> refused at P2Peerio.cpp:423; in range -> the frame is
    // allocated and the endian sentinel in the body parser
    // (MsgVBHeap.cpp:2382-2386) is what has to reject it. Both are correct
    // outcomes, so this case is EXP_ANY and exists to be mutated across that
    // boundary. It is the defect the sentinel was added for, arriving from the
    // wire rather than from a stored file.
    w = oBase;
    {
        unsigned s1 = RdU32(w.b);
        unsigned sw = ((s1 & 0x000000FFu) << 24) | ((s1 & 0x0000FF00u) << 8) |
                      ((s1 & 0x00FF0000u) >> 8)  | ((s1 & 0xFF000000u) >> 24);
        WrU32(w.b + 0, sw);
        WrU32(w.b + 4, ~sw);
    }
    AddCase(8, "endian_swapped",
            "byte_order.md s4 - swapped oSync survives the complement gate",
            EXP_ANY, false, w);

    // ---- 9 --------------------------------------------------------------
    // A frame that is SHORTER than it claims: the header is honest about a
    // length the peer never sends. The parser must sit in stage 3 forever and
    // must NOT hand a half-filled buffer to the body parser — the tail of the
    // pUserDB2 allocation is uninitialised heap, so a message built from it
    // would be an information leak as well as a parse of garbage.
    w = oBase; w.n = oBase.n - 1;
    AddCase(9, "truncated_body",
            "stage 3 - a half frame must NEVER become a P2PeerMsg",
            EXP_NOMSG, false, w);

    // ---- 10 -------------------------------------------------------------
    // The same valid frame, delivered in short reads (a byte or a few per
    // completion). Drives the accumulation arithmetic on both partial-read
    // paths — &pBuffer[dwBytes] / sizeof(oSync)-dwBytes at stage 1, and
    // &pUserDB2[dwBytes] / nSizeof-dwBytes at stage 3 — dozens of times, and
    // must still produce exactly the message case 0 produces.
    AddCase(10, "split_reads",
            "stages 1+3 partial-read accumulation; same result as case 0",
            EXP_MSG1, true, oBase);

    // ---- 11 -------------------------------------------------------------
    // Two whole frames back to back in one stream, delivered in RNG-sized
    // chunks: the coalesced case. Exercises the re-entry reset at
    // P2Peerio.cpp:529-532 (pUserDB2 = 0, dwBytes = 0, uiSync1 = 0) — the state
    // that has to be clean or frame N+1 parses against frame N's leftovers.
    std::memset(&w, 0, sizeof(w));
    if ((unsigned)(2 * oBase.n) > kMaxWire) return false;
    std::memcpy(w.b,            oBase.b, oBase.n);
    std::memcpy(w.b + oBase.n,  oBase.b, oBase.n);
    w.n = 2 * oBase.n;
    AddCase(11, "coalesced_2",
            "P2Peerio.cpp:529-532 re-entry reset across two frames",
            EXP_MSG2, true, w);

    // ---- 12 -------------------------------------------------------------
    // Past the framing layer and into the block chain. The image is a VBHeap:
    //   [0..7]   oSync
    //   [8..9]   VBHeapRoot::nSize     [10..11] VBHeapRoot::uVBLock
    //   [12..]   control keys - aAlloc, aAllocSize, nAllocItems, aFree,
    //            aFreeLast, aFreeSize, nFreeItems, aSpare8  (MsgVBHeap.cpp:257-288)
    // Here aAlloc points PAST the end of the image and the counters are
    // inflated, so the first step of the block walk reads outside the buffer.
    // The declared frame size is left honest, so stage 2 passes it and the
    // walk runs on a buffer of exactly the size it was promised — which is the
    // part MsgVBHeap.cpp:2373-2377 records as NOT fixed: the complement is
    // forgeable, so nothing between the wire and the walk checks these links.
    w = oBase;
    if (w.n > 44)
    {
        WrU32(w.b + 12, w.n + 16u);      // aAlloc      -> past the image
        WrU32(w.b + 16, 0x00FFFFFFu);    // aAllocSize  -> absurd
        WrU32(w.b + 20, 0x0000FFFFu);    // nAllocItems -> absurd
        WrU32(w.b + 24, w.n - 1u);       // aFree       -> inside, but mid-block
        WrU32(w.b + 32, 0xFFFFFFFFu);    // aFreeSize   -> underflow bait
    }
    AddCase(12, "root_chain",
            "MsgVBHeap.cpp:2373-2377 - forged VBHeapRoot links, honest length",
            EXP_ANY, false, w);

    // ---- 13 -------------------------------------------------------------
    // One level further down: the first VBLock's own header. VBLockHdr is
    // { UINT08 uVBLockDefs; union { UINT08/16/32/64 nSize } } (Msgcore.h:249-259)
    // and it sits immediately after the root, at 8 + VBHeapRoot::nSize (read
    // from the image, not assumed). Stage 2 checks the declared IMAGE size
    // against the buffer it allocated, so the image cannot lie about itself —
    // but nothing checks a declared BLOCK size against the image. This is
    // "declared larger than the real buffer" reached from the wire, one
    // indirection below where the fix was applied.
    w = oBase;
    {
        unsigned nRoot = (unsigned)w.b[8] | ((unsigned)w.b[9] << 8);   // UINT16
        unsigned nBlk  = 8u + nRoot;
        if (nRoot >= 4 && nBlk + 5 <= w.n)
        {
            w.b[nBlk] = 0xFF;                       // uVBLockDefs: every flag set
            WrU32(w.b + nBlk + 1, 0x00FFFFFFu);     // nSize32: bigger than the image
        }
    }
    AddCase(13, "block_hdr",
            "MsgVBHeap.cpp:2374 - a BLOCK declared larger than the image",
            EXP_ANY, false, w);

    // =====================================================================
    //  14-17: THE SIZE BAND.  ProductionPlan.md Stage 6 step 16.
    //
    //  Everything above runs on a frame of a couple of hundred bytes, and the
    //  step names that as the gap: nothing fuzzed AT the limits, and the 30 KB
    //  defect of session 33 was found by looking rather than by fuzzing.
    //
    //  Size is not a quantity here, it is a different set of branches. Stage 1
    //  and stage 3 both accumulate across completions - `&pBuffer[dwBytes]`,
    //  `nSizeof - dwBytes` - and arithmetic that is correct over 200 bytes and
    //  wrong over 32000 is the classic shape: a 16-bit intermediate, a signed
    //  short, an off-by-one that only bites when the ceiling is in reach. None
    //  of those can be reached from a 200-byte frame at all.
    //
    //  oBig is a REAL frame built by the library's own serializer, sized as
    //  close under m_dwMaxRecvSize as the payload granularity allows - not a
    //  header claiming a large size, which case 5 already covers. The
    //  difference is the point: case 5 tests the REFUSAL at the bound, these
    //  test that the bound is not accidentally refusing what it should accept,
    //  and that the path which handles 32 KB actually works.
    // =====================================================================

    // ---- 14 -------------------------------------------------------------
    // A well-formed frame just under the ceiling, delivered whole. It must
    // produce exactly one P2PeerMsg, for the same reason case 0 must: a
    // ceiling that refuses legitimate traffic is a defect in the other
    // direction, and nothing else in this file would notice.
    AddCase(14, "big_valid",
            "stage 2/:423 - a LEGITIMATE frame at the size ceiling must PARSE",
            EXP_MSG1, false, oBig);

    // ---- 15 -------------------------------------------------------------
    // The same frame in RNG-sized short reads. This is the case the size band
    // exists for: stage 3's accumulation runs over tens of thousands of bytes
    // across many completions, which is where a truncating intermediate shows
    // and where 200 bytes can never reach.
    //
    // It cannot starve on the turn budget by accident. Deliver takes
    // 1 + Below(nWant), so the remainder shrinks by a uniform factor and the
    // expected turn count is logarithmic - about 20 for 32 KB against a budget
    // of 96. And it is not a probability anyway: the RNG is derived from
    // (seed, case, -1), so the seed vector's delivery pattern is FIXED and
    // identical on both platforms.
    AddCase(15, "big_split",
            "stage 3 accumulation over ~32 KB in short reads; same result as 14",
            EXP_MSG1, true, oBig);

    // ---- 16 -------------------------------------------------------------
    // Two ceiling-sized frames back to back, in short reads: the re-entry
    // reset (P2Peerio.cpp:529-532) at a size where a buffer that was not
    // released, or an offset that was not cleared, costs 32 KB rather than 200
    // bytes - and where frame 2 parsing against frame 1's leftovers is
    // guaranteed to land somewhere structural.
    std::memset(&w, 0, sizeof(w));
    if ((unsigned)(2 * oBig.n) > kMaxWire) return false;
    std::memcpy(w.b,           oBig.b, oBig.n);
    std::memcpy(w.b + oBig.n,  oBig.b, oBig.n);
    w.n = 2 * oBig.n;
    AddCase(16, "big_coalesced",
            "P2Peerio.cpp:529-532 re-entry reset across two CEILING-sized frames",
            EXP_MSG2, true, w);

    // ---- 17 -------------------------------------------------------------
    // The bound from the INSIDE. Case 5 is m_dwMaxRecvSize + 1 and must be
    // refused; this is m_dwMaxRecvSize EXACTLY and must not be, because the
    // shipping test is `nSizeof > m_dwMaxRecvSize` (P2Peerio.cpp:423) and a
    // rewrite to `>=` would pass every other case in this file.
    //
    // Header only, so the body never arrives and it starves in stage 3 - which
    // is the correct outcome and is what makes the case testable without
    // building a 32 KB body that the serializer would have to agree with. What
    // is being asserted is that it got PAST stage 2 at all.
    AddCase(17, "limit_exact",
            "P2Peerio.cpp:423 - m_dwMaxRecvSize EXACTLY must be ACCEPTED, not refused",
            EXP_NOMSG, false, HeaderOnly(32768, (unsigned char)VBLock_Addr32));

    return true;
}

// ===========================================================================
//  The mutator — the amplifier on top of the corpus
// ===========================================================================
static const unsigned char kInteresting8[] =
    { 0x00, 0x01, 0x02, 0x08, 0x09, 0x7F, 0x80, 0xFE, 0xFF };
static const unsigned kInteresting32[] =
    { 0u, 1u, 4u, 8u, 9u, 10u, 0x0000FFFFu, 0x00FFFFFFu, 0x00FFFFFEu,
      32767u, 32768u, 32769u, 0x7FFFFFFFu, 0x80000000u, 0xFFFFFFFFu };

static void Mutate(Wire* pWire, Rng& oRng)
{
    unsigned nOps = 1 + oRng.Below(4);
    for (unsigned i = 0; i < nOps && pWire->n > 0; ++i)
    {
        // Biased at the structural head - oSync, VBHeapRoot and the first
        // VBLock header. Every length and every link the parser trusts lives
        // in the first ~64 bytes; the rest is payload.
        unsigned nSpan = (pWire->n < 64u) ? pWire->n : 64u;
        unsigned off   = (oRng.Below(10) < 7) ? oRng.Below(nSpan)
                                              : oRng.Below(pWire->n);

        switch (oRng.Below(6))
        {
        case 0:                                        // bit flip
            pWire->b[off] ^= (unsigned char)(1u << oRng.Below(8));
            break;
        case 1:                                        // interesting byte
            pWire->b[off] = kInteresting8[oRng.Below((unsigned)
                                (sizeof(kInteresting8)/sizeof(kInteresting8[0])))];
            break;
        case 2:                                        // interesting dword
            if (off + 4 <= pWire->n)
                WrU32(pWire->b + off,
                      kInteresting32[oRng.Below((unsigned)
                          (sizeof(kInteresting32)/sizeof(kInteresting32[0])))]);
            break;
        case 3:                                        // interesting word
            if (off + 2 <= pWire->n)
            {
                unsigned short v = (unsigned short)
                    kInteresting32[oRng.Below((unsigned)
                        (sizeof(kInteresting32)/sizeof(kInteresting32[0])))];
                std::memcpy(pWire->b + off, &v, 2);
            }
            break;
        case 4:                                        // truncate the stream
            pWire->n = 1 + oRng.Below(pWire->n);
            break;
        case 5:                                        // splice a run over itself
            {
                unsigned nRun = 1 + oRng.Below(pWire->n - off);
                unsigned src  = oRng.Below(pWire->n - nRun + 1);
                std::memmove(pWire->b + off, pWire->b + src,
                             (off + nRun <= pWire->n) ? nRun : (pWire->n - off));
            }
            break;
        }
    }

    // Three mutants in four get the complement repaired. Without this most
    // mutants die at the checksum gate and the fuzzer never reaches the code
    // that matters — and repairing it is exactly what an attacker does, because
    // MsgVBHeap.cpp:2373 says the checksum is trivially forgeable. The
    // remaining quarter is what keeps the re-sync path under fire; it is also
    // by far the slowest quarter (one P2Pevent per byte slid), which is the
    // other reason the ratio is 3:1 and not 1:1.
    if (oRng.Below(4) != 0) RepairComplement(*pWire);

    // A third get the declared size re-stamped to the REAL stream length: a
    // self-consistent frame, which is what carries a mutated body all the way
    // into the block walk.
    if (oRng.Below(3) == 0 && pWire->n >= 8)
        StampSync(*pWire, pWire->n, (unsigned char)VBLock_Addr32);
}

// ===========================================================================
//  Reporting
// ===========================================================================
static int  g_nFindings = 0;
static bool g_bVerbose  = false;

static void Finding(const char* pszWhat, const char* pszWhy)
{
    ++g_nFindings;
    std::fflush(stdout);
    std::printf("\n  *** FINDING: %s ***\n", pszWhat);
    DumpCursor(stdout);
    EmitRepro(pszWhy);
}

// ===========================================================================
//  Persistent corpus replay - ProductionPlan.md Stage 6 step 16
//
//  A saved input is bytes and nothing else: it carries no case, no expectation
//  and no split flag, because the file outlives the harness version that wrote
//  it and anything else stored beside it would be a promise this code would
//  have to keep. So it is driven WHOLE and the only propositions asserted are
//  the ones that hold for any input at all - no crash, no hang, no non-P2Pevent
//  exception. A refusal is a pass here exactly as it is everywhere else.
//
//  It is deliberately NOT given an expectation of its own. A corpus entry is
//  usually a fixed defect's input, and the RIGHT behaviour for it after the fix
//  is "refused cleanly" - which is what "no finding" already means. Inventing a
//  per-file expectation would need a metadata format beside the bytes, and the
//  bytes are the thing worth keeping.
// ===========================================================================
static unsigned *g_oCorpusTotals = 0;      // the run's tally, while replaying
static int       g_nRoundBase    = 0;      // iteration offset in continuous mode
static unsigned  g_nRunSeed      = kDefaultSeed;

static void CorpusOne(const char* pszPath, const unsigned char* p, unsigned n,
                      void* /*pvUser*/)
{
    if (n > kMaxWire) return;              // FuzzCorpusRun already caps, belt and braces

    Wire w;
    std::memset(&w, 0, sizeof(w));
    std::memcpy(w.b, p, n);
    w.n = n;

    //  COPIED, not aliased. The path FuzzCorpusRun hands over is a local of its
    //  own loop, and g_cur outlives this call by design - the crash filter and
    //  the watchdog read it from another thread and after this frame is gone.
    //  A dangling name in a crash report is worse than no name.
    static char s_szPath[512];
#ifdef _WIN32
    strncpy_s(s_szPath, sizeof(s_szPath), pszPath ? pszPath : "(corpus)", _TRUNCATE);
#else
    std::strncpy(s_szPath, pszPath ? pszPath : "(corpus)", sizeof(s_szPath) - 1);
    s_szPath[sizeof(s_szPath) - 1] = 0;
#endif

    //  The RNG still comes from the seed, not the clock. Keyed on the CONTENT
    //  hash rather than on a counter, so a given file draws the same numbers
    //  wherever it sits in the directory - a corpus entry that only reproduced
    //  when it was the fourth file would be no reproducer at all.
    Rng oRng; oRng.Seed(IterState(g_nRunSeed, -1, (int)FuzzContentHash(p, n)));

    SetCursor(s_szPath, -1, -1, g_nRunSeed, w);

    DriveResult oRes;
    Drive(w, oRng, false, &oRes);
    if (g_oCorpusTotals) ++g_oCorpusTotals[oRes.eOutcome];

    if (oRes.eOutcome == OUT_ESCAPED)
        Finding("a SAVED CORPUS input made a non-P2Pevent exception escape",
                "corpus-escape");

    if (g_bVerbose)
        std::printf("[fuzz] corpus %s -> %s msgs=%d\n",
                    pszPath, kOutcomeName[oRes.eOutcome], oRes.nMsgs);
}

// Did the seed vector do what the corpus entry says it must? Applied to the
// UNMUTATED vectors only - mutants have no expected outcome by construction.
static void CheckExpectation(const Case& oCase, const DriveResult& oRes)
{
    // An input abandoned at an ASSERT (POSIX) never reached the end of the
    // parse, so the corpus entry's expectation was not exercised. Reporting it
    // as a pass would claim a measurement that did not happen; reporting it as
    // a FINDING would call a Debug-only diagnostic a defect. It is neither, and
    // it is printed so a seed vector that stops behaving is impossible to miss.
    if (oRes.eOutcome == OUT_ASSERT)
    {
        if (oCase.eExpect != EXP_ANY)
        {
            std::fflush(stdout);
            std::printf("  [fuzz] UNTESTABLE: seed vector for case '%s' was "
                        "abandoned at an ASSERT before its expectation could be "
                        "checked\n", oCase.pszName);
        }
        return;
    }
    switch (oCase.eExpect)
    {
    case EXP_MSG1:
        if (oRes.eOutcome != OUT_MSG || oRes.nMsgs != 1)
            Finding("positive control did not parse - the harness is not "
                    "driving the parser, so every other PASS here is empty",
                    "control");
        break;
    case EXP_MSG2:
        if (oRes.nMsgs != 2)
            Finding("two coalesced frames did not both parse - the frame "
                    "re-entry reset (P2Peerio.cpp:529-532) is not clean",
                    "reentry");
        break;
    case EXP_REFUSE:
        if (oRes.eOutcome != OUT_REFUSED)
            Finding("a frame that must be REFUSED was not - the stage 2 bound "
                    "this case pins (see the case comment) is gone",
                    "unrefused");
        break;
    case EXP_NOMSG:
        if (oRes.nMsgs != 0)
            Finding("a frame shorter than it claims produced a P2PeerMsg - "
                    "the body was parsed out of uninitialised heap",
                    "shortbody");
        break;
    default:
        break;
    }
    if (oRes.eOutcome == OUT_ESCAPED)
        Finding("a non-P2Pevent exception escaped RecvP2PeerMsg", "escape");
}

// ===========================================================================
int main(int argc, char* argv[])
{
#ifdef _WIN32
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
    _CrtSetReportHook(AssertReportHook);
    SetUnhandledExceptionFilter(CrashFilter);
#else
    signal(SIGSEGV, CrashSignal);
    signal(SIGBUS,  CrashSignal);
    signal(SIGILL,  CrashSignal);
    signal(SIGFPE,  CrashSignal);
    signal(SIGABRT, CrashSignal);
#endif
    StartWatchdog();

    unsigned    nSeed      = kDefaultSeed;
    int         nIters     = kDefaultIters;
    int         nReplayCse = -1;
    int         nReplayItr = -1;
    int         nSeconds   = 0;
    const char *pszCorpus  = 0;

    // p2p_fuzzframe [seed] [iters] [--replay <case> <iter>] [--strict-assert]
    //               [--corpus <dir>] [--repro-dir <dir>] [--seconds <n>] [--verbose]
    int nPos = 0;
    for (int i = 1; i < argc; ++i)
    {
        //  --strict-assert is the baseline-0 case: no assert is tolerated. Kept
        //  as a spelling because it is what the docs and the progress log name,
        //  and because it is the right thing to run by hand once the population
        //  is believed closed.
        if (std::strcmp(argv[i], "--strict-assert") == 0) { g_nAssertBase = 0; continue; }
        if (std::strncmp(argv[i], "--assert-baseline=", 18) == 0)
        { g_nAssertBase = (int)std::strtol(argv[i] + 18, 0, 0); continue; }
        if (std::strcmp(argv[i], "--assert-baseline") == 0 && i + 1 < argc)
        { g_nAssertBase = (int)std::strtol(argv[i+1], 0, 0); ++i; continue; }
        if (std::strcmp(argv[i], "--verbose")       == 0) { g_bVerbose    = true; continue; }
        //  ProductionPlan.md Stage 6 step 16 - the PERSISTENT half.  Refer
        //  fuzz_corpus.h; in short, --corpus replays a directory of saved
        //  inputs before anything is mutated, and --repro-dir is where a
        //  finding writes the bytes that caused it.
        if (std::strcmp(argv[i], "--corpus") == 0 && i + 1 < argc)
        { pszCorpus = argv[++i]; continue; }
        if (std::strcmp(argv[i], "--repro-dir") == 0 && i + 1 < argc)
        {
#ifdef _WIN32
            strncpy_s(g_szReproDir, sizeof(g_szReproDir), argv[++i], _TRUNCATE);
#else
            std::strncpy(g_szReproDir, argv[++i], sizeof(g_szReproDir) - 1);
#endif
            continue;
        }
        //  CONTINUOUS MODE.  Rounds keep coming, with the iteration index
        //  climbing across rounds, so round N is genuinely new inputs rather
        //  than the same ones again.  The registered ctest gate does NOT pass
        //  it: a gate whose duration depends on the machine is not a gate.
        if (std::strcmp(argv[i], "--seconds") == 0 && i + 1 < argc)
        { nSeconds = (int)std::strtol(argv[++i], 0, 0); continue; }
        if (std::strcmp(argv[i], "--replay") == 0 && i + 2 < argc)
        {
            nReplayCse = (int)std::strtol(argv[i+1], 0, 0);
            nReplayItr = (int)std::strtol(argv[i+2], 0, 0);
            i += 2; continue;
        }
        if (nPos == 0) { nSeed  = (unsigned)std::strtoul(argv[i], 0, 0); ++nPos; continue; }
        if (nPos == 1) { nIters = (int)std::strtol (argv[i], 0, 0);      ++nPos; continue; }
    }
    if (nIters < 0) nIters = 0;
    g_nRunSeed = nSeed;

    std::printf("=== p2p_fuzzframe - RecvP2PeerMsg stages 1-3 fuzz harness ===\n");
    std::printf("SEED : 0x%08X   (replay with: p2p_fuzzframe 0x%08X)\n", nSeed, nSeed);
    std::printf("Iters: %d per case x %d cases = %d executions\n",
                nIters, kCases, nIters * kCases);
    std::printf("Asserting: no hostile frame may crash, hang, or become a message\n"
                "           it is too short to be. A clean refusal is a PASS.\n\n");
    std::fflush(stdout);

    if (!StartupP2Pmsg(16)) { Log("SETUP: StartupP2Pmsg() failed"); return 2; }
    WSADATA oWsaData;
    WSAStartup(MAKEWORD(2, 2), &oWsaData);          // no-op shim on Linux

    int nExit = 2;
    {
        // ---- the base frame, built by the library's own serializer ---------
        // Identical to P2Peerio::SendP2PeerMsg (P2Peerio.cpp:242-265), which is
        // what p2p_authgate does: the corpus starts from a frame the library
        // itself calls well formed, so every refusal below is attributable to
        // the mutation and not to the harness writing a bad frame by hand.
        //  static, not automatic: these two live for the whole function and
        //  are 65 KB each.  Refer kMaxWire for the stack overflow that made
        //  the distinction matter.
        static Wire oBase;
        std::memset(&oBase, 0, sizeof(oBase));
        {
            static const wchar_t* kPayload = L"fuzzframe";
            P2Psize_t nBytes = (P2Psize_t)((wcslen(kPayload) + 1) * sizeof(wchar_t));

            P2PeerMsg32 oMsg(kSrcAddr, kDstAddr, P2Pmsg_BCast, kPayload, nBytes);
            oMsg.PrepareP2Piomage(~(DWORD)0);       // P2Peerio's default m_dwIFmask
            const P2Piomage* pImage = oMsg.P2Piomage();
            if (!pImage) { Log("SETUP: P2Piomage() returned null"); return 2; }

            UINT nImage = P2Piomage_Sizeof(pImage);
            if (!nImage || nImage * 2 > kMaxWire)
            {
                std::printf("[fuzz] SETUP: frame size %u does not fit the wire buffer\n",
                            (unsigned)nImage);
                return 2;
            }
            std::memcpy(oBase.b, pImage, nImage);
            oBase.n = nImage;
        }
        std::printf("[fuzz] base frame built by the library: %u bytes"
                    " (declared %u, sizeof(oSync)=%u, sizeof(VBListIOmage)=%u)\n",
                    oBase.n, DeclaredOf(oBase.b), SyncSizeof(), HdrSizeof());
        std::fflush(stdout);

        // ---- the CEILING frame - ProductionPlan.md Stage 6 step 16 --------
        // A second base, built the same way, sized as close under
        // m_dwMaxRecvSize as the payload granularity allows. Cases 14-17 run on
        // it; refer BuildCorpus for why size is a set of branches rather than a
        // quantity.
        //
        // The size is CONVERGED ON rather than computed, and that is deliberate.
        // The overhead between a payload and its serialized image is the
        // library's business - the addresses, the name, the VBHeap the image is
        // built as - and a harness that hard-coded an arithmetic relation would
        // go silently wrong the day that layout changed, producing a "big" frame
        // of the wrong size that still passed. Measuring, adjusting and
        // REPORTING cannot go silently wrong: if it cannot land under the
        // ceiling it says so and the run is SETUP, rather than a green pass on a
        // frame that was never big.
        static Wire oBig;
        std::memset(&oBig, 0, sizeof(oBig));
        {
            static wchar_t s_aBig[24000];
            const unsigned nCeiling = 32768u;      // P2Peerio.cpp:74 m_dwMaxRecvSize
            unsigned nChars = 16000;               // a starting guess, then measured

            for (int nTry = 0; nTry < 6 && oBig.n == 0; ++nTry)
            {
                if (nChars < 2 || nChars > (unsigned)(sizeof(s_aBig)/sizeof(s_aBig[0])))
                    break;
                for (unsigned k = 0; k + 1 < nChars; ++k)
                    s_aBig[k] = (wchar_t)(L'a' + (k % 26));
                s_aBig[nChars - 1] = 0;

                P2Psize_t nBytes = (P2Psize_t)(nChars * sizeof(wchar_t));
                P2PeerMsg32 oMsg(kSrcAddr, kDstAddr, P2Pmsg_BCast, s_aBig, nBytes);
                oMsg.PrepareP2Piomage(~(DWORD)0);
                const P2Piomage* pImage = oMsg.P2Piomage();
                if (!pImage) break;

                UINT nImage = P2Piomage_Sizeof(pImage);
                if (!nImage) break;

                if (nImage > nCeiling)
                {
                    // Overshot: drop exactly the excess, rounded UP to a whole
                    // wchar_t so the payload stays a valid string, and one more
                    // for margin against a length that is not linear in it.
                    unsigned nDrop = (nImage - nCeiling + (unsigned)sizeof(wchar_t) - 1)
                                   / (unsigned)sizeof(wchar_t);
                    nChars -= (nDrop + 1);
                    continue;
                }
                if (nImage * 2 > kMaxWire) break;   // case 16 needs two of them

                std::memcpy(oBig.b, pImage, nImage);
                oBig.n = nImage;
            }
        }
        if (oBig.n == 0)
        {
            Log("SETUP: could not build a frame at the size ceiling");
            return 2;
        }
        std::printf("[fuzz] ceiling frame built by the library: %u bytes"
                    " (declared %u, ceiling %u, headroom %u)\n",
                    oBig.n, DeclaredOf(oBig.b), 32768u, 32768u - oBig.n);
        std::fflush(stdout);

        if (!BuildCorpus(oBase, oBig)) { Log("SETUP: corpus does not fit the wire buffer"); return 2; }

        std::clock_t tStart = std::clock();
        unsigned aTotals[OUT__COUNT];
        for (int i = 0; i < OUT__COUNT; ++i) aTotals[i] = 0;

        // ---- corpus replay - ProductionPlan.md Stage 6 step 16 ------------
        //  Saved inputs first, because a regression pin that runs after the
        //  campaign is a pin that a crash in the campaign stops you reaching.
        //  Refer fuzz_corpus.h; MscsUnitTests/fuzz/README.md is the how-to.
        unsigned nCorpus = 0;
        if (pszCorpus && nReplayCse < 0)
        {
            g_oCorpusTotals = aTotals;
            unsigned nSkipped = 0, nUnlisted = 0;
            nCorpus = FuzzCorpusRun(pszCorpus, CorpusOne, 0, &nSkipped, &nUnlisted);
            g_oCorpusTotals = 0;
            std::printf("[fuzz] corpus: %u saved input(s) replayed from %s\n",
                        nCorpus, pszCorpus);
            //  Say what was NOT run.  A fuzzer that quietly skips part of its
            //  corpus reports coverage it does not have.
            if (nSkipped)
                std::printf("[fuzz] corpus: %u file(s) SKIPPED - unreadable, empty, "
                            "or larger than %u bytes\n", nSkipped, kFuzzCorpusMax);
            if (nUnlisted)
                std::printf("[fuzz] corpus: %u file(s) NOT LISTED - the directory "
                            "holds more than %u entries\n", nUnlisted, kFuzzCorpusMaxFiles);
            std::fflush(stdout);
        }

        // ---- replay mode --------------------------------------------------
        if (nReplayCse >= 0)
        {
            if (nReplayCse >= kCases) { Log("SETUP: --replay case out of range"); return 2; }
            Case& oCase = g_aCases[nReplayCse];
            Wire  oW    = oCase.oWire;
            Rng   oRng; oRng.Seed(IterState(nSeed, nReplayCse, nReplayItr));
            if (nReplayItr >= 0) Mutate(&oW, oRng);

            SetCursor(oCase.pszName, nReplayCse, nReplayItr, nSeed, oW);
            std::printf("[fuzz] REPLAY case %d (%s) iteration %d\n",
                        nReplayCse, oCase.pszName, nReplayItr);
            DumpCursor(stdout);

            DriveResult oRes;
            Drive(oW, oRng, oCase.bSplit, &oRes);
            ++aTotals[oRes.eOutcome];
            std::printf("[fuzz] outcome=%s msgs=%d turns=%u fed=%u/%u\n",
                        kOutcomeName[oRes.eOutcome], oRes.nMsgs,
                        oRes.nTurns, oRes.nFed, oW.n);
            if (nReplayItr < 0) CheckExpectation(oCase, oRes);
            if (oRes.eOutcome == OUT_ESCAPED)  Finding("non-P2Pevent exception escaped", "escape");
        }
        // ---- the run ------------------------------------------------------
        else
        {
          //  std::time, NOT std::clock.  --seconds is documented as a
          //  WALL-CLOCK budget and the scheduled campaign sizes its job on
          //  that; std::clock measures CPU time, which on a loaded CI runner
          //  is a different and always smaller number - so a 900-second budget
          //  would quietly run long. p2p_fuzzblock uses std::time for the same
          //  reason and the two must agree.
          const std::time_t tRounds = std::time(0);
          int nRound = 0;
          for (;;)
          {
            for (int c = 0; c < kCases; ++c)
            {
                Case& oCase = g_aCases[c];
                unsigned aCounts[OUT__COUNT];
                for (int i = 0; i < OUT__COUNT; ++i) aCounts[i] = 0;
                //  PER-CASE assert tally.  The budget is a whole-run number,
                //  and a whole-run number that moves cannot say WHERE it moved
                //  - which is the one question worth asking of it, because
                //  "the population is unchanged" is the only thing a green
                //  tick here claims.  Added when the size band (cases 14-17)
                //  took the Windows count from 7,082 to 89,901 and there was
                //  no way to show from the run itself that the increase was
                //  the new cases rather than a regression in the old ones.
                const int nAssertsBeforeCase = g_nAsserts;

                // The seed vector itself, unmutated, with its expectation checked.
                {
                    Rng oRng; oRng.Seed(IterState(nSeed, c, -1));
                    SetCursor(oCase.pszName, c, -1, nSeed, oCase.oWire);
                    DriveResult oRes;
                    Drive(oCase.oWire, oRng, oCase.bSplit, &oRes);
                    ++aCounts[oRes.eOutcome]; ++aTotals[oRes.eOutcome];
                    CheckExpectation(oCase, oRes);
                    if (g_bVerbose)
                        std::printf("[fuzz]   seed vector: %s msgs=%d turns=%u\n",
                                    kOutcomeName[oRes.eOutcome], oRes.nMsgs, oRes.nTurns);
                }

                // The mutants.
                for (int it0 = 0; it0 < nIters; ++it0)
                {
                    //  g_nRoundBase is 0 for the single-round gate, so the
                    //  registered run's iteration numbers - and therefore its
                    //  --replay arguments - are unchanged by continuous mode
                    //  existing.
                    const int it = g_nRoundBase + it0;
                    Rng  oRng; oRng.Seed(IterState(nSeed, c, it));
                    Wire oW = oCase.oWire;
                    Mutate(&oW, oRng);

                    SetCursor(oCase.pszName, c, it, nSeed, oW);
                    DriveResult oRes;
                    Drive(oW, oRng, oCase.bSplit, &oRes);
                    ++aCounts[oRes.eOutcome]; ++aTotals[oRes.eOutcome];

                    if (oRes.eOutcome == OUT_ESCAPED)
                        Finding("a non-P2Pevent exception escaped RecvP2PeerMsg",
                                "escape");
                }

                //  abandon= is how many inputs were ABANDONED at an assert
                //  (a POSIX outcome; always 0 on Windows, where the hook
                //  continues).  asserts= is how many were TRIPPED by this case,
                //  which is the number the budget is made of.  They are printed
                //  side by side because reading either as the other is the
                //  mistake ProductionPlan.md Stage 2 step 7 is about.
                std::printf("[fuzz] %-16s msg=%-5u refused=%-5u starved=%-5u "
                            "stalled=%-5u budget=%-5u abandon=%-5u asserts=%-7d  (%s)\n",
                            oCase.pszName, aCounts[OUT_MSG], aCounts[OUT_REFUSED],
                            aCounts[OUT_STARVED], aCounts[OUT_STALLED],
                            aCounts[OUT_BUDGET], aCounts[OUT_ASSERT],
                            g_nAsserts - nAssertsBeforeCase,
                            oCase.pszTargets);
                std::fflush(stdout);
            }
            ++nRound;

            //  Without --seconds this is exactly one round, which is what the
            //  registered gate wants.  With it, rounds keep coming and the
            //  iteration index climbs, so round N is new inputs rather than the
            //  same ones again - the difference between a campaign and a loop.
            if (nSeconds <= 0) break;
            if ((long)(std::time(0) - tRounds) >= (long)nSeconds) break;
            g_nRoundBase = nRound * (nIters > 0 ? nIters : 1);
          }
          if (nSeconds > 0)
            std::printf("[fuzz] %d round(s) of %d iterations x %d cases\n",
                        nRound, nIters, kCases);
        }

        double dSecs = (double)(std::clock() - tStart) / (double)CLOCKS_PER_SEC;
        std::printf("\n[fuzz] totals[%s]: message=%u refused=%u starved=%u stalled=%u "
                    "budget=%u ESCAPED=%u abandoned=%u   asserts=%d   %.2fs\n",
                    FUZZ_DEPTH_MODEL,
                    aTotals[OUT_MSG], aTotals[OUT_REFUSED], aTotals[OUT_STARVED],
                    aTotals[OUT_STALLED], aTotals[OUT_BUDGET],
                    aTotals[OUT_ESCAPED], aTotals[OUT_ASSERT], g_nAsserts, dSecs);

        // -------------------------------------------------------------------
        //  The coverage figure, named after the model that produced it.
        //  ProductionPlan.md Stage 2 step 7: the exit criterion is that this
        //  cannot be mistaken for the other platform's, so it is never printed
        //  bare - the model name is inside the key, on BOTH platforms, and the
        //  denominator is stated so nobody has to reconstruct it.
        // -------------------------------------------------------------------
        {
            unsigned nInputs = 0;
            for (int i = 0; i < OUT__COUNT; ++i) nInputs += aTotals[i];
            unsigned nFinished = nInputs - aTotals[OUT_ASSERT];
            double   dPct      = nInputs ? (100.0 * (double)nFinished / (double)nInputs) : 0.0;

            std::printf("[fuzz] depth[%s]: %u/%u inputs (%.1f%%) ran to the END of the\n"
                        "       parse; %u were abandoned at an assert.\n",
                        FUZZ_DEPTH_MODEL, nFinished, nInputs, dPct, aTotals[OUT_ASSERT]);
            std::printf("       DO NOT COMPARE THIS WITH THE OTHER PLATFORM'S FIGURE. The tag is\n"
                        "       a property of the BUILD, not of this run: on Windows a violated\n"
                        "       invariant is counted and execution CONTINUES (which is where a\n"
                        "       Release build goes), while off Windows glibc's noreturn\n"
                        "       __assert_fail leaves the trap no way back and the input is\n"
                        "       ABANDONED. Equal percentages would still not mean equal work.\n"
                        "       ESCAPED=%u is likewise only a claim about the inputs that ran.\n",
                        aTotals[OUT_ESCAPED]);
        }

        if (g_nAsserts)
            std::printf("[fuzz] NOTE: %d ASSERT(s) tripped, and the expected number is ZERO.\n"
                        "       Each one means WIRE DATA violated an invariant the code\n"
                        "       believes, reached PRE-AUTH, at a check meant for this\n"
                        "       library's own heaps. Since 2026-08-21 the receive path adopts\n"
                        "       an image through P2PmsgHeap_CreateIOMAGE(pIOmage,nBufferLen),\n"
                        "       which walks it inside an untrusted gate and REFUSES rather\n"
                        "       than asserting - so a trip here says either the gate was not\n"
                        "       entered on this path, or a check was added outside it.\n"
                        "       Replay the printed case and find out which.\n", g_nAsserts);
        // The POSIX-only "N inputs were abandoned" note that used to sit here
        // has been folded into the depth[] block above, which prints on BOTH
        // platforms. Printing it only off Windows was itself part of the
        // problem the step names: a Windows run said nothing about its own
        // depth model, so its totals line looked like the neutral one and the
        // Linux line looked like the annotated exception to it. Neither is
        // neutral.

        // -------------------------------------------------------------------
        //  The assert budget. See g_nAssertBase for why this is a baseline
        //  rather than a zero-tolerance gate.
        // -------------------------------------------------------------------
        if (g_nAssertBase >= 0)
        {
            const int nOver = g_nAsserts - g_nAssertBase;
            if (nOver > 0)
            {
                //  A REGRESSION: more invariants are being violated than when
                //  the baseline was recorded. Count the excess -- not the whole
                //  population -- so the finding count names what changed.
                //
                //  With the baseline at 0 the excess IS the population, and the
                //  wording below still holds: something widened what hostile
                //  wire data can reach. The likeliest cause is now a specific
                //  one -- a receive path that adopts an image through the
                //  pointer-only P2PmsgHeap_CreateIOMAGE, so the walks run as
                //  assertions instead of as a gate. See the banner at the top.
                std::printf(
                  "\n[fuzz] ASSERT BUDGET: %d tripped, baseline %d -> REGRESSION by %d.\n"
                  "       Something widened what hostile wire data can reach. This is the\n"
                  "       one thing the budget exists to catch; do not raise the baseline\n"
                  "       to clear it without saying what changed and why it is acceptable.\n",
                  g_nAsserts, g_nAssertBase, nOver);
                g_nFindings += nOver;
            }
            else if (g_nAssertBase == 0 && g_nAsserts == 0)
            {
                //  The state this gate was built to reach, and it took three
                //  goes to get here -- see g_nAssertBase for the other two.
                std::printf(
                  "\n[fuzz] ASSERT BUDGET: 0 tripped, baseline 0 -> CLEAN.\n"
                  "       No wire datum reached a check meant for this library's own\n"
                  "       heaps. That is a property of the receive path, not of this\n"
                  "       harness: the image is adopted through the length-validated\n"
                  "       P2PmsgHeap_CreateIOMAGE, which walks it inside an untrusted\n"
                  "       gate and refuses instead of asserting. ProductionPlan.md\n"
                  "       Stage 1 step 4, closed 2026-08-21.\n");
#if defined(NDEBUG)
                //  Kept, and it says more here than it used to. Zero from a
                //  Release run is not evidence of anything: ASSERT is compiled
                //  out, so a clean run and a broken one both report it. What a
                //  Release run DOES prove is next to it on the totals line --
                //  the refused/message counts, which must match the Debug run
                //  frame for frame now that the walks decide in both builds.
                std::printf(
                  "[fuzz] The assert tally is NOT MEANINGFUL in this configuration: ASSERT\n"
                  "       is compiled out, so zero is what a clean run and a broken one\n"
                  "       both report. The figures that ARE meaningful here are message=\n"
                  "       and refused= above: they must equal the Debug run's exactly.\n");
#endif
            }
            else
            {
                std::printf(
                  "\n[fuzz] ASSERT BUDGET: %d tripped, baseline %d -> within budget.\n"
                  "       THIS IS NOT A CLEAN RESULT. All a green tick here claims is that\n"
                  "       the population is unchanged.\n",
                  g_nAsserts, g_nAssertBase);

                //  Ratchet. A baseline that only ever moves up stops meaning
                //  anything, so a genuine improvement is reported as work to
                //  finish rather than absorbed silently. This is the mechanism
                //  that walked the Windows baseline 89,901 -> 0.
                //
                //  NOT IN A BUILD WITH ASSERT COMPILED OUT. Release trips zero
                //  by construction, so an unguarded ratchet here advises
                //  "lower it to 0" -- which, followed at the time, would have
                //  put the Debug suite permanently red again. Caught by running
                //  it: the advice appeared on the first Release run of this
                //  gate. It is only correct to follow from a DEBUG run, which
                //  is where the 0 in CMakeLists.txt now comes from.
#if defined(NDEBUG)
                std::printf(
                  "[fuzz] The budget is NOT MEANINGFUL in this configuration: ASSERT is\n"
                  "       compiled out, so zero is what a clean run and a broken one both\n"
                  "       report. Do not lower the baseline from a Release run. The number\n"
                  "       that gates is the Debug one.\n");
#else
                if (nOver < 0)
                    std::printf(
                      "[fuzz] RATCHET: %d fewer than the baseline. Lower it to %d in\n"
                      "       MscsUnitTests/CMakeLists.txt in the same commit that earned\n"
                      "       the improvement, or the gate goes slack by exactly that much.\n",
                      -nOver, g_nAsserts);
#endif
            }
        }

        if (g_nFindings == 0)
        {
            std::printf(
              "RESULT: PASS - %d frames, no crash, no hang, no escaped exception,\n"
              "  and every seed vector behaved as its comment says it must.\n"
              "  NOTE: this is only meaningful while case 0 (valid) still parses -\n"
              "  a parser that refused everything would pass every other case.\n",
              (int)(aTotals[OUT_MSG] + aTotals[OUT_REFUSED] + aTotals[OUT_STARVED] +
                    aTotals[OUT_STALLED] + aTotals[OUT_ESCAPED] + aTotals[OUT_BUDGET] +
                    aTotals[OUT_ASSERT]));

            //  Say what the pass does NOT mean, on the pass itself. A green
            //  line that omits an open finding is how the finding gets
            //  forgotten, and this harness has already been read as green once
            //  while tripping ~7,900 asserts. It prints only when there is
            //  something to disclose; with the budget at 0 and 0 tripped there
            //  is not, and a caveat that fires on a clean run is the same
            //  training-to-ignore-it problem one level down.
            if (g_nAsserts)
                std::printf(
                  "  PASS DOES NOT MEAN CLEAN: %d assert(s) tripped and are within the\n"
                  "  recorded budget. The pre-auth invariant violations they mark are\n"
                  "  still open (ProductionPlan.md Stage 1 step 4).\n", g_nAsserts);
            nExit = 0;
        }
        else
        {
            std::printf(
              "RESULT: FAIL - %d finding(s) above, seed 0x%08X.\n"
              "  Each one prints the exact case and iteration; replay it with\n"
              "  p2p_fuzzframe 0x%08X --replay <case> <iter>.\n",
              g_nFindings, nSeed, nSeed);
            nExit = 1;
        }
    }

    CleanupP2Pmsg();
    WSACleanup();

    std::printf("Done (exit=%d).\n", nExit);
    std::fflush(stdout);
    return nExit;
}
