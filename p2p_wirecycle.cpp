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
// p2p_wirecycle.cpp — a received frame whose OBJECT GRAPH is forged into a
// cycle, or nested abusively deep, must not HANG or CRASH the readers. F-P6-6.
//
// ---------------------------------------------------------------------------
// THE DEFECT (measured 2026-11-24, p2p_performance_progress.md F-P6-6)
//
//   The ingress heap walk (P2PmsgHeap_CreateIOMAGE with the buffer extent,
//   finding F12-F14) proves the BLOCK structure of a received frame: every
//   block is in bounds, the free list terminates, the sizes add up. It does
//   NOT walk the OBJECT GRAPH those blocks form. A frame can pass it and still
//   carry:
//
//     * a sibling chain whose aNext/aPrev links loop back on themselves, so
//       the first reader to walk the siblings never terminates, or
//     * a descendant/attribute pointer that aims a child back at an ancestor,
//       so the first reader to recurse into it never returns.
//
//   Both are reached PRE-DISPATCH on the ordinary receive path. GetSource() is
//   read for every inbound application message (P2PeerCon::GateAppMsgInbound,
//   routing, the inline-dispatch handoff), and it walks the address node's
//   siblings. A cycle there HUNG the pump thread outright — a one-frame denial
//   of service from any logged-in peer. A forged descendant drove unbounded
//   recursion in AssertValid, a STACK OVERFLOW (0xC00000FD). Neither is caught
//   by the block walk, because neither violates a block invariant: the links
//   are in-bounds addresses of real blocks, just wired into a loop.
//
// THE FIX (F-P6-6)
//
//   Two bounds in Msgcore, on the two axes a forged tree can run away on:
//
//     WIDTH  P3PmsgCurs::Goto (by name and by index, MsgCurs.cpp) counts its
//            steps against the heap's BYTE EXTENT. A chain cannot have more
//            items than the heap has bytes, so a legitimate acyclic walk never
//            reaches the bound while a cycle reaches it for certain. Only an
//            IMAGE heap (one built from wire bytes) is bounded; a process-built
//            SYSTEM heap keeps the unbounded path, since nothing a stranger
//            sent lands on one.
//     DEPTH  P3PmsgAssertDepthGuard (P2Pmsg.cpp) caps the AssertValid family's
//            recursion at a fixed, stack-safe nesting depth. Fixed and not the
//            extent because each level spends STACK, which does not scale with
//            the image.
//
//   And the gate that makes them matter: P2PeerCon::GateAppMsgInbound now calls
//   pMsg->AssertValid() — the now-bounded whole-tree walk — on every inbound
//   application message before the source is read, unconditionally (the
//   untrusted path; g_bP2Pmsg_AssertValid governs our own OUTBOUND posts, not
//   this). A forged frame is refused there, which drops the connection.
//
// ---------------------------------------------------------------------------
// WHAT THIS TEST ASSERTS — the DoS property, not a particular refusal
//
//   For each forged frame, every reader either RETURNS or THROWS a P2Pevent.
//   It must do one of those PROMPTLY. It must never:
//
//     * HANG — a non-terminating walk. Caught by a watchdog thread that fires
//       after kHangSeconds of no progress and fails the run. A well-formed
//       frame completes every op in single-digit milliseconds, so a stall is
//       the library looping, not a slow machine.
//     * CRASH — a stack overflow or access violation. A crash exits the process
//       nonzero, which ctest reads as a failure; the Windows filter below names
//       it first.
//
//   A throw is a PASS (the frame is refused and, on the wire, the connection
//   dropped). A clean return is also a PASS: some ops legitimately finish
//   before they reach the cycle — GetSource() on a sibling cycle matches the
//   first sibling and returns — and the property under test is "does not hang
//   or crash", not "throws". Asserting a specific refusal per op would encode
//   the current control flow, not the requirement.
//
//   THE POSITIVE CONTROL (an unforged frame, first) is what proves the harness
//   is real: it must build, and its GetSource / GetDestin / AssertValid must
//   all succeed and read back the addresses the serializer wrote. If the
//   control fails, the forged cases prove nothing and the run is inconclusive.
//
// No socket, no connection: the frames are built by the library's own
// serializer and handed straight to the P2PeerMsg(image,len) ingress
// constructor, exactly as p2p_fuzzframe drives the framing path without one.
//
// USAGE
//   p2p_wirecycle
//   Verdict = process EXIT CODE: 0 PASS, 1 FAIL (hang/crash), 3 INCONCLUSIVE
//   (the positive control failed).
//
// Build (Linux):
//   g++ -std=c++23 -fpermissive -D_UNICODE -DUNICODE -I. -I../Msgcore \
//       -I../Targetcore -I../Msgcore/Platform p2p_wirecycle.cpp \
//       -L../build/Targetcore -ltargetcore -L../build/Msgcore -lmsgcore -luring \
//       -Wl,-rpath,../build/Targetcore -Wl,-rpath,../build/Msgcore -o p2p_wirecycle

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2Peerio.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"

#include <atomic>
#include <cstdio>
#include <cstring>

#ifndef _WIN32
#  include <csignal>
#  include <unistd.h>
#  include <pthread.h>
#endif

// ===========================================================================
//  Liveness + watchdog — the only way a HANG reports itself as a named failure
//  rather than as ctest's bare "Timeout". Modelled on p2p_fuzzframe's.
// ===========================================================================
static std::atomic<unsigned long> g_nProgress { 0 };
static const char*                g_pszWhere  = "startup";
static void Progress(const char* where) { g_pszWhere = where; g_nProgress.fetch_add(1, std::memory_order_relaxed); }

static const unsigned kHangSeconds = 15;

static void WatchdogFired()
{
    std::fflush(stdout);
    std::fprintf(stderr,
        "\n[wirecycle] *** HANG: no progress for %u seconds at '%s' ***\n"
        "RESULT: FAIL - a reader did not return on a forged frame. This is a\n"
        "  NON-TERMINATING WALK in the object model, not a slow test: the\n"
        "  sibling bound (MsgCurs.cpp) or the depth guard (P2Pmsg.cpp) is not\n"
        "  holding. F-P6-6.\n", kHangSeconds, g_pszWhere);
    std::fflush(stderr);
    _exit(1);
}

#ifdef _WIN32
static DWORD WINAPI WatchdogThread(LPVOID)
{
    unsigned long nLast = g_nProgress.load(std::memory_order_relaxed);
    unsigned      nIdle = 0;
    for (;;)
    {
        ::Sleep(250);
        const unsigned long nNow = g_nProgress.load(std::memory_order_relaxed);
        if (nNow != nLast) { nLast = nNow; nIdle = 0; continue; }
        if (++nIdle >= kHangSeconds * 4) WatchdogFired();
    }
}
static void StartWatchdog() { ::CreateThread(0, 0, &WatchdogThread, 0, 0, 0); }

static LONG WINAPI CrashFilter(EXCEPTION_POINTERS* p)
{
    std::fflush(stdout);
    std::fprintf(stderr,
        "\n[wirecycle] *** CRASH: exception 0x%08lX at '%s' ***\n"
        "RESULT: FAIL - a forged frame crashed a reader (0xC00000FD is a stack\n"
        "  overflow: the depth guard is not holding). F-P6-6.\n",
        p ? p->ExceptionRecord->ExceptionCode : 0UL, g_pszWhere);
    std::fflush(stderr);
    return EXCEPTION_EXECUTE_HANDLER;      // terminate with the handler, nonzero
}
static void InstallCrashTrap() { SetUnhandledExceptionFilter(CrashFilter); }
#else
static void* WatchdogThread(void*)
{
    unsigned long nLast = g_nProgress.load(std::memory_order_relaxed);
    unsigned      nIdle = 0;
    for (;;)
    {
        ::usleep(250 * 1000);
        const unsigned long nNow = g_nProgress.load(std::memory_order_relaxed);
        if (nNow != nLast) { nLast = nNow; nIdle = 0; continue; }
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
extern "C" void CrashSignal(int nSig)
{
    std::fflush(stdout);
    std::fprintf(stderr,
        "\n[wirecycle] *** CRASH: signal %d at '%s' *** RESULT: FAIL (F-P6-6)\n",
        nSig, g_pszWhere);
    std::fflush(stderr);
    _exit(1);
}
static void InstallCrashTrap()
{
    signal(SIGSEGV, CrashSignal);
    signal(SIGABRT, CrashSignal);
    signal(SIGILL,  CrashSignal);
}
#endif

// ===========================================================================
//  Frame construction and forgery
// ===========================================================================
static const P2PaddrSTR kSrc = L"Fuzz.Client";
static const P2PaddrSTR kDst = L"Fuzz.Server";

static int  FindU32(const char* p, unsigned v, int nMax)
{ for (int i = 0; i < nMax; i++) { unsigned x; std::memcpy(&x, p + i, 4); if (x == v) return i; } return -1; }
static void PutU32(char* p, unsigned v) { std::memcpy(p, &v, 4); }

// Overwrite a UTF-16LE or byte name in place (same length), so GotoKey can no
// longer match it and the by-name walk must scan every sibling — the case that
// walks a cycle to the end rather than matching its first element.
static bool RenameInPlace(char* b, unsigned n, const char* from, const char* to)
{
    const int L = (int)std::strlen(from);
    bool hit = false;
    for (unsigned i = 0; i + 2 * L <= n; i++)
    {
        bool u16 = true;
        for (int k = 0; k < L; k++) if (b[i + 2 * k] != from[k] || b[i + 2 * k + 1]) u16 = false;
        if (u16) { for (int k = 0; k < L; k++) b[i + 2 * k] = to[k]; hit = true; }
        else if (!std::memcmp(b + i, from, L)) { std::memcpy(b + i, to, L); hit = true; }
    }
    return hit;
}

// The VBItem header is six addresses: aParent,aPrev,aNext,aExtra,aStack,aDescn.
// We locate aNext inside the Src item by searching for the Dst address (the
// serializer links Src->Dst), which also fixes the field offsets relative to it.
struct Forgery { const char* name; bool (*apply)(char* b, unsigned n,
                                                  unsigned aSrc, unsigned aDst, unsigned aNet); };

static int NextOff(const char* b, unsigned aSrc, unsigned aDst)
{ return FindU32(b + aSrc, aDst, 48); }   // offset of aNext within the Src item

static bool ForgeSiblingCycle(char* b, unsigned n, unsigned aSrc, unsigned aDst, unsigned)
{   // Src<->Dst: Dst.aNext = Src, Src.aPrev = Dst  (A<->B loop)
    int o = NextOff(b, aSrc, aDst); if (o < 0) return false;
    PutU32(b + aDst + o,     aSrc);        // Dst.aNext = Src
    PutU32(b + aSrc + o - 4, aDst);        // Src.aPrev = Dst
    (void)n; return true;
}
static bool ForgeSelfLoop(char* b, unsigned n, unsigned aSrc, unsigned aDst, unsigned)
{   // Dst.aNext = Dst, Dst.aPrev = Dst  (1-cycle)
    int o = NextOff(b, aSrc, aDst); if (o < 0) return false;
    PutU32(b + aDst + o,     aDst);
    PutU32(b + aDst + o - 4, aDst);
    (void)n; return true;
}
static bool ForgeRenamedCycle(char* b, unsigned n, unsigned aSrc, unsigned aDst, unsigned)
{   // A<->B loop AND rename Src so a by-name scan for "Src" walks the whole loop
    if (!ForgeSiblingCycle(b, n, aSrc, aDst, 0)) return false;
    return RenameInPlace(b + aSrc, 64, "Src", "Sxc");
}
static bool ForgeDescendantCycle(char* b, unsigned n, unsigned aSrc, unsigned aDst, unsigned aNet)
{   // Aim Src's descendant pointer at NET's descendant collection -> a child
    // that points back at its own ancestor: unbounded recursion if not capped.
    int o = NextOff(b, aSrc, aDst); if (o < 0) return false;
    const int oDescn = o + 12;             // aDescn is three addresses past aNext
    unsigned d; std::memcpy(&d, b + aNet + oDescn, 4);
    if (!d) return false;
    PutU32(b + aSrc + oDescn, d);
    (void)n; return true;
}

static const Forgery kForgeries[] =
{
    { "sibling-cycle",   ForgeSiblingCycle   },
    { "self-loop",       ForgeSelfLoop       },
    { "renamed-cycle",   ForgeRenamedCycle   },
    { "descendant-cycle",ForgeDescendantCycle},
};

// The 2-arg ingress constructor ADOPTS its buffer and frees it when the
// P2PeerMsg is deleted, exactly as P2Peerio::RecvP2PeerMsg relies on (it hands
// over a `new char[nSizeof+4]` and zeroes its own pointer). So every
// construction needs its OWN heap copy - a shared or static buffer would be
// freed by the first delete and read by the next. On an ingress REFUSAL the
// constructor detaches and throws without freeing, so the buffer is still ours.
static P2PeerMsg* AdoptFrame(const char* bytes, unsigned n)
{
    char* heap = new char[n + 4];
    std::memcpy(heap, bytes, n);
    try { return new P2PeerMsg((VBListIOmage*)heap, (VBLsize)n); }
    catch (...) { delete[] heap; throw; }
}

// Run every reader a received message meets on the way in. Each bumps progress
// first, so a hang inside any one is visible to the watchdog. A thrown P2Pevent
// is the designed refusal and is swallowed per op (a refusal on one reader must
// not stop us exercising the others on a fresh copy of the same frame).
static void ExerciseReaders(const char* b, unsigned n, const char* tag)
{
    char op[64];
    auto one = [&](const char* name, void(*fn)(P2PeerMsg*))
    {
        std::snprintf(op, sizeof(op), "%s/%s", tag, name);
        Progress(op);
        P2PeerMsg* r = 0;
        try { r = AdoptFrame(b, n); }
        catch (P2Pevent* e) { e->Cancel(false); return; }   // refused at ingress: fine
        try { fn(r); } catch (P2Pevent* e) { e->Cancel(false); }   // refused by the reader: fine
        delete r;                                            // frees the adopted buffer
    };
    one("GetSource",  [](P2PeerMsg* r){ (void)r->GetSource(); });
    one("GetDestin",  [](P2PeerMsg* r){ (void)r->GetDestin(); });
    one("Map_Match",  [](P2PeerMsg* r){ (void)r->Map_MatchName(P2Pmsg_Login); });
    one("AssertValid",[](P2PeerMsg* r){ r->AssertValid(); });
    one("Exists",     [](P2PeerMsg* r){ (void)r->r_item(VBLockBSTR_NET).Exists(L"zz"); });
    one("Copy",       [](P2PeerMsg* r){ P2PeerMsg q(*r); (void)q; });
}

int main()
{
    std::printf("=== p2p_wirecycle - forged object-graph frames must not hang or crash ===\n");
    std::fflush(stdout);

    InstallCrashTrap();
    if (!StartupP2Pmsg(16)) { std::printf("SETUP: StartupP2Pmsg() failed\n"); return 3; }
    WSADATA oWsa; WSAStartup(MAKEWORD(2, 2), &oWsa);   // no-op shim on Linux
    StartWatchdog();

    // --- Build the base frame with the library's own serializer ----------
    static char  oBase[8192];
    unsigned     nBase = 0;
    unsigned     aSrc = 0, aDst = 0, aNet = 0;
    {
        static const wchar_t kPayload[] = L"wirecycle";
        P2PeerMsg32 oMsg(kSrc, kDst, P2Pmsg_Login, kPayload, (P2Psize_t)sizeof(kPayload));
        oMsg.PrepareP2Piomage(~(DWORD)0);               // full replica: image == live heap layout
        const P2Piomage* pImage = oMsg.P2Piomage();
        if (!pImage) { std::printf("SETUP: P2Piomage() null\n"); return 3; }
        nBase = P2Piomage_Sizeof(pImage);
        if (!nBase || nBase > sizeof(oBase)) { std::printf("SETUP: frame %u does not fit\n", nBase); return 3; }
        std::memcpy(oBase, pImage, nBase);

        // Block addresses of the NET node and its Src/Dst children, read from
        // the live object (same layout as the full-replica image).
        P3PmsgItem& oNet = oMsg.r_item(VBLockBSTR_NET);
        aNet = (unsigned)oNet.r_Object().m_aVBLock;
        aSrc = (unsigned)oNet.SelectItem(L"Src").r_Object().m_aVBLock;
        aDst = (unsigned)oNet.SelectItem(L"Dst").r_Object().m_aVBLock;
    }
    if (aSrc >= nBase || aDst >= nBase || aNet >= nBase)
    { std::printf("SETUP: address out of frame (src=%u dst=%u net=%u n=%u)\n", aSrc, aDst, aNet, nBase); return 3; }
    std::printf("[wirecycle] base frame %u bytes; Src@%u Dst@%u Net@%u\n", nBase, aSrc, aDst, aNet);
    std::fflush(stdout);

    // --- POSITIVE CONTROL: the unforged frame must read back correctly ---
    {
        Progress("control");
        P2PeerMsg* r = 0;
        try { r = AdoptFrame(oBase, nBase); }
        catch (P2Pevent* e) { e->Cancel(false); std::printf("CONTROL: ingress refused a VALID frame\n"); return 3; }
        bool ok = true;
        try {
            P2PaddrSTR s = r->GetSource();
            P2PaddrSTR d = r->GetDestin();
            ok = s && d && !wcscmp(s, kSrc) && !wcscmp(d, kDst);
            r->AssertValid();                            // must not throw on a valid frame
        } catch (P2Pevent* e) { e->Cancel(false); ok = false; }
        delete r;
        if (!ok) { std::printf("CONTROL: a reader failed on a VALID frame - run inconclusive\n"); return 3; }
        std::printf("[wirecycle] positive control OK (source/destin/assert on a valid frame)\n");
        std::fflush(stdout);
    }

    // --- The forged frames: none may hang (watchdog) or crash (exit) -----
    for (const Forgery& f : kForgeries)
    {
        static char oWork[8192];
        std::memcpy(oWork, oBase, nBase);
        if (!f.apply(oWork, nBase, aSrc, aDst, aNet))
        { std::printf("SETUP: could not build forgery '%s'\n", f.name); return 3; }
        std::printf("[wirecycle] exercising forgery: %s\n", f.name);
        std::fflush(stdout);
        ExerciseReaders(oWork, nBase, f.name);
    }

    Progress("done");
    std::printf("\nRESULT: PASS - every forged frame was handled without a hang or a crash.\n");
    std::fflush(stdout);
    return 0;
}
