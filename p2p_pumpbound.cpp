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
// p2p_pumpbound.cpp - does the queue-full diagnostic tell the truth about the
// bound it just enforced?
//
// BACKGROUND - ProductionPlan.md Stage 0 step 2. s_cP2PmsgMAX was 50000. Seven
// sites in P2Pwin32.cpp tested the depth and ALL SEVEN printed
//
//     "P2Pmsg pump is full, 10000 entries"
//
// The literal had outlived the constant. An operator reading that line was told
// a figure five times too small, and the only way to learn the real one was to
// read the source - which is the opposite of what a diagnostic is for. Two of
// the seven sites were also testing something other than s_cP2PmsgMAX (one a
// hardcoded 10000, one s_cP2PmsgMAX*2), so the file appeared to hold three
// different bounds.
//
// It held one. Established by execution, not by reading:
//   * the hardcoded-10000 site is inside a BLOCK COMMENT (a superseded
//     PostP2Pmsg overload) and does not compile;
//   * the *2 site is in PerformP2PeventNotn, which is exported and called from
//     NOWHERE in the tree. The reading that would have made a doubled band a
//     considered exception - "event delivery needs headroom the ordinary
//     posters have been refused, so the message saying the pump is full can
//     still get out" - is false anyway: a raised P2Pevent reaches a client via
//     P2Pevent::Cancel -> P2PeventPost_HWND, which PostMessage's to a window
//     and calls one static callback. It posts no P2Pmsg and spends none of this
//     budget, so there was nothing for a reserve to protect.
// Both are now the one constant, and every diagnostic renders it.
//
// WHAT THIS TEST ASSERTS, and why it needs no figure of its own. Hardcoding
// 50000 here would just move the literal into the test: lower the constant and
// the test goes red for the wrong reason. So the check is SELF-REFERENTIAL -
// the rendered number is compared against the capacity the run actually
// measured:
//
//   B  = live P2Pmsg count before the run          (GetP2PmsgCount(~0))
//   k  = posts that SUCCEEDED before the throw
//   The guard is `s_cP2Pmsg > s_cP2PmsgMAX`, read BEFORE the message is
//   manufactured, so the first refusal happens when B + k = MAX + 1, i.e.
//
//       MAX  ==  B + k - 1      and      live-at-throw  ==  MAX + 1
//
// A diagnostic naming any other figure fails. Lower s_cP2PmsgMAX, rebuild, and
// this same test passes reporting the new number - that is the falsification
// the plan asks for, and it costs a rebuild rather than an edit here.
//
// THREE PHASES, because the guard has TWO renderings and only one of them can
// break on Linux. The live sites split by the width of their format literal -
// numeric-only messages stay narrow, per rule 3 of p2p_diag_wideformat_sweep.md,
// and the two that were written with Message_T are wide:
//
//   Phase 1 (WIDE)   fills the queue through PostP2Pmsg(P2PeerMsg*,...).
//   Phase 2 (WIDE)   PostP2PmsgBatch(), one post.
//   Phase 3 (NARROW) PostP2Pmsg(DWORD,P2Pmsg_t,WPARAM,LPARAM), one post.
//
// The wide phases are the ones with something to catch: a wide format goes
// through Platform's p2p_fix_wformat on Linux, a rewriter that exists to turn %s
// into %ls and that walks every specifier it meets - so it is exactly what could
// mangle a %lu and print garbage where the bound should be. The narrow phase
// costs one call and covers the other half of the file.
//
// Phases 2 and 3 cost one post each: the queue is still over capacity from phase
// 1, so their guards fire on entry. That matters for phase 3 for a second
// reason - its post path manufactures a P2Pmsg with no pTarget and the following
// ASSERT(VerifyP2Pmsg(...)) would trip on it. The capacity guard sits BEFORE the
// manufacture, so a refused call never reaches it. Do not repurpose phase 3 into
// anything that expects a post to SUCCEED.
//
// The pump is never drained: the hub is created on THIS thread and PumpP2Pmsg()
// is never called, so nothing competes with the loop and the bound is reached
// deterministically rather than by out-running a consumer.
//
// VERDICT = process EXIT CODE:
//   0  PASS   every diagnostic rendered the bound the run measured
//   1  FAIL   a diagnostic named a figure that was not the enforced bound
//   2  SETUP  startup / hub creation failed (test inconclusive)
//   3  INCONCLUSIVE no throw inside the post ceiling, or the queue never
//                   filled far enough for a refusal to mean anything

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"

#include <cstdio>
#include <cstring>
#include <string>

// ---------------------------------------------------------------------------
static const P2PaddrSTR kHubAddr = L"Bound.Hub";
static const P2PaddrSTR kSrcAddr = L"Bound.Src";
static const P2PaddrSTR kDstAddr = L"Bound.Dst";

//  A ceiling on how many posts this will attempt before giving up. It is not a
//  claim about the bound - it is the difference between a failed run and a run
//  that allocates until the machine dies, and it is generous enough that a
//  plausible future bound still fits under it.
static const long kPostCeiling = 5000000L;

//  Below this, a refusal proves nothing: if the FIRST post throws, the setup is
//  broken and "the bound was enforced" is indistinguishable from "posting never
//  worked". This is the positive control, inline, per suite convention.
static const long kMinCredible = 1000L;

static void Log ( const char *msg )
{
    std::printf ( "[pumpbound] %s\n", msg );
    std::fflush ( stdout );
}

// =========================================================================
class BoundHub : public P2PeerHub
{
public:
    BoundHub ( P2PaddrSTR strAddr ) : P2PeerHub ( strAddr ) { }
    virtual ~BoundHub ( ) { }
};

// ---------------------------------------------------------------------------
//  Pull the figure out of a diagnostic: the LAST run of decimal digits in it.
//  NOTES: Deliberately dumb - a parser that understood the sentence would stop
//         noticing the day the sentence changed
//       : LAST, not first. The message is "P2Pmsg pump is full, N entries" and
//         the first digit run is the 2 in "P2Pmsg" - which this test duly
//         reported as the rendered bound on its first run, and is a fair
//         warning about how much of a diagnostic is incidental text
//       : Returns false when the message carries no digits at all - which is
//         what a rendering that lost its argument looks like
static bool LastNumber ( const wchar_t *lpszText, unsigned long &ulOut )
{
    if ( !lpszText ) return false;

    bool bFound = false;
    for ( const wchar_t *p = lpszText; *p; )
    {
      if ( *p < L'0' || *p > L'9' ) { ++p; continue; }

      unsigned long ul = 0;
      for ( ; *p >= L'0' && *p <= L'9'; ++p )
      {
        if ( ul > 0xFFFFFFFFUL / 10 ) return false;    // nonsense, not a bound
        ul = ul * 10 + (unsigned long)( *p - L'0' );
      }
      ulOut  = ul;
      bFound = true;
    }
    return bFound;
}

//  Render a caught P2Pevent's message as narrow text for the log, and hand back
//  the figure it named.
//  NOTES: Cancel(false) is mandatory - Cancel() would Display() the event, and
//         on Windows that is a MessageBox in a headless ctest run
static bool TakeMessage ( P2Pevent *pEVT, std::string &strOut, unsigned long &ulNumber )
{
    strOut.clear ( );
    ulNumber = 0;
    if ( !pEVT ) return false;

    const CString  csMessage = pEVT -> GetMessage ( );
    const wchar_t *lpszText  = (const wchar_t *)csMessage.GetString ( );

    for ( const wchar_t *w = lpszText; w && *w; ++w )
      strOut.push_back ( ( *w >= 32 && *w < 127 ) ? (char)*w : '?' );

    const bool bFound = LastNumber ( lpszText, ulNumber );
    pEVT -> Cancel ( false );
    return bFound;
}

//  The verdict for one refusal that was expected to happen on entry, with the
//  queue already over capacity. Returns the exit code (0 pass, 1 fail).
static int CheckRefusal ( const char *lpszPhase, bool bThrew, bool bHadNumber
                        , unsigned long ulRendered, unsigned long ulMeasured
                        , const std::string &strMessage )
{
    std::printf ( "[pumpbound] %s\n", lpszPhase );
    std::printf ( "[pumpbound]   diagnostic                    : %s\n",
                  bThrew ? strMessage.c_str() : "(never thrown)" );
    std::fflush ( stdout );

    if ( !bThrew )
    {
      std::printf ( "[pumpbound] FAIL: this path accepted a post with the queue already over\n"
                    "            capacity - its guard is not the same bound as phase 1's.\n" );
      std::fflush ( stdout );
      return 1;
    }
    if ( !bHadNumber || ulRendered != ulMeasured )
    {
      std::printf ( "[pumpbound] FAIL: this rendering says %lu, the enforced bound is %lu.\n"
                    "            For a WIDE site on Linux that is where p2p_fix_wformat\n"
                    "            mangling a %%lu would show; otherwise it is a literal that\n"
                    "            has drifted from s_cP2PmsgMAX (ProductionPlan Stage 0\n"
                    "            step 2 reopening).\n", ulRendered, ulMeasured );
      std::fflush ( stdout );
      return 1;
    }
    return 0;
}

// =========================================================================
int main ( int argc, char *argv[] )
{
    (void)argc; (void)argv;

    std::printf ( "=== p2p_pumpbound - does the queue-full diagnostic name the enforced bound? ===\n" );
    std::printf ( "Asserting: the figure printed when a post is refused equals the\n"
                  "           capacity this run actually measured - on both wide\n"
                  "           renderings and on the narrow one.\n\n" );
    std::fflush ( stdout );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }

    int nExit = 2;
    {
        //  The hub is created on THIS thread, which is what registers a pump
        //  here - and this thread then never calls PumpP2Pmsg(), so the queue
        //  only ever grows. SpawnHub() would start a thread that drains it.
        BoundHub oHub ( kHubAddr );
        try
        {
          CreateP2PmsgHub ( kHubAddr, &oHub, 4, 0 );
        }
        catch ( P2Pevent *pEVT )
        {
          std::string strMsg; unsigned long ul = 0;
          TakeMessage ( pEVT, strMsg, ul );
          std::printf ( "[pumpbound] SETUP: CreateP2PmsgHub() threw: %s\n", strMsg.c_str() );
          std::fflush ( stdout );
          CleanupP2Pmsg ( );
          return 2;
        }

        const P2PumpID nPumpID = (P2PumpID)GetCurrentThreadId ( );

        //  The baseline. Not assumed to be zero: StartupP2Pmsg and the hub may
        //  each have left live messages behind, and an assumption here would
        //  turn into an off-by-N in the assertion below.
        const unsigned long ulBase = (unsigned long)GetP2PmsgCount ( (P2PumpID)~0 );
        std::printf ( "[pumpbound] live P2Pmsg count before the run : %lu\n", ulBase );
        std::fflush ( stdout );

        // -----------------------------------------------------------------
        //  PHASE 1 - the narrow rendering, on the ordinary post path.
        // -----------------------------------------------------------------
        static const wchar_t wszBody[] = L"pumpbound";

        long          nPosted    = 0;
        bool          bThrew     = false;
        std::string   strMessage;
        unsigned long ulRendered = 0;
        bool          bHadNumber = false;
        unsigned long ulLiveAtThrow = 0;

        for ( ; nPosted < kPostCeiling; )
        {
          P2PeerMsg32 *pMsg = new P2PeerMsg32 ( kSrcAddr, kDstAddr, P2Pmsg_BCast
                                              , wszBody, (P2Psize_t)sizeof(wszBody) );
          try
          {
            PostP2Pmsg ( pMsg, nPumpID, false );
            nPosted++;
          }
          catch ( P2Pevent *pEVT )
          {
            //  The refused message is already freed - PostP2Pmsg holds it in a
            //  P2PeerMsgSP before the capacity guard, so the throw releases it.
            ulLiveAtThrow = (unsigned long)GetP2PmsgCount ( (P2PumpID)~0 );
            bHadNumber    = TakeMessage ( pEVT, strMessage, ulRendered );
            bThrew        = true;
            break;
          }
        }

        std::printf ( "[pumpbound] phase 1 (wide, PostP2Pmsg(P2PeerMsg*,...))\n" );
        std::printf ( "[pumpbound]   posts accepted before refusal : %ld\n", nPosted );
        std::printf ( "[pumpbound]   live count at the refusal     : %lu\n", ulLiveAtThrow );
        std::printf ( "[pumpbound]   diagnostic                    : %s\n",
                      bThrew ? strMessage.c_str() : "(never thrown)" );
        std::fflush ( stdout );

        if ( !bThrew )
        {
          std::printf ( "[pumpbound] INCONCLUSIVE: %ld posts accepted and no refusal - the\n"
                        "            bound is above this test's ceiling, or is not enforced.\n",
                        kPostCeiling );
          std::fflush ( stdout );
          nExit = 3;
        }
        else if ( nPosted < kMinCredible )
        {
          std::printf ( "[pumpbound] INCONCLUSIVE: only %ld posts were accepted. The positive\n"
                        "            control fails - posting is broken, so a refusal here says\n"
                        "            nothing about the bound.\n", nPosted );
          std::fflush ( stdout );
          nExit = 3;
        }
        else
        {
          //  The measured bound. See the header: the guard reads the count
          //  BEFORE manufacturing, so the last accepted post left the count at
          //  MAX + 1 and the refusal saw it.
          const unsigned long ulMeasured = ulBase + (unsigned long)nPosted - 1;

          std::printf ( "[pumpbound]   bound this run measured       : %lu\n", ulMeasured );
          std::fflush ( stdout );

          nExit = 0;

          if ( !bHadNumber )
          {
            std::printf ( "[pumpbound] FAIL: the diagnostic named no figure at all. A rendering\n"
                          "            that loses its argument is how this defect looks after a\n"
                          "            format change.\n" );
            nExit = 1;
          }
          else if ( ulRendered != ulMeasured )
          {
            std::printf ( "[pumpbound] FAIL: the diagnostic says %lu, the enforced bound is %lu.\n"
                          "            This is ProductionPlan Stage 0 step 2 reopening: a literal\n"
                          "            has drifted from s_cP2PmsgMAX again.\n",
                          ulRendered, ulMeasured );
            nExit = 1;
          }

          //  Cross-check the arithmetic itself rather than trusting it: the
          //  refusal must have seen exactly one message more than the bound.
          if ( nExit == 0 && ulLiveAtThrow != ulMeasured + 1 )
          {
            std::printf ( "[pumpbound] FAIL: live count at refusal is %lu, expected %lu. The\n"
                          "            guard's comparison is not the one this test models, so\n"
                          "            the figure it agreed with proves nothing.\n",
                          ulLiveAtThrow, ulMeasured + 1 );
            nExit = 1;
          }

          // ---------------------------------------------------------------
          //  PHASE 2 - the other WIDE site. The queue is still over capacity,
          //  so one batch post is refused on entry.
          // ---------------------------------------------------------------
          if ( nExit == 0 )
          {
            P2PeerMsg32 *pBatchMsg = new P2PeerMsg32 ( kSrcAddr, kDstAddr, P2Pmsg_BCast
                                                     , wszBody, (P2Psize_t)sizeof(wszBody) );
            P2PeerMsg   *apMsg[1]  = { pBatchMsg };

            std::string   strBatch;
            unsigned long ulBatch     = 0;
            bool          bBatchThrew = false;
            bool          bBatchNum   = false;
            try
            {
              PostP2PmsgBatch ( apMsg, 1, nPumpID );
            }
            catch ( P2Pevent *pEVT )
            {
              bBatchNum   = TakeMessage ( pEVT, strBatch, ulBatch );
              bBatchThrew = true;
            }

            nExit = CheckRefusal ( "phase 2 (wide, PostP2PmsgBatch)", bBatchThrew
                                 , bBatchNum, ulBatch, ulMeasured, strBatch );
          }

          // ---------------------------------------------------------------
          //  PHASE 3 - the NARROW site. One call, refused on entry: see the
          //  header for why this phase must never expect a post to succeed.
          // ---------------------------------------------------------------
          if ( nExit == 0 )
          {
            std::string   strNarrow;
            unsigned long ulNarrow     = 0;
            bool          bNarrowThrew = false;
            bool          bNarrowNum   = false;
            try
            {
              PostP2Pmsg ( (DWORD)nPumpID, (P2Pmsg_t)P2Pmsg_BCast, (WPARAM)0, (LPARAM)0 );
            }
            catch ( P2Pevent *pEVT )
            {
              bNarrowNum   = TakeMessage ( pEVT, strNarrow, ulNarrow );
              bNarrowThrew = true;
            }

            nExit = CheckRefusal ( "phase 3 (narrow, PostP2Pmsg(DWORD,...))", bNarrowThrew
                                 , bNarrowNum, ulNarrow, ulMeasured, strNarrow );
          }

          if ( nExit == 0 )
          {
            std::printf ( "\n[pumpbound] PASS: all three renderings named %lu, the bound this\n"
                          "            run enforced.\n", ulMeasured );
            std::fflush ( stdout );
          }
        }

        //  Teardown. The queue is left holding everything that was accepted -
        //  that is the point of the run, and freeing it is CloseP2PmsgHub's job.
        Log ( "teardown begin" );
        try { CloseP2PmsgHub ( ); }
        catch ( P2Pevent *pEVT ) { if ( pEVT ) pEVT->Cancel ( false ); }
    }
    CleanupP2Pmsg ( );

    std::printf ( "[pumpbound] exit=%d\n", nExit );
    std::fflush ( stdout );
    return nExit;
}
