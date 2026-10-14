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
// p2p_hubdtorreport.cpp - does ~P2PeerHub REPORT a hub destroyed with its
// spawned pump still running, as its own comment promises, rather than abort?
//
// BACKGROUND - Targetcore 3.4.1, found 2026-10-14 by _OldExamples\AKAssms. Since
// F-TSAN-2 (2026-09-17) ~P2PeerHub checks for a spawned pump thread that is
// still running, and its comment says why it REPORTS instead of asserting:
// "aborting turns a reported defect into a Debug-only crash in every consumer
// that has the bug today". But the report was ONE P2Pevent::Message() of about
// 320 characters, and Msgcore's P2Pevent::Message() VERIFYs that one formatted
// line is under 255. So in every Debug build the report failed that VERIFY and
// the CRT aborted the process - exit code 3, at shutdown, with nothing logged.
// AKAssms (a hub with an empty most-derived destructor) died exactly so.
//
// WHAT IT DOES - a plain P2PeerHub, no connections, auth off.
//
//   Phase 1 (POSITIVE CONTROL): spawn, CloseHub(), delete. The ordinary
//   lifecycle must arm, run and tear down with no CRT assertion. If it does not,
//   nothing below means anything.
//
//   Phase 2 (THE REPORT): spawn, and delete WITHOUT CloseHub(). The pump thread
//   is checked to be still running just before the delete, so the destructor's
//   report path is the one taken. A plain P2PeerHub is its own most-derived
//   class, so there is no derived object for the pump to race - the report is
//   exercised without the race it describes. The destructor must return, the
//   pump thread must be gone, and NO CRT assertion may have fired.
//
// The assertion count comes from a CRT report hook, which also keeps a failing
// ASSERT from opening a modal dialog in a headless run. On Linux there is no
// such hook and MFC's VERIFY is not the CRT's: phase 2 still has to return and
// stop the pump, which is the half that platform can measure.
//
// VERDICT = process EXIT CODE:
//   0  PASS          both phases clean
//   1  FAIL          phase 2 tripped an assertion, or left the pump running
//   2  SETUP         StartupP2Pmsg / SpawnHub failed
//   3  INCONCLUSIVE  phase 1 (the positive control) tripped an assertion

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "Msgexception.h"

#ifdef _WIN32
#  include <crtdbg.h>
#endif

#include <atomic>
#include <cstdio>

static std::atomic<int> g_nAsserts ( 0 );

static void Log ( const char *msg )
{
    std::printf ( "%s\n", msg );
    std::fflush ( stdout );
}

#ifdef _WIN32
static int __cdecl AssertReportHook ( int nReportType, char *szMsg, int *pnRet )
{
    if ( nReportType == _CRT_ASSERT )
    {
        g_nAsserts.fetch_add ( 1 );
        std::fflush ( stdout );
        std::fprintf ( stderr, "[hubdtorreport] ASSERT: %s", szMsg ? szMsg : "(none)\n" );
        std::fflush ( stderr );
        if ( pnRet ) *pnRet = 0;     // do not launch the debugger
        return TRUE;                 // handled: continue, as Release would
    }
    return FALSE;
}
#endif

// Spawn a hub with auth off: it holds no connection, so nothing here depends on
// who a peer is, and an unprovisioned hub would otherwise refuse to arm.
static HANDLE Spawn ( P2PeerHub *pHub )
{
    pHub -> RequireAuth ( false );
    pHub -> RequireSeal ( false );
    return pHub -> SpawnHub ( );
}

int main ( int, char *[] )
{
    Log ( "p2p_hubdtorreport: ~P2PeerHub reports a running pump instead of aborting" );
#ifdef _WIN32
    _CrtSetReportHook ( AssertReportHook );
#endif
    if ( !StartupP2Pmsg ( 8 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }

    // Phase 1 - the positive control
    {
        P2PeerHub *pHub = new P2PeerHub ( L"Dtor.Control" );
        HANDLE hThread = Spawn ( pHub );
        if ( !hThread ) { Log ( "SETUP: SpawnHub() failed (control)" ); delete pHub; CleanupP2Pmsg ( ); return 2; }
        pHub -> CloseHub ( );
        delete pHub;
        WaitForSingleObject ( hThread, 5000 );
        CloseHandle ( hThread );
    }
    const int nControl = g_nAsserts.load ( );
    if ( nControl != 0 )
    {
        std::printf ( "INCONCLUSIVE: the ordinary spawn/CloseHub/delete tripped %d assertion(s)\n", nControl );
        CleanupP2Pmsg ( );
        return 3;
    }
    Log ( "  ok    phase 1: spawn, CloseHub(), delete - no assertion" );

    // Phase 2 - delete with the pump still running
    bool bWasRunning = false, bStopped = false;
    {
        P2PeerHub *pHub = new P2PeerHub ( L"Dtor.Report" );
        HANDLE hThread = Spawn ( pHub );
        if ( !hThread ) { Log ( "SETUP: SpawnHub() failed (report)" ); delete pHub; CleanupP2Pmsg ( ); return 2; }
        bWasRunning = WaitForSingleObject ( hThread, 0 ) == WAIT_TIMEOUT;
        delete pHub;                                        // no CloseHub() - on purpose
        bStopped = WaitForSingleObject ( hThread, 5000 ) == WAIT_OBJECT_0;
        CloseHandle ( hThread );
    }
    const int nReport = g_nAsserts.load ( ) - nControl;

    int nFail = 0;
    if ( !bWasRunning ) { Log ( "  FAIL  phase 2: the pump had already left - the report path was not taken" ); ++nFail; }
    else                  Log ( "  ok    phase 2: the pump was still running at the delete" );
    if ( !bStopped )    { Log ( "  FAIL  phase 2: the pump thread was still running after the destructor" ); ++nFail; }
    else                  Log ( "  ok    phase 2: the destructor closed the hub and the pump left" );
    if ( nReport != 0 )
    {
        std::printf ( "  FAIL  phase 2: %d assertion(s) - the report aborts a Debug build instead of reporting\n", nReport );
        ++nFail;
    }
    else
        Log ( "  ok    phase 2: reported without tripping an assertion" );

    CleanupP2Pmsg ( );
    Log ( nFail ? "FAIL" : "PASS" );
    return nFail ? 1 : 0;
}
