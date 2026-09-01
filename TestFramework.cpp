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
// TestFramework.cpp
//
// The runner lifecycle and assertion bookkeeping, shared by every MSCS test
// executable that uses TF_CASE / TF_CHECK.
//
// WHY THIS FILE EXISTS. All of this lived inside TestMain.cpp until the suite
// was split in two (2026-08-14): MscsUnitTests kept the Msgcore and TargetCore
// suites, and the TreeFS / replication / blob / P2PeerUtilityHubs suites moved
// to MscsUnitTestsExternal. Two runners need one framework, and this repository
// has been bitten repeatedly by the alternative -- a second copy that silently
// falls behind the first (the duplicate C wrapper in MSCS_JavaBindings, the two
// divergent DH implementations, the vendored Platform). So there is exactly ONE
// copy of this code and MscsUnitTestsExternal compiles this very file by path.
//
// It owns the process-wide lifecycle every MSCS test relies on:
//   * one CWinApp (MFC requires exactly one per executable),
//   * the P2Pmsg kernel (StartupP2Pmsg / CleanupP2Pmsg),
//   * Winsock,
//   * an assert hook that turns an MFC/CRT ASSERT into a recorded test failure
//     instead of a modal dialog that would hang a headless run.

#include "stdafx.h"

#ifdef _WIN32
#include <crtdbg.h>            // MSVC CRT-debug ASSERT report hooks (Windows only)
#endif

#include "P2Pwin32.h"          // StartupP2Pmsg / CleanupP2Pmsg
#include "TestFramework.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// MFC requires exactly one CWinApp instance per executable. This TU is linked
// into each runner exactly once, so each exe gets exactly one.
CWinApp theApp;

// ---------------------------------------------------------------------------
// Framework state
// ---------------------------------------------------------------------------
TestStats g_tf;

static const char* s_currentCase        = "(none)";
static int         s_caseFailureBaseline = 0;

void tf_begin_case(const char* name)
{
    s_currentCase        = name;
    s_caseFailureBaseline = g_tf.failures;
    ++g_tf.cases;
    printf("  - %s\n", name);
    fflush(stdout);
}

void tf_end_case()
{
    if (g_tf.failures > s_caseFailureBaseline)
        ++g_tf.caseFailures;
    s_currentCase = "(none)";
}

void tf_fail(const char* file, int line, const char* expr)
{
    ++g_tf.failures;
    printf("      FAIL [%s]  %s\n", s_currentCase, expr);
    printf("           at %s:%d\n", file, line);
    fflush(stdout);
}

// ---------------------------------------------------------------------------
// Assert trap: fold a debug ASSERT into a failure of the current case and
// let execution continue (return TRUE + retVal 0 = "handled, do not break").
// Without this a single internal ASSERT would pop a modal dialog and stall
// the whole headless run.
// ---------------------------------------------------------------------------
#ifdef _WIN32
static int __cdecl AssertReportHook(int nReportType, char* szMsg, int* pnRet)
{
    if (nReportType == _CRT_ASSERT)
    {
        ++g_tf.failures;
        printf("      ASSERT [%s]  %s\n",
               s_currentCase, szMsg ? szMsg : "(no message)");
        fflush(stdout);
        if (pnRet) *pnRet = 0;   // do not invoke the debugger
        return TRUE;             // handled -> continue execution
    }
    return FALSE;                // let other report types flow normally
}
#endif  // _WIN32

// ---------------------------------------------------------------------------
bool tf_runner_startup(const char* title)
{
#ifdef _WIN32
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
    _CrtSetReportHook(AssertReportHook);
#endif

    printf("=== %s ===\n", title);
    fflush(stdout);

    if (!StartupP2Pmsg(16))
    {
        printf("FATAL: StartupP2Pmsg() failed.\n");
        return false;
    }
    WSADATA oWsaData;
    WSAStartup(MAKEWORD(2, 2), &oWsaData);
    return true;
}

// A reduced run is not a pass.  Exit codes: 0 = every suite ran and passed,
// 1 = a check failed, 2 = everything that ran passed but suites were compiled
// out.  2 is distinct so a caller can tell "broken" from "incomplete"; both
// are non-zero, so ctest and any other pass/fail consumer treat them alike.
int tf_runner_finish(int nSkipped)
{
    WSACleanup();
    CleanupP2Pmsg();

    printf("\n=== Summary ===\n");
    printf("  cases   : %d  (%d with failures)\n", g_tf.cases, g_tf.caseFailures);
    printf("  checks  : %d  (%d failed)\n", g_tf.checks, g_tf.failures);
    printf("  skipped : %d suite(s)\n", nSkipped);
    printf("  result  : %s\n", g_tf.failures ? "FAIL"
                             : nSkipped      ? "INCOMPLETE"
                                             : "PASS");
    if (nSkipped && !g_tf.failures)
        printf("            %d suite(s) were compiled out (see SKIPPED above), so this\n"
               "            run does not prove the tree is green.  Exiting 2.\n", nSkipped);
    fflush(stdout);

    return g_tf.failures ? 1 : (nSkipped ? 2 : 0);
}
