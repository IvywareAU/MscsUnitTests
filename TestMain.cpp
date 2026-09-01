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
// TestMain.cpp
//
// Entry point for the MSCS core unit-test runner: Msgcore and TargetCore.
//
// SCOPE, and why it changed. Until 2026-08-14 this runner also drove the TreeFS,
// replication, blob and P2PeerUtilityHubs suites -- 184 of its 303 cases. Those
// moved to MscsUnitTestsExternal, so this directory now covers exactly the two
// libraries it is named for, and links only msgcore + targetcore + p2pplatform.
// That is not tidying: it is what makes this repository buildable from its own
// dependencies, both of which are published, instead of needing four components
// that are not.
//
// The process-wide lifecycle (CWinApp, the P2Pmsg kernel, Winsock, the assert
// trap) lives in TestFramework.cpp, which both runners compile.

#include "stdafx.h"

#include "TestFramework.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// ---------------------------------------------------------------------------
int main(int /*argc*/, char* /*argv*/[])
{
    if (!tf_runner_startup("MSCS unit tests (Msgcore + TargetCore)"))
        return 1;

    // A suite that is compiled out must SAY SO.  UtilHubsSuite was absent from the
    // Windows .vcxproj for 14 days (a5e9195 -> f7f7d72) and the omission was
    // invisible, because a dropped suite produced output indistinguishable from a
    // clean full run.  Every guard below now has an #else that reports the skip,
    // and the summary refuses to look complete when nSkipped > 0.
    int nSkipped = 0;

    printf("\n[Msgcore]\n");
    RunMsgcoreSuite();

    // The Msgcore C-API suite needs only the Msgcore_c C-API (in libmsgcore).
    // MSCS_NO_CAPI drops it; nothing in the tree defines that today, and the
    // guard is kept because the skip must stay visible if anything ever does.
#ifndef MSCS_NO_CAPI
    printf("\n[Msgcore C API]\n");
    RunMsgcoreCApiSuite();
#else
    printf("\n[Msgcore C API]       SKIPPED (MSCS_NO_CAPI)\n");
    ++nSkipped;
#endif

    printf("\n[TargetCore]\n");
    RunTargetCoreSuite();

    return tf_runner_finish(nSkipped);
}
