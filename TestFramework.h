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
// TestFramework.h
//
// A tiny, dependency-free assertion harness for the MSCS libraries.
//
// Why not a real framework: the MSCS libs are MFC DLLs that must be linked
// and initialised (StartupP2Pmsg / CWinApp) inside a single process, so the
// simplest reliable runner is one console exe that owns that lifecycle. This
// header gives just enough structure -- named cases and counted checks -- to
// turn the ad-hoc smoke code in MsgcoreTests.cpp into pass/fail reporting.
//
// Reporting is via narrow printf using %ls for wide strings, which is valid
// on a default (non _O_U16TEXT) Windows console. The process exit code is 0
// only when every check passed.
#pragma once

struct TestStats
{
    int checks        = 0;   // individual TF_CHECK evaluations
    int failures      = 0;   // checks that failed
    int cases         = 0;   // test cases entered
    int caseFailures  = 0;   // cases with at least one failed check
};

extern TestStats g_tf;

// Case lifecycle. Prefer the TF_CASE scope guard below over calling directly.
void tf_begin_case(const char* name);
void tf_end_case();

// Records a failed check (also used by the assert hook to fold an MFC/CRT
// ASSERT into the current case as a failure instead of aborting the run).
void tf_fail(const char* file, int line, const char* expr);

// RAII scope guard: `TF_CASE("name") { ... checks ... }`
struct TfCaseGuard
{
    TfCaseGuard(const char* name) { tf_begin_case(name); }
    ~TfCaseGuard()                { tf_end_case(); }
    operator bool() const         { return true; }
};

#define TF_CONCAT_(a, b) a##b
#define TF_CONCAT(a, b)  TF_CONCAT_(a, b)
#define TF_CASE(name)    if (TfCaseGuard TF_CONCAT(_tfcase_, __LINE__) = TfCaseGuard(name))

#define TF_CHECK(cond)                                             \
    do {                                                           \
        ++g_tf.checks;                                             \
        if (!(cond)) tf_fail(__FILE__, __LINE__, #cond);           \
    } while (0)

#define TF_CHECK_EQ(a, b)                                          \
    do {                                                           \
        ++g_tf.checks;                                             \
        if (!((a) == (b)))                                         \
            tf_fail(__FILE__, __LINE__, #a " == " #b);             \
    } while (0)

// Runner lifecycle, implemented in TestFramework.cpp -- which is compiled into
// BOTH this directory's unit_suite and MscsUnitTestsExternal's, by path, so the
// two runners cannot drift apart. Returns false if the P2Pmsg kernel would not
// start; tf_runner_finish returns the process exit code (0 pass, 1 failure,
// 2 = everything that ran passed but suites were compiled out).
bool tf_runner_startup(const char* title);
int  tf_runner_finish(int nSkipped);

// Suite entry points, defined in their respective .cpp files.
//
// Only the suites this directory OWNS are declared here. The TreeFS,
// replication, blob and P2PeerUtilityHubs suites moved to
// MscsUnitTestsExternal on 2026-08-14 and are declared in its ExternalSuites.h
// -- deliberately not left behind as dangling declarations, which would read
// like this runner still had them.
void RunMsgcoreSuite();
void RunMsgcoreCApiSuite();
void RunTargetCoreSuite();
