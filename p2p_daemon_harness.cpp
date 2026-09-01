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
// p2p_daemon_harness.cpp
//
// LinuxPort daemon runtime harness (LinuxPortPlan.md §6.2).
//
// P2PeerService is the Windows-service container for a P2PeerHub. On the Linux port its
// SCM (Service Control Manager) surface is shimmed to no-ops (Platform/p2psvc.h): the
// dispatcher, Install/UnInstall and status calls degrade to no-ops so the console/daemon
// path compiles and links. Compiling/linking was already proven; what was missing was a
// test that the daemon's actual RUNTIME lifecycle works end to end over io_uring:
// construct the service, hand it a real hub payload, bring the hub up the way the
// console-mode Run() path does (SpawnHub), stop it through the service's own control op
// (OnStop -- the same entry the SCM STOP handler invokes on Windows), and tear it down
// cleanly. Verdict = process exit code (0 = SUCCESS), matching the other Linux CTest
// harnesses (dmx/wsa/pipe/232/mix/alex).

#include "stdafx.h"
#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerService.h"

#include <cstdio>
#include <chrono>
#include <thread>

// Minimal daemon hub: no connections and no message map -- the service only needs a
// P2PeerHub payload to bring up and shut down, which is exactly the lifecycle under test.
class DaemonHub : public P2PeerHub
{
public:
    explicit DaemonHub(P2PaddrSTR strAddr) : P2PeerHub(strAddr) {}
    virtual ~DaemonHub() {}
};

// Concrete P2PeerService. The SCM callbacks are unused on Linux (the dispatcher is a
// no-op) and the ctor only stores them, so nullptr is fine.
class TestDaemon : public P2PeerService
{
public:
    TestDaemon() : P2PeerService(L"P2pTestDaemon", nullptr, nullptr) {}
};

static int g_checks = 0, g_fails = 0;
static void check(bool ok, const char* what)
{
    ++g_checks;
    if (!ok) ++g_fails;
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    std::fflush(stdout);
}

int main()
{
    std::printf("p2p_daemon_harness: P2PeerService SCM-shimmed daemon lifecycle (Linux)\n");

    if (!StartupP2Pmsg(16))
    {
        std::printf("FATAL: StartupP2Pmsg() failed.\n");
        return 1;
    }

    {
        TestDaemon svc;

        // The service takes ownership of its hub payload (~P2PeerService deletes it).
        DaemonHub* pHub = new DaemonHub(L"Daemon.Runtime");
        check(svc.PostP2PeerHub(pHub) == pHub, "PostP2PeerHub installs the hub payload");
        check(svc.GetP2PeerHub() == pHub,      "GetP2PeerHub returns the posted hub");

        // Bring the daemon's hub up. The console-mode Run() path spawns the hub exactly
        // this way; SpawnHub is non-blocking and returns the pump-thread handle.
        //
        // RequireAuth(false) because this harness is about the SERVICE lifecycle -
        // post, spawn, reach RUNNING, stop - and its hub never takes a connection.
        // Since ProductionPlan.md Stage 3 step 8 a hub that requires auth and holds
        // no keys refuses to arm, so leaving this out would fail at SpawnHub and
        // report a provisioning gap as a service-lifecycle defect.
        pHub->RequireAuth ( false );
        HANDLE hThread = svc.GetP2PeerHub()->SpawnHub();
        check(hThread != nullptr, "SpawnHub started the hub pump thread");

        bool running = false;
        for (int i = 0; i < 200 && !running; ++i)
        {
            if (svc.GetP2PeerHub()->GetHubID() > 0) running = true;
            else std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        check(running, "daemon hub reached RUNNING (GetHubID > 0)");

        // Stop through the SERVICE control op -- the same OnStop the SCM STOP handler
        // invokes on Windows (a plain virtual call on Linux). It signals the hub to close
        // on idle; with no connections the hub is already idle.
        svc.OnStop();

        // OnStop only signals; close deterministically and confirm the hub is gone.
        svc.GetP2PeerHub()->CloseHub();
        bool stopped = false;
        for (int i = 0; i < 200 && !stopped; ++i)
        {
            if (svc.GetP2PeerHub()->GetHubID() <= 0) stopped = true;
            else std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        check(stopped, "daemon hub reached STOPPED after OnStop + CloseHub (GetHubID <= 0)");

        // Reclaim the pump-thread handle SpawnHub handed back (joins/frees it). This is
        // the correct Win32 idiom; the service's own Run() ignores the handle, so a real
        // daemon leaks it once at shutdown -- a pre-existing minor gap, same on Windows.
        if (hThread) CloseHandle(hThread);

        // svc leaves scope here -> ~P2PeerService deletes pHub (no leak).
    }

    CleanupP2Pmsg();

    std::printf("p2p_daemon_harness: %d checks, %d failure(s)\n", g_checks, g_fails);
    return g_fails ? 1 : 0;
}
