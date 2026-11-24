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
// shm_xproc.cpp — the SHARED-MEMORY transport (P2PeerConShm, p2p_performance.md §6.3a)
// between two PROCESSES, which is what it is for. shm_mesh proves the byte path in one
// process; this proves the handover across a process boundary (DuplicateHandle into
// the pipe client's process / SCM_RIGHTS) and what only a second process can show:
//
//   phase 1 TRAFFIC  - a child client sends 300 messages of 16 B .. 20,000 B, posted
//                      at once, so the 64 KB ring fills and writers park. The server
//                      checks every byte of every message, then answers "done" back
//                      over the same link, which the child must receive to exit 0.
//   phase 2 DEATH    - a second child sends a few messages and kills ITSELF without
//                      closing anything (TerminateProcess / _exit). The server must
//                      see that connection close within 5 s - the pipe's death watch,
//                      the only thing that can tell it - and must not hang.
//   phase 3 SURVIVAL - a third child connects to the same listener and completes a
//                      message both ways: the service outlived a dead peer.
//
// One executable: run without arguments it is the SERVER and launches itself as each
// child ("--client <pipe> <count> <die>"). The pipe name carries the server's pid, so
// parallel runs cannot meet.
//
// Verdict = process EXIT CODE: 0 PASS | 1 FAIL | 3 TIMEOUT / INCONCLUSIVE.
//
#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConShm.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#if !defined(_WIN32)
#  include <spawn.h>
#  include <sys/wait.h>
#  include <signal.h>
#  include <unistd.h>
extern char **environ;
#endif

static const P2PaddrSTR kServerAddr = L"ShmXproc.Server";
static const P2PaddrSTR kClientAddr = L"ShmXproc.Client";
static const int        kSizes[]    = { 16, 512, 4000, 12000, 20000 };

static void Log ( const char *role, const char *msg )
{
    std::printf ( "[%s] %s\n", role, msg );
    std::fflush ( stdout );
}

//  Payload of message `seq`: its size cycles through kSizes; byte j is (seq*31 + j).
static std::vector<unsigned char> Payload ( int seq )
{
    std::vector<unsigned char> v ( kSizes[seq % 5] );
    for ( size_t j = 0; j < v.size ( ); ++j ) v[j] = (unsigned char)( seq * 31 + j );
    std::memcpy ( v.data ( ), &seq, sizeof seq );
    return v;
}

static bool Check ( P2PeerMsg *pMsg, int &seqOut )
{
    if ( !pMsg || !pMsg->Data ( ) || pMsg->DataSize ( ) < (int)sizeof ( int ) ) return false;
    int seq = 0;
    std::memcpy ( &seq, pMsg->Data ( ), sizeof seq );
    if ( seq < 0 || seq > 1000000 ) return false;
    std::vector<unsigned char> want = Payload ( seq );
    if ( (size_t)pMsg->DataSize ( ) != want.size ( ) ) return false;
    if ( std::memcmp ( pMsg->Data ( ), want.data ( ), want.size ( ) ) ) return false;
    seqOut = seq;
    return true;
}

// =========================================================================
//  SERVER
class ServerHub : public P2PeerHub
{
public:
    explicit ServerHub ( P2PaddrSTR a ) : P2PeerHub ( a ) {}
    std::atomic<int>  good { 0 }, bad { 0 }, closes { 0 };
    std::atomic<bool> wantDone { false };
    int               expect = 0;
    HANDLE            evCount = nullptr, evClose = nullptr;

protected:
    virtual msgRESULT On_P2PeerBCast ( P2PeerMsg *pMsg ) override
    {
        int seq = -1;
        if ( Check ( pMsg, seq ) ) good++;
        else                       bad++;
        if ( wantDone && good.load ( ) == expect )
        {
            const char done[] = "done";
            PostP2PeerMsg ( new P2PeerMsg32 ( kServerAddr, kClientAddr, P2Pmsg_BCast, done, (P2Psize_t)sizeof done ) );
            SetEvent ( evCount );
        }
        return msgHANDLED;
    }
    virtual conRESULT On_ConClose ( P2PeerCon *pCon ) override
    {
        if ( pCon && pCon->GetMode ( ) != P2PeerCon_SERVICE ) { closes++; SetEvent ( evClose ); }
        return P2PeerHub::On_ConClose ( pCon );
    }
};

// =========================================================================
//  CLIENT (the child process)
class ClientHub : public P2PeerHub
{
public:
    ClientHub ( P2PaddrSTR a, int n, bool die ) : P2PeerHub ( a ), m_n ( n ), m_die ( die ) {}
    HANDLE evDone = nullptr;

protected:
    virtual conRESULT On_ConLoginAck ( P2PeerCon *pCon, P2PaddrSTR a, P2PaddrSTR b,
                                       const void *pv, P2Psize_t n ) override
    {
        conRESULT r = P2PeerHub::On_ConLoginAck ( pCon, a, b, pv, n );
        for ( int seq = 0; seq < m_n; ++seq )
        {
            std::vector<unsigned char> p = Payload ( seq );
            PostP2PeerMsg ( new P2PeerMsg32 ( kClientAddr, kServerAddr, P2Pmsg_BCast,
                                              p.data ( ), (P2Psize_t)p.size ( ) ) );
        }
        if ( m_die )
        {
            //  From ANOTHER thread, so this pump keeps writing until the process
            //  vanishes: the death lands mid-stream, not before the first write
            std::thread ( [] {
                Sleep ( 30 );
                std::fflush ( stdout );
#if defined(_WIN32)
                TerminateProcess ( GetCurrentProcess ( ), 7 );
#else
                _exit ( 7 );
#endif
            } ).detach ( );
        }
        return r;
    }
    virtual msgRESULT On_P2PeerBCast ( P2PeerMsg *pMsg ) override
    {
        if ( pMsg && pMsg->DataSize ( ) == 5 && !std::memcmp ( pMsg->Data ( ), "done", 5 ) )
            SetEvent ( evDone );
        return msgHANDLED;
    }

private:
    int  m_n;
    bool m_die;
};

static int ClientMain ( const char *pipeName, int n, bool die )
{
    if ( !StartupP2Pmsg ( 8 ) ) return 1;
    std::wstring wpipe;
    for ( const char *p = pipeName; *p; ++p ) wpipe.push_back ( (wchar_t)*p );
    ClientHub hub ( kClientAddr, n, die );
    hub.evDone = CreateEvent ( NULL, FALSE, FALSE, NULL );
    hub.RequireAuth ( false );
    HANDLE hThread = hub.SpawnHub ( );
    if ( !hThread ) return 1;
    hub.PostP2PeerCon ( P2PeerConShm::ClientFactory ( kServerAddr, wpipe.c_str ( ) ) );
    int rc = WaitForSingleObject ( hub.evDone, 20000 ) == WAIT_OBJECT_0 ? 0 : 3;
    hub.CloseHub ( );
    WaitForSingleObject ( hThread, 3000 );
    CloseHandle ( hThread );
    CloseHandle ( hub.evDone );
    CleanupP2Pmsg ( );
    return rc;
}

// =========================================================================
//  Launching a child: this executable with --client
#if defined(_WIN32)
typedef HANDLE Child;
static Child Launch ( const std::string &pipe, int n, int die )
{
    char exe[MAX_PATH];
    GetModuleFileNameA ( nullptr, exe, MAX_PATH );
    std::string cmd = std::string ( "\"" ) + exe + "\" --client " + pipe + " " +
                      std::to_string ( n ) + " " + std::to_string ( die );
    std::vector<char> buf ( cmd.begin ( ), cmd.end ( ) ); buf.push_back ( 0 );
    STARTUPINFOA si {}; si.cb = sizeof si;
    PROCESS_INFORMATION pi {};
    if ( !CreateProcessA ( nullptr, buf.data ( ), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi ) )
        return nullptr;
    CloseHandle ( pi.hThread );
    return pi.hProcess;
}
static int Reap ( Child c, DWORD ms )
{
    if ( !c ) return -1;
    DWORD code = 99;
    if ( WaitForSingleObject ( c, ms ) != WAIT_OBJECT_0 ) { TerminateProcess ( c, 99 ); code = 98; }
    else GetExitCodeProcess ( c, &code );
    CloseHandle ( c );
    return (int)code;
}
#else
typedef pid_t Child;
static Child Launch ( const std::string &pipe, int n, int die )
{
    std::string sn = std::to_string ( n ), sd = std::to_string ( die );
    char *argv[] = { (char *)"shm_xproc", (char *)"--client", (char *)pipe.c_str ( ),
                     (char *)sn.c_str ( ), (char *)sd.c_str ( ), nullptr };
    pid_t pid = 0;
    std::fflush ( stdout );
    if ( posix_spawn ( &pid, "/proc/self/exe", nullptr, nullptr, argv, environ ) != 0 ) return -1;
    return pid;
}
static int Reap ( Child c, DWORD ms )
{
    if ( c <= 0 ) return -1;
    for ( DWORD t = 0; t < ms; t += 50 )
    {
        int st = 0;
        if ( waitpid ( c, &st, WNOHANG ) == c )
            return WIFEXITED ( st ) ? WEXITSTATUS ( st ) : 128 + WTERMSIG ( st );
        Sleep ( 50 );
    }
    kill ( c, SIGKILL );
    waitpid ( c, nullptr, 0 );
    return 98;
}
#endif

// =========================================================================
int main ( int argc, char *argv[] )
{
    if ( argc >= 5 && std::strcmp ( argv[1], "--client" ) == 0 )
        return ClientMain ( argv[2], std::atoi ( argv[3] ), std::atoi ( argv[4] ) != 0 );

    std::printf ( "=== shm_xproc - the shared-memory transport between two processes ===\n" );
    if ( !P2PeerConShm::IsSupported ( ) ) { Log ( "MAIN", "SETUP: transport unsupported here" ); return 3; }
    std::string pipe = "\\\\.\\pipe\\P2PshmXproc_" + std::to_string ( (unsigned long)GetCurrentProcessId ( ) );
    std::wstring wpipe ( pipe.begin ( ), pipe.end ( ) );

    if ( !StartupP2Pmsg ( 8 ) ) { Log ( "MAIN", "SETUP: StartupP2Pmsg" ); return 3; }
    WSADATA w; WSAStartup ( MAKEWORD ( 2, 2 ), &w );
    ServerHub hub ( kServerAddr );
    hub.evCount = CreateEvent ( NULL, FALSE, FALSE, NULL );
    hub.evClose = CreateEvent ( NULL, FALSE, FALSE, NULL );
    hub.RequireAuth ( false );
    HANDLE hThread = hub.SpawnHub ( );
    if ( !hThread ) { Log ( "MAIN", "SETUP: SpawnHub" ); return 3; }
    hub.PostP2PeerCon ( P2PeerConShm::ServiceFactory ( kClientAddr, wpipe.c_str ( ) ) );
    Sleep ( 500 );

    int rc = 0;
    char line[200];

    // ---- phase 1: traffic ------------------------------------------------
    const int kCount = 300;
    hub.expect = kCount; hub.wantDone = true;
    Child c1 = Launch ( pipe, kCount, 0 );
    bool got = WaitForSingleObject ( hub.evCount, 30000 ) == WAIT_OBJECT_0;
    int code1 = Reap ( c1, 20000 );
    //  The child's ORDERLY close, before phase 2 starts counting closes, so a late
    //  phase-1 close cannot stand in for the death phase 2 must detect
    bool closed1 = WaitForSingleObject ( hub.evClose, 5000 ) == WAIT_OBJECT_0;
    std::snprintf ( line, sizeof line, "phase 1: %d/%d messages intact, %d bad, child exit %d, close seen: %s",
                    hub.good.load ( ), kCount, hub.bad.load ( ), code1, closed1 ? "yes" : "NO" );
    Log ( "SERVER", line );
    if ( !got || hub.bad.load ( ) || code1 != 0 ) rc = got ? 1 : 3;
    else if ( !closed1 ) rc = 1;
    hub.wantDone = false;

    // ---- phase 2: the peer dies mid-stream -----------------------------------
    if ( rc == 0 )
    {
        ResetEvent ( hub.evClose );
        int closes0 = hub.closes.load ( );
        int good0 = hub.good.load ( );
        Child c2 = Launch ( pipe, 2000, 1 );
        int code2 = Reap ( c2, 20000 );
        bool closed = WaitForSingleObject ( hub.evClose, 5000 ) == WAIT_OBJECT_0 ||
                      hub.closes.load ( ) > closes0;
        std::snprintf ( line, sizeof line, "phase 2: child killed itself (exit %d) after %d messages arrived; "
                        "server saw the close: %s; bad %d",
                        code2, hub.good.load ( ) - good0, closed ? "yes" : "NO", hub.bad.load ( ) );
        Log ( "SERVER", line );
        if ( code2 != 7 ) rc = 3;              // the child did not die the way the case needs
        else if ( !closed || hub.bad.load ( ) ) rc = 1;
    }

    // ---- phase 3: the listener still serves ---------------------------------
    if ( rc == 0 )
    {
        int good0 = hub.good.load ( );
        hub.expect = good0 + 1; hub.wantDone = true;
        ResetEvent ( hub.evCount );
        Child c3 = Launch ( pipe, 1, 0 );
        bool ok3 = WaitForSingleObject ( hub.evCount, 15000 ) == WAIT_OBJECT_0;
        int code3 = Reap ( c3, 15000 );
        std::snprintf ( line, sizeof line, "phase 3: a new client after the death: %s, child exit %d",
                        ok3 ? "served" : "NOT served", code3 );
        Log ( "SERVER", line );
        if ( !ok3 || code3 != 0 ) rc = 1;
    }

    hub.CloseHub ( );
    WaitForSingleObject ( hThread, 3000 );
    CloseHandle ( hThread );
    CloseHandle ( hub.evCount );
    CloseHandle ( hub.evClose );
    CleanupP2Pmsg ( );
    WSACleanup ( );
    std::printf ( "RESULT: %s\nDone (exit=%d).\n", rc == 0 ? "PASS" : rc == 1 ? "FAIL" : "INCONCLUSIVE", rc );
    return rc;
}
