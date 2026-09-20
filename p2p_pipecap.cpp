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
// p2p_pipecap.cpp - SECURITY GATE TEST: does SetMaxAccepted() bind the PIPE
// transport, or only the socket one?
//
// BACKGROUND. p2p_acceptcap is the same question asked of P2PeerConWsa, and it
// has passed since 2026-08-16. OpenCodeWork.md item 2 is the observation that
// the answer was Wsa-specific: the DECISION helper AcceptAtCapacity() is on the
// base class (P2PeerCon.h:255) and the only call to it in the tree was
// P2PeerConWsa.cpp:1422. Pipe, serial and DMX never asked. P2PeerCon.h:237-238
// says why the call has to be made per transport rather than once at the base -
// "the refusal itself is transport-specific, because only the transport knows
// how to discard a half-accepted endpoint" - and three of the four transports
// never wrote their half.
//
// What the pipe had INSTEAD was an accident. CreateNamedPipe is called with a
// literal nMaxInstances of 2 (P2PeerConPipe.cpp:491), a number the transport
// does not own and cannot be asked about, so a Windows deployment was capped at
// two concurrent clients however SetMaxAccepted was configured, and the third
// client failed inside the kernel rather than being refused by a policy. On
// Linux not even that: the shim ignores nMaxInstances entirely and listens with
// a backlog of 8 (Platform/p2psock.h:404), so the pipe transport had no accept
// bound of any kind.
//
// WHAT IT DOES - three phases against one pipe service, using RAW CreateFile
// clients rather than hubs. Raw is p2p_acceptcap's reasoning and it carries
// over unchanged: the adversary being modelled does not run this library and
// will not complete a handshake, so the test must not either.
//
//   The cap is set to ONE, not two, and that is forced rather than stylistic.
//   A cap of 2 would need three concurrent clients to test, and the third
//   cannot be served on Windows for the accidental reason above - the refusal
//   would be the kernel's and the test would pass on a library that does
//   nothing. At a cap of 1 the refusal happens while the pipe still has an
//   instance free, so only the library can be responsible for it. This is
//   p2p_srcbound's "service cap set generously at 16" argument, applied to a
//   bound that comes from the platform instead of from a second policy.
//
//   Phase 1 (THE POSITIVE CONTROL): one raw client connects and MUST stay up.
//   Without it a transport that refused everything would pass phase 2.
//
//   Phase 2 (THE BOUND): a second raw client connects against SetMaxAccepted(1)
//   and MUST be dropped by the server.
//
//   Phase 3 (THE SLOT COMES BACK, and it is the load-bearing one): the first
//   client is closed, and a third connects. It MUST be admitted and stay up.
//   Without this phase, a service whose listener DIED at the refusal - which is
//   what the first draft of the Linux refusal did, by leaving m_hFile holding a
//   connected socket for Accept() to accept() on - is indistinguishable from
//   one that refused politely. "The client went away" is the same reading for
//   a bound that works and for a transport that broke itself; only a
//   reconnection tells them apart.
//
//   --uncapped runs phases 1 and 2 with SetMaxAccepted(0). BOTH clients must
//   then stay up. It is the control that attributes the phase 2 drop to the cap
//   and not to something about raw CreateFile clients on a pipe, and it is
//   worth running first on any red.
//
// VERDICT = process EXIT CODE:
//   0  PASS   the second client refused, the first untouched, the slot returned
//   1  FAIL   the over-cap client was served
//   2  SETUP  startup / listen failure (test inconclusive)
//   3  INCONCLUSIVE a control client died, so the refusal proves nothing

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConPipe.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"

#include <cstdio>
#include <cstring>

// ---------------------------------------------------------------------------
static LPCTSTR          kPipeName   = _T("\\\\.\\pipe\\P2PcapProbe");
static const P2PaddrSTR kServerAddr = L"PipeCap.Server";
static const P2PaddrSTR kDomain     = L"PipeCap.*";

static void Log ( const char *msg )
{
    std::printf ( "[pipecap] %s\n", msg );
    std::fflush ( stdout );
}

// ---------------------------------------------------------------------------
//  A raw pipe client. Opens the name and never says anything the library would
//  recognise - which is the whole point.
//  NOTES: Portable without a branch. On Windows this is the ordinary named-pipe
//         client open; on Linux the Platform shim intercepts a \\.\pipe\ path
//         in CreateFileW and makes it socket()+connect() to the AF_UNIX path
//         the server bound (p2pfile.h:189, p2psock.h:387), which is exactly
//         what P2PeerConPipe::Connect() does for a real client
//       : Share 0 is the normal pipe-client open on Windows. The shim's
//         exclusive-share flock path is below its pipe branch and is not
//         reached
static HANDLE RawOpen ( )
{
    HANDLE h = CreateFile ( kPipeName
                          , GENERIC_READ | GENERIC_WRITE
                          , 0, NULL, OPEN_EXISTING, 0, NULL );
    return ( h == INVALID_HANDLE_VALUE ) ? NULL : h;
}

static void RawClose ( HANDLE &h )
{
    if ( h ) { CloseHandle ( h ); h = NULL; }
}

// ---------------------------------------------------------------------------
//  Has the SERVER let go of this client?
//
//  The portability problem p2p_acceptcap solved for sockets recurs here in a
//  different shape, and the socket answer does not transfer: a pipe HANDLE is
//  not a SOCKET on Windows, so the FIONBIO-and-recv dance that file uses cannot
//  be written against one. The two platforms need two mechanisms.
//
//    Windows  PeekNamedPipe, which is non-destructive and answers about the
//             far end without consuming anything. A dropped client sees
//             ERROR_BROKEN_PIPE (the server closed the handle) or
//             ERROR_PIPE_NOT_CONNECTED (the server called
//             DisconnectNamedPipe), and BOTH are drops - which of them arrives
//             depends on which half of P2PeerConPipe::OnAccept's #ifdef ran,
//             so keying on one would make this test platform-specific twice
//             over
//    Linux    the handle is a P2PHandle* over an AF_UNIX fd, so ioctlsocket
//             (FIONBIO) reaches it - the shim templates its arg and only
//             fcntl()s the fd (p2psock.h:201) - and a non-blocking ReadFile
//             then returns TRUE with 0 bytes for an orderly close and FALSE
//             with ERROR_SHARING_VIOLATION while the peer is still there.
//             That error code rather than WSAEWOULDBLOCK is the shim mapping
//             EAGAIN through win32_from_errno, and it is the same trap
//             p2p_acceptcap documents at its own WasClosedByPeer
//
//  A timeout means STILL UP, which is the answer the control phases want.
static bool WasDroppedByServer ( HANDLE h, DWORD dwWaitMs )
{
    if ( !h ) return true;

#ifdef _WIN32
    for ( DWORD dwWaited = 0; ; dwWaited += 50 )
    {
        DWORD dwAvail = 0;
        if ( !PeekNamedPipe ( h, NULL, 0, NULL, &dwAvail, NULL ) )
          return true;                                 // broken, or disconnected
        if ( dwWaited >= dwWaitMs ) return false;      // never went: still up
        Sleep ( 50 );
    }
#else
    DWORD dwArg = 1;
    ioctlsocket ( (SOCKET)h, FIONBIO, &dwArg );

    for ( DWORD dwWaited = 0; ; dwWaited += 50 )
    {
        char  szBuf[64];
        DWORD dwRead = 0;
        if ( ReadFile ( h, szBuf, (DWORD)sizeof(szBuf), &dwRead, NULL ) )
        {
          if ( dwRead == 0 ) return true;              // orderly close: gone
          return false;                                // it spoke: still up
        }
        if ( GetLastError ( ) != ERROR_SHARING_VIOLATION )
          return true;                                 // reset, or gone
        if ( dwWaited >= dwWaitMs ) return false;      // never spoke: still up
        Sleep ( 50 );
    }
#endif
}

// =========================================================================
class PipeCapHub : public P2PeerHub
{
public:
    PipeCapHub ( P2PaddrSTR strAddr ) : P2PeerHub ( strAddr ) { }
    virtual ~PipeCapHub ( ) { }
};

// =========================================================================
int main ( int argc, char *argv[] )
{
    bool bUncapped = false;
    for ( int i = 1; i < argc; ++i )
      if ( std::strcmp ( argv[i], "--uncapped" ) == 0 )
        bUncapped = true;

    const long xCap = bUncapped ? 0 : 1;

    std::printf ( "=== p2p_pipecap - the accept cap on the PIPE transport%s ===\n",
                  bUncapped ? " (CONTROL: uncapped)" : "" );
    std::printf ( "Pipe : %ls\n", (LPCWSTR)kPipeName );
    std::printf ( "Asserting: %s\n\n",
                  bUncapped
                  ? "with SetMaxAccepted(0), TWO raw clients are both served."
                  : "against SetMaxAccepted(1), the second raw client is\n"
                    "           refused, the first is untouched, and the slot\n"
                    "           comes back when the first one leaves." );
    std::fflush ( stdout );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }
    WSADATA oWsaData;
    WSAStartup ( MAKEWORD(2,2), &oWsaData );      // no-op shim on Linux

    int nExit = 2;
    {
        PipeCapHub oServer ( kServerAddr );
        //  RequireAuth(false), for p2p_acceptcap's reason: this measures a
        //  RESOURCE bound, spent before a login is attempted, and requiring
        //  auth would drop a silent client for a second reason
        oServer.RequireAuth ( false );
        HANDLE hServerThread = oServer.SpawnHub ( );
        if ( !hServerThread ) { Log ( "SETUP: server SpawnHub() failed" ); return 2; }

        P2PeerConPipe *pSvc = P2PeerConPipe::ServiceFactory ( kDomain, kPipeName );
        if ( !pSvc ) { Log ( "SETUP: ServiceFactory failed" ); return 2; }

        //  The login deadline is OFF, so a client that goes away can only have
        //  gone away because of the cap. With both armed this would be
        //  measuring whichever fired first
        pSvc -> SetMaxAccepted   ( xCap );
        pSvc -> SetLoginDeadline ( 0 );
        oServer.PostP2PeerCon ( pSvc );
        std::printf ( "[pipecap] service posted; SetMaxAccepted(%ld), deadline off\n",
                      xCap );
        std::fflush ( stdout );
        Sleep ( 750 );          // CreateNamedPipe + the overlapped ConnectNamedPipe

        // ---- Phase 1: the positive control -------------------------------
        Log ( "--- phase 1: the first raw client, which must be served ---" );
        HANDLE h1 = RawOpen ( );
        if ( !h1 )
        {
            std::printf ( "\nRESULT: SETUP - the FIRST client could not open the "
                          "pipe at all (err %lu).\n"
                          "  The service is not listening, so nothing below "
                          "measures a bound.\n", (unsigned long)GetLastError ( ) );
            oServer.CloseHub ( );
            WaitForSingleObject ( hServerThread, 3000 );
            CloseHandle ( hServerThread );
            CleanupP2Pmsg ( ); WSACleanup ( );
            return 2;
        }
        Sleep ( 600 );          // let the accept complete and the service re-arm

        // ---- Phase 2: the bound ------------------------------------------
        Log ( bUncapped
              ? "--- phase 2: a second client, which must ALSO be served ---"
              : "--- phase 2: a second client against a cap of one ---" );
        HANDLE h2 = RawOpen ( );
        const bool b2Opened  = ( h2 != NULL );
        //  A refused client is EXPECTED to open. The pipe instance is already
        //  created and waiting when CreateFile runs; the refusal happens when
        //  the service processes the accept, so a refused peer sees a
        //  connection that opens and then goes - the same shape
        //  p2p_acceptcap's third socket sees
        const bool b2Dropped = !b2Opened || WasDroppedByServer ( h2, 5000 );
        const bool b1Up      = !WasDroppedByServer ( h1, 1000 );

        std::printf ( "[pipecap] first=%s second=%s (count=%ld of max %ld)\n",
                      b1Up ? "up" : "GONE",
                      !b2Opened  ? "OPEN REFUSED"
                      : b2Dropped ? "dropped" : "SERVED",
                      pSvc->GetAcceptedCount ( ), xCap );
        std::fflush ( stdout );

        if ( !b1Up )
        {
            std::printf (
              "\nRESULT: INCONCLUSIVE - the client INSIDE the cap was dropped.\n"
              "  A transport that refuses everything makes the second client's\n"
              "  fate meaningless. Check AcceptAtCapacity() is consulted BEFORE\n"
              "  AcceptSpawn() in P2PeerConPipe::OnAccept() and not after it -\n"
              "  after the spawn, THIS is already the accepted connection and\n"
              "  the count has already been taken.\n" );
            nExit = 3;
        }
        else if ( bUncapped )
        {
            //  The control's whole verdict: uncapped, the second client must
            //  survive. If it does not, the drop measured by the real run is
            //  not the cap and the gate below is reporting the wrong cause
            if ( b2Dropped )
            {
                std::printf (
                  "\nRESULT: FAIL - THE CONTROL DROPPED ITS SECOND CLIENT.\n"
                  "  SetMaxAccepted(0) is unbounded, so both raw clients should\n"
                  "  have been served. Something other than the cap is closing\n"
                  "  them, and the capped run's verdict cannot be trusted until\n"
                  "  this is understood. The first suspect is nMaxInstances: the\n"
                  "  literal 2 at P2PeerConPipe.cpp:491 is the only other bound\n"
                  "  on this transport, and two clients need two instances.\n" );
                nExit = 1;
            }
            else
            {
                std::printf (
                  "\nRESULT: PASS - the control holds.\n"
                  "  Uncapped, two raw pipe clients are both served, so a drop\n"
                  "  in the capped run is attributable to the cap.\n" );
                nExit = 0;
            }
        }
        else if ( !b2Dropped )
        {
            std::printf (
              "\nRESULT: FAIL - THE CAP DOES NOT BIND ON THE PIPE TRANSPORT.\n"
              "  One client was already live against SetMaxAccepted(1) and the\n"
              "  second was served anyway. This is OpenCodeWork.md item 2: the\n"
              "  decision helper AcceptAtCapacity() is on the base class and\n"
              "  the pipe transport never called it, so the only thing bounding\n"
              "  this transport was the literal nMaxInstances of 2 handed to\n"
              "  CreateNamedPipe - on Windows. On Linux the shim ignores that\n"
              "  argument and listens with a backlog of 8, so there was no\n"
              "  bound at all.\n"
              "\n"
              "  Check P2PeerConPipe::OnAccept() consults AcceptAtCapacity()\n"
              "  and that the SPAWNED service still carries the cap. The pipe\n"
              "  MORPHS at accept - AcceptSpawn() makes the new instance the\n"
              "  SERVICE and turns THIS into the accepted connection - so the\n"
              "  base's `pConSpawn->m_xMaxAccepted.store(0)`, which is right for\n"
              "  a transport whose spawn is the CHILD, zeroes the cap on the\n"
              "  very object that will evaluate it next.\n" );
            nExit = 1;
        }
        else
        {
            Log ( "cap holds - first served, second dropped" );

            // ---- Phase 3: the slot comes back ----------------------------
            //  A refusal that kills the listener reads exactly like a refusal
            //  that works, for as long as nobody knocks again. This is the
            //  phase that tells them apart, and it is the one the Linux
            //  refusal would have failed: DisconnectNamedPipe is a no-op
            //  there, so the first draft left m_hFile holding a CONNECTED
            //  socket that Accept() would then accept() on
            Log ( "--- phase 3: the first client leaves; a third must get in ---" );
            RawClose ( h1 );
            Sleep ( 1500 );              // let the service reap the slot

            HANDLE h3 = RawOpen ( );
            const bool b3Opened = ( h3 != NULL );
            const bool b3Up     = b3Opened && !WasDroppedByServer ( h3, 1500 );

            std::printf ( "[pipecap] third=%s (count=%ld)\n",
                          !b3Opened ? "OPEN REFUSED"
                          : b3Up     ? "up" : "CONNECTED THEN CLOSED",
                          pSvc->GetAcceptedCount ( ) );
            std::fflush ( stdout );
            RawClose ( h3 );

            if ( !b3Up )
            {
                std::printf (
                  "\nRESULT: FAIL - THE REFUSAL WAS A BROKEN PIPE, NOT A BOUND.\n"
                  "  The second client was dropped, but after the first one left\n"
                  "  a third could not be served either (%s). So the service did\n"
                  "  not refuse a connection, it stopped accepting them - and the\n"
                  "  drop measured in phase 2 is evidence of a damaged listener\n"
                  "  rather than of a cap.\n"
                  "\n"
                  "  The refusal is NOT THE SAME CALL on both platforms and this\n"
                  "  is what writing it as though it were looks like. On Windows\n"
                  "  m_hFile is the pipe INSTANCE and DisconnectNamedPipe returns\n"
                  "  it to a state the re-arm can wait on. On Linux the shim\n"
                  "  MORPHS the handle - ConnectNamedPipe closes the listen socket\n"
                  "  and puts the accepted fd in its place (p2psock.h:432) - and\n"
                  "  DisconnectNamedPipe is `{ return TRUE; }` (:434), so the\n"
                  "  Windows call leaves the client connected AND leaves m_hFile\n"
                  "  holding a connected socket. There the drop must be\n"
                  "  CloseHandle + m_hFile = 0, which lets Accept() rebuild the\n"
                  "  listener.\n"
                  "\n"
                  "  A slot that never comes back is the other candidate and is\n"
                  "  distinguishable by the count printed above: if it is still\n"
                  "  1 after the first client closed, the refusal is fine and the\n"
                  "  ACCOUNTING leaks - refer p2p_conreap, and note that the pipe\n"
                  "  counts its spawn rather than its accepted connection.\n",
                  b3Opened ? "it opened and was closed" : "the open was refused" );
                nExit = 1;
            }
            else
            {
                std::printf (
                  "\nRESULT: PASS - the accept cap binds on the pipe transport.\n"
                  "  Against SetMaxAccepted(1): one client served, the second\n"
                  "  refused while the pipe still had an instance free, and the\n"
                  "  slot returned to a third once the first left. The refusal\n"
                  "  is therefore the library's policy and not nMaxInstances,\n"
                  "  and it left the listener able to serve.\n" );
                nExit = 0;
            }
        }

        RawClose ( h1 ); RawClose ( h2 );
        Sleep ( 400 );

        Log ( "shutdown begin" );
        oServer.CloseHub ( );
        WaitForSingleObject ( hServerThread, 3000 );
        CloseHandle ( hServerThread );
    }

    CleanupP2Pmsg ( );
    WSACleanup ( );

    std::printf ( "Done (exit=%d).\n", nExit );
    std::fflush ( stdout );
    return nExit;
}
