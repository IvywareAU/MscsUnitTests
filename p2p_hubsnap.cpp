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
// p2p_hubsnap.cpp - can a hub be WATCHED by something that was not built into
// it? ProductionPlan.md Stage 4 step 13.
//
// BACKGROUND. P2PeerHub::Serialise() is the one snapshot the library already
// pushes everywhere: MSG_P2PexpHub is built from it, every P2Pevent that
// carries hub state carries it, and anything holding a hub can call it. Until
// this test it reported the hub's NAME, ADDRESS, DOMAIN and BUILD VERSION -
// six fields of identity and not one of state. An operator asking the two
// questions an operator actually asks, "is it keeping up?" and "how many peers
// is it holding?", had the choice of reading stderr or attaching a debugger.
//
// Both numbers already existed. GetP2PmsgCount() has been exported since the
// import and GetAcceptedCount() since Stage 4 step 10; neither was in the
// snapshot, so neither could be reached by anything on the far end of a
// message.
//
// WHAT IT MEASURES. A "monitor" that touches NOTHING except the public
// P2PeerHub::Serialise() - no friend access, no internal header, no counter
// the test itself maintains - polls the hub and applies a threshold to each
// field. That restriction is the test. A monitor allowed to call
// GetAcceptedCount() directly would prove the counter works, which was already
// known, rather than that the snapshot carries it.
//
//   Phase 1 (AT REST). Accepted is 0 and QueDepth is 0 with nothing connected,
//   and PumpsMax is NOT 0. That last one is a regression gate with history:
//   PumpsMax was in this snapshot from the import and was filled with a
//   literal 0 on every hub that ever ran. A field that always reports a
//   constant is worse than an absent one, because an absent field gets asked
//   about and a constant one gets believed.
//
//   Phase 2 (THE ACCEPTED ALARM). Three raw sockets connect - raw, because
//   the number being watched is a count of connections the hub is HOLDING and
//   a peer does not have to log in to be held. The monitor's threshold is 2,
//   so it must be quiet at 0 and must fire at 3, and the value it read must be
//   exactly 3 rather than merely "more than 2": a snapshot that reported the
//   service connection as well, or that reported each accepted child's share
//   of its service's counter, would also exceed 2 and would be wrong.
//
//   Phase 3 (THE QUEUE ALARM). A queue depth that is always 0 passes any test
//   that only reads it, which is exactly how PumpsMax survived for years. So
//   the depth is made non-zero DELIBERATELY: a second pump is created on a
//   worker thread that never pumps it, and four messages are posted to it.
//   The hub's own pump is running and idle throughout, so a non-zero reading
//   can ONLY have come from the parked pump - which is also the claim that
//   the field is HUB-scoped rather than a rename of GetP2PmsgCount(), the
//   per-pump figure that has always been available and that cannot see this
//   at all. The worker then closes its pump, and the depth must return to 0:
//   a counter that only counts up would pass everything above.
//
// WHAT IS NOT CLAIMED, AND WHY IT IS STILL NOT CLAIMED. Accepted is not
// checked to FALL when the peers disconnect. That used to be because it did
// not fall on Windows - ProductionPlan.md F-S4-1, a peer that connected, said
// nothing and disconnected was never reaped there, so the count was of
// connections ever accepted. THAT FINDING IS CLOSED (2026-08-20): the recv
// branch now tells a peer's FIN from an arming post by a mark set at
// submission, and the fall happens on both platforms.
//
// It is still not asserted HERE, and the reason has changed rather than gone
// away: this test's subject is the SNAPSHOT - whether a stranger holding
// nothing but Serialise() can read the two numbers - and reaping is a
// different proposition that deserves its own verdict. p2p_conreap is that
// gate, with the positive and negative controls the question needs; the login
// deadline's reaping path is measured by p2p_srcbound. Piling a third claim
// onto this binary would mean a red here no longer named what broke.
//
// VERDICT = process EXIT CODE:
//   0  PASS   both fields present, both track reality, both alarms behave
//   1  FAIL   a field is absent, constant, or reports the wrong number
//   2  SETUP  startup / listen failure (test inconclusive)
//   3  INCONCLUSIVE the parked pump could not be created, so the queue depth
//                   was never made non-zero and proves nothing

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConWsa.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"

#include <cstdio>
#include <cstring>

// ---------------------------------------------------------------------------
static const P2PaddrSTR kServerAddr = L"Snap.Server";
static const P2PaddrSTR kDomain     = L"Snap.*";

static void Log ( const char *msg )
{
    std::printf ( "[hubsnap] %s\n", msg );
    std::fflush ( stdout );
}

// ---------------------------------------------------------------------------
//  A raw TCP peer, as in p2p_acceptcap: connects and says nothing the library
//  would recognise. The hub holds it regardless, which is the point - what is
//  being watched is occupancy, not conversation
static SOCKET RawConnect ( short nPort )
{
    SOCKET s = socket ( AF_INET, SOCK_STREAM, IPPROTO_TCP );
    if ( s == INVALID_SOCKET ) return INVALID_SOCKET;

    sockaddr_in oAddr;
    std::memset ( &oAddr, 0, sizeof(oAddr) );
    oAddr.sin_family      = AF_INET;
    oAddr.sin_port        = htons ( (u_short)nPort );
    oAddr.sin_addr.s_addr = inet_addr ( "127.0.0.1" );

    if ( connect ( s, (sockaddr *)&oAddr, sizeof(oAddr) ) == SOCKET_ERROR )
    { closesocket ( s ); return INVALID_SOCKET; }

    return s;
}

static void RawClose ( SOCKET &s )
{
    if ( s != INVALID_SOCKET ) { closesocket ( s ); s = INVALID_SOCKET; }
}

// =========================================================================
class SnapHub : public P2PeerHub
{
public:
    SnapHub ( P2PaddrSTR strAddr ) : P2PeerHub ( strAddr ) { }
    virtual ~SnapHub ( ) { }
};

// =========================================================================
//  THE MONITOR, and the restriction on it is the test.
//  NOTES: It calls exactly one thing on the hub - the public Serialise() -
//         and reads named fields out of the P3PmsgItem that comes back. It
//         holds no pointer into the library, keeps no count of its own, and
//         would work identically against a snapshot that had arrived over a
//         wire as MSG_P2PexpHub, because that message is built by calling the
//         same function
//       : Alarming is a threshold on a number a stranger can read. If the
//         numbers are not in the snapshot there is nothing here to write
struct HubMonitor
{
    long nQueAlarmAt;                    // alarm when QueDepth exceeds this
    long nAccAlarmAt;                    // alarm when Accepted exceeds this

    bool bReadable;                      // all three fields present
    long nQue, nAcc, nPumpsMax;
    bool bQueAlarm, bAccAlarm;

    HubMonitor ( long nQueAt, long nAccAt )
      : nQueAlarmAt(nQueAt), nAccAlarmAt(nAccAt)
      , bReadable(false), nQue(-1), nAcc(-1), nPumpsMax(-1)
      , bQueAlarm(false), bAccAlarm(false) { }

    //  ReadAnyInt() rather than c_int(), and the difference is not cosmetic.
    //  c_int() THROWS on a width or sign mismatch, and these three fields are
    //  written as UINT32 - so a monitor built on c_int() would have to already
    //  know the cell width of a field it did not write, and would raise a
    //  P2Pevent the first time the hub chose a different one. ReadAnyInt is
    //  the width-agnostic read: it returns false only when the field is not an
    //  integer at all, which is the one thing a reader here needs to know
    static bool ReadNum ( P3PmsgItem& oSnap, LPCWSTR lpszName, long& nOut )
    {
        if ( !oSnap.Exists ( lpszName ) )
          return false;
        INT64 i64       = 0;
        bool  bUnsigned = false;
        if ( !oSnap.SelectItem ( lpszName ).r_data().ReadAnyInt ( i64, bUnsigned ) )
          return false;
        nOut = (long)i64;
        return true;
    }

    void Poll ( P2PeerHub& oHub )
    {
        P3PmsgItem oSnap = oHub.Serialise ( 0 );
        bReadable = ReadNum ( oSnap, L"QueDepth", nQue      ) &&
                    ReadNum ( oSnap, L"Accepted", nAcc      ) &&
                    ReadNum ( oSnap, L"PumpsMax", nPumpsMax );
        if ( !bReadable )
          return;
        bQueAlarm = nQue > nQueAlarmAt;
        bAccAlarm = nAcc > nAccAlarmAt;
    }

    void Report ( const char *szWhen ) const
    {
        std::printf ( "[hubsnap] %-16s QueDepth=%ld Accepted=%ld PumpsMax=%ld"
                      "  alarms: que=%s acc=%s\n"
                    , szWhen, nQue, nAcc, nPumpsMax
                    , bQueAlarm ? "FIRING" : "quiet"
                    , bAccAlarm ? "FIRING" : "quiet" );
        std::fflush ( stdout );
    }
};

// =========================================================================
//  The parked pump. Creates a second pump on this thread, attaches it to the
//  hub, and then does NOT pump it - so anything posted to it stays queued and
//  the hub's queue depth has somewhere to come from. Closes its own pump on
//  request, because a pump may only be cleaned up from its own thread
//  (CloseP2PmsgPump)
struct ParkCtx
{
    P2PmsgHubID    nHubID;
    P2PeerTarget  *pTarget;              // the pump's target must not be null:
                                         // PutP2Pmsg() asserts it valid
    volatile LONG  nPumpID;              // 0 = not up yet, ~0 = failed
    volatile LONG  bDrain;               // set by main to ask for closure
};
static ParkCtx s_oPark = { 0, 0, 0, 0 };

//  Reads a cross-thread flag. InterlockedCompareExchange is NOT in the Linux
//  shim (Platform/p2ptypes.h has Exchange, ExchangeAdd and Increment only),
//  and an add of zero is the portable read - refer p2p_expreg.cpp
static LONG AtomicRead ( volatile LONG *p )
{ return InterlockedExchangeAdd ( p, 0 ); }

static DWORD WINAPI ParkThread ( LPVOID )
{
    try
    {
      P2PumpID nPumpID = CreateP2PmsgPump ( s_oPark.nHubID, L"Parked", s_oPark.pTarget );
      InterlockedExchange ( &s_oPark.nPumpID, (LONG)nPumpID );
    }
    catch ( P2Pevent *pEVT )
    {
      pEVT -> Cancel ( );
      InterlockedExchange ( &s_oPark.nPumpID, (LONG)~0 );
      return 1;
    }

    // Park. Deliberately never calls RunP2PmsgPump()
    while ( !AtomicRead ( &s_oPark.bDrain ) )
      Sleep ( 50 );

    try   { CloseP2PmsgPump ( ); }
    catch ( P2Pevent *pEVT ) { pEVT -> Cancel ( ); }
    return 0;
}

// =========================================================================
int main ( int argc, char **argv )
{
    const short nPort = (short)( argc > 1 ? std::atoi ( argv[1] ) : 7834 );

    std::printf ( "=== p2p_hubsnap - a hub that can be watched from outside ===\n" );
    std::printf ( "Port : %d\n", (int)nPort );
    std::printf ( "Asserting: QueDepth and Accepted are IN the hub snapshot,\n"
                  "           track reality, and can be alarmed on by a reader\n"
                  "           that calls nothing but P2PeerHub::Serialise().\n\n" );
    std::fflush ( stdout );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }
    WSADATA oWsaData;
    WSAStartup ( MAKEWORD(2,2), &oWsaData );

    int nExit = 2;
    {
        SnapHub oServer ( kServerAddr );
        //  RequireAuth(false): what is being counted is occupancy, and a peer
        //  does not have to be allowed to speak in order to occupy. Requiring
        //  auth would drop the three raw sockets for a reason that has nothing
        //  to do with this measurement
        oServer.RequireAuth ( false );
        HANDLE hServerThread = oServer.SpawnHub ( );
        if ( !hServerThread ) { Log ( "SETUP: SpawnHub() failed" ); return 2; }

        P2PeerConWsa *pSvc = P2PeerConWsa::ServiceFactory ( kDomain, nPort );
        if ( !pSvc ) { Log ( "SETUP: ServiceFactory failed" ); return 2; }
        oServer.PostP2PeerCon ( pSvc );
        Sleep ( 500 );

        // -------------------------------------------------------------- 1 --
        Log ( "--- phase 1: at rest ---" );
        HubMonitor oMon ( /*que*/ 3, /*acc*/ 2 );
        oMon.Poll   ( oServer );
        oMon.Report ( "at rest" );

        const bool bPresent   = oMon.bReadable;
        const bool bRestQuiet = bPresent && !oMon.bQueAlarm && !oMon.bAccAlarm;
        const bool bRestZero  = bPresent && oMon.nQue == 0 && oMon.nAcc == 0;
        //  PumpsMax reported a literal 0 on every hub that ever ran until
        //  Stage 4 step 13. It is the hub's configured ceiling and cannot be 0
        const bool bPumpsMax  = bPresent && oMon.nPumpsMax > 0;

        // -------------------------------------------------------------- 2 --
        Log ( "--- phase 2: three raw peers, threshold 2 ---" );
        SOCKET a1 = RawConnect ( nPort ); Sleep ( 300 );
        SOCKET a2 = RawConnect ( nPort ); Sleep ( 300 );
        SOCKET a3 = RawConnect ( nPort ); Sleep ( 500 );
        const bool bDialled = a1 != INVALID_SOCKET &&
                              a2 != INVALID_SOCKET &&
                              a3 != INVALID_SOCKET;

        oMon.Poll   ( oServer );
        oMon.Report ( "3 connected" );
        //  EXACTLY three. "More than the threshold" would also be satisfied by
        //  a snapshot that counted the SERVICE connection as accepted, or that
        //  summed each child's shared view of its service's counter
        const bool bAccExact = oMon.nAcc == 3;
        const bool bAccFired = oMon.bAccAlarm;
        const bool bQueQuiet = !oMon.bQueAlarm;   // the hub's own pump is idle

        RawClose ( a1 ); RawClose ( a2 ); RawClose ( a3 );
        Sleep ( 500 );

        // -------------------------------------------------------------- 3 --
        Log ( "--- phase 3: a parked pump, four messages, threshold 3 ---" );
        s_oPark.nHubID  = oServer.GetHubID ( );
        s_oPark.pTarget = &oServer;
        HANDLE hPark = CreateThread ( 0, 0, ParkThread, 0, 0, 0 );

        LONG nParkPump = 0;
        for ( int i = 0; i < 100 && nParkPump == 0; ++i )
        { Sleep ( 50 ); nParkPump = AtomicRead ( &s_oPark.nPumpID ); }

        bool bParked  = ( nParkPump != 0 && nParkPump != (LONG)~0 );
        bool bQueRose = false, bQueFired = false, bQueFell = false;
        long nQueSeen = -1;

        if ( bParked )
        {
          const wchar_t szBody[] = L"hubsnap";
          for ( int i = 0; i < 4; ++i )
            PostP2Pmsg ( new P2PeerMsg32 ( L"Snap.Src", L"Snap.Dst", P2Pmsg_BCast
                                         , szBody, (P2Psize_t)sizeof(szBody) )
                       , (P2PumpID)nParkPump );
          Sleep ( 300 );

          oMon.Poll   ( oServer );
          oMon.Report ( "4 parked" );
          nQueSeen  = oMon.nQue;
          //  At least four: the hub's own pump may legitimately hold a message
          //  of its own in flight. Fewer than four means the aggregate is not
          //  seeing the second pump at all, which is the whole hub-scope claim
          bQueRose  = oMon.nQue >= 4;
          bQueFired = oMon.bQueAlarm;

          //  And it must come DOWN. A depth that only rises is indistinguish-
          //  able from a working one for the length of a test, and useless to
          //  an operator, who watches it precisely to see it recover
          InterlockedExchange ( &s_oPark.bDrain, 1 );
          WaitForSingleObject ( hPark, 5000 );
          Sleep ( 300 );
          oMon.Poll   ( oServer );
          oMon.Report ( "pump closed" );
          bQueFell  = oMon.nQue == 0 && !oMon.bQueAlarm;
        }
        else
        {
          InterlockedExchange ( &s_oPark.bDrain, 1 );
          WaitForSingleObject ( hPark, 5000 );
        }
        if ( hPark ) CloseHandle ( hPark );

        // ---------------------------------------------------------- verdict -
        if ( !bPresent )
        {
            std::printf (
              "\nRESULT: FAIL - THE HUB SNAPSHOT DOES NOT CARRY ITS OWN STATE.\n"
              "  P2PeerHub::Serialise() returned a snapshot without QueDepth,\n"
              "  Accepted or PumpsMax, so a monitor holding one has the hub's\n"
              "  name, address and build version and nothing about how it is\n"
              "  coping. Both numbers exist already - GetP2PmsgCount() and\n"
              "  GetAcceptedCount() are exported - so this is not a question of\n"
              "  measuring anything new, only of reporting it through the\n"
              "  channel that already reaches every consumer.\n"
              "  The fields are added in P2PeerHub::Serialise(), beside Version,\n"
              "  and are fed by GetP2PmsgHubQueCount() and\n"
              "  GetP2PmsgHubAcceptedCount() in P2Pwin32.cpp.\n" );
            nExit = 1;
        }
        else if ( !bRestQuiet || !bRestZero )
        {
            std::printf (
              "\nRESULT: FAIL - THE SNAPSHOT IS WRONG AT REST (que=%ld acc=%ld).\n"
              "  Nothing is connected and no message is queued, so both fields\n"
              "  must read 0 and neither alarm may fire. An alarm that is\n"
              "  already firing before anything has happened is an alarm nobody\n"
              "  will act on.\n", oMon.nQue, oMon.nAcc );
            nExit = 1;
        }
        else if ( !bPumpsMax )
        {
            std::printf (
              "\nRESULT: FAIL - PumpsMax IS A CONSTANT AGAIN (%ld).\n"
              "  This field was in the hub snapshot from the import and was\n"
              "  filled with a literal 0 on every hub that ever ran, which told\n"
              "  every reader that the hub could run no pumps at all. It is the\n"
              "  ceiling CreateP2PmsgPump() refuses against, and it cannot be 0\n"
              "  for a hub that exists.\n"
              "  Check GetP2PmsgHubPumpsMax() in P2Pwin32.cpp and the call to it\n"
              "  in P2PeerHub::Serialise().\n", oMon.nPumpsMax );
            nExit = 1;
        }
        else if ( !bDialled )
        {
            std::printf (
              "\nRESULT: INCONCLUSIVE - a raw peer could not connect.\n"
              "  Phase 2 needs three live connections before the Accepted field\n"
              "  proves anything; a connection refused by the operating system\n"
              "  is not the hub declining to report one.\n" );
            nExit = 3;
        }
        else if ( !bAccExact || !bAccFired )
        {
            std::printf (
              "\nRESULT: FAIL - Accepted DOES NOT TRACK THE HUB (read %ld, "
              "expected 3, alarm %s).\n"
              "  Three raw sockets are connected and the hub is holding all\n"
              "  three. A reading ABOVE 3 means the aggregate is counting the\n"
              "  same connections more than once - AcceptSpawn() gives each\n"
              "  child a SHARE of its service's counter, so summing over every\n"
              "  connection in the hub's list reports N accepted connections as\n"
              "  N*(N+1). A reading BELOW 3 means it is not seeing the service.\n"
              "  Check the SERVICE-only filter in GetP2PmsgHubAcceptedCount().\n"
            , oMon.nAcc, bAccFired ? "fired" : "SILENT" );
            nExit = 1;
        }
        else if ( !bQueQuiet )
        {
            std::printf (
              "\nRESULT: FAIL - the queue alarm fired on an idle hub.\n"
              "  Three raw sockets that said nothing produced a queue depth\n"
              "  above 3. Either the depth is not being read from the pumps or\n"
              "  messages are not being dispatched, and the two are worth\n"
              "  telling apart before trusting either field.\n" );
            nExit = 1;
        }
        else if ( !bParked )
        {
            std::printf (
              "\nRESULT: INCONCLUSIVE - the parked pump could not be created.\n"
              "  Phase 3 is the only part of this test that makes QueDepth\n"
              "  non-zero, and without it a field hard-wired to 0 would pass\n"
              "  everything above - which is exactly how PumpsMax survived from\n"
              "  the import. So the queue half is UNMEASURED rather than met.\n"
              "  CreateP2PmsgPump() refuses past the hub's PumpsMax (%ld here)\n"
              "  and refuses a thread that already owns a pump.\n"
              , oMon.nPumpsMax );
            nExit = 3;
        }
        else if ( !bQueRose || !bQueFired )
        {
            std::printf (
              "\nRESULT: FAIL - QueDepth DOES NOT SEE THE HUB'S OTHER PUMPS "
              "(read %ld, expected >= 4, alarm %s).\n"
              "  Four messages are queued on a second pump of this hub that\n"
              "  nobody is pumping, and the hub's own pump is idle. A reading\n"
              "  of 0 means the field is the per-pump GetP2PmsgCount() wearing\n"
              "  a hub's name: it reports the pump the CALLER is standing in,\n"
              "  and a hub whose explorer pump is drowning while its own is\n"
              "  idle would read as healthy.\n"
              "  Check the m_oCListP2PmsgPump walk in GetP2PmsgHubQueCount().\n"
            , nQueSeen, bQueFired ? "fired" : "SILENT" );
            nExit = 1;
        }
        else if ( !bQueFell )
        {
            std::printf (
              "\nRESULT: FAIL - QueDepth ONLY COUNTS UP (still %ld after the "
              "parked pump closed).\n"
              "  The pump holding those four messages has been closed and its\n"
              "  queue with it, so the depth must be back to 0 and the alarm\n"
              "  must be quiet. A depth that never falls is useless to the only\n"
              "  reader it has: an operator watches it to see a hub RECOVER.\n"
            , oMon.nQue );
            nExit = 1;
        }
        else
        {
            std::printf (
              "\nRESULT: PASS - the hub reports its own state, and a stranger\n"
              "  can alarm on it.\n"
              "  A monitor calling nothing but P2PeerHub::Serialise() read\n"
              "  Accepted=0 and QueDepth=0 on an idle hub with both alarms\n"
              "  quiet; read Accepted=3 - exactly three, not the service and\n"
              "  not each child's share of it - with three raw peers connected\n"
              "  and its threshold of 2 firing; read QueDepth>=4 from a second\n"
              "  pump of the same hub that it has no way of knowing exists,\n"
              "  with its threshold of 3 firing; and saw both return to 0 when\n"
              "  that pump closed. PumpsMax reported the hub's real ceiling\n"
              "  (%ld) rather than the literal 0 it carried from the import.\n"
            , oMon.nPumpsMax );
            nExit = 0;
        }

        Log ( "shutdown begin" );
        oServer.CloseHub ( );
        WaitForSingleObject ( hServerThread, 5000 );
        CloseHandle ( hServerThread );
    }
    CleanupP2Pmsg ( );
    WSACleanup ( );

    std::fflush ( stdout );
    return nExit;
}
