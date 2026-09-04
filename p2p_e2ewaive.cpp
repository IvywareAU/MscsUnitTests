// ===========================================================================
//  p2p_e2ewaive - securityRevision.md §6.3, the end-to-end waiver
//
//  ASSERTING: WaiveEndToEndInProcess() waives the seal for a destination this
//  process actually holds, waives it for NOTHING ELSE, and is OFF until an
//  operator says otherwise.
//
//  WHY THE GATE IS SHAPED LIKE THIS. Every other switch in this library fails
//  closed on a mechanism: it refuses when it cannot prove something. This one
//  cannot - it is an operator asserting a DEPLOYMENT property (in-process hubs
//  form one address subtree) that the library has no way to check. So the
//  thing that has to be gated is not "does the assumption hold", which is not
//  a question code can ask, but the two things around it that ARE mechanical:
//
//    - the predicate the waiver keys on is EXACT. A hub Alice held here says
//      nothing about Alice.Bob, which may be a child hub on another host.
//      Phase 0 is that algebra and it is the security-critical phase in this
//      file: if IsP2PmsgHubInProcess() ever answers TRUE for an address below
//      a hub, the waiver silently covers traffic that leaves the machine.
//    - the DEFAULT is off, and the posture says which it is. Phases 1 and 2.
//
//  Phase 3 and 4 are the enforcement, and they are a pair. The observable is
//  DELIVERY, not timing and not interception: Alice requires sealing and holds
//  no agreement key for Carol, so SealAppMsgOutbound must refuse to send. With
//  the waiver off that message does not arrive; with it on, and Carol a hub in
//  this process, the seal is never attempted and the message does. One switch
//  between the two runs and nothing else.
//
//  WHAT THIS FILE DOES NOT COVER, stated because it changes what green means:
//
//    - AN OUT-OF-PROCESS DESTINATION, behaviourally. That is the case the
//      waiver's assumption is about, and asserting it needs a second PROCESS -
//      an in-process hub and an out-of-process one are not distinguishable by
//      any address this harness can invent, which is the whole point of the
//      predicate. Phase 0 tests the predicate directly instead, on a live
//      registry, including the sub-address and prefix cases that ARE the
//      hazard. A second-process harness is the right shape for the rest and it
//      is not this one.
//    - THE ATTESTATION HALF, on the receive side. GateRelayInbound is reached
//      only on an ancestor link carrying a source not at-or-below the peer
//      that delivered it, and in a CHAIN the relay is a common ancestor of
//      both ends - so the descendant test admits first and that gate never
//      runs. That is not a gap in the waiver, it is the topology, and it is
//      recorded as finding 11 in securityRevision_progress.md with the same
//      measurement behind it. Gating it wants the p2p_authancestor shape.
//
//  NO SOCKETS. Three hubs over P2PeerConDmx, so no RESOURCE_LOCK and no port.
// ===========================================================================

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConDmx.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"
#include "P2PIdentityStore.h"
#include "P2PAuthLogin.h"
#include "TargetCore_c.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <atomic>

// ---------------------------------------------------------------------------
static int g_nChecks = 0;
static int g_nFailed = 0;

static void Log ( const char *msg )
{
    std::printf ( "[e2ewaive] %s\n", msg );
    std::fflush ( stdout );
}

static void Check ( bool bOk, const char *pszWhat )
{
    ++g_nChecks;
    if ( !bOk ) ++g_nFailed;
    std::printf ( "[e2ewaive]   %s  %s\n", bOk ? "ok  " : "FAIL", pszWhat );
    std::fflush ( stdout );
}

// ---------------------------------------------------------------------------
//  Provisioning. Lifted from p2p_linkcost, which provisions the same three
//  roles - with ONE deliberate difference, and it is what phases 3 and 4 turn
//  on: Alice's allow-list entry for Carol carries an IDENTITY and no
//  AGREEMENT key. Alice can therefore log in to the chain and cannot seal to
//  Carol, which is the refusal the waiver is being asked to skip.
// ---------------------------------------------------------------------------
static std::vector<std::string> g_vTempFiles;

static std::string TempPath ( const char *pszLeaf )
{
    char  szDir[MAX_PATH + 2] = { 0 };
    DWORD n = GetTempPathA ( MAX_PATH + 1, szDir );
    std::string s = ( n > 0 && n <= MAX_PATH ) ? std::string ( szDir )
                                               : std::string ( ".\\" );
    char szPid[32];
    std::snprintf ( szPid, sizeof(szPid), "%lu",
                    (unsigned long)GetCurrentProcessId ( ) );
    s += "p2p_e2ewaive_"; s += pszLeaf; s += "_"; s += szPid; s += ".tmp";
    DeleteFileA ( s.c_str ( ) );
    g_vTempFiles.push_back ( s );
    return s;
}

static void ScrubTempFiles ( )
{
    for ( size_t i = 0; i < g_vTempFiles.size ( ); ++i )
        DeleteFileA ( g_vTempFiles[i].c_str ( ) );
    g_vTempFiles.clear ( );
}

static bool MakeIdentity ( const std::string &sPath, unsigned char *pPubOut )
{
    p2pcng::EcdsaP256 oKey;
    if ( !oKey.Generate ( ) )                                             return false;
    if ( p2pcng::SaveIdentity ( sPath.c_str ( ), oKey ) != p2pcng::IdOk )  return false;
    return oKey.ExportPublic ( pPubOut );
}

static bool MakeAgreement ( const std::string &sPath, unsigned char *pPubOut )
{
    p2pcng::EcdhP256 oKey;
    if ( !oKey.Generate ( ) )                                              return false;
    if ( p2pcng::SaveAgreement ( sPath.c_str ( ), oKey ) != p2pcng::IdOk )  return false;
    return oKey.ExportPublic ( pPubOut );
}

// ---------------------------------------------------------------------------
//  One row per phase that stands a chain up, and the addresses are NOT derived
//  from a loop index at the point of use. Refer p2p_linkcost's header: the
//  same shortcut in p2p_linktrust put two phases on one hub address a
//  millisecond apart and produced a failure indistinguishable from a real one.
// ---------------------------------------------------------------------------
static const int kRuns = 2;
static const P2PaddrSTR kMidAddr  [kRuns] = { L"WvOff",       L"WvOn"       };
static const P2PaddrSTR kAliceAddr[kRuns] = { L"WvOff.Alice", L"WvOn.Alice" };
static const P2PaddrSTR kCarolAddr[kRuns] = { L"WvOff.Carol", L"WvOn.Carol" };
static const char      *kMidUtf8  [kRuns] = { "WvOff",        "WvOn"        };
static const char      *kAliceUtf8[kRuns] = { "WvOff.Alice",  "WvOn.Alice"  };
static const char      *kCarolUtf8[kRuns] = { "WvOff.Carol",  "WvOn.Carol"  };
static LPCTSTR          kSvcAlice [kRuns] = { _T("E2EWaiveA0"), _T("E2EWaiveA1") };
static LPCTSTR          kSvcCarol [kRuns] = { _T("E2EWaiveC0"), _T("E2EWaiveC1") };

static std::string g_sAliceKey, g_sAliceAgr, g_sAliceAcl;
static std::string g_sCarolKey,              g_sCarolAcl;
static std::string g_sMidKey,                g_sMidAcl;

static bool Provision ( )
{
    g_sAliceKey = TempPath ( "alicekey" );
    g_sAliceAgr = TempPath ( "aliceagr" );
    g_sAliceAcl = TempPath ( "aliceacl" );
    g_sCarolKey = TempPath ( "carolkey" );
    g_sCarolAcl = TempPath ( "carolacl" );
    g_sMidKey   = TempPath ( "midkey"   );
    g_sMidAcl   = TempPath ( "midacl"   );

    unsigned char idAlice[p2pcng::kEcdsaPubLen], agrAlice[p2pcng::kEcdhPubLen];
    unsigned char idCarol[p2pcng::kEcdsaPubLen];
    unsigned char idMid  [p2pcng::kEcdsaPubLen];

    if ( !MakeIdentity  ( g_sAliceKey, idAlice  ) ||
         !MakeAgreement ( g_sAliceAgr, agrAlice ) ||
         !MakeIdentity  ( g_sCarolKey, idCarol  ) ||
         !MakeIdentity  ( g_sMidKey,   idMid    )    )
    { Log ( "SETUP: key generation failed" ); return false; }

    for ( int i = 0; i < kRuns; ++i )
    {
      //  IDENTITY ONLY for Carol, and this is the fixture's whole point. Alice
      //  can log in to the relay and reach Carol; she cannot SEAL to her,
      //  because no agreement key for that address was ever published. That is
      //  the "Publish an agreement key for the scope" refusal in
      //  SealAppMsgOutbound, arranged rather than waited for
      if ( p2pcng::AppendAllowList ( g_sAliceAcl.c_str ( ), kMidUtf8[i],
                                     idMid ) != p2pcng::IdOk ||
           p2pcng::AppendAllowList ( g_sAliceAcl.c_str ( ), kCarolUtf8[i],
                                     idCarol ) != p2pcng::IdOk )
      { Log ( "SETUP: Alice allow-list failed" ); return false; }

      if ( p2pcng::AppendAllowList ( g_sCarolAcl.c_str ( ), kMidUtf8[i],
                                     idMid ) != p2pcng::IdOk ||
           p2pcng::AppendAllowList ( g_sCarolAcl.c_str ( ), kAliceUtf8[i],
                                     idAlice ) != p2pcng::IdOk )
      { Log ( "SETUP: Carol allow-list failed" ); return false; }

      if ( p2pcng::AppendAllowList ( g_sMidAcl.c_str ( ), kAliceUtf8[i],
                                     idAlice ) != p2pcng::IdOk ||
           p2pcng::AppendAllowList ( g_sMidAcl.c_str ( ), kCarolUtf8[i],
                                     idCarol ) != p2pcng::IdOk )
      { Log ( "SETUP: middle allow-list failed" ); return false; }
    }
    return true;
}

// ---------------------------------------------------------------------------
static std::atomic<long> g_nRecv  ( 0 );
static HANDLE            g_hReady = NULL;   // auto-reset: a peer has logged in

class WaiveHub : public P2PeerHub
{
public:
    enum Role { RoleAlice, RoleMiddle, RoleCarol };

    WaiveHub ( P2PaddrSTR strAddr, Role eRole )
        : P2PeerHub ( strAddr ), m_eRole ( eRole ) { }
    virtual ~WaiveHub ( ) { }

protected:
    //  NOTES: Returns msgHANDLED WITHOUT calling the base, which stops a
    //         P2Pmsg_BCast arriving at its destination being fanned out again.
    //         p2p_linkcost's Carol does the same, for the same reason
    virtual msgRESULT On_P2PeerBCast ( P2PeerMsg *pMsg ) override
    {
        if ( m_eRole != RoleCarol )
          return msgHANDLED;
        (void)pMsg;
        g_nRecv.fetch_add ( 1 );
        return msgHANDLED;
    }

    //  GUARDED exactly as p2p_linkcost guards it: the bypass is only reachable
    //  where there is no auth gate to bypass, so a phase that requires
    //  authentication cannot quietly measure an unauthenticated link
    virtual conRESULT On_ConLogin ( P2PeerCon *pCon, P2PaddrSTR strThatP2Paddr,
                                    const void *pvLoginMsg, P2Psize_t iSize ) override
    {
        if ( IsAuthRequired ( ) || ( !pvLoginMsg && !iSize ) )
          return P2PeerHub::On_ConLogin ( pCon, strThatP2Paddr, pvLoginMsg, iSize );
        pCon -> OnLogin  ( strThatP2Paddr );
        pCon -> LoginAck ( strThatP2Paddr, 0, 0 );
        return conHANDLED;
    }

    virtual conRESULT On_ConLoginAck ( P2PeerCon *pCon, P2PaddrSTR strThisP2Paddr,
                                       P2PaddrSTR strThatP2Paddr,
                                       const void *pvLoginAck, P2Psize_t iSize ) override
    {
        conRESULT r = P2PeerHub::On_ConLoginAck ( pCon, strThisP2Paddr,
                                                  strThatP2Paddr, pvLoginAck, iSize );
        if ( g_hReady ) SetEvent ( g_hReady );
        return r;
    }

private:
    Role m_eRole;
};

// ===========================================================================
//  Stand the chain up, send ONE message, report whether it arrived.
//  NOTES: One message rather than many, deliberately. The observable is a
//         BOOLEAN - did the seal refuse or did it not - and a count would
//         invite reading a partial delivery as a slow one
// ===========================================================================
static bool RunChain ( int nIx, bool bWaive, long *pnRecv )
{
    *pnRecv = 0;
    g_nRecv.store ( 0 );
    ResetEvent ( g_hReady );

    // ---- the relay ---------------------------------------------------------
    //  NOTES: NO SEAL REQUIREMENT and no agreement key. A hub in the middle
    //         neither originates nor terminates sealed bodies - it forwards
    //         blocks it cannot read
    WaiveHub oMid ( kMidAddr[nIx], WaiveHub::RoleMiddle );
    oMid.RequireAuth       ( true  );
    oMid.RequireRelayAuth  ( false );
    oMid.RequireSeal       ( false );
    oMid.RequireRevocation ( false );
    if ( oMid.SetIdentity  ( g_sMidKey.c_str ( ) ) != p2pcng::IdOk ||
         oMid.SetAllowList ( g_sMidAcl.c_str ( ) ) != p2pcng::IdOk )
    { Log ( "SETUP: middle provisioning failed" ); return false; }

    if ( !oMid.SpawnHub ( ) ) { Log ( "SETUP: middle SpawnHub failed" ); return false; }

    P2PeerConDmx *pSvcA = P2PeerConDmx::ServiceFactory ( kAliceAddr[nIx],
                                                         kSvcAlice[nIx] );
    P2PeerConDmx *pSvcC = P2PeerConDmx::ServiceFactory ( kCarolAddr[nIx],
                                                         kSvcCarol[nIx] );
    if ( !pSvcA || !pSvcC ) { Log ( "SETUP: Dmx ServiceFactory failed" ); return false; }
    oMid.PostP2PeerCon ( pSvcA );
    oMid.PostP2PeerCon ( pSvcC );
    Sleep ( 500 );

    // ---- the destination ---------------------------------------------------
    //  NOTES: NO AGREEMENT KEY, and it costs nothing: Carol opens nothing in
    //         this harness because nothing is ever successfully sealed to her.
    //         With the waiver off the body never leaves Alice; with it on the
    //         body arrives in clear and OpenAppMsgInbound returns early on a
    //         message that is not sealed
    WaiveHub oCarol ( kCarolAddr[nIx], WaiveHub::RoleCarol );
    oCarol.RequireAuth       ( true  );
    oCarol.RequireRelayAuth  ( false );
    oCarol.RequireSeal       ( false );
    oCarol.RequireRevocation ( false );
    if ( oCarol.SetIdentity  ( g_sCarolKey.c_str ( ) ) != p2pcng::IdOk ||
         oCarol.SetAllowList ( g_sCarolAcl.c_str ( ) ) != p2pcng::IdOk )
    { Log ( "SETUP: Carol provisioning failed" ); return false; }

    if ( !oCarol.SpawnHub ( ) ) { Log ( "SETUP: Carol SpawnHub failed" ); return false; }
    P2PeerConDmx *pConC = P2PeerConDmx::ClientFactory ( kMidAddr[nIx],
                                                        kSvcCarol[nIx] );
    if ( !pConC ) { Log ( "SETUP: Carol ClientFactory failed" ); return false; }
    oCarol.PostP2PeerCon ( pConC );
    if ( WaitForSingleObject ( g_hReady, 10000 ) != WAIT_OBJECT_0 )
    { Log ( "SETUP: Carol never logged in" ); return false; }

    // ---- the origin --------------------------------------------------------
    //  NOTES: RequireSeal(true) with her OWN agreement key, so she arms - and
    //         no agreement key for Carol in her allow-list, so she cannot seal
    //         to the destination. That pair is the fixture
    WaiveHub oAlice ( kAliceAddr[nIx], WaiveHub::RoleAlice );
    oAlice.RequireAuth       ( true  );
    oAlice.RequireRelayAuth  ( false );
    oAlice.RequireSeal       ( true  );
    oAlice.RequireRevocation ( false );
    if ( oAlice.SetIdentity     ( g_sAliceKey.c_str ( ) ) != p2pcng::IdOk ||
         oAlice.SetAllowList    ( g_sAliceAcl.c_str ( ) ) != p2pcng::IdOk ||
         oAlice.SetAgreementKey ( g_sAliceAgr.c_str ( ) ) != p2pcng::IdOk    )
    { Log ( "SETUP: Alice provisioning failed" ); return false; }

    //  THE ONE SWITCH BETWEEN THE TWO RUNS
    oAlice.WaiveEndToEndInProcess ( bWaive );

    if ( !oAlice.SpawnHub ( ) ) { Log ( "SETUP: Alice SpawnHub failed" ); return false; }
    P2PeerConDmx *pConA = P2PeerConDmx::ClientFactory ( kMidAddr[nIx],
                                                        kSvcAlice[nIx] );
    if ( !pConA ) { Log ( "SETUP: Alice ClientFactory failed" ); return false; }
    oAlice.PostP2PeerCon ( pConA );
    if ( WaitForSingleObject ( g_hReady, 10000 ) != WAIT_OBJECT_0 )
    { Log ( "SETUP: Alice never logged in" ); return false; }
    Sleep ( 300 );

    //  Carol is a hub in this process and the waiver is keyed on exactly that.
    //  Asserted HERE, on the live registry, rather than assumed - if this is
    //  false the two runs below are not testing what they say they are
    Check ( IsP2PmsgHubInProcess ( kCarolAddr[nIx] ) != FALSE,
            "the destination is a hub this process holds" );

    const char szBody[] = "a body Alice cannot seal to a destination she holds";
    oAlice.PostP2PeerMsg (
      new P2PeerMsg32 ( kAliceAddr[nIx], kCarolAddr[nIx], P2Pmsg_BCast,
                        szBody, (P2Psize_t)( sizeof(szBody) - 1 ) ) );

    //  A fixed wait, and it has to be one: the assertion in the waiver-off run
    //  is that NOTHING arrives, and there is no event for that
    Sleep ( 2000 );
    *pnRecv = g_nRecv.load ( );
    return true;
}

// ===========================================================================
int main ( int argc, char *argv[] )
{
    (void)argc; (void)argv;

    std::printf ( "=== p2p_e2ewaive - securityRevision.md §6.3 ===\n" );
    std::printf ( "Asserting: the end-to-end waiver is OFF by default, keys on "
                  "an EXACT in-process\n"
                  "           hub address, and skips the seal for that and "
                  "nothing else.\n\n" );
    std::fflush ( stdout );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }

    g_hReady = CreateEvent ( NULL, FALSE, FALSE, NULL );
    if ( !g_hReady ) { Log ( "SETUP: CreateEvent failed" ); CleanupP2Pmsg ( ); return 2; }

    // ---- Phase 0: THE PREDICATE -------------------------------------------
    //  The security-critical phase. Everything else in this file is a
    //  consequence of this algebra being right
    Log ( "--- phase 0: IsP2PmsgHubInProcess, on a live registry ---" );
    {
        Check ( IsP2PmsgHubInProcess ( L"Waive.Solo" ) == FALSE,
                "an address with no hub behind it reads FALSE before anything runs" );

        WaiveHub oSolo ( L"Waive.Solo", WaiveHub::RoleMiddle );
        oSolo.RequireAuth       ( false );
        oSolo.RequireSeal       ( false );
        oSolo.RequireRevocation ( false );
        if ( !oSolo.SpawnHub ( ) )
        { Log ( "SETUP: solo SpawnHub failed" ); CleanupP2Pmsg ( ); return 2; }
        Sleep ( 300 );

        Check ( IsP2PmsgHubInProcess ( L"Waive.Solo" ) != FALSE,
                "the hub's own address reads TRUE" );

        //  THE HAZARD, and the reason the match is equality. A child hub may
        //  sit on another host; answering TRUE here would waive the seal on
        //  exactly the traffic that leaves the machine
        Check ( IsP2PmsgHubInProcess ( L"Waive.Solo.Leaf" ) == FALSE,
                "an address BELOW that hub reads FALSE - the match is exact" );
        Check ( IsP2PmsgHubInProcess ( L"Waive.Solo.Branch.Leaf" ) == FALSE,
                "and so does one two levels below it" );
        Check ( IsP2PmsgHubInProcess ( L"Waive" ) == FALSE,
                "a PREFIX of the hub's address reads FALSE" );
        Check ( IsP2PmsgHubInProcess ( L"Waive.Other" ) == FALSE,
                "a sibling that is not a hub reads FALSE" );
        Check ( IsP2PmsgHubInProcess ( L"" ) == FALSE,
                "the empty address is not a wildcard" );
        Check ( IsP2PmsgHubInProcess ( NULL ) == FALSE,
                "and neither is a null one" );
    }
    //  The hub is gone. The predicate reads the LIVE registry, so it must say
    //  so - a stale TRUE here would waive the seal to an address nothing in
    //  this process answers for any more
    Sleep ( 500 );
    Check ( IsP2PmsgHubInProcess ( L"Waive.Solo" ) == FALSE,
            "after the hub is destroyed the address reads FALSE again" );

    // ---- Phase 1: THE DEFAULT ---------------------------------------------
    Log ( "--- phase 1: the default, and it is off ---" );
    {
        WaiveHub oHub ( L"Waive.Default", WaiveHub::RoleMiddle );
        Check ( !oHub.IsEndToEndWaivedInProcess ( ),
                "a hub that called nothing has NOT waived" );

        P2PeerHub::Posture oP;
        std::memset ( &oP, 0, sizeof(oP) );
        Check ( oHub.TryReadPosture ( oP ), "the posture reads" );
        Check ( !oP.bWaiveE2E, "and reports WaiveE2E off" );
        Check ( oP.bSealRequired,
                "beside SealRequired ON - the pair an operator has to be able "
                "to read" );

    }

    // ---- Phase 1b: THE SAME THING THROUGH THE FLAT C ABI ------------------
    //  A SEPARATE HUB, and it has to be: the flat-C entry points resolve a
    //  handle through P2PhandleIs, which only knows objects p2peerhub_create
    //  made. A C++ hub cast to P2PeerHubHandle reads as no hub at all - and it
    //  would read 0 here for that reason rather than because the bit is off,
    //  which is a check that cannot fail and therefore is not one
    Log ( "--- phase 1b: the flat C ABI, on a handle it owns ---" );
    {
        P2PeerHubHandle h = p2peerhub_create ( L"Waive.FlatC" );
        Check ( h != NULL, "p2peerhub_create returns a handle" );
        if ( h )
        {
          Check ( p2peerhub_is_end_to_end_waived_in_process ( h ) == 0,
                  "and it reads NOT waived by default" );

          p2peerhub_waive_end_to_end_in_process ( h, 1 );
          Check ( p2peerhub_is_end_to_end_waived_in_process ( h ) == 1,
                  "the flat C setter takes" );

          p2peerhub_waive_end_to_end_in_process ( h, 0 );
          Check ( p2peerhub_is_end_to_end_waived_in_process ( h ) == 0,
                  "and goes back off" );

          p2peerhub_destroy ( h );
        }
        Check ( p2peerhub_is_end_to_end_waived_in_process ( NULL ) == 0,
                "a null handle reads NOT waived, which is the fail-closed "
                "reading" );
    }

    // ---- Phase 2: THE SETTER ----------------------------------------------
    Log ( "--- phase 2: setting it, and reading it back ---" );
    {
        WaiveHub oHub ( L"Waive.Setter", WaiveHub::RoleMiddle );
        oHub.WaiveEndToEndInProcess ( true );
        Check ( oHub.IsEndToEndWaivedInProcess ( ), "it takes" );

        P2PeerHub::Posture oP;
        std::memset ( &oP, 0, sizeof(oP) );
        Check ( oHub.TryReadPosture ( oP ) && oP.bWaiveE2E,
                "and the posture says so - the decision stays visible" );

        //  It is a switch, not a latch. A posture that could not be put back
        //  would make the waiver a one-way door on a live hub
        oHub.WaiveEndToEndInProcess ( false );
        Check ( !oHub.IsEndToEndWaivedInProcess ( ), "and it goes back off" );

        std::memset ( &oP, 0, sizeof(oP) );
        Check ( oHub.TryReadPosture ( oP ) && !oP.bWaiveE2E,
                "and the posture follows it back" );
    }

    if ( !Provision ( ) ) { CleanupP2Pmsg ( ); return 2; }

    // ---- Phase 3: THE REFUSAL, WAIVER OFF ---------------------------------
    Log ( "--- phase 3: waiver OFF - Alice cannot seal, so she does not send ---" );
    {
        long nRecv = -1;
        if ( !RunChain ( 0, false, &nRecv ) )
        { Log ( "SETUP: chain failed" ); ScrubTempFiles ( ); CleanupP2Pmsg ( ); return 2; }
        std::printf ( "[e2ewaive]   delivered=%ld\n", nRecv );
        Check ( nRecv == 0,
                "the message does NOT arrive - RequireSeal refuses rather than "
                "downgrading" );
    }

    // ---- Phase 4: THE WAIVER ----------------------------------------------
    Log ( "--- phase 4: waiver ON, destination in this process - it goes ---" );
    {
        long nRecv = -1;
        if ( !RunChain ( 1, true, &nRecv ) )
        { Log ( "SETUP: chain failed" ); ScrubTempFiles ( ); CleanupP2Pmsg ( ); return 2; }
        std::printf ( "[e2ewaive]   delivered=%ld\n", nRecv );
        Check ( nRecv == 1,
                "the SAME message arrives - one switch between the two runs" );
    }

    ScrubTempFiles ( );
    if ( g_hReady ) CloseHandle ( g_hReady );
    CleanupP2Pmsg ( );

    std::printf ( "\n[e2ewaive] %d checks, %d failed\n", g_nChecks, g_nFailed );
    if ( g_nFailed )
    {
      std::printf ( "\nRESULT: FAIL - the end-to-end waiver does not hold.\n" );
      return 1;
    }
    std::printf ( "\nRESULT: PASS - off by default, exact on the address, and "
                  "it skips the seal\n"
                  "        for an in-process destination and for nothing "
                  "else.\n" );
    return 0;
}
