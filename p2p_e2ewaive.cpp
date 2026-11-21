// ===========================================================================
//  p2p_e2ewaive - securityRevision.md §6.3, the end-to-end waiver
//
//  ASSERTING: WaiveEndToEndInProcess() waives the seal for a destination this
//  process actually holds, on a link that stays in this process, and for
//  NOTHING ELSE. ON by default since Targetcore 3.6.0 (p2p_performance.md
//  decision 2); it was opt-in, and phases 1/1b asserted OFF, until then.
//
//  3.6.0 ADDED PHASES 5 AND 6, and they are why the default could change. A
//  TCP loopback link is a link that LEAVES THE PROCESS as far as the library
//  can tell (P2Peerio::LeavesProcess is true for every transport except DMX),
//  so a hub reached over one stands in for a hub on another host - the thing
//  the header below says this file could not build. That is exactly the
//  distinction the guards key on, so it is a faithful model of them:
//    - phase 5, A-B-C: Alice -TCP- Mid -DMX- Carol. Guard 1: Alice's own link
//      leaves, so she must seal, cannot, and the body does not arrive.
//    - phase 6, A-A2-B-C: Alice -DMX- Mid -TCP- Far -DMX- Carol, Mid not
//      sealing. Guard 3: Alice waives over her in-process hop, and Mid refuses
//      to put the unsealed body on its leaving link.
//  Each carries an EMPTY-body positive control on the same route, which the
//  seal never touches ("nothing to hide"), so a silent body is a refusal and
//  not a dead link.
//
//  FALSIFIED 2026-11-21, Windows Debug. Guard 3 off: phase 6 red (body=1).
//  Guard 1 off: STILL GREEN, and that is by construction rather than a blind
//  spot - guard 3 runs on every hop including the origin's, so Alice's own
//  unsealed body is refused on her leaving link either way. Guards 1 and 3
//  both off: phases 5 AND 6 red, body=1 each, i.e. the body crossed TCP in
//  clear - the pre-3.6.0 A-B-C leak, reproduced. So phase 5 is held by two
//  guards independently, and phase 6 by guard 3.
//
//  PHASE 7 IS GUARD 2, the receive side, added the same day. A chain cannot
//  reach GateRelayInbound (finding 11, below), so phase 7 uses four hubs:
//  Top -DMX- Src and Top -DMX- P, with Dst below P. Src is not below P, so Dst
//  gates every message from Src. Only Src and Dst require relay attestation,
//  so Src's waiver alone decides whether her message is signed. 7a, Dst on
//  DMX: her unsigned body is admitted (the exemption). 7b, Dst on TCP: the same
//  body is refused (the guard). The control is signed (Src's waiver off for
//  it): the gate refuses an unattested message whatever it carries.
//  FALSIFIED 2026-11-21, Windows Debug: StaysInProcess() dropped from the
//  exemption turns 7b red (body=1); the exemption removed turns 7a red
//  (body=0, "no auth block"). Restored.
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
//    - the DEFAULT, and the posture says which it is. Phases 1 and 2.
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
//    - THE ATTESTATION HALF IN A CHAIN. GateRelayInbound is reached only on
//      an ancestor link carrying a source not at-or-below the peer that
//      delivered it, and in a CHAIN the relay is a common ancestor of both
//      ends - so the descendant test admits first and that gate never runs.
//      That is the topology, not a gap in the waiver, and it is recorded as
//      finding 11 in securityRevision_progress.md. Phase 7 gates it in the
//      p2p_authancestor shape instead.
//
//  PHASES 0-4 USE NO SOCKETS (three hubs over P2PeerConDmx). Phases 5, 6 and
//  7b each listen on one loopback port, argv[1], argv[2] and argv[3], under a
//  RESOURCE_LOCK each.
// ===========================================================================

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConDmx.h"
#include "P2PeerConWsa.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"
#include "P2PIdentityStore.h"
#include "P2PAuthLogin.h"
#include "Targetcore_c.h"

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
//  Runs 0 and 1 are phases 3 and 4 (all DMX); 2 is phase 5 (Alice on TCP);
//  3 is phase 6 (Mid -TCP- Far, Carol below Far).
static const int kRuns = 4;
static const P2PaddrSTR kMidAddr  [kRuns] = { L"WvOff",       L"WvOn",
                                              L"WvTcp",       L"WvRly"           };
static const P2PaddrSTR kAliceAddr[kRuns] = { L"WvOff.Alice", L"WvOn.Alice",
                                              L"WvTcp.Alice", L"WvRly.Alice"     };
static const P2PaddrSTR kCarolAddr[kRuns] = { L"WvOff.Carol", L"WvOn.Carol",
                                              L"WvTcp.Carol", L"WvRly.Far.Carol" };
static const char      *kMidUtf8  [kRuns] = { "WvOff",        "WvOn",
                                              "WvTcp",        "WvRly"            };
static const char      *kAliceUtf8[kRuns] = { "WvOff.Alice",  "WvOn.Alice",
                                              "WvTcp.Alice",  "WvRly.Alice"      };
static const char      *kCarolUtf8[kRuns] = { "WvOff.Carol",  "WvOn.Carol",
                                              "WvTcp.Carol",  "WvRly.Far.Carol"  };
static LPCTSTR          kSvcAlice [kRuns] = { _T("E2EWaiveA0"), _T("E2EWaiveA1"),
                                              _T("E2EWaiveA2"), _T("E2EWaiveA3") };
static LPCTSTR          kSvcCarol [kRuns] = { _T("E2EWaiveC0"), _T("E2EWaiveC1"),
                                              _T("E2EWaiveC2"), _T("E2EWaiveC3") };
//  Phase 6 only: the hub on "the other host", and the listener patterns
static const P2PaddrSTR kFarAddr     = L"WvRly.Far";
static const char      *kFarUtf8     = "WvRly.Far";
static const P2PaddrSTR kTcpDomain   = L"WvTcp.*";
static const P2PaddrSTR kRlyDomain   = L"WvRly.*";

//  Phase 7 only (guard 2): four hubs, so the destination's ancestor-link gate
//  runs at all - finding 11. Src and P are children of Top over DMX; Dst is
//  P's child, over DMX in 7a and TCP in 7b. Src -> Dst arrives at Dst from P,
//  and Src is not below P, so Dst runs GateRelayInbound on it. Row 0 is 7a,
//  row 1 is 7b; separate addresses for the reason given above kRuns
static const P2PaddrSTR kG2Top   [2] = { L"WvRcvD",         L"WvRcvT"         };
static const P2PaddrSTR kG2Src   [2] = { L"WvRcvD.Src",     L"WvRcvT.Src"     };
static const P2PaddrSTR kG2P     [2] = { L"WvRcvD.P",       L"WvRcvT.P"       };
static const P2PaddrSTR kG2Dst   [2] = { L"WvRcvD.P.Dst",   L"WvRcvT.P.Dst"   };
static const char      *kG2TopU8 [2] = { "WvRcvD",          "WvRcvT"          };
static const char      *kG2SrcU8 [2] = { "WvRcvD.Src",      "WvRcvT.Src"      };
static const char      *kG2PU8   [2] = { "WvRcvD.P",        "WvRcvT.P"        };
static const char      *kG2DstU8 [2] = { "WvRcvD.P.Dst",    "WvRcvT.P.Dst"    };
static LPCTSTR          kG2SvcSrc[2] = { _T("E2EWaiveS7a"), _T("E2EWaiveS7b") };
static LPCTSTR          kG2SvcP  [2] = { _T("E2EWaiveP7a"), _T("E2EWaiveP7b") };
static LPCTSTR          kG2SvcDst    =   _T("E2EWaiveD7a");
static const P2PaddrSTR kG2TcpDomain =   L"WvRcvT.P.*";

static std::string g_sAliceKey, g_sAliceAgr, g_sAliceAcl;
static std::string g_sCarolKey,              g_sCarolAcl;
static std::string g_sMidKey,                g_sMidAcl;
static std::string g_sFarKey,                g_sFarAcl;

static bool Provision ( )
{
    g_sAliceKey = TempPath ( "alicekey" );
    g_sAliceAgr = TempPath ( "aliceagr" );
    g_sAliceAcl = TempPath ( "aliceacl" );
    g_sCarolKey = TempPath ( "carolkey" );
    g_sCarolAcl = TempPath ( "carolacl" );
    g_sMidKey   = TempPath ( "midkey"   );
    g_sMidAcl   = TempPath ( "midacl"   );
    g_sFarKey   = TempPath ( "farkey"   );
    g_sFarAcl   = TempPath ( "faracl"   );

    unsigned char idAlice[p2pcng::kEcdsaPubLen], agrAlice[p2pcng::kEcdhPubLen];
    unsigned char idCarol[p2pcng::kEcdsaPubLen];
    unsigned char idMid  [p2pcng::kEcdsaPubLen];
    unsigned char idFar  [p2pcng::kEcdsaPubLen];

    if ( !MakeIdentity  ( g_sAliceKey, idAlice  ) ||
         !MakeAgreement ( g_sAliceAgr, agrAlice ) ||
         !MakeIdentity  ( g_sCarolKey, idCarol  ) ||
         !MakeIdentity  ( g_sMidKey,   idMid    ) ||
         !MakeIdentity  ( g_sFarKey,   idFar    )    )
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

    //  Phase 6's extra hop: Mid and Far log in to each other over TCP, and
    //  Carol logs in to Far over DMX
    if ( p2pcng::AppendAllowList ( g_sMidAcl.c_str ( ),   kFarUtf8,
                                   idFar   ) != p2pcng::IdOk ||
         p2pcng::AppendAllowList ( g_sFarAcl.c_str ( ),   kMidUtf8[3],
                                   idMid   ) != p2pcng::IdOk ||
         p2pcng::AppendAllowList ( g_sFarAcl.c_str ( ),   kCarolUtf8[3],
                                   idCarol ) != p2pcng::IdOk ||
         p2pcng::AppendAllowList ( g_sCarolAcl.c_str ( ), kFarUtf8,
                                   idFar   ) != p2pcng::IdOk    )
    { Log ( "SETUP: phase 6 allow-lists failed" ); return false; }

    //  Phase 7 reuses the four identities under new addresses - an allow-list
    //  maps an ADDRESS to a key, so one key answering for two addresses is two
    //  entries, not a shortcut (perf_fanout does the same). Src = Alice's key
    //  and acl, Top = Mid's, P = Far's, Dst = Carol's. Dst lists Src because
    //  it verifies Src's attestation; nobody else needs to
    for ( int i = 0; i < 2; ++i )
    {
      if ( p2pcng::AppendAllowList ( g_sAliceAcl.c_str ( ), kG2TopU8[i], idMid   ) != p2pcng::IdOk ||
           p2pcng::AppendAllowList ( g_sMidAcl.c_str ( ),   kG2SrcU8[i], idAlice ) != p2pcng::IdOk ||
           p2pcng::AppendAllowList ( g_sMidAcl.c_str ( ),   kG2PU8[i],   idFar   ) != p2pcng::IdOk ||
           p2pcng::AppendAllowList ( g_sFarAcl.c_str ( ),   kG2TopU8[i], idMid   ) != p2pcng::IdOk ||
           p2pcng::AppendAllowList ( g_sFarAcl.c_str ( ),   kG2DstU8[i], idCarol ) != p2pcng::IdOk ||
           p2pcng::AppendAllowList ( g_sCarolAcl.c_str ( ), kG2PU8[i],   idFar   ) != p2pcng::IdOk ||
           p2pcng::AppendAllowList ( g_sCarolAcl.c_str ( ), kG2SrcU8[i], idAlice ) != p2pcng::IdOk    )
      { Log ( "SETUP: phase 7 allow-lists failed" ); return false; }
    }
    return true;
}

// ---------------------------------------------------------------------------
static std::atomic<long> g_nRecv  ( 0 );   // bodies Carol received
static std::atomic<long> g_nEmpty ( 0 );   // EMPTY messages - the controls
static HANDLE            g_hReady = NULL;   // auto-reset: a peer has logged in

class WaiveHub : public P2PeerHub
{
public:
    enum Role { RoleAlice, RoleMiddle, RoleCarol };

    WaiveHub ( P2PaddrSTR strAddr, Role eRole )
        : P2PeerHub ( strAddr ), m_eRole ( eRole ) { }
    //  CLOSE FIRST, and it has to be here rather than in ~P2PeerHub. Every
    //  hub in this suite spawns a pump thread and closes it before the object
    //  dies; this one was the only exception, and TSan charged it two vptr
    //  races for it - the base destructor rewrites the vtable pointer on
    //  ENTRY, so by the time ~P2PeerHub's own CloseHub() runs the pump thread
    //  has already been dispatching virtuals through an object that no longer
    //  has them. One of the two reports caught it mid-seal, inside
    //  P2PeerCon::GetAuthHub from SealAppMsgOutbound. Refer the note on
    //  ~P2PeerHub, which now says so out loud when it catches this.
    virtual ~WaiveHub ( ) { CloseHub ( ); }

protected:
    //  NOTES: Returns msgHANDLED WITHOUT calling the base, which stops a
    //         P2Pmsg_BCast arriving at its destination being fanned out again.
    //         p2p_linkcost's Carol does the same, for the same reason
    virtual msgRESULT On_P2PeerBCast ( P2PeerMsg *pMsg ) override
    {
        if ( m_eRole != RoleCarol )
          return msgHANDLED;
        if ( pMsg && pMsg->DataSize ( ) == 0 )
          g_nEmpty.fetch_add ( 1 );
        else
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

    //  SpawnHub hands back a thread handle the CALLER owns -- Targetcore_c.h
     //  says so in as many words: "THE HANDLE IS YOURS AND YOU DO NOT NEED IT
     //  ... ignoring the return value entirely is a leaked thread handle, not
     //  a leaked thread." Nothing here needs it (CloseHub joins the thread),
     //  so it is taken only to be given straight back. LSan counted four of
     //  these, one per SpawnHub in this file.
    HANDLE hMid = oMid.SpawnHub ( );
    if ( !hMid ) { Log ( "SETUP: middle SpawnHub failed" ); return false; }
    CloseHandle ( hMid );

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

    HANDLE hCarol = oCarol.SpawnHub ( );
    if ( !hCarol ) { Log ( "SETUP: Carol SpawnHub failed" ); return false; }
    CloseHandle ( hCarol );
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

    HANDLE hAlice = oAlice.SpawnHub ( );
    if ( !hAlice ) { Log ( "SETUP: Alice SpawnHub failed" ); return false; }
    CloseHandle ( hAlice );
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
//  Phases 5 and 6: the same Alice, the same Carol, a hop that LEAVES.
//  NOTES: Alice's waiver is NOT SET - these run on the 3.6.0 default, which
//         is the configuration the guards exist for
//       : bRelay false = phase 5, Alice -TCP- Mid -DMX- Carol.
//         bRelay true  = phase 6, Alice -DMX- Mid -TCP- Far -DMX- Carol, and
//         Mid does not seal (RequireSeal(false), as in every run here)
//       : Two messages, EMPTY first. The empty one is the positive control:
//         SealAppMsgOutbound and WaivedBodyLeavesProcess both pass an empty
//         body untouched, so if it does not arrive the route is broken and the
//         run is inconclusive, not green
// ===========================================================================
static bool RunLeaving ( bool bRelay, short nPort, long *pnEmpty, long *pnBody )
{
    const int nIx = bRelay ? 3 : 2;
    *pnEmpty = *pnBody = 0;
    g_nRecv.store ( 0 );
    g_nEmpty.store ( 0 );
    ResetEvent ( g_hReady );

    // ---- the relay, listening on TCP, and on DMX for whoever is in process -
    WaiveHub oMid ( kMidAddr[nIx], WaiveHub::RoleMiddle );
    oMid.RequireAuth       ( true  );
    oMid.RequireRelayAuth  ( false );
    oMid.RequireSeal       ( false );
    oMid.RequireRevocation ( false );
    if ( oMid.SetIdentity  ( g_sMidKey.c_str ( ) ) != p2pcng::IdOk ||
         oMid.SetAllowList ( g_sMidAcl.c_str ( ) ) != p2pcng::IdOk )
    { Log ( "SETUP: middle provisioning failed" ); return false; }
    HANDLE hMid = oMid.SpawnHub ( );
    if ( !hMid ) { Log ( "SETUP: middle SpawnHub failed" ); return false; }
    CloseHandle ( hMid );

    P2PeerConWsa *pSvcTcp = P2PeerConWsa::ServiceFactory (
                              bRelay ? kRlyDomain : kTcpDomain, nPort );
    if ( !pSvcTcp ) { Log ( "SETUP: TCP ServiceFactory failed" ); return false; }
    oMid.PostP2PeerCon ( pSvcTcp );
    if ( bRelay )
    {
      P2PeerConDmx *pSvcA = P2PeerConDmx::ServiceFactory ( kAliceAddr[nIx],
                                                           kSvcAlice[nIx] );
      if ( !pSvcA ) { Log ( "SETUP: Dmx ServiceFactory failed" ); return false; }
      oMid.PostP2PeerCon ( pSvcA );
    }
    else
    {
      P2PeerConDmx *pSvcC = P2PeerConDmx::ServiceFactory ( kCarolAddr[nIx],
                                                           kSvcCarol[nIx] );
      if ( !pSvcC ) { Log ( "SETUP: Dmx ServiceFactory failed" ); return false; }
      oMid.PostP2PeerCon ( pSvcC );
    }
    Sleep ( 500 );

    // ---- phase 6 only: "the other host", reached over TCP ------------------
    WaiveHub oFar ( kFarAddr, WaiveHub::RoleMiddle );
    if ( bRelay )
    {
      oFar.RequireAuth       ( true  );
      oFar.RequireRelayAuth  ( false );
      oFar.RequireSeal       ( false );
      oFar.RequireRevocation ( false );
      if ( oFar.SetIdentity  ( g_sFarKey.c_str ( ) ) != p2pcng::IdOk ||
           oFar.SetAllowList ( g_sFarAcl.c_str ( ) ) != p2pcng::IdOk )
      { Log ( "SETUP: far provisioning failed" ); return false; }
      HANDLE hFar = oFar.SpawnHub ( );
      if ( !hFar ) { Log ( "SETUP: far SpawnHub failed" ); return false; }
      CloseHandle ( hFar );
      P2PeerConDmx *pSvcC = P2PeerConDmx::ServiceFactory ( kCarolAddr[nIx],
                                                           kSvcCarol[nIx] );
      if ( !pSvcC ) { Log ( "SETUP: far Dmx ServiceFactory failed" ); return false; }
      oFar.PostP2PeerCon ( pSvcC );
      P2PeerConWsa *pUp = P2PeerConWsa::ClientFactory ( kMidAddr[nIx],
                                                        L"127.0.0.1", nPort );
      if ( !pUp ) { Log ( "SETUP: far ClientFactory failed" ); return false; }
      oFar.PostP2PeerCon ( pUp );
      if ( WaitForSingleObject ( g_hReady, 15000 ) != WAIT_OBJECT_0 )
      { Log ( "SETUP: far never logged in" ); return false; }
    }

    // ---- the destination, on DMX to its parent -----------------------------
    WaiveHub oCarol ( kCarolAddr[nIx], WaiveHub::RoleCarol );
    oCarol.RequireAuth       ( true  );
    oCarol.RequireRelayAuth  ( false );
    oCarol.RequireSeal       ( false );
    oCarol.RequireRevocation ( false );
    if ( oCarol.SetIdentity  ( g_sCarolKey.c_str ( ) ) != p2pcng::IdOk ||
         oCarol.SetAllowList ( g_sCarolAcl.c_str ( ) ) != p2pcng::IdOk )
    { Log ( "SETUP: Carol provisioning failed" ); return false; }
    HANDLE hCarol = oCarol.SpawnHub ( );
    if ( !hCarol ) { Log ( "SETUP: Carol SpawnHub failed" ); return false; }
    CloseHandle ( hCarol );
    P2PeerConDmx *pConC = P2PeerConDmx::ClientFactory (
                            bRelay ? kFarAddr : kMidAddr[nIx], kSvcCarol[nIx] );
    if ( !pConC ) { Log ( "SETUP: Carol ClientFactory failed" ); return false; }
    oCarol.PostP2PeerCon ( pConC );
    if ( WaitForSingleObject ( g_hReady, 10000 ) != WAIT_OBJECT_0 )
    { Log ( "SETUP: Carol never logged in" ); return false; }

    // ---- the origin: requires sealing, cannot seal to Carol, waiver DEFAULT -
    WaiveHub oAlice ( kAliceAddr[nIx], WaiveHub::RoleAlice );
    oAlice.RequireAuth       ( true  );
    oAlice.RequireRelayAuth  ( false );
    oAlice.RequireSeal       ( true  );
    oAlice.RequireRevocation ( false );
    if ( oAlice.SetIdentity     ( g_sAliceKey.c_str ( ) ) != p2pcng::IdOk ||
         oAlice.SetAllowList    ( g_sAliceAcl.c_str ( ) ) != p2pcng::IdOk ||
         oAlice.SetAgreementKey ( g_sAliceAgr.c_str ( ) ) != p2pcng::IdOk    )
    { Log ( "SETUP: Alice provisioning failed" ); return false; }
    Check ( oAlice.IsEndToEndWaivedInProcess ( ),
            "Alice runs on the default, and the default waives" );
    HANDLE hAlice = oAlice.SpawnHub ( );
    if ( !hAlice ) { Log ( "SETUP: Alice SpawnHub failed" ); return false; }
    CloseHandle ( hAlice );
    P2PeerCon *pConA = bRelay
      ? (P2PeerCon *)P2PeerConDmx::ClientFactory ( kMidAddr[nIx], kSvcAlice[nIx] )
      : (P2PeerCon *)P2PeerConWsa::ClientFactory ( kMidAddr[nIx],
                                                   L"127.0.0.1", nPort );
    if ( !pConA ) { Log ( "SETUP: Alice ClientFactory failed" ); return false; }
    oAlice.PostP2PeerCon ( pConA );
    if ( WaitForSingleObject ( g_hReady, 15000 ) != WAIT_OBJECT_0 )
    { Log ( "SETUP: Alice never logged in" ); return false; }
    Sleep ( 300 );

    Check ( IsP2PmsgHubInProcess ( kCarolAddr[nIx] ) != FALSE,
            "the destination is a hub this process holds" );

    //  The control first: an empty body is never sealed and never refused
    oAlice.PostP2PeerMsg (
      new P2PeerMsg32 ( kAliceAddr[nIx], kCarolAddr[nIx], P2Pmsg_BCast,
                        "", (P2Psize_t)0 ) );
    const char szBody[] = "a body that must not cross a link leaving the process";
    oAlice.PostP2PeerMsg (
      new P2PeerMsg32 ( kAliceAddr[nIx], kCarolAddr[nIx], P2Pmsg_BCast,
                        szBody, (P2Psize_t)( sizeof(szBody) - 1 ) ) );

    Sleep ( 3000 );
    *pnEmpty = g_nEmpty.load ( );
    *pnBody  = g_nRecv.load  ( );
    return true;
}

// ===========================================================================
//  Phase 7: guard 2, the receive side.
//  NOTES: bTcp false = 7a, Dst on DMX to P: the unsigned body is ADMITTED,
//         which is the exemption working (and without it the waiver would
//         break attestation, the reason the receive half exists at all).
//         bTcp true = 7b, Dst on TCP to P: the same unsigned body is REFUSED,
//         because the link it arrived on leaves the process.
//       : Only Src and Dst require relay attestation. A hub signs for any
//         source at or below itself (AttestAppMsgOutbound), so a relaying Top
//         that required it would sign for Src and the gate would have nothing
//         unsigned to judge
//       : THE CONTROL IS SIGNED: Src sends it with her waiver OFF, and it has
//         to arrive before she turns the waiver back on and sends the body.
//         An empty body would not do here - unlike the seal, the gate refuses
//         an unattested message whatever it carries.
//       : A refusal at the gate DROPS THE LINK (it throws), which is why the
//         control goes first and nothing is sent after the body
// ===========================================================================
static bool SetUpHub ( WaiveHub &oHub, const std::string &sKey,
                       const std::string &sAcl, bool bRelayAuth )
{
    oHub.RequireAuth       ( true  );
    oHub.RequireRelayAuth  ( bRelayAuth );
    oHub.RequireSeal       ( false );
    oHub.RequireRevocation ( false );
    if ( oHub.SetIdentity  ( sKey.c_str ( ) ) != p2pcng::IdOk ||
         oHub.SetAllowList ( sAcl.c_str ( ) ) != p2pcng::IdOk )
      return false;
    HANDLE h = oHub.SpawnHub ( );
    if ( !h ) return false;
    CloseHandle ( h );
    return true;
}

static bool RunGate2 ( bool bTcp, short nPort, long *pnCtl, long *pnBody )
{
    const int i = bTcp ? 1 : 0;
    *pnCtl = *pnBody = 0;
    g_nRecv.store ( 0 );
    g_nEmpty.store ( 0 );
    ResetEvent ( g_hReady );

    // ---- Top: DMX services for its two children ---------------------------
    WaiveHub oTop ( kG2Top[i], WaiveHub::RoleMiddle );
    if ( !SetUpHub ( oTop, g_sMidKey, g_sMidAcl, false ) )
    { Log ( "SETUP: top failed" ); return false; }
    P2PeerConDmx *pSvcS = P2PeerConDmx::ServiceFactory ( kG2Src[i], kG2SvcSrc[i] );
    P2PeerConDmx *pSvcP = P2PeerConDmx::ServiceFactory ( kG2P[i],   kG2SvcP[i]   );
    if ( !pSvcS || !pSvcP ) { Log ( "SETUP: top Dmx ServiceFactory failed" ); return false; }
    oTop.PostP2PeerCon ( pSvcS );
    oTop.PostP2PeerCon ( pSvcP );
    Sleep ( 500 );

    // ---- P: Top's child, Dst's parent -------------------------------------
    WaiveHub oP ( kG2P[i], WaiveHub::RoleMiddle );
    if ( !SetUpHub ( oP, g_sFarKey, g_sFarAcl, false ) )
    { Log ( "SETUP: P failed" ); return false; }
    P2PeerCon *pSvcD = bTcp
      ? (P2PeerCon *)P2PeerConWsa::ServiceFactory ( kG2TcpDomain, nPort )
      : (P2PeerCon *)P2PeerConDmx::ServiceFactory ( kG2Dst[i], kG2SvcDst );
    if ( !pSvcD ) { Log ( "SETUP: P ServiceFactory failed" ); return false; }
    oP.PostP2PeerCon ( pSvcD );
    P2PeerConDmx *pUpP = P2PeerConDmx::ClientFactory ( kG2Top[i], kG2SvcP[i] );
    if ( !pUpP ) { Log ( "SETUP: P ClientFactory failed" ); return false; }
    oP.PostP2PeerCon ( pUpP );
    if ( WaitForSingleObject ( g_hReady, 10000 ) != WAIT_OBJECT_0 )
    { Log ( "SETUP: P never logged in" ); return false; }
    Sleep ( 300 );

    // ---- Dst: requires attestation, waiver at its default (on) -------------
    WaiveHub oDst ( kG2Dst[i], WaiveHub::RoleCarol );
    if ( !SetUpHub ( oDst, g_sCarolKey, g_sCarolAcl, true ) )
    { Log ( "SETUP: Dst failed" ); return false; }
    Check ( oDst.IsEndToEndWaivedInProcess ( ),
            "Dst runs on the default, and the default waives" );
    P2PeerCon *pUpD = bTcp
      ? (P2PeerCon *)P2PeerConWsa::ClientFactory ( kG2P[i], L"127.0.0.1", nPort )
      : (P2PeerCon *)P2PeerConDmx::ClientFactory ( kG2P[i], kG2SvcDst );
    if ( !pUpD ) { Log ( "SETUP: Dst ClientFactory failed" ); return false; }
    oDst.PostP2PeerCon ( pUpD );
    if ( WaitForSingleObject ( g_hReady, 15000 ) != WAIT_OBJECT_0 )
    { Log ( "SETUP: Dst never logged in" ); return false; }

    // ---- Src: signs when her waiver is off, not when it is on --------------
    WaiveHub oSrc ( kG2Src[i], WaiveHub::RoleAlice );
    if ( !SetUpHub ( oSrc, g_sAliceKey, g_sAliceAcl, true ) )
    { Log ( "SETUP: Src failed" ); return false; }
    oSrc.WaiveEndToEndInProcess ( false );
    P2PeerConDmx *pUpS = P2PeerConDmx::ClientFactory ( kG2Top[i], kG2SvcSrc[i] );
    if ( !pUpS ) { Log ( "SETUP: Src ClientFactory failed" ); return false; }
    oSrc.PostP2PeerCon ( pUpS );
    if ( WaitForSingleObject ( g_hReady, 10000 ) != WAIT_OBJECT_0 )
    { Log ( "SETUP: Src never logged in" ); return false; }
    Sleep ( 300 );

    Check ( IsP2PmsgHubInProcess ( kG2Src[i] ) != FALSE,
            "the source is a hub this process holds" );

    //  The control: signed, so admitted on either link
    oSrc.PostP2PeerMsg (
      new P2PeerMsg32 ( kG2Src[i], kG2Dst[i], P2Pmsg_BCast, "", (P2Psize_t)0 ) );
    for ( int n = 0; n < 100 && g_nEmpty.load ( ) == 0; ++n )
      Sleep ( 50 );
    *pnCtl = g_nEmpty.load ( );
    if ( *pnCtl != 1 )
      return true;                      // the caller reports it inconclusive

    //  The body: Src waives, so it goes UNSIGNED - the case guard 2 judges
    oSrc.WaiveEndToEndInProcess ( true );
    const char szBody[] = "an unsigned body from an in-process source";
    oSrc.PostP2PeerMsg (
      new P2PeerMsg32 ( kG2Src[i], kG2Dst[i], P2Pmsg_BCast,
                        szBody, (P2Psize_t)( sizeof(szBody) - 1 ) ) );
    Sleep ( 3000 );
    *pnBody = g_nRecv.load ( );
    return true;
}

// ===========================================================================
int main ( int argc, char *argv[] )
{
    const short nPortTcp = ( argc >= 2 ) ? (short)atoi ( argv[1] ) : 7829;
    const short nPortRly = ( argc >= 3 ) ? (short)atoi ( argv[2] ) : 7831;
    const short nPortRcv = ( argc >= 4 ) ? (short)atoi ( argv[3] ) : 7832;

    std::printf ( "=== p2p_e2ewaive - securityRevision.md §6.3 ===\n" );
    std::printf ( "Asserting: the end-to-end waiver is ON by default (3.6.0), "
                  "keys on an EXACT\n"
                  "           in-process hub address AND a link that stays in "
                  "the process, and skips\n"
                  "           the seal for that and nothing else.\n\n" );
    std::fflush ( stdout );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }
    WSADATA oWsaData;
    WSAStartup ( MAKEWORD ( 2, 2 ), &oWsaData );

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
        HANDLE hSolo = oSolo.SpawnHub ( );
        if ( !hSolo )
        { Log ( "SETUP: solo SpawnHub failed" ); CleanupP2Pmsg ( ); return 2; }
        CloseHandle ( hSolo );
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
    //  ON since 3.6.0 (p2p_performance.md decision 2). Until then this phase
    //  asserted OFF, and the default was the waiver's whole safety; phases 5
    //  and 6 are what replaced it
    Log ( "--- phase 1: the default, and it is ON (3.6.0) ---" );
    {
        WaiveHub oHub ( L"Waive.Default", WaiveHub::RoleMiddle );
        Check ( oHub.IsEndToEndWaivedInProcess ( ),
                "a hub that called nothing HAS waived - the 3.6.0 default" );

        P2PeerHub::Posture oP;
        std::memset ( &oP, 0, sizeof(oP) );
        Check ( oHub.TryReadPosture ( oP ), "the posture reads" );
        Check ( oP.bWaiveE2E, "and reports WaiveE2E on" );
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
          Check ( p2peerhub_is_end_to_end_waived_in_process ( h ) == 1,
                  "and it reads WAIVED by default (3.6.0)" );

          p2peerhub_waive_end_to_end_in_process ( h, 0 );
          Check ( p2peerhub_is_end_to_end_waived_in_process ( h ) == 0,
                  "the flat C setter opts out" );

          p2peerhub_waive_end_to_end_in_process ( h, 1 );
          Check ( p2peerhub_is_end_to_end_waived_in_process ( h ) == 1,
                  "and back in" );

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

    // ---- Phase 5: GUARD 1, A-B-C ------------------------------------------
    //  Alice's own link leaves the process. Before 3.6.0, with the waiver on,
    //  this body went over it unsealed; now Alice must seal, cannot, and the
    //  body does not leave her
    Log ( "--- phase 5: waiver ON (default), Alice's link LEAVES - she must seal ---" );
    {
        long nEmpty = -1, nBody = -1;
        if ( !RunLeaving ( false, nPortTcp, &nEmpty, &nBody ) )
        { Log ( "SETUP: phase 5 chain failed" ); ScrubTempFiles ( ); CleanupP2Pmsg ( ); return 2; }
        std::printf ( "[e2ewaive]   control=%ld body=%ld\n", nEmpty, nBody );
        if ( nEmpty != 1 )
        { Log ( "INCONCLUSIVE: the empty control did not arrive - the route is down" );
          ScrubTempFiles ( ); CleanupP2Pmsg ( ); return 3; }
        Check ( nBody == 0,
                "the body does NOT arrive - a leaving hop is sealed or refused, "
                "never waived" );
    }

    // ---- Phase 6: GUARD 3, A-A2-B-C ---------------------------------------
    //  Alice waives over her in-process hop to Mid, as she should; Mid does not
    //  seal, and its next hop leaves the process. Mid must refuse
    Log ( "--- phase 6: waived over an in-process hop, relayed onto a LEAVING one ---" );
    {
        long nEmpty = -1, nBody = -1;
        if ( !RunLeaving ( true, nPortRly, &nEmpty, &nBody ) )
        { Log ( "SETUP: phase 6 chain failed" ); ScrubTempFiles ( ); CleanupP2Pmsg ( ); return 2; }
        std::printf ( "[e2ewaive]   control=%ld body=%ld\n", nEmpty, nBody );
        if ( nEmpty != 1 )
        { Log ( "INCONCLUSIVE: the empty control did not arrive - the route is down" );
          ScrubTempFiles ( ); CleanupP2Pmsg ( ); return 3; }
        Check ( nBody == 0,
                "the body does NOT arrive - the relay refuses rather than put a "
                "waived body on a leaving link" );
    }

    // ---- Phase 7: GUARD 2, the receive side -------------------------------
    //  7a is the exemption (an unsigned message from an in-process source on
    //  an in-process link is admitted); 7b is the guard (the same message on a
    //  link that leaves is refused). Without 7a, 7b would pass on a gate that
    //  refuses everything unsigned, which proves nothing about the exemption
    Log ( "--- phase 7a: unsigned, in-process source, arrives over DMX - admitted ---" );
    {
        long nCtl = -1, nBody = -1;
        if ( !RunGate2 ( false, nPortRcv, &nCtl, &nBody ) )
        { Log ( "SETUP: phase 7a failed" ); ScrubTempFiles ( ); CleanupP2Pmsg ( ); return 2; }
        std::printf ( "[e2ewaive]   control=%ld body=%ld\n", nCtl, nBody );
        if ( nCtl != 1 )
        { Log ( "INCONCLUSIVE: the signed control did not arrive - the route is down" );
          ScrubTempFiles ( ); CleanupP2Pmsg ( ); return 3; }
        Check ( nBody == 1,
                "the body arrives - the receive side exempts an in-process "
                "source on an in-process link" );
    }
    Log ( "--- phase 7b: the same, arriving over TCP - refused ---" );
    {
        long nCtl = -1, nBody = -1;
        if ( !RunGate2 ( true, nPortRcv, &nCtl, &nBody ) )
        { Log ( "SETUP: phase 7b failed" ); ScrubTempFiles ( ); CleanupP2Pmsg ( ); return 2; }
        std::printf ( "[e2ewaive]   control=%ld body=%ld\n", nCtl, nBody );
        if ( nCtl != 1 )
        { Log ( "INCONCLUSIVE: the signed control did not arrive - the route is down" );
          ScrubTempFiles ( ); CleanupP2Pmsg ( ); return 3; }
        Check ( nBody == 0,
                "the body does NOT arrive - an in-process source on a link "
                "that leaves must be attested" );
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
    std::printf ( "\nRESULT: PASS - on by default, exact on the address, and "
                  "it skips the seal\n"
                  "        for an in-process destination over in-process "
                  "links and for nothing else.\n" );
    return 0;
}
