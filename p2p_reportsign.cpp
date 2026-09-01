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
// p2p_reportsign.cpp - F-S9-1: the undeliverable report, and the exemption it
//                      used to need.
//
// ---------------------------------------------------------------------------
// THE FINDING
//
//   P2PeerCon::GateRelayInbound binds a relayed message's source to the
//   identity that SIGNED it, and refuses one that arrives down a link to an
//   ancestor claiming a source nobody has attested for. p2p_authancestor is
//   the gate on that rule.
//
//   The library's own undeliverable report could never satisfy it. The report
//   was built by WrappedResponseFactory, which SWAPS the two addresses - so it
//   was sourced from the address that could not be reached. A report for
//   "Ghost.Nowhere" therefore arrived declaring a source in no branch at all,
//   carrying no attestation, because nobody holds a key for an address that
//   does not exist. It is byte-for-byte the shape the gate refuses.
//
//   So the gate exempted P2Pmsg_Exception BY CLASS, and the residual was
//   recorded rather than glossed: a peer on an ancestor link could forge an
//   undeliverable report claiming ANY source. It could not deliver application
//   traffic that way - everything the P2PeerMsg_MAP dispatches was still bound
//   - but it could tell an application that a message had failed when it had
//   not, or hand it a fabricated error attributed to an arbitrary address.
//   ProductionPlan.md carried that as F-S9-1.
//
// WHAT CLOSES IT, AND WHERE
//
//   Not a better predicate at the gate - the TRUTH at the source. The report
//   is not from the address that could not be reached; it is from the hub that
//   could not reach it, and that hub can speak for itself.
//   P2PeerTarget::RouteP2PeerMsg now stamps the report with its own hub
//   address, and the class exemption is GONE.
//
//   Two consequences, and this test asserts both because they fail
//   differently:
//
//     ONE HOP DOWN the reader's peer IS the reporting hub, so the plain
//     descendant test admits the report before GateRelayInbound is reached.
//     No keys, no allow-list, no provisioning of any kind. That is the common
//     deployment and p2p_bigreport is its guard.
//
//     FURTHER DOWN the reader's peer is a relay, the reporting hub is above
//     it, and the source is outside the relay's subtree - so the report must
//     be ATTESTED like anything else. It is: AttestAppMsgOutbound signs it as
//     the origin, because the hub now holds a key for the address the report
//     declares. That is the whole of "the reporting hub signs the report as
//     itself", and it is what this test is shaped to reach.
//
// ---------------------------------------------------------------------------
// WHY THIS NEEDS THREE HUBS
//
//   Two would prove only the easy half. With the reader one hop below the
//   reporting hub, the descendant test admits the report and the attestation
//   path is never entered - so a green run would say nothing about signing.
//   Putting a keyless relay in between is what forces the report through
//   GateRelayInbound, which is the branch F-S9-1 lived in.
//
//       Rep                       (service on nPort - raises the report,
//        |                         and the ONLY hub holding an identity)
//       Rep.Mid                   (client of Rep, AND service on nPort+1 -
//        |                         the relay, holds no keys at all)
//       Rep.Mid.Leaf              (client of Rep.Mid - the gate under test,
//                                  allow-list naming Rep and nothing else)
//
//   At the Leaf, m_oThatP2Paddr is "Rep.Mid". A source of "Rep" is NOT at or
//   below it, so the Leaf's inbound gate takes the ancestor branch and the
//   report has to carry a signature. A source of "Ghost.Nowhere" is not at or
//   below it either, which is phase 3.
//
//   PHASE 1  POSITIVE CONTROL. Rep.Mid posts a BCast sourced "Rep.Mid" -
//            itself. At or below the peer, so the DESCENDANT test admits it
//            and none of this is involved. Without it a refusal and a broken
//            transport are the same thing: silence.
//
//   PHASE 2  THE REPORT, RELAYED. The Leaf posts a BCast to "Ghost.Nowhere".
//            It routes up to Rep, which has no connection that can reach it
//            and raises the report; the report comes back DOWN through the
//            keyless relay. It must ARRIVE, and it must declare "Rep" as its
//            source. Two separate assertions with two separate exit codes,
//            because a report that arrives sourced "Ghost.Nowhere" means the
//            exemption is still doing the work and the stamp is not.
//
//   PHASE 3  THE FORGERY - the pre-fix report shape, replayed by a peer not
//            entitled to it. Rep.Mid builds a report exactly as the library
//            used to: an ExceptionFactory response to a BCast addressed to
//            "Ghost.Nowhere", which comes out sourced "Ghost.Nowhere" and
//            addressed to the Leaf. Nothing about it is malformed; it is what
//            every undeliverable report looked like until this fix. It must
//            be REFUSED and the connection dropped.
//
//   ORDER MATTERS AND IS NOT ARBITRARY: a refusal DROPS THE CONNECTION, so
//   the two phases that must arrive run before the one that must not.
//
// WHAT A GREEN RUN DOES NOT SAY. It does not say a forged report is
// impossible - a hub that IS entitled to the source it claims can still
// report a failure that did not happen, and no signature distinguishes a
// lying hub from a mistaken one. It says the claim is now BOUND to an
// identity, which is the same thing every other message on this link gets and
// is exactly what the class exemption removed.
//
// VERDICT = process EXIT CODE:
//   0  PASS   the report arrived, sourced by the hub that raised it and
//             attested by it; the forged report was refused
//   1  FAIL   phase 3: the forged report was ADMITTED. The class exemption is
//             back, or GateRelayInbound is not being reached
//   2  SETUP  startup / key / factory failure (test inconclusive)
//   3  INCONCLUSIVE the positive control never arrived - the transport is
//             broken, so nothing after it proves anything. NOT a pass
//   4  FAIL   phase 2: the report never arrived at all. With the exemption
//             gone and the source unstamped this is what happens, and it is
//             the defect SECURITY.md's "Undeliverable report" row records as
//             fixed - the sender is not told
//   5  FAIL   phase 2: the report ARRIVED but declared the wrong source. The
//             stamp did not happen, so it is being admitted by something
//             other than the rule - check that the class exemption really is
//             gone from GateRelayInbound

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConWsa.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"
#include "P2PIdentityStore.h"
#include "P2PAuthLogin.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
static const P2PaddrSTR kRootAddr  = L"Rep";              // raises the report
static const P2PaddrSTR kMidAddr   = L"Rep.Mid";          // the keyless relay
static const P2PaddrSTR kLeafAddr  = L"Rep.Mid.Leaf";     // the gate under test
static const P2PaddrSTR kGhostAddr = L"Ghost.Nowhere";    // routable nowhere

//  The domain check is p2p_authgate's subject, not this one's; a narrower
//  pattern would only be a second thing able to fail this test.
static const P2PaddrSTR kDomain    = L"*";

static const wchar_t kPayControl[] = L"phase1-from-the-relay-itself";
static const wchar_t kPayReport [] = L"phase2-seed-for-the-undeliverable-report";
static const wchar_t kPayForged [] = L"phase3-seed-for-the-forged-report";

static HANDLE g_hMidUp    = NULL;   // Rep.Mid has logged in to Rep
static HANDLE g_hLeafUp   = NULL;   // Rep.Mid.Leaf has logged in to Rep.Mid
static HANDLE g_hControl  = NULL;   // phase 1 reached the Leaf
static HANDLE g_hReport   = NULL;   // phase 2's report reached the Leaf
static HANDLE g_hForged   = NULL;   // phase 3's forgery reached the Leaf - must not
static HANDLE g_hConClose = NULL;   // the Leaf's connection went down

//  Phase 2 and phase 3 both arrive as an exception wrapping a BCast, so the
//  handler cannot tell them apart by shape. It does not have to: main() waits
//  for phase 2 to be decided before phase 3 is even posted, and this flag is
//  what carries that ordering into the handler.
static bool        g_bPhase3 = false;
//  What phase 2's report DECLARED. Recorded rather than compared in the
//  handler, so the assertion and its diagnosis live at the phase.
static std::wstring g_wReportSource;

static void Log ( const char *msg )
{
    std::printf ( "[reportsign] %s\n", msg );
    std::fflush ( stdout );
}

static std::string N ( const wchar_t *w )
{
    std::string s;
    if ( w ) for ( ; *w; ++w )
    {
        unsigned long c = (unsigned long)*w;
        s.push_back ( c < 0x80 ? (char)c : '?' );
    }
    return s;
}

//  THE PAYLOAD POINTER IS NOT ALIGNED, so it cannot be read as wchar_t in
//  place - P2PeerMsg::Data() addresses application bytes inside a pack(1)
//  image. Copying them out into storage the caller aligned is the contract
//  F-S5-3 closed on; see P3PmsgData::c_vBlobCopy() for the same thing offered
//  as an accessor.
static std::wstring BodyW ( P2PeerMsg *pMsg )
{
    if ( !pMsg || !pMsg->Data ( ) ) return std::wstring ( );
    const size_t cb = (size_t)pMsg->DataSize ( );
    std::wstring w ( cb / sizeof(wchar_t), L'\0' );
    if ( !w.empty ( ) )
      std::memcpy ( &w[0], pMsg->Data ( ), w.size ( ) * sizeof(wchar_t) );
    const size_t nNul = w.find ( L'\0' );
    if ( nNul != std::wstring::npos ) w.resize ( nNul );
    return w;
}

// ---------------------------------------------------------------------------
// Provisioning. The private key stays in its file; only the public point is
// published into the Leaf's allow-list.
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
                    (unsigned long)GetCurrentProcessId() );
    s += "p2p_reportsign_"; s += pszLeaf; s += "_"; s += szPid; s += ".tmp";
    DeleteFileA ( s.c_str() );
    g_vTempFiles.push_back ( s );
    return s;
}

static void ScrubTempFiles ( )
{
    for ( size_t i = 0; i < g_vTempFiles.size(); ++i )
        DeleteFileA ( g_vTempFiles[i].c_str() );
    g_vTempFiles.clear();
}

static bool MakeIdentity ( const std::string &sPath, unsigned char *pPubOut )
{
    p2pcng::EcdsaP256 oKey;
    if ( !oKey.Generate() )                                            return false;
    if ( p2pcng::SaveIdentity ( sPath.c_str(), oKey ) != p2pcng::IdOk ) return false;
    return oKey.ExportPublic ( pPubOut );
}

// =========================================================================
class ReportHub : public P2PeerHub
{
public:
    enum Role { RoleRoot, RoleMid, RoleLeaf };

    ReportHub ( P2PaddrSTR strAddr, Role eRole )
        : P2PeerHub ( strAddr ), m_eRole ( eRole ) { }
    virtual ~ReportHub ( ) { }

    // Phase 1. The relay speaking for itself - admitted by the descendant test,
    // so nothing under test here is involved.
    void PostAs ( P2PaddrSTR strSource, const wchar_t *lpszPayload )
    {
        P2Psize_t nBytes =
            (P2Psize_t)( ( wcslen ( lpszPayload ) + 1 ) * sizeof(wchar_t) );
        PostP2PeerMsg ( new P2PeerMsg32 ( strSource, kLeafAddr,
                                          P2Pmsg_BCast, lpszPayload, nBytes ) );
        std::printf ( "[reportsign] %s posted a BCast to the Leaf sourced '%s'\n",
                      RoleName(), N ( strSource ).c_str() );
        std::fflush ( stdout );
    }

    // Phase 2. Posted BY THE LEAF, and the report comes back on its own.
    void PostToNowhere ( const wchar_t *lpszPayload )
    {
        P2Psize_t nBytes =
            (P2Psize_t)( ( wcslen ( lpszPayload ) + 1 ) * sizeof(wchar_t) );
        PostP2PeerMsg ( new P2PeerMsg32 ( kLeafAddr, kGhostAddr,
                                          P2Pmsg_BCast, lpszPayload, nBytes ) );
        std::printf ( "[reportsign] LEAF posted a BCast to '%s'\n",
                      N ( kGhostAddr ).c_str() );
        std::fflush ( stdout );
    }

    // Phase 3. THE PRE-FIX REPORT SHAPE, built the way the library used to
    // build it and posted by a hub that is not entitled to the source it comes
    // out with. Nothing here is malformed or hand-assembled: ExceptionFactory
    // swaps the addresses, so answering a BCast addressed to "Ghost.Nowhere"
    // produces a report SOURCED "Ghost.Nowhere" and addressed to the Leaf -
    // which is exactly what every undeliverable report looked like until the
    // stamp went in, and exactly what the class exemption used to admit.
    bool PostForgedReport ( )
    {
        P2Psize_t nBytes =
            (P2Psize_t)( ( wcslen ( kPayForged ) + 1 ) * sizeof(wchar_t) );
        P2PeerMsg32 oSeed ( kLeafAddr, kGhostAddr, P2Pmsg_BCast,
                            kPayForged, nBytes );

        // The event the live path attaches, without AFPmsg() - the same
        // omission RouteP2PeerMsg makes, and for the same reason.
        P2Pevent *pEVT = EVERR->MODULE
                              ->Message_T("Message not deliverable")
                              ->Advice_T ("Connection lost")
                              ->HResult  (P2Pevent_UNDELIVERABLE)
                              ->Group    ("P2P");
        P2PeerMsg *pFake = oSeed.ExceptionFactory ( pEVT );
        pEVT -> Cancel ( );
        if ( !pFake )
          return false;

        std::printf ( "[reportsign] MID posted a FORGED report sourced '%s' to '%s'\n",
                      N ( pFake->GetSource() ).c_str(),
                      N ( pFake->GetDestin() ).c_str() );
        std::fflush ( stdout );
        PostP2PeerMsg ( pFake );
        return true;
    }

protected:
    // Every message each hub routes, named. Kept rather than removed: the
    // failure this test guards produces SILENCE at the routing hub, and a
    // trace showing a message arriving and nothing coming back is what
    // separates that from a message that never left.
    virtual msgRESULT PeekP2PeerMsg ( P2PeerMsg *pMsg ) override
    {
        std::printf ( "[reportsign] %s routing '%s' %s -> %s\n", RoleName(),
                      pMsg ? N ( pMsg->c_name()    ).c_str() : "<null>",
                      pMsg ? N ( pMsg->GetSource() ).c_str() : "<null>",
                      pMsg ? N ( pMsg->GetDestin() ).c_str() : "<null>" );
        std::fflush ( stdout );
        return P2PeerHub::PeekP2PeerMsg ( pMsg );
    }

    virtual msgRESULT On_P2PeerBCast ( P2PeerMsg *pMsg ) override
    {
        if ( m_eRole == RoleLeaf && pMsg )
        {
            const std::wstring wBody = BodyW ( pMsg );
            std::printf ( "[reportsign] LEAF BCast handler; source='%s' body='%s'\n",
                          N ( pMsg->GetSource() ).c_str(), N ( wBody.c_str() ).c_str() );
            std::fflush ( stdout );
            if ( wBody == kPayControl && g_hControl )
              SetEvent ( g_hControl );
        }
        return P2PeerHub::On_P2PeerBCast ( pMsg );
    }

    // THE ARRIVAL THIS TEST WAITS ON, and it is not the obvious one. A report
    // is a P2Pmsg_Exception WRAPPING the undeliverable message, and dispatch
    // matches on the name of the message it wraps - so a report about a BCast
    // lands in the ON_P2PeerMsg_CATCH(P2Pmsg_BCast, On_MsgCatch) entry, not in
    // the ON_P2PeerMsg_CATCH(P2Pmsg_Exception, ...) one. Both are taken here
    // so the test cannot be fooled by that routing detail.
    virtual msgRESULT On_MsgCatch ( P2PeerMsg *pMsg ) override
    {
        if ( m_eRole == RoleLeaf )
            NoteReport ( pMsg, "On_MsgCatch" );
        return P2PeerHub::On_MsgCatch ( pMsg );
    }

    virtual msgRESULT On_MsgCatchCatch ( P2PeerMsg *pMsg ) override
    {
        if ( m_eRole == RoleLeaf )
            NoteReport ( pMsg, "On_MsgCatchCatch" );
        return P2PeerHub::On_MsgCatchCatch ( pMsg );
    }

    // The failure signature of a refusal: instead of a message, the link goes
    // down. Phase 3 wants exactly this and phases 1 and 2 must not produce it.
    virtual conRESULT On_ConClose ( P2PeerCon *pCon ) override
    {
        if ( m_eRole == RoleLeaf )
        {
            Log ( "LEAF connection CLOSED" );
            if ( g_hConClose ) SetEvent ( g_hConClose );
        }
        return P2PeerHub::On_ConClose ( pCon );
    }

    // Server side of the login, and not merely for the trace. Rep loads an
    // identity because it must SIGN; that same key makes P2PeerCon sign its
    // LOGIN too, and a hub requiring no authentication hands the block up as
    // login payload - which the stock handler refuses outright. The same note
    // is on p2p_authancestor and p2p_sealhop, for the same reason.
    virtual conRESULT On_ConLogin ( P2PeerCon *pCon, P2PaddrSTR strThatP2Paddr,
                                    const void *pvLoginMsg,
                                    P2Psize_t iSize ) override
    {
        std::printf ( "[reportsign] %s: login FROM '%s' (%d bytes of payload)\n",
                      RoleName(), N ( strThatP2Paddr ).c_str(), (int)iSize );
        std::fflush ( stdout );

        if ( strThatP2Paddr )
        {
            if      ( wcscmp ( strThatP2Paddr, kMidAddr  ) == 0 )
            { if ( g_hMidUp  ) SetEvent ( g_hMidUp  ); }
            else if ( wcscmp ( strThatP2Paddr, kLeafAddr ) == 0 )
            { if ( g_hLeafUp ) SetEvent ( g_hLeafUp ); }
        }

        if ( pvLoginMsg && iSize )
        {
            pCon -> OnLogin  ( strThatP2Paddr );
            pCon -> LoginAck ( strThatP2Paddr, 0, 0 );
            return conHANDLED;
        }
        return P2PeerHub::On_ConLogin ( pCon, strThatP2Paddr, pvLoginMsg, iSize );
    }

private:
    void NoteReport ( P2PeerMsg *pMsg, const char *pszWhere )
    {
        const wchar_t *pwSrc = pMsg ? pMsg->GetSource ( ) : 0;
        std::printf ( "[reportsign] LEAF received a report via %s: '%s' from '%s'\n",
                      pszWhere,
                      pMsg ? N ( pMsg->c_name() ).c_str() : "<null>",
                      N ( pwSrc ).c_str() );
        std::fflush ( stdout );

        //  Ordering, not shape - refer g_bPhase3. Anything arriving once the
        //  forgery has been posted IS the forgery; anything before it is the
        //  report phase 2 asked for.
        if ( g_bPhase3 )
        {
            if ( g_hForged ) SetEvent ( g_hForged );
            return;
        }
        g_wReportSource = pwSrc ? pwSrc : L"";
        if ( g_hReport ) SetEvent ( g_hReport );
    }

    const char *RoleName ( ) const
    {
        return m_eRole == RoleRoot ? "ROOT"
             : m_eRole == RoleMid  ? "MID" : "LEAF";
    }

    Role m_eRole;
};

// =========================================================================
int main ( int argc, char *argv[] )
{
    short nPort = ( argc >= 2 ) ? (short)atoi ( argv[1] ) : 7844;

    std::printf ( "=== p2p_reportsign - F-S9-1, the undeliverable report and its exemption ===\n" );
    std::printf ( "Ports: %d (%s listens), %d (%s listens)\n",
                  (int)nPort, N ( kRootAddr ).c_str(),
                  (int)( nPort + 1 ), N ( kMidAddr ).c_str() );
    std::printf ( "Route: %s -> %s -> %s, report back down the same path\n\n",
                  N ( kLeafAddr ).c_str(), N ( kMidAddr ).c_str(),
                  N ( kRootAddr ).c_str() );
    std::fflush ( stdout );

    g_hMidUp    = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hLeafUp   = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hControl  = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hReport   = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hForged   = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hConClose = CreateEvent ( NULL, FALSE, FALSE, NULL );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }
    WSADATA oWsaData;
    WSAStartup ( MAKEWORD ( 2, 2 ), &oWsaData );

    // ---- Provisioning -----------------------------------------------------
    // ONE key in the whole topology, and it belongs to the hub that raises the
    // report. That is the claim in one line: the reporting hub can sign the
    // report because the report is now sourced from an address it owns.
    const std::string sRootKey = TempPath ( "rootkey" );
    const std::string sLeafAcl = TempPath ( "leafacl" );

    unsigned char pubRoot[p2pcng::kEcdsaPubLen];
    if ( !MakeIdentity ( sRootKey, pubRoot ) )
    { Log ( "SETUP: key generation failed" ); ScrubTempFiles(); return 2; }
    if ( p2pcng::AppendAllowList ( sLeafAcl.c_str(), "Rep",
                                   pubRoot ) != p2pcng::IdOk )
    { Log ( "SETUP: allow-list provisioning failed" ); ScrubTempFiles(); return 2; }

    int nExit = 2;
    {
        // ---- Rep: the top, and the reporting hub --------------------------
        //  RequireAuth(false) on every hub here, and it is the point rather
        //  than a workaround: what is under test is the RELAY gate - "who
        //  wrote this" - and running with login auth off is what stops the two
        //  claims sharing the credit for a refusal. Stage 3 step 8 made login
        //  auth the default, so each hub says so explicitly.
        ReportHub oRoot ( kRootAddr, ReportHub::RoleRoot );
        oRoot.RequireAuth ( false );
        //  RequireSeal(false) since 2026-08-21 (Stage 3 step 20), and it is the
        //  same argument as the RequireAuth(false) beside it: this is a RELAY
        //  test, not a confidentiality one. With the automatic seal on, a
        //  cross-branch message is sealed to its destination before it goes -
        //  and a hub with no agreement key for that destination DROPS it, so
        //  the topology under test never carries anything and the gate would
        //  measure the seal instead of the thing it is named after.
        //
        //  IT ALSO MEETS A REAL LIMIT, recorded here because this is where it
        //  shows: a BROADCAST has no single destination to seal to. The
        //  address lookup is exact, so P2PmsgBCast to a subtree finds no
        //  agreement key and is refused. Sealing and broadcast do not compose
        //  today - ProductionPlan.md Stage 3 step 20 carries it.
        oRoot.RequireSeal ( false );
        if ( oRoot.SetIdentity ( sRootKey.c_str() ) != p2pcng::IdOk )
        { Log ( "SETUP: Rep identity failed" ); ScrubTempFiles(); return 2; }
        if ( !oRoot.CanAuthSign() )
        { Log ( "SETUP: Rep cannot sign" ); ScrubTempFiles(); return 2; }

        HANDLE hRootThread = oRoot.SpawnHub();
        if ( !hRootThread ) { Log ( "SETUP: Rep SpawnHub() failed" ); ScrubTempFiles(); return 2; }

        P2PeerConWsa *pSvcRoot = P2PeerConWsa::ServiceFactory ( kDomain, nPort );
        if ( !pSvcRoot ) { Log ( "SETUP: Rep ServiceFactory failed" ); ScrubTempFiles(); return 2; }
        oRoot.PostP2PeerCon ( pSvcRoot );
        Log ( "Rep listening - holds the only identity in the topology" );
        Sleep ( 500 );

        // ---- Rep.Mid: the relay, a client AND a service --------------------
        // No identity, no allow-list, no policy of its own. A router being
        // unable to forge what it forwards is the whole claim, so giving it a
        // key would blunt the test - and phase 3 is that same router trying.
        ReportHub oMid ( kMidAddr, ReportHub::RoleMid );
        oMid.RequireAuth ( false );
        oMid.RequireSeal ( false );
        HANDLE hMidThread = oMid.SpawnHub();
        P2PeerConWsa *pCliMid =
            P2PeerConWsa::ClientFactory ( kRootAddr, L"127.0.0.1", nPort );
        P2PeerConWsa *pSvcMid =
            P2PeerConWsa::ServiceFactory ( kDomain, (short)( nPort + 1 ) );
        if ( !hMidThread || !pCliMid || !pSvcMid )
        { Log ( "SETUP: Rep.Mid failed" ); ScrubTempFiles(); return 2; }
        oMid.PostP2PeerCon ( pCliMid );
        oMid.PostP2PeerCon ( pSvcMid );
        Log ( "Rep.Mid dialling the root, and listening for its own child" );

        if ( WaitForSingleObject ( g_hMidUp, 15000 ) != WAIT_OBJECT_0 )
        {
            std::printf ( "\nRESULT: SETUP - Rep.Mid never logged in to Rep.\n" );
            oMid.CloseHub(); oRoot.CloseHub();
            WaitForSingleObject ( hMidThread,  3000 );
            WaitForSingleObject ( hRootThread, 3000 );
            CloseHandle ( hMidThread ); CloseHandle ( hRootThread );
            CleanupP2Pmsg(); ScrubTempFiles(); WSACleanup();
            return 2;
        }
        Sleep ( 300 );

        // ---- Rep.Mid.Leaf: the gate under test -----------------------------
        // Allow-list only. It verifies; it never signs, so it needs no
        // identity of its own.
        ReportHub oLeaf ( kLeafAddr, ReportHub::RoleLeaf );
        if ( oLeaf.SetAllowList ( sLeafAcl.c_str() ) != p2pcng::IdOk )
        { Log ( "SETUP: Leaf allow-list failed" ); ScrubTempFiles(); return 2; }
        oLeaf.RequireAuth ( false );
        oLeaf.RequireSeal ( false );

        HANDLE hLeafThread = oLeaf.SpawnHub();
        P2PeerConWsa *pCliLeaf =
            P2PeerConWsa::ClientFactory ( kMidAddr, L"127.0.0.1", (short)( nPort + 1 ) );
        if ( !hLeafThread || !pCliLeaf )
        { Log ( "SETUP: Leaf failed" ); ScrubTempFiles(); return 2; }
        oLeaf.PostP2PeerCon ( pCliLeaf );
        Log ( "Leaf dialling its parent" );

        if ( WaitForSingleObject ( g_hLeafUp, 15000 ) != WAIT_OBJECT_0 )
        {
            std::printf ( "\nRESULT: SETUP - the Leaf never completed a login.\n" );
            oLeaf.CloseHub(); oMid.CloseHub(); oRoot.CloseHub();
            WaitForSingleObject ( hLeafThread, 3000 );
            WaitForSingleObject ( hMidThread,  3000 );
            WaitForSingleObject ( hRootThread, 3000 );
            CloseHandle ( hLeafThread ); CloseHandle ( hMidThread );
            CloseHandle ( hRootThread );
            CleanupP2Pmsg(); ScrubTempFiles(); WSACleanup();
            return 2;
        }
        Sleep ( 300 );

        //  ASSERTED, not set. If relay attestation is not already the default
        //  the whole run would be measuring this test's own configuration
        //  rather than the library's - which is how Stage 3 step 9 asked to be
        //  guarded.
        if ( !oLeaf.IsRelayAuthRequired() || !oRoot.IsRelayAuthRequired() )
        {
            Log ( "SETUP: relay attestation is NOT the default - step 9 has been "
                  "reverted, and this test would measure its own configuration" );
            nExit = 2;
        }
        else
        {
        Log ( "--- relay attestation is REQUIRED, by default, at the leaf ---" );

        // ---- Phase 1: the positive control --------------------------------
        Log ( "--- phase 1: control, the relay speaking for ITSELF ---" );
        oMid.PostAs ( kMidAddr, kPayControl );

        if ( WaitForSingleObject ( g_hControl, 15000 ) != WAIT_OBJECT_0 )
        {
            std::printf (
              "\nRESULT: INCONCLUSIVE - the CONTROL message (sourced by the\n"
              "  relay itself) never reached the Leaf's handler, so the link is\n"
              "  broken and nothing after it would prove anything. This is NOT\n"
              "  a pass. Check wsa_mesh and p2p_authspoof first.\n" );
            nExit = 3;
        }
        else
        {
            Log ( "positive control OK - the relay's own message was delivered" );
            Sleep ( 300 );

            // ---- Phase 2: the report, relayed -----------------------------
            // Nothing here turns anything on. The Leaf posts to an address
            // that exists nowhere; Rep raises the report and signs it as
            // itself, because it now holds a key for the address the report
            // declares. Before the fix the report declared "Ghost.Nowhere",
            // which nobody could ever sign for.
            Log ( "--- phase 2: the Leaf posts to nowhere; the report must come back ---" );
            oLeaf.PostToNowhere ( kPayReport );

            if ( WaitForSingleObject ( g_hReport, 15000 ) != WAIT_OBJECT_0 )
            {
                std::printf (
                  "\nRESULT: FAIL - the undeliverable report NEVER ARRIVED.\n"
                  "  The sender was not told its message could not be\n"
                  "  delivered, which is the defect SECURITY.md's\n"
                  "  'Undeliverable report' row records as fixed.\n"
                  "  With the class exemption gone this is what an UNSTAMPED\n"
                  "  report does: it declares '%s', nobody holds a key for\n"
                  "  that address, and GateRelayInbound refuses it.\n"
                  "  Check that P2PeerTarget::RouteP2PeerMsg stamps the\n"
                  "  report with GetP2PaddrHub(), and that Rep can sign.\n",
                  N ( kGhostAddr ).c_str() );
                nExit = 4;
            }
            else if ( g_wReportSource != kRootAddr )
            {
                std::printf (
                  "\nRESULT: FAIL - the report arrived but declared source '%s'\n"
                  "  where '%s' was required. It is therefore being admitted by\n"
                  "  something other than the rule - almost certainly the\n"
                  "  P2Pmsg_Exception class exemption in GateRelayInbound, which\n"
                  "  F-S9-1 closed. A report that names an address nobody owns\n"
                  "  cannot be attested by anyone, which is the whole finding.\n",
                  N ( g_wReportSource.c_str() ).c_str(),
                  N ( kRootAddr ).c_str() );
                nExit = 5;
            }
            else
            {
                Log ( "report OK - it came back down a relay, sourced by the hub "
                      "that raised it, on that hub's own signature" );

                // ---- Phase 3: the forgery -------------------------------
                // The pre-fix report shape, from a hub not entitled to it.
                // Destructive by construction - a refusal drops the link - so
                // it runs last.
                Log ( "--- phase 3: the relay replaying the PRE-FIX report shape ---" );
                g_bPhase3 = true;
                if ( !oMid.PostForgedReport() )
                {
                    Log ( "SETUP: could not build the forged report" );
                    nExit = 2;
                }
                else
                {
                    Log ( "waiting 8s to see whether the forged report is admitted..." );
                    if ( WaitForSingleObject ( g_hForged, 8000 ) == WAIT_OBJECT_0 )
                    {
                        std::printf (
                          "\nRESULT: FAIL - the FORGED report was ADMITTED.\n"
                          "  The Leaf accepted a P2Pmsg_Exception from its parent\n"
                          "  sourced '%s' - an address outside that parent's\n"
                          "  subtree, with no attestation from anyone - on DEFAULT\n"
                          "  configuration, with phase 2 proving the machinery is\n"
                          "  live on this very connection.\n"
                          "  That is F-S9-1 open: an application can be told a\n"
                          "  message failed that did not, or handed a fabricated\n"
                          "  error attributed to an arbitrary address. Check that\n"
                          "  the Map_MatchName(P2Pmsg_Exception) exemption really\n"
                          "  is gone from P2PeerCon::GateRelayInbound.\n",
                          N ( kGhostAddr ).c_str() );
                        nExit = 1;
                    }
                    else
                    {
                        const bool bDropped =
                          WaitForSingleObject ( g_hConClose, 2000 ) == WAIT_OBJECT_0;
                        std::printf (
                          "\nRESULT: PASS - F-S9-1 is closed at both ends.\n"
                          "  Phase 2: an undeliverable report crossed a KEYLESS\n"
                          "  relay and was admitted on the reporting hub's own\n"
                          "  signature, declaring '%s' - the hub that raised it -\n"
                          "  rather than the address that could not be reached.\n"
                          "  Phase 3: the same relay replaying the pre-fix report\n"
                          "  shape, sourced '%s', was REFUSED%s.\n"
                          "  What separates them is a private key the relay does\n"
                          "  not hold, which is the same thing that separates any\n"
                          "  other message on this link - and that is the point:\n"
                          "  P2Pmsg_Exception is no longer a class apart.\n",
                          N ( kRootAddr ).c_str(), N ( kGhostAddr ).c_str(),
                          bDropped ? " and the connection dropped"
                                   : " (the connection close was not observed "
                                     "within 2s, which is timing rather than "
                                     "admission - the report did not arrive)" );
                        nExit = 0;
                    }
                }
            }
        }
        }

        Log ( "shutdown" );
        oLeaf.CloseHub();
        oMid .CloseHub();
        oRoot.CloseHub();
        WaitForSingleObject ( hLeafThread, 3000 );
        WaitForSingleObject ( hMidThread,  3000 );
        WaitForSingleObject ( hRootThread, 3000 );
        CloseHandle ( hLeafThread );
        CloseHandle ( hMidThread  );
        CloseHandle ( hRootThread );
    }

    CleanupP2Pmsg();
    if ( g_hMidUp    ) { CloseHandle ( g_hMidUp    ); g_hMidUp    = NULL; }
    if ( g_hLeafUp   ) { CloseHandle ( g_hLeafUp   ); g_hLeafUp   = NULL; }
    if ( g_hControl  ) { CloseHandle ( g_hControl  ); g_hControl  = NULL; }
    if ( g_hReport   ) { CloseHandle ( g_hReport   ); g_hReport   = NULL; }
    if ( g_hForged   ) { CloseHandle ( g_hForged   ); g_hForged   = NULL; }
    if ( g_hConClose ) { CloseHandle ( g_hConClose ); g_hConClose = NULL; }
    ScrubTempFiles();
    WSACleanup();

    std::printf ( "Done (exit=%d).\n", nExit );
    std::fflush ( stdout );
    return nExit;
}
