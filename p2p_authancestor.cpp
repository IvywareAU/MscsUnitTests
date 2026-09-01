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
// p2p_authancestor.cpp - the source-binding rule on a link to an ANCESTOR.
//
// ---------------------------------------------------------------------------
// THIS TEST HAS CHANGED MEANING TWICE, AND THAT IS THE POINT
//
//   Until 2026-08-14 it asserted the presence of a deliberate GAP. Its own
//   header said so in a warning box: a green run meant "the exemption is still
//   there", not "anything is secure". It was the only test in the suite shaped
//   that way.
//
//   On 2026-08-14 the exemption became closable, so it began asserting a
//   PROTECTION - while one phase still pinned the old behaviour as the
//   DEFAULT, because closing it was opt-in.
//
//   On 2026-08-18 (ProductionPlan.md Stage 3 step 9) closing it BECAME the
//   default, so that phase inverted. The old behaviour is still pinned, but as
//   the documented MIGRATION - what a tree gets when it asks for it by name -
//   rather than as what it gets by saying nothing. Nothing in this file now
//   turns RequireRelayAuth on; the phases that depend on it assert that it is
//   already true, so a reverted default fails as SETUP rather than passing for
//   the wrong reason.
//
// ---------------------------------------------------------------------------
// WHAT THE RULE IS
//
//   P2PeerCon::GateAppMsgInbound binds a message's declared source to the
//   identity its connection logged in as: the source must BE that identity or
//   be a descendant of it (IsRable - exact match or a hop-boundary prefix).
//   Anything else is discarded and the connection dropped. That is what
//   p2p_authspoof guards.
//
// WHY AN ANCESTOR LINK COULD NOT BE HELD TO IT
//
//   A peer at or ABOVE this hub is its gateway to the whole of the rest of the
//   tree, so a message routed DOWN from it legitimately carries a source
//   belonging to some other branch entirely - which is outside the relaying
//   peer's subtree, and so fails the descendant test. Without an exemption,
//   downward transit and multi-hop broadcast could not work at all.
//
//   The address alone cannot tell that apart from the parent inventing the
//   source. So the link was exempted outright, and SECURITY.md roadmap item 1
//   recorded it as half-done: "it needs per-branch route knowledge, or an
//   attestation from the relaying hop, neither of which exists."
//
// WHAT CLOSES IT
//
//   Not a better predicate - EVIDENCE. With RequireRelayAuth(true) the message
//   must carry an attestation signed by the ORIGIN's identity key, which the
//   relaying ancestor does not hold, and the same at-or-below test is then
//   applied to the identity that SIGNED rather than to the peer that
//   DELIVERED. The rule is not weakened on this link; it is bound against a
//   different, proven thing. Refer p2pauth's kRelayFixedLen block comment.
//
// ---------------------------------------------------------------------------
// WHY THIS NEEDS FOUR HUBS
//
//   The exemption only fires when the source lies OUTSIDE the relaying
//   ancestor's subtree. For a message to arrive that way HONESTLY, the relaying
//   ancestor must itself have received it from ITS ancestor - so the shortest
//   real topology is four levels deep, and that is why the previous version of
//   this test could not build one and simulated the shape instead by having the
//   parent CLAIM a foreign source. Simulating it was fine while the assertion
//   was "nothing is checked"; it is useless now that something is.
//
//       Anc                      (service on nPort - the top, and a relay)
//        |     \
//        |      \_____ Anc.Other (client of Anc - ANOTHER BRANCH, the ORIGIN)
//        |
//       Anc.Mid                  (client of Anc, AND service on nPort+1 -
//        |                        the relaying PARENT, holds no keys)
//        |
//       Anc.Mid.Leaf             (client of Anc.Mid - the gate under test)
//
//   At the Leaf, m_oThatP2Paddr is "Anc.Mid" - an ancestor of "Anc.Mid.Leaf" -
//   so the Leaf's inbound gate sits on an ancestor link, and a source of
//   "Anc.Other" is outside that peer's subtree. That is the one shape the
//   exemption covers, and now the one shape the attestation covers.
//
//   Neither relay holds any key. A router being unable to forge what it
//   forwards is the whole claim, so giving one a key would blunt the test.
//
//   PHASE 1  POSITIVE CONTROL. Anc.Mid posts a BCast sourced "Anc.Mid" -
//            itself. At or below the peer, so the DESCENDANT test admits it and
//            none of this is involved. Without this step a rejection and a
//            broken transport look identical: both are silence.
//
//   PHASE 2  LEGITIMATE DOWNWARD RELAY, WITH NO SWITCH SET ANYWHERE.
//            Anc.Other - a real hub, holding a real identity key, listed in the
//            Leaf's allow-list - posts to the Leaf. The message goes UP to Anc
//            and DOWN through Anc.Mid, which is exactly the transit the
//            exemption existed to permit. It must ARRIVE: a default that broke
//            downward traffic would not be a default, it would be an outage.
//
//   PHASE 3  THE MIGRATION. RequireRelayAuth(false) at the Leaf, and Anc.Mid's
//            unattested claim of "Anc.Other" ARRIVES again - the pre-2026-08-18
//            behaviour, restored exactly, on request. Two jobs: it proves a
//            tree that cannot provision its neighbours has a way out, and it
//            makes phase 4's refusal ATTRIBUTABLE, because the identical
//            message on the identical connection is shown arriving when and
//            only when the switch is off.
//
//   PHASE 4  THE FORGERY, back on the DEFAULT. Anc.Mid posts a BCast sourced
//            "Anc.Other" again - byte-for-byte the shape of phase 3 - but it
//            holds none of that peer's key material and cannot attest for it.
//            It must be REFUSED and the connection dropped. This is the gap,
//            closed, and closed by default.
//
//   ORDER MATTERS AND IS NOT ARBITRARY: a refusal DROPS THE CONNECTION, so the
//   two phases that must arrive have to run before the one that must not.
//
// VERDICT = process EXIT CODE:
//   0  PASS   every phase behaved
//   1  FAIL   phase 4: the forged source was ADMITTED on default
//             configuration. The gap is open - GateRelayInbound is not being
//             reached, or is admitting without a valid block
//   2  SETUP  startup / key / factory failure (test inconclusive)
//   3  INCONCLUSIVE the positive control never arrived - the transport is
//             broken, so nothing after it proves anything. NOT a pass
//   4  FAIL   phase 2: the exemption is gone by DEFAULT. Closing it is opt-in;
//             a tree with RequireRelayAuth(false) must behave exactly as it
//             did before. If that was deliberate, say so in SECURITY.md and
//             Readme.md and rewrite this phase
//   5  FAIL   phase 3: an attested cross-branch relay was refused. Downward
//             transit past the first common ancestor cannot work in that
//             state, which is the failure the exemption existed to avoid.
//             Check the Leaf's allow-list and Elsewhere.Peer's identity

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
static const P2PaddrSTR kTopAddr     = L"Anc";               // the top relay
static const P2PaddrSTR kMidAddr     = L"Anc.Mid";           // the relaying PARENT
static const P2PaddrSTR kLeafAddr    = L"Anc.Mid.Leaf";      // the gate under test
static const P2PaddrSTR kOtherAddr   = L"Anc.Other";         // another branch, the ORIGIN
//  Wildcard. The domain check is not what is under test here - it is
//  p2p_authgate's subject - and a pattern narrow enough to be interesting
//  would only be a second thing able to fail this test.
static const P2PaddrSTR kDomain      = L"*";

//  One payload per phase, so the Leaf's handler can tell phases 2, 3 and 4
//  apart - all three declare the same source, which is the entire difficulty.
static const wchar_t kPayControl [] = L"phase1-from-the-parent-itself";
static const wchar_t kPayRelay   [] = L"phase2-genuine-downward-relay-on-the-default";
static const wchar_t kPayExempt  [] = L"phase3-exemption-restored-by-explicit-opt-out";
static const wchar_t kPayForged  [] = L"phase4-forged-by-the-relaying-parent";

static HANDLE      g_hMidUp     = NULL;   // Anc.Mid has logged in to Anc
static HANDLE      g_hLeafUp    = NULL;   // Anc.Mid.Leaf has logged in to Anc.Mid
static HANDLE      g_hOtherUp   = NULL;   // Anc.Other has logged in to Anc
static HANDLE      g_hControl   = NULL;   // phase 1 reached the Leaf
static HANDLE      g_hRelay     = NULL;   // phase 2 reached the Leaf
static HANDLE      g_hExempt    = NULL;   // phase 3 reached the Leaf
static HANDLE      g_hForged    = NULL;   // phase 4 reached the Leaf - must not

static void Log ( const char *msg )
{
    std::printf ( "[authancestor] %s\n", msg );
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
//  place.  P2PeerMsg::Data() addresses the application bytes where they sit
//  inside the packed message image, and that image is pack(1) - a payload
//  begins at whatever offset the block headers and names ahead of it add up
//  to, which is odd about half the time.  Casting it to wchar_t* is undefined
//  behaviour; on Linux, where wchar_t wants 4-byte alignment, it is what UBSan
//  reported as F-S5-3, at this very line.
//    Copying the bytes out into storage the caller aligned is the fix, and it
//  is what the library's own wide accessors have always done internally.
//  See P3PmsgData::c_vBlobCopy() for the same thing offered as an accessor.
static std::wstring BodyW ( P2PeerMsg *pMsg )
{
    if ( !pMsg || !pMsg->Data ( ) ) return std::wstring ( );
    const size_t cb = (size_t)pMsg->DataSize ( );
    std::wstring w ( cb / sizeof(wchar_t), L'\0' );
    if ( !w.empty ( ) )
      std::memcpy ( &w[0], pMsg->Data ( ), w.size ( ) * sizeof(wchar_t) );
    const size_t nNul = w.find ( L'\0' );      // the payloads are literals
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
    s += "p2p_authancestor_"; s += pszLeaf; s += "_"; s += szPid; s += ".tmp";
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
class AncestorHub : public P2PeerHub
{
public:
    enum Role { RoleTop, RoleMid, RoleLeaf, RoleOther };

    AncestorHub ( P2PaddrSTR strAddr, Role eRole )
        : P2PeerHub ( strAddr ), m_eRole ( eRole ) { }
    virtual ~AncestorHub ( ) { }

    // Driven from main() so the posts are strictly ordered: each phase is seen
    // to land, or seen not to, before the next one is even sent.
    void PostAs ( P2PaddrSTR strSource, const wchar_t *lpszPayload )
    {
        P2Psize_t nBytes =
            (P2Psize_t)( ( wcslen ( lpszPayload ) + 1 ) * sizeof(wchar_t) );
        PostP2PeerMsg ( new P2PeerMsg32 ( strSource, kLeafAddr,
                                          P2Pmsg_BCast, lpszPayload, nBytes ) );
        std::printf ( "[authancestor] %s posted a BCast to the Leaf sourced '%s'\n",
                      RoleName(), N ( strSource ).c_str() );
        std::fflush ( stdout );
    }

protected:
    // The Leaf is the hub whose admission gate is under test: it is the end of
    // the connection whose peer is an ancestor.
    virtual msgRESULT On_P2PeerBCast ( P2PeerMsg *pMsg ) override
    {
        if ( m_eRole != RoleLeaf || !pMsg )
            return msgHANDLED;

        const std::wstring wBody = BodyW ( pMsg );   // copied out, aligned
        const wchar_t *pw = pMsg->Data() ? wBody.c_str() : nullptr;
        std::printf ( "[authancestor] LEAF handler ran; source='%s' body='%s'\n",
                      N ( pMsg->GetSource() ).c_str(), N ( pw ).c_str() );
        std::fflush ( stdout );

        if ( !pw ) return msgHANDLED;
        //  Keyed on the BODY, not the source: phases 2, 3 and 4 all declare
        //  "Elsewhere.Peer", and telling them apart by the thing under test
        //  would be circular.
        if      ( wcscmp ( pw, kPayControl ) == 0 ) { if ( g_hControl ) SetEvent ( g_hControl ); }
        else if ( wcscmp ( pw, kPayExempt  ) == 0 ) { if ( g_hExempt  ) SetEvent ( g_hExempt  ); }
        else if ( wcscmp ( pw, kPayRelay   ) == 0 ) { if ( g_hRelay   ) SetEvent ( g_hRelay   ); }
        else if ( wcscmp ( pw, kPayForged  ) == 0 ) { if ( g_hForged  ) SetEvent ( g_hForged  ); }
        return msgHANDLED;
    }

    // Server side of the login, and NOT merely for the trace.
    //
    // Elsewhere.Peer loads an identity because it must SIGN its attestations.
    // That same key makes P2PeerCon sign its LOGIN too, and the Root requires
    // no authentication, so the block is handed up as login payload - which the
    // stock handler refuses outright ("contains login data"). Without this the
    // origin never finishes logging in. The same note is on p2p_sealhop, for
    // the same reason.
    virtual conRESULT On_ConLogin ( P2PeerCon *pCon, P2PaddrSTR strThatP2Paddr,
                                    const void *pvLoginMsg,
                                    P2Psize_t iSize ) override
    {
        std::printf ( "[authancestor] %s: login FROM '%s' (%d bytes of payload)\n",
                      RoleName(), N ( strThatP2Paddr ).c_str(), (int)iSize );
        std::fflush ( stdout );

        //  WHO just arrived decides which gate main() may open. Compared by
        //  address rather than counted, because the logins race and a counter
        //  would let one arrive twice and look like two different hubs.
        if ( strThatP2Paddr )
        {
            if      ( wcscmp ( strThatP2Paddr, kMidAddr   ) == 0 )
            { if ( g_hMidUp   ) SetEvent ( g_hMidUp   ); }
            else if ( wcscmp ( strThatP2Paddr, kLeafAddr  ) == 0 )
            { if ( g_hLeafUp  ) SetEvent ( g_hLeafUp  ); }
            else if ( wcscmp ( strThatP2Paddr, kOtherAddr ) == 0 )
            { if ( g_hOtherUp ) SetEvent ( g_hOtherUp ); }
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
    const char *RoleName ( ) const
    {
        return m_eRole == RoleTop  ? "TOP"
             : m_eRole == RoleMid  ? "MID"
             : m_eRole == RoleLeaf ? "LEAF" : "OTHER";
    }

    Role m_eRole;
};

// =========================================================================
int main ( int argc, char *argv[] )
{
    short nPort = ( argc >= 2 ) ? (short)atoi ( argv[1] ) : 7820;

    std::printf ( "=== p2p_authancestor - the source-binding rule on an ancestor link ===\n" );
    std::printf ( "Ports: %d (%s listens), %d (%s listens)\n",
                  (int)nPort, N ( kTopAddr ).c_str(),
                  (int)( nPort + 1 ), N ( kMidAddr ).c_str() );
    std::printf ( "Route: %s -> %s -> %s -> %s\n\n",
                  N ( kOtherAddr ).c_str(), N ( kTopAddr ).c_str(),
                  N ( kMidAddr ).c_str(), N ( kLeafAddr ).c_str() );
    std::fflush ( stdout );

    g_hMidUp   = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hLeafUp  = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hOtherUp = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hControl = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hExempt  = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hRelay   = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hForged  = CreateEvent ( NULL, FALSE, FALSE, NULL );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }
    WSADATA oWsaData;
    WSAStartup ( MAKEWORD ( 2, 2 ), &oWsaData );

    // ---- Provisioning -----------------------------------------------------
    // Anc.Other needs an identity to attest WITH; the Leaf needs that peer's
    // public point to check the attestation AGAINST. Neither relay gets
    // anything at all - a router that cannot forge what it forwards is the
    // whole claim, and giving one a key would blunt the test.
    const std::string sOtherKey = TempPath ( "otherkey" );
    const std::string sLeafAcl  = TempPath ( "leafacl"  );

    unsigned char pubOther[p2pcng::kEcdsaPubLen];
    if ( !MakeIdentity ( sOtherKey, pubOther ) )
    { Log ( "SETUP: key generation failed" ); ScrubTempFiles(); return 2; }
    if ( p2pcng::AppendAllowList ( sLeafAcl.c_str(), "Anc.Other",
                                   pubOther ) != p2pcng::IdOk )
    { Log ( "SETUP: allow-list provisioning failed" ); ScrubTempFiles(); return 2; }

    int nExit = 2;
    {
        // ---- The Top: where the two branches meet -------------------------
        AncestorHub oTop ( kTopAddr, AncestorHub::RoleTop );
        //  RequireAuth(false) on every hub in the topology, and it is the point
        //  rather than a workaround. What is under test is RequireRelayAuth -
        //  "who WROTE this message", which P2PeerHub.h is explicit is a
        //  different claim from "who is on the other end of this connection".
        //  Running with login auth off is what keeps the two from being confused
        //  for one another: every refusal below is the attestation gate, because
        //  there is no login gate to share the credit. Stage 3 step 8 made login
        //  auth the default, so each hub now says so.
        oTop.RequireAuth ( false );
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
        oTop.RequireSeal ( false );
        HANDLE hTopThread = oTop.SpawnHub();
        if ( !hTopThread ) { Log ( "SETUP: top SpawnHub() failed" ); ScrubTempFiles(); return 2; }

        P2PeerConWsa *pSvcTop = P2PeerConWsa::ServiceFactory ( kDomain, nPort );
        if ( !pSvcTop ) { Log ( "SETUP: top ServiceFactory failed" ); ScrubTempFiles(); return 2; }
        oTop.PostP2PeerCon ( pSvcTop );
        Log ( "top listening - no keys" );
        Sleep ( 500 );   // let the listener bind before dialling

        // ---- The Mid: the relaying PARENT, a client AND a service ---------
        // Both at once, which is what an interior node of the tree is. It has
        // no identity, no allow-list and no attestation policy: everything it
        // forwards, it forwards as it found it.
        AncestorHub oMid ( kMidAddr, AncestorHub::RoleMid );
        oMid.RequireAuth ( false );     // see oTop - the attestation gate, alone
        oMid.RequireSeal ( false );
        HANDLE hMidThread = oMid.SpawnHub();
        P2PeerConWsa *pCliMid =
            P2PeerConWsa::ClientFactory ( kTopAddr, L"127.0.0.1", nPort );
        P2PeerConWsa *pSvcMid = P2PeerConWsa::ServiceFactory ( kDomain, (short)( nPort + 1 ) );
        if ( !hMidThread || !pCliMid || !pSvcMid )
        { Log ( "SETUP: mid failed" ); ScrubTempFiles(); return 2; }
        oMid.PostP2PeerCon ( pCliMid );
        oMid.PostP2PeerCon ( pSvcMid );
        Log ( "mid dialling the top, and listening for its own child" );

        if ( WaitForSingleObject ( g_hMidUp, 15000 ) != WAIT_OBJECT_0 )
        {
            std::printf ( "\nRESULT: SETUP - the mid hub never logged in to the top.\n" );
            oMid.CloseHub(); oTop.CloseHub();
            WaitForSingleObject ( hMidThread, 3000 );
            WaitForSingleObject ( hTopThread, 3000 );
            CloseHandle ( hMidThread ); CloseHandle ( hTopThread );
            CleanupP2Pmsg(); ScrubTempFiles(); WSACleanup();
            return 2;
        }
        Sleep ( 300 );

        // ---- The Leaf: the gate under test --------------------------------
        // Allow-list only. It verifies; it never signs, so it needs no identity
        // of its own - which is worth having exactly one hub demonstrate.
        AncestorHub oLeaf ( kLeafAddr, AncestorHub::RoleLeaf );
        if ( oLeaf.SetAllowList ( sLeafAcl.c_str() ) != p2pcng::IdOk )
        { Log ( "SETUP: Leaf allow-list failed" ); ScrubTempFiles(); return 2; }
        oLeaf.RequireAuth ( false );    // see oTop - the attestation gate, alone
        oLeaf.RequireSeal ( false );

        HANDLE hLeafThread = oLeaf.SpawnHub();
        P2PeerConWsa *pCliLeaf =
            P2PeerConWsa::ClientFactory ( kMidAddr, L"127.0.0.1", (short)( nPort + 1 ) );
        if ( !hLeafThread || !pCliLeaf )
        { Log ( "SETUP: Leaf failed" ); ScrubTempFiles(); return 2; }
        oLeaf.PostP2PeerCon ( pCliLeaf );
        Log ( "leaf dialling its parent" );

        if ( WaitForSingleObject ( g_hLeafUp, 15000 ) != WAIT_OBJECT_0 )
        {
            std::printf ( "\nRESULT: SETUP - the leaf never completed a login.\n" );
            oLeaf.CloseHub(); oMid.CloseHub(); oTop.CloseHub();
            WaitForSingleObject ( hLeafThread, 3000 );
            WaitForSingleObject ( hMidThread, 3000 );
            WaitForSingleObject ( hTopThread, 3000 );
            CloseHandle ( hLeafThread ); CloseHandle ( hMidThread ); CloseHandle ( hTopThread );
            CleanupP2Pmsg(); ScrubTempFiles(); WSACleanup();
            return 2;
        }
        Sleep ( 300 );   // let the LoginAck land before posting down the link

        // ---- Phase 1: the positive control --------------------------------
        // Source "Anc.Mid" is the peer itself, so the DESCENDANT test admits
        // it. This arriving proves the link carries traffic at all, and it does
        // not depend on the exemption or on anything added to close it.
        Log ( "--- phase 1: control, the parent speaking for ITSELF ---" );
        oMid.PostAs ( kMidAddr, kPayControl );

        if ( WaitForSingleObject ( g_hControl, 15000 ) != WAIT_OBJECT_0 )
        {
            std::printf (
              "\nRESULT: INCONCLUSIVE - the CONTROL message (sourced by the\n"
              "  parent itself) never reached the leaf's handler, so the link\n"
              "  is broken and nothing after it would prove anything. This is\n"
              "  NOT a pass. Check wsa_mesh and p2p_authspoof first.\n" );
            nExit = 3;
        }
        else
        {
            Log ( "positive control OK - the parent's own message was delivered" );

            {
                // ---- The origin, in the other branch -----------------------
                // NOTHING here turns relay attestation on. It is the DEFAULT
                // since ProductionPlan.md Stage 3 step 9, and that is the whole
                // point of the reordering below: the origin signs and the leaf
                // insists because neither was configured, not because this test
                // configured them.
                //
                // Both relays are left unprovisioned throughout, which is the
                // deployment worth proving: an intermediate hub needs no keys
                // and no policy, it just carries the field. That is also why
                // relay attestation is deliberately NOT part of the arming gate
                // step 8 put in front of login auth - a router that holds no
                // keys would otherwise have to be provisioned, or opted out, to
                // carry traffic it is not being asked to vouch for.
                AncestorHub oOther ( kOtherAddr, AncestorHub::RoleOther );
                HANDLE      hOtherThread = NULL;

                //  do/while(0) rather than goto: the origin hub and its thread
                //  handle are constructed here, and a forward goto past them is
                //  ill-formed. Every setup failure below breaks out to the one
                //  shutdown path at the bottom.
                do
                {
                if ( oOther.SetIdentity ( sOtherKey.c_str() ) != p2pcng::IdOk )
                { Log ( "SETUP: Anc.Other identity failed" ); nExit = 2; break; }
                if ( !oOther.CanAuthSign() )
                { Log ( "SETUP: Anc.Other cannot sign" ); nExit = 2; break; }
                //  ASSERTED, not set. If either of these is false the tree is
                //  not running on default configuration and every result below
                //  would be measuring this test's own setup.
                if ( !oLeaf.IsRelayAuthRequired() || !oOther.IsRelayAuthRequired() )
                { Log ( "SETUP: relay attestation is NOT the default - step 9 "
                        "has been reverted, and this test would measure its own "
                        "configuration rather than the library's" );
                  nExit = 2; break; }
                Log ( "--- relay attestation is REQUIRED, by default, at the leaf ---" );

                oOther.RequireAuth ( false );   // see oTop - attestation, not login
                oOther.RequireSeal ( false );
                hOtherThread = oOther.SpawnHub();
                P2PeerConWsa *pCliOther =
                    P2PeerConWsa::ClientFactory ( kTopAddr, L"127.0.0.1", nPort );
                if ( !hOtherThread || !pCliOther )
                { Log ( "SETUP: Anc.Other failed" ); nExit = 2; break; }
                oOther.PostP2PeerCon ( pCliOther );

                if ( WaitForSingleObject ( g_hOtherUp, 15000 ) != WAIT_OBJECT_0 )
                {
                    Log ( "SETUP: Anc.Other never completed a login" );
                    nExit = 2;
                }
                else
                {
                    Sleep ( 500 );

                    // ---- Phase 2: legitimate downward relay, NO SWITCH SET -
                    // A real hub in another branch, signing with a key the
                    // Leaf's allow-list names. Two keyless relays carry it
                    // untouched. This has to keep working - it is the traffic
                    // the exemption existed to permit - and it has to keep
                    // working with nothing configured, which is what step 9
                    // asks for in as many words.
                    Log ( "--- phase 2: genuine relay on the DEFAULT, Anc.Other -> Anc -> Anc.Mid -> Leaf ---" );
                    oOther.PostAs ( kOtherAddr, kPayRelay );

                    if ( WaitForSingleObject ( g_hRelay, 15000 ) != WAIT_OBJECT_0 )
                    {
                        std::printf (
                          "\nRESULT: FAIL - an ATTESTED cross-branch relay was refused.\n"
                          "  Downward transit past the first common ancestor cannot\n"
                          "  work in that state, which is the failure the exemption\n"
                          "  existed to avoid - so this is the fix breaking the thing\n"
                          "  it was meant to make safe, not the thing it was meant to\n"
                          "  stop.\n"
                          "  Check that Anc.Other holds an identity, that the leaf's\n"
                          "  allow-list names it, and that the relays are forwarding\n"
                          "  the attestation field rather than dropping it.\n" );
                        nExit = 5;
                    }
                    else
                    {
                        Log ( "attested relay OK - the origin's signature carried "
                              "through both relays" );

                        // ---- Phase 3: THE MIGRATION ----------------------
                        // RequireRelayAuth(false) on the leaf restores the old
                        // exemption exactly, and the same unattested claim the
                        // next phase will refuse now ARRIVES.
                        //
                        // This phase is not a nicety. It does two jobs nothing
                        // else here can do: it proves the documented one-line
                        // migration works, so a tree that cannot provision its
                        // neighbours is not simply broken by the new default;
                        // and it makes phase 4's refusal ATTRIBUTABLE, because
                        // the identical message on the identical connection is
                        // shown arriving when and only when the switch is off.
                        // Without it, a refused phase 4 and a dead link look
                        // the same.
                        //
                        // Non-destructive by construction: an ADMITTED message
                        // leaves the connection up, so this has to run before
                        // the refusal that drops it.
                        Log ( "--- phase 3: the migration - RequireRelayAuth(false) at the leaf ---" );
                        oLeaf.RequireRelayAuth ( false );
                        if ( oLeaf.IsRelayAuthRequired() )
                        { Log ( "SETUP: RequireRelayAuth(false) did not take" ); nExit = 2; break; }
                        oMid.PostAs ( kOtherAddr, kPayExempt );

                        if ( WaitForSingleObject ( g_hExempt, 10000 ) != WAIT_OBJECT_0 )
                        {
                            std::printf (
                              "\nRESULT: FAIL - with relay attestation turned OFF at\n"
                              "  the leaf, a cross-branch source down an ancestor link\n"
                              "  was STILL refused. That is the pre-2026-08-18 default\n"
                              "  behaviour and it is the documented migration for a\n"
                              "  tree that cannot provision its neighbours - so with\n"
                              "  this broken, Stage 3 step 9 is an outage rather than\n"
                              "  a default and there is no way back.\n" );
                            nExit = 4;
                        }
                        else
                        {
                        Log ( "migration confirmed - the exemption is restored on request" );
                        oLeaf.RequireRelayAuth ( true );   // back to the default

                        // ---- Phase 4: the forgery ------------------------
                        // The same claim as phase 3, from the same hub, on the
                        // same connection - and with the switch back at its
                        // DEFAULT it must die. The Mid holds no key for
                        // Anc.Other and cannot attest for it.
                        Log ( "--- phase 4: the parent forging that same source, on the default ---" );
                        oMid.PostAs ( kOtherAddr, kPayForged );
                        Log ( "waiting 8s to see whether the forged source is admitted..." );

                        if ( WaitForSingleObject ( g_hForged, 8000 ) == WAIT_OBJECT_0 )
                        {
                            std::printf (
                              "\nRESULT: FAIL - the forged source was ADMITTED.\n"
                              "  The leaf accepted a message from its parent whose\n"
                              "  source ('Anc.Other') lies outside the parent's\n"
                              "  subtree, WITHOUT an attestation from that origin -\n"
                              "  on DEFAULT configuration, with phase 2 proving the\n"
                              "  machinery is live and phase 3 proving the identical\n"
                              "  message arrives when the switch is off.\n"
                              "  The ancestor exemption is still open. Check that\n"
                              "  P2PeerCon::GateRelayInbound is reached and that it is\n"
                              "  not falling through on a null hub or an absent block.\n" );
                            nExit = 1;
                        }
                        else
                        {
                            std::printf (
                              "\nRESULT: PASS - the ancestor link is source-bound BY\n"
                              "  DEFAULT. Phase 2 showed a genuine cross-branch message\n"
                              "  relayed DOWN through two keyless relays and admitted on\n"
                              "  the ORIGIN's signature, with no switch set anywhere.\n"
                              "  Phase 4 showed the same parent claiming the same source\n"
                              "  with no such signature, and being refused and dropped.\n"
                              "  What separates them is a private key the relaying hub\n"
                              "  does not hold. Phase 3 showed RequireRelayAuth(false)\n"
                              "  still restores the old exemption exactly, which is what\n"
                              "  makes this a default rather than an outage.\n" );
                            nExit = 0;
                        }
                        }
                    }
                }
                } while ( 0 );

                Log ( "origin shutdown" );
                oOther.CloseHub();
                if ( hOtherThread )
                {
                    WaitForSingleObject ( hOtherThread, 3000 );
                    CloseHandle ( hOtherThread );
                }
            }
        }

        Log ( "shutdown" );
        oLeaf.CloseHub();
        oMid .CloseHub();
        oTop .CloseHub();
        WaitForSingleObject ( hLeafThread, 3000 );
        WaitForSingleObject ( hMidThread,  3000 );
        WaitForSingleObject ( hTopThread,  3000 );
        CloseHandle ( hLeafThread );
        CloseHandle ( hMidThread  );
        CloseHandle ( hTopThread  );
    }

    CleanupP2Pmsg();
    if ( g_hMidUp   ) { CloseHandle ( g_hMidUp   ); g_hMidUp   = NULL; }
    if ( g_hLeafUp  ) { CloseHandle ( g_hLeafUp  ); g_hLeafUp  = NULL; }
    if ( g_hOtherUp ) { CloseHandle ( g_hOtherUp ); g_hOtherUp = NULL; }
    if ( g_hControl ) { CloseHandle ( g_hControl ); g_hControl = NULL; }
    if ( g_hExempt  ) { CloseHandle ( g_hExempt  ); g_hExempt  = NULL; }
    if ( g_hRelay   ) { CloseHandle ( g_hRelay   ); g_hRelay   = NULL; }
    if ( g_hForged  ) { CloseHandle ( g_hForged  ); g_hForged  = NULL; }
    ScrubTempFiles();
    WSACleanup();

    std::printf ( "Done (exit=%d).\n", nExit );
    std::fflush ( stdout );
    return nExit;
}
