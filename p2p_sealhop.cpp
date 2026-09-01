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
// p2p_sealhop.cpp — can a hub carry a message it cannot read?
//
// BACKGROUND — what the four auth gates do NOT cover.
//
//   p2p_authgate   : an unauthenticated peer cannot reach a handler.
//   p2p_authspoof  : a logged-in peer cannot forge its source mid-session.
//   p2p_authpsk    : a peer cannot claim an identity that is not its own.
//   p2p_authrelay  : an identity proven on one channel cannot be borrowed.
//   p2p_sealhop    : a hub that ROUTES a message cannot read its body.  <-- this
//
//   Every gate above is about a party that is NOT supposed to be there. This
//   one is about a party that IS: the intermediate hub is a legitimate,
//   configured, trusted-to-route member of the tree. It must be able to read
//   the destination address — routing is decided on it (P2PeerHub.cpp:706) —
//   and a hub that could not read the frame could not forward it. So the
//   connection cypher cannot help here, however good it is: it protects one
//   HOP, and the middle hub is the far end of the first one.
//
//   The answer is to seal the BODY to the destination and leave the addresses
//   in clear. P2PeerSeal.h does that with ECIES plus a sender signature.
//
// WHAT IT DOES — three real hubs, two real sockets, library routing.
//
//       Seal.Alice  ---->  Seal  ---->  Seal.Carol
//        (sender)         (middle)      (recipient)
//                       holds NO keys
//
//   The middle hub is configured with no identity, no agreement key and no
//   allow-list. It observes everything it forwards through PeekP2PeerMsg, which
//   the library calls on the routing path for exactly this purpose ("Application
//   may wish to observe outgoing messages").
//
//   AUTH IS OFF, DELIBERATELY. RequireAuth is never turned on and no login is
//   proven, so there is no session key and nothing on the wire is encrypted by
//   the link. If the secret stays hidden it is the seal that hid it, and there
//   is no second explanation available.
//
//   Phase 1 (POSITIVE CONTROL) — Alice sends a marker in CLEAR to Carol.
//     It must arrive, and the middle hub MUST see it. This proves two things at
//     once: the three-hop route works, and the observer at the middle is really
//     looking at the bodies it carries. Without it, phase 2 could pass because
//     the message never went anywhere.
//
//   Phase 2 (THE PROBE) — Alice SEALS a secret to Carol and sends it the same
//     way, over the same route, through the same observer.
//       * the middle hub must NOT see the secret
//       * Carol must open it and recover the secret exactly
//     Both halves matter. A body nobody can read is easy; the test is a body
//     the middle cannot read and the destination can.
//
// VERDICT = process EXIT CODE:
//   0  PASS   middle saw the cleartext marker, did not see the sealed secret,
//             and Carol recovered it
//   1  FAIL   the middle hub saw the secret, or Carol could not open it
//   2  SETUP  startup / socket / provisioning failure (inconclusive)
//   3  INCONCLUSIVE phase 1 never arrived — the route is broken, so the probe
//             would prove nothing. NOT a pass.

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConWsa.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"
#include "P2PIdentityStore.h"
#include "P2PAuthLogin.h"
#include "P2PeerSeal.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
static const P2PaddrSTR kAliceAddr = L"Seal.Alice";
static const P2PaddrSTR kMidAddr   = L"Seal";
static const P2PaddrSTR kCarolAddr = L"Seal.Carol";
static const P2PaddrSTR kDomain    = L"Seal.*";

// The marker travels in clear; the secret travels sealed. Distinct strings, so
// "the middle saw it" can never be confused between the two phases.
static const char kMarker[] = "MARKER-IN-THE-CLEAR-4711";
static const char kSecret[] = "SECRET-artichoke-90210";

static HANDLE g_hCarolPlain  = NULL;   // phase 1 reached Carol
static HANDLE g_hCarolSealed = NULL;   // phase 2 reached Carol AND opened

static volatile bool g_bMidSawMarker = false;   // must become true
static volatile bool g_bMidSawSecret = false;   // must stay false
static volatile bool g_bCarolOpened  = false;
static volatile bool g_bCarolWrong   = false;   // opened, but not our plaintext
static int           g_nMidForwarded = 0;

static void Log ( const char *msg )
{
    std::printf ( "[sealhop] %s\n", msg );
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

// Does this buffer contain that needle anywhere? The question the Java twin
// asks of its intermediate, and the only question worth asking of a body that
// is supposed to be opaque.
static bool Contains ( const void *pv, size_t cb, const char *pszNeedle )
{
    const size_t cbNeedle = std::strlen ( pszNeedle );
    if ( !pv || cb < cbNeedle || cbNeedle == 0 ) return false;
    const char *p = (const char *)pv;
    for ( size_t i = 0; i + cbNeedle <= cb; ++i )
        if ( std::memcmp ( p + i, pszNeedle, cbNeedle ) == 0 ) return true;
    return false;
}

// ---------------------------------------------------------------------------
// Provisioning. Private keys stay in their files; only public points are
// published into the other peer's allow-list.
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
    s += "p2p_sealhop_"; s += pszLeaf; s += "_"; s += szPid; s += ".tmp";
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
    if ( !oKey.Generate() )                                          return false;
    if ( p2pcng::SaveIdentity ( sPath.c_str(), oKey ) != p2pcng::IdOk ) return false;
    return oKey.ExportPublic ( pPubOut );
}

static bool MakeAgreement ( const std::string &sPath, unsigned char *pPubOut )
{
    p2pcng::EcdhP256 oKey;
    if ( !oKey.Generate() )                                           return false;
    if ( p2pcng::SaveAgreement ( sPath.c_str(), oKey ) != p2pcng::IdOk ) return false;
    return oKey.ExportPublic ( pPubOut );
}

// =========================================================================
class SealHub : public P2PeerHub
{
public:
    enum Role { RoleAlice, RoleMiddle, RoleCarol };

    SealHub ( P2PaddrSTR strAddr, Role eRole )
        : P2PeerHub ( strAddr ), m_eRole ( eRole )
    { m_strSelf = strAddr; }
    virtual ~SealHub ( ) { }

protected:
    // The middle hub's window onto what it carries. Called by
    // P2PeerHub::RouteP2PeerMsg before the message is handed to the outbound
    // connection - i.e. on exactly the bytes this hub is about to forward.
    virtual msgRESULT PeekP2PeerMsg ( P2PeerMsg *pMsg ) override
    {
        if ( m_eRole == RoleMiddle && pMsg && pMsg->DataSize() > 0 && pMsg->Data() )
        {
            const void  *pv = pMsg->Data();
            const size_t cb = (size_t)pMsg->DataSize();
            g_nMidForwarded++;

            const bool bMarker = Contains ( pv, cb, kMarker );
            const bool bSecret = Contains ( pv, cb, kSecret );
            if ( bMarker ) g_bMidSawMarker = true;
            if ( bSecret ) g_bMidSawSecret = true;

            std::printf ( "[sealhop] MIDDLE forwarding %s -> %s, %u body bytes;"
                          " marker=%s secret=%s\n",
                          N ( pMsg->GetSource() ).c_str(),
                          N ( pMsg->GetDestin() ).c_str(),
                          (unsigned)cb,
                          bMarker ? "VISIBLE" : "no",
                          bSecret ? "VISIBLE" : "no" );
            std::fflush ( stdout );
        }
        return P2PeerHub::PeekP2PeerMsg ( pMsg );
    }

    // A custom login handler, and NOT for convenience.
    //
    // Alice loads an identity because she must SIGN what she seals. That same
    // key makes P2PeerCon sign her LOGIN too (P2PeerCon.cpp:2300, on
    // CanAuthSign()), and the middle hub requires no authentication, so the
    // block is handed up as login payload - which the stock handler refuses
    // outright ("Remote login request contains login data. Implement a custom
    // handler"). Without this the sender never finishes logging in.
    //
    // Worth knowing before deploying: a peer that seals also signs its logins,
    // so every hub it connects to must either require auth or accept a login
    // that carries data.
    virtual conRESULT On_ConLogin ( P2PeerCon *pCon, P2PaddrSTR strThatP2Paddr,
                                    const void *pvLoginMsg, P2Psize_t iSize ) override
    {
        std::printf ( "[sealhop] %s: login FROM '%s' (%d bytes of payload)\n",
                      RoleName(), N ( strThatP2Paddr ).c_str(), (int)iSize );
        std::fflush ( stdout );

        if ( !pvLoginMsg && !iSize )
            return P2PeerHub::On_ConLogin ( pCon, strThatP2Paddr, pvLoginMsg, iSize );

        pCon -> OnLogin  ( strThatP2Paddr );
        pCon -> LoginAck ( strThatP2Paddr, 0, 0 );
        return conHANDLED;
    }

    virtual conRESULT On_ConLoginAck ( P2PeerCon *pCon, P2PaddrSTR strThisP2Paddr,
                                       P2PaddrSTR strThatP2Paddr,
                                       const void *pvLoginAck, P2Psize_t iSize ) override
    {
        std::printf ( "[sealhop] %s: login ACK - this='%s' that='%s'\n",
                      RoleName(), N ( strThisP2Paddr ).c_str(),
                      N ( strThatP2Paddr ).c_str() );
        std::fflush ( stdout );
        return P2PeerHub::On_ConLoginAck ( pCon, strThisP2Paddr, strThatP2Paddr,
                                           pvLoginAck, iSize );
    }

    virtual msgRESULT On_P2PeerBCast ( P2PeerMsg *pMsg ) override
    {
        if ( m_eRole != RoleCarol || !pMsg || !pMsg->Data() )
            return msgHANDLED;

        const unsigned char *pIn = (const unsigned char *)pMsg->Data();
        const size_t         cbIn = (size_t)pMsg->DataSize();

        // Carol tries to open every body she is given. A cleartext one fails
        // the shape test, which is how the two phases tell themselves apart
        // without a flag on the wire that an attacker could flip.
        std::vector<unsigned char> vPlain ( p2pseal::OpenedSize ( cbIn ) + 1, 0 );
        size_t cbPlain = 0;
        p2pseal::SealResult e = p2pseal::SealErrFormat;
        if ( cbIn > p2pseal::kSealOverhead )
            e = OpenFrom ( pMsg->GetSource(), m_strSelf.GetString(),
                           pIn, cbIn, &vPlain[0], vPlain.size() - 1, &cbPlain );

        if ( e == p2pseal::SealOk )
        {
            const bool bMatch = ( cbPlain == std::strlen ( kSecret ) ) &&
                                ( std::memcmp ( &vPlain[0], kSecret, cbPlain ) == 0 );
            std::printf ( "[sealhop] CAROL opened a sealed body, %u bytes,"
                          " content %s\n", (unsigned)cbPlain,
                          bMatch ? "EXACTLY the secret" : "NOT what was sent" );
            std::fflush ( stdout );

            g_bCarolOpened = true;
            if ( !bMatch ) g_bCarolWrong = true;
            if ( g_hCarolSealed ) SetEvent ( g_hCarolSealed );
        }
        else if ( Contains ( pIn, cbIn, kMarker ) )
        {
            Log ( "CAROL received the cleartext marker" );
            if ( g_hCarolPlain ) SetEvent ( g_hCarolPlain );
        }
        else
        {
            std::printf ( "[sealhop] CAROL could not open a %u byte body: %s\n",
                          (unsigned)cbIn, p2pseal::SealResultText ( e ) );
            std::fflush ( stdout );
        }
        return msgHANDLED;
    }

private:
    const char *RoleName ( ) const
    {
        return m_eRole == RoleMiddle ? "MIDDLE"
             : m_eRole == RoleAlice  ? "ALICE" : "CAROL";
    }

    Role    m_eRole;
    CString m_strSelf;
};

// =========================================================================
int main ( int argc, char *argv[] )
{
    short nPort = ( argc >= 2 ) ? (short)atoi ( argv[1] ) : 7818;

    std::printf ( "=== p2p_sealhop - can a routing hub read what it carries? ===\n" );
    std::printf ( "Port : %d (the middle hub listens)\n", (int)nPort );
    std::printf ( "Route: %s -> %s -> %s, auth OFF, nothing encrypted by the link.\n\n",
                  N ( kAliceAddr ).c_str(), N ( kMidAddr ).c_str(),
                  N ( kCarolAddr ).c_str() );
    std::fflush ( stdout );

    g_hCarolPlain  = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hCarolSealed = CreateEvent ( NULL, FALSE, FALSE, NULL );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }
    WSADATA oWsaData;
    WSAStartup ( MAKEWORD ( 2, 2 ), &oWsaData );

    // ---- Provisioning -----------------------------------------------------
    // Alice needs an identity to SIGN with; Carol an agreement key to be sealed
    // TO. The middle hub gets nothing at all - that is the experiment.
    const std::string sAliceKey   = TempPath ( "alicekey"   );
    const std::string sCarolAgree = TempPath ( "carolagree" );
    const std::string sAliceAcl   = TempPath ( "aliceacl"   );
    const std::string sCarolAcl   = TempPath ( "carolacl"   );

    unsigned char pubAlice [p2pcng::kEcdsaPubLen];
    unsigned char agrCarol [p2pcng::kEcdhPubLen];
    if ( !MakeIdentity  ( sAliceKey,   pubAlice ) ||
         !MakeAgreement ( sCarolAgree, agrCarol )   )
    { Log ( "SETUP: key generation failed" ); ScrubTempFiles(); return 2; }

    // Carol's entry in Alice's allow-list carries BOTH columns: the identity
    // point (unused here, but that is the file format) and the agreement point
    // that makes her sealable. Alice's entry in Carol's list needs only the
    // identity - that is whose signature Carol will demand.
    unsigned char idCarol[p2pcng::kEcdsaPubLen];
    {
        p2pcng::EcdsaP256 oCarolId;
        if ( !oCarolId.Generate() || !oCarolId.ExportPublic ( idCarol ) )
        { Log ( "SETUP: Carol identity failed" ); ScrubTempFiles(); return 2; }
    }
    if ( p2pcng::AppendAllowList ( sAliceAcl.c_str(), "Seal.Carol",
                                   idCarol, agrCarol ) != p2pcng::IdOk ||
         p2pcng::AppendAllowList ( sCarolAcl.c_str(), "Seal.Alice",
                                   pubAlice ) != p2pcng::IdOk )
    { Log ( "SETUP: allow-list provisioning failed" ); ScrubTempFiles(); return 2; }

    int nExit = 2;
    {
        // ---- The middle hub: a router with no keys ------------------------
        SealHub oMiddle ( kMidAddr, SealHub::RoleMiddle );
        //  AUTH OFF, and now SAID rather than assumed. The header has always
        //  claimed "RequireAuth is never turned on" - which was true only
        //  because off was the default. Since ProductionPlan.md Stage 3 step 8
        //  it is not, so the claim is written down at each of the three hubs.
        //  It is the load-bearing part of this test: a sealed body that only
        //  Carol can open, carried by a hub that holds no keys, over links with
        //  NO connection cypher - so a pass cannot be credited to the link.
        oMiddle.RequireAuth ( false );

        //  AND RequireSeal(false), NEW ON 2026-08-21 and for the same shape of
        //  reason. Sealing a relayed body became the default in Stage 3 step
        //  20, and this test's CONTROL is phase 1 - a marker sent in CLEAR so
        //  the middle hub can be SEEN seeing it. With the default on, that
        //  marker is sealed automatically and the control cannot happen: the
        //  test would pass while proving nothing, which is the worst outcome a
        //  gate can have.
        //
        //  Turning it off does not weaken what this test proves. Phase 2 seals
        //  by HAND, with SealFor, and that is the proposition - a body sealed
        //  to Carol is opaque to the hub that routes it. Leaving the automatic
        //  path on would test the automatic path instead, which is
        //  p2p_sealdefault's job.
        oMiddle.RequireSeal ( false );
        HANDLE hMidThread = oMiddle.SpawnHub();
        if ( !hMidThread ) { Log ( "SETUP: middle SpawnHub() failed" ); return 2; }

        P2PeerConWsa *pSvc = P2PeerConWsa::ServiceFactory ( kDomain, nPort );
        if ( !pSvc ) { Log ( "SETUP: ServiceFactory failed" ); return 2; }
        oMiddle.PostP2PeerCon ( pSvc );
        Log ( "middle hub listening - no identity, no agreement key, no allow-list" );
        Sleep ( 500 );

        // ---- Carol: can open what is sealed to her ------------------------
        SealHub oCarol ( kCarolAddr, SealHub::RoleCarol );
        if ( oCarol.SetAgreementKey ( sCarolAgree.c_str() ) != p2pcng::IdOk ||
             oCarol.SetAllowList    ( sCarolAcl.c_str()   ) != p2pcng::IdOk )
        { Log ( "SETUP: Carol configuration failed" ); return 2; }
        if ( !oCarol.CanOpen() ) { Log ( "SETUP: Carol cannot open" ); return 2; }
        oCarol.RequireAuth ( false );   // see oMiddle above - the link stays in clear
        oCarol.RequireSeal ( false );

        HANDLE hCarolThread = oCarol.SpawnHub();
        P2PeerConWsa *pConCarol =
            P2PeerConWsa::ClientFactory ( kMidAddr, L"127.0.0.1", nPort );
        if ( !hCarolThread || !pConCarol ) { Log ( "SETUP: Carol failed" ); return 2; }
        oCarol.PostP2PeerCon ( pConCarol );
        Sleep ( 1000 );

        // ---- Alice: can seal to Carol -------------------------------------
        SealHub oAlice ( kAliceAddr, SealHub::RoleAlice );
        if ( oAlice.SetIdentity  ( sAliceKey.c_str() ) != p2pcng::IdOk ||
             oAlice.SetAllowList ( sAliceAcl.c_str() ) != p2pcng::IdOk )
        { Log ( "SETUP: Alice configuration failed" ); return 2; }
        if ( !oAlice.CanSeal() ) { Log ( "SETUP: Alice cannot seal" ); return 2; }
        oAlice.RequireAuth ( false );   // see oMiddle above - the link stays in clear
        oAlice.RequireSeal ( false );

        HANDLE hAliceThread = oAlice.SpawnHub();
        P2PeerConWsa *pConAlice =
            P2PeerConWsa::ClientFactory ( kMidAddr, L"127.0.0.1", nPort );
        if ( !hAliceThread || !pConAlice ) { Log ( "SETUP: Alice failed" ); return 2; }
        oAlice.PostP2PeerCon ( pConAlice );
        Sleep ( 1500 );

        // ---- Phase 1: the positive control --------------------------------
        Log ( "--- phase 1: a marker in CLEAR, so the middle can be seen seeing ---" );
        oAlice.PostP2PeerMsg ( new P2PeerMsg32 ( kAliceAddr, kCarolAddr,
                                                 P2Pmsg_BCast, kMarker,
                                                 (P2Psize_t)std::strlen ( kMarker ) ) );

        if ( WaitForSingleObject ( g_hCarolPlain, 20000 ) != WAIT_OBJECT_0 )
        {
            std::printf (
              "\nRESULT: INCONCLUSIVE - the cleartext marker never reached Carol,\n"
              "  so the route is not carrying anything and the probe would prove\n"
              "  nothing. This is NOT a pass.\n" );
            nExit = 3;
        }
        else if ( !g_bMidSawMarker )
        {
            std::printf (
              "\nRESULT: INCONCLUSIVE - the marker arrived but the middle hub never\n"
              "  saw it, so the observer is not watching the path the message took.\n"
              "  Phase 2 would be measuring nothing. This is NOT a pass.\n" );
            nExit = 3;
        }
        else
        {
            Log ( "positive control OK - the middle hub reads cleartext it forwards" );

            // ---- Phase 2: the probe ---------------------------------------
            Log ( "--- phase 2: the same route, the same observer, a SEALED body ---" );

            const size_t cbSecret = std::strlen ( kSecret );
            std::vector<unsigned char> vSealed ( p2pseal::SealedSize ( cbSecret ), 0 );
            size_t cbSealed = 0;
            p2pseal::SealResult e = oAlice.SealFor ( kAliceAddr, kCarolAddr,
                                                     kSecret, cbSecret,
                                                     &vSealed[0], vSealed.size(),
                                                     &cbSealed );
            if ( e != p2pseal::SealOk )
            {
                std::printf ( "SETUP: SealFor failed: %s\n",
                              p2pseal::SealResultText ( e ) );
                nExit = 2;
            }
            else
            {
                std::printf ( "[sealhop] Alice sealed %u bytes into %u\n",
                              (unsigned)cbSecret, (unsigned)cbSealed );
                std::fflush ( stdout );

                oAlice.PostP2PeerMsg ( new P2PeerMsg32 ( kAliceAddr, kCarolAddr,
                                                         P2Pmsg_BCast, &vSealed[0],
                                                         (P2Psize_t)cbSealed ) );

                const bool bArrived =
                    ( WaitForSingleObject ( g_hCarolSealed, 20000 ) == WAIT_OBJECT_0 );

                if ( g_bMidSawSecret )
                {
                    std::printf (
                      "\nRESULT: FAIL - THE MIDDLE HUB READ THE SECRET.\n"
                      "  The body was supposed to be sealed to Carol, and the hub\n"
                      "  that merely forwards it recovered the plaintext. End-to-end\n"
                      "  confidentiality does not hold across a hop.\n" );
                    nExit = 1;
                }
                else if ( !bArrived || !g_bCarolOpened )
                {
                    std::printf (
                      "\nRESULT: FAIL - Carol never opened the sealed body.\n"
                      "  Hiding a body from everybody is not the property under\n"
                      "  test; the destination must still recover it.\n" );
                    nExit = 1;
                }
                else if ( g_bCarolWrong )
                {
                    std::printf (
                      "\nRESULT: FAIL - Carol opened the body but got back\n"
                      "  something other than what Alice sealed.\n" );
                    nExit = 1;
                }
                else
                {
                    std::printf (
                      "\nRESULT: PASS - the middle hub forwarded %d bodies, read the\n"
                      "  cleartext one, and could not read the sealed one. Carol\n"
                      "  recovered the secret exactly.\n"
                      "  Auth was OFF throughout: no login was proven and no session\n"
                      "  key exists, so the link encrypted nothing. The seal is the\n"
                      "  only thing that hid it.\n", g_nMidForwarded );
                    nExit = 0;
                }
            }
        }

        Log ( "shutdown begin" );
        oAlice.CloseHub();
        WaitForSingleObject ( hAliceThread, 3000 );
        CloseHandle ( hAliceThread );

        oCarol.CloseHub();
        WaitForSingleObject ( hCarolThread, 3000 );
        CloseHandle ( hCarolThread );

        oMiddle.CloseHub();
        WaitForSingleObject ( hMidThread, 3000 );
        CloseHandle ( hMidThread );
    }

    CleanupP2Pmsg();
    ScrubTempFiles();
    if ( g_hCarolPlain  ) { CloseHandle ( g_hCarolPlain  ); g_hCarolPlain  = NULL; }
    if ( g_hCarolSealed ) { CloseHandle ( g_hCarolSealed ); g_hCarolSealed = NULL; }
    WSACleanup();

    std::printf ( "Done (exit=%d).\n", nExit );
    std::fflush ( stdout );
    return nExit;
}
