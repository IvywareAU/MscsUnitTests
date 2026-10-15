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
// p2p_sealwire.cpp - does a SEALED message carry its plaintext on the wire?
//
// FINDING F-L4-1 (P2PeerLan L4, 2026-10-12). P2PeerCon::SealAppMsgOutbound
// swaps the sealed block in with SetData, which reallocates inside the
// message's own heap and frees the old block WITHOUT ZEROING IT. The send path
// puts the whole heap on the wire (PrepareP2Piomage's full-replica path), so
// the plaintext travelled beside its own ciphertext: a relay holding no keys
// could read it straight out of the frame, and the link cypher only hid it
// from the cable. Two side effects of the same mechanism:
//   * a sealed frame was ~2x the body, so the 32768-byte frame cap allowed a
//     body of only ~15 KB; a larger one was refused by the next hub and the
//     LINK DROPPED;
//   * every sealed byte was sent twice.
//
// p2p_sealhop could not see this: its middle hub reads Data(), the payload
// item, and that IS the ciphertext. The plaintext was in a FREE block of the
// same image. So this test reads what the wire carried, not what the API says.
//
// WHAT IT DOES - three hubs, two sockets, the AUTOMATIC seal.
//
//       Seal.Alice  ---->  Seal  ---->  Seal.Carol
//        (sender)        (middle)       (recipient)
//                       holds NO keys
//
//   Alice keeps the default RequireSeal(true), holds an identity and Carol's
//   agreement key, and sends a plain body; her outbound connection seals it
//   because the route crosses the middle hub. The middle observes each message
//   it forwards through PeekP2PeerMsg and scans the WHOLE received image - a
//   received message's heap is the frame that came off the socket. Carol's
//   connection opens it on arrival. Auth is off, so the link encrypts nothing
//   and the frame the middle scans is the frame the cable carried.
//
//   Phase 1 (2 KB body)
//     CONTROLS: Carol receives the body back in clear, exactly (the route and
//     the automatic seal/open work); the middle forwarded it SEALED (the seal
//     ran); and the middle finds Carol's address in the image (the scanner is
//     reading the frame - an image scan that finds nothing proves nothing).
//     THE PROBE: the plaintext is nowhere in the frame, and the frame is no
//     bigger than one sealed body plus the addressing.
//   Phase 2 (20 KB body) - over the old ~15 KB ceiling, under the 32 KB cap
//     once the frame holds the body once. It must arrive.
//
// VERDICT = process EXIT CODE:
//   0  PASS   no plaintext in the frame, frame ~one body, 20 KB arrives
//   1  FAIL   plaintext in the frame, or a doubled frame, or 20 KB lost
//   2  SETUP  startup / socket / provisioning failure (inconclusive)
//   3  INCONCLUSIVE a control failed - the probe would prove nothing

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

//  The body is this pattern repeated, so a plaintext fragment anywhere in the
//  frame is found whatever offset the heap put it at.
static const char kNeedle[] = "PLAINTEXT-artichoke-90210-";

static HANDLE g_hCarolGot = NULL;

//  Written by the middle hub's pump, read by main after Carol's event
static volatile bool     g_bMidSawSealed  = false;   // forwarded body was sealed
static volatile bool     g_bMidSawPlain   = false;   // needle found in the FRAME
static volatile bool     g_bMidSawAddress = false;   // control: Carol's address found
static volatile unsigned g_cbMidFrame     = 0;       // frame size of the last one
static volatile unsigned g_cbMidBody      = 0;       // its (sealed) body size
static volatile bool     g_bCarolExact    = false;
static volatile unsigned g_cbCarol        = 0;
static std::vector<char> g_vExpect;                  // what Carol must get back

static void Log ( const char *msg )
{
    std::printf ( "[sealwire] %s\n", msg );
    std::fflush ( stdout );
}

static bool Contains ( const void *pv, size_t cb, const void *pNeedle, size_t cbNeedle )
{
    if ( !pv || cb < cbNeedle || cbNeedle == 0 ) return false;
    const char *p = (const char *)pv;
    for ( size_t i = 0; i + cbNeedle <= cb; ++i )
        if ( std::memcmp ( p + i, pNeedle, cbNeedle ) == 0 ) return true;
    return false;
}

static std::vector<char> MakeBody ( size_t cb )
{
    std::vector<char> v ( cb );
    const size_t n = std::strlen ( kNeedle );
    for ( size_t i = 0; i < cb; ++i ) v[i] = kNeedle[i % n];
    return v;
}

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
    s += "p2p_sealwire_"; s += pszLeaf; s += "_"; s += szPid; s += ".tmp";
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
class WireHub : public P2PeerHub
{
public:
    enum Role { RoleAlice, RoleMiddle, RoleCarol };

    WireHub ( P2PaddrSTR strAddr, Role eRole )
        : P2PeerHub ( strAddr ), m_eRole ( eRole ) { }
    virtual ~WireHub ( ) { }

protected:
    //  The middle hub's window onto the FRAME. A received message's heap is the
    //  buffer the socket filled, so the full-replica image is what the cable
    //  carried - free blocks included, which is the whole point
    virtual msgRESULT PeekP2PeerMsg ( P2PeerMsg *pMsg ) override
    {
        if ( m_eRole == RoleMiddle && pMsg && pMsg->DataSize() > 0 )
        {
            const bool bSealed = pMsg->IsSealed ( );
            const void *pvImage = pMsg->PrepareP2Piomage ( ~(DWORD)0 );
            const UINT  cbImage = pMsg->P2PiomageSize ( );

            const bool bPlain = Contains ( pvImage, cbImage, kNeedle, std::strlen ( kNeedle ) );
            const size_t cbAddr = std::wcslen ( kCarolAddr ) * sizeof(wchar_t);
            const bool bAddr  = Contains ( pvImage, cbImage, kCarolAddr, cbAddr );
            pMsg->ReleaseP2Piomage ( );

            if ( bSealed ) g_bMidSawSealed  = true;
            if ( bPlain  ) g_bMidSawPlain   = true;
            if ( bAddr   ) g_bMidSawAddress = true;
            g_cbMidFrame = cbImage;
            g_cbMidBody  = (unsigned)pMsg->DataSize ( );

            std::printf ( "[sealwire] MIDDLE forwarding: sealed=%s frame=%u body=%u"
                          " plaintext-in-frame=%s carol-addr-in-frame=%s\n",
                          bSealed ? "yes" : "NO", (unsigned)cbImage,
                          (unsigned)pMsg->DataSize ( ),
                          bPlain ? "YES" : "no", bAddr ? "yes" : "no" );
            std::fflush ( stdout );
        }
        return P2PeerHub::PeekP2PeerMsg ( pMsg );
    }

    //  Alice signs her logins because she holds an identity; the middle hub
    //  requires no auth, so it must accept a login that carries data. Same
    //  handler, same reason, as p2p_sealhop
    virtual conRESULT On_ConLogin ( P2PeerCon *pCon, P2PaddrSTR strThatP2Paddr,
                                    const void *pvLoginMsg, P2Psize_t iSize ) override
    {
        if ( !pvLoginMsg && !iSize )
            return P2PeerHub::On_ConLogin ( pCon, strThatP2Paddr, pvLoginMsg, iSize );
        pCon -> OnLogin  ( strThatP2Paddr );
        pCon -> LoginAck ( strThatP2Paddr, 0, 0 );
        return conHANDLED;
    }

    //  Carol gets the body after her connection opened it
    virtual msgRESULT On_P2PeerBCast ( P2PeerMsg *pMsg ) override
    {
        if ( m_eRole != RoleCarol || !pMsg )
            return msgHANDLED;
        const size_t cb = (size_t)pMsg->DataSize ( );
        g_cbCarol     = (unsigned)cb;
        g_bCarolExact = !pMsg->IsSealed ( ) && cb == g_vExpect.size ( ) &&
                        std::memcmp ( pMsg->Data ( ), &g_vExpect[0], cb ) == 0;
        std::printf ( "[sealwire] CAROL received %u bytes, %s\n", (unsigned)cb,
                      g_bCarolExact ? "EXACTLY the plaintext" : "NOT what was sent" );
        std::fflush ( stdout );
        if ( g_hCarolGot ) SetEvent ( g_hCarolGot );
        return msgHANDLED;
    }

private:
    Role m_eRole;
};

//  One send, Alice -> Carol, and what the middle and Carol saw of it
static bool SendOne ( WireHub& oAlice, size_t cbBody, DWORD dwWaitMs )
{
    g_bMidSawSealed = g_bMidSawPlain = g_bMidSawAddress = false;
    g_cbMidFrame = g_cbMidBody = 0;
    g_bCarolExact = false; g_cbCarol = 0;
    ResetEvent ( g_hCarolGot );

    g_vExpect = MakeBody ( cbBody );
    oAlice.PostP2PeerMsg ( new P2PeerMsg32 ( kAliceAddr, kCarolAddr, P2Pmsg_BCast,
                                             &g_vExpect[0], (P2Psize_t)cbBody ) );
    return WaitForSingleObject ( g_hCarolGot, dwWaitMs ) == WAIT_OBJECT_0;
}

// =========================================================================
int main ( int argc, char *argv[] )
{
    short nPort = ( argc >= 2 ) ? (short)atoi ( argv[1] ) : 7817;

    std::printf ( "=== p2p_sealwire - is the plaintext in a sealed message's frame? ===\n" );
    std::printf ( "Port : %d (the middle hub listens)\n", (int)nPort );
    std::printf ( "Route: Seal.Alice -> Seal -> Seal.Carol, AUTOMATIC seal, auth OFF.\n\n" );
    std::fflush ( stdout );

    g_hCarolGot = CreateEvent ( NULL, TRUE, FALSE, NULL );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }
    WSADATA oWsaData;
    WSAStartup ( MAKEWORD ( 2, 2 ), &oWsaData );

    // ---- Provisioning, as p2p_sealhop ---------------------------------------
    const std::string sAliceKey   = TempPath ( "alicekey"   );
    const std::string sCarolAgree = TempPath ( "carolagree" );
    const std::string sAliceAcl   = TempPath ( "aliceacl"   );
    const std::string sCarolAcl   = TempPath ( "carolacl"   );

    unsigned char pubAlice [p2pcng::kEcdsaPubLen];
    unsigned char agrCarol [p2pcng::kEcdhPubLen];
    unsigned char idCarol  [p2pcng::kEcdsaPubLen];
    {
        p2pcng::EcdsaP256 oCarolId;
        if ( !MakeIdentity  ( sAliceKey,   pubAlice ) ||
             !MakeAgreement ( sCarolAgree, agrCarol ) ||
             !oCarolId.Generate ( ) || !oCarolId.ExportPublic ( idCarol ) )
        { Log ( "SETUP: key generation failed" ); ScrubTempFiles(); return 2; }
    }
    if ( p2pcng::AppendAllowList ( sAliceAcl.c_str(), "Seal.Carol",
                                   idCarol, agrCarol ) != p2pcng::IdOk ||
         p2pcng::AppendAllowList ( sCarolAcl.c_str(), "Seal.Alice",
                                   pubAlice ) != p2pcng::IdOk )
    { Log ( "SETUP: allow-list provisioning failed" ); ScrubTempFiles(); return 2; }

    int nExit = 2;
    {
        //  The middle: a router with no keys, auth off. RequireSeal(false)
        //  because it originates nothing; what it forwards is sealed by Alice
        WireHub oMiddle ( kMidAddr, WireHub::RoleMiddle );
        oMiddle.RequireAuth ( false );
        oMiddle.RequireSeal ( false );
        HANDLE hMidThread = oMiddle.SpawnHub();
        if ( !hMidThread ) { Log ( "SETUP: middle SpawnHub() failed" ); return 2; }
        P2PeerConWsa *pSvc = P2PeerConWsa::ServiceFactory ( kDomain, nPort );
        if ( !pSvc ) { Log ( "SETUP: ServiceFactory failed" ); return 2; }
        oMiddle.PostP2PeerCon ( pSvc );
        Sleep ( 500 );

        //  Carol: opens what is sealed to her
        WireHub oCarol ( kCarolAddr, WireHub::RoleCarol );
        if ( oCarol.SetAgreementKey ( sCarolAgree.c_str() ) != p2pcng::IdOk ||
             oCarol.SetAllowList    ( sCarolAcl.c_str()   ) != p2pcng::IdOk ||
             !oCarol.CanOpen ( ) )
        { Log ( "SETUP: Carol configuration failed" ); return 2; }
        oCarol.RequireAuth ( false );
        HANDLE hCarolThread = oCarol.SpawnHub();
        P2PeerConWsa *pConCarol =
            P2PeerConWsa::ClientFactory ( kMidAddr, L"127.0.0.1", nPort );
        if ( !hCarolThread || !pConCarol ) { Log ( "SETUP: Carol failed" ); return 2; }
        oCarol.PostP2PeerCon ( pConCarol );
        Sleep ( 1000 );

        //  Alice: RequireSeal stays at its default, TRUE - the automatic path
        WireHub oAlice ( kAliceAddr, WireHub::RoleAlice );
        if ( oAlice.SetIdentity  ( sAliceKey.c_str() ) != p2pcng::IdOk ||
             oAlice.SetAllowList ( sAliceAcl.c_str() ) != p2pcng::IdOk ||
             !oAlice.CanSeal ( ) )
        { Log ( "SETUP: Alice configuration failed" ); return 2; }
        oAlice.RequireAuth ( false );
        if ( !oAlice.IsSealRequired ( ) ) { Log ( "SETUP: seal is not required" ); return 2; }
        HANDLE hAliceThread = oAlice.SpawnHub();
        P2PeerConWsa *pConAlice =
            P2PeerConWsa::ClientFactory ( kMidAddr, L"127.0.0.1", nPort );
        if ( !hAliceThread || !pConAlice ) { Log ( "SETUP: Alice failed" ); return 2; }
        oAlice.PostP2PeerCon ( pConAlice );
        Sleep ( 1500 );

        // ---- Phase 1: 2 KB ----------------------------------------------------
        Log ( "--- phase 1: a 2 KB body, sealed automatically ---" );
        const size_t cb1 = 2048;
        const bool bGot1 = SendOne ( oAlice, cb1, 20000 );
        const unsigned cbFrame1 = g_cbMidFrame, cbSealed1 = g_cbMidBody;

        if ( !bGot1 || !g_bCarolExact || !g_bMidSawSealed || !g_bMidSawAddress )
        {
            std::printf ( "\nRESULT: INCONCLUSIVE - a control failed: carol-got=%s exact=%s"
                          " middle-saw-sealed=%s scanner-found-address=%s.\n"
                          "  Without all four the frame scan below proves nothing.\n",
                          bGot1 ? "yes" : "no", g_bCarolExact ? "yes" : "no",
                          g_bMidSawSealed ? "yes" : "no", g_bMidSawAddress ? "yes" : "no" );
            nExit = 3;
        }
        else
        {
            nExit = 0;
            if ( g_bMidSawPlain )
            {
                std::printf ( "FAIL: the PLAINTEXT is in the sealed message's frame -\n"
                              "      a relay with no keys reads it out of the free block\n" );
                nExit = 1;
            }
            //  One sealed body plus addressing, attestation and headers. The old
            //  frame was the plaintext PLUS the sealed body, so > cb1 + cbSealed1
            if ( cbFrame1 > cbSealed1 + 2048 )
            {
                std::printf ( "FAIL: frame %u bytes for a %u-byte sealed body - the frame\n"
                              "      carries more than the body once\n",
                              cbFrame1, cbSealed1 );
                nExit = 1;
            }

            // ---- Phase 2: 20 KB -----------------------------------------------
            Log ( "--- phase 2: a 20 KB body - over the old ~15 KB sealed ceiling ---" );
            const size_t cb2 = 20000;
            const bool bGot2 = SendOne ( oAlice, cb2, 20000 );
            if ( !bGot2 || !g_bCarolExact )
            {
                std::printf ( "FAIL: the 20 KB sealed body did not arrive intact (got=%s,"
                              " exact=%s) - the frame exceeded the 32768-byte cap\n",
                              bGot2 ? "yes" : "no", g_bCarolExact ? "yes" : "no" );
                nExit = 1;
            }
            else if ( g_bMidSawPlain )
            {
                std::printf ( "FAIL: the 20 KB frame carries the plaintext\n" );
                nExit = 1;
            }
            std::printf ( "[sealwire] phase 1 frame=%u (sealed body %u); phase 2 frame=%u\n",
                          cbFrame1, cbSealed1, (unsigned)g_cbMidFrame );
        }

        Log ( "shutdown begin" );
        oAlice.CloseHub();  WaitForSingleObject ( hAliceThread, 3000 ); CloseHandle ( hAliceThread );
        oCarol.CloseHub();  WaitForSingleObject ( hCarolThread, 3000 ); CloseHandle ( hCarolThread );
        oMiddle.CloseHub(); WaitForSingleObject ( hMidThread,   3000 ); CloseHandle ( hMidThread );
    }

    CleanupP2Pmsg();
    ScrubTempFiles();
    if ( g_hCarolGot ) { CloseHandle ( g_hCarolGot ); g_hCarolGot = NULL; }
    WSACleanup();

    std::printf ( nExit == 0 ? "\nRESULT: PASS\n"
                : nExit == 1 ? "\nRESULT: FAIL\n" : "\nRESULT: not a verdict (exit %d)\n",
                  nExit );
    std::fflush ( stdout );
    return nExit;
}
