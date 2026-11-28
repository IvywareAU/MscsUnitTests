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
// p2p_vnetsameroot.cpp - a VNet mount between two networks with the SAME root.
//
// BACKGROUND - p2p_vnetmount joins two networks with different roots (Out and
// In). Nothing in the design asks for that: V:x names x in the far network's
// own terms, so the two networks should be free to use the same names. This
// test checks that claim at its worst case. Both networks are rooted at
// "Root", and the far service has the SAME FULL ADDRESS as the sender:
//
//   outer (key KO)                          inner (key KI)
//     Root                                    Root
//     Root.L        Root.Mid                  Root.L
//     Root.L.Leaf   Root.Mid.Gate ==mount==   Root.L.Leaf   (accepted by Root)
//                                             Root.Root
//
// Root.Root is the collision the same root makes inside the hub's route
// index. The index files a connection under the first segment below the hub,
// and ':' ends a segment as '.' does, so the inner Root files its mount
// (Root:Root.Mid.Gate) and its child Root.Root under the SAME key, "Root". For
// an unqualified Root.Root the mount is then a candidate, and only the mount's
// "nothing else crosses a mount" test keeps it from taking the message.
//
// Two hubs named Root, Root.L and Root.L.Leaf live in one process. Each
// network has its own allow-list, so the same address carries a different key
// on each side. The process's hub index holds both hubs for each name
// (s_mapP2PmsgHubAddr keeps a vector per address).
//
// Addresses across the mount, as each side sees them:
//   from outside, the inner Leaf is   Root.Mid.Gate:Root.L.Leaf
//   from inside,  the outer Leaf is   Root:Root.L.Leaf
//
// Every link is DMX, and every hub has RequireAuth, RequireSeal and
// RequireRelayAuth on, as in p2p_vnetmount.
//
// PHASES
//   1  POSITIVE CONTROL: outer Root.L.Leaf -> Root.Mid.Gate.
//   2  NO CROSS-TALK: outer Root.Mid.Gate -> "Root.L.Leaf" and inner Root ->
//      "Root.L.Leaf", both unqualified. Each must reach ITS OWN network's Leaf
//      and only that one. And inner Root -> Root.Root, which shares the
//      mount's route-index key and must still reach the child.
//   3  INTO THE MOUNT: outer Leaf -> Root.Mid.Gate:Root.L.Leaf. The inner Leaf
//      must receive it from Root:Root.L.Leaf.
//   4  BACK OUT: the inner Leaf replies to Root:Root.L.Leaf. The outer Leaf
//      must receive it from Root.Mid.Gate:Root.L.Leaf.
//   5  A second round trip on the same links.
//   Throughout: NO link closes, and no message lands in the twin of the hub
//   it was meant for.
//
// MUTATION-CHECKED 2026-11-29 (Linux Debug, Targetcore 3.12.0). Each mutant
// below turned this test red, then the source was restored by hash:
//   M1 VNetWireSrc drops the P: prefix              4 links closed, 3-5 fail
//   M2 VNetWireDst leaves H:x unrewritten           4 links closed, 3-5 fail
//   M3 a mount binds sources like any link          4 links closed, 3-5 fail
//   M4 VNetMountOut keeps the origin's attestation  6 links closed, 3-5 fail
//   M5 ':' is not a hop boundary                    3-5 undelivered
//   M6 a mount is picked for unqualified addresses  Root.Root undelivered
// M6 is caught by THIS test only (p2p_vnetmount passes under it), and only
// because of Root.Root and the mount being posted first: before both were
// added, M6 survived.
//
// VERDICT = process EXIT CODE:
//   0  PASS
//   1  FAIL
//   2  SETUP  startup / provisioning failure (test inconclusive)
//   3  INCONCLUSIVE phase 1 failed - the trees never came up, proves nothing

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConDmx.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"
#include "P2PIdentityStore.h"
#include "P2PAuthLogin.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
static void Log ( const char *msg )
{
    std::printf ( "[vnetsameroot] %s\n", msg );
    std::fflush ( stdout );
}

static std::string N ( const wchar_t *w )
{
    std::string s;
    if ( w ) for ( ; *w; ++w ) s.push_back ( *w < 0x80 ? (char)*w : '?' );
    return s;
}

// Payload copied out: Data() is not aligned for wchar_t (F-S5-3)
static std::string BodyA ( P2PeerMsg *pMsg )
{
    if ( !pMsg || !pMsg->Data ( ) ) return std::string ( );
    const size_t cb = (size_t)pMsg->DataSize ( );
    std::vector<wchar_t> w ( cb / sizeof(wchar_t) + 1, L'\0' );
    std::memcpy ( w.data ( ), pMsg->Data ( ), ( w.size ( ) - 1 ) * sizeof(wchar_t) );
    return N ( w.data ( ) );
}

static std::atomic<int> g_nCloses ( 0 );

// What each hub received: "src|body" lines
struct Inbox
{
    std::mutex               mx;
    std::vector<std::string> lines;
    HANDLE                   hEvent = NULL;
    void Add ( const std::string &s )
    {
        { std::lock_guard<std::mutex> g ( mx ); lines.push_back ( s ); }
        SetEvent ( hEvent );
    }
    int Count ( const std::string &s )
    {
        std::lock_guard<std::mutex> g ( mx );
        int n = 0;
        for ( const std::string &l : lines ) if ( l == s ) ++n;
        return n;
    }
    bool Has ( const std::string &s ) { return Count ( s ) > 0; }
    //  Any line whose body is this, whoever sent it
    bool HasBody ( const std::string &sBody )
    {
        std::lock_guard<std::mutex> g ( mx );
        const std::string sTail = "|" + sBody;
        for ( const std::string &l : lines )
          if ( l.size ( ) >= sTail.size ( ) &&
               l.compare ( l.size ( ) - sTail.size ( ), sTail.size ( ), sTail ) == 0 )
            return true;
        return false;
    }
    std::string All ( )
    {
        std::lock_guard<std::mutex> g ( mx );
        std::string o;
        for ( const std::string &l : lines ) o += "    " + l + "\n";
        return o.empty ( ) ? "    (nothing)\n" : o;
    }
};

static bool WaitFor ( Inbox &box, const std::string &s, int nMin, int nTicks )
{
    for ( int i = 0; i < nTicks && box.Count ( s ) < nMin; ++i ) WaitForSingleObject ( box.hEvent, 100 );
    return box.Count ( s ) >= nMin;
}

// =========================================================================
//  pszNet only labels the log: the two networks share every hub name
class MountHub : public P2PeerHub
{
public:
    MountHub ( P2PaddrSTR strAddr, const char *pszNet, Inbox *pInbox, bool bEcho )
        : P2PeerHub ( strAddr ), m_pszNet ( pszNet ), m_pInbox ( pInbox ), m_bEcho ( bEcho )
    { m_strSelf = strAddr; }

    void Send ( P2PaddrSTR strTo, const wchar_t *pszBody )
    {
        PostP2PeerMsg ( new P2PeerMsg32 ( m_strSelf.GetString ( ), strTo, P2Pmsg_BCast, pszBody,
                                          (P2Psize_t)( ( wcslen ( pszBody ) + 1 ) * sizeof(wchar_t) ) ) );
    }

protected:
    virtual msgRESULT On_P2PeerBCast ( P2PeerMsg *pMsg ) override
    {
        if ( !pMsg ) return msgHANDLED;
        //  Only what was addressed HERE - a relaying hub sees traffic too
        CString strDst = pMsg->GetDestin ( ) ? pMsg->GetDestin ( ) : L"";
        if ( strDst != m_strSelf ) return msgHANDLED;
        const std::string sSrc  = N ( pMsg->GetSource ( ) );
        const std::string sBody = BodyA ( pMsg );
        std::printf ( "[vnetsameroot] %s %s received '%s' from %s\n",
                      m_pszNet, N ( m_strSelf ).c_str ( ), sBody.c_str ( ), sSrc.c_str ( ) );
        std::fflush ( stdout );
        if ( m_pInbox ) m_pInbox->Add ( sSrc + "|" + sBody );
        if ( m_bEcho && sBody == "ping" )
        {
            CString strBack = pMsg->GetSource ( );       // reply to whoever it says it was
            Send ( strBack, L"pong" );
        }
        return msgHANDLED;
    }

    virtual conRESULT On_ConClose ( P2PeerCon *pCon ) override
    {
        ++g_nCloses;
        std::printf ( "[vnetsameroot] %s %s: LINK CLOSED (%s)\n", m_pszNet, N ( m_strSelf ).c_str ( ),
                      pCon ? N ( pCon->GetP2Paddress ( ).c_wstr ( ) ).c_str ( ) : "?" );
        std::fflush ( stdout );
        return P2PeerHub::On_ConClose ( pCon );
    }

private:
    const char *m_pszNet;
    Inbox      *m_pInbox;
    bool        m_bEcho;
    CString     m_strSelf;
};

// ---------------------------------------------------------------------------
static std::vector<std::string> g_vTempFiles;

static std::string TempPath ( const char *pszLeaf )
{
    char  szDir[MAX_PATH + 2] = { 0 };
    DWORD n = GetTempPathA ( MAX_PATH + 1, szDir );
    std::string s = ( n > 0 && n <= MAX_PATH ) ? std::string ( szDir ) : std::string ( ".\\" );
    char szPid[32];
    std::snprintf ( szPid, sizeof(szPid), "%lu", (unsigned long)GetCurrentProcessId ( ) );
    s += "p2p_vnetsameroot_"; s += pszLeaf; s += "_"; s += szPid; s += ".tmp";
    DeleteFileA ( s.c_str ( ) );
    g_vTempFiles.push_back ( s );
    return s;
}

static void ScrubTempFiles ( )
{
    for ( size_t i = 0; i < g_vTempFiles.size ( ); ++i ) DeleteFileA ( g_vTempFiles[i].c_str ( ) );
    g_vTempFiles.clear ( );
}

struct Keys
{
    std::string   id, agree;
    unsigned char pub[p2pcng::kEcdsaPubLen];
    unsigned char agreePub[p2pcng::kEcdhPubLen];
};

static bool MakeKeys ( const char *pszLeaf, Keys &k )
{
    k.id    = TempPath ( ( std::string ( pszLeaf ) + "_id" ).c_str ( ) );
    k.agree = TempPath ( ( std::string ( pszLeaf ) + "_ag" ).c_str ( ) );
    p2pcng::EcdsaP256 oId;
    p2pcng::EcdhP256  oAg;
    return oId.Generate ( ) && p2pcng::SaveIdentity ( k.id.c_str ( ), oId ) == p2pcng::IdOk &&
           oId.ExportPublic ( k.pub ) &&
           oAg.Generate ( ) && p2pcng::SaveAgreement ( k.agree.c_str ( ), oAg ) == p2pcng::IdOk &&
           oAg.ExportPublic ( k.agreePub );
}

static bool Line ( const std::string &sAcl, const char *pszAddr, const Keys &k )
{
    return p2pcng::AppendAllowList ( sAcl.c_str ( ), pszAddr, k.pub, k.agreePub ) == p2pcng::IdOk;
}

static bool Prepare ( P2PeerHub &hub, const Keys &k, const std::string &sAcl )
{
    if ( hub.SetIdentity ( k.id.c_str ( ) )        != p2pcng::IdOk ) return false;
    if ( hub.SetAgreementKey ( k.agree.c_str ( ) ) != p2pcng::IdOk ) return false;
    if ( hub.SetAllowList ( sAcl.c_str ( ) )       != p2pcng::IdOk ) return false;
    hub.RequireAuth ( true );
    hub.RequireSeal ( true );
    hub.RequireRelayAuth ( true );
    hub.RequireRevocation ( false );     // not about revocation; see p2p_authchannel
    return true;
}

// =========================================================================
int main ( int argc, char *argv[] )
{
    (void)argc; (void)argv;
    std::printf ( "=== p2p_vnetsameroot - a VNet mount between two networks both rooted at Root ===\n\n" );
    std::fflush ( stdout );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }

    //  One allow-list per network. The same address appears in both with a
    //  different key: that is the point
    Keys kO, kI;
    const std::string sAclO = TempPath ( "acl_out" );
    const std::string sAclI = TempPath ( "acl_in" );
    if ( !MakeKeys ( "out", kO ) || !MakeKeys ( "in", kI ) ||
         // the outer network, and what lies beyond its mount
         !Line ( sAclO, "Root", kO ) || !Line ( sAclO, "Root.L", kO ) || !Line ( sAclO, "Root.L.Leaf", kO ) ||
         !Line ( sAclO, "Root.Mid", kO ) || !Line ( sAclO, "Root.Mid.Gate", kO ) ||
         !Line ( sAclO, "Root.Mid.Gate:Root", kI ) ||             // the mount's login ack
         !Line ( sAclO, "Root.Mid.Gate:Root.L.Leaf", kO ) ||      // spoken for by the gate
         // the inner network, and what lies beyond ITS mount
         !Line ( sAclI, "Root", kI ) || !Line ( sAclI, "Root.L", kI ) || !Line ( sAclI, "Root.L.Leaf", kI ) ||
         !Line ( sAclI, "Root.Root", kI ) ||
         !Line ( sAclI, "Root:Root.Mid.Gate", kO ) ||             // the mount's login
         !Line ( sAclI, "Root:Root.L.Leaf", kI ) )                // spoken for by the inner Root
    { Log ( "SETUP: provisioning failed" ); ScrubTempFiles ( ); return 2; }

    Inbox boxOLeaf, boxOGate, boxILeaf, boxIRR;
    boxOLeaf.hEvent = CreateEvent ( NULL, FALSE, FALSE, NULL );
    boxOGate.hEvent = CreateEvent ( NULL, FALSE, FALSE, NULL );
    boxILeaf.hEvent = CreateEvent ( NULL, FALSE, FALSE, NULL );
    boxIRR  .hEvent = CreateEvent ( NULL, FALSE, FALSE, NULL );

    int nExit = 2;
    {
        MountHub oORoot ( L"Root",          "outer", 0,         false );
        MountHub oOL    ( L"Root.L",        "outer", 0,         false );
        MountHub oOLeaf ( L"Root.L.Leaf",   "outer", &boxOLeaf, false );
        MountHub oOMid  ( L"Root.Mid",      "outer", 0,         false );
        MountHub oOGate ( L"Root.Mid.Gate", "outer", &boxOGate, false );
        MountHub oIRoot ( L"Root",          "inner", 0,         false );
        MountHub oIL    ( L"Root.L",        "inner", 0,         false );
        MountHub oILeaf ( L"Root.L.Leaf",   "inner", &boxILeaf, true  );
        MountHub oIRR   ( L"Root.Root",     "inner", &boxIRR,   false );

        MountHub *aOuter[] = { &oORoot, &oOL, &oOLeaf, &oOMid, &oOGate };
        MountHub *aInner[] = { &oIRoot, &oIL, &oILeaf, &oIRR };
        for ( MountHub *p : aOuter ) if ( !Prepare ( *p, kO, sAclO ) ) { Log ( "SETUP: outer hub" ); ScrubTempFiles ( ); return 2; }
        for ( MountHub *p : aInner ) if ( !Prepare ( *p, kI, sAclI ) ) { Log ( "SETUP: inner hub" ); ScrubTempFiles ( ); return 2; }

        std::vector<HANDLE> vThreads;
        for ( MountHub *p : aOuter ) vThreads.push_back ( p->SpawnHub ( ) );
        for ( MountHub *p : aInner ) vThreads.push_back ( p->SpawnHub ( ) );
        for ( HANDLE h : vThreads ) if ( !h ) { Log ( "SETUP: SpawnHub failed (auth not armed?)" ); ScrubTempFiles ( ); return 2; }

        // THE MOUNT, posted FIRST. The inner Root accepts the gate - whose
        // login it sees as Root:Root.Mid.Gate - and the gate dials it as
        // Root.Mid.Gate:Root.
        // NOTES: First, because the hub's route pick is the first connection
        //        that matches, in posting order. Posted after the tree links,
        //        a mount that claimed an unqualified Root.L.Leaf would always
        //        lose to the real link and the test could not see it: the
        //        mutation check of 2026-11-29 caught exactly that. A mount
        //        coming up before the tree is an ordinary deployment
        {
            P2PeerConDmx *pSvcMount = P2PeerConDmx::ServiceFactory ( L"Root:Root.Mid.Gate", L"vs-mount" );
            P2PeerConDmx *pCliMount = P2PeerConDmx::ClientFactory ( L"Root.Mid.Gate:Root", L"vs-mount" );
            if ( !pSvcMount || !pCliMount ) { Log ( "SETUP: mount factories" ); ScrubTempFiles ( ); return 2; }
            pSvcMount->SetVNetMount ( L"Root.Mid.Gate" );
            pCliMount->SetVNetMount ( L"Root" );
            oIRoot.PostP2PeerCon ( pSvcMount );
            oOGate.PostP2PeerCon ( pCliMount );
        }

        // Each parent posts a DMX service named for the child it accepts; the
        // child dials it. The DMX names are process-wide, so each network
        // gets its own: the hub names alone would collide
        auto Link = [] ( MountHub &parent, P2PaddrSTR child, MountHub &hChild, P2PaddrSTR parentAddr,
                         const wchar_t *pszDmx )
        {
            parent.PostP2PeerCon ( P2PeerConDmx::ServiceFactory ( child, pszDmx ) );
            hChild.PostP2PeerCon ( P2PeerConDmx::ClientFactory ( parentAddr, pszDmx ) );
        };
        Link ( oORoot, L"Root.L",        oOL,    L"Root",     L"vs-out-l" );
        Link ( oOL,    L"Root.L.Leaf",   oOLeaf, L"Root.L",   L"vs-out-l-leaf" );
        Link ( oORoot, L"Root.Mid",      oOMid,  L"Root",     L"vs-out-mid" );
        Link ( oOMid,  L"Root.Mid.Gate", oOGate, L"Root.Mid", L"vs-out-mid-gate" );
        Link ( oIRoot, L"Root.L",        oIL,    L"Root",     L"vs-in-l" );
        Link ( oIL,    L"Root.L.Leaf",   oILeaf, L"Root.L",   L"vs-in-l-leaf" );
        Link ( oIRoot, L"Root.Root",     oIRR,   L"Root",     L"vs-in-root" );
        Sleep ( 1500 );                       // logins, key agreements

        // ---- 1: positive control ------------------------------------------
        Log ( "--- phase 1: outer Root.L.Leaf -> Root.Mid.Gate ---" );
        oOLeaf.Send ( L"Root.Mid.Gate", L"hello" );
        const bool b1 = WaitFor ( boxOGate, "Root.L.Leaf|hello", 1, 50 );

        if ( !b1 )
        {
            std::printf ( "\nRESULT: INCONCLUSIVE - the outer tree never carried a message, so\n"
                          "  nothing below proves anything. The gate saw:\n%s", boxOGate.All ( ).c_str ( ) );
            nExit = 3;
        }
        else
        {
            // ---- 2: the same unqualified name, sent inside each network -----
            Log ( "--- phase 2: Root.L.Leaf, unqualified, sent inside each network ---" );
            oOGate.Send ( L"Root.L.Leaf", L"local-out" );
            oIRoot.Send ( L"Root.L.Leaf", L"local-in" );
            oIRoot.Send ( L"Root.Root",   L"local-rr" );   // the mount's index key
            bool b2 = WaitFor ( boxOLeaf, "Root.Mid.Gate|local-out", 1, 50 );
            b2 = WaitFor ( boxILeaf, "Root|local-in", 1, 50 ) && b2;
            const bool b2rr = WaitFor ( boxIRR, "Root|local-rr", 1, 50 );
            Sleep ( 300 );                     // time for a stray copy to land
            const bool bLeak2 = boxOLeaf.HasBody ( "local-in" ) || boxILeaf.HasBody ( "local-out" );

            // ---- 3 + 4: into the mount and back ---------------------------
            Log ( "--- phase 3: outer Root.L.Leaf -> Root.Mid.Gate:Root.L.Leaf ---" );
            oOLeaf.Send ( L"Root.Mid.Gate:Root.L.Leaf", L"ping" );
            const bool b3 = WaitFor ( boxILeaf, "Root:Root.L.Leaf|ping", 1, 80 );
            Log ( "--- phase 4: inner Root.L.Leaf replies to Root:Root.L.Leaf ---" );
            const bool b4 = WaitFor ( boxOLeaf, "Root.Mid.Gate:Root.L.Leaf|pong", 1, 80 );

            // ---- 5: a second round trip on the same links -----------------
            Log ( "--- phase 5: a second round trip ---" );
            oOLeaf.Send ( L"Root.Mid.Gate:Root.L.Leaf", L"ping" );
            const bool b5 = WaitFor ( boxOLeaf, "Root.Mid.Gate:Root.L.Leaf|pong", 2, 40 );
            Sleep ( 300 );

            //  The twin check: a ping in the outer Leaf, or a pong in the inner
            //  one, means a message reached the hub of the same name in the
            //  wrong network
            const bool bLeak = bLeak2 || boxOLeaf.HasBody ( "ping" ) || boxILeaf.HasBody ( "pong" );
            //  Exactly two pings: not one lost, not one delivered twice
            const bool bTwo  = boxILeaf.Count ( "Root:Root.L.Leaf|ping" ) == 2;

            const int nCloses = g_nCloses.load ( );
            std::printf ( "\n--- what each end saw ---\n"
                          "  outer Root.L.Leaf:\n%s  inner Root.L.Leaf:\n%s"
                          "  links closed: %d\n",
                          boxOLeaf.All ( ).c_str ( ), boxILeaf.All ( ).c_str ( ), nCloses );
            std::printf ( "  phase 2  each network's Root.L.Leaf got its own message   : %s\n", b2 ? "yes" : "NO" );
            std::printf ( "  phase 2  Root.Root got it past the mount's shared index key: %s\n", b2rr ? "yes" : "NO" );
            std::printf ( "  phase 3  into the mount, seen as Root:Root.L.Leaf          : %s\n", b3 ? "yes" : "NO" );
            std::printf ( "  phase 4  back out, seen as Root.Mid.Gate:Root.L.Leaf       : %s\n", b4 ? "yes" : "NO" );
            std::printf ( "  phase 5  a second round trip on the same links            : %s\n", b5 ? "yes" : "NO" );
            std::printf ( "  the inner Leaf got exactly the two pings sent              : %s\n", bTwo  ? "yes" : "NO" );
            std::printf ( "  no message reached the same-named hub in the other network : %s\n", bLeak ? "NO" : "yes" );

            if ( b2 && b2rr && b3 && b4 && b5 && bTwo && !bLeak && nCloses == 0 )
            {
                std::printf ( "\nRESULT: PASS - two networks with identical names were joined by a mount.\n"
                              "  Each side addressed the other only through the qualifier, no message\n"
                              "  reached the same-named hub in the wrong network, and no link closed.\n" );
                nExit = 0;
            }
            else
            {
                std::printf ( "\nRESULT: FAIL - %s\n",
                              bLeak   ? "a message reached the same-named hub in the other network"
                            : nCloses ? "a link closed (a gate refused something it should have admitted)"
                                      : "a message did not arrive with the addresses the mount should give it" );
                nExit = 1;
            }
        }

        for ( MountHub *p : aOuter ) p->CloseHub ( );
        for ( MountHub *p : aInner ) p->CloseHub ( );
        for ( HANDLE h : vThreads ) { WaitForSingleObject ( h, 5000 ); CloseHandle ( h ); }
    }

    ScrubTempFiles ( );
    CleanupP2Pmsg ( );
    CloseHandle ( boxOLeaf.hEvent );
    CloseHandle ( boxOGate.hEvent );
    CloseHandle ( boxILeaf.hEvent );
    CloseHandle ( boxIRR  .hEvent );
    return nExit;
}
