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
// p2p_vnetmount.cpp - the VNet qualifier, end to end through a MOUNT.
//
// BACKGROUND - p2p_PeerLan_L7b.md §7. `[VNetname:]Root.Hub` was documented
// grammar with no implementation (AddressingSchemas.md Blocker 3). As built:
// V:x is x inside the network MOUNTED at the hub V; ':' is a hop boundary, so
// V:x routes towards V like V.x does; and a mount is a connection that rewrites
// addresses as messages cross it (Dst H:x -> x, Src s -> P:s) and is a
// GATEWAY - it opens a body sealed into its network, drops the origin's relay
// attestation, and the far side's next hop seals and attests afresh.
//
// TWO NETWORKS IN ONE PROCESS, every link DMX, every hub with RequireAuth,
// RequireSeal and RequireRelayAuth ON - the posture a P2PeerLan tree runs:
//
//   outer (key KO)                          inner (key KI)
//     Out                                     In
//     Out.L        Out.Mid                    In.Sub
//     Out.L.Leaf   Out.Mid.Gate ====mount==== (accepted by In)
//                                             In.Sub.Svc
//
// The depth is the point. A relayed message is checked against its ORIGIN's
// attestation only when its source is outside the delivering peer's subtree,
// so the gate fires at Out.Mid.Gate (from Out.Mid, source Out.L.Leaf), at
// In.Sub.Svc (from In.Sub, source In:Out.L.Leaf) and at Out.L.Leaf (from Out.L,
// source Out.Mid.Gate:In.Sub.Svc). The last two would DROP THE LINK if the
// mount carried the origin's block across the rewrite instead of dropping it.
//
// Keys: one per network, shared by its hubs, as P2PeerLan's app hubs share an
// app's. Lines for addresses BEYOND a mount carry the keys of the hub that
// speaks for them on this side: Out.Mid.Gate:In.Sub.Svc is KO (the gate seals
// and attests for it), In:Out.L.Leaf is KI. The two mount logins are the far
// hub's own key: In:Out.Mid.Gate is KO, Out.Mid.Gate:In is KI.
//
// PHASES
//   1  POSITIVE CONTROL: Out.L.Leaf -> Out.Mid.Gate, inside the outer network.
//   2  INTO THE MOUNT: Out.L.Leaf -> Out.Mid.Gate:In.Sub.Svc. In.Sub.Svc must
//      receive the plaintext from In:Out.L.Leaf.
//   3  BACK OUT: In.Sub.Svc replies to the source it saw. Out.L.Leaf must
//      receive it from Out.Mid.Gate:In.Sub.Svc.
//   4  A VNet NOBODY MOUNTED: Out.L.Leaf -> Out.Mid:Nowhere. With sealing on
//      it never leaves the sender - there is no key for that address, so
//      SealAppMsgOutbound refuses it - and a second round trip afterwards on
//      the same links must still work.
//   Throughout: NO link closes.
//
// MUTATION-CHECKED 2026-10-14: with VNetMountOut's ClearRelayAttest() removed
// the relay gate refused the origin's block at In.Sub.Svc and at Out.L.Leaf
// ("The attesting identity is not in this hub's allow-list"), 4 links closed,
// phases 2 and 3 failed. So the depth above is doing its job.
//
// VERDICT = process EXIT CODE:
//   0  PASS   2 and 3 delivered with the right addresses, no link closed
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
    std::printf ( "[vnetmount] %s\n", msg );
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

struct Inbox;
static int CountOf ( Inbox &box, const std::string &s );

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
    bool Has ( const std::string &s )
    {
        std::lock_guard<std::mutex> g ( mx );
        for ( const std::string &l : lines ) if ( l == s ) return true;
        return false;
    }
    std::string All ( )
    {
        std::lock_guard<std::mutex> g ( mx );
        std::string o;
        for ( const std::string &l : lines ) o += "  " + l + "\n";
        return o.empty ( ) ? "  (nothing)\n" : o;
    }
};

static int CountOf ( Inbox &box, const std::string &s )
{
    std::lock_guard<std::mutex> g ( box.mx );
    int n = 0;
    for ( const std::string &l : box.lines ) if ( l == s ) ++n;
    return n;
}

// =========================================================================
class MountHub : public P2PeerHub
{
public:
    MountHub ( P2PaddrSTR strAddr, Inbox *pInbox, bool bEcho )
        : P2PeerHub ( strAddr ), m_pInbox ( pInbox ), m_bEcho ( bEcho )
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
        std::printf ( "[vnetmount] %s received '%s' from %s\n",
                      N ( m_strSelf ).c_str ( ), sBody.c_str ( ), sSrc.c_str ( ) );
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
        std::printf ( "[vnetmount] %s: LINK CLOSED (%s)\n", N ( m_strSelf ).c_str ( ),
                      pCon ? N ( pCon->GetP2Paddress ( ).c_wstr ( ) ).c_str ( ) : "?" );
        std::fflush ( stdout );
        return P2PeerHub::On_ConClose ( pCon );
    }

private:
    Inbox  *m_pInbox;
    bool    m_bEcho;
    CString m_strSelf;
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
    s += "p2p_vnetmount_"; s += pszLeaf; s += "_"; s += szPid; s += ".tmp";
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
    std::printf ( "=== p2p_vnetmount - V:x through a VNet mount, auth + seal + relay auth on ===\n\n" );
    std::fflush ( stdout );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }

    Keys kO, kI;
    const std::string sAclO = TempPath ( "acl_out" );
    const std::string sAclI = TempPath ( "acl_in" );
    if ( !MakeKeys ( "out", kO ) || !MakeKeys ( "in", kI ) ||
         // the outer network, and what lies beyond its mount
         !Line ( sAclO, "Out", kO ) || !Line ( sAclO, "Out.L", kO ) || !Line ( sAclO, "Out.L.Leaf", kO ) ||
         !Line ( sAclO, "Out.Mid", kO ) || !Line ( sAclO, "Out.Mid.Gate", kO ) ||
         !Line ( sAclO, "Out.Mid.Gate:In", kI ) ||                // the mount's login ack
         !Line ( sAclO, "Out.Mid.Gate:In.Sub.Svc", kO ) ||        // spoken for by the gate
         // the inner network, and what lies beyond ITS mount
         !Line ( sAclI, "In", kI ) || !Line ( sAclI, "In.Sub", kI ) || !Line ( sAclI, "In.Sub.Svc", kI ) ||
         !Line ( sAclI, "In:Out.Mid.Gate", kO ) ||                // the mount's login
         !Line ( sAclI, "In:Out.L.Leaf", kI ) )                   // spoken for by In
    { Log ( "SETUP: provisioning failed" ); ScrubTempFiles ( ); return 2; }

    Inbox inLeaf, inGate, inSvc;
    inLeaf.hEvent = CreateEvent ( NULL, FALSE, FALSE, NULL );
    inGate.hEvent = CreateEvent ( NULL, FALSE, FALSE, NULL );
    inSvc .hEvent = CreateEvent ( NULL, FALSE, FALSE, NULL );

    int nExit = 2;
    {
        MountHub oOut   ( L"Out",          0,       false );
        MountHub oL     ( L"Out.L",        0,       false );
        MountHub oLeaf  ( L"Out.L.Leaf",   &inLeaf, false );
        MountHub oMid   ( L"Out.Mid",      0,       false );
        MountHub oGate  ( L"Out.Mid.Gate", &inGate, false );
        MountHub oIn    ( L"In",           0,       false );
        MountHub oSub   ( L"In.Sub",       0,       false );
        MountHub oSvc   ( L"In.Sub.Svc",   &inSvc,  true  );

        MountHub *aOuter[] = { &oOut, &oL, &oLeaf, &oMid, &oGate };
        MountHub *aInner[] = { &oIn, &oSub, &oSvc };
        for ( MountHub *p : aOuter ) if ( !Prepare ( *p, kO, sAclO ) ) { Log ( "SETUP: outer hub" ); ScrubTempFiles ( ); return 2; }
        for ( MountHub *p : aInner ) if ( !Prepare ( *p, kI, sAclI ) ) { Log ( "SETUP: inner hub" ); ScrubTempFiles ( ); return 2; }

        std::vector<HANDLE> vThreads;
        for ( MountHub *p : aOuter ) vThreads.push_back ( p->SpawnHub ( ) );
        for ( MountHub *p : aInner ) vThreads.push_back ( p->SpawnHub ( ) );
        for ( HANDLE h : vThreads ) if ( !h ) { Log ( "SETUP: SpawnHub failed (auth not armed?)" ); ScrubTempFiles ( ); return 2; }

        // Each parent posts a DMX service named for the child it accepts;
        // the child dials it (P2PeerConDmx::Connect retries until it exists)
        auto Link = [] ( MountHub &parent, P2PaddrSTR child, MountHub &hChild, P2PaddrSTR parentAddr,
                         const wchar_t *pszDmx )
        {
            parent.PostP2PeerCon ( P2PeerConDmx::ServiceFactory ( child, pszDmx ) );
            hChild.PostP2PeerCon ( P2PeerConDmx::ClientFactory ( parentAddr, pszDmx ) );
        };
        Link ( oOut, L"Out.L",        oL,    L"Out",     L"vm-out-l" );
        Link ( oL,   L"Out.L.Leaf",   oLeaf, L"Out.L",   L"vm-out-l-leaf" );
        Link ( oOut, L"Out.Mid",      oMid,  L"Out",     L"vm-out-mid" );
        Link ( oMid, L"Out.Mid.Gate", oGate, L"Out.Mid", L"vm-out-mid-gate" );
        Link ( oIn,  L"In.Sub",       oSub,  L"In",      L"vm-in-sub" );
        Link ( oSub, L"In.Sub.Svc",   oSvc,  L"In.Sub",  L"vm-in-sub-svc" );

        // THE MOUNT. In accepts the gate - whose login it will see as
        // In:Out.Mid.Gate - and the gate dials In as Out.Mid.Gate:In
        {
            P2PeerConDmx *pSvcMount = P2PeerConDmx::ServiceFactory ( L"In:Out.Mid.Gate", L"vm-mount" );
            P2PeerConDmx *pCliMount = P2PeerConDmx::ClientFactory ( L"Out.Mid.Gate:In", L"vm-mount" );
            if ( !pSvcMount || !pCliMount ) { Log ( "SETUP: mount factories" ); ScrubTempFiles ( ); return 2; }
            pSvcMount->SetVNetMount ( L"Out.Mid.Gate" );
            pCliMount->SetVNetMount ( L"In" );
            oIn  .PostP2PeerCon ( pSvcMount );
            oGate.PostP2PeerCon ( pCliMount );
        }
        Sleep ( 1500 );                       // logins, key agreements

        // ---- 1: positive control ------------------------------------------
        Log ( "--- phase 1: Out.L.Leaf -> Out.Mid.Gate (inside the outer network) ---" );
        oLeaf.Send ( L"Out.Mid.Gate", L"hello" );
        bool b1 = false;
        for ( int i = 0; i < 50 && !( b1 = inGate.Has ( "Out.L.Leaf|hello" ) ); ++i ) WaitForSingleObject ( inGate.hEvent, 100 );

        if ( !b1 )
        {
            std::printf ( "\nRESULT: INCONCLUSIVE - the outer tree never carried a message, so\n"
                          "  nothing below proves anything. Gate saw:\n%s", inGate.All ( ).c_str ( ) );
            nExit = 3;
        }
        else
        {
            // ---- 2 + 3: into the mount and back ----------------------------
            Log ( "--- phase 2: Out.L.Leaf -> Out.Mid.Gate:In.Sub.Svc ---" );
            oLeaf.Send ( L"Out.Mid.Gate:In.Sub.Svc", L"ping" );
            bool b2 = false, b3 = false;
            for ( int i = 0; i < 80 && !( b2 = inSvc.Has ( "In:Out.L.Leaf|ping" ) ); ++i ) WaitForSingleObject ( inSvc.hEvent, 100 );
            Log ( "--- phase 3: In.Sub.Svc replies to In:Out.L.Leaf ---" );
            for ( int i = 0; i < 80 && !( b3 = inLeaf.Has ( "Out.Mid.Gate:In.Sub.Svc|pong" ) ); ++i ) WaitForSingleObject ( inLeaf.hEvent, 100 );

            // ---- 4: a VNet nobody mounted ----------------------------------
            Log ( "--- phase 4: Out.L.Leaf -> Out.Mid:Nowhere (no mount, no key: refused at the sender) ---" );
            oLeaf.Send ( L"Out.Mid:Nowhere", L"lost" );
            Sleep ( 800 );

            // ---- and a second round trip, after phase 4, on the same links --
            oLeaf.Send ( L"Out.Mid.Gate:In.Sub.Svc", L"ping" );
            for ( int i = 0; i < 40 && CountOf ( inLeaf, "Out.Mid.Gate:In.Sub.Svc|pong" ) < 2; ++i )
                WaitForSingleObject ( inLeaf.hEvent, 100 );
            const bool b5 = CountOf ( inLeaf, "Out.Mid.Gate:In.Sub.Svc|pong" ) >= 2;

            const int nCloses = g_nCloses.load ( );
            std::printf ( "\n--- what each end saw ---\n"
                          "In.Sub.Svc:\n%sOut.L.Leaf:\n%s"
                          "  links closed: %d\n",
                          inSvc.All ( ).c_str ( ), inLeaf.All ( ).c_str ( ), nCloses );
            std::printf ( "  phase 2  into the mount, seen as In:Out.L.Leaf      : %s\n", b2 ? "yes" : "NO" );
            std::printf ( "  phase 3  back out, seen as Out.Mid.Gate:In.Sub.Svc  : %s\n", b3 ? "yes" : "NO" );
            std::printf ( "  after 4  a second round trip on the same links     : %s\n", b5 ? "yes" : "NO" );

            if ( b2 && b3 && b5 && nCloses == 0 )
            {
                std::printf ( "\nRESULT: PASS - V:x crossed a mount both ways with auth, seal and relay\n"
                              "  attestation on in both networks, each side saw the other's addresses in\n"
                              "  its own terms, and no link closed.\n" );
                nExit = 0;
            }
            else
            {
                std::printf ( "\nRESULT: FAIL - %s\n",
                              nCloses ? "a link closed (a gate refused something it should have admitted)"
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
    CloseHandle ( inLeaf.hEvent );
    CloseHandle ( inGate.hEvent );
    CloseHandle ( inSvc .hEvent );
    return nExit;
}
