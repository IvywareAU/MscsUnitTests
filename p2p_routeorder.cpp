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
// p2p_routeorder - which connection does RouteP2PeerMsg pick?
//
// WHY: the pick is the FIRST connection, in the order they were posted, whose
// address takes the destination. The route index (MSCS p2p_performance F-P4-10)
// asks fewer connections, and must still answer that. The rest of the suite
// does not pin it: four mutants of the index - order ignored, a re-addressed
// connection never re-filed, a hub rename ignored, a dropped connection left
// in - passed all 79 other tests on 2026-11-26.
//
// HOW: one hub, no transport. Rec is a connection that never connects and
// records each message the router hands it. A Rec posted with the hub's own
// address is given its real one through the public SetP2Paddr(), the library's
// own assignment; Rename() writes m_oThatP2Paddr directly, as P2PeerWeb's
// WebConHttp does to a posted connection. Every one of those runs on the hub's
// pump, where the library makes them, so the test itself has no race (TSan).
//
// Exit codes: 0 pass, 1 fail, 2 setup, 3 inconclusive (the control failed).

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConDmx.h"
#include "P2PeerioDmx.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"

#include <cstdio>
#include <functional>
#include <mutex>
#include <string>

static std::mutex  g_mx;
static std::string g_sPicked;            // names of the Recs that were handed a message

class Rec : public P2PeerConDmx
{
public:
    Rec ( P2PaddrSTR strThat, const char *pszName ) : m_sName ( pszName )
    {
        m_oThatP2Paddr   = strThat;
        m_sServiceName   = L"p2p-routeorder-nobody";
        m_eP2PeerConMode = P2PeerCon_CLIENT;
        SetP2Peerio ( new P2PeerioDmx ( ) );
    }
    void Rename ( P2PaddrSTR strThat ) { m_oThatP2Paddr = strThat; }

    virtual bool Connect ( ) override { return true; }     // never
    virtual P2PeerMsg *PostP2PeerMsg ( P2PeerMsg *pMsg ) override
    {
        { std::lock_guard<std::mutex> g ( g_mx ); g_sPicked += m_sName; }
        delete pMsg;
        return 0;
    }

private:
    std::string m_sName;
};

class OrderHub : public P2PeerHub
{
public:
    OrderHub ( ) : P2PeerHub ( L"Rt" ) { m_hRan = CreateEvent ( NULL, FALSE, FALSE, NULL ); }
    ~OrderHub ( ) { CloseHandle ( m_hRan ); }

    //  Runs fn on the hub's pump: RouteP2PeerMsg peeks before it picks
    void Run ( std::function<void()> fn )
    {
        m_fn = fn;
        PostP2PeerMsg ( new P2PeerMsg32 ( L"Rt", L"Run.Run", P2Pmsg_BCast, L"x", (P2Psize_t)( 2 * sizeof(wchar_t) ) ) );
        if ( WaitForSingleObject ( m_hRan, 10000 ) != WAIT_OBJECT_0 )
        { std::printf ( "SETUP: the hub did not run a step\n" ); std::fflush ( stdout ); exit ( 2 ); }
    }
    virtual msgRESULT PeekP2PeerMsg ( P2PeerMsg *pMsg ) override
    {
        CString strDst = pMsg->GetDestin ( );
        if ( strDst != L"Run.Run" )
          return P2PeerHub::PeekP2PeerMsg ( pMsg );
        m_fn ( );
        SetEvent ( m_hRan );
        return msgHANDLED;
    }

private:
    std::function<void()> m_fn;
    HANDLE                m_hRan;
};

static OrderHub *g_pHub  = 0;
static int       g_nFail = 0;

static Rec *Post ( P2PaddrSTR strThat, const char *pszName )
{
    Rec *p = new Rec ( strThat, pszName );
    if ( !g_pHub->PostP2PeerCon ( p ) )
    { std::printf ( "SETUP: PostP2PeerCon(%s) refused\n", pszName ); std::fflush ( stdout ); exit ( 2 ); }
    return p;
}

//  The library's own address assignment. SetP2Paddr() also names the HUB, so
//  the hub's name is put back
static void Assign ( Rec *p, P2PaddrSTR strNew )
{
    g_pHub->Run ( [=] { p->SetP2Paddr ( strNew ); g_pHub->SetP2PaddrHub ( L"Rt" ); } );
}

static Rec *PostAssigned ( P2PaddrSTR strThat, const char *pszName )
{
    Rec *p = Post ( L"Rt", pszName );
    Assign ( p, strThat );
    return p;
}

static std::string Pick ( P2PaddrSTR strDst )
{
    { std::lock_guard<std::mutex> g ( g_mx ); g_sPicked.clear ( ); }
    g_pHub->PostP2PeerMsg ( new P2PeerMsg32 ( L"Rt", strDst, P2Pmsg_BCast, L"x", (P2Psize_t)( 2 * sizeof(wchar_t) ) ) );
    for ( int i = 0; i < 30; ++i )
    {
        Sleep ( 20 );
        std::lock_guard<std::mutex> g ( g_mx );
        if ( !g_sPicked.empty ( ) ) break;
    }
    std::lock_guard<std::mutex> g ( g_mx );
    return g_sPicked.empty ( ) ? "-" : g_sPicked;
}

static bool Expect ( const char *pszWhat, P2PaddrSTR strDst, const char *pszWant )
{
    const std::string s = Pick ( strDst );
    const bool b = s == pszWant;
    std::printf ( "%-4s %-58s want %s got %s\n", b ? "ok" : "FAIL", pszWhat, pszWant, s.c_str ( ) );
    std::fflush ( stdout );
    if ( !b ) ++g_nFail;
    return b;
}

int main ( )
{
    std::printf ( "=== p2p_routeorder - the router picks the first taker in posted order ===\n\n" );
    std::fflush ( stdout );
    if ( !StartupP2Pmsg ( 16 ) ) { std::printf ( "SETUP: StartupP2Pmsg\n" ); return 2; }

    int nExit = 0;
    {
        OrderHub oHub;
        g_pHub = &oHub;
        oHub.RequireAuth      ( false );
        oHub.RequireSeal      ( false );
        oHub.RequireRelayAuth ( false );
        HANDLE hThread = oHub.SpawnHub ( );
        if ( !hThread ) { std::printf ( "SETUP: SpawnHub\n" ); return 2; }

        PostAssigned ( L"Rt.A", "A" );
        if ( !Expect ( "control: a child takes what is below it", L"Rt.A.q", "A" ) )
        {
            nExit = 3;
        }
        else
        {
            Expect ( "a sibling's prefix is not a hop",            L"Rt.AB.q", "-" );
            Expect ( "':' is a hop boundary",                      L"Rt.A:q",  "A" );

            Post ( L"Rt.A.q", "a" );
            Expect ( "assigned first, exact match posted later",   L"Rt.A.q", "A" );

            Post ( L"Rt.B.q", "b" );
            PostAssigned ( L"Rt.B", "B" );
            Expect ( "exact match posted first, assigned later",   L"Rt.B.q", "b" );
            Expect ( "the later one still takes its other child",  L"Rt.B.z", "B" );

            Rec *pC = Post ( L"Rt.C0", "C" );
            oHub.Run ( [=] { pC->Rename ( L"Rt.C" ); } );
            Expect ( "renamed by direct write: the new address",   L"Rt.C.q",  "C" );
            Expect ( "renamed by direct write: not the old",       L"Rt.C0.q", "-" );

            Rec *pE = PostAssigned ( L"Rt.E", "E" );
            Expect ( "before a second assignment",                 L"Rt.E.q", "E" );
            oHub.Run ( [] { g_pHub->SetP2PaddrHub ( L"Rt.E" ); } );   // what SetP2Paddr requires
            Assign ( pE, L"Rt.F" );
            Expect ( "assigned again: the new address",            L"Rt.F.q", "E" );
            Expect ( "assigned again: not the old",                L"Rt.E.q", "-" );

            PostAssigned ( L"Rt.G", "G" );
            Expect ( "before the drop",                            L"Rt.G.q", "G" );
            oHub.ConSignal ( L"Rt.G", P2PsigCon_DESTROY );
            for ( int i = 0; i < 100 && oHub.ConExists ( L"Rt.G" ); ++i ) Sleep ( 20 );
            if ( oHub.ConExists ( L"Rt.G" ) )
            { std::printf ( "SETUP: the dropped connection is still listed\n" ); nExit = 2; }
            Sleep ( 300 );
            Expect ( "dropped: nothing takes it",                  L"Rt.G.q", "-" );
            PostAssigned ( L"Rt.G", "H" );
            Expect ( "its successor does",                         L"Rt.G.q", "H" );

            //  The hub becomes a grandchild of A, so A is its uplink
            oHub.Run ( [] { g_pHub->SetP2PaddrHub ( L"Rt.A.Y" ); } );
            Expect ( "hub renamed below A: A is the uplink",       L"Zz.q", "A" );
            oHub.Run ( [] { g_pHub->SetP2PaddrHub ( L"Rt" ); } );
            Expect ( "and back: A is a child again",               L"Rt.A.z", "A" );
            Expect ( "and back: no uplink",                        L"Zz.q", "-" );

            if ( g_nFail && !nExit ) nExit = 1;
        }

        oHub.CloseHub ( );
        WaitForSingleObject ( hThread, 5000 );
        CloseHandle ( hThread );
    }
    CleanupP2Pmsg ( );
    std::printf ( "\nRESULT: %s\n", nExit == 0 ? "PASS" : nExit == 3 ? "INCONCLUSIVE - the control failed"
                                             : nExit == 2 ? "SETUP" : "FAIL" );
    std::fflush ( stdout );
    return nExit;
}
