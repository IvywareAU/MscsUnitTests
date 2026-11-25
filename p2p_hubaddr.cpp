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
// p2p_hubaddr - does the process know exactly which hubs it holds?
//
// WHY: IsP2PmsgHubInProcess() and IsP2PmsgHubSealWaivedInProcess() decide
// whether a body may go unsealed and whether it may leave the process. They
// answer from an index of hub addresses (MSCS p2p_performance F-P4-11), which
// must follow a hub being created, re-addressed, sharing its address with
// another hub, and destroyed. A missing entry is as wrong as a stale one.
//
// Exit codes: 0 pass, 1 fail, 2 setup.

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"

#include <cstdio>
#include <functional>
#include <memory>

class AddrHub : public P2PeerHub
{
public:
    AddrHub ( P2PaddrSTR strAddr, bool bSeal ) : P2PeerHub ( strAddr )
    {
        m_hRan = CreateEvent ( NULL, FALSE, FALSE, NULL );
        RequireAuth       ( false );
        RequireSeal       ( bSeal );
        RequireRelayAuth  ( false );
        RequireRevocation ( false );
        m_hThread = SpawnHub ( );
        if ( !m_hThread ) { std::printf ( "SETUP: SpawnHub\n" ); std::fflush ( stdout ); exit ( 2 ); }
        Run ( [] { } );                              // its pump is up
    }
    void Close ( )
    {
        if ( !m_hThread ) return;
        CloseHub ( );
        if ( WaitForSingleObject ( m_hThread, 10000 ) != WAIT_OBJECT_0 )
        { std::printf ( "SETUP: a hub did not close\n" ); std::fflush ( stdout ); exit ( 2 ); }
        CloseHandle ( m_hThread );
        m_hThread = 0;
    }
    ~AddrHub ( ) { Close ( ); CloseHandle ( m_hRan ); }

    void Rename ( P2PaddrSTR strNew ) { Run ( [=] { SetP2PaddrHub ( strNew ); } ); }

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
    void Run ( std::function<void()> fn )             // on this hub's pump
    {
        m_fn = fn;
        PostP2PeerMsg ( new P2PeerMsg32 ( L"Ha", L"Run.Run", P2Pmsg_BCast, L"x", (P2Psize_t)( 2 * sizeof(wchar_t) ) ) );
        if ( WaitForSingleObject ( m_hRan, 10000 ) != WAIT_OBJECT_0 )
        { std::printf ( "SETUP: a hub did not run a step\n" ); std::fflush ( stdout ); exit ( 2 ); }
    }
    std::function<void()> m_fn;
    HANDLE                m_hRan, m_hThread;
};

static int g_nFail = 0;

static void Is ( const char *pszWhat, P2PaddrSTR strAddr, bool bIn, bool bWaived )
{
    const bool b1 = IsP2PmsgHubInProcess ( strAddr ) != FALSE;
    const bool b2 = IsP2PmsgHubSealWaivedInProcess ( strAddr ) != FALSE;
    const bool b  = b1 == bIn && b2 == bWaived;
    std::printf ( "%-4s %-52s want %d/%d got %d/%d\n", b ? "ok" : "FAIL", pszWhat, bIn, bWaived, b1, b2 );
    std::fflush ( stdout );
    if ( !b ) ++g_nFail;
}

int main ( )
{
    std::printf ( "=== p2p_hubaddr - in process / seal-waived, by hub address ===\n\n" );
    std::fflush ( stdout );
    if ( !StartupP2Pmsg ( 64 ) ) { std::printf ( "SETUP: StartupP2Pmsg\n" ); return 2; }
    {
        Is ( "nothing yet",                         L"Ha.A", false, false );
        Is ( "empty",                               L"",     false, false );
        Is ( "null",                                NULL,    false, false );

        std::unique_ptr<AddrHub> pA ( new AddrHub ( L"Ha.A", false ) );
        std::unique_ptr<AddrHub> pS ( new AddrHub ( L"Ha.S", true ) );
        Is ( "a plain hub",                         L"Ha.A", true,  false );
        Is ( "a sealing hub",                       L"Ha.S", true,  true );
        Is ( "below it",                            L"Ha.S.x", false, false );
        Is ( "its prefix",                          L"Ha",   false, false );
        Is ( "its case",                            L"ha.s", false, false );
        Is ( "still not a wildcard",                L"",     false, false );

        pS->Rename ( L"Ha.T" );
        Is ( "re-addressed: the new address",       L"Ha.T", true,  true );
        Is ( "re-addressed: not the old",           L"Ha.S", false, false );
        pS->Rename ( L"Ha.T" );
        Is ( "re-addressed to the same",            L"Ha.T", true,  true );
        pS->Rename ( L"Ha.S" );
        Is ( "and back",                            L"Ha.S", true,  true );
        Is ( "and back: not the other",             L"Ha.T", false, false );

        //  Two hubs, one address
        {
            std::unique_ptr<AddrHub> pS2 ( new AddrHub ( L"Ha.S2", true ) );
            pS2->Rename ( L"Ha.S" );
            Is ( "two hubs share it",               L"Ha.S",  true,  true );
            pS2->Rename ( L"Ha.S3" );
            Is ( "one moved away: the other stays", L"Ha.S",  true,  true );
            Is ( "one moved away: it is found",     L"Ha.S3", true,  true );
            pS2->Rename ( L"Ha.S" );
            pS2->Close ( );
        }
        Is ( "one of two destroyed: the other stays", L"Ha.S", true, true );
        {
            AddrHub oS4 ( L"Ha.S", true );
            pS->Close ( );
            pS.reset ( );
            Is ( "the FIRST of two destroyed",      L"Ha.S",  true,  true );
        }
        Is ( "both destroyed",                      L"Ha.S",  false, false );

        //  Two hubs, one address, DIFFERENT policies.  Which one answers is the
        //  registry's order (thread IDs), so no answer can be written down here;
        //  but a rename does not touch the registry, so moving either hub away
        //  and back must not change it.  An index that answered by its own
        //  filing order would
        {
            AddrHub oP ( L"Ha.D", true ), oQ ( L"Ha.D", false );
            const bool bWaived = IsP2PmsgHubSealWaivedInProcess ( L"Ha.D" ) != FALSE;
            Is ( "two policies share it",           L"Ha.D",  true,  bWaived );
            oP.Rename ( L"Ha.D2" );
            Is ( "the sealing one away",            L"Ha.D",  true,  false );
            oP.Rename ( L"Ha.D" );
            Is ( "the sealing one back: no change", L"Ha.D",  true,  bWaived );
            oQ.Rename ( L"Ha.D2" );
            Is ( "the plain one away",              L"Ha.D",  true,  true );
            oQ.Rename ( L"Ha.D" );
            Is ( "the plain one back: no change",   L"Ha.D",  true,  bWaived );
        }
        Is ( "two policies: both destroyed",        L"Ha.D",  false, false );

        //  Many: the index must agree with the registry at any size
        {
            std::unique_ptr<AddrHub> ap[24];
            wchar_t sz[32];
            bool b = true;
            for ( int i = 0; i < 24; ++i )
            { swprintf ( sz, 32, L"Ha.M%02d", i ); ap[i].reset ( new AddrHub ( sz, i % 2 != 0 ) ); }
            for ( int i = 0; i < 24; i += 3 ) ap[i].reset ( );
            for ( int i = 0; i < 24; ++i )
            {
                swprintf ( sz, 32, L"Ha.M%02d", i );
                b = b && ( IsP2PmsgHubInProcess ( sz ) != FALSE ) == ( i % 3 != 0 )
                      && ( IsP2PmsgHubSealWaivedInProcess ( sz ) != FALSE ) == ( i % 3 != 0 && i % 2 != 0 );
            }
            std::printf ( "%-4s 24 hubs, every third destroyed\n", b ? "ok" : "FAIL" );
            if ( !b ) ++g_nFail;
        }
        Is ( "the plain hub was not disturbed",     L"Ha.A", true, false );
        pA->Rename ( L"Ha.A2" );
        pA.reset ( );
        Is ( "destroyed after a rename: the old",   L"Ha.A",  false, false );
        Is ( "destroyed after a rename: the new",   L"Ha.A2", false, false );
    }
    CleanupP2Pmsg ( );
    std::printf ( "\nRESULT: %s\n", g_nFail ? "FAIL" : "PASS" );
    std::fflush ( stdout );
    return g_nFail ? 1 : 0;
}
