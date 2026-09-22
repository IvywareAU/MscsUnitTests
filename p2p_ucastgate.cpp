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
// p2p_ucastgate.cpp — the upcast relay, and the bound nothing could measure.
//
// BACKGROUND — a test that could not be written, and why it can be now.
//
//   P2PeerHub::On_P2PeerUCast is the mirror of On_P2PeerBCast: a copy per
//   link, re-addressed to that link's own peer, gated on a per-connection
//   opt-in bit. Until 2026-09-22 it was DEAD CODE with live-looking
//   dependants. There was no P2Pmsg_UCast message ID anywhere in the tree, no
//   entry for one in P2PeerHub's message map and no other caller of the
//   virtual, so nothing could reach it — while ConState_UCasts and
//   ConUCasts_OK were declared, three applications set the bit believing it
//   routed something, and nine harnesses in this suite overrode the handler as
//   though it fired, one of them (p2p_authgate.cpp:153) treating a call to it
//   as a BREACH.
//
//   The gate inside it was also wrong, and the two facts are related. It read
//
//       if ( !oP2PaddrCon.IsChild(m_oP2PaddrHub) ||
//            !pCon->GetState(ConUCasts_OK)         )
//
//   GetState returns m_dwState & dwMask, so testing it as a bool admits a
//   connection carrying ANY ONE of the three bits — and ConState_Send is set on
//   every accepted and every connected connection there is. The bound was a
//   three-bit mask that bound on nothing. It was the only place in the library
//   that tested state with the masked accessor; On_P2PeerBCast four lines of
//   intent away has always used HasState, which is all-or-nothing.
//
//   THE FIX WENT IN UNGATED ON 2026-09-22 AND SAID SO. A test that offers an
//   upcast to a connection lacking ConState_UCasts could not be written,
//   because no test could offer an upcast to anything. The register recorded
//   the correction as carried by the compiler and the comment, counted it
//   among the UNGATED rows, and left the real decision open: delete the relay,
//   or wire it up and write this test in the same change. This file is the
//   second half of that decision.
//
// WHAT IT ASKS — three questions, and two of them are about the loop's
// predicate rather than about traffic.
//
//        Uc                    (top / root)
//         |
//        Uc.Mid                (middle)
//         |
//        Uc.Mid.Leaf           (origin)
//
//   An upcast is posted by a hub TO ITSELF, which is what drives the fan-out —
//   the same shape as a tree broadcast (p2p_sealbcast phase 3) and for the same
//   reason: a message addressed elsewhere is routed by address and never
//   reaches the handler. Each parent receives the copy addressed to itself,
//   delivers it locally, and the base handler fans it out again, so an upcast
//   climbs to the root and EVERY ANCESTOR ON THE WAY RECEIVES IT. That is
//   worth stating because the first guess is that an upcast is a unicast that
//   knows its way; it is not, it is an audience, and the whole of
//   RequireSealUpcast follows from it.
//
//   Phase 1 (CONTROL — the path works at all) — the leaf upcasts, and BOTH the
//     middle and the top must receive it. This is the control p2p_dmxcap's
//     header argues for and the one the previous exit criterion here was
//     missing: without it phase 2 measures an empty loop and passes for the
//     wrong reason. It also reads TMsg_Ups off the copy that reached the top
//     and requires it to name the LEAF — the origin's address survived two
//     re-addressings, which is the whole reason the field exists.
//
//   Phase 2 (THE GATE — the bound that could not be measured) — ConState_UCasts
//     is cleared on the middle's connection to the top, and nothing else
//     changes. The upcast must reach the middle and must NOT reach the top.
//
//     MEASURED RED 2026-09-22 against the GetState form of the line: the
//     middle's connection to the top still carries ConState_Send and
//     ConState_Login after the clear, so GetState(ConUCasts_OK) is non-zero,
//     the connection is selected, and the top receives an upcast it was not
//     entitled to. Phase 1 stays green in that run, which is what makes the
//     pair a measurement rather than a pair of assertions.
//
//   Phase 3 (DIRECTION — the predicate is the other half of the line) — the
//     middle upcasts. The top must receive it and the LEAF must not. The gate
//     is two tests joined by ||, and phase 2 only exercises one of them; a
//     relay that had the state bit right and enumerated every connection would
//     pass phase 2 and flood the tree.
//
// WHAT IT DOES NOT ASK. Sealing. These hubs run RequireSeal(false), like every
// other socket test here, and the reason is not local convenience this time:
// an upcast on a sealing hub is REFUSED, by design, because a chain of
// ancestors is no more sealable than a subtree — so a routing test that left
// sealing on would measure the refusal and never reach the gate. That refusal,
// and the RequireSealUpcast switch that records a deployment choosing
// otherwise, are p2p_sealbcast phase 6.
//
// Verdict = process EXIT CODE:  0 SUCCESS | 1 SETUP | 2 FAILED | 3 TIMEOUT
// Exit 3 is NOT a pass and ctest reads it as a failure.

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConWsa.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>

// --- narrow-print helper (portable; no wide stdio) -------------------------
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
static void Log ( const char *msg )
{
    std::printf ( "[ucastgate] %s\n", msg );
    std::fflush ( stdout );
}

// -------------------------------------------------------------------------
static const P2PaddrSTR kTopAddr  = L"Uc";
static const P2PaddrSTR kMidAddr  = L"Uc.Mid";
static const P2PaddrSTR kLeafAddr = L"Uc.Mid.Leaf";

//  One tag per phase, so a body that arrives late cannot be counted against
//  the phase that follows it. Distinct in their first bytes, which is all the
//  matcher reads.
static const char kTagControl[] = "UCAST-phase1-control-41927";
static const char kTagGated  [] = "UCAST-phase2-gated-58314";
static const char kTagDown   [] = "UCAST-phase3-downward-70663";

enum Phase { PhControl = 0, PhGated = 1, PhDown = 2, PhCount = 3 };

//  Who saw what. Written on hub threads, read by main after a wait, which is
//  the same discipline every other test here uses for a flag that is set once
//  and never cleared.
static volatile bool g_abTopSaw  [PhCount] = { false, false, false };
static volatile bool g_abMidSaw  [PhCount] = { false, false, false };
static volatile bool g_abLeafSaw [PhCount] = { false, false, false };

//  The upcast scope the TOP read off the phase 1 copy, captured on the hub
//  thread because the message does not outlive the handler.
static std::string   g_sTopScopeSeen;

static HANDLE g_hTopControl = NULL;   // phase 1 reached the top
static HANDLE g_hMidControl = NULL;   // phase 1 reached the middle
static HANDLE g_hMidGated   = NULL;   // phase 2 reached the middle
static HANDLE g_hTopDown    = NULL;   // phase 3 reached the top
static HANDLE g_hMidUp      = NULL;   // the middle logged in to the top
static HANDLE g_hLeafUp     = NULL;   // the leaf logged in to the middle

// -------------------------------------------------------------------------
static bool Contains ( const void *pv, size_t cb, const char *pszTag )
{
    const size_t cbTag = std::strlen ( pszTag );
    if ( !pv || cb < cbTag )
      return false;
    const char *p = (const char *)pv;
    for ( size_t i = 0; i + cbTag <= cb; ++i )
      if ( std::memcmp ( p + i, pszTag, cbTag ) == 0 )
        return true;
    return false;
}

static int PhaseOf ( const void *pv, size_t cb )
{
    if ( Contains ( pv, cb, kTagControl ) ) return PhControl;
    if ( Contains ( pv, cb, kTagGated   ) ) return PhGated;
    if ( Contains ( pv, cb, kTagDown    ) ) return PhDown;
    return -1;
}

// =========================================================================
class UCastHub : public P2PeerHub
{
public:
    enum Role { RoleTop, RoleMid, RoleLeaf };

    UCastHub ( P2PaddrSTR strAddr, Role eRole )
        : P2PeerHub ( strAddr ), m_eRole ( eRole ) {}
    virtual ~UCastHub ( ) {}

    void Upcast ( const char *pszTag )
    {
        //  ADDRESSED TO ITSELF, which is what reaches the handler. A message
        //  addressed anywhere else is routed by address and the relay never
        //  sees it - the same shape as a tree broadcast, and the reason
        //  p2p_sealbcast phase 3 posts kTopAddr -> kTopAddr.
        const P2PaddrSTR strSelf = GetP2PaddrHub ( ).c_wstr ( );
        PostP2PeerMsg ( new P2PeerMsg32 ( strSelf, strSelf, P2Pmsg_UCast,
                                          pszTag,
                                          (P2Psize_t)( std::strlen ( pszTag ) + 1 ) ) );
    }

protected:
    //  MUST DELEGATE. The base handler IS the relay; a derived hub that
    //  returns without calling it observes the message and stops the fan-out,
    //  which is the same contract FacadeHub::On_P2PeerUCast records.
    virtual msgRESULT On_P2PeerUCast ( P2PeerMsg *pMsg ) override
    {
        if ( pMsg && pMsg->Data ( ) )
        {
            const int nPhase = PhaseOf ( pMsg->Data ( ),
                                         (size_t)pMsg->DataSize ( ) );
            if ( nPhase >= 0 )
            {
                std::printf ( "[ucastgate] %s received the phase %d upcast"
                              " (Dst='%s' Ups='%s')\n",
                              RoleName ( ), nPhase + 1,
                              N ( pMsg->GetDestin  ( ) ).c_str ( ),
                              N ( pMsg->GetUpScope ( ) ).c_str ( ) );
                std::fflush ( stdout );
                Record ( nPhase, pMsg );
            }
        }
        return P2PeerHub::On_P2PeerUCast ( pMsg );
    }

    //  Both relay bits, on both sides of the handshake, and the line is not
    //  boilerplate. NOTHING IN THE LIBRARY SETS EITHER on an ordinary
    //  connection - they say what an application has decided a link may carry,
    //  not what it is capable of - so without this the relay enumerates the
    //  connections, matches none, and every phase here measures an empty loop
    //  and passes. p2p_sealbcast carries the same note at the same line.
    virtual conRESULT On_ConLogin ( P2PeerCon *pCon, P2PaddrSTR strThatP2Paddr,
                                    const void *pvLoginMsg, P2Psize_t iSize ) override
    {
        if ( pCon )
            pCon -> SetState ( ConState_BCasts | ConState_UCasts, 0 );
        std::printf ( "[ucastgate] %s: login FROM '%s'\n", RoleName ( ),
                      N ( strThatP2Paddr ).c_str ( ) );
        std::fflush ( stdout );

        if ( strThatP2Paddr )
        {
            if      ( wcscmp ( strThatP2Paddr, kMidAddr  ) == 0 )
            { if ( g_hMidUp  ) SetEvent ( g_hMidUp  ); }
            else if ( wcscmp ( strThatP2Paddr, kLeafAddr ) == 0 )
            { if ( g_hLeafUp ) SetEvent ( g_hLeafUp ); }
        }
        return P2PeerHub::On_ConLogin ( pCon, strThatP2Paddr, pvLoginMsg, iSize );
    }

    virtual conRESULT On_ConLoginAck ( P2PeerCon *pCon, P2PaddrSTR strThisP2Paddr,
                                       P2PaddrSTR strThatP2Paddr,
                                       const void *pvLoginAck, P2Psize_t iSize ) override
    {
        if ( pCon )
            pCon -> SetState ( ConState_BCasts | ConState_UCasts, 0 );
        return P2PeerHub::On_ConLoginAck ( pCon, strThisP2Paddr, strThatP2Paddr,
                                           pvLoginAck, iSize );
    }

    virtual conRESULT On_ConClose ( P2PeerCon *pCon ) override
    {
        std::printf ( "[ucastgate] %s: connection to '%s' CLOSED\n", RoleName ( ),
                      pCon ? N ( pCon->GetP2Paddress ( ).c_wstr ( ) ).c_str ( ) : "?" );
        std::fflush ( stdout );
        return P2PeerHub::On_ConClose ( pCon );
    }

private:
    void Record ( int nPhase, P2PeerMsg *pMsg )
    {
        switch ( m_eRole )
        {
          case RoleTop:
            g_abTopSaw[nPhase] = true;
            if ( nPhase == PhControl )
            {
              g_sTopScopeSeen = N ( pMsg->GetUpScope ( ) );
              if ( g_hTopControl ) SetEvent ( g_hTopControl );
            }
            if ( nPhase == PhDown && g_hTopDown ) SetEvent ( g_hTopDown );
            break;
          case RoleMid:
            g_abMidSaw[nPhase] = true;
            if ( nPhase == PhControl && g_hMidControl ) SetEvent ( g_hMidControl );
            if ( nPhase == PhGated   && g_hMidGated   ) SetEvent ( g_hMidGated   );
            break;
          case RoleLeaf:
            g_abLeafSaw[nPhase] = true;
            break;
        }
    }

    const char *RoleName ( ) const
    {
        return m_eRole == RoleTop ? "TOP"
             : m_eRole == RoleMid ? "MID" : "LEAF";
    }

    Role m_eRole;
};

// =========================================================================
//  Waits until one hub's connection to one peer carries the whole of
//  ConUCasts_OK.
//  NOTES: NOT A SLEEP, and the difference matters. The login events this test
//         waits on are signalled on the SERVER side of each handshake - the
//         middle reports the leaf's login - and the client's own connection
//         does not carry ConState_Login until its ACK has come back and
//         On_ConLoginAck has run. Posting the moment the server says "logged
//         in" therefore raced the client's own state, the relay enumerated a
//         connection that was one bit short, skipped it, and phase 1 failed
//         reporting that the upcast never left the leaf. Measured 2026-09-22
//         on the first run of this file
//       : The precondition is printed either way. A phase that starts without
//         it is a phase whose result means something else, and the whole point
//         of the control is that a skipped connection and a gated one must not
//         look alike
static bool WaitForUCastReady ( P2PeerHub &oHub, P2PaddrSTR strPeer,
                                const char *pszWho, DWORD dwMillis )
{
    const DWORD dwStep = 100;
    for ( DWORD dwWaited = 0; ; dwWaited += dwStep )
    {
        SafeP2PeerCon oSafeCon;
        if ( oHub.ConQuery ( strPeer, oSafeCon ) && (P2PeerCon *)oSafeCon != 0 )
        {
            P2PeerCon *pCon = (P2PeerCon *)oSafeCon;
            if ( pCon -> HasState ( ConUCasts_OK ) )
            {
                std::printf ( "[ucastgate] %s -> '%s' is upcast-ready"
                              " (waited %ums)\n",
                              pszWho, N ( strPeer ).c_str ( ),
                              (unsigned)dwWaited );
                std::fflush ( stdout );
                return true;
            }
        }
        if ( dwWaited >= dwMillis )
          break;
        Sleep ( dwStep );
    }
    std::printf ( "[ucastgate] %s -> '%s' never became upcast-ready\n",
                  pszWho, N ( strPeer ).c_str ( ) );
    std::fflush ( stdout );
    return false;
}

// =========================================================================
//  Clears ConState_UCasts on one hub's connection to one peer.
//  NOTES: Read back and reported rather than assumed. The bit is what phase 2
//         turns on, so a SetState that silently did nothing would make the
//         phase pass by measuring the wrong thing - the failure mode this
//         whole file exists to stop.
static bool ClearUCastBit ( P2PeerHub &oHub, P2PaddrSTR strPeer, bool bClear )
{
    SafeP2PeerCon oSafeCon;
    if ( !oHub.ConQuery ( strPeer, oSafeCon ) || (P2PeerCon *)oSafeCon == 0 )
      return false;
    P2PeerCon *pCon = (P2PeerCon *)oSafeCon;
    if ( bClear ) pCon -> SetState ( 0, ConState_UCasts );
    else          pCon -> SetState ( ConState_UCasts, 0 );

    const bool bHas = pCon -> HasState ( ConState_UCasts ) ? true : false;
    std::printf ( "[ucastgate] connection to '%s': ConState_UCasts now %s"
                  " (Send=%s Login=%s)\n",
                  N ( strPeer ).c_str ( ), bHas ? "SET" : "CLEAR",
                  pCon->HasState ( ConState_Send  ) ? "1" : "0",
                  pCon->HasState ( ConState_Login ) ? "1" : "0" );
    std::fflush ( stdout );
    return bHas == !bClear;
}

// =========================================================================
int main ( int argc, char *argv[] )
{
    const short nPort = ( argc >= 2 ) ? (short)atoi ( argv[1] ) : 7860;

    std::printf ( "=== p2p_ucastgate - the upcast relay and its opt-in bound ===\n" );
    std::printf ( "Ports : %d (top listens), %d (middle listens)\n",
                  (int)nPort, (int)( nPort + 1 ) );
    std::printf ( "Tree  : %s <- %s <- %s, auth OFF, sealing OFF.\n\n",
                  N ( kTopAddr ).c_str ( ), N ( kMidAddr ).c_str ( ),
                  N ( kLeafAddr ).c_str ( ) );
    std::fflush ( stdout );

    g_hTopControl = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hMidControl = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hMidGated   = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hTopDown    = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hMidUp      = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hLeafUp     = CreateEvent ( NULL, FALSE, FALSE, NULL );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 1; }
    WSADATA oWsaData;
    WSAStartup ( MAKEWORD ( 2, 2 ), &oWsaData );

    //  Sealing OFF on all three, and for a reason that is not local
    //  convenience: an upcast on a sealing hub is refused by design - refer
    //  the header, and p2p_sealbcast phase 6 for the measurement. Leaving it
    //  on here would measure that refusal and never reach the gate.
    UCastHub oTop  ( kTopAddr,  UCastHub::RoleTop  );
    UCastHub oMid  ( kMidAddr,  UCastHub::RoleMid  );
    UCastHub oLeaf ( kLeafAddr, UCastHub::RoleLeaf );
    oTop .RequireAuth ( false );  oTop .RequireSeal ( false );
    oMid .RequireAuth ( false );  oMid .RequireSeal ( false );
    oLeaf.RequireAuth ( false );  oLeaf.RequireSeal ( false );

    HANDLE hTop = oTop.SpawnHub ( );
    if ( !hTop ) { Log ( "SETUP: top SpawnHub failed" ); return 1; }
    oTop.PostP2PeerCon ( P2PeerConWsa::ServiceFactory ( kMidAddr, nPort ) );
    Log ( "TOP listening" );
    Sleep ( 750 );

    HANDLE hMid = oMid.SpawnHub ( );
    if ( !hMid ) { Log ( "SETUP: middle SpawnHub failed" ); return 1; }
    oMid.PostP2PeerCon ( P2PeerConWsa::ClientFactory ( kTopAddr, L"127.0.0.1", nPort ) );
    oMid.PostP2PeerCon ( P2PeerConWsa::ServiceFactory ( kLeafAddr, (short)( nPort + 1 ) ) );
    Log ( "MID dialling the top and listening for the leaf" );
    Sleep ( 750 );

    HANDLE hLeaf = oLeaf.SpawnHub ( );
    if ( !hLeaf ) { Log ( "SETUP: leaf SpawnHub failed" ); return 1; }
    oLeaf.PostP2PeerCon ( P2PeerConWsa::ClientFactory ( kMidAddr, L"127.0.0.1",
                                                        (short)( nPort + 1 ) ) );
    Log ( "LEAF dialling the middle" );

    int nExit = 0;
    if ( WaitForSingleObject ( g_hMidUp,  20000 ) != WAIT_OBJECT_0 ||
         WaitForSingleObject ( g_hLeafUp, 20000 ) != WAIT_OBJECT_0    )
    {
        Log ( "TIMEOUT - the tree never came up" );
        nExit = 3;
    }

    //  Both CLIENT sides, because those are the ones the events above do not
    //  speak for - refer WaitForUCastReady. The leaf's link to the middle and
    //  the middle's link to the top are the two hops every phase below runs
    //  over, and neither phase means anything until both carry the bits.
    if ( nExit == 0 &&
         ( !WaitForUCastReady ( oLeaf, kMidAddr, "LEAF", 20000 ) ||
           !WaitForUCastReady ( oMid,  kTopAddr, "MID",  20000 )    ) )
    {
        Log ( "TIMEOUT - a link never reached ConUCasts_OK" );
        nExit = 3;
    }

    // ---- Phase 1: the control --------------------------------------------
    if ( nExit == 0 )
    {
        Log ( "--- phase 1: CONTROL, the leaf upcasts and both ancestors must see it ---" );
        oLeaf.Upcast ( kTagControl );

        const bool bMid = WaitForSingleObject ( g_hMidControl, 15000 ) == WAIT_OBJECT_0;
        const bool bTop = WaitForSingleObject ( g_hTopControl, 15000 ) == WAIT_OBJECT_0;
        if ( !bMid || !bTop )
        {
            std::printf ( "[ucastgate] FAILED (1) - upcast reached mid=%s top=%s."
                          " The relay does not carry an upcast at all, so nothing"
                          " below this line means anything.\n",
                          bMid ? "yes" : "NO", bTop ? "yes" : "NO" );
            std::fflush ( stdout );
            nExit = 2;
        }
        else if ( g_sTopScopeSeen != N ( kLeafAddr ) )
        {
            std::printf ( "[ucastgate] FAILED (1) - the top read Ups='%s', expected"
                          " '%s'. The origin's address did not survive the"
                          " re-addressing, which is the whole reason TMsg_Ups"
                          " exists.\n",
                          g_sTopScopeSeen.c_str ( ), N ( kLeafAddr ).c_str ( ) );
            std::fflush ( stdout );
            nExit = 2;
        }
        else
            Log ( "OK (1) - the upcast climbed to the root carrying the leaf's address" );
    }

    // ---- Phase 2: the gate ------------------------------------------------
    if ( nExit == 0 )
    {
        Log ( "--- phase 2: THE GATE, ConState_UCasts cleared on mid -> top ---" );
        if ( !ClearUCastBit ( oMid, kTopAddr, true ) )
        {
            Log ( "SETUP (2) - could not clear ConState_UCasts on the middle's"
                  " connection to the top" );
            nExit = 1;
        }
        else
        {
            oLeaf.Upcast ( kTagGated );

            //  The middle first, and it is not a formality. It proves the
            //  upcast was carried as far as the gated hop, so "the top did not
            //  see it" cannot be satisfied by the message never having left
            //  the leaf.
            if ( WaitForSingleObject ( g_hMidGated, 15000 ) != WAIT_OBJECT_0 )
            {
                Log ( "FAILED (2) - the upcast did not even reach the middle;"
                      " the gate below would be measuring nothing" );
                nExit = 2;
            }
            else
            {
                //  A window rather than an event, because the assertion is an
                //  absence. Generous against the 15s the positive waits get.
                Sleep ( 4000 );
                if ( g_abTopSaw[PhGated] )
                {
                    Log ( "FAILED (2) - the TOP received an upcast over a"
                          " connection that does not carry ConState_UCasts."
                          " ConUCasts_OK is not binding." );
                    nExit = 2;
                }
                else
                    Log ( "OK (2) - the gated hop was not selected" );
            }
        }
        ClearUCastBit ( oMid, kTopAddr, false );
    }

    // ---- Phase 3: the direction -------------------------------------------
    if ( nExit == 0 )
    {
        Log ( "--- phase 3: DIRECTION, the middle upcasts; the leaf must not see it ---" );
        oMid.Upcast ( kTagDown );

        if ( WaitForSingleObject ( g_hTopDown, 15000 ) != WAIT_OBJECT_0 )
        {
            Log ( "FAILED (3) - the middle's upcast never reached the top;"
                  " restoring the bit after phase 2 did not take" );
            nExit = 2;
        }
        else
        {
            Sleep ( 2000 );
            if ( g_abLeafSaw[PhDown] )
            {
                Log ( "FAILED (3) - the LEAF received an upcast. The relay is"
                      " enumerating every connection, not the parent ones." );
                nExit = 2;
            }
            else
                Log ( "OK (3) - the upcast went up and only up" );
        }
    }

    // ---- Report -----------------------------------------------------------
    std::printf ( "\n  phase 1  control, upcast climbs  : %s\n"
                    "  phase 2  ConState_UCasts gate    : %s\n"
                    "  phase 3  parents only, not all   : %s\n",
                  ( g_abMidSaw[PhControl] && g_abTopSaw[PhControl] ) ? "PASS" : "FAIL",
                  ( g_abMidSaw[PhGated]   && !g_abTopSaw[PhGated]  ) ? "PASS" : "FAIL",
                  ( g_abTopSaw[PhDown]    && !g_abLeafSaw[PhDown]  ) ? "PASS" : "FAIL" );
    std::fflush ( stdout );

    // ---- Shutdown ---------------------------------------------------------
    Log ( "shutdown begin" );
    oLeaf.CloseHub ( );
    oMid .CloseHub ( );
    oTop .CloseHub ( );
    WaitForSingleObject ( hLeaf, 5000 );
    WaitForSingleObject ( hMid,  5000 );
    WaitForSingleObject ( hTop,  5000 );
    CloseHandle ( hLeaf );
    CloseHandle ( hMid  );
    CloseHandle ( hTop  );

    CleanupP2Pmsg ( );
    if ( g_hTopControl ) CloseHandle ( g_hTopControl );
    if ( g_hMidControl ) CloseHandle ( g_hMidControl );
    if ( g_hMidGated   ) CloseHandle ( g_hMidGated   );
    if ( g_hTopDown    ) CloseHandle ( g_hTopDown    );
    if ( g_hMidUp      ) CloseHandle ( g_hMidUp      );
    if ( g_hLeafUp     ) CloseHandle ( g_hLeafUp     );
    WSACleanup ( );

    std::printf ( "Done (exit=%d).\n", nExit );
    std::fflush ( stdout );
    return nExit;
}
