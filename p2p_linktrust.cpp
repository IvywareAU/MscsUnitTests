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
// p2p_linktrust.cpp - SECURITY GATE TEST: is what a link may skip decided by
// what its TRANSPORT can vouch for, and does a relaxation stay inside the
// class it was granted to?
//
// BACKGROUND. Every security switch in this tree is a property of the HUB, and
// every connection asks its hub and nothing else. A P2PeerConDmx connection is
// a pointer handoff between two objects on one heap; under RequireAuth(true)
// it nevertheless ran an ephemeral ECDH agreement, created a BCrypt AES key
// object that P2PeerioDmx overrides both message methods and never consults,
// and put four ECDSA operations on the login exchange - to protect a channel
// with no wire on it. The only way to say otherwise was RequireAuth(false),
// which is all-or-nothing per hub: a hub with three DMX links and one TCP link
// either paid on all four or authenticated none of them.
//
// securityRevision.md's answer, implemented in §8.2 steps 1 to 4:
//
//   * the TRANSPORT declares a trust class - P2PeerCon::TrustClass(), a fact,
//     a VIRTUAL on the class, and therefore nothing AcceptSpawn can fail to
//     copy. The same mechanism F-S6-3 chose for P2PeerioDmx::LeavesProcess().
//   * the HUB keeps the policy, per class - P2PeerHub::SetLinkPolicy(). There
//     is still no per-connection RequireAuth. What moved to the connection is
//     a classification, not a permission.
//   * an operator may only ever TIGHTEN - DemoteTrust(), no PromoteTrust,
//     because a class this library cannot verify is an intention and a policy
//     must not read one as a fact.
//
// WHAT THIS TEST DOES - one in-process phase, eight live ones, and two that
// build hubs and never dial them.
//
//   Phase 0 (THE DECLARATIONS). Every connection class in the tree,
//   constructed directly, asked what it vouches for. This is the rule's INPUT
//   and it is checked separately because a wrong answer here would make every
//   later phase pass for the wrong reason. DMX must read InProcess; a socket
//   with no peer and no loopback bind, and a serial line, must read Wire. The
//   PIPE is asked four times, because after §8.2 step 4 it has four answers
//   and they come from two different places: a service that will create a
//   local pipe and a client that will open a local NAME read Local, while a
//   service told P2PeerConPipeAccess_Legacy and a client holding a UNC name
//   read Wire. Every one of those is the FALLBACK branch - none of these
//   objects holds a handle - which is why phases 9 and 10 exist. It also
//   checks the demotion algebra: a demotion tightens, a second demotion NAMING
//   A HIGHER CLASS does nothing, and there is no way back up.
//
//   Phases 1-3 are DMX and are the original complaint.
//     1 (POSITIVE CONTROL) defaults, both ends. The agreement runs and the
//       login is signed - today's behaviour, unchanged. Without this every
//       later refusal is indistinguishable from a broken transport.
//     2 (THE FEATURE) SetLinkPolicy(InProcess, Open) at BOTH ends. The login
//       must be ACCEPTED and the payload must arrive, with no agreement, no
//       cypher and no verified signature on the connection.
//     3 (THE F-S6-1 REGRESSION) Open on the CLIENT hub only. The two ends now
//       read different halves of one switch, which is exactly what F-S6-1
//       was, and the server MUST refuse the login.
//
//       WHAT PHASE 3 DOES AND DOES NOT ISOLATE, stated because the difference
//       matters to what a green run means. A client that has relaxed the class
//       sends neither an agreement nor a signature, so an unrelaxed server has
//       TWO independent reasons to refuse it: the channel gate
//       (KeyXWanted() && !m_bKeyXDone, which fires first) and, behind it, a
//       login carrying no auth block at all. This phase asserts the REFUSAL,
//       not which of the two made it - deleting the channel gate leaves the
//       phase green, because the signature check then refuses instead. Both
//       are the correct outcome and the security property is that the login
//       is not accepted; isolating the line would want the diagnostic matched
//       out of the event stream, the way p2p_confchannel matches its phase 3.
//
//   Phases 4-6 are TCP over loopback, whose class is Local, and they are about
//   containment rather than about DMX.
//     4 (THE FENCE BETWEEN CLASSES) hubs with SetLinkPolicy(InProcess, Open)
//       and nothing else. The TCP link is Local, so it must authenticate IN
//       FULL. A relaxation that leaked across classes would pass phases 1-3
//       and be a network endpoint nobody opened.
//     5 (CONTROL FOR 6) SetLinkPolicy(Local, Open) at both ends, no demotion.
//       The link is Local and the login must be accepted with no agreement.
//     6 (THE ONE FORGETTABLE LINE) phase 5 again, with the SERVICE connection
//       DemoteTrust(Wire) before it is posted. The accepted child must inherit
//       that ceiling - it is the single copied field in this whole feature -
//       so it reads Wire, Wire policy is Full and cannot be otherwise, and the
//       server MUST refuse the login its own hub would have accepted one phase
//       earlier. Delete the m_eTrustCeiling line from P2PeerCon::AcceptSpawn
//       and this phase goes red on its own.
//
//   Phases 7-8 are §8.2 STEP 3 - the fence, and what it does to the arm gate.
//   Neither needs a peer: both are answered before anything is dialled.
//     7 (THE FENCE) RequireTrustAtLeast(InProcess), then a Wire socket, a
//       Local socket and a DMX connection offered to the same hub. The two
//       sockets must be REFUSED at PostP2PeerCon and the DMX one accepted -
//       and the same Wire socket must be accepted by a hub that differs only
//       by the absence of that one call, or the refusals prove nothing.
//     8 (THE ARM GATE) a hub with NO key files at all, walked through six
//       combinations of fence and per-class policy. It must arm - as
//       ArmNotRequiredByPolicy - exactly when it has a fence AND every class
//       at or above that fence is Open, and it must fall back to ArmNoIdentity
//       when either half is taken away. The last of the six is the one that
//       catches the wrong implementation: both relaxable classes Open with NO
//       fence must still refuse, because a socket can still be posted to it.
//
//   Phases 9-10 are §8.2 STEP 4 - the named pipe, made local and then read.
//   Both are live: a pipe is created, a client opens it, and the class is read
//   off the connection that HOLDS THE HANDLE rather than off a setting.
//     9 (THE PIPE IS LOCAL NOW) both hubs SetLinkPolicy(Local, Open), the
//       service left at its default P2PeerConPipeAccess_Owner. The accepted
//       child must read Local, and the login must be accepted with no
//       agreement, no cypher and no signature. This is the phase that pins the
//       DERIVATION: m_bPipeLocal is computed from the pipe mode and the
//       security attributes that were actually handed to CreateNamedPipe, so
//       deleting either PIPE_REJECT_REMOTE_CLIENTS or the descriptor makes the
//       child read Wire, the server demand a handshake the client did not run,
//       and this phase go red. A flag assigned beside the request instead of
//       read back from it would have left it green.
//    10 (§8.3 PHASE 6 - THE ESCAPE HATCH IS A WIRE) the same, with the service
//       told P2PeerConPipeAccess_Legacy - the pre-revision CreateNamedPipe,
//       byte for byte, which a deployment sharing a pipe across accounts is
//       meant to be able to ask for. That pipe is reachable over SMB, so the
//       child must read Wire and the link must authenticate IN FULL even
//       though its hub opened the Local class. The CLIENT is DemoteTrust(Wire)
//       here for the same reason: it opened a local NPFS name, so its own end
//       IS local and it would otherwise skip a handshake the server still
//       wants - which is phase 3's disagreement, not this phase's subject.
//
// WHAT IT MEASURES. The verdict is the SERVER accepting a login (On_ConLogin),
// not a payload arriving - p2p_authchannel's header explains at length why
// that distinction is the difference between a gate and a test that passes
// against the defect it was written for. The connection facts are read off the
// public posture accessors at the moment the gate let the login through:
// IsKeyXDone(), IsCypherActive(), IsAuthenticated(), TrustClass() and
// EffectiveTrust(). The accepted child's class is read in On_ConAccept, which
// is reached whether or not the login is later refused, and only for the
// object whose mode is P2PeerCon_Accept - that handler sees the SERVICE first
// and the child on a second pass.
//
// WHAT IT DOES NOT COVER, and why, so a green run is not read for more than it
// says. securityRevision.md §8.3's nine phases are all here now: its phase 6
// is phase 10 below and its phase 7 - a pipe service demoted to Wire, whose
// accepted child must read Wire - is the same one copied field phase 6 pins on
// a socket, exercised on the pipe by phase 10's demoted client.
//
// WHAT NO PHASE HERE CAN CHECK is the half of the pipe change that is about
// WHICH LOCAL ACCOUNT may open the endpoint. The descriptor
// D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW) replaces a platform default that
// granted Everyone and Anonymous read access, and demonstrating that would
// need a second logon session - A7 in THREAT_MODEL.md, and the class these
// phases read has never claimed to answer A7. What IS checked is the half the
// class does claim: that the endpoint cannot be reached from another machine.
//
// THE FENCE IS CHECKED WHERE A CONNECTION IS HANDED TO A HUB. An accepted
// child does not pass through PostP2PeerCon - AcceptSpawn posts it directly -
// and does not need to: it is spawned by a service the fence already admitted,
// and inherits both the class (a virtual) and the ceiling (the one copied
// field), neither of which can read higher than that service's own. What no
// phase here covers is a service DEMOTED after it was posted, which lowers its
// children below a floor that has already been passed. That direction is
// safe - a demoted link's class is stricter, so its policy is Full and it
// authenticates in full, which is phase 6 - but it is a state the fence does
// not re-examine, and this is where that is written down.
//
// Every hub in phases 1-7 is fully provisioned even when all its links are
// Open, which until §8.2 step 3 landed was what the library demanded of every
// hub that had not said RequireAuth(false). Phase 8 is the hub that no longer
// has to be.
//
// NOT WILL_FAIL: it asserts the behaviour steps 1 and 2 give.
//
// VERDICT = process EXIT CODE:
//   0  PASS   every phase behaved as above
//   1  FAIL   a relaxation was not honoured, or leaked, or a refusal was not made
//   2  SETUP  startup / provisioning failure (test inconclusive)
//   3  INCONCLUSIVE a positive control never arrived - proves nothing
//
// Build (Linux): as p2p_authgate.cpp.

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConDmx.h"
#include "P2PeerConWsa.h"
#include "P2PeerConPipe.h"
#include "P2PeerCon232.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"
#include "P2PIdentityStore.h"
#include "P2PAuthLogin.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <exception>

// ---------------------------------------------------------------------------
//  A HUB ADDRESS PER PHASE, and it is not cosmetic. Six live phases each build
//  a server hub and a client hub, run one login, and tear both down; reusing
//  two addresses across all six makes every phase depend on the previous
//  phase's deregistration having completed in the process-wide hub registry
//  before this one's CreateHub runs. That is a race with a sleep in it, which
//  is the shape of a test that passes until the machine is busy - and this one
//  did exactly that, failing once in a full ctest run (706 s wall against the
//  495 s of the run before it) and never in isolation. Distinct addresses
//  remove the dependency rather than widening the window.
//
//  Phase 0 uses no hub, so index 0 is never dialled.  Phases 7-8 build hubs
//  and never dial them - the fence and the arming gate are both answered
//  before a peer exists - but they take addresses out of the same table so
//  that no two phases can collide in the process-wide registry.
//
//  AN INDEX IS NOT A PHASE NUMBER, and pretending it was cost a debugging
//  session.  Phase 7 builds TWO hubs and takes indices 7 and 8; phase 8 takes
//  9; so the pipe phases take 10 and 11.  Written as kSrvAddr[nPhase] the pipe
//  phase would have re-used phase 8's address one millisecond after phase 8
//  tore its hub down - which is the exact race the per-phase address exists to
//  remove, reintroduced by the convenience of indexing with the phase number.
//  It presented as an abrupt termination in phase 9, indistinguishable at a
//  glance from the pre-existing intermittent one this suite already has.
static const P2PaddrSTR kSrvAddr[12] =
{ L"LinkTrust.S0", L"LinkTrust.S1", L"LinkTrust.S2", L"LinkTrust.S3"
, L"LinkTrust.S4", L"LinkTrust.S5", L"LinkTrust.S6", L"LinkTrust.S7"
, L"LinkTrust.S8", L"LinkTrust.S9", L"LinkTrust.SA", L"LinkTrust.SB" };
static const P2PaddrSTR kCliAddr[12] =
{ L"LinkTrust.C0", L"LinkTrust.C1", L"LinkTrust.C2", L"LinkTrust.C3"
, L"LinkTrust.C4", L"LinkTrust.C5", L"LinkTrust.C6", L"LinkTrust.C7"
, L"LinkTrust.C8", L"LinkTrust.C9", L"LinkTrust.CA", L"LinkTrust.CB" };
static const P2PaddrSTR kDomain     = L"LinkTrust.*";

//  How long a phase waits for a payload that is MEANT to arrive, and how long
//  the phases that must refuse wait before calling the refusal absent.
//  NOTES: Generous on purpose. A positive control that times out reports a
//         failure of the thing under test, and this suite runs alongside
//         thirty-six others on a machine whose load it does not control. The
//         refusal waits are shorter because nothing is expected to happen in
//         them and every second is spent
//       : The ctest TIMEOUT has to exceed the sum of these, and does
static const DWORD kWaitDeliver = 30000;
static const DWORD kWaitRefuse  = 10000;
//  Let a phase's hubs finish leaving before the next phase's are made. With a
//  distinct address per phase this is no longer load-bearing; it is kept
//  because a pump thread that has been joined has still only just released its
//  connections, and the next phase gains nothing by racing it.
static const DWORD kSettleMs    = 1000;

//  One payload per phase, so a stale delivery from a previous phase cannot be
//  read as this one's.
//  Indexed by ADDRESS index, not by phase number - refer kSrvAddr.
static const wchar_t *kPayload[12] =
{ L"phase0-unused"
, L"phase1-dmx-full"
, L"phase2-dmx-open"
, L"phase3-dmx-split"
, L"phase4-tcp-not-inprocess"
, L"phase5-tcp-local-open"
, L"phase6-tcp-demoted"
, L"phase7-unused"          // the fence answers before a peer exists
, L"phase7-unused-control"  // ...its control hub
, L"phase8-unused"          // ...and so does the arming gate
, L"phase9-pipe-local-open"
, L"phase10-pipe-legacy-wire"
};

//  A pipe name per phase, and the PROCESS ID in it.  A named pipe is a
//  machine-wide name: two copies of this suite running at once - which is what
//  ctest does - would otherwise contend for one endpoint, and the second
//  CreateNamedPipe would take the instance the first is listening on.  The
//  ports are held apart by RESOURCE_LOCK in CMakeLists.txt; a pipe name has no
//  such lock, so it carries the only thing guaranteed distinct instead.
static std::wstring PipeName ( int nPhase )
{
    wchar_t szName[64];
    std::swprintf ( szName, sizeof(szName) / sizeof(szName[0]),
                    L"\\\\.\\pipe\\p2p_linktrust_%lu_%d",
                    (unsigned long)GetCurrentProcessId ( ), nPhase );
    return std::wstring ( szName );
}

static void Log ( const char *msg )
{
    std::printf ( "[linktrust] %s\n", msg );
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

static const char *TrustName ( int n )
{
    switch ( n )
    {
      case P2PeerConTrust_Wire:      return "Wire";
      case P2PeerConTrust_Local:     return "Local";
      case P2PeerConTrust_InProcess: return "InProcess";
    }
    return "?";
}

//  The payload pointer is NOT aligned - P2PeerMsg::Data() addresses the
//  application bytes where they sit inside a pack(1) image, so casting it to
//  wchar_t* is undefined behaviour and UBSan says so on Linux. TargetCore
//  finding F-S5-3; copying the bytes out into aligned storage is the fix.
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
//  What one phase observed. Written by the server's pump thread, read by main
//  after that thread has been joined - there is no concurrent access to any of
//  it, which is why none of it is atomic.
struct Observed
{
    bool bLogin;          // the SERVER reached On_ConLogin - THE VERDICT
    bool bPayload;        // ...and the application message arrived
    bool bKeyXDone;       // the agreement completed on the accepted connection
    bool bCypher;         // a cypher is installed AND consulted on it
    bool bAuthed;         // a login signature verified on it
    int  nLoginTrust;     // EffectiveTrust() at the moment of the login
    bool bAccept;         // the SERVER reached On_ConAccept for a CHILD
    int  nChildClass;     // ...its TrustClass()
    int  nChildTrust;     // ...its EffectiveTrust()
};
static Observed g_obs;
static HANDLE   g_hPayload = NULL;
static HANDLE   g_hLogin   = NULL;
//  The server's service connection has reached On_ConListen.
//  NOTES: This replaced a Sleep() and the replacement is not tidiness. A phase
//         that sleeps before dialling is racing the listener, and losing that
//         race is WSAECONNREFUSED (10061) on the client's connect - which this
//         test then reports as the Local class failing to honour its own
//         policy, because from the outside a login that never happened and a
//         login that was refused look identical. It failed that way about one
//         run in eight
//       : Waiting on THIS is sound rather than merely longer, and the ordering
//         is the transport's: P2PeerConWsa::Listen() calls bind() and then
//         listen() and only then posts P2P_Listen, which is what dispatches
//         On_ConListen. By the time this event is set the kernel is accepting
//         into the backlog, so a connect cannot be refused for earliness
static HANDLE   g_hListening = NULL;

static void ResetObserved ( )
{
    std::memset ( &g_obs, 0, sizeof(g_obs) );
    g_obs.nLoginTrust = -1;
    g_obs.nChildClass = -1;
    g_obs.nChildTrust = -1;
    if ( g_hPayload   ) ResetEvent ( g_hPayload   );
    if ( g_hLogin     ) ResetEvent ( g_hLogin     );
    if ( g_hListening ) ResetEvent ( g_hListening );
}

// =========================================================================
class TrustHub : public P2PeerHub
{
public:
    //  strPeer is where a CLIENT posts its payload once it is logged in. It is
    //  a constructor argument rather than a file-scope constant because the
    //  server's address changes per phase - refer kSrvAddr
    TrustHub ( P2PaddrSTR strAddr, bool bServer, P2PaddrSTR strPeer,
               const wchar_t *pszPayload )
        : P2PeerHub ( strAddr ), m_bServer ( bServer )
        , m_bSent ( false ), m_pszPayload ( pszPayload )
    { m_strSelf = strAddr; m_strPeer = strPeer; }
    virtual ~TrustHub ( ) {}

protected:
    virtual msgRESULT On_P2PeerBCast ( P2PeerMsg *pMsg ) override
    {
        if ( m_bServer && pMsg )
        {
            const std::wstring wBody = BodyW ( pMsg );
            std::printf ( "[linktrust] SERVER received '%s'\n",
                          N ( wBody.c_str ( ) ).c_str ( ) );
            std::fflush ( stdout );
            g_obs.bPayload = true;
            if ( g_hPayload ) SetEvent ( g_hPayload );
        }
        return msgHANDLED;
    }

    //  The service is bound, listening and accepting into the backlog by the
    //  time this runs - refer g_hListening. It is what the client waits for
    //  instead of a sleep.
    virtual conRESULT On_ConListen ( P2PeerCon *pCon ) override
    {
        conRESULT result = P2PeerHub::On_ConListen ( pCon );
        if ( m_bServer && g_hListening ) SetEvent ( g_hListening );
        return result;
    }

    //  The accepted CHILD's class, read where it can be read whether or not
    //  the login that follows is refused.
    //  NOTES: This handler sees the SERVICE first and the spawned child on a
    //         second pass - refer P2PeerTarget::On_ConAccept, which re-posts
    //         the child under the service's address. Only the second is the
    //         object AcceptSpawn built, so only the second is asked
    virtual conRESULT On_ConAccept ( P2PeerCon *pCon ) override
    {
        if ( m_bServer && pCon && pCon->GetMode ( ) == P2PeerCon_Accept )
        {
            g_obs.bAccept     = true;
            g_obs.nChildClass = (int)pCon->TrustClass    ( );
            g_obs.nChildTrust = (int)pCon->EffectiveTrust( );
            std::printf ( "[linktrust] SERVER accepted a child: TrustClass=%s "
                          "EffectiveTrust=%s\n",
                          TrustName ( g_obs.nChildClass ),
                          TrustName ( g_obs.nChildTrust ) );
            std::fflush ( stdout );
        }
        return P2PeerHub::On_ConAccept ( pCon );
    }

    virtual conRESULT On_ConLogin ( P2PeerCon *pCon, P2PaddrSTR strThatP2Paddr,
                                    const void *pvLoginMsg, P2Psize_t iSize ) override
    {
        if ( m_bServer )
        {
            //  Reached only after AuthGateInbound has passed the login, so
            //  this is the gate's answer and nothing downstream of it.
            g_obs.bLogin = true;
            if ( pCon )
            {
                g_obs.bKeyXDone   = pCon->IsKeyXDone     ( );
                g_obs.bCypher     = pCon->IsCypherActive ( );
                g_obs.bAuthed     = pCon->IsAuthenticated( );
                g_obs.nLoginTrust = (int)pCon->EffectiveTrust ( );
            }
            std::printf ( "[linktrust] SERVER ACCEPTED a login claiming '%s' "
                          "(trust=%s keyx=%d cypher=%d authed=%d)\n",
                          N ( strThatP2Paddr ).c_str ( ),
                          TrustName ( g_obs.nLoginTrust ),
                          g_obs.bKeyXDone ? 1 : 0,
                          g_obs.bCypher   ? 1 : 0,
                          g_obs.bAuthed   ? 1 : 0 );
            std::fflush ( stdout );
            if ( g_hLogin ) SetEvent ( g_hLogin );
        }
        return P2PeerHub::On_ConLogin ( pCon, strThatP2Paddr, pvLoginMsg, iSize );
    }

    virtual conRESULT On_ConLoginAck ( P2PeerCon  *pCon,
                                       P2PaddrSTR  strThisP2Paddr,
                                       P2PaddrSTR  strThatP2Paddr,
                                       const void *pvLoginAck,
                                       P2Psize_t   iSize ) override
    {
        conRESULT result = P2PeerHub::On_ConLoginAck ( pCon, strThisP2Paddr,
                                                       strThatP2Paddr,
                                                       pvLoginAck, iSize );
        if ( !m_bServer && !m_bSent && m_pszPayload )
        {
            m_bSent = true;
            P2Psize_t nBytes =
                (P2Psize_t)( ( wcslen ( m_pszPayload ) + 1 ) * sizeof(wchar_t) );
            PostP2PeerMsg ( new P2PeerMsg32 ( m_strSelf.GetString ( ),
                                              m_strPeer.GetString ( ),
                                              P2Pmsg_BCast, m_pszPayload, nBytes ) );
        }
        return result;
    }

private:
    bool           m_bServer;
    bool           m_bSent;
    const wchar_t *m_pszPayload;
    CString        m_strSelf;
    CString        m_strPeer;
};

// ---------------------------------------------------------------------------
static std::vector<std::string> g_vTempFiles;

static std::string TempPath ( const char *pszLeaf )
{
    char szDir[MAX_PATH + 2] = { 0 };
    DWORD n = GetTempPathA ( MAX_PATH + 1, szDir );
    std::string s = ( n > 0 && n <= MAX_PATH ) ? std::string ( szDir )
                                               : std::string ( ".\\" );
    char szPid[32];
    std::snprintf ( szPid, sizeof(szPid), "%lu",
                    (unsigned long)GetCurrentProcessId ( ) );
    s += "p2p_linktrust_"; s += pszLeaf; s += "_"; s += szPid; s += ".tmp";
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
    if ( !oKey.Generate ( ) ) return false;
    if ( p2pcng::SaveIdentity ( sPath.c_str ( ), oKey ) != p2pcng::IdOk ) return false;
    return oKey.ExportPublic ( pPubOut );
}

// =========================================================================
//  Phase 0 - what each transport vouches for, and the demotion algebra.
//
//  No hub, no thread, no socket and no pipe: each class is constructed through
//  its default constructor, which allocates no io object and opens no handle,
//  and is asked. If these answers are wrong every later phase passes for the
//  wrong reason.
// =========================================================================
static bool Declares ( const char *pszWhat, const P2PeerCon *pCon,
                       P2PeerConTrust_e eExpect )
{
    const int nGot = pCon ? (int)pCon->TrustClass ( ) : -1;
    const bool bOk = ( nGot == (int)eExpect );
    std::printf ( "  %-24s TrustClass=%-9s expected %-9s  %s\n",
                  pszWhat, TrustName ( nGot ), TrustName ( (int)eExpect ),
                  bOk ? "ok" : "*** WRONG ***" );
    std::fflush ( stdout );
    return bOk;
}

static bool PhaseZero ( )
{
    bool bOk = true;

    //  DMX: construction keeps the frames in this process, so the answer does
    //  not depend on anything having been configured.
    {
        P2PeerConDmx *p = new P2PeerConDmx ( );
        bOk = Declares ( "P2PeerConDmx", p, P2PeerConTrust_InProcess ) && bOk;
        delete p;
    }

    //  A socket with no peer and no loopback bind. Wire, and it is the BASE
    //  class's answer arriving through an override that found nothing to say.
    {
        P2PeerConWsa *p = new P2PeerConWsa ( );
        bOk = Declares ( "P2PeerConWsa (unbound)", p, P2PeerConTrust_Wire ) && bOk;
        delete p;
    }

    //  ...and the same class told to bind loopback. This is the FALLBACK
    //  branch - a service carries no traffic, so what it answers is a posture
    //  reading; the accepted child's answer comes from getpeername() and is
    //  what phases 5 and 6 exercise.
    {
        P2PeerConWsa *p = new P2PeerConWsa ( );
        p->SetListenScope ( P2PeerConScope_Loopback );
        bOk = Declares ( "P2PeerConWsa (loopback)", p, P2PeerConTrust_Local ) && bOk;
        delete p;
    }

    //  The pipe, four ways. This is the row that MOVED in §8.2 step 4: it
    //  used to be a single Wire, because CreateListenPipe called
    //  CreateNamedPipe without PIPE_REJECT_REMOTE_CLIENTS and with a null
    //  security descriptor and the endpoint was therefore reachable over SMB
    //  from another host - THREAT_MODEL.md F-SR-1. It is not any more.
    //
    //  All four of these read the FALLBACK branch of P2PeerConPipe::
    //  TrustClass(), because none of them holds a handle. That branch answers
    //  from what the object is configured to become, and what that is depends
    //  on which end it is: a service creates the pipe, so its access mode
    //  decides; a client only opens a name, so the name decides. Phases 9 and
    //  10 are where an object that HAS a handle is asked.
    {
        //  A service at its default. Local now, and this is the default that
        //  moved - nobody has to ask for it.
        P2PeerConPipe *p = new P2PeerConPipe ( );
        bOk = Declares ( "P2PeerConPipe (owner)", p, P2PeerConTrust_Local ) && bOk;
        delete p;
    }
    {
        //  ...and the same service told to make the pipe the old way. Wire,
        //  and it has to be: the compatibility escape hatch is precisely the
        //  one that does not get to claim the class.
        P2PeerConPipe *p = new P2PeerConPipe ( );
        p->SetPipeAccess ( P2PeerConPipeAccess_Legacy );
        bOk = Declares ( "P2PeerConPipe (legacy)", p, P2PeerConTrust_Wire ) && bOk;
        delete p;
    }
    {
        //  A client holding a LOCAL device name. \\.\pipe\Name is NPFS on this
        //  machine and cannot be anything else, which is a kernel fact about
        //  this end and is all the class ever claimed.
        P2PeerConPipe *p =
            P2PeerConPipe::ClientFactory ( kSrvAddr[0], L"\\\\.\\pipe\\LinkTrustP0" );
        bOk = Declares ( "P2PeerConPipe (cli local)", p, P2PeerConTrust_Local ) && bOk;
        delete p;
    }
    {
        //  ...and a client holding a UNC name, which goes out through the SMB
        //  redirector. Wire. \\localhost\pipe\ and \\127.0.0.1\pipe\ read the
        //  same way and are meant to: they reach this machine THROUGH the
        //  network stack, and fail-closed is the direction to be wrong in.
        P2PeerConPipe *p =
            P2PeerConPipe::ClientFactory ( kSrvAddr[0], L"\\\\somehost\\pipe\\LinkTrustP0" );
        bOk = Declares ( "P2PeerConPipe (cli unc)", p, P2PeerConTrust_Wire ) && bOk;
        delete p;
    }

    //  Serial. A cable can be clipped and RS-232 has no DACL. "Directly
    //  attached hardware bus" describes where it is usually deployed, not what
    //  someone with access to it can do.
    {
        P2PeerCon232 *p = new P2PeerCon232 ( );
        bOk = Declares ( "P2PeerCon232", p, P2PeerConTrust_Wire ) && bOk;
        delete p;
    }

    //  The demotion algebra. DMX is the only class with room to fall twice.
    {
        P2PeerConDmx *p = new P2PeerConDmx ( );
        bool bSub = true;

        bSub = bSub && ( p->EffectiveTrust ( ) == P2PeerConTrust_InProcess );

        p->DemoteTrust ( P2PeerConTrust_Local );      // tightens
        bSub = bSub && ( p->TrustClass     ( ) == P2PeerConTrust_InProcess )
                    && ( p->EffectiveTrust ( ) == P2PeerConTrust_Local     );

        p->DemoteTrust ( P2PeerConTrust_InProcess );  // must NOT promote back
        bSub = bSub && ( p->EffectiveTrust ( ) == P2PeerConTrust_Local );

        p->DemoteTrust ( P2PeerConTrust_Wire );       // tightens again
        bSub = bSub && ( p->EffectiveTrust ( ) == P2PeerConTrust_Wire );

        p->DemoteTrust ( P2PeerConTrust_Local );      // still no way back up
        bSub = bSub && ( p->EffectiveTrust ( ) == P2PeerConTrust_Wire );

        std::printf ( "  %-24s demote tightens, never promotes            %s\n",
                      "P2PeerCon", bSub ? "ok" : "*** WRONG ***" );
        std::fflush ( stdout );
        bOk = bSub && bOk;
        delete p;
    }

    return bOk;
}

// =========================================================================
//  One DMX phase. Both hubs are built here because the policy differs on both
//  sides and phase 3 is precisely the two ends disagreeing.
// =========================================================================
static bool RunDmxPhase ( int nPhase,
                          const std::string &sSrvKey, const std::string &sSrvAcl,
                          const std::string &sCliKey, const std::string &sCliAcl,
                          P2PeerLinkPolicy_e eServer, P2PeerLinkPolicy_e eClient,
                          DWORD dwWaitMs, bool *pbSetupFailed )
{
    *pbSetupFailed = false;
    ResetObserved ( );

    wchar_t szService[64];
    std::swprintf ( szService, 64, L"LinkTrustDmx%d", nPhase );

    TrustHub oServer ( kSrvAddr[nPhase], true, kCliAddr[nPhase], 0 );
    if ( oServer.SetIdentity  ( sSrvKey.c_str ( ) ) != p2pcng::IdOk ||
         oServer.SetAllowList ( sSrvAcl.c_str ( ) ) != p2pcng::IdOk )
    { *pbSetupFailed = true; return false; }
    oServer.RequireAuth       ( true  );
    oServer.RequireRevocation ( false );          // this test is not about revocation
    oServer.SetLinkPolicy     ( P2PeerConTrust_InProcess, eServer );

    HANDLE hSrv = oServer.SpawnHub ( );
    if ( !hSrv ) { *pbSetupFailed = true; return false; }
    P2PeerConDmx *pSvc = P2PeerConDmx::ServiceFactory ( kCliAddr[nPhase], szService );
    if ( !pSvc ) { *pbSetupFailed = true; return false; }
    oServer.PostP2PeerCon ( pSvc );
    //  Wait for the service to BE listening rather than sleeping and hoping.
    //  A timeout here is a setup failure and not a verdict: the phase never
    //  started, so it has proved nothing either way
    if ( WaitForSingleObject ( g_hListening, 15000 ) != WAIT_OBJECT_0 )
    {
        *pbSetupFailed = true;
        oServer.CloseHub ( );
        WaitForSingleObject ( hSrv, 5000 );
        CloseHandle ( hSrv );
        return false;
    }

    bool bArrived = false;
    {
        TrustHub oClient ( kCliAddr[nPhase], false, kSrvAddr[nPhase],
                           kPayload[nPhase] );
        if ( oClient.SetIdentity  ( sCliKey.c_str ( ) ) != p2pcng::IdOk ||
             oClient.SetAllowList ( sCliAcl.c_str ( ) ) != p2pcng::IdOk )
        { *pbSetupFailed = true; }
        else
        {
            oClient.RequireAuth       ( true  );
            oClient.RequireRevocation ( false );
            oClient.SetLinkPolicy     ( P2PeerConTrust_InProcess, eClient );

            HANDLE hCli = oClient.SpawnHub ( );
            P2PeerConDmx *pCli =
                P2PeerConDmx::ClientFactory ( kSrvAddr[nPhase], szService );
            if ( !hCli || !pCli ) { *pbSetupFailed = true; }
            else
            {
                oClient.PostP2PeerCon ( pCli );
                bArrived = ( WaitForSingleObject ( g_hPayload, dwWaitMs )
                             == WAIT_OBJECT_0 );
                oClient.CloseHub ( );
                WaitForSingleObject ( hCli, 3000 );
                CloseHandle ( hCli );
            }
        }
    }

    oServer.CloseHub ( );
    WaitForSingleObject ( hSrv, 5000 );
    CloseHandle ( hSrv );
    Sleep ( kSettleMs );
    return bArrived;
}

// =========================================================================
//  One TCP phase, over loopback, whose class is Local.
//
//  bDemoteService is the whole of phase 6: it is set on the SERVICE, before it
//  is posted, and everything the phase asserts afterwards is about whether
//  AcceptSpawn carried it to the child.
// =========================================================================
static bool RunWsaPhase ( int nPhase,
                          const std::string &sSrvKey, const std::string &sSrvAcl,
                          const std::string &sCliKey, const std::string &sCliAcl,
                          P2PeerLinkPolicy_e eLocal, P2PeerLinkPolicy_e eProc,
                          bool bDemoteService, short nPort,
                          DWORD dwWaitMs, bool *pbSetupFailed )
{
    *pbSetupFailed = false;
    ResetObserved ( );

    TrustHub oServer ( kSrvAddr[nPhase], true, kCliAddr[nPhase], 0 );
    if ( oServer.SetIdentity  ( sSrvKey.c_str ( ) ) != p2pcng::IdOk ||
         oServer.SetAllowList ( sSrvAcl.c_str ( ) ) != p2pcng::IdOk )
    { *pbSetupFailed = true; return false; }
    oServer.RequireAuth       ( true  );
    oServer.RequireRevocation ( false );
    oServer.SetLinkPolicy     ( P2PeerConTrust_Local,     eLocal );
    oServer.SetLinkPolicy     ( P2PeerConTrust_InProcess, eProc  );

    HANDLE hSrv = oServer.SpawnHub ( );
    if ( !hSrv ) { *pbSetupFailed = true; return false; }
    P2PeerConWsa *pSvc = P2PeerConWsa::ServiceFactory ( kDomain, nPort );
    if ( !pSvc ) { *pbSetupFailed = true; return false; }
    if ( bDemoteService )
      pSvc->DemoteTrust ( P2PeerConTrust_Wire );
    oServer.PostP2PeerCon ( pSvc );
    //  As the DMX runner: wait for the listener, do not sleep at it. This is
    //  the phase that actually lost the race - a client that dials before
    //  bind()/listen() gets WSAECONNREFUSED, and a phase whose verdict is
    //  "was the login accepted" cannot tell that from a policy that refused it
    if ( WaitForSingleObject ( g_hListening, 15000 ) != WAIT_OBJECT_0 )
    {
        *pbSetupFailed = true;
        oServer.CloseHub ( );
        WaitForSingleObject ( hSrv, 5000 );
        CloseHandle ( hSrv );
        return false;
    }

    bool bArrived = false;
    {
        TrustHub oClient ( kCliAddr[nPhase], false, kSrvAddr[nPhase],
                           kPayload[nPhase] );
        if ( oClient.SetIdentity  ( sCliKey.c_str ( ) ) != p2pcng::IdOk ||
             oClient.SetAllowList ( sCliAcl.c_str ( ) ) != p2pcng::IdOk )
        { *pbSetupFailed = true; }
        else
        {
            oClient.RequireAuth       ( true  );
            oClient.RequireRevocation ( false );
            oClient.SetLinkPolicy     ( P2PeerConTrust_Local,     eLocal );
            oClient.SetLinkPolicy     ( P2PeerConTrust_InProcess, eProc  );

            HANDLE hCli = oClient.SpawnHub ( );
            P2PeerConWsa *pCli =
                P2PeerConWsa::ClientFactory ( kSrvAddr[nPhase], L"127.0.0.1", nPort );
            if ( !hCli || !pCli ) { *pbSetupFailed = true; }
            else
            {
                oClient.PostP2PeerCon ( pCli );
                bArrived = ( WaitForSingleObject ( g_hPayload, dwWaitMs )
                             == WAIT_OBJECT_0 );
                oClient.CloseHub ( );
                WaitForSingleObject ( hCli, 3000 );
                CloseHandle ( hCli );
            }
        }
    }

    oServer.CloseHub ( );
    WaitForSingleObject ( hSrv, 5000 );
    CloseHandle ( hSrv );
    Sleep ( kSettleMs );
    return bArrived;
}


// =========================================================================
//  Phases 9 and 10 - THE NAMED PIPE, made local and then read.
//
//  §8.2 step 4 and §8.3 phase 6.  Both phases build a real pipe, dial it, and
//  read the class off the connection that HOLDS THE HANDLE - which is the only
//  reading that can tell a transport that was made local from one that was
//  merely configured to be.  Phase 0's four pipe rows are all the fallback
//  branch; these two are the fact.
//
//  WHY THE CLIENT IS DEMOTED IN PHASE 10 and not in phase 9.  The two ends of
//  a pipe answer the locality question from different evidence: the service
//  from the arguments its CreateNamedPipe was given, the client from the
//  device its name resolves to.  A legacy SERVICE is Wire while a client that
//  opened \\.\pipe\Name is still, truthfully, Local - so with the Local class
//  open the client would skip a handshake the server still wants, and the
//  server would refuse.  That refusal is phase 3's subject, not this one's.
//  DemoteTrust(Wire) on the client puts both ends on the same class so that
//  what phase 10 measures is the HANDSHAKE, which is what §8.3 phase 6 asks
//  for: "Wire, full handshake regardless of policy".
//
//  ON_ConListen IS THE RIGHT SIGNAL HERE TOO, and for a better reason than on
//  the socket.  P2PeerTarget::On_ConListen calls pCon->OnListen(), which is
//  where CreateListenPipe() runs, and then pCon->Accept(), which is the
//  overlapped ConnectNamedPipe - and only then does the hub's handler return
//  and this test's override set the event.  So by the time the client dials,
//  the pipe exists AND its accept is pending.  pipe_mesh.cpp sleeps 750ms at
//  this point; a sleep that is long enough on an idle machine is the shape of
//  a test that fails under ctest, which is exactly what this suite already
//  learned once on the socket phases.
// =========================================================================
//  nAddr is the index into kSrvAddr/kCliAddr/kPayload and is NOT nPhase -
//  refer the note on kSrvAddr for what happens when the two are conflated.
static bool RunPipePhase ( int nPhase, int nAddr,
                           const std::string &sSrvKey, const std::string &sSrvAcl,
                           const std::string &sCliKey, const std::string &sCliAcl,
                           P2PeerConPipeAccess_e eAccess, bool bDemoteClient,
                           DWORD dwWaitMs, bool *pbSetupFailed )
{
    *pbSetupFailed = false;
    ResetObserved ( );

    const std::wstring wPipe = PipeName ( nPhase );

    TrustHub oServer ( kSrvAddr[nAddr], true, kCliAddr[nAddr], 0 );
    if ( oServer.SetIdentity  ( sSrvKey.c_str ( ) ) != p2pcng::IdOk ||
         oServer.SetAllowList ( sSrvAcl.c_str ( ) ) != p2pcng::IdOk )
    { *pbSetupFailed = true; return false; }
    oServer.RequireAuth       ( true  );
    oServer.RequireRevocation ( false );
    oServer.SetLinkPolicy     ( P2PeerConTrust_Local, P2PeerLinkPolicy_Open );

    HANDLE hSrv = oServer.SpawnHub ( );
    if ( !hSrv ) { *pbSetupFailed = true; return false; }
    P2PeerConPipe *pSvc = P2PeerConPipe::ServiceFactory ( kDomain, wPipe.c_str ( ) );
    if ( !pSvc ) { *pbSetupFailed = true; return false; }
    //  BEFORE the post, because it describes the pipe CreateListenPipe will
    //  make and CreateListenPipe runs on the pump thread the post wakes.
    pSvc->SetPipeAccess ( eAccess );
    oServer.PostP2PeerCon ( pSvc );
    if ( WaitForSingleObject ( g_hListening, 15000 ) != WAIT_OBJECT_0 )
    {
        *pbSetupFailed = true;
        oServer.CloseHub ( );
        WaitForSingleObject ( hSrv, 5000 );
        CloseHandle ( hSrv );
        return false;
    }

    bool bArrived = false;
    {
        TrustHub oClient ( kCliAddr[nAddr], false, kSrvAddr[nAddr],
                           kPayload[nAddr] );
        if ( oClient.SetIdentity  ( sCliKey.c_str ( ) ) != p2pcng::IdOk ||
             oClient.SetAllowList ( sCliAcl.c_str ( ) ) != p2pcng::IdOk )
        { *pbSetupFailed = true; }
        else
        {
            oClient.RequireAuth       ( true  );
            oClient.RequireRevocation ( false );
            oClient.SetLinkPolicy     ( P2PeerConTrust_Local, P2PeerLinkPolicy_Open );

            HANDLE hCli = oClient.SpawnHub ( );
            P2PeerConPipe *pCli =
                P2PeerConPipe::ClientFactory ( kSrvAddr[nAddr], wPipe.c_str ( ) );
            if ( !hCli || !pCli ) { *pbSetupFailed = true; }
            else
            {
                if ( bDemoteClient )
                  pCli->DemoteTrust ( P2PeerConTrust_Wire );
                oClient.PostP2PeerCon ( pCli );
                bArrived = ( WaitForSingleObject ( g_hPayload, dwWaitMs )
                             == WAIT_OBJECT_0 );
                oClient.CloseHub ( );
                WaitForSingleObject ( hCli, 3000 );
                CloseHandle ( hCli );
            }
        }
    }

    oServer.CloseHub ( );
    WaitForSingleObject ( hSrv, 5000 );
    CloseHandle ( hSrv );
    Sleep ( kSettleMs );
    return bArrived;
}

// =========================================================================
//  Phase 7 - THE FENCE.  RequireTrustAtLeast() and PostP2PeerCon.
//
//  securityRevision.md 8.3 phase 5, and it needs no peer: the fence answers
//  when the connection is handed to the hub, which is before anything has been
//  dialled, listened on or accepted.  So this phase builds one hub, offers it
//  three connections, and reads three return values - then does it again on a
//  hub that differs by the one call.
//
//  WHY THE FENCE EXISTS AT ALL, since nothing here is weakened without it.  A
//  hub that has opened its in-process class is one PostP2PeerCon away from
//  carrying a socket.  That socket authenticates IN FULL - the wire's policy
//  is Full and cannot be set otherwise, which is what phase 4 pins - so no
//  traffic is exposed; what happens is that a hub which exists to route inside
//  a process becomes a network endpoint nobody asked for.  The fence is how an
//  operator says it will not be one, and this is the phase that shows the
//  saying is enforced rather than merely recorded.
//
//  A DISTINCT ADDRESS PER OFFERED CONNECTION, and it is not tidiness.  All
//  four would otherwise be posted as kDomain, and PostP2PeerCon refuses a
//  DUPLICATE address as well as a link below the floor - so with the fence
//  taken out the first socket would be ACCEPTED and the second refused as its
//  duplicate, and this phase would go half red instead of red.  A gate whose
//  falsification reddens only one of its assertions is not measuring the
//  other one.  With an address each, every post below can be refused for
//  exactly one reason.
//
//  OWNERSHIP.  A refused PostP2PeerCon RELEASES the connection - the
//  SafeP2PeerCon at the top of that function holds the only reference, so the
//  object is gone by the time FALSE comes back.  That is what the two refusals
//  already there do, and it is why nothing below deletes, or touches, a
//  connection the hub said no to.
// =========================================================================
static bool PhaseSeven ( const std::string &sSrvKey, const std::string &sSrvAcl,
                         short nPort, bool *pbSetupFailed )
{
    *pbSetupFailed = false;
    ResetObserved ( );
    bool bOk = true;

    //  THE FENCED HUB.  Fully provisioned, so its arming has nothing to do
    //  with this phase - phase 8 is where an unprovisioned hub is asked about.
    TrustHub oFence ( kSrvAddr[7], true, kCliAddr[7], 0 );
    if ( oFence.SetIdentity  ( sSrvKey.c_str ( ) ) != p2pcng::IdOk ||
         oFence.SetAllowList ( sSrvAcl.c_str ( ) ) != p2pcng::IdOk )
    { *pbSetupFailed = true; return false; }
    oFence.RequireAuth          ( true  );
    oFence.RequireRevocation    ( false );
    oFence.RequireTrustAtLeast  ( P2PeerConTrust_InProcess );

    if ( oFence.GetRequiredTrust ( ) != P2PeerConTrust_InProcess )
    {
        std::printf ( "  the fence did not take: GetRequiredTrust()=%s\n",
                      TrustName ( (int)oFence.GetRequiredTrust ( ) ) );
        std::fflush ( stdout );
        return false;
    }

    HANDLE hFence = oFence.SpawnHub ( );
    if ( !hFence ) { *pbSetupFailed = true; return false; }

    //  A plain socket.  Wire - no peer and no loopback bind - and two classes
    //  below the floor.
    {
        P2PeerConWsa *p = P2PeerConWsa::ServiceFactory ( L"LinkTrust.F1", nPort );
        if ( !p ) { *pbSetupFailed = true; }
        else
        {
            const BOOL b = oFence.PostP2PeerCon ( p );
            std::printf ( "  fenced hub, Wire  socket posted: %s  expected refused\n",
                          b ? "ACCEPTED" : "refused" );
            std::fflush ( stdout );
            bOk = !b && bOk;
        }
    }

    //  A loopback-scoped socket.  Local, which is ONE class below the floor
    //  and is the interesting case: it is the class an operator most easily
    //  believes is close enough to in-process, and the fence does not read it
    //  that way.
    {
        P2PeerConWsa *p = P2PeerConWsa::ServiceFactory ( L"LinkTrust.F2",
                                                         (short)( nPort + 1 ) );
        if ( !p ) { *pbSetupFailed = true; }
        else
        {
            p->SetListenScope ( P2PeerConScope_Loopback );
            const BOOL b = oFence.PostP2PeerCon ( p );
            std::printf ( "  fenced hub, Local socket posted: %s  expected refused\n",
                          b ? "ACCEPTED" : "refused" );
            std::fflush ( stdout );
            bOk = !b && bOk;
        }
    }

    //  ...and the class the hub was fenced TO.  Without this the phase would
    //  pass against a fence that refuses everything, which is not a fence.
    {
        P2PeerConDmx *p = P2PeerConDmx::ServiceFactory ( kCliAddr[7],
                                                         L"LinkTrustFence" );
        if ( !p ) { *pbSetupFailed = true; }
        else
        {
            const BOOL b = oFence.PostP2PeerCon ( p );
            std::printf ( "  fenced hub, DMX          posted: %s  expected accepted\n",
                          b ? "accepted" : "REFUSED" );
            std::fflush ( stdout );
            bOk = ( b != 0 ) && bOk;
        }
    }

    oFence.CloseHub ( );
    WaitForSingleObject ( hFence, 5000 );
    CloseHandle ( hFence );
    Sleep ( kSettleMs );

    //  THE CONTROL, and it is the half that attributes the refusals above to
    //  the fence rather than to anything else about a socket on this hub: the
    //  same connection, on a hub identical but for the one call.
    {
        TrustHub oOpen ( kSrvAddr[8], true, kCliAddr[8], 0 );
        if ( oOpen.SetIdentity  ( sSrvKey.c_str ( ) ) != p2pcng::IdOk ||
             oOpen.SetAllowList ( sSrvAcl.c_str ( ) ) != p2pcng::IdOk )
        { *pbSetupFailed = true; return false; }
        oOpen.RequireAuth       ( true  );
        oOpen.RequireRevocation ( false );

        if ( oOpen.GetRequiredTrust ( ) != P2PeerConTrust_Wire )
        {
            std::printf ( "  an unconfigured hub reports a fence of %s, not Wire\n",
                          TrustName ( (int)oOpen.GetRequiredTrust ( ) ) );
            std::fflush ( stdout );
            bOk = false;
        }

        HANDLE hOpen = oOpen.SpawnHub ( );
        if ( !hOpen ) { *pbSetupFailed = true; return false; }
        P2PeerConWsa *p = P2PeerConWsa::ServiceFactory ( L"LinkTrust.F3",
                                                         (short)( nPort + 2 ) );
        if ( !p ) { *pbSetupFailed = true; }
        else
        {
            const BOOL b = oOpen.PostP2PeerCon ( p );
            std::printf ( "  UNfenced hub, Wire socket posted: %s  expected accepted\n",
                          b ? "accepted" : "REFUSED" );
            std::fflush ( stdout );
            bOk = ( b != 0 ) && bOk;
        }
        oOpen.CloseHub ( );
        WaitForSingleObject ( hOpen, 5000 );
        CloseHandle ( hOpen );
        Sleep ( kSettleMs );
    }

    return bOk;
}

// =========================================================================
//  Phase 8 - THE ARM GATE.  ArmNotRequiredByPolicy.
//
//  securityRevision.md 8.3 phase 8, and 6.5.  A hub that requires
//  authentication, has fenced out every class it will not carry and has opened
//  every class it will, can never demand a signature from anybody - so the
//  identity and allow-list files it would demand one WITH are files it will
//  never open, and refusing to start for want of them refuses a hub that is
//  not misconfigured.
//
//  NO FILES ARE PROVISIONED IN THIS PHASE AND THAT IS THE POINT.  Every other
//  hub in this test is fully keyed even where all its links are Open, because
//  until this landed that is what the library demanded.  This one holds
//  nothing at all.
//
//  SIX READINGS, and the four in the middle are the ones worth having.  BOTH
//  halves of the condition have to be present for the verdict to change, and
//  each reading moves exactly one of them:
//
//     fence   InProcess policy   Local policy    must arm as
//     -----   ----------------   ------------    -----------------------
//     none    Full               Full            ArmNoIdentity
//     InProc  Full               Full            ArmNoIdentity   <- the fence
//                                                                  alone is
//                                                                  not enough
//     InProc  Open               Full            NotRequiredByPolicy
//     Local   Open               Full            ArmNoIdentity   <- a class it
//                                                                  would hold
//                                                                  is not open
//     Local   Open               Open            NotRequiredByPolicy
//     none    Open               Open            ArmNoIdentity   <- no fence,
//                                                                  so a wire
//                                                                  can arrive
//
//  The last row is the one an implementation gets wrong first: with both
//  relaxable classes opened it reads as "there is nothing left to demand", and
//  that is false.  Without a floor, the next PostP2PeerCon may hand this hub a
//  socket - class Wire, policy Full and not settable otherwise - which would
//  then be asked for a signature by a hub holding no key to check one with.
// =========================================================================
static bool ArmIs ( const char *pszWhat, P2PeerHub &rHub,
                    p2pauth::ArmResult eExpect )
{
    const p2pauth::ArmResult eGot = rHub.AuthArm ( );
    const bool bOk = ( eGot == eExpect );
    std::printf ( "  %-38s arm=%d expected %d  %s\n",
                  pszWhat, (int)eGot, (int)eExpect,
                  bOk ? "ok" : "*** WRONG ***" );
    std::fflush ( stdout );
    return bOk;
}

static bool PhaseEight ( bool *pbSetupFailed )
{
    *pbSetupFailed = false;
    ResetObserved ( );
    bool bOk = true;

    //  Deliberately unprovisioned: no SetIdentity, no SetAllowList, and no
    //  RequireAuth(false) either.  This hub asks for authentication and then
    //  describes a set of links on which there is none of it left to do.
    TrustHub oHub ( kSrvAddr[9], true, kCliAddr[9], 0 );
    oHub.RequireAuth       ( true  );
    oHub.RequireRevocation ( false );

    bOk = ArmIs ( "no fence, nothing open", oHub,
                  p2pauth::ArmNoIdentity ) && bOk;

    oHub.RequireTrustAtLeast ( P2PeerConTrust_InProcess );
    bOk = ArmIs ( "fence InProcess, nothing open", oHub,
                  p2pauth::ArmNoIdentity ) && bOk;

    oHub.SetLinkPolicy ( P2PeerConTrust_InProcess, P2PeerLinkPolicy_Open );
    bOk = ArmIs ( "fence InProcess, InProcess open", oHub,
                  p2pauth::ArmNotRequiredByPolicy ) && bOk;

    oHub.RequireTrustAtLeast ( P2PeerConTrust_Local );
    bOk = ArmIs ( "fence Local, only InProcess open", oHub,
                  p2pauth::ArmNoIdentity ) && bOk;

    oHub.SetLinkPolicy ( P2PeerConTrust_Local, P2PeerLinkPolicy_Open );
    bOk = ArmIs ( "fence Local, Local and InProcess open", oHub,
                  p2pauth::ArmNotRequiredByPolicy ) && bOk;

    oHub.RequireTrustAtLeast ( P2PeerConTrust_Wire );
    bOk = ArmIs ( "NO fence, Local and InProcess open", oHub,
                  p2pauth::ArmNoIdentity ) && bOk;

    if ( !bOk )
      return false;

    //  ...and the verdict that reaches an operator: it STARTS.  Everything
    //  above is a query; this is the gate CreateHub()/SpawnHub() actually run,
    //  and until this landed it refused this hub for want of a key it will
    //  never use.
    oHub.RequireTrustAtLeast ( P2PeerConTrust_InProcess );
    HANDLE h = oHub.SpawnHub ( );
    std::printf ( "  %-38s %s\n", "fenced+opened hub with NO key files",
                  h ? "SPAWNED" : "*** REFUSED ***" );
    std::fflush ( stdout );
    if ( !h )
      return false;

    oHub.CloseHub ( );
    WaitForSingleObject ( h, 5000 );
    CloseHandle ( h );
    Sleep ( kSettleMs );
    return true;
}

// -------------------------------------------------------------------------
static void Report ( int nPhase, const char *pszWhat, bool bArrived )
{
    std::printf ( "[linktrust] phase %d (%s): login=%s payload=%s "
                  "keyx=%d cypher=%d authed=%d loginTrust=%s "
                  "child=%s/%s\n",
                  nPhase, pszWhat,
                  g_obs.bLogin   ? "YES" : "no",
                  bArrived       ? "YES" : "no",
                  g_obs.bKeyXDone ? 1 : 0,
                  g_obs.bCypher   ? 1 : 0,
                  g_obs.bAuthed   ? 1 : 0,
                  TrustName ( g_obs.nLoginTrust ),
                  g_obs.bAccept ? TrustName ( g_obs.nChildClass ) : "-",
                  g_obs.bAccept ? TrustName ( g_obs.nChildTrust ) : "-" );
    std::fflush ( stdout );
}

// =========================================================================
//  NO MODAL DIALOG, EVER.
//  NOTES: A debug ASSERT inside the library pops a MODAL dialog by default,
//         on whichever thread raised it - which for this suite is a hub's
//         PUMP thread.  Nobody is there to click it: under ctest the run
//         stalls until the TIMEOUT and is reported as a failure with no
//         diagnostic, and on a developer's desktop it interrupts them.  Either
//         way the one thing that never happens is that the assertion text gets
//         recorded, which is the only part of it worth having
//       : Routed to stderr and EXECUTION CONTINUES (return TRUE, *pnRet 0 =
//         handled, do not break).  The same shape TestFramework.cpp uses for
//         the harnesses that go through it; this file has its own main and so
//         needs its own copy
//       : P2Pevent::ForceTextOutput(true) is the other half and covers the
//         LIBRARY's own error dialog, which is a different mechanism from the
//         CRT's - refer Msgexception.h.  It is what P2PMSG_NO_UI=1 and
//         "ErrToMessageBox: 0" in P2Pmsg.cfg say from outside the process, and
//         a test should not depend on its environment having said it
//       : SetErrorMode takes the LAST one: the Windows Error Reporting box for
//         a hard fault.  A fault is still a failure and still kills the
//         process; what it must not do is wait for a human first
//  WHAT abort() WAS CALLED FOR.
//  NOTES: The suite's long-standing intermittent death is an abort() with no
//         diagnostic, which is what an UNHANDLED exception on a hub's pump
//         thread looks like from outside.  std::terminate runs before the
//         stack is gone, and current_exception() still holds the object, so
//         rethrowing it here is the one place its text can still be read
//       : P2Pevent is thrown as a RAW POINTER by this tree's EVERR->Throw(),
//         hence the pointer catch before the std::exception one
//       : This handler does not make the process survive - it must not.  It
//         makes the abort say what it was for, and then lets the default
//         terminate end the run as it would have
static std::terminate_handler g_pfnPrevTerminate = 0;

static void LinkTrustOnTerminate ( )
{
    std::printf ( "\n[linktrust] *** TERMINATE - an exception reached the top of a "
                  "thread\n" );
    try
    {
        std::exception_ptr p = std::current_exception ( );
        if ( p ) std::rethrow_exception ( p );
        std::printf ( "[linktrust]     ...with no exception in flight\n" );
    }
    catch ( P2Pevent *pEVT )
    {
        if ( pEVT )
        {
            std::printf ( "[linktrust]     P2Pevent %s in %s\n"
                          "[linktrust]     %s\n"
                          "[linktrust]     ADVICE: %s\n",
                          N ( pEVT->GetClassText ( ) ).c_str ( ),
                          N ( pEVT->GetModule    ( ) ).c_str ( ),
                          N ( pEVT->GetMessage   ( ) ).c_str ( ),
                          N ( pEVT->GetAdvice    ( ) ).c_str ( ) );
            pEVT->Cancel ( false );
        }
        else
            std::printf ( "[linktrust]     P2Pevent: (null)\n" );
    }
    catch ( const std::exception &e )
    {
        std::printf ( "[linktrust]     std::exception: %s\n", e.what ( ) );
    }
    catch ( ... )
    {
        std::printf ( "[linktrust]     (an exception of unknown type)\n" );
    }
    std::fflush ( stdout );
    if ( g_pfnPrevTerminate ) g_pfnPrevTerminate ( );
    std::abort ( );
}

#ifdef _WIN32
static int __cdecl LinkTrustAssertHook ( int nReportType, char *szMsg, int *pnRet )
{
    if ( nReportType == _CRT_ASSERT || nReportType == _CRT_ERROR )
    {
        std::printf ( "[linktrust] *** ASSERT: %s\n",
                      szMsg ? szMsg : "(no message)" );
        std::fflush ( stdout );
        if ( pnRet ) *pnRet = 0;      // do not invoke the debugger
        return TRUE;                  // handled -> continue
    }
    return FALSE;
}
#endif

int main ( int argc, char *argv[] )
{
#ifdef _WIN32
    _CrtSetReportMode ( _CRT_ASSERT, _CRTDBG_MODE_FILE );
    _CrtSetReportFile ( _CRT_ASSERT, _CRTDBG_FILE_STDERR );
    _CrtSetReportMode ( _CRT_ERROR,  _CRTDBG_MODE_FILE );
    _CrtSetReportFile ( _CRT_ERROR,  _CRTDBG_FILE_STDERR );
    _CrtSetReportHook ( LinkTrustAssertHook );
    SetErrorMode ( SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
                   SEM_NOOPENFILEERRORBOX );
#endif
    g_pfnPrevTerminate = std::set_terminate ( LinkTrustOnTerminate );
    P2Pevent::ForceTextOutput ( true );

    short nPort = ( argc >= 2 ) ? (short)atoi ( argv[1] ) : 7853;

    std::printf ( "=== p2p_linktrust - is a relaxation bounded by what the transport vouches for? ===\n" );
    std::printf ( "Ports: %d (phases 4-6), %d (phase 7)\n",
                  (int)nPort, (int)nPort + 3 );
    std::printf ( "Pipes: %s and the same for phase 10\n",
                  N ( PipeName ( 9 ).c_str ( ) ).c_str ( ) );
    std::printf ( "Asserting: an in-process link may skip the handshake when its hub\n"
                  "           says so, a loopback link on the same hub may not, a\n"
                  "           connection demoted on the listener stays demoted on the\n"
                  "           child the listener accepts, a fenced hub refuses a link\n"
                  "           below its floor outright, a hub that has fenced and\n"
                  "           opened everything it will carry arms with no key files,\n"
                  "           and a named pipe is Local when this transport made it so\n"
                  "           and Wire when it was asked for the old one.\n\n" );
    std::fflush ( stdout );

    // ---- Phase 0 ----------------------------------------------------------
    Log ( "--- phase 0: what each transport vouches for ---" );
    if ( !PhaseZero ( ) )
    {
        std::printf (
          "\nRESULT: FAIL - a transport declares the wrong trust class, or the\n"
          "  demotion is not monotonic. Every later phase reads these answers, so\n"
          "  nothing below this line would have meant what it said.\n" );
        return 1;
    }
    Log ( "phase 0 OK - the declarations are the ones the policy reads" );

    g_hPayload   = CreateEvent ( NULL, TRUE, FALSE, NULL );
    g_hLogin     = CreateEvent ( NULL, TRUE, FALSE, NULL );
    g_hListening = CreateEvent ( NULL, TRUE, FALSE, NULL );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }
    WSADATA oWsaData;
    WSAStartup ( MAKEWORD(2,2), &oWsaData );

    // ---- Provisioning -----------------------------------------------------
    const std::string sSrvKey = TempPath ( "srvkey" );
    const std::string sCliKey = TempPath ( "clikey" );
    const std::string sSrvAcl = TempPath ( "srvacl" );
    const std::string sCliAcl = TempPath ( "cliacl" );

    unsigned char pubSrv[p2pcng::kEcdsaPubLen];
    unsigned char pubCli[p2pcng::kEcdsaPubLen];
    if ( !MakeIdentity ( sSrvKey, pubSrv ) || !MakeIdentity ( sCliKey, pubCli ) )
    { Log ( "SETUP: identity generation failed" ); ScrubTempFiles ( ); return 2; }

    //  Every phase's pair, in both lists. An allow-list entry is an exact
    //  address and never a pattern, so a per-phase address means a per-phase
    //  line - six of each. One key on each side throughout: the phases differ
    //  by policy, and a second key would give them a second way to differ.
    //  Phases 7 and 8 never log anybody in, but phase 7's two hubs are
    //  provisioned like the rest - an allow-list that names NOBODY is
    //  ArmEmptyAllow and would refuse to spawn them, which would report a
    //  provisioning artefact as a fence that did not work.
    //  Phases 9 and 10 are addressed .SA/.CA and .SB/.CB - the table ran out
    //  of digits at ten, and hexadecimal-looking eleventh and twelfth entries
    //  are cheaper than renumbering ten addresses that appear in a hub
    //  registry, four allow-lists and every line of this test's output.
    static const char *kAcl[] = { "1", "2", "3", "4", "5", "6", "7", "8",
                                  "9", "A", "B" };
    for ( int i = 0; i < (int)( sizeof(kAcl) / sizeof(kAcl[0]) ); ++i )
    {
        char szSrv[32], szCli[32];
        std::snprintf ( szSrv, sizeof(szSrv), "LinkTrust.S%s", kAcl[i] );
        std::snprintf ( szCli, sizeof(szCli), "LinkTrust.C%s", kAcl[i] );
        if ( p2pcng::AppendAllowList ( sSrvAcl.c_str ( ), szCli, pubCli ) != p2pcng::IdOk ||
             p2pcng::AppendAllowList ( sCliAcl.c_str ( ), szSrv, pubSrv ) != p2pcng::IdOk )
        { Log ( "SETUP: allow-list provisioning failed" ); ScrubTempFiles ( ); return 2; }
    }

    int  nExit  = 0;
    bool bSetup = false;

    // ---- Phase 1: DMX, defaults - the positive control ---------------------
    Log ( "--- phase 1: DMX, both ends default (agreement must run) ---" );
    bool b1 = RunDmxPhase ( 1, sSrvKey, sSrvAcl, sCliKey, sCliAcl,
                            P2PeerLinkPolicy_Full, P2PeerLinkPolicy_Full,
                            kWaitDeliver, &bSetup );
    if ( bSetup ) { Log ( "SETUP: phase 1 failed" ); ScrubTempFiles ( ); return 2; }
    Report ( 1, "DMX full", b1 );
    const bool bFull1 = g_obs.bLogin && b1 && g_obs.bKeyXDone && g_obs.bAuthed &&
                        g_obs.nLoginTrust == (int)P2PeerConTrust_InProcess;
    if ( !bFull1 )
    {
        std::printf (
          "\nRESULT: INCONCLUSIVE - the DMX positive control did not complete a\n"
          "  full handshake, so nothing below it proves anything. This is NOT a\n"
          "  pass. Check dmx_mesh and p2p_authpsk first.\n" );
        nExit = 3;
    }

    //  Phase 1's cypher reading is asserted apart, because it is the ONE place
    //  a reader might expect a 1 and be right to. DMX answers 0 - the cypher
    //  is installed on a P2PeerioDmx that overrides both message methods and
    //  consults neither, which is F-S6-3's one legitimate exemption and is why
    //  the connection snapshot carries OffProcess beside Cypher.
    if ( nExit == 0 && g_obs.bCypher )
    {
        std::printf (
          "\nRESULT: FAIL - a DMX connection reports its cypher as CONSULTED.\n"
          "  P2PeerioDmx overrides SendP2PeerMsg/RecvP2PeerMsg and calls neither\n"
          "  hook, so this can only mean the transport changed under the test.\n" );
        nExit = 1;
    }

    // ---- Phase 2: DMX, both ends Open - the feature ------------------------
    if ( nExit == 0 )
    {
        Log ( "--- phase 2: DMX, SetLinkPolicy(InProcess, Open) BOTH ends "
              "(must deliver, with no handshake) ---" );
        bool b2 = RunDmxPhase ( 2, sSrvKey, sSrvAcl, sCliKey, sCliAcl,
                                P2PeerLinkPolicy_Open, P2PeerLinkPolicy_Open,
                                kWaitDeliver, &bSetup );
        if ( bSetup ) { Log ( "SETUP: phase 2 failed" ); ScrubTempFiles ( ); return 2; }
        Report ( 2, "DMX open", b2 );

        if ( !g_obs.bLogin || !b2 )
        {
            std::printf (
              "\nRESULT: FAIL - an in-process link whose hub opened its class did\n"
              "  not get through. SetLinkPolicy(InProcess, Open) is meant to be\n"
              "  the supported answer to paying for a handshake on a pointer\n"
              "  handoff; if it cannot carry a login and a message it is not one.\n" );
            nExit = 1;
        }
        else if ( g_obs.bKeyXDone || g_obs.bAuthed )
        {
            std::printf (
              "\nRESULT: FAIL - the link was OPENED and ran the handshake anyway\n"
              "  (keyx=%d authed=%d). The policy was read as the wrong value, or\n"
              "  KeyXWanted() is not composing the class into its answer, and the\n"
              "  cost the whole feature exists to remove is still being paid.\n",
              g_obs.bKeyXDone ? 1 : 0, g_obs.bAuthed ? 1 : 0 );
            nExit = 1;
        }
    }

    // ---- Phase 3: DMX, client Open only - the F-S6-1 regression ------------
    if ( nExit == 0 )
    {
        Log ( "--- phase 3: DMX, Open on the CLIENT hub only "
              "(server MUST refuse) ---" );
        bool b3 = RunDmxPhase ( 3, sSrvKey, sSrvAcl, sCliKey, sCliAcl,
                                P2PeerLinkPolicy_Full, P2PeerLinkPolicy_Open,
                                kWaitRefuse, &bSetup );
        if ( bSetup ) { Log ( "SETUP: phase 3 failed" ); ScrubTempFiles ( ); return 2; }
        Report ( 3, "DMX split", b3 );

        if ( g_obs.bLogin || b3 )
        {
            std::printf (
              "\nRESULT: FAIL - THE TWO ENDS READ DIFFERENT HALVES OF ONE SWITCH.\n"
              "  The client's hub opened its in-process class and the server's did\n"
              "  not, so the client ran no agreement and signed nothing - and the\n"
              "  server took the login anyway. That is F-S6-1 reintroduced through\n"
              "  the class rather than through RequireAuth: a connection reporting\n"
              "  itself logged in with no channel behind it, on a hub whose\n"
              "  operator asked for the full posture on this class.\n"
              "  Fix: AuthGateInbound() must ask KeyXWanted(), which composes the\n"
              "  hub's switch with this link's class, and not IsAuthRequired().\n" );
            nExit = 1;
        }
    }

    // ---- Phase 4: TCP on a hub that opened InProcess -----------------------
    if ( nExit == 0 )
    {
        Log ( "--- phase 4: TCP loopback on hubs with InProcess opened "
              "(must authenticate IN FULL) ---" );
        bool b4 = RunWsaPhase ( 4, sSrvKey, sSrvAcl, sCliKey, sCliAcl,
                                P2PeerLinkPolicy_Full, P2PeerLinkPolicy_Open,
                                false, nPort, kWaitDeliver, &bSetup );
        if ( bSetup ) { Log ( "SETUP: phase 4 failed" ); ScrubTempFiles ( ); return 2; }
        Report ( 4, "TCP, InProcess opened", b4 );

        if ( !g_obs.bLogin || !b4 )
        {
            std::printf (
              "\nRESULT: INCONCLUSIVE - the TCP control never got through, so\n"
              "  phases 5 and 6 prove nothing. Check wsa_mesh and p2p_authpsk.\n" );
            nExit = 3;
        }
        else if ( !g_obs.bKeyXDone || !g_obs.bAuthed || !g_obs.bCypher )
        {
            std::printf (
              "\nRESULT: FAIL - A RELAXATION LEAKED ACROSS CLASSES.\n"
              "  Both hubs opened P2PeerConTrust_InProcess and nothing else. This\n"
              "  link is a socket, its class is Local, and it completed without\n"
              "  the agreement (keyx=%d), without a verified login (authed=%d) or\n"
              "  without a consulted cypher (cypher=%d). A hub relaxed for the\n"
              "  links inside its own process would be a network endpoint nobody\n"
              "  opened, which is the failure the per-class policy exists to make\n"
              "  impossible.\n",
              g_obs.bKeyXDone ? 1 : 0, g_obs.bAuthed ? 1 : 0, g_obs.bCypher ? 1 : 0 );
            nExit = 1;
        }
        else if ( g_obs.nLoginTrust != (int)P2PeerConTrust_Local )
        {
            std::printf (
              "\nRESULT: FAIL - a loopback socket reported trust class %s, not\n"
              "  Local. The class is read from getpeername() on the accepted\n"
              "  child, so this says the kernel's answer is not reaching the\n"
              "  policy - and every later assertion about Local is meaningless.\n",
              TrustName ( g_obs.nLoginTrust ) );
            nExit = 1;
        }
    }

    // ---- Phase 5: TCP with Local opened - the control for phase 6 ----------
    if ( nExit == 0 )
    {
        Log ( "--- phase 5: TCP loopback with Local opened, no demotion "
              "(must deliver, with no handshake) ---" );
        bool b5 = RunWsaPhase ( 5, sSrvKey, sSrvAcl, sCliKey, sCliAcl,
                                P2PeerLinkPolicy_Open, P2PeerLinkPolicy_Full,
                                false, (short)( nPort + 1 ), kWaitDeliver, &bSetup );
        if ( bSetup ) { Log ( "SETUP: phase 5 failed" ); ScrubTempFiles ( ); return 2; }
        Report ( 5, "TCP, Local opened", b5 );

        if ( !g_obs.bLogin || !b5 || g_obs.bKeyXDone || g_obs.bAuthed )
        {
            std::printf (
              "\nRESULT: FAIL - the Local class did not honour its own policy\n"
              "  (login=%d payload=%d keyx=%d authed=%d). Phase 6 is this phase\n"
              "  plus one call, so without this as a control its refusal could\n"
              "  not be attributed to the demotion.\n",
              g_obs.bLogin ? 1 : 0, b5 ? 1 : 0,
              g_obs.bKeyXDone ? 1 : 0, g_obs.bAuthed ? 1 : 0 );
            nExit = 1;
        }
        else if ( !g_obs.bAccept ||
                  g_obs.nChildClass != (int)P2PeerConTrust_Local ||
                  g_obs.nChildTrust != (int)P2PeerConTrust_Local )
        {
            std::printf (
              "\nRESULT: FAIL - an UNDEMOTED accepted child read %s/%s rather than\n"
              "  Local/Local. Phase 6 measures a difference from this reading, so\n"
              "  it cannot mean anything until this one is right.\n",
              TrustName ( g_obs.nChildClass ), TrustName ( g_obs.nChildTrust ) );
            nExit = 1;
        }
    }

    // ---- Phase 6: the same, with the SERVICE demoted ----------------------
    if ( nExit == 0 )
    {
        Log ( "--- phase 6: phase 5 with the SERVICE demoted to Wire "
              "(child must inherit it, and the server MUST refuse) ---" );
        bool b6 = RunWsaPhase ( 6, sSrvKey, sSrvAcl, sCliKey, sCliAcl,
                                P2PeerLinkPolicy_Open, P2PeerLinkPolicy_Full,
                                true, (short)( nPort + 2 ), kWaitRefuse, &bSetup );
        if ( bSetup ) { Log ( "SETUP: phase 6 failed" ); ScrubTempFiles ( ); return 2; }
        Report ( 6, "TCP, Local opened, service demoted", b6 );

        if ( !g_obs.bAccept )
        {
            std::printf (
              "\nRESULT: INCONCLUSIVE - the server never accepted a connection in\n"
              "  phase 6, so the refusal below cannot be attributed to anything.\n" );
            nExit = 3;
        }
        else if ( g_obs.nChildClass != (int)P2PeerConTrust_Local ||
                  g_obs.nChildTrust != (int)P2PeerConTrust_Wire )
        {
            std::printf (
              "\nRESULT: FAIL - THE DEMOTION DID NOT REACH THE ACCEPTED CHILD.\n"
              "  The child read TrustClass=%s EffectiveTrust=%s; it must read\n"
              "  Local/Wire - the transport still vouches for a loopback socket,\n"
              "  and the operator's ceiling holds it below that. m_eTrustCeiling\n"
              "  is the ONE copied field in this feature and P2PeerCon::\n"
              "  AcceptSpawn is where it is copied. Without that line an operator\n"
              "  who demoted a listener demoted only the object that never\n"
              "  carries traffic.\n",
              TrustName ( g_obs.nChildClass ), TrustName ( g_obs.nChildTrust ) );
            nExit = 1;
        }
        else if ( g_obs.bLogin || b6 )
        {
            std::printf (
              "\nRESULT: FAIL - the child read Local/Wire and the server accepted\n"
              "  its login anyway. The class reached the snapshot and not the\n"
              "  gate: P2PeerLinkPolicy for the wire is Full and cannot be set\n"
              "  otherwise, so a link demoted to Wire must run the full handshake\n"
              "  however its hub has relaxed the class the transport vouches for.\n" );
            nExit = 1;
        }
    }

    // ---- Phase 7: the fence -----------------------------------------------
    if ( nExit == 0 )
    {
        Log ( "--- phase 7: RequireTrustAtLeast(InProcess) "
              "(a link below the floor must be REFUSED at post) ---" );
        const bool b7 = PhaseSeven ( sSrvKey, sSrvAcl, (short)( nPort + 3 ),
                                     &bSetup );
        if ( bSetup ) { Log ( "SETUP: phase 7 failed" ); ScrubTempFiles ( ); return 2; }
        if ( !b7 )
        {
            std::printf (
              "\nRESULT: FAIL - THE FENCE IS NOT A FENCE.\n"
              "  A hub told RequireTrustAtLeast(InProcess) must refuse a socket at\n"
              "  PostP2PeerCon and accept a DMX connection, and a hub told nothing\n"
              "  must accept both. Whichever of those three did not happen, the\n"
              "  effect is the same: SetLinkPolicy(InProcess, Open) is back to\n"
              "  being one PostP2PeerCon away from a hub that routes inside a\n"
              "  process quietly becoming a network endpoint - which is the whole\n"
              "  difference between this and RequireAuth(false).\n" );
            nExit = 1;
        }
        else
            Log ( "phase 7 OK - the floor holds, and only where it was set" );
    }

    // ---- Phase 8: the arm gate --------------------------------------------
    if ( nExit == 0 )
    {
        Log ( "--- phase 8: a hub with NO key files, fenced and opened "
              "(must arm as ArmNotRequiredByPolicy) ---" );
        const bool b8 = PhaseEight ( &bSetup );
        if ( bSetup ) { Log ( "SETUP: phase 8 failed" ); ScrubTempFiles ( ); return 2; }
        if ( !b8 )
        {
            std::printf (
              "\nRESULT: FAIL - the arming gate does not agree with the policy it\n"
              "  is gating. A hub that has fenced out every class it will not\n"
              "  carry and opened every class it will can never demand a signature\n"
              "  from anybody, so the files it would demand one WITH are files it\n"
              "  will never open; refusing to start for want of them refuses a hub\n"
              "  that is not misconfigured. BOTH halves are required, and the\n"
              "  reading above says which one was not read: a fence with a class\n"
              "  still Full, or opened classes with no fence at all, must each\n"
              "  still report ArmNoIdentity.\n" );
            nExit = 1;
        }
        else
            Log ( "phase 8 OK - it arms on the policy, and only on both halves of it" );
    }

    // ---- Phase 9: the pipe is Local now -----------------------------------
    if ( nExit == 0 )
    {
        Log ( "--- phase 9: a named pipe at its default access, Local opened "
              "(must deliver, with no handshake, and the child must read Local) ---" );
        const bool b9 = RunPipePhase ( 9, 10, sSrvKey, sSrvAcl, sCliKey, sCliAcl,
                                       P2PeerConPipeAccess_Owner, false,
                                       kWaitDeliver, &bSetup );
        if ( bSetup ) { Log ( "SETUP: phase 9 failed" ); ScrubTempFiles ( ); return 2; }
        Report ( 9, "pipe, owner access, Local opened", b9 );

        if ( !g_obs.bAccept ||
             g_obs.nChildClass != (int)P2PeerConTrust_Local )
        {
            std::printf (
              "\nRESULT: FAIL - A NAMED PIPE THIS TRANSPORT CREATED DID NOT READ\n"
              "  LOCAL. The accepted child read TrustClass=%s. m_bPipeLocal is\n"
              "  derived from the pipe mode and the security attributes actually\n"
              "  handed to CreateNamedPipe, so this says one of them did not get\n"
              "  there: PIPE_REJECT_REMOTE_CLIENTS, without which the endpoint is\n"
              "  reachable over SMB from another host, or the explicit descriptor,\n"
              "  without which it keeps the platform default that grants Everyone\n"
              "  and Anonymous read access. Both are required and neither is\n"
              "  optional - a policy must not be allowed to rely on a locality the\n"
              "  code does not make true.\n",
              g_obs.bAccept ? TrustName ( g_obs.nChildClass ) : "no child at all" );
            nExit = 1;
        }
        else if ( !g_obs.bLogin || !b9 )
        {
            std::printf (
              "\nRESULT: FAIL - the child read Local and the link still did not get\n"
              "  through (login=%d payload=%d). The hub opened the Local class, so\n"
              "  a pipe carrying that class should have logged in with no handshake\n"
              "  at all; check pipe_mesh first, since a pipe that cannot carry a\n"
              "  login is not this feature's failure.\n",
              g_obs.bLogin ? 1 : 0, b9 ? 1 : 0 );
            nExit = 1;
        }
        else if ( g_obs.bKeyXDone || g_obs.bAuthed )
        {
            std::printf (
              "\nRESULT: FAIL - the pipe read Local, its hub opened Local, and the\n"
              "  handshake ran anyway (keyx=%d authed=%d). The class reached the\n"
              "  snapshot and not KeyXWanted().\n",
              g_obs.bKeyXDone ? 1 : 0, g_obs.bAuthed ? 1 : 0 );
            nExit = 1;
        }
    }

    // ---- Phase 10: the legacy pipe is a wire ------------------------------
    if ( nExit == 0 )
    {
        Log ( "--- phase 10: the same pipe asked for P2PeerConPipeAccess_Legacy "
              "(must read Wire and authenticate IN FULL) ---" );
        const bool b10 = RunPipePhase ( 10, 11, sSrvKey, sSrvAcl, sCliKey, sCliAcl,
                                        P2PeerConPipeAccess_Legacy, true,
                                        kWaitDeliver, &bSetup );
        if ( bSetup ) { Log ( "SETUP: phase 10 failed" ); ScrubTempFiles ( ); return 2; }
        Report ( 10, "pipe, legacy access, Local opened", b10 );

        if ( !g_obs.bAccept ||
             g_obs.nChildClass != (int)P2PeerConTrust_Wire )
        {
            std::printf (
              "\nRESULT: FAIL - A LEGACY PIPE CLAIMED A CLASS IT CANNOT KEEP.\n"
              "  The accepted child read TrustClass=%s and must read Wire.\n"
              "  P2PeerConPipeAccess_Legacy reproduces the pre-revision\n"
              "  CreateNamedPipe byte for byte - no PIPE_REJECT_REMOTE_CLIENTS, a\n"
              "  NULL descriptor - and that pipe is reachable over SMB from another\n"
              "  host. It exists so a deployment that shares a pipe across accounts\n"
              "  can keep working, and the whole point of naming it is that it does\n"
              "  NOT get to claim the class the new default earns.\n",
              g_obs.bAccept ? TrustName ( g_obs.nChildClass ) : "no child at all" );
            nExit = 1;
        }
        else if ( !g_obs.bLogin || !b10 )
        {
            std::printf (
              "\nRESULT: INCONCLUSIVE - the legacy pipe never completed a login\n"
              "  (login=%d payload=%d), so what it would have skipped cannot be\n"
              "  read. Both ends are on Wire here, which is the posture phase 1\n"
              "  runs over DMX and phase 4 over TCP.\n",
              g_obs.bLogin ? 1 : 0, b10 ? 1 : 0 );
            nExit = 3;
        }
        else if ( !g_obs.bKeyXDone || !g_obs.bAuthed || !g_obs.bCypher )
        {
            std::printf (
              "\nRESULT: FAIL - A WIRE-CLASS LINK SKIPPED THE HANDSHAKE\n"
              "  (keyx=%d authed=%d cypher=%d). Its hub opened the LOCAL class and\n"
              "  this link is not in it: a pipe made the old way is reachable from\n"
              "  another machine, and the wire's policy is Full and cannot be set\n"
              "  otherwise. securityRevision.md 8.3 phase 6.\n",
              g_obs.bKeyXDone ? 1 : 0, g_obs.bAuthed ? 1 : 0, g_obs.bCypher ? 1 : 0 );
            nExit = 1;
        }
    }

    if ( nExit == 0 )
        std::printf (
          "\nRESULT: PASS - an in-process link skips the handshake when its hub\n"
          "  says so and not otherwise; a loopback link on a hub relaxed for\n"
          "  in-process links still authenticates in full; the two ends of a\n"
          "  relaxed link must agree or the login is refused; a connection\n"
          "  demoted on the listener is still demoted on the child the listener\n"
          "  accepts; a fenced hub refuses a link below its floor at the moment\n"
          "  it is posted; a hub that has fenced and opened every class it\n"
          "  will carry arms with no key files, while one missing either half of\n"
          "  that still does not; and a named pipe reads Local when this\n"
          "  transport made it local and Wire when it was asked for the pipe the\n"
          "  platform used to give it.\n" );

    ScrubTempFiles ( );
    WSACleanup ( );
    CleanupP2Pmsg ( );
    if ( g_hPayload   ) CloseHandle ( g_hPayload   );
    if ( g_hLogin     ) CloseHandle ( g_hLogin     );
    if ( g_hListening ) CloseHandle ( g_hListening );
    return nExit;
}
