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
// p2p_linkcost.cpp — what does a posture cost a message?
//
// securityRevision.md §8.4, "the measurement that has not been made", and
// §8.2 step 5. It is quoted here in full because the whole of this file is an
// answer to it and nothing else:
//
//     Nothing in the tree times the security path; the figures in §3 are
//     operation counts. Before §6.3 is decided, one run of dmx_mesh extended
//     to three in-process hubs in a chain, N messages of a fixed size, under
//     four postures: everything off; RequireAuth only; plus attestation; plus
//     seal. Report messages per second and CPU time per message. The result
//     decides whether the end-to-end waiver is worth its assumption or whether
//     §6.2 alone recovers what matters.
//
// THE DECISION IT FEEDS. §6.3 would let a hub skip relay attestation and
// sealing for a destination that is a hub IN THIS PROCESS. That waiver is the
// one thing in the whole proposal that cannot be made fail-closed by
// construction — it holds only if a message to an in-process hub never
// transits an out-of-process one, which is a DEPLOYMENT rule and not a fact
// the library can check. A rule like that has to be paid for. This measures
// what it would buy.
//
// THE TOPOLOGY, and it is §8.4's, extended by one hub from dmx_mesh's two:
//
//       Cost<n>.Alice  --Dmx-->  Cost<n>  --Dmx-->  Cost<n>.Carol
//         (origin)              (relay)             (destination)
//
// Three hubs, two in-process Dmx links, real pumps, real login, library
// routing. No socket and no OS handle anywhere on the path, which is the
// point: this is the shape §6.3 is about, so any cost measured here is a cost
// paid for a threat that has no way in.
//
// <n> IS THE POSTURE INDEX AND THE ADDRESSES ARE PER POSTURE. Reusing one
// address across five teardown/rebuild cycles is the process-wide-registry
// race that cost a debugging session in step 4, and the fix there was the same
// as the fix here: a table, indexed explicitly. The Dmx service names are
// per-posture for the same reason — P2PeerConDmx::Connect matches a listener
// by service name out of a process-wide list.
//
// THE FIVE POSTURES. §8.4 asked for four; the fifth is the one that answers
// its closing question ("or whether §6.2 alone recovers what matters"), and it
// could not have been asked before step 2 landed.
//
//   A  everything off              RequireAuth/RelayAuth/Seal all false
//   B  RequireAuth only            + the link handshake, per connection
//   C  + relay attestation         + an ECDSA signature per message at origin
//   D  + seal                      + an ECIES seal per message, opened at the
//                                    destination.  THIS IS THE TREE'S DEFAULT
//                                    POSTURE — all three of those flags
//                                    initialise TRUE (P2PAuthLogin.cpp:497+),
//                                    so D is what a hub that calls nothing
//                                    gets today
//   E  D + SetLinkPolicy(InProcess, Open) on all three hubs — §6.2, i.e. what
//      step 2 already shipped.  E vs D is what §6.2 recovers; E vs A is what
//      is LEFT, and what is left is the only thing §6.3 could take away
//
// WHAT IS MEASURED. Wall time and PROCESS CPU time (kernel+user, every thread)
// across the delivery of N messages of a fixed body size, plus an idle
// baseline taken with the same three hubs up and no traffic — subtracted, so
// the per-message figure is not mostly pump timeouts. Both the raw and the
// corrected number are printed; a reader who distrusts the correction has the
// raw one.
//
// FLOW CONTROL, AND WHY THERE IS ANY. s_cP2PmsgMAX bounds the live messages in
// a process and there are high/low marks below it (p2p_backpressure). A test
// that posted N messages as fast as a loop can would measure the brake rather
// than the posture. The sender holds a window of messages in flight and waits
// on an event when it is full; the destination decrements the count and signals
// the event. THAT COUNTER IS TEST SCAFFOLDING AND NOT TRAFFIC — everything is
// in one process, so it costs a shared atomic and no message.
//
// WHAT THIS TOPOLOGY CANNOT SEE, and it is not a small thing.
//
//   P2PeerCon::GateAppMsgInbound reaches GateRelayInbound ONLY on an ancestor
//   link carrying a source that is NOT at-or-below the peer that delivered it.
//   Every hub in a chain like this one is a common ancestor of the two ends —
//   Cost is above Cost.Alice — so the descendant test admits the message and
//   the VERIFY never runs. The library says so itself, in that function's own
//   notes, and names p2p_sealhop's identical shape as the reason deleting the
//   branch once left the whole suite green.
//
//   So the attestation cost measured in posture C is ONE SIGNATURE AT THE
//   ORIGIN and no verification anywhere. That is honest for this topology and
//   it is not the whole cost in a topology where the gate fires. Part 2 below
//   closes that gap by timing the primitives directly.
//
// PART 2 — THE PRIMITIVES. AttestRelay / VerifyRelay / SealFor / OpenFrom are
// public on P2PeerHub, so each is timed on its own, N iterations, on a hub that
// is constructed and provisioned but never spawned. This is the part that
// generalises: it says what one attestation and one seal COST, independent of
// how often a given tree shape happens to call them. Blocks are pre-generated
// so the verify and open loops time only the verify and the open.
//
// VERDICT = process EXIT CODE, AND IT IS NOT A PERFORMANCE ASSERTION.
//
//   0  OK          every posture delivered all N messages; the numbers printed
//   2  SETUP       startup / key generation / connection failure
//   3  INCOMPLETE  a posture did not deliver N within its timeout, so its
//                  numbers describe a stall rather than a posture
//
// There is deliberately NO threshold on messages per second. A timing bound in
// ctest is a flake on someone else's build machine, and this file exists to
// produce a number for a document to argue over, not to fail a build. What it
// DOES assert is delivery — a posture that quietly dropped its traffic would
// otherwise post the best throughput in the table.

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConDmx.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"
#include "P2PIdentityStore.h"
#include "P2PAuthLogin.h"
#include "P2PeerSeal.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <atomic>
#include <chrono>
#include <exception>

#ifndef _WIN32
#  include <sys/resource.h>
#endif

// ---------------------------------------------------------------------------
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
    std::printf ( "[linkcost] %s\n", msg );
    std::fflush ( stdout );
}

// ---------------------------------------------------------------------------
//  Time.
//  NOTES: Wall is steady_clock, which is monotonic on both toolchains.
//       : CPU is the WHOLE PROCESS, kernel plus user, every thread - which is
//         the only figure worth having here.  The work is spread over three
//         pump threads and their IO callbacks, so a per-thread or
//         per-call-site measurement would attribute a seal to whichever thread
//         happened to run it and miss the two hops that carried the result
static double WallSeconds ( )
{
    using namespace std::chrono;
    return duration_cast< duration<double> > (
             steady_clock::now ( ).time_since_epoch ( ) ).count ( );
}

//  How coarse is CpuSeconds()?
//  NOTES: GetProcessTimes accumulates on the SCHEDULER TICK - 15.625 ms on a
//         stock Windows kernel - so a CPU figure is quantised at that step no
//         matter how carefully the interval around it is measured.  Divided by
//         N that is 52 us per message at N=300 and 0.8 us at N=20000, which is
//         the difference between a column that says nothing and one that
//         decides something
//       : PRINTED rather than commented, because a reader looking at the table
//         has to be able to see whether the differences between two rows are
//         bigger than the instrument.  A measurement that does not carry its
//         own resolution is an opinion
static double CpuTickSeconds ( )
{
#ifdef _WIN32
    //  The tick the process times are accumulated on.  GetSystemTimeAdjustment
    //  reports it in 100ns units; the second output is the period whether or
    //  not adjustment is disabled, which is what is wanted here
    DWORD dwAdj = 0, dwIncrement = 0; BOOL bDisabled = FALSE;
    if ( GetSystemTimeAdjustment ( &dwAdj, &dwIncrement, &bDisabled ) &&
         dwIncrement > 0 )
      return (double)dwIncrement * 1e-7;
    return 0.015625;
#else
    return 0.0;   // getrusage is microsecond-resolution on glibc
#endif
}

static double CpuSeconds ( )
{
#ifdef _WIN32
    FILETIME ftCreate, ftExit, ftKernel, ftUser;
    if ( !GetProcessTimes ( GetCurrentProcess ( ), &ftCreate, &ftExit,
                            &ftKernel, &ftUser ) )
      return 0.0;
    ULARGE_INTEGER uK, uU;
    uK.LowPart  = ftKernel.dwLowDateTime;
    uK.HighPart = ftKernel.dwHighDateTime;
    uU.LowPart  = ftUser.dwLowDateTime;
    uU.HighPart = ftUser.dwHighDateTime;
    //  FILETIME ticks are 100ns
    return (double)( uK.QuadPart + uU.QuadPart ) * 1e-7;
#else
    struct rusage ru;
    if ( getrusage ( RUSAGE_SELF, &ru ) != 0 )
      return 0.0;
    return (double)ru.ru_utime.tv_sec + (double)ru.ru_utime.tv_usec * 1e-6
         + (double)ru.ru_stime.tv_sec + (double)ru.ru_stime.tv_usec * 1e-6;
#endif
}

// ---------------------------------------------------------------------------
//  Provisioning.  Private keys stay in their files; only public points are
//  published into the other hub's allow-list.  Lifted from p2p_sealhop, which
//  provisions the same three roles for the same reason.
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
                    (unsigned long)GetCurrentProcessId ( ) );
    s += "p2p_linkcost_"; s += pszLeaf; s += "_"; s += szPid; s += ".tmp";
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
    if ( !oKey.Generate ( ) )                                          return false;
    if ( p2pcng::SaveIdentity ( sPath.c_str ( ), oKey ) != p2pcng::IdOk ) return false;
    return oKey.ExportPublic ( pPubOut );
}

static bool MakeAgreement ( const std::string &sPath, unsigned char *pPubOut )
{
    p2pcng::EcdhP256 oKey;
    if ( !oKey.Generate ( ) )                                           return false;
    if ( p2pcng::SaveAgreement ( sPath.c_str ( ), oKey ) != p2pcng::IdOk ) return false;
    return oKey.ExportPublic ( pPubOut );
}

// ---------------------------------------------------------------------------
//  The postures.  §8.4 asked for the first four.
// ---------------------------------------------------------------------------
struct Posture
{
    const char *pszName;
    bool        bAuth;      // RequireAuth        - the per-hop handshake
    bool        bAttest;    // RequireRelayAuth   - a signature per message
    bool        bSeal;      // RequireSeal        - an ECIES envelope per message
    bool        bOpen;      // SetLinkPolicy(InProcess, Open) - §6.2, step 2
};

static const int     kPostures = 5;
static const Posture kPost[kPostures] =
{ { "A  everything off",                    false, false, false, false }
, { "B  RequireAuth only",                  true,  false, false, false }
, { "C  + relay attestation",               true,  true,  false, false }
, { "D  + seal   (the tree's defaults)",    true,  true,  true,  false }
, { "E  D + SetLinkPolicy(InProcess,Open)", true,  true,  true,  true  }
};

//  ONE ROW PER POSTURE, and the addresses are NOT derived from a loop index at
//  the point of use.  Refer the header: the same shortcut in p2p_linktrust put
//  two phases on one hub address a millisecond apart and produced a failure
//  indistinguishable from a real one.
static const P2PaddrSTR kMidAddr[kPostures] =
{ L"Cost0",       L"Cost1",       L"Cost2",       L"Cost3",       L"Cost4"       };
static const P2PaddrSTR kAliceAddr[kPostures] =
{ L"Cost0.Alice", L"Cost1.Alice", L"Cost2.Alice", L"Cost3.Alice", L"Cost4.Alice" };
static const P2PaddrSTR kCarolAddr[kPostures] =
{ L"Cost0.Carol", L"Cost1.Carol", L"Cost2.Carol", L"Cost3.Carol", L"Cost4.Carol" };
static const char      *kMidUtf8[kPostures] =
{ "Cost0",        "Cost1",        "Cost2",        "Cost3",        "Cost4"        };
static const char      *kAliceUtf8[kPostures] =
{ "Cost0.Alice",  "Cost1.Alice",  "Cost2.Alice",  "Cost3.Alice",  "Cost4.Alice"  };
static const char      *kCarolUtf8[kPostures] =
{ "Cost0.Carol",  "Cost1.Carol",  "Cost2.Carol",  "Cost3.Carol",  "Cost4.Carol"  };

static LPCTSTR kSvcAlice[kPostures] =
{ _T("LinkCostA0"), _T("LinkCostA1"), _T("LinkCostA2"), _T("LinkCostA3"), _T("LinkCostA4") };
static LPCTSTR kSvcCarol[kPostures] =
{ _T("LinkCostC0"), _T("LinkCostC1"), _T("LinkCostC2"), _T("LinkCostC3"), _T("LinkCostC4") };

// ---------------------------------------------------------------------------
//  The key material, generated once and shared by every posture.
//  NOTES: The FILES are shared; the ALLOW-LIST ENTRIES are not, because the
//         addresses are per posture and an allow-list is keyed on the address.
//         So each list carries five entries per peer - one per posture - which
//         is dead weight in four of them and correct in the fifth.  The
//         alternative is five sets of files, and a duplicated fixture drifts
//         exactly like duplicated code
// ---------------------------------------------------------------------------
static std::string g_sAliceKey, g_sAliceAgr, g_sAliceAcl;
static std::string g_sCarolKey, g_sCarolAgr, g_sCarolAcl;
static std::string g_sMidKey,                g_sMidAcl;
static std::string g_sBenchAKey, g_sBenchAAgr, g_sBenchAAcl;
static std::string g_sBenchCKey, g_sBenchCAgr, g_sBenchCAcl;

static bool Provision ( )
{
    g_sAliceKey  = TempPath ( "alicekey"  );
    g_sAliceAgr  = TempPath ( "aliceagr"  );
    g_sAliceAcl  = TempPath ( "aliceacl"  );
    g_sCarolKey  = TempPath ( "carolkey"  );
    g_sCarolAgr  = TempPath ( "carolagr"  );
    g_sCarolAcl  = TempPath ( "carolacl"  );
    g_sMidKey    = TempPath ( "midkey"    );
    g_sMidAcl    = TempPath ( "midacl"    );
    g_sBenchAAcl = TempPath ( "benchaacl" );
    g_sBenchCAcl = TempPath ( "benchcacl" );

    //  The bench hubs reuse the same PRIVATE keys under different addresses.
    //  Nothing here is a trust decision - the two allow-lists above are what
    //  make Bench.Alice and Bench.Carol distinct peers
    g_sBenchAKey = g_sAliceKey;  g_sBenchAAgr = g_sAliceAgr;
    g_sBenchCKey = g_sCarolKey;  g_sBenchCAgr = g_sCarolAgr;

    unsigned char idAlice[p2pcng::kEcdsaPubLen], agrAlice[p2pcng::kEcdhPubLen];
    unsigned char idCarol[p2pcng::kEcdsaPubLen], agrCarol[p2pcng::kEcdhPubLen];
    unsigned char idMid  [p2pcng::kEcdsaPubLen];

    if ( !MakeIdentity  ( g_sAliceKey, idAlice  ) ||
         !MakeAgreement ( g_sAliceAgr, agrAlice ) ||
         !MakeIdentity  ( g_sCarolKey, idCarol  ) ||
         !MakeAgreement ( g_sCarolAgr, agrCarol ) ||
         !MakeIdentity  ( g_sMidKey,   idMid    )    )
    { Log ( "SETUP: key generation failed" ); return false; }

    for ( int i = 0; i < kPostures; ++i )
    {
      //  Alice must reach the relay (login) and seal to Carol (agreement)
      if ( p2pcng::AppendAllowList ( g_sAliceAcl.c_str ( ), kMidUtf8[i],
                                     idMid ) != p2pcng::IdOk ||
           p2pcng::AppendAllowList ( g_sAliceAcl.c_str ( ), kCarolUtf8[i],
                                     idCarol, agrCarol ) != p2pcng::IdOk )
      { Log ( "SETUP: Alice allow-list failed" ); return false; }

      //  Carol must reach the relay, and check the signature on what she opens
      if ( p2pcng::AppendAllowList ( g_sCarolAcl.c_str ( ), kMidUtf8[i],
                                     idMid ) != p2pcng::IdOk ||
           p2pcng::AppendAllowList ( g_sCarolAcl.c_str ( ), kAliceUtf8[i],
                                     idAlice, agrAlice ) != p2pcng::IdOk )
      { Log ( "SETUP: Carol allow-list failed" ); return false; }

      //  The relay logs both ends in and carries what it cannot read
      if ( p2pcng::AppendAllowList ( g_sMidAcl.c_str ( ), kAliceUtf8[i],
                                     idAlice ) != p2pcng::IdOk ||
           p2pcng::AppendAllowList ( g_sMidAcl.c_str ( ), kCarolUtf8[i],
                                     idCarol ) != p2pcng::IdOk )
      { Log ( "SETUP: middle allow-list failed" ); return false; }
    }

    if ( p2pcng::AppendAllowList ( g_sBenchAAcl.c_str ( ), "Bench.Carol",
                                   idCarol, agrCarol ) != p2pcng::IdOk ||
         p2pcng::AppendAllowList ( g_sBenchCAcl.c_str ( ), "Bench.Alice",
                                   idAlice, agrAlice ) != p2pcng::IdOk )
    { Log ( "SETUP: bench allow-list failed" ); return false; }

    return true;
}

// ---------------------------------------------------------------------------
//  Run state.  One posture at a time, reset between.
// ---------------------------------------------------------------------------
static std::atomic<long> g_nRecv      ( 0 );
static std::atomic<long> g_nInFlight  ( 0 );
static std::atomic<long> g_nOpenFail  ( 0 );   // a body Carol could not read
static HANDLE            g_hDrain   = NULL;    // auto-reset: room in the window
static HANDLE            g_hDone    = NULL;    // auto-reset: N have arrived
static HANDLE            g_hReady   = NULL;    // auto-reset: Carol has logged in
static long              g_nTarget  = 0;
//  WHAT THE ORIGIN'S LINK ACTUALLY DID, read off the connection at its login
//  ack.  Without this the table's most important row is unfalsifiable: "B
//  costs nothing over A" and "B did nothing" produce the same numbers, and so
//  do "E opened the link" and "SetLinkPolicy never took".  Read the same five
//  accessors p2p_linktrust reads, from the same place
static int               g_nKeyX    = -1;
static int               g_nCypher  = -1;
static int               g_nAuthed  = -1;
static int               g_nTrust   = -1;
static long              g_nWindow  = 128;
static size_t            g_cbBody   = 256;

// =========================================================================
class CostHub : public P2PeerHub
{
public:
    enum Role { RoleAlice, RoleMiddle, RoleCarol };

    CostHub ( P2PaddrSTR strAddr, Role eRole )
        : P2PeerHub ( strAddr ), m_eRole ( eRole ) { }
    virtual ~CostHub ( ) { }

protected:
    //  The destination.  Counts, releases one slot of the send window, and
    //  signals when the run is complete.
    //  NOTES: Returns msgHANDLED WITHOUT calling the base, which is what stops
    //         a P2Pmsg_BCast arriving at its destination from being fanned out
    //         again.  p2p_sealhop's Carol does the same and for the same reason
    virtual msgRESULT On_P2PeerBCast ( P2PeerMsg *pMsg ) override
    {
        if ( m_eRole != RoleCarol )
          return msgHANDLED;

        //  The body is checked for LENGTH only.  Comparing content would put a
        //  memcmp of the payload into the measured path at the destination,
        //  which is the one place this file must not add work to
        if ( !pMsg || (size_t)pMsg->DataSize ( ) != g_cbBody )
          g_nOpenFail.fetch_add ( 1 );

        const long nLeft = g_nInFlight.fetch_sub ( 1 ) - 1;
        if ( nLeft < g_nWindow && g_hDrain )
          SetEvent ( g_hDrain );

        const long nGot = g_nRecv.fetch_add ( 1 ) + 1;
        if ( nGot >= g_nTarget && g_hDone )
          SetEvent ( g_hDone );

        return msgHANDLED;
    }

    //  A custom login handler, and GUARDED so it cannot disable what is being
    //  measured.
    //  NOTES: A hub that holds an identity signs its login even when the peer
    //         requires no authentication (P2PeerCon::LoginSend, on
    //         CanAuthSign), and the stock handler refuses a login carrying
    //         data outright.  p2p_sealhop hit this and took the same way out
    //       : THE GUARD IS THE POINT.  Handing the login straight to OnLogin/
    //         LoginAck bypasses the auth gate, so postures B through E - every
    //         posture whose cost this file exists to measure - would be
    //         measuring an unauthenticated link while reporting an
    //         authenticated one.  IsAuthRequired() decides, so the bypass can
    //         only happen where there is nothing to bypass
    virtual conRESULT On_ConLogin ( P2PeerCon *pCon, P2PaddrSTR strThatP2Paddr,
                                    const void *pvLoginMsg, P2Psize_t iSize ) override
    {
        if ( IsAuthRequired ( ) || ( !pvLoginMsg && !iSize ) )
          return P2PeerHub::On_ConLogin ( pCon, strThatP2Paddr, pvLoginMsg, iSize );

        pCon -> OnLogin  ( strThatP2Paddr );
        pCon -> LoginAck ( strThatP2Paddr, 0, 0 );
        return conHANDLED;
    }

    virtual conRESULT On_ConLoginAck ( P2PeerCon *pCon, P2PaddrSTR strThisP2Paddr,
                                       P2PaddrSTR strThatP2Paddr,
                                       const void *pvLoginAck, P2Psize_t iSize ) override
    {
        conRESULT r = P2PeerHub::On_ConLoginAck ( pCon, strThisP2Paddr,
                                                  strThatP2Paddr, pvLoginAck, iSize );
        if ( m_eRole == RoleAlice && pCon )
        {
          g_nKeyX   = pCon->IsKeyXDone       ( ) ? 1 : 0;
          g_nCypher = pCon->IsCypherActive   ( ) ? 1 : 0;
          g_nAuthed = pCon->IsAuthenticated  ( ) ? 1 : 0;
          g_nTrust  = (int)pCon->EffectiveTrust ( );
        }
        std::printf ( "[linkcost]   %-6s login ack from '%s'"
                      "  (trust=%d keyx=%d cypher=%d authed=%d)\n",
                      RoleName ( ), N ( strThatP2Paddr ).c_str ( ),
                      (int)( pCon ? pCon->EffectiveTrust  ( ) : -1 ),
                      (int)( pCon ? pCon->IsKeyXDone      ( ) : 0 ),
                      (int)( pCon ? pCon->IsCypherActive  ( ) : 0 ),
                      (int)( pCon ? pCon->IsAuthenticated ( ) : 0 ) );
        std::fflush ( stdout );
        if ( g_hReady ) SetEvent ( g_hReady );
        return r;
    }

private:
    const char *RoleName ( ) const
    {
        return m_eRole == RoleMiddle ? "MIDDLE"
             : m_eRole == RoleAlice  ? "ALICE" : "CAROL";
    }

    Role m_eRole;
};

// ---------------------------------------------------------------------------
struct Result
{
    bool   bRan;
    bool   bComplete;
    long   nRecv;
    double dWall;        // seconds, the delivery of N
    double dCpu;         // seconds, whole process, over the same interval
    double dIdleCpuPS;   // seconds of CPU per second of idle, same three hubs
    int    nKeyX, nCypher, nAuthed, nTrust;   // what the origin's link did
};

// =========================================================================
//  One posture: stand the chain up, send N, tear it down.
// =========================================================================
static bool RunPosture ( int nIx, long nCount, Result *pOut )
{
    const Posture &oP = kPost[nIx];

    std::printf ( "\n--- posture %s ---\n", oP.pszName );
    std::printf ( "[linkcost]   auth=%d attest=%d seal=%d linkOpen=%d;"
                  " %s -> %s -> %s\n",
                  (int)oP.bAuth, (int)oP.bAttest, (int)oP.bSeal, (int)oP.bOpen,
                  kAliceUtf8[nIx], kMidUtf8[nIx], kCarolUtf8[nIx] );
    std::fflush ( stdout );

    pOut->bRan = false; pOut->bComplete = false; pOut->nRecv = 0;
    pOut->dWall = 0.0;  pOut->dCpu = 0.0;        pOut->dIdleCpuPS = 0.0;

    pOut->nKeyX = pOut->nCypher = pOut->nAuthed = pOut->nTrust = -1;
    g_nKeyX = g_nCypher = g_nAuthed = g_nTrust = -1;
    g_nRecv.store ( 0 ); g_nInFlight.store ( 0 ); g_nOpenFail.store ( 0 );
    g_nTarget = nCount;
    ResetEvent ( g_hDone ); ResetEvent ( g_hDrain ); ResetEvent ( g_hReady );

    bool bOk = false;
    {
        // ---- the relay -----------------------------------------------------
        //  NOTES: NO KEYS OF ANY KIND beyond what RequireAuth needs, and no
        //         seal requirement.  A hub in the middle of a tree neither
        //         originates nor terminates sealed bodies - it forwards blocks
        //         it cannot read, which is P2PAuthLogin.h's own argument for
        //         why there is no ArmNoAgreement
        CostHub oMid ( kMidAddr[nIx], CostHub::RoleMiddle );
        oMid.RequireAuth      ( oP.bAuth   );
        oMid.RequireRelayAuth ( oP.bAttest );
        oMid.RequireSeal      ( false      );
        oMid.RequireRevocation ( false     );   // see the note at Carol's
        if ( oP.bAuth )
        {
          if ( oMid.SetIdentity  ( g_sMidKey.c_str ( ) ) != p2pcng::IdOk ||
               oMid.SetAllowList ( g_sMidAcl.c_str ( ) ) != p2pcng::IdOk )
          { Log ( "SETUP: middle provisioning failed" ); return false; }
        }
        if ( oP.bOpen )
          oMid.SetLinkPolicy ( P2PeerConTrust_InProcess, P2PeerLinkPolicy_Open );

        HANDLE hMid = oMid.SpawnHub ( );
        if ( !hMid ) { Log ( "SETUP: middle SpawnHub failed" ); return false; }

        P2PeerConDmx *pSvcA = P2PeerConDmx::ServiceFactory ( kAliceAddr[nIx],
                                                             kSvcAlice[nIx] );
        P2PeerConDmx *pSvcC = P2PeerConDmx::ServiceFactory ( kCarolAddr[nIx],
                                                             kSvcCarol[nIx] );
        if ( !pSvcA || !pSvcC )
        { Log ( "SETUP: Dmx ServiceFactory failed" ); return false; }
        oMid.PostP2PeerCon ( pSvcA );
        oMid.PostP2PeerCon ( pSvcC );
        Sleep ( 500 );

        // ---- the destination ----------------------------------------------
        CostHub oCarol ( kCarolAddr[nIx], CostHub::RoleCarol );
        oCarol.RequireAuth      ( oP.bAuth   );
        oCarol.RequireRelayAuth ( oP.bAttest );
        oCarol.RequireSeal      ( false      );   // Carol OPENS; she sends nothing
        //  NOT A POSTURE THIS FILE MEASURES, and it is off for a reason that
        //  is about the measurement rather than about convenience: a
        //  revocation list is consulted when a LOGIN is verified, which is
        //  once per connection, and this file's subject is what a MESSAGE
        //  costs.  Leaving it on would add a fixed setup cost to postures B-E
        //  and none to A, which is the one difference between the rows that
        //  would not be the difference under test.  Every other harness in the
        //  suite says it the same way
        oCarol.RequireRevocation ( false     );
        if ( oP.bAuth || oP.bAttest || oP.bSeal )
        {
          if ( oCarol.SetIdentity  ( g_sCarolKey.c_str ( ) ) != p2pcng::IdOk ||
               oCarol.SetAllowList ( g_sCarolAcl.c_str ( ) ) != p2pcng::IdOk )
          { Log ( "SETUP: Carol provisioning failed" ); return false; }
        }
        if ( oP.bSeal )
        {
          if ( oCarol.SetAgreementKey ( g_sCarolAgr.c_str ( ) ) != p2pcng::IdOk )
          { Log ( "SETUP: Carol agreement key failed" ); return false; }
          if ( !oCarol.CanOpen ( ) )
          { Log ( "SETUP: Carol cannot open" ); return false; }
        }
        if ( oP.bOpen )
          oCarol.SetLinkPolicy ( P2PeerConTrust_InProcess, P2PeerLinkPolicy_Open );

        HANDLE hCarol = oCarol.SpawnHub ( );
        P2PeerConDmx *pConC = P2PeerConDmx::ClientFactory ( kMidAddr[nIx],
                                                            kSvcCarol[nIx] );
        if ( !hCarol || !pConC ) { Log ( "SETUP: Carol failed" ); return false; }
        oCarol.PostP2PeerCon ( pConC );
        if ( WaitForSingleObject ( g_hReady, 10000 ) != WAIT_OBJECT_0 )
        { Log ( "SETUP: Carol never logged in" ); return false; }

        // ---- the origin ----------------------------------------------------
        CostHub oAlice ( kAliceAddr[nIx], CostHub::RoleAlice );
        oAlice.RequireAuth      ( oP.bAuth   );
        oAlice.RequireRelayAuth ( oP.bAttest );
        oAlice.RequireSeal      ( oP.bSeal   );
        oAlice.RequireRevocation ( false     );   // see the note at Carol's
        if ( oP.bAuth || oP.bAttest || oP.bSeal )
        {
          if ( oAlice.SetIdentity  ( g_sAliceKey.c_str ( ) ) != p2pcng::IdOk ||
               oAlice.SetAllowList ( g_sAliceAcl.c_str ( ) ) != p2pcng::IdOk )
          { Log ( "SETUP: Alice provisioning failed" ); return false; }
        }
        if ( oP.bSeal )
        {
          if ( oAlice.SetAgreementKey ( g_sAliceAgr.c_str ( ) ) != p2pcng::IdOk )
          { Log ( "SETUP: Alice agreement key failed" ); return false; }
          if ( !oAlice.CanSeal ( ) )
          { Log ( "SETUP: Alice cannot seal" ); return false; }
        }
        if ( oP.bOpen )
          oAlice.SetLinkPolicy ( P2PeerConTrust_InProcess, P2PeerLinkPolicy_Open );

        HANDLE hAlice = oAlice.SpawnHub ( );
        P2PeerConDmx *pConA = P2PeerConDmx::ClientFactory ( kMidAddr[nIx],
                                                            kSvcAlice[nIx] );
        if ( !hAlice || !pConA ) { Log ( "SETUP: Alice failed" ); return false; }
        oAlice.PostP2PeerCon ( pConA );
        if ( WaitForSingleObject ( g_hReady, 10000 ) != WAIT_OBJECT_0 )
        { Log ( "SETUP: Alice never logged in" ); return false; }
        Sleep ( 300 );

        // ---- the idle baseline ---------------------------------------------
        //  NOTES: Three hubs up, two links logged in, NOTHING sent.  A pump
        //         that wakes on a timeout costs CPU whether or not there is
        //         traffic, and over a run that takes a quarter of a second
        //         that is not a rounding error.  Subtracting it is what makes
        //         "CPU per message" a property of the MESSAGE
        //       : Measured per posture rather than once, because the postures
        //         do not hold the same number of live objects
        {
          const double dC0 = CpuSeconds ( ), dW0 = WallSeconds ( );
          Sleep ( 500 );
          const double dC1 = CpuSeconds ( ), dW1 = WallSeconds ( );
          const double dW  = dW1 - dW0;
          pOut->dIdleCpuPS = ( dW > 0.0 ) ? ( dC1 - dC0 ) / dW : 0.0;
        }

        // ---- the run --------------------------------------------------------
        std::vector<unsigned char> vBody ( g_cbBody, 0 );
        for ( size_t i = 0; i < g_cbBody; ++i )
          vBody[i] = (unsigned char)( 'a' + ( i % 26 ) );

        const double dCpu0  = CpuSeconds  ( );
        const double dWall0 = WallSeconds ( );

        bool bStalled = false;
        for ( long i = 0; i < nCount && !bStalled; ++i )
        {
          while ( g_nInFlight.load ( ) >= g_nWindow )
          {
            if ( WaitForSingleObject ( g_hDrain, 30000 ) != WAIT_OBJECT_0 )
            { bStalled = true; break; }
          }
          if ( bStalled ) break;

          g_nInFlight.fetch_add ( 1 );
          oAlice.PostP2PeerMsg (
            new P2PeerMsg32 ( kAliceAddr[nIx], kCarolAddr[nIx], P2Pmsg_BCast,
                              &vBody[0], (P2Psize_t)g_cbBody ) );
        }

        const bool bDone = !bStalled &&
          ( g_nRecv.load ( ) >= nCount ||
            WaitForSingleObject ( g_hDone, 60000 ) == WAIT_OBJECT_0 );

        const double dWall1 = WallSeconds ( );
        const double dCpu1  = CpuSeconds  ( );

        pOut->bRan      = true;
        pOut->bComplete = bDone;
        pOut->nRecv     = g_nRecv.load ( );
        pOut->dWall     = dWall1 - dWall0;
        pOut->dCpu      = dCpu1  - dCpu0;
        pOut->nKeyX     = g_nKeyX;   pOut->nCypher = g_nCypher;
        pOut->nAuthed   = g_nAuthed; pOut->nTrust  = g_nTrust;
        bOk             = true;

        std::printf ( "[linkcost]   delivered %ld/%ld in %.3f s wall, %.3f s CPU"
                      " (idle %.3f CPU/s)%s\n",
                      pOut->nRecv, nCount, pOut->dWall, pOut->dCpu,
                      pOut->dIdleCpuPS,
                      g_nOpenFail.load ( ) ? "  *** SHORT BODIES SEEN" : "" );
        std::fflush ( stdout );

        // ---- teardown -------------------------------------------------------
        oAlice.CloseHub ( );
        WaitForSingleObject ( hAlice, 5000 ); CloseHandle ( hAlice );
        oCarol.CloseHub ( );
        WaitForSingleObject ( hCarol, 5000 ); CloseHandle ( hCarol );
        oMid.CloseHub ( );
        WaitForSingleObject ( hMid,   5000 ); CloseHandle ( hMid   );
    }
    Sleep ( 250 );
    return bOk;
}

// =========================================================================
//  Part 2 - the primitives, timed on their own.
//  NOTES: The chain above cannot see VerifyRelay at all (the header says why),
//         and it can only see a seal and an open bundled into one round trip.
//         These four loops are what generalises to a tree of another shape
// =========================================================================
static void RunPrimitives ( long nIter )
{
    std::printf ( "\n--- part 2: the primitives, %ld iterations each ---\n", nIter );
    std::fflush ( stdout );

    //  Constructed and provisioned, never spawned.  None of the four takes the
    //  pump - each is a lock on the hub and a call into p2pauth / p2pseal
    P2PeerHub oA ( L"Bench.Alice" );
    P2PeerHub oC ( L"Bench.Carol" );

    if ( oA.SetIdentity     ( g_sBenchAKey.c_str ( ) ) != p2pcng::IdOk ||
         oA.SetAllowList    ( g_sBenchAAcl.c_str ( ) ) != p2pcng::IdOk ||
         oA.SetAgreementKey ( g_sBenchAAgr.c_str ( ) ) != p2pcng::IdOk ||
         oC.SetIdentity     ( g_sBenchCKey.c_str ( ) ) != p2pcng::IdOk ||
         oC.SetAllowList    ( g_sBenchCAcl.c_str ( ) ) != p2pcng::IdOk ||
         oC.SetAgreementKey ( g_sBenchCAgr.c_str ( ) ) != p2pcng::IdOk    )
    { Log ( "SETUP: bench hub provisioning failed - primitives skipped" ); return; }

    std::vector<unsigned char> vBody ( g_cbBody, 0 );
    for ( size_t i = 0; i < g_cbBody; ++i )
      vBody[i] = (unsigned char)( 'a' + ( i % 26 ) );

    // ---- attest ------------------------------------------------------------
    //  Every block is kept, so the verify loop below can be handed a FRESH one
    //  each iteration.  Verifying one block N times would measure a cache, and
    //  might not even do that - a replay refusal would read as a slow verify
    std::vector< std::vector<unsigned char> > vBlocks;
    vBlocks.reserve ( (size_t)nIter );

    double dW0 = WallSeconds ( ), dC0 = CpuSeconds ( );
    long   nBad = 0;
    for ( long i = 0; i < nIter; ++i )
    {
      unsigned char aBlock[p2pauth::kRelayMaxLen];
      size_t        cb = 0;
      if ( oA.AttestRelay ( L"Bench.Alice", L"Bench.Alice", L"Bench.Carol",
                            L"BCast", &vBody[0], g_cbBody,
                            aBlock, sizeof(aBlock), &cb ) != p2pauth::AuthOk )
      { ++nBad; continue; }
      vBlocks.push_back ( std::vector<unsigned char> ( aBlock, aBlock + cb ) );
    }
    double dW1 = WallSeconds ( ), dC1 = CpuSeconds ( );
    std::printf ( "[linkcost]   AttestRelay   %8.1f us wall  %8.1f us CPU  per call"
                  "  (%ld refused)\n",
                  ( dW1 - dW0 ) * 1e6 / (double)nIter,
                  ( dC1 - dC0 ) * 1e6 / (double)nIter, nBad );
    std::fflush ( stdout );

    // ---- verify ------------------------------------------------------------
    dW0 = WallSeconds ( ); dC0 = CpuSeconds ( ); nBad = 0;
    for ( size_t i = 0; i < vBlocks.size ( ); ++i )
    {
      wchar_t wszAtt[p2pauth::kRelayAttesterMax + 1];
      long    nSkew = 0;
      wszAtt[0] = 0;
      if ( oC.VerifyRelay ( L"Bench.Alice", L"Bench.Carol", L"BCast",
                            &vBody[0], g_cbBody,
                            &vBlocks[i][0], vBlocks[i].size ( ),
                            wszAtt, sizeof(wszAtt)/sizeof(wszAtt[0]),
                            &nSkew ) != p2pauth::AuthOk )
        ++nBad;
    }
    dW1 = WallSeconds ( ); dC1 = CpuSeconds ( );
    if ( !vBlocks.empty ( ) )
      std::printf ( "[linkcost]   VerifyRelay   %8.1f us wall  %8.1f us CPU  per call"
                    "  (%ld refused)\n",
                    ( dW1 - dW0 ) * 1e6 / (double)vBlocks.size ( ),
                    ( dC1 - dC0 ) * 1e6 / (double)vBlocks.size ( ), nBad );
    std::fflush ( stdout );

    // ---- seal --------------------------------------------------------------
    const size_t cbRoom = p2pseal::SealedSize ( g_cbBody, p2pseal::kSealMaxReaders );
    std::vector< std::vector<unsigned char> > vSealed;
    vSealed.reserve ( (size_t)nIter );

    dW0 = WallSeconds ( ); dC0 = CpuSeconds ( ); nBad = 0;
    for ( long i = 0; i < nIter; ++i )
    {
      std::vector<unsigned char> v ( cbRoom );
      size_t cb = 0;
      if ( oA.SealFor ( L"Bench.Alice", L"Bench.Carol", &vBody[0], g_cbBody,
                        &v[0], cbRoom, &cb ) != p2pseal::SealOk )
      { ++nBad; continue; }
      v.resize ( cb );
      vSealed.push_back ( v );
    }
    dW1 = WallSeconds ( ); dC1 = CpuSeconds ( );
    std::printf ( "[linkcost]   SealFor       %8.1f us wall  %8.1f us CPU  per call"
                  "  (%ld refused, %u -> %u bytes)\n",
                  ( dW1 - dW0 ) * 1e6 / (double)nIter,
                  ( dC1 - dC0 ) * 1e6 / (double)nIter, nBad,
                  (unsigned)g_cbBody,
                  (unsigned)( vSealed.empty ( ) ? 0 : vSealed[0].size ( ) ) );
    std::fflush ( stdout );

    // ---- open --------------------------------------------------------------
    dW0 = WallSeconds ( ); dC0 = CpuSeconds ( ); nBad = 0;
    for ( size_t i = 0; i < vSealed.size ( ); ++i )
    {
      std::vector<unsigned char> vPlain ( p2pseal::OpenedSize ( vSealed[i].size ( ) ) + 1 );
      size_t cb = 0;
      if ( oC.OpenFrom ( L"Bench.Alice", L"Bench.Carol",
                         &vSealed[i][0], vSealed[i].size ( ),
                         &vPlain[0], vPlain.size ( ), &cb ) != p2pseal::SealOk )
        ++nBad;
    }
    dW1 = WallSeconds ( ); dC1 = CpuSeconds ( );
    if ( !vSealed.empty ( ) )
      std::printf ( "[linkcost]   OpenFrom      %8.1f us wall  %8.1f us CPU  per call"
                    "  (%ld refused)\n",
                    ( dW1 - dW0 ) * 1e6 / (double)vSealed.size ( ),
                    ( dC1 - dC0 ) * 1e6 / (double)vSealed.size ( ), nBad );
    std::fflush ( stdout );
}

// =========================================================================
//  NO MODAL DIALOG, EVER.  The copy in p2p_linktrust carries the full
//  argument; this is the same three mechanisms, for the same reason.  A file
//  with its own main() needs its own copy - TestFramework.cpp's does not reach
//  here.
// =========================================================================
static std::terminate_handler g_pfnPrevTerminate = 0;

static void CostOnTerminate ( )
{
    std::printf ( "\n[linkcost] *** TERMINATE - an exception reached the top of a "
                  "thread\n" );
    try
    {
        std::exception_ptr p = std::current_exception ( );
        if ( p ) std::rethrow_exception ( p );
        std::printf ( "[linkcost]     ...with no exception in flight\n" );
    }
    catch ( P2Pevent *pEVT )
    {
        if ( pEVT )
        {
            std::printf ( "[linkcost]     P2Pevent %s in %s\n"
                          "[linkcost]     %s\n"
                          "[linkcost]     ADVICE: %s\n",
                          N ( pEVT->GetClassText ( ) ).c_str ( ),
                          N ( pEVT->GetModule    ( ) ).c_str ( ),
                          N ( pEVT->GetMessage   ( ) ).c_str ( ),
                          N ( pEVT->GetAdvice    ( ) ).c_str ( ) );
            pEVT->Cancel ( false );
        }
        else
            std::printf ( "[linkcost]     P2Pevent: (null)\n" );
    }
    catch ( const std::exception &e )
    {
        std::printf ( "[linkcost]     std::exception: %s\n", e.what ( ) );
    }
    catch ( ... )
    {
        std::printf ( "[linkcost]     (an exception of unknown type)\n" );
    }
    std::fflush ( stdout );
    if ( g_pfnPrevTerminate ) g_pfnPrevTerminate ( );
    std::abort ( );
}

#ifdef _WIN32
static int __cdecl CostAssertHook ( int nReportType, char *szMsg, int *pnRet )
{
    if ( nReportType == _CRT_ASSERT || nReportType == _CRT_ERROR )
    {
        std::printf ( "[linkcost] *** ASSERT: %s\n",
                      szMsg ? szMsg : "(no message)" );
        std::fflush ( stdout );
        if ( pnRet ) *pnRet = 0;      // do not invoke the debugger
        return TRUE;                  // handled -> continue
    }
    return FALSE;
}
#endif

// =========================================================================
int main ( int argc, char *argv[] )
{
#ifdef _WIN32
    _CrtSetReportMode ( _CRT_ASSERT, _CRTDBG_MODE_FILE );
    _CrtSetReportFile ( _CRT_ASSERT, _CRTDBG_FILE_STDERR );
    _CrtSetReportMode ( _CRT_ERROR,  _CRTDBG_MODE_FILE );
    _CrtSetReportFile ( _CRT_ERROR,  _CRTDBG_FILE_STDERR );
    _CrtSetReportHook ( CostAssertHook );
    SetErrorMode ( SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
                   SEM_NOOPENFILEERRORBOX );
#endif
    g_pfnPrevTerminate = std::set_terminate ( CostOnTerminate );
    P2Pevent::ForceTextOutput ( true );

    long nCount = ( argc >= 2 ) ? std::atol ( argv[1] ) : 4000;
    if ( nCount < 100 ) nCount = 100;
    if ( argc >= 3 ) g_cbBody = (size_t)std::atol ( argv[2] );
    if ( g_cbBody < 16 || g_cbBody > 32768 ) g_cbBody = 256;

    std::printf ( "=== p2p_linkcost - what does a posture cost a message? ===\n" );
    std::printf ( "securityRevision.md 8.4, and the number 6.3 is decided on.\n" );
    std::printf ( "N = %ld messages of %u bytes, three in-process hubs in a chain,\n"
                  "window = %ld in flight.\n",
                  nCount, (unsigned)g_cbBody, g_nWindow );
    std::fflush ( stdout );

    g_hDrain = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hDone  = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hReady = CreateEvent ( NULL, FALSE, FALSE, NULL );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg failed" ); return 2; }

    if ( !Provision ( ) ) { ScrubTempFiles ( ); CleanupP2Pmsg ( ); return 2; }

    int    nExit = 0;
    //  ZEROED, and a posture that is never reached must print "(not run)"
    //  rather than a number.  It printed 1e68 microseconds per message first,
    //  which is what an uninitialised double looks like once it has been
    //  divided by something
    Result aRes[kPostures];
    std::memset ( aRes, 0, sizeof(aRes) );
    for ( int i = 0; i < kPostures; ++i )
    {
      if ( !RunPosture ( i, nCount, &aRes[i] ) )
      { nExit = 2; break; }
      if ( !aRes[i].bComplete ) nExit = ( nExit == 0 ) ? 3 : nExit;
    }

    if ( nExit != 2 )
      RunPrimitives ( ( nCount < 2000 ) ? nCount : 2000 );

    // ---- the table --------------------------------------------------------
    std::printf ( "\n=== RESULT - %ld messages of %u bytes, "
                  "Cost.Alice -> Cost -> Cost.Carol, all in process ===\n\n",
                  nCount, (unsigned)g_cbBody );
    std::printf ( "  %-38s %10s %12s %12s %12s  %s\n",
                  "posture", "msg/s", "wall us/msg", "CPU us/msg",
                  "CPU-idle", "origin link" );
    std::printf ( "  %-38s %10s %12s %12s %12s  %s\n",
                  "--------------------------------------",
                  "----------", "------------", "------------",
                  "------------", "-----------------------------" );
    for ( int i = 0; i < kPostures; ++i )
    {
      if ( !aRes[i].bRan ) { std::printf ( "  %-38s  (not run)\n", kPost[i].pszName ); continue; }
      const double dN    = (double)( aRes[i].nRecv > 0 ? aRes[i].nRecv : 1 );
      const double dRate = ( aRes[i].dWall > 0.0 ) ? dN / aRes[i].dWall : 0.0;
      const double dIdle = aRes[i].dIdleCpuPS * aRes[i].dWall;
      const double dNet  = aRes[i].dCpu - dIdle;
      std::printf ( "  %-38s %10.0f %12.1f %12.1f %12.1f  "
                    "trust=%d keyx=%d cyph=%d auth=%d%s\n",
                    kPost[i].pszName, dRate,
                    aRes[i].dWall * 1e6 / dN,
                    aRes[i].dCpu  * 1e6 / dN,
                    ( dNet > 0.0 ? dNet : 0.0 ) * 1e6 / dN,
                    aRes[i].nTrust, aRes[i].nKeyX,
                    aRes[i].nCypher, aRes[i].nAuthed,
                    aRes[i].bComplete ? "" : "  INCOMPLETE" );
    }

    {
      const double dTick = CpuTickSeconds ( );
      std::printf ( "\n  CPU RESOLUTION: %.3f ms scheduler tick = %.2f us per message\n"
                    "  at N = %ld.  Two rows differ meaningfully only by more than that.\n",
                    dTick * 1e3, dTick * 1e6 / (double)nCount, nCount );
    }
    std::printf ( "\n  CPU is the WHOLE PROCESS, kernel+user, all threads.\n"
                  "  CPU-idle subtracts the same three hubs pumping with no traffic;\n"
                  "  a blocked pump costs nothing, so the correction is near zero and\n"
                  "  the two CPU columns agree.  That is a result, not a broken column.\n"
                  "  ORIGIN LINK is read off Alice's connection at its login ack, and it\n"
                  "  is what stops this table being unfalsifiable: keyx/cyph/auth = 1 in\n"
                  "  B means the handshake really ran, and 0 in E means SetLinkPolicy\n"
                  "  really took.  Without it, 'costs nothing' and 'did nothing' read the\n"
                  "  same.  trust 2 = in-process.\n"
                  "  Attestation here is ONE SIGNATURE AT THE ORIGIN and no verify:\n"
                  "  in a chain the relay is a common ancestor of both ends, so\n"
                  "  GateAppMsgInbound's descendant test admits the message before\n"
                  "  GateRelayInbound is reached.  Part 2 prices the verify.\n" );

    if ( nExit == 3 )
      std::printf ( "\nRESULT: INCOMPLETE - a posture did not deliver every message\n"
                    "  within its timeout, so its row describes a stall.  NOT a\n"
                    "  measurement.\n" );
    else if ( nExit == 0 )
      std::printf ( "\nRESULT: OK - every posture delivered every message.\n" );

    ScrubTempFiles ( );
    CleanupP2Pmsg ( );
    if ( g_hDrain ) CloseHandle ( g_hDrain );
    if ( g_hDone  ) CloseHandle ( g_hDone  );
    if ( g_hReady ) CloseHandle ( g_hReady );

    std::printf ( "Done (exit=%d).\n", nExit );
    std::fflush ( stdout );
    return nExit;
}
