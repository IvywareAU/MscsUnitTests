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
// p2p_replayguard.cpp - SECURITY GATE TEST: can a signed block that was already
// accepted be delivered a SECOND time?
//
// BACKGROUND - the gap this closes. RefuseSealReplay() and RefuseRelayReplay()
// landed on 2026-08-16 with their behaviour pinned by AuthSelfTest sections 17
// and 18 - thoroughly, including the count bound and the eviction it implies.
// What no test touched was the HUB. AuthSelfTest drives p2pauth::AuthPolicy
// directly; every switch here is reached through P2PeerHub, under
// m_oCSectionHub, on a hub whose pump is running. So the wiring between the two
// - the setters, the getters, and the seal opened on a live receive path rather
// than in a loop - was the least-tested code in the tree while being the newest
// security code in the tree. That is the wrong way round, and this closes it.
//
// It is deliberately NOT a re-run of AuthSelfTest at a distance. The cache
// semantics are proved there. What is proved here is that a real hub, sealed
// to and attested at over a real connection, refuses the second copy.
//
// WHAT IT DOES - two halves against two hubs over real TCP.
//
//   THE SEALED BODY (phases 1-3). Alice seals a body to Bob ONCE and posts the
//   identical bytes twice - which is exactly what a capture-and-redeliver
//   attacker has, because it is what went over the wire.
//     Phase 1 (CONTROL, switch OFF): both copies MUST open. Without this the
//     later refusal could be anything - a body that never arrived twice, a
//     transport that de-duplicated, a handler that ran once.
//     Phase 2 (THE REFUSAL, switch ON): first copy opens, second MUST NOT.
//     Phase 3 (LIVENESS): a DIFFERENT body still opens, so the cache refuses
//     replays rather than everything after the first.
//
//   THE RELAY ATTESTATION (phases 4-6). Same shape, through
//   P2PeerHub::AttestRelay / VerifyRelay: control accepts twice with the switch
//   off, the switch on refuses the second, and a fresh attestation still
//   verifies.
//
// Note what the sealed half does NOT claim, because the difference is the
// design and not an oversight: a relay block carries a signed timestamp and a
// sealed body does not, so the relay cache expires entries and the seal cache
// is bounded by COUNT alone. The most recent bodies cannot be replayed; an
// older one can. This test is inside the count, which is where the guarantee
// is - SECURITY.md's "Body hidden from an intermediate hub" row states the
// part that is not.
//
// VERDICT = process EXIT CODE:
//   0  PASS   controls replay, switches refuse, liveness holds
//   1  FAIL   a switch that is on accepted a second copy
//   2  SETUP  startup / provisioning failure (test inconclusive)
//   3  INCONCLUSIVE a control did not behave, so the refusals prove nothing

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
static const P2PaddrSTR kBobAddr    = L"Replay.Bob";      // server, opens
static const P2PaddrSTR kAliceAddr  = L"Replay.Alice";    // client, seals
static const P2PaddrSTR kDomain     = L"Replay.*";

// The relay attestation's addresses. The source is BELOW the attester, which is
// the shape the at-or-below test accepts - refer p2p_authancestor for what that
// rule is and why. Nothing here is testing the rule; it is testing the cache.
static const wchar_t *kRelAttester = L"Replay.Alice";
static const wchar_t *kRelSrc      = L"Replay.Alice.Widget";
static const wchar_t *kRelDst      = L"Replay.Bob";
static const wchar_t *kRelName     = L"P2PmsgBCast";
static const char     kRelBody[]   = "transiting down from another branch";

// Bob's tally of what his receive path made of each arriving body.
static volatile LONG g_nOpened  = 0;      // p2pseal::SealOk
static volatile LONG g_nReplay  = 0;      // p2pseal::SealErrReplay
static volatile LONG g_nOther   = 0;      // anything else - a setup problem

static void Log ( const char *msg )
{
    std::printf ( "[replayguard] %s\n", msg );
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

// ---------------------------------------------------------------------------
// Provisioning - what an operator does by hand.
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
    s += "p2p_replayguard_"; s += pszLeaf; s += "_"; s += szPid; s += ".tmp";
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

static bool MakeAgreement ( const std::string &sPath, unsigned char *pPubOut )
{
    p2pcng::EcdhP256 oKey;
    if ( !oKey.Generate ( ) ) return false;
    if ( p2pcng::SaveAgreement ( sPath.c_str ( ), oKey ) != p2pcng::IdOk ) return false;
    return oKey.ExportPublic ( pPubOut );
}

// =========================================================================
class GuardHub : public P2PeerHub
{
public:
    GuardHub ( P2PaddrSTR strAddr, bool bOpener )
        : P2PeerHub ( strAddr ), m_bOpener ( bOpener )
    { m_strSelf = strAddr; }
    virtual ~GuardHub ( ) { }

protected:
    //  Bob's receive path. Every arriving body is a sealed block, and what this
    //  records is what OpenFrom() made of it - which is the only place the
    //  RefuseSealReplay switch can be observed from outside the library.
    virtual msgRESULT On_P2PeerBCast ( P2PeerMsg *pMsg ) override
    {
        if ( !m_bOpener || !pMsg ) return msgHANDLED;

        // DataSize(), not Sizeof(). Sizeof() is the whole message and
        // OpenFrom would then be handed trailing bytes that were never sealed,
        // which fails as "sender signature did not verify" - a refusal that
        // looks like a crypto problem and is a length problem
        const unsigned char *pIn = (const unsigned char *)pMsg->Data ( );
        const size_t         cbIn = (size_t)pMsg->DataSize ( );
        if ( !pIn || !cbIn ) return msgHANDLED;

        std::vector<unsigned char> vPlain ( p2pseal::OpenedSize ( cbIn ) + 2, 0 );
        size_t cbOut = 0;
        p2pseal::SealResult e = OpenFrom ( pMsg->GetSource ( ),
                                           m_strSelf.GetString ( ),
                                           pIn, cbIn,
                                           &vPlain[0], vPlain.size ( ), &cbOut );

        if      ( e == p2pseal::SealOk )         InterlockedIncrement ( &g_nOpened );
        else if ( e == p2pseal::SealErrReplay )  InterlockedIncrement ( &g_nReplay );
        else                                     InterlockedIncrement ( &g_nOther );

        std::printf ( "[replayguard] BOB opened a body from '%s': %s (%u bytes)\n",
                      N ( pMsg->GetSource ( ) ).c_str ( ),
                      p2pseal::SealResultText ( e ), (unsigned)cbOut );
        std::fflush ( stdout );
        return msgHANDLED;
    }

private:
    bool    m_bOpener;
    CString m_strSelf;
};

// -------------------------------------------------------------------------
//  Post the SAME sealed bytes to Bob twice, and wait for his handler to have
//  run on both. Identical bytes deliberately: a fresh seal would carry a fresh
//  signature and would not be a replay of anything
// -------------------------------------------------------------------------
static void PostTwice ( GuardHub &oAlice, const std::vector<unsigned char> &vSealed )
{
    for ( int i = 0; i < 2; i++ )
    {
        oAlice.PostP2PeerMsg ( new P2PeerMsg32 ( kAliceAddr, kBobAddr,
                                                 P2Pmsg_BCast,
                                                 &vSealed[0],
                                                 (P2Psize_t)vSealed.size ( ) ) );
        Sleep ( 900 );
    }
}

// =========================================================================
int main ( int argc, char *argv[] )
{
    short nPort = ( argc >= 2 ) ? (short)atoi ( argv[1] ) : 7828;

    std::printf ( "=== p2p_replayguard - seal and relay replay refusal, at the hub ===\n" );
    std::printf ( "Port : %d\n", (int)nPort );
    std::printf ( "Asserting: a signed block already accepted is refused the\n"
                  "           second time, and only when the switch says so.\n\n" );
    std::fflush ( stdout );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }
    WSADATA oWsaData;
    WSAStartup ( MAKEWORD(2,2), &oWsaData );

    // ---- Provisioning -----------------------------------------------------
    const std::string sAliceKey = TempPath ( "alicekey" );
    const std::string sBobKey   = TempPath ( "bobkey"   );
    const std::string sBobAgree = TempPath ( "bobagree" );
    const std::string sAliceAcl = TempPath ( "aliceacl" );
    const std::string sBobAcl   = TempPath ( "bobacl"   );

    // Bob needs an IDENTITY as well as an agreement key. The agreement key is
    // what makes him sealable TO; the identity is what signs his login ack, and
    // without it the connection never completes and no body ever arrives to be
    // replayed - which is a setup failure that looks exactly like a passing
    // replay guard, since both are silence on the receive path
    unsigned char pubAlice [p2pcng::kEcdsaPubLen];
    unsigned char agrBob   [p2pcng::kEcdhPubLen];
    unsigned char idBob    [p2pcng::kEcdsaPubLen];
    if ( !MakeIdentity  ( sAliceKey, pubAlice ) ||
         !MakeIdentity  ( sBobKey,   idBob    ) ||
         !MakeAgreement ( sBobAgree, agrBob   ) )
    { Log ( "SETUP: key generation failed" ); ScrubTempFiles ( ); return 2; }

    // Bob's line in Alice's list carries the agreement point, which is what
    // makes him sealable to. Alice's line in Bob's list carries the identity,
    // which is whose signature Bob demands - on the seal AND on the attestation
    if ( p2pcng::AppendAllowList ( sAliceAcl.c_str ( ), "Replay.Bob",
                                   idBob, agrBob ) != p2pcng::IdOk ||
         p2pcng::AppendAllowList ( sBobAcl.c_str ( ), "Replay.Alice",
                                   pubAlice ) != p2pcng::IdOk )
    { Log ( "SETUP: allow-list provisioning failed" ); ScrubTempFiles ( ); return 2; }

    int nExit = 2;
    {
        // ---- Bob: the server, and the one who opens ----------------------
        GuardHub oBob ( kBobAddr, true );
        if ( oBob.SetIdentity     ( sBobKey  .c_str ( ) ) != p2pcng::IdOk ||
             oBob.SetAgreementKey ( sBobAgree.c_str ( ) ) != p2pcng::IdOk ||
             oBob.SetAllowList    ( sBobAcl  .c_str ( ) ) != p2pcng::IdOk )
        { Log ( "SETUP: Bob configuration failed" ); ScrubTempFiles ( ); return 2; }
        if ( !oBob.CanOpen ( ) )
        { Log ( "SETUP: Bob cannot open" ); ScrubTempFiles ( ); return 2; }
        oBob.RequireAuth ( true );
        //  RequireRevocation(false) since 2026-08-21 (Stage 3 step 19): a hub
        //  that requires auth must now hold a POSITION on revocation, and this
        //  test is not about revocation. Saying so is the documented migration
        //  and it is one line. It does NOT turn revocation off - a list named
        //  anyway is still loaded, still enforced and still fails closed.
        oBob.RequireRevocation ( false );

        HANDLE hBobThread = oBob.SpawnHub ( );
        if ( !hBobThread ) { Log ( "SETUP: Bob SpawnHub() failed" ); return 2; }

        P2PeerConWsa *pSvc = P2PeerConWsa::ServiceFactory ( kDomain, nPort );
        if ( !pSvc ) { Log ( "SETUP: ServiceFactory failed" ); return 2; }
        oBob.PostP2PeerCon ( pSvc );
        Log ( "Bob listening" );
        Sleep ( 500 );

        // ---- Alice: the client, and the one who seals --------------------
        GuardHub oAlice ( kAliceAddr, false );
        if ( oAlice.SetIdentity  ( sAliceKey.c_str ( ) ) != p2pcng::IdOk ||
             oAlice.SetAllowList ( sAliceAcl.c_str ( ) ) != p2pcng::IdOk )
        { Log ( "SETUP: Alice configuration failed" ); return 2; }
        if ( !oAlice.CanSeal ( ) )
        { Log ( "SETUP: Alice cannot seal" ); return 2; }
        oAlice.RequireAuth ( true );
        oAlice.RequireRevocation ( false );

        HANDLE hAliceThread = oAlice.SpawnHub ( );
        P2PeerConWsa *pCon =
            P2PeerConWsa::ClientFactory ( kBobAddr, L"127.0.0.1", nPort );
        if ( !hAliceThread || !pCon ) { Log ( "SETUP: Alice failed" ); return 2; }
        oAlice.PostP2PeerCon ( pCon );
        Sleep ( 1200 );

        // Seal three separate bodies up front. Each is sealed ONCE; the replay
        // is the same bytes posted again, never a second sealing
        std::vector<unsigned char> vBody[3];
        bool bSealed = true;
        for ( int i = 0; i < 3 && bSealed; i++ )
        {
            wchar_t wszPlain[64];
            std::swprintf ( wszPlain, 64, L"replayguard-body-%d", i );
            const size_t cbPlain = ( wcslen ( wszPlain ) + 1 ) * sizeof(wchar_t);

            vBody[i].assign ( p2pseal::SealedSize ( cbPlain ), 0 );
            size_t cbOut = 0;
            p2pseal::SealResult e = oAlice.SealFor ( kAliceAddr, kBobAddr,
                                                     wszPlain, cbPlain,
                                                     &vBody[i][0],
                                                     vBody[i].size ( ), &cbOut );
            if ( e != p2pseal::SealOk ) { bSealed = false; break; }
            vBody[i].resize ( cbOut );
        }
        if ( !bSealed ) { Log ( "SETUP: SealFor failed" ); return 2; }

        // ================= Phase 0: the defaults, at the hub ===============
        //  ProductionPlan.md Stage 3 step 10 turned both switches ON and gave
        //  the seal one a freshness window. Asserted HERE, through P2PeerHub,
        //  because AuthSelfTest asserts it on the policy object and the hub is
        //  a hand-maintained forwarding layer in front of it - exactly the
        //  shape that has silently dropped a setting before.
        std::printf ( "[replayguard] phase 0: seal=%d relay=%d window=%ds\n",
                      oBob.IsSealReplayRefused  ( ) ? 1 : 0,
                      oBob.IsRelayReplayRefused ( ) ? 1 : 0,
                      oBob.GetSealWindow ( ) );
        std::fflush ( stdout );
        if ( !oBob.IsSealReplayRefused  ( ) ||
             !oBob.IsRelayReplayRefused ( ) ||
              oBob.GetSealWindow ( ) != 86400 )
        {
            std::printf (
              "\nRESULT: FAIL - the replay switches are not on by default at the\n"
              "  hub, or the seal freshness window is not 24 hours. Stage 3 step\n"
              "  10 has been reverted, or P2PeerHub has stopped forwarding one of\n"
              "  them to AuthPolicy.\n" );
            Log ( "shutdown" );
            return 1;
        }

        // ================= Phase 1: control, switch OFF ====================
        //  OFF is now the MIGRATION rather than the default - the one line a
        //  DAG deployment, or an application that re-delivers on purpose, uses
        //  to get the pre-2026-08-18 behaviour back. Holding it still is what
        //  makes turning the switch on by default a default rather than an
        //  outage, so this phase matters more than it did, not less.
        Log ( "--- phase 1: same sealed body twice, RefuseSealReplay OFF ---" );
        oBob.RefuseSealReplay ( false );
        g_nOpened = g_nReplay = g_nOther = 0;
        PostTwice ( oAlice, vBody[0] );
        const LONG n1Open = g_nOpened, n1Replay = g_nReplay, n1Other = g_nOther;
        std::printf ( "[replayguard] phase 1: opened=%ld replay=%ld other=%ld\n",
                      (long)n1Open, (long)n1Replay, (long)n1Other );
        std::fflush ( stdout );

        // ================= Phase 2: the refusal, switch ON =================
        Log ( "--- phase 2: same sealed body twice, RefuseSealReplay ON ---" );
        oBob.RefuseSealReplay ( true );
        g_nOpened = g_nReplay = g_nOther = 0;
        PostTwice ( oAlice, vBody[1] );
        const LONG n2Open = g_nOpened, n2Replay = g_nReplay, n2Other = g_nOther;
        std::printf ( "[replayguard] phase 2: opened=%ld replay=%ld other=%ld\n",
                      (long)n2Open, (long)n2Replay, (long)n2Other );
        std::fflush ( stdout );

        // ================= Phase 3: liveness ===============================
        Log ( "--- phase 3: a DIFFERENT body, switch still ON (liveness) ---" );
        g_nOpened = g_nReplay = g_nOther = 0;
        oAlice.PostP2PeerMsg ( new P2PeerMsg32 ( kAliceAddr, kBobAddr,
                                                 P2Pmsg_BCast, &vBody[2][0],
                                                 (P2Psize_t)vBody[2].size ( ) ) );
        Sleep ( 1200 );
        const LONG n3Open = g_nOpened, n3Replay = g_nReplay;
        std::printf ( "[replayguard] phase 3: opened=%ld replay=%ld\n",
                      (long)n3Open, (long)n3Replay );
        std::fflush ( stdout );

        // ================= Phases 4-6: the relay attestation ===============
        // Driven straight at the hub API: the routing integration is
        // p2p_authancestor's subject, and what is untested here is the cache
        Log ( "--- phases 4-6: relay attestation through the hub API ---" );
        bool bRelayOk = true, bRelayRefused = false, bRelayLive = false;
        bool bRelayCtrl = false;
        {
            unsigned char blk1[p2pauth::kRelayMaxLen];
            unsigned char blk2[p2pauth::kRelayMaxLen];
            size_t        cb1 = 0, cb2 = 0;
            wchar_t       wszAtt[128];
            long          nSkew = 0;

            if ( oAlice.AttestRelay ( kRelAttester, kRelSrc, kRelDst, kRelName,
                                      kRelBody, sizeof(kRelBody),
                                      blk1, sizeof(blk1), &cb1 ) != p2pauth::AuthOk ||
                 oAlice.AttestRelay ( kRelAttester, kRelSrc, kRelDst, kRelName,
                                      kRelBody, sizeof(kRelBody),
                                      blk2, sizeof(blk2), &cb2 ) != p2pauth::AuthOk )
            { bRelayOk = false; }

            if ( bRelayOk )
            {
                // Phase 4: control - switch OFF, the same block verifies twice
                oBob.RefuseRelayReplay ( false );
                const p2pauth::AuthResult a1 =
                    oBob.VerifyRelay ( kRelSrc, kRelDst, kRelName,
                                       kRelBody, sizeof(kRelBody), blk1, cb1,
                                       wszAtt, 128, &nSkew );
                const p2pauth::AuthResult a2 =
                    oBob.VerifyRelay ( kRelSrc, kRelDst, kRelName,
                                       kRelBody, sizeof(kRelBody), blk1, cb1,
                                       wszAtt, 128, &nSkew );
                bRelayCtrl = ( a1 == p2pauth::AuthOk && a2 == p2pauth::AuthOk );
                std::printf ( "[replayguard] phase 4 (control, off): %s then %s\n",
                              p2pauth::AuthResultText ( a1 ),
                              p2pauth::AuthResultText ( a2 ) );

                // Phase 5: switch ON, and the SAME block again
                oBob.RefuseRelayReplay ( true );
                const p2pauth::AuthResult a3 =
                    oBob.VerifyRelay ( kRelSrc, kRelDst, kRelName,
                                       kRelBody, sizeof(kRelBody), blk1, cb1,
                                       wszAtt, 128, &nSkew );
                const p2pauth::AuthResult a4 =
                    oBob.VerifyRelay ( kRelSrc, kRelDst, kRelName,
                                       kRelBody, sizeof(kRelBody), blk1, cb1,
                                       wszAtt, 128, &nSkew );
                bRelayRefused = ( a3 == p2pauth::AuthOk &&
                                  a4 == p2pauth::AuthErrReplay );
                std::printf ( "[replayguard] phase 5 (refusal, on): %s then %s\n",
                              p2pauth::AuthResultText ( a3 ),
                              p2pauth::AuthResultText ( a4 ) );

                // Phase 6: liveness - a DIFFERENT attestation over identical
                // content. It carries a different signature because ECDSA
                // signing is randomised, which is the premise the cache rests on
                const p2pauth::AuthResult a5 =
                    oBob.VerifyRelay ( kRelSrc, kRelDst, kRelName,
                                       kRelBody, sizeof(kRelBody), blk2, cb2,
                                       wszAtt, 128, &nSkew );
                bRelayLive = ( a5 == p2pauth::AuthOk );
                std::printf ( "[replayguard] phase 6 (liveness): %s\n",
                              p2pauth::AuthResultText ( a5 ) );
                std::fflush ( stdout );
            }
        }

        // ================= Verdict =========================================
        if ( !bRelayOk )
        {
            std::printf (
              "\nRESULT: SETUP - AttestRelay() would not produce a block, so the\n"
              "  relay half never ran. Check Alice's identity loaded.\n" );
            nExit = 2;
        }
        else if ( n1Other || n2Other )
        {
            std::printf (
              "\nRESULT: SETUP - a body came back neither opened nor refused, so\n"
              "  something other than replay is being measured. Check the\n"
              "  allow-list provisioning and the agreement key.\n" );
            nExit = 2;
        }
        else if ( n1Open != 2 || !bRelayCtrl )
        {
            std::printf (
              "\nRESULT: INCONCLUSIVE - THE CONTROL DID NOT REPLAY.\n"
              "  With both switches OFF the same block must be accepted twice;\n"
              "  it was not (seal opened=%ld of 2, relay control=%s). Until a\n"
              "  replay demonstrably gets through, a later refusal is not\n"
              "  evidence of a guard - it could be a body that only ever arrived\n"
              "  once. Check the transport before reading anything below.\n",
              (long)n1Open, bRelayCtrl ? "ok" : "failed" );
            nExit = 3;
        }
        else if ( n2Open != 1 || n2Replay != 1 )
        {
            std::printf (
              "\nRESULT: FAIL - A REPLAYED SEALED BODY WAS ACCEPTED.\n"
              "  RefuseSealReplay(true) was set on the receiving hub and the\n"
              "  identical sealed bytes were delivered twice; the hub opened them\n"
              "  %ld times and refused %ld. Capture-and-redeliver therefore works\n"
              "  against a hub that has asked for it not to. Check that\n"
              "  P2PeerHub::RefuseSealReplay() reaches AuthPolicy under\n"
              "  m_oCSectionHub, and that OpenFrom() consults the cache.\n",
              (long)n2Open, (long)n2Replay );
            nExit = 1;
        }
        else if ( !bRelayRefused )
        {
            std::printf (
              "\nRESULT: FAIL - A REPLAYED RELAY ATTESTATION WAS ACCEPTED.\n"
              "  RefuseRelayReplay(true) was set and the same signed block\n"
              "  verified twice. A captured downward relay can then be delivered\n"
              "  again for as long as its timestamp stays inside the window.\n" );
            nExit = 1;
        }
        else if ( n3Open != 1 || !bRelayLive )
        {
            std::printf (
              "\nRESULT: INCONCLUSIVE - the refusals held, but fresh traffic did\n"
              "  not get through afterwards (seal opened=%ld of 1, relay live=%s).\n"
              "  A hub that refuses everything also refuses replays, so this is\n"
              "  not a pass: the caches may be matching far more than they should.\n",
              (long)n3Open, bRelayLive ? "ok" : "failed" );
            nExit = 3;
        }
        else
        {
            std::printf (
              "\nRESULT: PASS - both replay refusals hold at the hub.\n"
              "  Switch off: the same sealed body opened twice and the same\n"
              "  attestation verified twice, so a replay does get through when\n"
              "  nothing is asked to stop it (phases 1, 4).\n"
              "  Switch on: the second copy refused in both cases (phases 2, 5).\n"
              "  Fresh traffic still accepted afterwards, so the caches refuse\n"
              "  repeats rather than everything (phases 3, 6).\n" );
            nExit = 0;
        }

        Log ( "shutdown begin" );
        oAlice.CloseHub ( );
        WaitForSingleObject ( hAliceThread, 3000 );
        CloseHandle ( hAliceThread );
        oBob.CloseHub ( );
        WaitForSingleObject ( hBobThread, 3000 );
        CloseHandle ( hBobThread );
    }

    CleanupP2Pmsg ( );
    ScrubTempFiles ( );
    WSACleanup ( );

    std::printf ( "Done (exit=%d).\n", nExit );
    std::fflush ( stdout );
    return nExit;
}
