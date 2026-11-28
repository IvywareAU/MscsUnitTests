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
// p2p_sealmode.cpp - p2p_performance T1d: the two seal modes behind one switch
// (decision 1), asserted at the HUB rather than on p2pseal.
//
// WHY AT THE HUB. p2pseal::SealSelfTest already proves the v3 format: round
// trip, the context and its cache, replay, rotation, every refusal. What it
// cannot see is the layer an operator actually configures - P2PeerHub
// forwarding to p2pauth::AuthPolicy, which picks the mode, owns the two caches,
// flushes them and couples the seq window to RefuseSealReplay. That layer is
// a hand-maintained forwarding shim, the shape that has silently dropped a
// setting before (p2p_replayguard phase 0 says the same), so it gets its own
// gate.
//
// NO SOCKETS. Two provisioned hubs, never spawned: Alice seals with SealFor,
// Bob opens with OpenFrom - the same two calls the send and receive paths
// make, under the same hub lock.
//
//   Phase 1 (DEFAULTS)     nothing called: PerMessage, context accepted, and
//                          TryReadPosture says so. A v2 body, and it opens.
//   Phase 2 (OPT IN)       SealModeOutbound(Context): v3 bodies, one context
//                          (same point, seq 0, 1), both open at Bob, and the
//                          posture reports the mode and its bounds.
//   Phase 3 (REPLAY)       the same v3 bytes again are refused; with
//                          RefuseSealReplay(false) they open - the seq window
//                          follows the switch and does not overrule it.
//   Phase 4 (REFUSAL)      SealModeAccept(false): v3 refused with
//                          SealErrContextRefused, v2 still opens; on again,
//                          v3 opens.
//   Phase 5 (ROTATION)     bounds of 2 messages: the third seal starts a new
//                          context.
//   Phase 6 (FLUSH)        ReloadAllowList on Alice ends her context: the
//                          next body is seq 0 under a new point.
//   Phase 7 (DOWNGRADE)    a v3 body relabelled v2 does not open.
//   Phase 8 (BACK)         SealModeOutbound(PerMessage): v2 bytes again.
//   Phase 9 (FLAT C)       the four p2peerhub_seal_mode_* entry points on a
//                          handle the ABI made: defaults, 0 = default bound,
//                          an unknown mode reads 0, a null handle.
//
// VERDICT = process EXIT CODE:
//   0  PASS   every phase behaved as above
//   1  FAIL   a mode, a refusal or a flush did not take
//   2  SETUP  provisioning failed (test inconclusive)

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "Msgexception.h"
#include "P2PIdentityStore.h"
#include "P2PAuthLogin.h"
#include "P2PeerSeal.h"
#include "Targetcore_c.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
static int g_nChecks = 0;
static int g_nFailed = 0;

static void Log ( const char *msg )
{
    std::printf ( "[sealmode] %s\n", msg );
    std::fflush ( stdout );
}

static void Check ( bool bOk, const char *pszWhat )
{
    ++g_nChecks;
    if ( !bOk ) ++g_nFailed;
    std::printf ( "[sealmode] %-6s %s\n", bOk ? "ok" : "FAIL", pszWhat );
    std::fflush ( stdout );
}

static void Note ( const char *pszWhat, p2pseal::SealResult e )
{
    std::printf ( "[sealmode]        %s = %s\n",
                  pszWhat, p2pseal::SealResultText ( e ) );
    std::fflush ( stdout );
}

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
    s += "p2p_sealmode_"; s += pszLeaf; s += "_"; s += szPid; s += ".tmp";
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

// ---------------------------------------------------------------------------
static const wchar_t *kAlice = L"Mode.Alice";
static const wchar_t *kBob   = L"Mode.Alice.Relay.Bob";

static const char   g_szBody[] = "a body sealed under one mode or the other";
static const size_t g_cbBody   = sizeof(g_szBody) - 1;

//  v3 offsets, from the header's layout, so a reader of this test can check
//  them against P2PeerSeal.h rather than against the implementation.
static const size_t kOffCtx = p2pseal::kSealVerLen + p2pseal::kSealTimeLen;
static const size_t kOffSeq = kOffCtx + p2pseal::kSealEphLen;

static unsigned long long SeqOf ( const std::vector<unsigned char> &v )
{
    unsigned long long u = 0;
    for ( size_t i = 0; i < p2pseal::kSealSeqLen; ++i )
        u = ( u << 8 ) | v[kOffSeq + i];
    return u;
}

static bool SameCtx ( const std::vector<unsigned char> &a,
                      const std::vector<unsigned char> &b )
{
    return a.size ( ) > kOffSeq && b.size ( ) > kOffSeq
        && std::memcmp ( &a[kOffCtx], &b[kOffCtx], p2pseal::kSealEphLen ) == 0;
}

//  Seal at Alice. Sized with SealedSizeV3, as the header asks of a direct
//  caller, so the same buffer serves either mode.
static p2pseal::SealResult SealAt ( P2PeerHub &oHub,
                                    std::vector<unsigned char> &vOut )
{
    vOut.assign ( p2pseal::SealedSizeV3 ( g_cbBody,
                                          p2pseal::kSealMaxReaders ), 0 );
    size_t cb = 0;
    p2pseal::SealResult e = oHub.SealFor ( kAlice, kBob, g_szBody, g_cbBody,
                                           &vOut[0], vOut.size ( ), &cb );
    vOut.resize ( e == p2pseal::SealOk ? cb : 0 );
    return e;
}

//  Open at Bob, and insist on the original bytes when it says it opened.
static p2pseal::SealResult OpenAt ( P2PeerHub &oHub,
                                    const std::vector<unsigned char> &vIn )
{
    if ( vIn.empty ( ) ) return p2pseal::SealErrFormat;
    std::vector<unsigned char> vPlain ( p2pseal::OpenedSize ( vIn.size ( ) ) + 1 );
    size_t cb = 0;
    p2pseal::SealResult e = oHub.OpenFrom ( kAlice, kBob, &vIn[0], vIn.size ( ),
                                            &vPlain[0], vPlain.size ( ), &cb );
    if ( e == p2pseal::SealOk &&
         ( cb != g_cbBody || std::memcmp ( &vPlain[0], g_szBody, g_cbBody ) != 0 ) )
        return p2pseal::SealErrInternal;   // "opened" to the wrong bytes
    return e;
}

// =========================================================================
int main ( int argc, char *argv[] )
{
    (void)argc; (void)argv;

    std::printf ( "=== p2p_sealmode - p2p_performance T1d, at the hub ===\n" );
    std::printf ( "Asserting: PerMessage stays the default and writes v2; Context\n"
                  "           writes v3 only when asked, and the hub's refusal,\n"
                  "           replay coupling, rotation and flush all take.\n\n" );
    std::fflush ( stdout );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }

    // ---- Provisioning -----------------------------------------------------
    const std::string sAliceKey = TempPath ( "alicekey" );
    const std::string sBobKey   = TempPath ( "bobkey"   );
    const std::string sBobAgree = TempPath ( "bobagree" );
    const std::string sAliceAcl = TempPath ( "aliceacl" );
    const std::string sBobAcl   = TempPath ( "bobacl"   );

    unsigned char pubAlice[p2pcng::kEcdsaPubLen];
    unsigned char idBob   [p2pcng::kEcdsaPubLen];
    unsigned char agrBob  [p2pcng::kEcdhPubLen];
    if ( !MakeIdentity  ( sAliceKey, pubAlice ) ||
         !MakeIdentity  ( sBobKey,   idBob    ) ||
         !MakeAgreement ( sBobAgree, agrBob   ) )
    { Log ( "SETUP: key generation failed" ); ScrubTempFiles ( );
      CleanupP2Pmsg ( ); return 2; }

    if ( p2pcng::AppendAllowList ( sAliceAcl.c_str ( ), "Mode.Alice.Relay.Bob",
                                   idBob, agrBob ) != p2pcng::IdOk ||
         p2pcng::AppendAllowList ( sBobAcl.c_str ( ), "Mode.Alice",
                                   pubAlice ) != p2pcng::IdOk )
    { Log ( "SETUP: allow-list provisioning failed" ); ScrubTempFiles ( );
      CleanupP2Pmsg ( ); return 2; }

    int nExit = 2;
    {
        P2PeerHub oAlice ( kAlice );
        P2PeerHub oBob   ( kBob );
        if ( oAlice.SetIdentity     ( sAliceKey.c_str ( ) ) != p2pcng::IdOk ||
             oAlice.SetAllowList    ( sAliceAcl.c_str ( ) ) != p2pcng::IdOk ||
             oBob.SetIdentity       ( sBobKey  .c_str ( ) ) != p2pcng::IdOk ||
             oBob.SetAgreementKey   ( sBobAgree.c_str ( ) ) != p2pcng::IdOk ||
             oBob.SetAllowList      ( sBobAcl  .c_str ( ) ) != p2pcng::IdOk ||
             !oAlice.CanSeal ( ) || !oBob.CanOpen ( ) )
        { Log ( "SETUP: hub configuration failed" ); ScrubTempFiles ( );
          CleanupP2Pmsg ( ); return 2; }

        std::vector<unsigned char> v0, v1, v2, v3;
        p2pseal::SealResult e;

        // ---- Phase 1: DEFAULTS ---------------------------------------------
        Log ( "--- phase 1: nothing called ---" );
        {
            Check ( oAlice.GetSealModeOutbound ( ) == p2pseal::SealMode_PerMessage,
                    "a hub that called nothing writes PerMessage" );
            Check ( oBob.IsSealContextAccepted ( ),
                    "and opens context bodies without being told to" );
            P2PeerHub::Posture oP;
            Check ( oAlice.TryReadPosture ( oP )
                    && oP.nSealMode == (int)p2pseal::SealMode_PerMessage
                    && oP.nSealCtxMsgs == p2pseal::kSealCtxMaxMsgsDefault
                    && oP.nSealCtxSecs == p2pseal::kSealCtxMaxSecsDefault
                    && oP.bSealAcceptCtx,
                    "the posture says PerMessage, 4096 / 300, accepted" );

            e = SealAt ( oAlice, v0 );
            Note ( "SealFor (default)", e );
            Check ( e == p2pseal::SealOk && v0[0] == p2pseal::kSealVersion
                    && v0.size ( ) == p2pseal::SealedSize ( g_cbBody, 1 ),
                    "and the body is v2, exactly the pre-3.12.0 size" );
            e = OpenAt ( oBob, v0 );
            Note ( "OpenFrom (v2)", e );
            Check ( e == p2pseal::SealOk, "which Bob opens" );
        }

        // ---- Phase 2: OPT IN -----------------------------------------------
        Log ( "--- phase 2: SealModeOutbound(Context) ---" );
        oAlice.SealModeOutbound ( p2pseal::SealMode_Context );
        {
            P2PeerHub::Posture oP;
            Check ( oAlice.TryReadPosture ( oP )
                    && oP.nSealMode == (int)p2pseal::SealMode_Context,
                    "the posture says Context" );

            Check ( SealAt ( oAlice, v1 ) == p2pseal::SealOk
                    && SealAt ( oAlice, v2 ) == p2pseal::SealOk,
                    "two bodies seal" );
            Check ( !v1.empty ( ) && v1[0] == p2pseal::kSealVersion3
                    && v1.size ( ) == p2pseal::SealedSizeV3 ( g_cbBody, 1 ),
                    "as v3, kSealSeqLen longer than v2" );
            Check ( SameCtx ( v1, v2 ) && SeqOf ( v1 ) == 0 && SeqOf ( v2 ) == 1,
                    "in ONE context: the same point, seq 0 then 1" );

            e = OpenAt ( oBob, v1 );
            Note ( "OpenFrom (v3 #0)", e );
            Check ( e == p2pseal::SealOk, "Bob opens the first" );
            e = OpenAt ( oBob, v2 );
            Note ( "OpenFrom (v3 #1)", e );
            Check ( e == p2pseal::SealOk, "and the second" );
        }

        // ---- Phase 3: REPLAY -----------------------------------------------
        Log ( "--- phase 3: the same v3 bytes again ---" );
        {
            e = OpenAt ( oBob, v1 );
            Note ( "OpenFrom (v3 #0 again)", e );
            Check ( e == p2pseal::SealErrReplay, "a replay is refused" );

            oBob.RefuseSealReplay ( false );
            e = OpenAt ( oBob, v1 );
            Note ( "OpenFrom (again, RefuseSealReplay(false))", e );
            Check ( e == p2pseal::SealOk,
                    "and with RefuseSealReplay(false) it opens - the seq window "
                    "follows the switch rather than overruling it" );
            oBob.RefuseSealReplay ( true );
        }

        // ---- Phase 4: REFUSAL ----------------------------------------------
        Log ( "--- phase 4: SealModeAccept(false) at Bob ---" );
        oBob.SealModeAccept ( false );
        {
            Check ( !oBob.IsSealContextAccepted ( ), "the switch took" );
            P2PeerHub::Posture oP;
            Check ( oBob.TryReadPosture ( oP ) && !oP.bSealAcceptCtx,
                    "and the posture says so" );

            Check ( SealAt ( oAlice, v3 ) == p2pseal::SealOk, "a fresh v3 body" );
            e = OpenAt ( oBob, v3 );
            Note ( "OpenFrom (v3, refusing)", e );
            Check ( e == p2pseal::SealErrContextRefused,
                    "is refused by POLICY, not as a version or a forgery" );

            oAlice.SealModeOutbound ( p2pseal::SealMode_PerMessage );
            Check ( SealAt ( oAlice, v0 ) == p2pseal::SealOk
                    && v0[0] == p2pseal::kSealVersion, "a v2 body" );
            e = OpenAt ( oBob, v0 );
            Note ( "OpenFrom (v2, refusing v3)", e );
            Check ( e == p2pseal::SealOk, "still opens - only v3 is refused" );

            oBob.SealModeAccept ( true );
            e = OpenAt ( oBob, v3 );
            Note ( "OpenFrom (the refused v3, accepting again)", e );
            Check ( e == p2pseal::SealOk,
                    "and with the switch back on the refused body opens" );
        }

        // ---- Phase 5: ROTATION ---------------------------------------------
        Log ( "--- phase 5: bounds of 2 messages ---" );
        oAlice.SealModeOutbound ( p2pseal::SealMode_Context, 2, 300 );
        {
            P2PeerHub::Posture oP;
            Check ( oAlice.TryReadPosture ( oP ) && oP.nSealCtxMsgs == 2
                    && oP.nSealCtxSecs == 300, "the posture reports the bounds" );
            Check ( SealAt ( oAlice, v1 ) == p2pseal::SealOk
                    && SealAt ( oAlice, v2 ) == p2pseal::SealOk
                    && SealAt ( oAlice, v3 ) == p2pseal::SealOk, "three bodies" );
            Check ( SameCtx ( v1, v2 ) && SeqOf ( v2 ) == 1,
                    "the first two share a context" );
            Check ( !SameCtx ( v2, v3 ) && SeqOf ( v3 ) == 0,
                    "and the third starts a new one at seq 0" );
            Check ( OpenAt ( oBob, v1 ) == p2pseal::SealOk
                    && OpenAt ( oBob, v2 ) == p2pseal::SealOk
                    && OpenAt ( oBob, v3 ) == p2pseal::SealOk,
                    "all three open at Bob" );
        }

        // ---- Phase 6: FLUSH ------------------------------------------------
        Log ( "--- phase 6: ReloadAllowList ends the context ---" );
        oAlice.SealModeOutbound ( p2pseal::SealMode_Context );
        {
            Check ( SealAt ( oAlice, v1 ) == p2pseal::SealOk
                    && SealAt ( oAlice, v2 ) == p2pseal::SealOk
                    && SameCtx ( v1, v2 ), "two bodies in one context" );
            Check ( oAlice.ReloadAllowList ( ) == p2pcng::IdOk, "reload" );
            Check ( SealAt ( oAlice, v3 ) == p2pseal::SealOk
                    && !SameCtx ( v2, v3 ) && SeqOf ( v3 ) == 0,
                    "and the next body is seq 0 under a NEW point" );
            Check ( OpenAt ( oBob, v3 ) == p2pseal::SealOk, "which Bob opens" );
        }

        // ---- Phase 7: DOWNGRADE --------------------------------------------
        Log ( "--- phase 7: a v3 body relabelled v2 ---" );
        {
            Check ( SealAt ( oAlice, v1 ) == p2pseal::SealOk, "a fresh v3 body" );
            v1[0] = p2pseal::kSealVersion;
            e = OpenAt ( oBob, v1 );
            Note ( "OpenFrom (relabelled)", e );
            Check ( e != p2pseal::SealOk, "does not open" );
        }

        // ---- Phase 8: BACK -------------------------------------------------
        Log ( "--- phase 8: SealModeOutbound(PerMessage) ---" );
        oAlice.SealModeOutbound ( p2pseal::SealMode_PerMessage );
        {
            Check ( SealAt ( oAlice, v0 ) == p2pseal::SealOk
                    && v0[0] == p2pseal::kSealVersion
                    && v0.size ( ) == p2pseal::SealedSize ( g_cbBody, 1 ),
                    "v2 bytes again" );
            Check ( OpenAt ( oBob, v0 ) == p2pseal::SealOk, "and Bob opens them" );
        }

        // ---- Phase 9: THE FLAT C ABI ---------------------------------------
        //  A hub the ABI made: the flat entry points resolve handles through
        //  P2PhandleIs, so a C++ hub cast to a handle reads as no hub at all
        //  and every check below would pass for that reason (p2p_e2ewaive
        //  phase 1b found this first).
        Log ( "--- phase 9: the same switches through the flat C ABI ---" );
        {
            P2PeerHubHandle h = p2peerhub_create ( L"Mode.FlatC" );
            Check ( h != NULL, "p2peerhub_create returns a handle" );
            if ( h )
            {
                P2PeerHub *pHub = (P2PeerHub *)h;
                Check ( p2peerhub_get_seal_mode_outbound ( h ) == 0
                        && p2peerhub_is_seal_context_accepted ( h ) == 1,
                        "it reads mode 0 and accept 1 by default" );

                p2peerhub_seal_mode_outbound ( h, 1, 0, 0 );
                P2PeerHub::Posture oP;
                Check ( p2peerhub_get_seal_mode_outbound ( h ) == 1
                        && pHub->TryReadPosture ( oP )
                        && oP.nSealCtxMsgs == p2pseal::kSealCtxMaxMsgsDefault
                        && oP.nSealCtxSecs == p2pseal::kSealCtxMaxSecsDefault,
                        "mode 1 takes, and 0 for a bound means its default" );

                p2peerhub_seal_mode_outbound ( h, 1, 7, 9 );
                Check ( pHub->TryReadPosture ( oP )
                        && oP.nSealCtxMsgs == 7 && oP.nSealCtxSecs == 9,
                        "explicit bounds take" );

                p2peerhub_seal_mode_outbound ( h, 42, 0, 0 );
                Check ( p2peerhub_get_seal_mode_outbound ( h ) == 0,
                        "an unknown mode is mode 0, not a mode nobody named" );

                p2peerhub_seal_mode_accept ( h, 0 );
                Check ( p2peerhub_is_seal_context_accepted ( h ) == 0,
                        "accept 0 takes" );
                p2peerhub_seal_mode_accept ( h, 1 );
                Check ( p2peerhub_is_seal_context_accepted ( h ) == 1,
                        "and back" );

                p2peerhub_destroy ( h );
            }
            Check ( p2peerhub_get_seal_mode_outbound ( NULL ) == 0
                    && p2peerhub_is_seal_context_accepted ( NULL ) == 1,
                    "a null handle reads what an unconfigured hub does" );
        }

        nExit = g_nFailed ? 1 : 0;
    }

    // ---- Verdict -----------------------------------------------------------
    std::printf ( "\n[sealmode] %d checks, %d failed\n", g_nChecks, g_nFailed );
    ScrubTempFiles ( );
    CleanupP2Pmsg ( );

    if ( nExit )
    {
        std::printf ( "\nRESULT: FAIL - a seal mode setting did not take at the hub.\n" );
        return nExit;
    }
    std::printf ( "\nRESULT: PASS - PerMessage by default, Context only when asked,\n"
                  "        and the refusal, replay coupling, rotation and flush hold.\n" );
    return 0;
}
