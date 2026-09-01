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
// p2p_sealdefault.cpp - ProductionPlan.md Stage 3 step 20: the sealed body
// becomes a MULTI-RECIPIENT envelope (kSealVersion 1 -> 2), and sealing a body
// that will cross an intermediate hub becomes the DEFAULT - refusing to send
// rather than downgrading to cleartext when it cannot be done.
//
// WHY THE FORMAT HAD TO CHANGE FOR THE DEFAULT TO BE POSSIBLE
//
// v1 sealed to exactly one reader: the destination. That is the right answer
// until a deployment needs an intermediate hub to read the body - content
// routing, a filter, a store-and-forward broker - and then v1 offers one
// option, which is not to seal. So "seal by default" would have meant "break
// every deployment that needs a hub to read", and the honest colour for the
// Readme row stayed yellow.
//
// v2 encrypts the body once under a random content key and wraps that key once
// per reader. The destination is a reader; so is every hub THE SENDER NAMED.
// That last part is the whole security argument and phase 3 is what checks it:
// a relay cannot add itself, because the reader set is bound into the body's
// additional data and into the signed transcript.
//
// WHAT THIS TEST DOES - seven phases, no sockets.
//
//   Phase 1 (ROUND TRIP)       v2 seals and opens with one reader, and the
//                              plaintext comes back. The control: without it
//                              every refusal below could be a build in which
//                              nothing opens at all.
//   Phase 2 (THE NEW ABILITY)  two readers - a destination and a named hub -
//                              and BOTH open the same block, to the same
//                              bytes. This is the thing v1 could not do.
//   Phase 3 (THE LIMIT OF IT)  a third party that was NOT named cannot open
//                              it, and gets SealErrNotAReader rather than a
//                              tag failure - "not for me" and "damaged" are
//                              different facts and a relay has to tell them
//                              apart to know whether to forward.
//   Phase 4 (FALSIFICATION)    edit the block - flip a byte in a reader slot -
//                              and the named reader must now REFUSE it. The
//                              recipient set being signed is what stops a hub
//                              splicing itself in, so this is the phase that
//                              would fail if the binding were dropped.
//   Phase 5 (THE DEFAULT)      a hub that called nothing reports
//                              IsSealRequired() == true.
//   Phase 6 (REFUSE, NOT       the hub is asked to seal to a destination whose
//            DOWNGRADE)        agreement key it does not hold, and must return
//                              a refusal rather than anything that could be
//                              read as "sent it in clear". This is the whole
//                              instruction the step was given.
//   Phase 7 (THE MIGRATION)    RequireSeal(false) takes, and does NOT turn
//                              anything else off - auth is still required.
//
// WHAT IS NOT COVERED HERE, and it is written down rather than left implied:
// there is no v1 body in this test, because nothing in the tree can write one
// any more - Seal() always emits v2. The v1 read path is exercised only by
// seal_interop's stored vectors, and if those are v1 they are the compatibility
// gate; if they were regenerated they are not, and nothing checks it.
//
// VERDICT = process EXIT CODE:
//   0  PASS   every phase behaved as above
//   1  FAIL   a body opened that should not have, or refused that should not
//   2  SETUP  key generation / temp-file failure (test inconclusive)

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "Msgexception.h"
#include "P2PIdentityStore.h"
#include "P2PAuthLogin.h"
#include "P2PeerSeal.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
static int g_nChecks = 0;
static int g_nFailed = 0;

static void Log ( const char *msg )
{
    std::printf ( "[sealdefault] %s\n", msg );
    std::fflush ( stdout );
}

static void Check ( bool bOk, const char *pszWhat )
{
    ++g_nChecks;
    if ( !bOk ) ++g_nFailed;
    std::printf ( "[sealdefault] %-6s %s\n", bOk ? "ok" : "FAIL", pszWhat );
    std::fflush ( stdout );
}

static void Note ( const char *pszWhat, p2pseal::SealResult e )
{
    std::printf ( "[sealdefault]        %s = %s\n",
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
    s += "p2p_sealdefault_"; s += pszLeaf; s += "_"; s += szPid; s += ".tmp";
    DeleteFileA ( s.c_str ( ) );
    g_vTempFiles.push_back ( s );
    return s;
}

static void ScrubTempFiles ( )
{
    for ( size_t i = 0; i < g_vTempFiles.size ( ); ++i )
    {
        DeleteFileA (   g_vTempFiles[i].c_str ( ) );
        DeleteFileA ( ( g_vTempFiles[i] + ".pub" ).c_str ( ) );
    }
    g_vTempFiles.clear ( );
}

// =========================================================================
int main ( int argc, char *argv[] )
{
    (void)argc; (void)argv;

    std::printf ( "=== p2p_sealdefault - ProductionPlan Stage 3 step 20 ===\n" );
    std::printf ( "Asserting: a sealed body can name several readers, only the "
                  "SENDER chooses them,\n"
                  "           and a body that cannot be sealed is not sent.\n\n" );
    std::fflush ( stdout );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }

    const wchar_t *pSrc = L"Seal.Origin";
    const wchar_t *pDst = L"Seal.Origin.Branch.Leaf";

    //  One sender identity, and three agreement keys: the destination, a hub
    //  the sender chooses to let read, and a third party it does not.
    p2pcng::EcdsaP256 oSender;
    p2pcng::EcdhP256  oDest, oHub, oStranger;
    if ( !oSender.Generate ( ) || !oDest.Generate ( )
      || !oHub.Generate ( )    || !oStranger.Generate ( ) )
    { Log ( "SETUP: key generation failed" ); CleanupP2Pmsg ( ); return 2; }

    unsigned char aSenderPub[p2pcng::kEcdsaPubLen];
    unsigned char aDest[p2pcng::kEcdhPubLen];
    unsigned char aHub [p2pcng::kEcdhPubLen];
    if ( !oSender.ExportPublic ( aSenderPub )
      || !oDest.ExportPublic   ( aDest )
      || !oHub.ExportPublic    ( aHub ) )
    { Log ( "SETUP: key export failed" ); CleanupP2Pmsg ( ); return 2; }

    const char szBody[] = "the body an intermediate hub is not supposed to read";
    const size_t cbBody = sizeof(szBody) - 1;

    // ---- Phase 1: ROUND TRIP ----------------------------------------------
    Log ( "--- phase 1: v2 round trip, one reader ---" );
    {
        std::vector<unsigned char> vSealed ( p2pseal::SealedSize ( cbBody, 1 ) );
        size_t cbSealed = 0;

        p2pseal::SealResult e =
          p2pseal::Seal ( oSender, aDest, pSrc, pDst, szBody, cbBody,
                          &vSealed[0], vSealed.size ( ), &cbSealed );
        Note ( "Seal", e );
        Check ( e == p2pseal::SealOk, "a one-reader body seals" );
        Check ( cbSealed == p2pseal::SealedSize ( cbBody, 1 ),
                "and is exactly SealedSize(n=1) long" );
        Check ( !vSealed.empty ( ) && vSealed[0] == p2pseal::kSealVersion,
                "the first byte is the version, and it is 2" );
        Check ( p2pseal::SealReaderCount ( &vSealed[0], cbSealed ) == 1,
                "SealReaderCount reads 1 without any key at all" );

        std::vector<unsigned char> vPlain ( p2pseal::OpenedSize ( cbSealed ) + 1 );
        size_t cbPlain = 0;
        e = p2pseal::Open ( oDest, aSenderPub, pSrc, pDst, &vSealed[0], cbSealed,
                            &vPlain[0], vPlain.size ( ), &cbPlain );
        Note ( "Open", e );
        Check ( e == p2pseal::SealOk,  "the destination opens it" );
        Check ( cbPlain == cbBody,     "to the original length" );
        Check ( cbPlain == cbBody &&
                std::memcmp ( &vPlain[0], szBody, cbBody ) == 0,
                "and the original bytes" );
    }

    // ---- Phase 2: THE NEW ABILITY -----------------------------------------
    Log ( "--- phase 2: two readers - destination AND a named hub ---" );
    {
        unsigned char aReaders[2 * p2pcng::kEcdhPubLen];
        std::memcpy ( aReaders,                          aDest, p2pcng::kEcdhPubLen );
        std::memcpy ( aReaders + p2pcng::kEcdhPubLen,    aHub,  p2pcng::kEcdhPubLen );

        std::vector<unsigned char> vSealed ( p2pseal::SealedSize ( cbBody, 2 ) );
        size_t cbSealed = 0;

        p2pseal::SealResult e =
          p2pseal::SealTo ( oSender, aReaders, 2, pSrc, pDst, szBody, cbBody,
                            &vSealed[0], vSealed.size ( ), &cbSealed );
        Note ( "SealTo(2)", e );
        Check ( e == p2pseal::SealOk, "a two-reader body seals" );
        Check ( p2pseal::SealReaderCount ( &vSealed[0], cbSealed ) == 2,
                "and says so - two slots on the wire" );

        //  ONE body, not two. The whole reason for enveloping rather than
        //  sealing twice.
        Check ( cbSealed == cbBody + p2pseal::SealOverhead ( 2 ),
                "one copy of the body plus one slot per reader" );

        std::vector<unsigned char> vA ( p2pseal::OpenedSize ( cbSealed ) + 1 );
        std::vector<unsigned char> vB ( p2pseal::OpenedSize ( cbSealed ) + 1 );
        size_t cbA = 0, cbB = 0;

        p2pseal::SealResult eA =
          p2pseal::Open ( oDest, aSenderPub, pSrc, pDst, &vSealed[0], cbSealed,
                          &vA[0], vA.size ( ), &cbA );
        p2pseal::SealResult eB =
          p2pseal::Open ( oHub,  aSenderPub, pSrc, pDst, &vSealed[0], cbSealed,
                          &vB[0], vB.size ( ), &cbB );
        Note ( "Open(destination)", eA );
        Note ( "Open(named hub)",   eB );

        Check ( eA == p2pseal::SealOk, "the destination opens it" );
        Check ( eB == p2pseal::SealOk, "and so does the hub the SENDER named" );
        Check ( cbA == cbBody && cbB == cbBody &&
                std::memcmp ( &vA[0], szBody, cbBody ) == 0 &&
                std::memcmp ( &vB[0], szBody, cbBody ) == 0,
                "both to the same original bytes" );

        // ---- Phase 3: THE LIMIT OF IT -------------------------------------
        Log ( "--- phase 3: a party the sender did NOT name ---" );
        std::vector<unsigned char> vC ( p2pseal::OpenedSize ( cbSealed ) + 1 );
        size_t cbC = 0;
        p2pseal::SealResult eC =
          p2pseal::Open ( oStranger, aSenderPub, pSrc, pDst, &vSealed[0], cbSealed,
                          &vC[0], vC.size ( ), &cbC );
        Note ( "Open(stranger)", eC );
        Check ( eC != p2pseal::SealOk, "cannot open it" );
        Check ( eC == p2pseal::SealErrNotAReader,
                "and is told NOT-A-READER, not a tag failure - a relay has to "
                "tell 'not for me' from 'damaged' to know whether to forward" );
        Check ( cbC == 0, "and gets no plaintext back" );

        // ---- Phase 4: FALSIFICATION ---------------------------------------
        Log ( "--- phase 4: FALSIFICATION - edit the recipient block ---" );
        {
            std::vector<unsigned char> vBad ( vSealed.begin ( ),
                                              vSealed.begin ( ) + cbSealed );
            //  First byte of the SECOND slot's wrapped key.
            const size_t iSlot0 = p2pseal::kSealVerLen + p2pseal::kSealTimeLen
                                + p2pseal::kSealEphLen + p2pseal::kSealCountLen;
            const size_t iEdit  = iSlot0 + p2pseal::kSealSlotLen
                                + p2pseal::kSealRTagLen;
            vBad[iEdit] ^= 0x01;

            std::vector<unsigned char> vD ( p2pseal::OpenedSize ( cbSealed ) + 1 );
            size_t cbD = 0;
            p2pseal::SealResult eD =
              p2pseal::Open ( oHub, aSenderPub, pSrc, pDst, &vBad[0], cbSealed,
                              &vD[0], vD.size ( ), &cbD );
            Note ( "Open(edited slot)", eD );
            Check ( eD != p2pseal::SealOk,
                    "the named hub REFUSES a block whose reader region moved" );
            Check ( eD == p2pseal::SealErrSignature,
                    "and refuses it on the SIGNATURE - the recipient set is "
                    "signed, which is what stops a relay splicing itself in" );
        }
    }

    // ---- Phase 5: THE DEFAULT ---------------------------------------------
    Log ( "--- phase 5: a hub that called nothing ---" );
    {
        P2PeerHub oHubDef ( L"Seal.Default" );
        Check ( oHubDef.IsSealRequired ( ),
                "RequireSeal defaults to TRUE (nothing was called)" );
    }

    // ---- Phase 6: REFUSE, NOT DOWNGRADE -----------------------------------
    Log ( "--- phase 6: asked to seal to a destination it has no key for ---" );
    {
        const std::string sKey = TempPath ( "identity" );
        P2PeerHub oHubRef ( L"Seal.Refuser" );

        char szFp[p2pcng::kIdFingerprintLen] = { 0 };
        bool bCreated = false;
        if ( oHubRef.ProvisionAuth ( sKey.c_str ( ), szFp, sizeof(szFp),
                                     &bCreated ) != p2pcng::IdOk )
        { Log ( "SETUP: ProvisionAuth failed" ); ScrubTempFiles ( );
          CleanupP2Pmsg ( ); return 2; }

        Check ( oHubRef.CanSeal ( ),
                "it holds an identity, so it CAN sign a seal" );

        std::vector<unsigned char> vOut ( p2pseal::SealedSize ( cbBody, 1 ) );
        size_t cbOut = 0;
        p2pseal::SealResult e =
          oHubRef.SealFor ( pSrc, L"Nobody.We.Know", szBody, cbBody,
                            &vOut[0], vOut.size ( ), &cbOut );
        Note ( "SealFor(unknown destination)", e );

        //  THE INSTRUCTION THIS STEP WAS GIVEN, in one assertion. There is no
        //  success path here that could be read as "sent it in clear".
        Check ( e != p2pseal::SealOk,
                "REFUSES - there is no path that seals to nobody and calls it "
                "done" );
        Check ( e == p2pseal::SealErrNoAgreement,
                "and names the reason as a missing agreement key, which is a "
                "provisioning gap rather than an attack" );
        Check ( cbOut == 0, "and produces no output to send by accident" );
    }

    // ---- Phase 7: THE MIGRATION -------------------------------------------
    Log ( "--- phase 7: RequireSeal(false), the documented migration ---" );
    {
        P2PeerHub oHubOff ( L"Seal.OptOut" );
        oHubOff.RequireSeal ( false );
        Check ( !oHubOff.IsSealRequired ( ), "RequireSeal(false) took" );

        //  NARROW, like phase 9 of p2p_armgate asserts for revocation. An
        //  opt-out that quietly took authentication with it would be a much
        //  larger change than the one being made.
        Check ( oHubOff.IsAuthRequired ( ),
                "and auth is STILL required - the opt-out is narrow" );
    }

    // ---- Verdict -----------------------------------------------------------
    std::printf ( "\n[sealdefault] %d checks, %d failed\n", g_nChecks, g_nFailed );
    ScrubTempFiles ( );
    CleanupP2Pmsg ( );

    if ( g_nFailed )
    {
      std::printf ( "\nRESULT: FAIL - the sealed envelope does not hold.\n" );
      return 1;
    }
    std::printf ( "\nRESULT: PASS - several readers, chosen by the sender and "
                  "nobody else,\n"
                  "        and a body that cannot be sealed is not sent.\n" );
    return 0;
}
