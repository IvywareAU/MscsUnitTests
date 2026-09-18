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
// p2p_gcmdirection.cpp - the session cypher holds TWO keys, one per direction,
// and the key a peer seals with is never the key it opens with.
// Targetcore_ProdDocs/OpenCodeWork.md item 1 stage 1.
//
// WHY THE SPLIT EXISTS, AND IT IS NOT ABOUT THE HANDSHAKE
//
// AesGcm::Seal draws a fresh RANDOM 96-bit nonce per call (P2PCngCrypto.cpp),
// and NIST SP 800-38D section 8.3 bounds a random-IV key at 2^32 invocations -
// past that a nonce collision stops being negligible. A GCM nonce collision is
// not graceful degradation: it leaks the XOR of the two plaintexts AND exposes
// the GHASH subkey, which is a forgery primitive.
//
// KeyXDerive used to run HKDF once and install the single result on one
// P2PeerioGcm serving both Encrypt and Decrypt, so BOTH ends of a link drew
// into the same nonce space under the same key. The budget was spent from both
// ends at once, a collision between an A-to-B frame and a B-to-A frame was as
// fatal as one within a direction, and neither end could do anything about it:
// each draws independently and never sees the other's nonces, so no counter
// either end kept would have been authoritative. Split, each key has exactly
// one writer - which is what makes bounding it possible at all.
//
// THE BOUND IS ENFORCED AS OF STAGE 2, and phase 5b is where. Sealing refuses
// once a key has been used kGcmMaxSeals times. 2^32 seals cannot be reached in
// a test, so the ceiling is settable - which is not a weakening, because the
// path exercised at a ceiling of three is the same fetch_add and the same
// comparison a production key meets at 2^32.
//
// WHAT THIS TEST DOES - six phases, the first five with no sockets.
//
//   Phase 1 (CONTROL)          A seals, B opens, the plaintext comes back.
//                              Without it every refusal below could be a build
//                              in which nothing opens at all.
//   Phase 2 (THE PROPERTY)     A must NOT open its own frame. This is the
//                              whole point: on a single-key build it WOULD
//                              open, so this is the phase that fails if the
//                              split is ever undone.
//   Phase 3 (THE MIRROR)       B seals, A opens, and B cannot open its own -
//                              so phase 2's refusal cannot be a dud key.
//   Phase 4 (WRONG ORDER)      a peer that installed the pair backwards opens
//                              nothing. This is the loud failure the
//                              derivation comment promises.
//   Phase 5b (THE BUDGET)      the send key refuses past its ceiling, the
//                              ceiling is the NIST figure by default, a
//                              re-key resets the count, and opening a frame
//                              spends none of it. Stage 2.
//   Phase 5 (THE LOOPBACK)     the single-key SetKey() still round-trips. Four
//                              callers depend on it - GcmCryptoSelfTest,
//                              p2p_confchannel and TargetcoreSuite - and it is
//                              a legitimate shape, not a leftover.
//   Phase 6 (THE REAL THING)   two hubs, RequireAuth(true), a real socket, and
//                              traffic in BOTH directions. Phases 1-5 drive
//                              P2PeerioGcm directly; only this one runs
//                              KeyXDerive, and it is the phase that puts the
//                              real derivation under the sanitisers.
//
// WHAT PHASE 6 CANNOT PROVE, WRITTEN DOWN BECAUSE IT IS NOT OBVIOUS AND IT
// BOUNDS WHAT A GREEN HERE MEANS:
//
// It cannot catch a SYMMETRIC mislabelling. Both ends run this same code, so
// if the c2s/s2c assignment were swapped in BOTH the send and the receive
// expression, the client would seal with s2c and the server would open with
// s2c and the link would work perfectly. Only an ASYMMETRIC error - one of the
// two expressions wrong - breaks it, and that phase 6 does catch, because
// nothing arrives. No test can distinguish a consistent relabelling from the
// intended one while there is exactly one implementation; that would need a
// second implementation or a pinned test vector, and this project has neither
// for the session cypher. Recorded rather than papered over.
//
// VERDICT = process EXIT CODE:
//   0  PASS   every phase behaved as above
//   1  FAIL   a frame opened that should not have, or refused that should not
//   2  SETUP  key generation / temp-file / listener failure (inconclusive)

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConWsa.h"
#include "P2PeerMsg.h"
#include "P2PeerioGcm.h"
#include "P2PCngCrypto.h"
#include "Msgexception.h"
#include "P2PIdentityStore.h"
#include "P2PAuthLogin.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
static int g_nChecks = 0;
static int g_nFailed = 0;

static void Log ( const char *msg )
{
    std::printf ( "[gcmdirection] %s\n", msg );
    std::fflush ( stdout );
}

static void Check ( bool bOk, const char *pszWhat )
{
    ++g_nChecks;
    if ( !bOk ) ++g_nFailed;
    std::printf ( "[gcmdirection] %-6s %s\n", bOk ? "ok" : "FAIL", pszWhat );
    std::fflush ( stdout );
}

// ---------------------------------------------------------------------------
//  Phases 1 to 5 - the cypher contract, no sockets
//
//  NOTE: these drive P2PeerioGcm directly and say nothing about KeyXDerive.
//        They are the fast, deterministic half; phase 6 is the real path.
static void CypherPhases ( )
{
    unsigned char aK1[p2pcng::kAesKeyLen];
    unsigned char aK2[p2pcng::kAesKeyLen];
    for ( size_t i = 0; i < sizeof(aK1); ++i )
    {
      aK1[i] = (unsigned char)( i * 3 + 5 );
      aK2[i] = (unsigned char)( i * 11 + 2 );
    }

    //  The two ends of a link: A seals with K1 and opens with K2; B is the
    //  mirror. This is exactly what KeyXDerive builds from c2s and s2c.
    P2PeerioGcm oA, oB;
    oA.SetKeyPair ( (const char *)aK1, (int)sizeof(aK1)
                  , (const char *)aK2, (int)sizeof(aK2) );
    oB.SetKeyPair ( (const char *)aK2, (int)sizeof(aK2)
                  , (const char *)aK1, (int)sizeof(aK1) );

    const char szBody[] = "one key per direction";
    const UINT nBody    = (UINT)sizeof(szBody);
    const UINT nSealed  = oA.SealedSize ( nBody );

    std::vector<unsigned char> vAB   ( nSealed );
    std::vector<unsigned char> vBA   ( nSealed );
    std::vector<unsigned char> vPlay ( nBody );

    // -- Phase 1: control -------------------------------------------------
    Log ( "--- phase 1: A seals, B opens (control) ---" );
    const bool bSealedAB = ( oA.Encrypt ( szBody, (char *)&vAB[0], (int)nBody, 0, 0 ) != FALSE );
    Check ( bSealedAB, "A sealed a frame" );

    bool bOpenedB = false;
    if ( bSealedAB )
      bOpenedB = ( oB.Decrypt ( (const char *)&vAB[0], (int)nSealed
                              , (char *)&vPlay[0], 0, 0 ) != FALSE );
    Check ( bOpenedB, "B opened A's frame" );
    Check ( bOpenedB && std::memcmp ( &vPlay[0], szBody, nBody ) == 0,
            "B recovered the plaintext exactly" );

    // -- Phase 2: the property --------------------------------------------
    Log ( "--- phase 2: A must NOT open its own frame (single-key build fails here) ---" );
    const bool bSelfOpened =
        bSealedAB && ( oA.Decrypt ( (const char *)&vAB[0], (int)nSealed
                                  , (char *)&vPlay[0], 0, 0 ) != FALSE );
    Check ( !bSelfOpened, "A refused the frame it sealed itself" );

    // -- Phase 3: the mirror ----------------------------------------------
    Log ( "--- phase 3: the mirror, so phase 2 cannot be a dud key ---" );
    const bool bSealedBA = ( oB.Encrypt ( szBody, (char *)&vBA[0], (int)nBody, 0, 0 ) != FALSE );
    Check ( bSealedBA, "B sealed a frame" );

    bool bOpenedA = false;
    if ( bSealedBA )
      bOpenedA = ( oA.Decrypt ( (const char *)&vBA[0], (int)nSealed
                              , (char *)&vPlay[0], 0, 0 ) != FALSE );
    Check ( bOpenedA, "A opened B's frame" );
    Check ( bOpenedA && std::memcmp ( &vPlay[0], szBody, nBody ) == 0,
            "A recovered the plaintext exactly" );

    const bool bSelfOpenedB =
        bSealedBA && ( oB.Decrypt ( (const char *)&vBA[0], (int)nSealed
                                  , (char *)&vPlay[0], 0, 0 ) != FALSE );
    Check ( !bSelfOpenedB, "B refused the frame it sealed itself" );

    // -- Phase 4: the wrong order -----------------------------------------
    Log ( "--- phase 4: a peer that installed the pair backwards opens nothing ---" );
    {
      P2PeerioGcm oWrong;                // same as A, where it should mirror A
      oWrong.SetKeyPair ( (const char *)aK1, (int)sizeof(aK1)
                        , (const char *)aK2, (int)sizeof(aK2) );
      const bool bWrongOpened =
          bSealedAB && ( oWrong.Decrypt ( (const char *)&vAB[0], (int)nSealed
                                        , (char *)&vPlay[0], 0, 0 ) != FALSE );
      Check ( !bWrongOpened, "a backwards peer opened nothing" );
    }

    // -- Phase 5b: THE NONCE BUDGET (stage 2) ------------------------------
    //  2^32 seals cannot be reached in a test, which is why the ceiling is
    //  settable. Setting it is not a weakening of the check: the enforcement
    //  path exercised here is the same fetch_add and the same comparison a
    //  production key meets at 2^32.
    Log ( "--- phase 5b: the seal budget refuses past its ceiling ---" );
    {
      P2PeerioGcm oBudget;
      oBudget.SetKeyPair ( (const char *)aK1, (int)sizeof(aK1)
                         , (const char *)aK2, (int)sizeof(aK2) );

      Check ( oBudget.GetSealCeiling ( ) == P2PeerioGcm::kGcmMaxSeals,
              "a fresh cypher defaults to the NIST 2^32 ceiling" );
      Check ( oBudget.GetSealCount ( ) == 0, "and to a zero seal count" );

      oBudget.SetSealCeiling ( 3 );

      std::vector<unsigned char> vB ( nSealed );
      int nAdmitted = 0;
      for ( int i = 0; i < 5; ++i )
        if ( oBudget.Encrypt ( szBody, (char *)&vB[0], (int)nBody, 0, 0 ) )
          ++nAdmitted;

      Check ( nAdmitted == 3, "exactly the ceiling was admitted, no more" );
      Check ( oBudget.GetSealCount ( ) >= 3, "the count records what happened" );

      //  The refusal must be the BUDGET and not a broken cypher: raise the
      //  ceiling and the same object seals again. Without this the phase
      //  above would pass on a cypher that had simply stopped working.
      oBudget.SetSealCeiling ( P2PeerioGcm::kGcmMaxSeals );
      Check ( oBudget.Encrypt ( szBody, (char *)&vB[0], (int)nBody, 0, 0 ) != FALSE,
              "raising the ceiling lets it seal - the refusal was the budget" );

      //  A new key is a new budget.
      P2PeerioGcm oReset;
      oReset.SetKeyPair ( (const char *)aK1, (int)sizeof(aK1)
                        , (const char *)aK2, (int)sizeof(aK2) );
      oReset.SetSealCeiling ( 1 );
      oReset.Encrypt ( szBody, (char *)&vB[0], (int)nBody, 0, 0 );
      Check ( oReset.Encrypt ( szBody, (char *)&vB[0], (int)nBody, 0, 0 ) == FALSE,
              "the second seal is refused at a ceiling of one" );
      oReset.SetKeyPair ( (const char *)aK2, (int)sizeof(aK2)
                        , (const char *)aK1, (int)sizeof(aK1) );
      Check ( oReset.GetSealCount ( ) == 0, "re-keying reset the count" );
      Check ( oReset.Encrypt ( szBody, (char *)&vB[0], (int)nBody, 0, 0 ) != FALSE,
              "and the new key seals again on its own budget" );

      //  Decrypt draws no nonce, so it must not spend the budget.
      P2PeerioGcm oRx;
      oRx.SetKeyPair ( (const char *)aK2, (int)sizeof(aK2)
                     , (const char *)aK1, (int)sizeof(aK1) );
      std::vector<unsigned char> vRx ( nBody );
      oRx.Decrypt ( (const char *)&vB[0], (int)nSealed, (char *)&vRx[0], 0, 0 );
      Check ( oRx.GetSealCount ( ) == 0, "opening a frame spends no budget" );
    }

    // -- Phase 5: the loopback form ---------------------------------------
    Log ( "--- phase 5: single-key SetKey() still round-trips (four callers need it) ---" );
    {
      P2PeerioGcm oLoop;
      oLoop.SetKey ( (const char *)aK1, (int)sizeof(aK1), 0, 0 );

      std::vector<unsigned char> vLoop ( nSealed );
      const bool bLoopSealed =
          ( oLoop.Encrypt ( szBody, (char *)&vLoop[0], (int)nBody, 0, 0 ) != FALSE );
      const bool bLoopOpened =
          bLoopSealed && ( oLoop.Decrypt ( (const char *)&vLoop[0], (int)nSealed
                                         , (char *)&vPlay[0], 0, 0 ) != FALSE );
      Check ( bLoopSealed && bLoopOpened, "loopback sealed and opened its own frame" );
      Check ( bLoopOpened && std::memcmp ( &vPlay[0], szBody, nBody ) == 0,
              "loopback recovered the plaintext" );
    }
}

// ---------------------------------------------------------------------------
//  Phase 6 - two hubs, a real socket, traffic BOTH ways
static const wchar_t *kDomain     = L"GcmDir.*";   // the listener PATTERN, not an address
static const wchar_t *kServerAddr = L"GcmDir.Server";
static const wchar_t *kClientAddr = L"GcmDir.Client";

static const wchar_t *kToServer   = L"client-to-server body";
static const wchar_t *kToClient   = L"server-to-client body";

static HANDLE g_hServerGot = 0;        // server saw the client's body
static HANDLE g_hClientGot = 0;        // client saw the server's reply

static bool Contains ( const void *pv, size_t cb, const wchar_t *psz )
{
    const size_t cbNeedle = ( wcslen ( psz ) ) * sizeof(wchar_t);
    if ( !pv || cb < cbNeedle || cbNeedle == 0 ) return false;
    const char *p = (const char *)pv;
    for ( size_t i = 0; i + cbNeedle <= cb; ++i )
      if ( std::memcmp ( p + i, psz, cbNeedle ) == 0 ) return true;
    return false;
}

class DirHub : public P2PeerHub
{
public:
    DirHub ( const wchar_t *pszAddr, bool bServer )
      : P2PeerHub ( pszAddr ), m_bServer ( bServer ), m_bSent ( false )
      , m_strSelf ( pszAddr ) { }

    //  Inbound bodies, both routing modes - refer p2p_sealbcast's note on this
    //  override. The server replies the first time it sees the client's body,
    //  which is what makes this test cover the SERVER-to-CLIENT key as well.
    virtual msgRESULT PeekP2PeerMsg ( P2PeerMsg *pMsg ) override
    {
        if ( pMsg && pMsg->DataSize ( ) > 0 && pMsg->Data ( ) )
        {
          const void  *pv = pMsg->Data ( );
          const size_t cb = (size_t)pMsg->DataSize ( );

          if ( m_bServer && Contains ( pv, cb, kToServer ) )
          {
            if ( g_hServerGot ) SetEvent ( g_hServerGot );
            if ( !m_bSent )
            {
              m_bSent = true;
              P2Psize_t nBytes =
                  (P2Psize_t)( ( wcslen ( kToClient ) + 1 ) * sizeof(wchar_t) );
              PostP2PeerMsg ( new P2PeerMsg32 ( m_strSelf.GetString ( ), kClientAddr,
                                                P2Pmsg_BCast, kToClient, nBytes ) );
              Log ( "server got the client body and replied" );
            }
          }
          else if ( !m_bServer && Contains ( pv, cb, kToClient ) )
          {
            if ( g_hClientGot ) SetEvent ( g_hClientGot );
            Log ( "client got the server reply" );
          }
        }
        return P2PeerHub::PeekP2PeerMsg ( pMsg );
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
        if ( !m_bServer && !m_bSent )
        {
          m_bSent = true;
          P2Psize_t nBytes =
              (P2Psize_t)( ( wcslen ( kToServer ) + 1 ) * sizeof(wchar_t) );
          PostP2PeerMsg ( new P2PeerMsg32 ( m_strSelf.GetString ( ), kServerAddr,
                                            P2Pmsg_BCast, kToServer, nBytes ) );
          Log ( "client logged in and posted its body" );
        }
        return result;
    }

private:
    bool    m_bServer;
    bool    m_bSent;
    CString m_strSelf;
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
    s += "p2p_gcmdirection_"; s += pszLeaf; s += "_"; s += szPid; s += ".tmp";
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

// ---------------------------------------------------------------------------
int main ( int argc, char *argv[] )
{
    const short nPort = ( argc >= 2 ) ? (short)atoi ( argv[1] ) : 7859;

    std::printf ( "p2p_gcmdirection - the session cypher keys each direction "
                  "separately\n" );
    std::printf ( "Port : %d\n", (int)nPort );
    std::fflush ( stdout );

    //  Phases 1-5 first: they need nothing and they are what fails on a
    //  single-key build. If the cypher contract is broken there is no point
    //  standing up a socket to find out again.
    CypherPhases ( );

    // -- Phase 6 ----------------------------------------------------------
    Log ( "--- phase 6: two hubs, RequireAuth(true), traffic BOTH ways ---" );

    //  The pump and Winsock, needed only from here on - phases 1 to 5 drive the
    //  cypher directly and touch neither.
    if ( !StartupP2Pmsg ( 16 ) )
    { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }
    WSADATA oWsaData;
    WSAStartup ( MAKEWORD(2,2), &oWsaData );

    const std::string sSrvKey = TempPath ( "srv_id" );
    const std::string sCliKey = TempPath ( "cli_id" );
    const std::string sSrvAcl = TempPath ( "srv_acl" );
    const std::string sCliAcl = TempPath ( "cli_acl" );

    unsigned char pubSrv[p2pcng::kEcdsaPubLen];
    unsigned char pubCli[p2pcng::kEcdsaPubLen];
    if ( !MakeIdentity ( sSrvKey, pubSrv ) || !MakeIdentity ( sCliKey, pubCli ) )
    { Log ( "SETUP: identity generation failed" ); ScrubTempFiles ( );
      WSACleanup ( ); CleanupP2Pmsg ( ); return 2; }

    if ( p2pcng::AppendAllowList ( sSrvAcl.c_str ( ), "GcmDir.Client", pubCli ) != p2pcng::IdOk ||
         p2pcng::AppendAllowList ( sCliAcl.c_str ( ), "GcmDir.Server", pubSrv ) != p2pcng::IdOk )
    { Log ( "SETUP: allow-list provisioning failed" ); ScrubTempFiles ( );
      WSACleanup ( ); CleanupP2Pmsg ( ); return 2; }

    g_hServerGot = CreateEvent ( 0, TRUE, FALSE, 0 );
    g_hClientGot = CreateEvent ( 0, TRUE, FALSE, 0 );
    if ( !g_hServerGot || !g_hClientGot )
    { Log ( "SETUP: event creation failed" ); ScrubTempFiles ( );
      WSACleanup ( ); CleanupP2Pmsg ( ); return 2; }

    bool bSetupFailed = false;
    {
      DirHub oServer ( kServerAddr, true );
      if ( oServer.SetIdentity  ( sSrvKey.c_str ( ) ) != p2pcng::IdOk ||
           oServer.SetAllowList ( sSrvAcl.c_str ( ) ) != p2pcng::IdOk )
      { Log ( "SETUP: server auth configuration failed" ); bSetupFailed = true; }

      if ( !bSetupFailed )
      {
        oServer.RequireAuth ( true );
        oServer.RequireRevocation ( false );   // documented migration; not this test's subject
        oServer.RequireSeal ( false );         // end-to-end sealing is a different mechanism

        HANDLE hServerThread = oServer.SpawnHub ( );
        if ( !hServerThread ) { Log ( "SETUP: server SpawnHub() failed" ); bSetupFailed = true; }

        P2PeerConWsa *pSvc = bSetupFailed ? 0
                           : P2PeerConWsa::ServiceFactory ( kDomain, nPort );
        if ( !bSetupFailed && !pSvc )
        { Log ( "SETUP: ServiceFactory failed" ); bSetupFailed = true; }

        if ( !bSetupFailed )
        {
          oServer.PostP2PeerCon ( pSvc );
          Sleep ( 500 );

          DirHub oClient ( kClientAddr, false );
          if ( oClient.SetIdentity  ( sCliKey.c_str ( ) ) != p2pcng::IdOk ||
               oClient.SetAllowList ( sCliAcl.c_str ( ) ) != p2pcng::IdOk )
          { Log ( "SETUP: client auth configuration failed" ); bSetupFailed = true; }

          if ( !bSetupFailed )
          {
            oClient.RequireAuth ( true );
            oClient.RequireRevocation ( false );
            oClient.RequireSeal ( false );

            HANDLE hClientThread = oClient.SpawnHub ( );
            if ( !hClientThread ) { Log ( "SETUP: client SpawnHub() failed" ); bSetupFailed = true; }

            P2PeerConWsa *pCli = bSetupFailed ? 0
                               : P2PeerConWsa::ClientFactory ( kServerAddr, L"127.0.0.1", nPort );
            if ( !bSetupFailed && !pCli )
            { Log ( "SETUP: ClientFactory failed" ); bSetupFailed = true; }

            if ( !bSetupFailed )
            {
              oClient.PostP2PeerCon ( pCli );

              const DWORD dwUp = WaitForSingleObject ( g_hServerGot, 15000 );
              Check ( dwUp == WAIT_OBJECT_0,
                      "client-to-server body arrived over a real authenticated link" );

              const DWORD dwDn = WaitForSingleObject ( g_hClientGot, 15000 );
              Check ( dwDn == WAIT_OBJECT_0,
                      "server-to-client reply arrived - the OTHER direction's key works" );

              Sleep ( 300 );
            }
            oClient.CloseHub ( );
            // NOTES: CloseHub() waits for the pump thread to LEAVE, but it is
            //        documented to leave the SpawnHub() handle alone - refer
            //        P2PeerHub.cpp:493, "IT ONLY READS THE MEMBER". The handle
            //        is the caller's, and on Linux it owns a P2PThreadImpl
            //        holding the std::thread: CloseHandle is what joins-or-
            //        detaches it and frees that (Platform/p2pthread.h:221-230).
            //        Omitting it leaves a thread TSan never sees ended and
            //        32+24 bytes LSan never sees freed - which is exactly what
            //        the first sanitiser run to contain this test reported on
            //        2026-09-19. Wait-then-close is the pattern the harness
            //        already uses for the relay threads (a8108cd).
            if ( hClientThread )
            {
              WaitForSingleObject ( hClientThread, 3000 );
              CloseHandle ( hClientThread );
            }
          }
        }
        oServer.CloseHub ( );
        if ( hServerThread )
        {
          WaitForSingleObject ( hServerThread, 3000 );
          CloseHandle ( hServerThread );
        }
      }
    }

    if ( g_hServerGot ) CloseHandle ( g_hServerGot );
    if ( g_hClientGot ) CloseHandle ( g_hClientGot );
    ScrubTempFiles ( );
    WSACleanup ( );
    CleanupP2Pmsg ( );

    if ( bSetupFailed )
    {
      Log ( "SETUP failure - phase 6 inconclusive" );
      std::printf ( "[gcmdirection] checks : %d  (%d failed)\n", g_nChecks, g_nFailed );
      std::fflush ( stdout );
      return 2;
    }

    std::printf ( "\n[gcmdirection] checks : %d  (%d failed)\n", g_nChecks, g_nFailed );
    std::printf ( "[gcmdirection] result : %s\n", g_nFailed == 0 ? "PASS" : "FAIL" );
    if ( g_nFailed == 0 )
      std::printf (
        "[gcmdirection]\n"
        "[gcmdirection] What this proves: the cypher keys the two directions\n"
        "[gcmdirection] separately, so each key has ONE writer and the 2^32\n"
        "[gcmdirection] random-nonce budget is per direction and countable -\n"
        "[gcmdirection] and, since phase 5b, that it is COUNTED and REFUSED at\n"
        "[gcmdirection] its ceiling, the refusal being the budget rather than a\n"
        "[gcmdirection] cypher that has stopped working.\n"
        "[gcmdirection] What it does NOT prove: that the c2s/s2c labels are\n"
        "[gcmdirection] the intended way round, which no test can show while\n"
        "[gcmdirection] there is one implementation. Refer the header.\n" );
    std::fflush ( stdout );
    return g_nFailed == 0 ? 0 : 1;
}
