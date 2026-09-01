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
// p2p_armgate.cpp - ProductionPlan.md Stage 3 step 8: RequireAuth(true) BY
// DEFAULT, and what a hub does when it cannot honour that.
//
// WHAT CHANGED, AND WHY THE DEFAULT ALONE IS NOT THE PROTECTION
//
// From the day peer authentication landed until 2026-08-18 it was off unless
// somebody asked for it. Off meant a hub verified nothing, and the deployments
// that most needed verification were exactly the ones that never called
// RequireAuth. Flipping the default closes that - but flipping it ON ITS OWN
// would trade one silent failure for a louder, later one: a hub that requires
// auth and holds no keys does not refuse an attacker, it refuses EVERYONE, and
// it does so at the first peer's login. Which is to say, in production, at
// 3am, to the operator who was not the one who deployed it.
//
// So the default flip comes with an ARMING GATE. A hub that requires auth and
// cannot enforce it does not start at all: CreateHub() returns FALSE and
// SpawnHub() returns 0, and the refusal names the file that is missing. The
// failure moves from the first peer's connection to the deployment, which is
// the only time anyone is looking.
//
// AND ON 2026-08-21 THE GATE GREW A SECOND QUESTION (Stage 3 step 19).
// RequireRevocation now defaults to true, so a hub that requires auth must
// also hold a revocation POSITION: name a list, or say RequireRevocation
// (false). The two halves it adds do NOT rest on the same argument, and the
// phases below are built to keep them apart.
//
//   * A CONFIGURED list that will not load fails closed - every point reads
//     as revoked - so that hub refuses EVERY peer. That is step 8's argument
//     exactly, and phase 10 is its falsification.
//   * NO list refuses nobody. That hub WORKS. It is gated anyway, because
//     revocation is the only mechanism here for WITHDRAWING trust already
//     granted, and phase 8 is the case. This is a bigger break than step 8's
//     and the test says so rather than burying it.
//
// WHAT THIS TEST DOES - ten phases, no sockets. Every phase is a hub that
// is asked to arm, and the question is only ever whether it did.
//
//   Phase 1 (THE DEFAULT)      a hub configured with NOTHING must not arm, and
//                              must say the identity is what is missing.
//   Phase 2 (HALF PROVISIONED) identity but no allow-list: still refuses, and
//                              the reported reason MOVES ON to the allow-list.
//                              Without this, phase 1 could be a hub that never
//                              arms for any reason at all.
//   Phase 3 (EMPTY ALLOW-LIST) a file that exists and parses and lists nobody.
//                              Refuses, distinctly. This is the state reached
//                              by accident - created the file, has not filled
//                              it in - and it is the same refuse-everyone
//                              outcome as having no file, so it is the same
//                              refusal to arm.
//   Phase 4 (POSITIVE CONTROL) fully provisioned: MUST arm. Without it every
//                              refusal above is indistinguishable from a build
//                              in which nothing arms.
//   Phase 5 (THE FALSIFICATION) the one ProductionPlan.md names: take the hub
//                              of phase 4, DELETE ITS ALLOW-LIST, and watch it
//                              refuse to arm - reporting ArmAllowUnusable and
//                              still able to NAME the path, because "not
//                              configured" is a diagnostic an operator has to
//                              decode and "<path> could not be read" is one
//                              they can act on.
//   Phase 6 (THE MIGRATION)    RequireAuth(false) arms, unprovisioned, exactly
//                              as the tree did before the flip. This is the
//                              documented one-line migration, and if it did
//                              not work the change would be an outage rather
//                              than a default.
//   Phase 8 (NO POSITION)      identity and allow-list and nothing said about
//                              revocation - the state every deployment
//                              provisioned before 2026-08-21 is in. Refuses,
//                              and the reason MOVES ON to revocation, so it
//                              cannot be phase 4 failing for another reason.
//   Phase 9 (THE OTHER         RequireRevocation(false) arms. Without it the
//            MIGRATION)        change is an outage rather than a default. It
//                              also checks the opt-out is NARROW - auth is
//                              still required afterwards.
//   Phase 10 (FALSIFICATION 2) provision a revocation list, watch it arm,
//                              DELETE the list, and watch the same hub refuse
//                              with ArmRevocationUnusable - distinctly from
//                              ArmNoRevocation, naming the revocation file and
//                              not the allow-list. Then prove the opt-out does
//                              not excuse it.
//   Phase 7 (FIRST RUN)        ProvisionAuth() creates the identity, writes
//                              the publishable half beside it, and hands back
//                              the fingerprint an operator reads down a phone
//                              line. Run twice: the second run must find the
//                              key rather than replace it - a first-run helper
//                              that regenerates on restart would rotate every
//                              hub's identity behind the operator's back.
//
// WHAT IT DELIBERATELY DOES NOT TEST: that an authenticated login works. That
// is p2p_authpsk's job and it has been passing since 2026-08-11. This is about
// the state BEFORE any peer arrives.
//
// VERDICT = process EXIT CODE:
//   0  PASS   every phase behaved as above
//   1  FAIL   a hub armed that should not have, or refused that should not
//   2  SETUP  key generation / temp-file failure (test inconclusive)

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
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
    std::printf ( "[armgate] %s\n", msg );
    std::fflush ( stdout );
}

static void Check ( bool bOk, const char *pszWhat )
{
    ++g_nChecks;
    if ( !bOk ) ++g_nFailed;
    std::printf ( "[armgate] %-6s %s\n", bOk ? "ok" : "FAIL", pszWhat );
    std::fflush ( stdout );
}

// ---------------------------------------------------------------------------
// Temp files, same shape as p2p_keyrotate - process-id qualified so two runs
// on one machine cannot collide, and scrubbed on every exit path.
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
    s += "p2p_armgate_"; s += pszLeaf; s += "_"; s += szPid; s += ".tmp";
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

static bool MakeIdentity ( const std::string &sPath, unsigned char *pPubOut )
{
    p2pcng::EcdsaP256 oKey;
    if ( !oKey.Generate ( ) ) return false;
    if ( p2pcng::SaveIdentity ( sPath.c_str ( ), oKey ) != p2pcng::IdOk ) return false;
    return oKey.ExportPublic ( pPubOut );
}

//  fopen rather than GetFileAttributes: the Platform shim carries DeleteFileA
//  but not the attribute query, and "can I open it for reading" is the only
//  property this test needs from the .pub file anyway.
static bool FileExists ( const std::string &sPath )
{
    FILE *pf = std::fopen ( sPath.c_str ( ), "rb" );
    if ( !pf ) return false;
    std::fclose ( pf );
    return true;
}

static bool WriteEmptyFile ( const std::string &sPath )
{
    //  A file that EXISTS and parses to nothing. '#' comments and blank lines
    //  are ignored by LoadAllowList, so this loads cleanly and lists nobody -
    //  which is the point of the phase.
    FILE *pf = std::fopen ( sPath.c_str ( ), "wb" );
    if ( !pf ) return false;
    std::fputs ( "# an allow-list that names nobody\n\n", pf );
    std::fclose ( pf );
    return true;
}

//  A revocation list that is VALID and lists one throwaway point. Not an
//  empty file: this test is about whether a POSITION has been taken, and a
//  list with an entry in it is the ordinary provisioned state. The point
//  belongs to a key generated here and used for nothing else, so it revokes
//  nobody who exists.
static bool MakeRevocationList ( const std::string &sPath )
{
    p2pcng::EcdsaP256 oThrowaway;
    if ( !oThrowaway.Generate ( ) ) return false;

    unsigned char aPoint[p2pcng::kIdRevokePointLen];
    if ( !oThrowaway.ExportPublic ( aPoint ) ) return false;

    return p2pcng::AppendRevocationList ( sPath.c_str ( ), aPoint, 0,
                                          "p2p_armgate throwaway" )
           == p2pcng::IdOk;
}

// ---------------------------------------------------------------------------
// Ask a hub to arm and report what happened. Uses SpawnHub rather than
// CreateHub because the refusal has to be observed WITHOUT the caller having
// to pump anything - and because SpawnHub is the one every deployment in this
// tree actually calls. CreateHub is checked once in phase 1, so the two cannot
// drift apart on whether they gate at all.
// ---------------------------------------------------------------------------
static bool TryArm ( P2PeerHub &oHub )
{
    HANDLE hThread = oHub.SpawnHub ( );
    if ( !hThread )
      return false;

    oHub.CloseHub ( );
    WaitForSingleObject ( hThread, 5000 );
    CloseHandle ( hThread );
    return true;
}

static const char *ArmName ( p2pauth::ArmResult e )
{
    switch ( e )
    {
      case p2pauth::ArmOk:            return "ArmOk";
      case p2pauth::ArmNotRequired:   return "ArmNotRequired";
      case p2pauth::ArmNoIdentity:    return "ArmNoIdentity";
      case p2pauth::ArmNoAllowList:   return "ArmNoAllowList";
      case p2pauth::ArmAllowUnusable: return "ArmAllowUnusable";
      case p2pauth::ArmEmptyAllow:    return "ArmEmptyAllow";
      case p2pauth::ArmNoRevocation:  return "ArmNoRevocation";
      case p2pauth::ArmRevocationUnusable: return "ArmRevocationUnusable";
    }
    return "?";
}

// =========================================================================
int main ( int argc, char *argv[] )
{
    (void)argc; (void)argv;

    std::printf ( "=== p2p_armgate - ProductionPlan Stage 3 steps 8 and 19 ===\n" );
    std::printf ( "Asserting: a hub that requires auth and cannot enforce it "
                  "does not start,\n"
                  "           and that since 2026-08-21 that includes having "
                  "no position on revocation.\n\n" );
    std::fflush ( stdout );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }

    const std::string sKey   = TempPath ( "identity" );
    const std::string sAcl   = TempPath ( "allow"    );
    const std::string sEmpty = TempPath ( "empty"    );
    const std::string sNew   = TempPath ( "firstrun" );
    //  A SECOND allow-list, because phase 5 DELETES the first one - that is
    //  the falsification, not a leak - and every phase after it that wants a
    //  provisioned hub needs a file that still exists.
    const std::string sAcl2   = TempPath ( "allow2"    );
    const std::string sRev    = TempPath ( "revoke"    );
    const std::string sRevDel = TempPath ( "revokedel" );

    unsigned char aPub[p2pcng::kEcdsaPubLen];
    if ( !MakeIdentity ( sKey, aPub ) )
    { Log ( "SETUP: identity generation failed" ); ScrubTempFiles ( ); CleanupP2Pmsg ( ); return 2; }
    if ( p2pcng::AppendAllowList ( sAcl.c_str ( ), "Arm.Peer", aPub ) != p2pcng::IdOk )
    { Log ( "SETUP: allow-list provisioning failed" ); ScrubTempFiles ( ); CleanupP2Pmsg ( ); return 2; }
    if ( !WriteEmptyFile ( sEmpty ) )
    { Log ( "SETUP: empty allow-list creation failed" ); ScrubTempFiles ( ); CleanupP2Pmsg ( ); return 2; }
    if ( p2pcng::AppendAllowList ( sAcl2.c_str ( ), "Arm.Peer", aPub ) != p2pcng::IdOk )
    { Log ( "SETUP: second allow-list provisioning failed" ); ScrubTempFiles ( ); CleanupP2Pmsg ( ); return 2; }
    if ( !MakeRevocationList ( sRev ) || !MakeRevocationList ( sRevDel ) )
    { Log ( "SETUP: revocation list creation failed" ); ScrubTempFiles ( ); CleanupP2Pmsg ( ); return 2; }

    // ---- Phase 1: THE DEFAULT ---------------------------------------------
    Log ( "--- phase 1: a hub configured with nothing at all ---" );
    {
        P2PeerHub oHub ( L"Arm.Bare" );

        Check ( oHub.IsAuthRequired ( ),
                "RequireAuth defaults to TRUE (nothing was called)" );

        p2pauth::ArmResult eArm = oHub.AuthArm ( );
        std::printf ( "[armgate]        AuthArm() = %s: %s\n",
                      ArmName ( eArm ), p2pauth::AuthArmText ( eArm ) );
        Check ( eArm == p2pauth::ArmNoIdentity,
                "unconfigured hub reports ArmNoIdentity" );

        Check ( !TryArm ( oHub ),      "SpawnHub() REFUSED an unconfigured hub" );
        Check ( oHub.GetHubID ( ) == 0,
                "no pump thread was left behind by the refusal" );

        //  CreateHub gates too - the two arm paths must not drift.
        Check ( !oHub.CreateHub ( L"Arm.Bare" ),
                "CreateHub() REFUSED an unconfigured hub" );
    }

    // ---- Phase 2: HALF PROVISIONED ----------------------------------------
    Log ( "--- phase 2: an identity, and no allow-list ---" );
    {
        P2PeerHub oHub ( L"Arm.IdOnly" );
        if ( oHub.SetIdentity ( sKey.c_str ( ) ) != p2pcng::IdOk )
        { Log ( "SETUP: SetIdentity failed" ); ScrubTempFiles ( ); CleanupP2Pmsg ( ); return 2; }

        p2pauth::ArmResult eArm = oHub.AuthArm ( );
        std::printf ( "[armgate]        AuthArm() = %s: %s\n",
                      ArmName ( eArm ), p2pauth::AuthArmText ( eArm ) );
        Check ( eArm == p2pauth::ArmNoAllowList,
                "the reported reason MOVED ON to the allow-list" );
        Check ( !TryArm ( oHub ), "SpawnHub() REFUSED a hub with no allow-list" );
    }

    // ---- Phase 3: AN ALLOW-LIST THAT NAMES NOBODY -------------------------
    Log ( "--- phase 3: an allow-list that exists, parses, and lists nobody ---" );
    {
        P2PeerHub oHub ( L"Arm.Empty" );
        if ( oHub.SetIdentity  ( sKey  .c_str ( ) ) != p2pcng::IdOk )
        { Log ( "SETUP: SetIdentity failed" ); ScrubTempFiles ( ); CleanupP2Pmsg ( ); return 2; }

        //  IdOk: it is a VALID file. That is what makes this its own phase -
        //  nothing in the loading path objects to it.
        Check ( oHub.SetAllowList ( sEmpty.c_str ( ) ) == p2pcng::IdOk,
                "an allow-list naming nobody LOADS without error" );

        p2pauth::ArmResult eArm = oHub.AuthArm ( );
        std::printf ( "[armgate]        AuthArm() = %s: %s\n",
                      ArmName ( eArm ), p2pauth::AuthArmText ( eArm ) );
        Check ( eArm == p2pauth::ArmEmptyAllow,
                "an empty allow-list is its own refusal, not ArmOk" );
        Check ( !TryArm ( oHub ), "SpawnHub() REFUSED a hub that trusts nobody" );
    }

    // ---- Phase 4: THE POSITIVE CONTROL ------------------------------------
    Log ( "--- phase 4: fully provisioned - this one MUST start ---" );
    {
        P2PeerHub oHub ( L"Arm.Good" );
        //  THREE files since 2026-08-21, not two. "Fully provisioned" grew a
        //  revocation list when the gate did, and this phase is the definition
        //  of the term - if it did not move, the positive control would be
        //  asserting a state no deployment can now reach.
        if ( oHub.SetIdentity       ( sKey.c_str ( ) ) != p2pcng::IdOk ||
             oHub.SetAllowList      ( sAcl.c_str ( ) ) != p2pcng::IdOk ||
             oHub.SetRevocationList ( sRev.c_str ( ) ) != p2pcng::IdOk )
        { Log ( "SETUP: provisioning failed" ); ScrubTempFiles ( ); CleanupP2Pmsg ( ); return 2; }

        Check ( oHub.IsRevocationRequired ( ),
                "RequireRevocation defaults to TRUE (nothing was called)" );

        p2pauth::ArmResult eArm = oHub.AuthArm ( );
        std::printf ( "[armgate]        AuthArm() = %s: %s\n",
                      ArmName ( eArm ), p2pauth::AuthArmText ( eArm ) );
        Check ( eArm == p2pauth::ArmOk, "a provisioned hub reports ArmOk" );
        Check ( TryArm ( oHub ),
                "SpawnHub() STARTED a provisioned hub (positive control)" );
    }

    // ---- Phase 5: THE FALSIFICATION ---------------------------------------
    Log ( "--- phase 5: THE FALSIFICATION - delete the allow-list ---" );
    {
        P2PeerHub oHub ( L"Arm.Deleted" );
        if ( oHub.SetIdentity       ( sKey.c_str ( ) ) != p2pcng::IdOk ||
             oHub.SetAllowList      ( sAcl.c_str ( ) ) != p2pcng::IdOk ||
             oHub.SetRevocationList ( sRev.c_str ( ) ) != p2pcng::IdOk )
        { Log ( "SETUP: provisioning failed" ); ScrubTempFiles ( ); CleanupP2Pmsg ( ); return 2; }
        Check ( oHub.AuthArm ( ) == p2pauth::ArmOk,
                "armed before the allow-list was removed" );

        DeleteFileA ( sAcl.c_str ( ) );
        Log ( "allow-list file deleted" );

        //  The hub keeps running on the list it already validated - that is
        //  deliberate, and it is why the reload is what changes the answer
        //  rather than the deletion. What must NOT survive is the claim to be
        //  provisioned: this hub is one restart from having nothing.
        Check ( oHub.ReloadAllowList ( ) != p2pcng::IdOk,
                "ReloadAllowList() reports the failure" );

        p2pauth::ArmResult eArm = oHub.AuthArm ( );
        std::printf ( "[armgate]        AuthArm() = %s: %s\n",
                      ArmName ( eArm ), p2pauth::AuthArmText ( eArm ) );
        Check ( eArm == p2pauth::ArmAllowUnusable,
                "a deleted allow-list reports ArmAllowUnusable" );

        const char *pszPath = oHub.AuthAllowListPath ( );
        std::printf ( "[armgate]        AuthAllowListPath() = %s\n",
                      pszPath ? pszPath : "(null)" );
        Check ( pszPath && sAcl == pszPath,
                "the refusal can still NAME the file that went missing" );

        Check ( !TryArm ( oHub ),
                "SpawnHub() REFUSED after the allow-list went missing" );
    }

    // ---- Phase 6: THE MIGRATION -------------------------------------------
    Log ( "--- phase 6: RequireAuth(false), the documented one-line migration ---" );
    {
        P2PeerHub oHub ( L"Arm.OptOut" );
        oHub.RequireAuth ( false );

        Check ( !oHub.IsAuthRequired ( ), "RequireAuth(false) took" );

        p2pauth::ArmResult eArm = oHub.AuthArm ( );
        std::printf ( "[armgate]        AuthArm() = %s: %s\n",
                      ArmName ( eArm ), p2pauth::AuthArmText ( eArm ) );
        Check ( eArm == p2pauth::ArmNotRequired,
                "reports ArmNotRequired - NOT ArmOk, so 'armed' cannot be "
                "misread as 'authenticating'" );
        Check ( TryArm ( oHub ),
                "SpawnHub() STARTED an unprovisioned hub that opted out" );
    }

    // ---- Phase 7: FIRST RUN -----------------------------------------------
    Log ( "--- phase 7: ProvisionAuth(), the first-run story ---" );
    {
        const std::string sPub = sNew + ".pub";
        DeleteFileA ( sNew.c_str ( ) );
        DeleteFileA ( sPub.c_str ( ) );

        char szFp1[p2pcng::kIdFingerprintLen] = { 0 };
        bool bCreated = false;

        P2PeerHub oHub ( L"Arm.FirstRun" );
        p2pcng::IdResult e = oHub.ProvisionAuth ( sNew.c_str ( ), szFp1,
                                                  sizeof(szFp1), &bCreated );
        Check ( e == p2pcng::IdOk,  "ProvisionAuth() succeeded on a fresh path" );
        Check ( bCreated,           "it reported that it CREATED the key" );
        Check ( szFp1[0] != 0,      "it handed back a fingerprint to publish" );
        std::printf ( "[armgate]        fingerprint = %s\n", szFp1 );

        Check ( FileExists ( sPub ),
                "it wrote the publishable half beside the identity (.pub)" );
        Check ( oHub.CanAuthSign ( ),
                "the hub can sign with the key it just made" );

        //  Still refuses to arm: a key is half of provisioning, and WHO TO
        //  TRUST is the half no library can supply.
        Check ( oHub.AuthArm ( ) == p2pauth::ArmNoAllowList,
                "provisioned identity alone still does not arm - the "
                "allow-list is the operator's half" );

        //  Second run. A first-run helper that regenerates on restart would
        //  rotate every hub's identity behind the operator's back, and every
        //  peer that had published the old point would stop being able to
        //  verify it.
        char szFp2[p2pcng::kIdFingerprintLen] = { 0 };
        bool bCreated2 = true;
        P2PeerHub oHub2 ( L"Arm.SecondRun" );
        e = oHub2.ProvisionAuth ( sNew.c_str ( ), szFp2, sizeof(szFp2), &bCreated2 );
        Check ( e == p2pcng::IdOk,  "ProvisionAuth() succeeded on the second run" );
        Check ( !bCreated2,         "the second run FOUND the key rather than making one" );
        Check ( std::strcmp ( szFp1, szFp2 ) == 0,
                "the identity did not change between runs" );
    }

    // ---- Phase 8: NO REVOCATION POSITION ----------------------------------
    Log ( "--- phase 8: identity and allow-list, and nothing said about "
          "revocation ---" );
    {
        //  The state EVERY deployment provisioned before 2026-08-21 is in, and
        //  the reason this break is louder than step 8's: this hub works. It
        //  refuses nobody, it verifies logins correctly, and it starts. The
        //  gate stops it anyway, because it can never withdraw a key.
        P2PeerHub oHub ( L"Arm.NoRevoc" );
        if ( oHub.SetIdentity  ( sKey .c_str ( ) ) != p2pcng::IdOk ||
             oHub.SetAllowList ( sAcl2.c_str ( ) ) != p2pcng::IdOk )
        { Log ( "SETUP: provisioning failed" ); ScrubTempFiles ( ); CleanupP2Pmsg ( ); return 2; }

        Check ( !oHub.IsRevocationConfigured ( ),
                "no revocation list is configured" );

        p2pauth::ArmResult eArm = oHub.AuthArm ( );
        std::printf ( "[armgate]        AuthArm() = %s: %s\n",
                      ArmName ( eArm ), p2pauth::AuthArmText ( eArm ) );
        Check ( eArm == p2pauth::ArmNoRevocation,
                "the reported reason MOVED ON to revocation - so this is not "
                "phase 4 failing for the allow-list's reason" );
        Check ( !TryArm ( oHub ),
                "SpawnHub() REFUSED a hub that can never withdraw a key" );

        //  The refusal must name the REVOCATION file, and there is none - so
        //  it names nothing rather than naming the allow-list, which is fine
        //  and is the whole point of the path being per-result.
        Check ( oHub.AuthRevocationListPath ( ) == 0,
                "AuthRevocationListPath() is null - the refusal does not "
                "misdirect to the allow-list, which is present and correct" );
    }

    // ---- Phase 9: THE MIGRATION, second half ------------------------------
    Log ( "--- phase 9: RequireRevocation(false), the other one-line "
          "migration ---" );
    {
        P2PeerHub oHub ( L"Arm.RevocOptOut" );
        if ( oHub.SetIdentity  ( sKey .c_str ( ) ) != p2pcng::IdOk ||
             oHub.SetAllowList ( sAcl2.c_str ( ) ) != p2pcng::IdOk )
        { Log ( "SETUP: provisioning failed" ); ScrubTempFiles ( ); CleanupP2Pmsg ( ); return 2; }

        oHub.RequireRevocation ( false );
        Check ( !oHub.IsRevocationRequired ( ), "RequireRevocation(false) took" );

        p2pauth::ArmResult eArm = oHub.AuthArm ( );
        std::printf ( "[armgate]        AuthArm() = %s: %s\n",
                      ArmName ( eArm ), p2pauth::AuthArmText ( eArm ) );
        Check ( eArm == p2pauth::ArmOk,
                "reports ArmOk - the hub is authenticating, it has simply "
                "declared that having no revocation list is deliberate" );
        Check ( TryArm ( oHub ),
                "SpawnHub() STARTED a hub that opted out of revocation" );

        //  WITHOUT THIS PHASE THE CHANGE IS AN OUTAGE RATHER THAN A DEFAULT,
        //  which is the same thing phase 6 says about RequireAuth(false).
        Check ( oHub.IsAuthRequired ( ),
                "and it is still REQUIRING AUTH - the opt-out is narrow, it "
                "did not turn authentication off as a side effect" );
    }

    // ---- Phase 10: THE SECOND FALSIFICATION -------------------------------
    Log ( "--- phase 10: FALSIFICATION - delete a CONFIGURED revocation "
          "list ---" );
    {
        //  The half that DOES rest on step 8's argument. A configured list
        //  that will not load makes every point read as revoked, so this hub
        //  refuses every peer - it used to do that at the first login, having
        //  started happily.
        P2PeerHub oHub ( L"Arm.RevocDeleted" );
        if ( oHub.SetIdentity       ( sKey   .c_str ( ) ) != p2pcng::IdOk ||
             oHub.SetAllowList      ( sAcl2  .c_str ( ) ) != p2pcng::IdOk ||
             oHub.SetRevocationList ( sRevDel.c_str ( ) ) != p2pcng::IdOk )
        { Log ( "SETUP: provisioning failed" ); ScrubTempFiles ( ); CleanupP2Pmsg ( ); return 2; }

        Check ( oHub.AuthArm ( ) == p2pauth::ArmOk,
                "armed before the revocation list was removed" );

        DeleteFileA ( sRevDel.c_str ( ) );
        Log ( "revocation list file deleted" );

        Check ( oHub.ReloadRevocationList ( ) != p2pcng::IdOk,
                "ReloadRevocationList() reports the failure" );

        p2pauth::ArmResult eArm = oHub.AuthArm ( );
        std::printf ( "[armgate]        AuthArm() = %s: %s\n",
                      ArmName ( eArm ), p2pauth::AuthArmText ( eArm ) );
        Check ( eArm == p2pauth::ArmRevocationUnusable,
                "a deleted revocation list reports ArmRevocationUnusable - "
                "NOT ArmNoRevocation, which would read as never configured" );

        const char *pszPath = oHub.AuthRevocationListPath ( );
        std::printf ( "[armgate]        AuthRevocationListPath() = %s\n",
                      pszPath ? pszPath : "(null)" );
        Check ( pszPath && sRevDel == pszPath,
                "the refusal NAMES the revocation file that went missing - "
                "and not the allow-list, which is still there" );

        Check ( !TryArm ( oHub ),
                "SpawnHub() REFUSED after the revocation list went missing" );

        //  AND IT IS NOT ESCAPABLE BY THE OPT-OUT. A switch that said "require
        //  no position" must not also mean "and run on a broken one".
        oHub.RequireRevocation ( false );
        Check ( oHub.AuthArm ( ) == p2pauth::ArmRevocationUnusable,
                "RequireRevocation(false) does NOT excuse a configured list "
                "that will not load" );
    }

    // ---- Verdict -----------------------------------------------------------
    std::printf ( "\n[armgate] %d checks, %d failed\n", g_nChecks, g_nFailed );
    ScrubTempFiles ( );
    CleanupP2Pmsg ( );

    if ( g_nFailed )
    {
      std::printf ( "\nRESULT: FAIL - the arming gate does not hold.\n" );
      return 1;
    }
    std::printf ( "\nRESULT: PASS - a hub that requires auth and cannot enforce "
                  "it does not start,\n"
                  "        it names the file that is missing - the right one "
                  "of the two - and both opt-outs still work.\n" );
    return 0;
}
