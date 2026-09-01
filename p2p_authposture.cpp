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
// p2p_authposture.cpp - can a RUNNING hub be asked whether any of its
// protections are on? TargetCore ProductionPlan.md F-S6-2, THREAT_MODEL.md
// asset S9.
//
// BACKGROUND. Stage 4 step 13 put the two numbers an operator asks for -
// "is it keeping up" and "how many peers is it holding" - into the hub's
// snapshot, and p2p_hubsnap is the gate that keeps them there. Neither
// snapshot carried a single SECURITY fact. Not whether the hub requires
// authentication, not whether it holds a key at all, not whether relay
// attestation is on, not whether a revocation list is loaded, not whether
// THIS connection authenticated, not as whom, and not whether its cypher is
// installed. A deployment could confirm its own posture only by reading the
// source of the library it had linked.
//
// F-S6-1 is why that is a finding and not a wish. From the day the defaults
// went on (2026-08-18) until 2026-08-20, "this hub requires authentication"
// and "this connection is encrypted" were different facts on the same hub,
// and nothing inside the process or outside it could have discovered they
// had come apart. The divergence was found by writing a threat model, which
// is not an instrument that runs on every build.
//
// WHAT IT MEASURES. A monitor that touches NOTHING but the public
// P2PeerHub::Serialise() and P2PeerCon::Serialise() - no friend access, no
// internal header, no accessor the library did not already export to a
// stranger - reads the posture of three differently-configured hubs and of
// two connections. The restriction is the test: a monitor allowed to call
// IsAuthRequired() directly would prove the accessor works, which was never
// in doubt, rather than that the SNAPSHOT carries it.
//
//   Phase 1 (AUTH OFF). A hub with no identity and RequireAuth(false):
//   all nine hub fields present, AuthRequired=0, AuthCanSign=0, AuthArm=1
//   (ArmNotRequired).
//
//   Phase 2 (AUTH ON). A hub with an identity, an allow-list and
//   RequireAuth(true): AuthRequired=1, AuthCanSign=1, AuthArm=0 (ArmOk).
//   Read against phase 1 this is also the constant-field gate that PumpsMax
//   failed for years - a field wired to a literal passes any test that only
//   reads it, so every one of these three must MOVE between the two hubs.
//
//   Phase 3 (THE F-S6-1 SHAPE). A hub that holds a key and requires nothing -
//   the ordinary state of a peer provisioned for somewhere else in the tree,
//   and exactly the configuration whose two halves came apart. AuthCanSign=1
//   and AuthRequired=0 must read as two DIFFERENT values out of one snapshot.
//   If the snapshot collapsed intent and capability into one "secure" field,
//   this is the phase that fails, and it is the whole reason there are three
//   fields rather than one.
//
//   Phase 4 (AN AUTHENTICATED CONNECTION). A real login between two hubs that
//   both require it. The connection's snapshot must say AuthDone=1,
//   KeyXDone=1, Cypher=1, OffProcess=1, and AuthPeer must name the peer's
//   address - the one the verified transcript covered, not the one the peer
//   asked to be called.
//
//   Phase 5 (AN UNAUTHENTICATED CONNECTION). The same code path with no
//   identity anywhere and RequireAuth(false) at both ends. The three proof
//   flags must read 0 and AuthPeer must be empty. Without this phase, fields
//   hard-wired to 1 would pass phase 4. OffProcess stays 1: it is a property
//   of the TRANSPORT, not of the login, and TCP leaves the process whether
//   anyone authenticated or not - which is the point of it being a separate
//   field.
//
// WHAT Cypher DOES AND DOES NOT SAY. Cypher=1 says the io object holds a
// cypher AND the class holding it consults its hooks. It does not say the
// bytes on this particular wire were encrypted, and it cannot. What it now
// comes with is OffProcess, added closing F-S6-3, and the pair is readable
// where the single field was not: 0/0 is the in-process DMX handoff and is
// correct, 1/0 is a plaintext wire - and a hub that requires authentication
// no longer creates the second one, because P2PeerCon::KeyXDerive refuses to
// key it (see p2p_confchannel, which is that rule's gate). This test covers
// TCP, where the base class is what runs and the answer is 1/1.
//
// VERDICT = process EXIT CODE:
//   0  PASS   every field present, and every one of them tracks reality
//   1  FAIL   a field is absent, constant, or reports the wrong posture
//   2  SETUP  startup / provisioning failure (test inconclusive)
//   3  INCONCLUSIVE the authenticated login never completed, so phase 4
//                   measures nothing - check p2p_authchannel and wsa_mesh
//
// Build (Linux): as p2p_authchannel.cpp.

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerCon.h"
#include "P2PeerConWsa.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"
#include "P2PIdentityStore.h"
#include "P2PAuthLogin.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <exception>
#include <cstdlib>
#include <string>

// ---------------------------------------------------------------------------
static const P2PaddrSTR kSrvAddr   = L"Posture.Server";
static const P2PaddrSTR kCliAddr   = L"Posture.Client";
static const P2PaddrSTR kDomain    = L"Posture.*";

static const P2PaddrSTR kSrvOpen   = L"Postopen.Server";
static const P2PaddrSTR kCliOpen   = L"Postopen.Client";
static const P2PaddrSTR kDomOpen   = L"Postopen.*";

static HANDLE g_hLoggedIn  = NULL;   // client saw its login acknowledged (auth)
static HANDLE g_hOpenLogin = NULL;   // ...and on the unauthenticated pair

//  Route the library's own diagnostics into this test's stdout. Without it
//  a refusal raised on a pump thread goes wherever P2Pevent decides, which
//  for a console process is not this transcript - and a gate that cannot say
//  WHY the peer was refused is a gate that reports "inconclusive" forever.
static void WINAPI DiagSink ( P2Pevent_e eClass, LPCWSTR lpszOrigin,
                              LPCWSTR lpszText )
{
    std::string sOrigin, sText;
    for ( const wchar_t *w = lpszOrigin; w && *w; ++w )
        sOrigin.push_back ( *w < 0x80 ? (char)*w : '?' );
    for ( const wchar_t *w = lpszText;   w && *w; ++w )
        sText.push_back   ( *w < 0x80 ? (char)*w : '?' );
    std::printf ( "[authposture][diag %d] %s: %s\n",
                  (int)eClass, sOrigin.c_str ( ), sText.c_str ( ) );
    std::fflush ( stdout );
}

//  Name what kills the process, instead of leaving a bare exit code.
//  NOTES: This is not decoration. The first version of this test died with
//         exit 3, no output and no stderr, because a monitor called
//         SelectItem() on a name Exists() had confirmed through a dotted path
//         and the library threw a P2Pevent that nothing on that stack caught.
//         An unhandled throw inside a SECURITY gate that reports only a number
//         is indistinguishable from a hang, a crash and a refusal
//       : Exits 1. A gate that died did not measure what it claims to measure,
//         and the one thing it must never do is look like a pass
static void PostureTerminate ( )
{
    std::printf ( "[authposture] TERMINATE - unhandled exception\n" );
    std::fflush ( stdout );
    try { throw; }
    catch ( P2Pevent *pEvent )
    {
        std::printf ( "[authposture] TERMINATE - P2Pevent* raised\n" );
        if ( pEvent ) pEvent -> Display ( );
        std::fflush ( stdout );
    }
    catch ( ... ) { std::printf ( "[authposture] TERMINATE - unknown\n" ); }
    std::fflush ( stdout );
    std::printf ( "\nRESULT: FAIL - the gate died before it could report.\n" );
    std::fflush ( stdout );
    _exit ( 1 );
}

static void Log ( const char *msg )
{
    std::printf ( "[authposture] %s\n", msg );
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
    s += "p2p_authposture_"; s += pszLeaf; s += "_"; s += szPid; s += ".tmp";
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
//  THE MONITOR, and the restriction on it is the test.
//  NOTES: One call per subject - the public Serialise() - and named fields
//         read out of the P3PmsgItem that comes back. It would work
//         identically against a snapshot that had arrived over a wire as
//         MSG_P2PexpHub, because that message is built by calling the same
//         function
//       : ReadNum() rather than c_int(), for the reason p2p_hubsnap gives:
//         c_int() throws on a width or sign mismatch, so a monitor built on
//         it would have to already know the cell width of a field it did not
//         write. ReadAnyInt is the width-agnostic read
//       : A string field is COPIED out immediately. On Linux c_wstr() returns
//         a pointer into a ring of thread-local buffers that the next
//         accessor call on this thread recycles - see F-S5-3, and the same
//         mistake in P2PeerHub::RouteP2PeerMsg
struct Snap
{
    //  Templated on the node type because a connection snapshot has to be
    //  DESCENDED (see ConPosture::Poll) and a descent hands back a
    //  P3PmsgField, not a P3PmsgItem.
    //
    //  Exists() first, and never SelectItem() on a name it has not confirmed:
    //  SelectItem THROWS on a missing item, and the throw is not caught
    //  anywhere in a monitor's call stack. Writing this the other way round is
    //  what killed the first version of this test with a bare exit code and no
    //  message - and the dotted PATH form ("{P2PeerCon}.AuthDone") is worse
    //  than useless here, because Exists resolves it and SelectItem does not,
    //  so a reader that trusts the pair gets a confirmed name and then an
    //  exception on it.
    template <class NodeT>
    static bool ReadNum ( NodeT& oSnap, LPCWSTR lpszName, long& nOut )
    {
        if ( !oSnap.Exists ( lpszName ) )
          return false;
        INT64 i64       = 0;
        bool  bUnsigned = false;
        if ( !oSnap.SelectItem ( lpszName ).r_data ( ).ReadAnyInt ( i64, bUnsigned ) )
          return false;
        nOut = (long)i64;
        return true;
    }

    template <class NodeT>
    static bool ReadStr ( NodeT& oSnap, LPCWSTR lpszName, std::string& sOut )
    {
        if ( !oSnap.Exists ( lpszName ) )
          return false;
        sOut = N ( oSnap.SelectItem ( lpszName ).c_wstr ( ) );
        return true;
    }
};

//  A hub's security posture, as a stranger can read it
struct HubPosture
{
    bool bReadable;
    long nAuthReq, nCanSign, nArm;
    long nRelayAuth, nRelayReplay, nSealReplay;
    long nRevocList, nRevocOk, nRevocFresh;
    long nPostureOk;               // the hub could read its own posture
    long nRevocEpoch;

    HubPosture ( )
      : bReadable(false), nAuthReq(-1), nCanSign(-1), nArm(-1)
      , nRelayAuth(-1), nRelayReplay(-1), nSealReplay(-1)
      , nRevocList(-1), nRevocOk(-1), nRevocFresh(-1), nRevocEpoch(-1)
      , nPostureOk(-1) { }

    void Poll ( P2PeerHub& oHub )
    {
        P3PmsgItem oSnap = oHub.Serialise ( 0 );
        bReadable = Snap::ReadNum ( oSnap, L"PostureOk",    nPostureOk   ) &&
                    Snap::ReadNum ( oSnap, L"AuthRequired", nAuthReq     ) &&
                    Snap::ReadNum ( oSnap, L"AuthCanSign",  nCanSign     ) &&
                    Snap::ReadNum ( oSnap, L"AuthArm",      nArm         ) &&
                    Snap::ReadNum ( oSnap, L"RelayAuth",    nRelayAuth   ) &&
                    Snap::ReadNum ( oSnap, L"RelayReplay",  nRelayReplay ) &&
                    Snap::ReadNum ( oSnap, L"SealReplay",   nSealReplay  ) &&
                    Snap::ReadNum ( oSnap, L"RevocList",    nRevocList   ) &&
                    Snap::ReadNum ( oSnap, L"RevocOk",      nRevocOk     ) &&
                    Snap::ReadNum ( oSnap, L"RevocFresh",   nRevocFresh  ) &&
                    Snap::ReadNum ( oSnap, L"RevocEpoch",   nRevocEpoch  );
    }

    void Report ( const char *szWho ) const
    {
        std::printf ( "[authposture] %-18s PostureOk=%ld AuthRequired=%ld AuthCanSign=%ld AuthArm=%ld"
                      "  RelayAuth=%ld RelayReplay=%ld SealReplay=%ld"
                      "  RevocList=%ld RevocOk=%ld RevocFresh=%ld RevocEpoch=%ld\n"
                    , szWho, nPostureOk, nAuthReq, nCanSign, nArm
                    , nRelayAuth, nRelayReplay, nSealReplay
                    , nRevocList, nRevocOk, nRevocFresh, nRevocEpoch );
        std::fflush ( stdout );
    }
};

//  A connection's proof state, as a stranger can read it
struct ConPosture
{
    bool        bFound;
    bool        bReadable;
    long        nAuthDone, nKeyXDone, nCypher, nOffProcess;
    std::string sAuthPeer;
    std::string sPath;              // which prefix the fields were found under

    ConPosture ( )
      : bFound(false), bReadable(false)
      , nAuthDone(-1), nKeyXDone(-1), nCypher(-1), nOffProcess(-1) { }

    //  A connection snapshot is a TREE, and that is the shape of the
    //  diagnostic image rather than an inconvenience of this test. Every
    //  transport subclass builds its own node - {P2PeerConWsa} carries the IP
    //  address and port - and appends the base class's {P2PeerCon} node to it,
    //  which is where the posture lives. So the monitor tries the plain name
    //  first (a bare P2PeerCon) and then descends one level, which is the same
    //  two steps for any transport. Guessing wrong is not silent: the prefix
    //  that worked is printed, so a future subclass that buries it deeper
    //  shows up as an unreadable snapshot rather than as a wrong value
    void Poll ( P2PeerHub& oHub, P2PaddrSTR strPeer )
    {
        SafeP2PeerCon oSafeCon;
        if ( !oHub.ConQuery ( strPeer, oSafeCon ) || (P2PeerCon *)oSafeCon == 0 )
          return;
        bFound = true;

        P3PmsgItem oSnap = ((P2PeerCon *)oSafeCon) -> Serialise ( 0 );

        if ( Read ( oSnap ) )
        { sPath = "(top level)"; return; }

        if ( oSnap.Exists ( L"{P2PeerCon}" ) &&
             Read ( oSnap.SelectItem ( L"{P2PeerCon}" ) ) )
          sPath = "{P2PeerCon}";
    }

    template <class NodeT>
    bool Read ( NodeT& oNode )
    {
        bReadable = Snap::ReadNum ( oNode, L"AuthDone",   nAuthDone   ) &&
                    Snap::ReadNum ( oNode, L"KeyXDone",   nKeyXDone   ) &&
                    Snap::ReadNum ( oNode, L"Cypher",     nCypher     ) &&
                    Snap::ReadNum ( oNode, L"OffProcess", nOffProcess ) &&
                    Snap::ReadStr ( oNode, L"AuthPeer",   sAuthPeer   );
        return bReadable;
    }

    void Report ( const char *szWho ) const
    {
        std::printf ( "[authposture] %-18s AuthDone=%ld KeyXDone=%ld Cypher=%ld"
                      " OffProcess=%ld  AuthPeer='%s'  [under '%s']\n"
                    , szWho, nAuthDone, nKeyXDone, nCypher, nOffProcess
                    , sAuthPeer.c_str ( ), sPath.c_str ( ) );
        std::fflush ( stdout );
    }
};

// =========================================================================
//  The hub. It exists to signal that a login completed - nothing here
//  reaches into the library for a posture, because reaching in is the one
//  thing this test may not do
class PostureHub : public P2PeerHub
{
public:
    PostureHub ( P2PaddrSTR strAddr, HANDLE hLoggedIn )
      : P2PeerHub ( strAddr ), m_hLoggedIn ( hLoggedIn ) { }
    virtual ~PostureHub ( ) { }

protected:
    virtual conRESULT On_ConLoginAck ( P2PeerCon  *pCon,
                                       P2PaddrSTR  strThisP2Paddr,
                                       P2PaddrSTR  strThatP2Paddr,
                                       const void *pvLoginAck,
                                       P2Psize_t   iSize ) override
    {
        conRESULT result = P2PeerHub::On_ConLoginAck ( pCon, strThisP2Paddr,
                                                       strThatP2Paddr,
                                                       pvLoginAck, iSize );
        if ( m_hLoggedIn ) SetEvent ( m_hLoggedIn );
        return result;
    }

private:
    HANDLE m_hLoggedIn;
};

// =========================================================================
int main ( int argc, char *argv[] )
{
    short nPort     = ( argc >= 2 ) ? (short)atoi ( argv[1] ) : 7838;
    short nPortOpen = (short)( nPort + 1 );

    std::printf ( "=== p2p_authposture - can a running hub be asked what is on? ===\n" );
    std::printf ( "Ports: %d (authenticated), %d (open)\n",
                  (int)nPort, (int)nPortOpen );
    std::printf ( "Asserting: the hub and connection snapshots carry the security\n"
                  "           posture, and every field tracks the hub it came from.\n\n" );
    std::fflush ( stdout );

    g_hLoggedIn  = CreateEvent ( NULL, TRUE, FALSE, NULL );
    g_hOpenLogin = CreateEvent ( NULL, TRUE, FALSE, NULL );

    P2Pevent::SetTextSink ( &DiagSink );
    std::set_terminate ( &PostureTerminate );

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
    if ( !MakeIdentity ( sSrvKey, pubSrv ) ||
         !MakeIdentity ( sCliKey, pubCli ) )
    { Log ( "SETUP: identity generation failed" ); ScrubTempFiles ( ); return 2; }

    if ( p2pcng::AppendAllowList ( sSrvAcl.c_str ( ), "Posture.Client", pubCli ) != p2pcng::IdOk ||
         p2pcng::AppendAllowList ( sCliAcl.c_str ( ), "Posture.Server", pubSrv ) != p2pcng::IdOk )
    { Log ( "SETUP: allow-list provisioning failed" ); ScrubTempFiles ( ); return 2; }

    int  nExit    = 0;
    bool bSetup   = false;
    bool bNoLogin = false;

    {
        // ---- Phase 1: a hub with nothing switched on ----------------------
        // SPAWNED, then read, then closed. The finding is that a RUNNING hub
        // cannot be asked what is on, so every hub here runs - and a hub
        // constructed and never armed is a state this library does not
        // otherwise get asked about.
        HubPosture oOff;
        {
            PostureHub oPlain ( L"Postnone.Hub", NULL );
            oPlain.RequireAuth ( false );
            HANDLE hPlain = oPlain.SpawnHub ( );
            if ( !hPlain ) { Log ( "SETUP: phase 1 SpawnHub failed" ); bSetup = true; }
            else
            {
              oOff.Poll ( oPlain );
              oPlain.CloseHub ( );
              WaitForSingleObject ( hPlain, 3000 );
              CloseHandle ( hPlain );
            }
        }
        if ( bSetup ) { ScrubTempFiles ( ); return 2; }
        oOff.Report ( "auth OFF" );
        if ( !oOff.bReadable )
        {
            Log ( "FAILED (1) - the hub snapshot does not carry the posture at all" );
            Log ( "             this is F-S6-2 exactly: nine fields, none present" );
            nExit = 1;
        }
        else if ( oOff.nAuthReq != 0 || oOff.nCanSign != 0 ||
                  oOff.nArm != (long)p2pauth::ArmNotRequired )
        {
            Log ( "FAILED (1) - a hub with no key and RequireAuth(false) reports "
                  "otherwise" );
            nExit = 1;
        }
        else if ( oOff.nPostureOk != 1 )
        {
            //  The posture is read with TryEnterCriticalSection so that a
            //  snapshot can never wait on the hub it is describing - see
            //  P2PeerHub.h for the lock order that forces it. Nothing else is
            //  touching this hub here, so a 0 means the non-blocking read is
            //  broken rather than contended
            Log ( "FAILED (1) - the hub could not read its own posture on an "
                  "idle hub" );
            nExit = 1;
        }
        else if ( oOff.nRevocList != 0 )
        {
            //  This assertion exists because the first version of the field
            //  FAILED it. RevocList was IsRevocationUsable(), which is true for
            //  a hub with no list at all - so a hub with no revocation reported
            //  its revocation as fine. Reading it is what found that; keep the
            //  reading
            Log ( "FAILED (1) - a hub with no revocation list says it has one" );
            nExit = 1;
        }
        else
            Log ( "OK (1) - auth off reads as off, no revocation claimed, and "
                  "it says why it is armed" );

        // ---- Phase 3 first: the F-S6-1 shape ------------------------------
        // Out of numerical order deliberately: it is the same lightweight
        // construct-and-read as phase 1, and doing it here keeps every hub
        // that needs a pump in one block below.
        HubPosture oKeyNoReq;
        {
            PostureHub oProv ( L"Postkey.Hub", NULL );
            if ( oProv.SetIdentity ( sCliKey.c_str ( ) ) != p2pcng::IdOk )
            { Log ( "SETUP: phase 3 identity load failed" ); bSetup = true; }
            oProv.RequireAuth ( false );
            HANDLE hProv = bSetup ? NULL : oProv.SpawnHub ( );
            if ( !hProv ) { Log ( "SETUP: phase 3 SpawnHub failed" ); bSetup = true; }
            else
            {
              oKeyNoReq.Poll ( oProv );
              oProv.CloseHub ( );
              WaitForSingleObject ( hProv, 3000 );
              CloseHandle ( hProv );
            }
        }
        if ( bSetup ) { ScrubTempFiles ( ); return 2; }
        oKeyNoReq.Report ( "key, no require" );

        if ( !oKeyNoReq.bReadable )
        {
            Log ( "FAILED (3) - posture unreadable on a hub that holds a key" );
            nExit = 1;
        }
        else if ( oKeyNoReq.nCanSign != 1 || oKeyNoReq.nAuthReq != 0 )
        {
            Log ( "FAILED (3) - intent and capability do not read separately" );
            Log ( "             this is the F-S6-1 state, and it must be visible:" );
            Log ( "             a hub that CAN sign and does not REQUIRE anything" );
            nExit = 1;
        }
        else
            Log ( "OK (3) - AuthCanSign=1 with AuthRequired=0, read as two facts" );

        // ---- Phase 2, 4 and 5: hubs that run ------------------------------
        PostureHub oServer ( kSrvAddr, NULL );
        if ( oServer.SetIdentity  ( sSrvKey.c_str ( ) ) != p2pcng::IdOk ||
             oServer.SetAllowList ( sSrvAcl.c_str ( ) ) != p2pcng::IdOk )
        { Log ( "SETUP: server auth configuration failed" ); ScrubTempFiles ( ); return 2; }
        oServer.RequireAuth ( true );
        //  RequireRevocation(false) since 2026-08-21 (Stage 3 step 19): a hub
        //  that requires auth must now hold a POSITION on revocation, and this
        //  test is not about revocation. Saying so is the documented migration
        //  and it is one line. It does NOT turn revocation off - a list named
        //  anyway is still loaded, still enforced and still fails closed.
        oServer.RequireRevocation ( false );

        HubPosture oOn;
        oOn.Poll ( oServer );
        oOn.Report ( "auth ON" );

        if ( !oOn.bReadable )
        {
            Log ( "FAILED (2) - posture unreadable on the configured hub" );
            nExit = 1;
        }
        else if ( oOn.nAuthReq != 1 || oOn.nCanSign != 1 ||
                  oOn.nArm != (long)p2pauth::ArmOk )
        {
            Log ( "FAILED (2) - a hub with a key, an allow-list and "
                  "RequireAuth(true) reports otherwise" );
            nExit = 1;
        }
        else if ( oOn.nAuthReq == oOff.nAuthReq || oOn.nArm == oOff.nArm )
        {
            //  The constant-field gate. PumpsMax reported a literal 0 on every
            //  hub that ever ran and survived years of tests that only read it
            Log ( "FAILED (2) - the field does not MOVE between two differently "
                  "configured hubs; it is a constant, not a reading" );
            nExit = 1;
        }
        else
            Log ( "OK (2) - auth on reads as on, and differs from the hub that is off" );

        HANDLE hServerThread = oServer.SpawnHub ( );
        if ( !hServerThread ) { Log ( "SETUP: server SpawnHub() failed" ); ScrubTempFiles ( ); return 2; }

        P2PeerConWsa *pSvc = P2PeerConWsa::ServiceFactory ( kDomain, nPort );
        if ( !pSvc ) { Log ( "SETUP: ServiceFactory failed" ); ScrubTempFiles ( ); return 2; }
        oServer.PostP2PeerCon ( pSvc );
        Sleep ( 500 );

        // ---- Phase 4: an authenticated connection -------------------------
        {
            PostureHub oClient ( kCliAddr, g_hLoggedIn );
            if ( oClient.SetIdentity  ( sCliKey.c_str ( ) ) != p2pcng::IdOk ||
                 oClient.SetAllowList ( sCliAcl.c_str ( ) ) != p2pcng::IdOk )
            { Log ( "SETUP: client auth configuration failed" ); bSetup = true; }
            else
            {
              oClient.RequireAuth ( true );
              oClient.RequireRevocation ( false );
              Log ( "phase 4: client configured, dialling the server" );

              HANDLE hCliThread = oClient.SpawnHub ( );
              P2PeerConWsa *pCon =
                  P2PeerConWsa::ClientFactory ( kSrvAddr, L"127.0.0.1", nPort );
              if ( !hCliThread || !pCon )
              { Log ( "SETUP: phase 4 client hub or connection failed" ); bSetup = true; }
              else
              {
                oClient.PostP2PeerCon ( pCon );
                Log ( "phase 4: connection posted, waiting for the login ack" );


                if ( WaitForSingleObject ( g_hLoggedIn, 15000 ) != WAIT_OBJECT_0 )
                {
                  Log ( "INCONCLUSIVE (4) - the authenticated login never "
                        "completed" );
                  bNoLogin = true;
                }
                else
                {
                  //  Read from MAIN, off the pump thread, through the hub's own
                  //  lookup - the route any monitor takes. Not from inside a
                  //  handler, where a retained pointer would be proving
                  //  something about this test rather than about the snapshot
                  ConPosture oAuthCon;
                  oAuthCon.Poll ( oClient, kSrvAddr );
                  oAuthCon.Report ( "authenticated" );

                  if ( !oAuthCon.bFound )
                  {
                    Log ( "INCONCLUSIVE (4) - the connection was gone before it "
                          "could be read" );
                    bNoLogin = true;
                  }
                  else if ( !oAuthCon.bReadable )
                  {
                    Log ( "FAILED (4) - the connection snapshot carries no proof "
                          "state; F-S6-2 on the connection half" );
                    nExit = 1;
                  }
                  else if ( oAuthCon.nAuthDone != 1 || oAuthCon.nKeyXDone != 1 ||
                            oAuthCon.nCypher != 1 || oAuthCon.nOffProcess != 1 )
                  {
                    Log ( "FAILED (4) - an authenticated, agreed, encrypted "
                          "connection over TCP does not report itself as one" );
                    nExit = 1;
                  }
                  else if ( oAuthCon.sAuthPeer != N ( kSrvAddr ) )
                  {
                    Log ( "FAILED (4) - AuthPeer does not name the identity the "
                          "signature verified as" );
                    nExit = 1;
                  }
                  else
                    Log ( "OK (4) - proven, agreed, encrypted, and it names its peer" );
                }
                oClient.CloseHub ( );
                WaitForSingleObject ( hCliThread, 3000 );
                CloseHandle ( hCliThread );
              }
            }
        }

        oServer.CloseHub ( );
        WaitForSingleObject ( hServerThread, 3000 );
        CloseHandle ( hServerThread );
        Sleep ( 300 );

        // ---- Phase 5: an unauthenticated connection -----------------------
        // No identity, no allow-list, RequireAuth(false) at both ends. Without
        // this, four fields wired to 1 pass phase 4.
        if ( nExit == 0 && !bNoLogin )
        {
            PostureHub oSrvOpen ( kSrvOpen, NULL );
            oSrvOpen.RequireAuth ( false );
            HANDLE hSrvOpenThread = oSrvOpen.SpawnHub ( );
            P2PeerConWsa *pSvcOpen = hSrvOpenThread
                ? P2PeerConWsa::ServiceFactory ( kDomOpen, nPortOpen ) : 0;
            if ( !hSrvOpenThread || !pSvcOpen ) { Log ( "SETUP: open server failed" ); bSetup = true; }
            else
            {
              oSrvOpen.PostP2PeerCon ( pSvcOpen );
              Sleep ( 500 );

              PostureHub oCliOpen ( kCliOpen, g_hOpenLogin );
              oCliOpen.RequireAuth ( false );
              HANDLE hCliOpenThread = oCliOpen.SpawnHub ( );
              P2PeerConWsa *pConOpen =
                  P2PeerConWsa::ClientFactory ( kSrvOpen, L"127.0.0.1", nPortOpen );
              if ( !hCliOpenThread || !pConOpen ) { Log ( "SETUP: open client failed" ); bSetup = true; }
              else
              {
                oCliOpen.PostP2PeerCon ( pConOpen );
                if ( WaitForSingleObject ( g_hOpenLogin, 15000 ) != WAIT_OBJECT_0 )
                {
                  Log ( "INCONCLUSIVE (5) - the unauthenticated login never "
                        "completed" );
                  bNoLogin = true;
                }
                else
                {
                  ConPosture oOpenCon;
                  oOpenCon.Poll ( oCliOpen, kSrvOpen );
                  oOpenCon.Report ( "unauthenticated" );

                  if ( !oOpenCon.bFound || !oOpenCon.bReadable )
                  {
                    Log ( "INCONCLUSIVE (5) - the open connection could not be read" );
                    bNoLogin = true;
                  }
                  else if ( oOpenCon.nAuthDone != 0 || oOpenCon.nKeyXDone != 0 ||
                            oOpenCon.nCypher != 0 || !oOpenCon.sAuthPeer.empty ( ) )
                  {
                    Log ( "FAILED (5) - an unauthenticated connection in clear "
                          "reports itself as proven or encrypted" );
                    Log ( "             the proof fields are constants, and phase 4 "
                          "proved nothing" );
                    nExit = 1;
                  }
                  // OffProcess is NOT in the test above, and must not be. It
                  // describes the transport rather than the login, so TCP
                  // answers 1 in both phases - which is the whole reason
                  // F-S6-3 made it a field of its own rather than folding it
                  // into Cypher. Asserted here so that a reader does not take
                  // its absence from the phase-5 list for an oversight.
                  else if ( oOpenCon.nOffProcess != 1 )
                  {
                    Log ( "FAILED (5) - a TCP connection reports that its frames "
                          "do not leave this process" );
                    nExit = 1;
                  }
                  else
                    Log ( "OK (5) - no proof, no agreement, no cypher, no identity" );
                }
                oCliOpen.CloseHub ( );
                WaitForSingleObject ( hCliOpenThread, 3000 );
                CloseHandle ( hCliOpenThread );
              }
              oSrvOpen.CloseHub ( );
              WaitForSingleObject ( hSrvOpenThread, 3000 );
              CloseHandle ( hSrvOpenThread );
            }
        }
    }

    ScrubTempFiles ( );
    WSACleanup ( );
    CleanupP2Pmsg ( );
    if ( g_hLoggedIn  ) CloseHandle ( g_hLoggedIn  );
    if ( g_hOpenLogin ) CloseHandle ( g_hOpenLogin );

    if ( bSetup )
    {
        std::printf ( "\nRESULT: SETUP - the harness could not be built, so nothing "
                      "was measured.\n" );
        return 2;
    }
    if ( bNoLogin && nExit == 0 )
    {
        std::printf (
          "\nRESULT: INCONCLUSIVE - a login this test depends on never completed,\n"
          "  so the connection posture was never read. This is NOT a pass. Check\n"
          "  p2p_authchannel and wsa_mesh first.\n" );
        return 3;
    }
    if ( nExit != 0 )
    {
        std::printf (
          "\nRESULT: FAIL - a running hub cannot be asked what is switched on, or\n"
          "  the answer it gives does not track the hub it came from. That is\n"
          "  ProductionPlan.md F-S6-2, and F-S6-1 is what it costs: two facts came\n"
          "  apart for two days and nothing could have reported it.\n" );
        return 1;
    }

    std::printf (
      "\nRESULT: PASS - the posture is in both snapshots and every field moved\n"
      "  with the hub it was read from. Intent (AuthRequired), capability\n"
      "  (AuthCanSign) and enforceability (AuthArm) read separately, which is\n"
      "  the F-S6-1 shape, and a connection reports whether it is proven, agreed\n"
      "  and encrypted, and as whom.\n" );
    return 0;
}
