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
// p2p_confchannel.cpp - SECURITY GATE TEST: a hub that requires
// authentication keys the connection. Does it require the TRANSPORT to USE
// the key it just installed?
//
// BACKGROUND - Targetcore ProductionPlan.md F-S6-3, opened by the threat-model
// sweep of Stage 6 step 17 and left open by F-S6-2, which could only report
// it. The cypher lives in P2Peerio::SendP2PeerMsg / RecvP2PeerMsg, so whether
// a transport is encrypted has depended on which subclass its factory happened
// to construct:
//
//   TCP, named pipe, serial -> construct P2Peerio itself   -> hooks run
//   DMX  (P2PeerConDmx)     -> constructs P2PeerioDmx      -> hooks do not run
//   -                       -> P2PeerioBSTR                -> hooks do not run
//
// P2PeerioDmx is RIGHT not to encrypt: its handoff is a pointer between two
// objects in one process, so there is no wire. P2PeerioBSTR is the same
// omission with none of the justification, and nothing constructs it - so the
// day a transport is wired to it, that transport is plaintext on a hub whose
// operator set RequireAuth(true).
//
// F-S6-1's fix cannot catch that, and this is the part worth stating plainly:
// it refuses a login when KeyXWanted() is true and the agreement has NOT
// completed. Here the agreement HAS completed. The cypher IS installed. The
// override simply does not consult it. Every condition F-S6-1 tests is
// satisfied by the defective connection.
//
// So the distinction was made by CLASS - true of every transport in the tree
// by inheritance, enforced nowhere - which is a convention, not a rule.
//
// WHAT THE FIX IS. Two declarations a subclass author has to make, stated over
// "Protocol translation" in P2Peerio.h where they will meet them:
//
//   LeavesProcess()  - do this class's frames leave this process (default
//                      TRUE, so silence means "a wire", never "exempt")
//   IsCypherActive() - is a cypher installed AND consulted
//
// and the pair true/false refused at P2PeerCon::KeyXDerive, at the instant the
// cypher is installed and BEFORE m_bKeyXDone is set. P2PeerioDmx answers false
// to the first and is exempt by DECLARATION rather than by being recognised as
// itself. A second enforcement in P2Peerio::Send catches the author who
// overrides the message methods and declares nothing.
//
// WHAT THIS TEST DOES - one in-process phase and four over TCP.
//
//   Phase 0 (THE DECLARATIONS). Every io class in the tree, constructed
//   directly, given a cypher through PostP2Pcrypto(), and asked both
//   questions. This is the rule's INPUT, and it is checked separately because
//   a wrong answer here would make every later phase pass for the wrong
//   reason. P2Peerio must read 1/1, P2PeerioDmx 0/0, P2PeerioBSTR 1/0 - and
//   the base class before the cypher is posted must read 1/0 too, or "Cypher"
//   is a constant. It also requires P2PeerioBSTR to ANNOUNCE itself when
//   constructed - the "make the omission loud" half of the fix - which is
//   where this test found that a warning is not loud at all by default (see
//   kBstrPhrase below).
//
//   Phase 1 (POSITIVE CONTROL). Stock client to the authenticating server.
//   Must log in and deliver.
//
//   Phase 2 (THE TRANSPORT IS NOT BROKEN). The same client with its io object
//   replaced by MuteIo - which DELEGATES both message methods to the base
//   class, so the bytes on the wire are byte-for-byte phase 1's, and then
//   makes P2PeerioBSTR's DECLARATION about itself. Sent to the OPEN server
//   with RequireAuth(false) at both ends, so no cypher is ever installed and
//   no gate can fire. Must deliver. Without this phase, phase 3's refusal is
//   indistinguishable from an io class that cannot talk.
//
//   Phase 3 (THE FIRST GATE). MuteIo again, unchanged, to the AUTHENTICATING
//   server with RequireAuth(true). One call different from phase 2. Must be
//   refused - by KeyXDerive, reading the declaration.
//
//   Phase 4 (CONTROL FOR PHASE 5). RawIo on the OPEN server. RawIo is the
//   author who declares NOTHING: it overrides SendP2PeerMsg, writes the
//   message image straight to Send() without going near the cypher hooks, and
//   inherits both answers - so LeavesProcess() is true and IsCypherActive()
//   reads the pointer, and the phase 3 gate waves it through. With no cypher
//   in play it must deliver.
//
//   Phase 5 (THE SECOND GATE). The same RawIo to the AUTHENTICATING server.
//   The declaration gate passes it, the agreement completes, the cypher is
//   installed - and the FIRST frame it writes afterwards must be refused by
//   P2Peerio::Send, which requires a sealing decision it never made. This is
//   the enforcement that needs nothing from the subclass author, and it is the
//   residual F-S6-2's note said could not be closed by reporting.
//
//   Phase 6 (LIVENESS). Phase 1 again. A server that has fallen over also
//   refuses everything.
//
// WHAT IT MEASURES, AND WHY NOT DELIVERY. Step 17's gate measured whether a
// payload arrived and PASSED against the tree that had the defect, because
// delivery had its own unrelated reason not to happen. A gate must measure the
// DECISION. So phase 3's verdict is taken from two things at once:
//
//   * the authenticating server never reaching On_ConLogin, and
//   * the refusal itself, read out of the client's own diagnostic stream
//     through P2Pevent::SetTextSink - the text KeyXDerive raises when it
//     refuses to arm. A phase 3 that failed to deliver WITHOUT that
//     diagnostic is not a pass, and this test says so: it reports
//     INCONCLUSIVE rather than green, because something else stopped it.
//
// WHERE THE REFUSAL HAPPENS. On the CLIENT, not the server, and that is
// correct: F-S6-3 is a local misconfiguration, not a remote attack. Nobody on
// the network can make a peer construct the wrong io class - the peer's own
// factory does that - so the connection has to refuse itself. Both ends run
// the same KeyXDerive, so a server built this way refuses in the same line.
//
// NOT WILL_FAIL: it asserts the behaviour the fix gives. Against the tree one
// commit earlier phase 3 delivered its payload, which is the defect.
//
// VERDICT = process EXIT CODE:
//   0  PASS   0 correct, 1/2/4/6 delivered, 3 and 5 refused AT THEIR GATES
//   1  FAIL   a declaration is wrong, or a plaintext connection was keyed
//   2  SETUP  startup / provisioning failure (test inconclusive)
//   3  INCONCLUSIVE a control never arrived, or phase 3 failed silently -
//                   either way the gate was not what was measured
//
// Build (Linux): as p2p_authchannel.cpp.

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConWsa.h"
#include "P2PeerMsg.h"
#include "P2Peerio.h"
#include "P2PeerioDmx.h"
#include "P2PeerioBSTR.h"
#include "P2PeerioGcm.h"
#include "Msgexception.h"
#include "P2PIdentityStore.h"
#include "P2PAuthLogin.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
static const P2PaddrSTR kAuthSrvAddr = L"ConfChan.Server";
static const P2PaddrSTR kOpenSrvAddr = L"ConfOpen.Server";
static const P2PaddrSTR kClientAddr  = L"ConfChan.Client";
static const P2PaddrSTR kOpenCliAddr = L"ConfOpen.Client";
static const P2PaddrSTR kAuthDomain  = L"ConfChan.*";
static const P2PaddrSTR kOpenDomain  = L"ConfOpen.*";

static const wchar_t *kPay1 = L"phase1-stock-io";
static const wchar_t *kPay2 = L"phase2-mute-io-open-hub";
static const wchar_t *kPay3 = L"phase3-mute-io-auth-hub";
static const wchar_t *kPay4 = L"phase4-raw-io-open-hub";
static const wchar_t *kPay5 = L"phase5-raw-io-auth-hub";
static const wchar_t *kPay6 = L"phase6-liveness";

static HANDLE g_hPay1 = NULL;
static HANDLE g_hPay2 = NULL;
static HANDLE g_hPay3 = NULL;   // must stay unsignalled
static HANDLE g_hPay4 = NULL;
static HANDLE g_hPay5 = NULL;   // must stay unsignalled
static HANDLE g_hPay6 = NULL;

// Login ACCEPTANCE at the authenticating server - the decision, not one of its
// consequences. Set from On_ConLogin, which is downstream of every gate.
static HANDLE g_hLogin1 = NULL;
static HANDLE g_hLogin3 = NULL;   // must stay unsignalled
static HANDLE g_hLogin5 = NULL;   // must stay unsignalled
static HANDLE g_hLogin6 = NULL;

static int g_nPhase = 0;

// Set by the diagnostic sink when the F-S6-3 refusal is raised anywhere in
// this process. Written with InterlockedExchange because the sink runs on
// whichever thread raised the event, which is routinely a hub's own pump; READ
// plainly, because every read below happens after RunPhase has closed the hub
// and joined its thread, so there is no writer left to race with. The
// interlocked READ this used to do was not buying that ordering - it was
// InterlockedCompareExchange, which the Linux compatibility layer does not
// provide, and the Linux build is where that showed up.
static volatile LONG g_lGateRefusal = 0;

static void Log ( const char *msg )
{
    std::printf ( "[confchannel] %s\n", msg );
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

//  THE PAYLOAD POINTER IS NOT ALIGNED, so it cannot be read as wchar_t in
//  place.  P2PeerMsg::Data() addresses the application bytes where they sit
//  inside the packed message image, and that image is pack(1) - a payload
//  begins at whatever offset the block headers and names ahead of it add up
//  to, which is odd about half the time.  Casting it to wchar_t* is undefined
//  behaviour; on Linux, where wchar_t wants 4-byte alignment, UBSan reports it
//  at the dereference.  Targetcore's finding F-S5-3.
//    Copying the bytes out into storage the caller aligned is the fix.  See
//  P3PmsgData::c_vBlobCopy() for the same thing offered as an accessor.
static std::wstring BodyW ( P2PeerMsg *pMsg )
{
    if ( !pMsg || !pMsg->Data ( ) ) return std::wstring ( );
    const size_t cb = (size_t)pMsg->DataSize ( );
    std::wstring w ( cb / sizeof(wchar_t), L'\0' );
    if ( !w.empty ( ) )
      std::memcpy ( &w[0], pMsg->Data ( ), w.size ( ) * sizeof(wchar_t) );
    const size_t nNul = w.find ( L'\0' );      // the payloads are literals
    if ( nNul != std::wstring::npos ) w.resize ( nNul );
    return w;
}

// ---------------------------------------------------------------------------
//  Every diagnostic this process raises, printed - and one of them watched
//  for. The watched phrase is the tail of the message P2PeerCon::KeyXDerive
//  raises when it refuses to arm a transport that will not consult the cypher
//  it was just given. Matched on a FRAGMENT rather than the whole line,
//  because the assembled text carries the origin and the advice lines too.
//
//  This is what stops phase 3 passing for the wrong reason. A refused
//  connection and a broken one look identical from outside; only the refusal
//  says which happened.
static const char *kGatePhrase = "does not consult it";

//  The other half of the fix, and the half that turned out not to be loud on
//  its own. P2PeerioBSTR's constructor announces that the class takes the
//  cypher hooks out of the path - but it announces it at WARNING, and the
//  default notification mask is P2Pevotn_ERROR ALONE, so the announcement was
//  invisible. This test proved that by NOT seeing it. Phase 0 therefore widens
//  the mask before constructing one, and then requires the warning: a "loud"
//  diagnostic that nothing checks is a claim.
static const char *kBstrPhrase = "does not encrypt";

static volatile LONG g_lBstrWarning = 0;

//  The SECOND enforcement, in P2Peerio::Send: bytes reaching the writer with a
//  cypher installed and no sealing decision recorded against them. Watched for
//  separately from kGatePhrase, because the two gates answer different
//  failures and a test that could not tell them apart would credit either one
//  with the other's refusal.
static const char *kSendPhrase = "that nothing consulted";

static volatile LONG g_lSendRefusal = 0;

static void WINAPI DiagSink ( P2Pevent_e eClass, LPCWSTR lpszOrigin,
                              LPCWSTR lpszText )
{
    const std::string sOrigin = N ( lpszOrigin );
    const std::string sText   = N ( lpszText );
    std::printf ( "[confchannel][diag %d] %s: %s\n",
                  (int)eClass, sOrigin.c_str ( ), sText.c_str ( ) );
    std::fflush ( stdout );

    if ( sText.find ( kGatePhrase ) != std::string::npos )
        InterlockedExchange ( &g_lGateRefusal, 1 );
    if ( sText.find ( kBstrPhrase ) != std::string::npos )
        InterlockedExchange ( &g_lBstrWarning, 1 );
    if ( sText.find ( kSendPhrase ) != std::string::npos )
        InterlockedExchange ( &g_lSendRefusal, 1 );
}

//  Name what kills the process instead of leaving a bare exit code: an
//  unhandled throw inside a security gate that reports only a number is
//  indistinguishable from a hang, a crash and a refusal. Same reason as
//  p2p_authposture, and the same exit 1 - a gate that died did not measure
//  what it claims to measure.
static void ConfTerminate ( )
{
    std::printf ( "\n[confchannel] TERMINATE - an exception escaped the test.\n"
                  "  This is a FAILURE of the gate, not a verdict from it.\n" );
    std::fflush ( stdout );
    std::exit ( 1 );
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
    s += "p2p_confchannel_"; s += pszLeaf; s += "_"; s += szPid; s += ".tmp";
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
//  MuteIo - P2PeerioBSTR's DECLARATION on a working wire.
//
//  The two message methods DELEGATE to the base class, so every byte this
//  class puts on the wire is a byte P2Peerio put there: phases 2 and 3
//  transport identically to phase 1, and a phase 3 that fails cannot be
//  blamed on framing. What it changes is the pair of answers, and those are
//  copied from P2PeerioBSTR rather than invented - true to LeavesProcess(),
//  false to IsCypherActive().
//
//  WHAT PHASE 3 THEREFORE PROVES, EXACTLY. Because it delegates, MuteIo's
//  frames really are sealed - it LIES about not consulting the cypher. So
//  phase 3 is not a disclosure test and must not be described as one: it
//  proves that the DECLARATION is read and acted on, which is the half of
//  F-S6-3 about P2PeerioBSTR, a class whose identical declaration is true.
//  RawIo below is where cleartext actually reaches the wire.
//
//  Why not drive P2PeerioBSTR itself over TCP: because it would not work, and
//  for a reason that has nothing to do with this gate. It speaks a different
//  framing - a P2Psize_t length prefix and no P2PeerMsg header - so it cannot
//  exchange a key with a peer running the base class, and a phase built on it
//  would be refused whatever the library did. That is precisely the trap step
//  17 recorded. Phase 0 asserts P2PeerioBSTR's own declarations directly,
//  where no transport is involved; this class carries them onto a wire.
class MuteIo : public P2Peerio
{
public:
    virtual P2Peerio* Clone ( ) { return new MuteIo; }

    virtual DWORD SendP2PeerMsg ( HANDLE hFile, P2PeerMsg *pMsg,
                                  OVERLAPPEDcon *pOVERLAPPEDsend )
    {   return P2Peerio::SendP2PeerMsg ( hFile, pMsg, pOVERLAPPEDsend ); }

    virtual P2PeerMsg* RecvP2PeerMsg ( HANDLE hFile,
                                       OVERLAPPEDcon *pOVERLAPPEDrecv )
    {   return P2Peerio::RecvP2PeerMsg ( hFile, pOVERLAPPEDrecv ); }

    virtual bool IsCypherActive ( ) const { return false; }
    virtual bool LeavesProcess  ( ) const { return true;  }
};

// =========================================================================
//  RawIo - the subclass author who declares NOTHING.
//
//  MuteIo above is honest: it overrides the message methods and says so. This
//  one is the case F-S6-2's note said reporting could never close - it
//  overrides SendP2PeerMsg, writes the message image straight to Send(), and
//  answers neither question. It therefore inherits LeavesProcess()==true (the
//  safe default) and IsCypherActive()==the-pointer, which is TRUE once a
//  cypher is installed. The KeyXDerive gate has nothing to catch it with, and
//  correctly does not try: it reads declarations, and this class made none.
//
//  What catches it is P2Peerio::Send, which requires a sealing decision to
//  have been made about the bytes it is being asked to write. The base class's
//  SendP2PeerMsg records one whether it seals the frame or exempts it by type;
//  this override never runs that code, so the first frame it writes AFTER the
//  cypher is installed is refused. Nothing here had to be declared, and that
//  is the point.
//
//  The body is the base class's send path with exactly one thing missing - the
//  call to EncryptP2PiomageSwap - which is the shape of the P2PeerioBSTR
//  defect written as briefly as it can be written.
class RawIo : public P2Peerio
{
public:
    virtual P2Peerio* Clone ( ) { return new RawIo; }

    virtual DWORD SendP2PeerMsg ( HANDLE hFile, P2PeerMsg *pMsg,
                                  OVERLAPPEDcon *pOVERLAPPEDsend )
    {
        pMsg -> PrepareP2Piomage ( GetIFmask ( ) );
        const P2Piomage *pImage = pMsg -> P2Piomage ( );
        return Send ( hFile, pImage, P2Piomage_Sizeof ( pImage ),
                      pOVERLAPPEDsend );
    }
};

// =========================================================================
class ConfHub : public P2PeerHub
{
public:
    ConfHub ( P2PaddrSTR strAddr, bool bServer, const wchar_t *pszPayload )
        : P2PeerHub ( strAddr ), m_bServer ( bServer )
        , m_bSent ( false ), m_pszPayload ( pszPayload )
    { m_strSelf = strAddr; }
    virtual ~ConfHub ( ) {}

    void SetTarget ( P2PaddrSTR strTarget ) { m_strTarget = strTarget; }

protected:
    virtual msgRESULT On_P2PeerBCast ( P2PeerMsg *pMsg ) override
    {
        if ( m_bServer && pMsg )
        {
            const std::wstring wBody = BodyW ( pMsg );   // copied out, aligned
            std::string sBody = pMsg->Data ( ) ? N ( wBody.c_str ( ) )
                                               : std::string ( "<null>" );
            std::printf ( "[confchannel] SERVER received '%s'\n", sBody.c_str ( ) );
            std::fflush ( stdout );

            if      ( sBody == N ( kPay1 ) ) { if ( g_hPay1 ) SetEvent ( g_hPay1 ); }
            else if ( sBody == N ( kPay2 ) ) { if ( g_hPay2 ) SetEvent ( g_hPay2 ); }
            else if ( sBody == N ( kPay3 ) ) { if ( g_hPay3 ) SetEvent ( g_hPay3 ); }
            else if ( sBody == N ( kPay4 ) ) { if ( g_hPay4 ) SetEvent ( g_hPay4 ); }
            else if ( sBody == N ( kPay5 ) ) { if ( g_hPay5 ) SetEvent ( g_hPay5 ); }
            else if ( sBody == N ( kPay6 ) ) { if ( g_hPay6 ) SetEvent ( g_hPay6 ); }
        }
        return msgHANDLED;
    }

    virtual conRESULT On_ConLogin ( P2PeerCon *pCon, P2PaddrSTR strThatP2Paddr,
                                    const void *pvLoginMsg, P2Psize_t iSize ) override
    {
        if ( m_bServer )
        {
            std::printf ( "[confchannel] SERVER ACCEPTED a login claiming '%s' "
                          "(phase %d)\n",
                          N ( strThatP2Paddr ).c_str ( ), g_nPhase );
            std::fflush ( stdout );

            if      ( g_nPhase == 1 ) { if ( g_hLogin1 ) SetEvent ( g_hLogin1 ); }
            else if ( g_nPhase == 3 ) { if ( g_hLogin3 ) SetEvent ( g_hLogin3 ); }
            else if ( g_nPhase == 5 ) { if ( g_hLogin5 ) SetEvent ( g_hLogin5 ); }
            else if ( g_nPhase == 6 ) { if ( g_hLogin6 ) SetEvent ( g_hLogin6 ); }
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
                                              m_strTarget.GetString ( ),
                                              P2Pmsg_BCast, m_pszPayload, nBytes ) );
            std::printf ( "[confchannel] client logged in and posted '%s'\n",
                          N ( m_pszPayload ).c_str ( ) );
            std::fflush ( stdout );
        }
        return result;
    }

private:
    bool           m_bServer;
    bool           m_bSent;
    const wchar_t *m_pszPayload;
    CString        m_strSelf;
    CString        m_strTarget;
};

// -------------------------------------------------------------------------
//  One client phase. eIo chooses the io class and bRequireAuth the hub
//  policy; between phase 2 and phase 3, and again between 4 and 5, exactly one
//  of the two changes.
// -------------------------------------------------------------------------
typedef enum { IoStock, IoMute, IoRaw } IoKind_e;

static bool RunPhase ( int nPhase, P2PaddrSTR strSelf, P2PaddrSTR strTarget,
                       const char *pszKeyFile, const char *pszAclFile,
                       bool bRequireAuth, IoKind_e eIo,
                       const wchar_t *pszPayload,
                       HANDLE hEvent, HANDLE hLoginEvent,
                       short nPort, DWORD dwWaitMs,
                       bool *pbSetupFailed, bool *pbLoginAccepted )
{
    *pbSetupFailed   = false;
    *pbLoginAccepted = false;
    g_nPhase         = nPhase;

    ConfHub oClient ( strSelf, false, pszPayload );
    oClient.SetTarget ( strTarget );
    if ( pszKeyFile && oClient.SetIdentity  ( pszKeyFile ) != p2pcng::IdOk )
    { *pbSetupFailed = true; return false; }
    if ( pszAclFile && oClient.SetAllowList ( pszAclFile ) != p2pcng::IdOk )
    { *pbSetupFailed = true; return false; }
    oClient.RequireAuth ( bRequireAuth );
    //  RequireRevocation(false) since 2026-08-21 (Stage 3 step 19). This hub
    //  takes RequireAuth as a PARAMETER, which is the point of the phase - so
    //  it needs a revocation position whichever way that parameter goes, and
    //  this test is not about revocation.
    oClient.RequireRevocation ( false );

    HANDLE hThread = oClient.SpawnHub ( );
    P2PeerConWsa *pCon =
        P2PeerConWsa::ClientFactory ( strTarget, L"127.0.0.1", nPort );
    if ( !hThread || !pCon ) { *pbSetupFailed = true; return false; }

    // The one line this test exists for. ClientFactory installs a base
    // P2Peerio; this replaces it before the connection is posted, which is
    // the same extension point a new transport's factory would use.
    if ( eIo == IoMute )
    {
        pCon -> SetP2Peerio ( new MuteIo );
        Log ( "client io object replaced with MuteIo "
              "(declares LeavesProcess=1, IsCypherActive=0)" );
    }
    else if ( eIo == IoRaw )
    {
        pCon -> SetP2Peerio ( new RawIo );
        Log ( "client io object replaced with RawIo "
              "(declares nothing; writes straight to Send)" );
    }

    oClient.PostP2PeerCon ( pCon );

    bool bArrived = ( WaitForSingleObject ( hEvent, dwWaitMs ) == WAIT_OBJECT_0 );

    // Acceptance read AFTER the payload wait, not before: where the payload is
    // meant to arrive the login necessarily precedes it, and where it is not,
    // the full wait has to elapse before a login that never came can be called
    // absent.
    if ( hLoginEvent )
      *pbLoginAccepted =
          ( WaitForSingleObject ( hLoginEvent, 0 ) == WAIT_OBJECT_0 );

    oClient.CloseHub ( );
    WaitForSingleObject ( hThread, 3000 );
    CloseHandle ( hThread );
    Sleep ( 300 );                       // let the server drop its side
    return bArrived;
}

// =========================================================================
//  Phase 0 - the declarations the rule reads.
//
//  No socket, no hub, no thread. Each io class is constructed, handed a
//  cypher through PostP2Pcrypto() exactly as P2PeerCon::KeyXDerive hands it
//  one, and asked the two questions. If these answers are wrong, every
//  network phase below is measuring something else.
static bool Declares ( const char *szWho, P2Peerio *pIO,
                       bool bLeavesWant, bool bCypherWant )
{
    const bool bLeaves = pIO -> LeavesProcess  ( );
    const bool bCypher = pIO -> IsCypherActive ( );
    const bool bOk     = ( bLeaves == bLeavesWant && bCypher == bCypherWant );
    std::printf ( "[confchannel] %-16s LeavesProcess=%d IsCypherActive=%d   "
                  "expected %d/%d   %s\n",
                  szWho, bLeaves ? 1 : 0, bCypher ? 1 : 0,
                  bLeavesWant ? 1 : 0, bCypherWant ? 1 : 0,
                  bOk ? "ok" : "WRONG" );
    std::fflush ( stdout );
    return bOk;
}

static bool PhaseZero ( )
{
    bool bOk = true;

    // The base class BEFORE a cypher. Cypher must read 0, or the field is a
    // constant and phase 1 proves nothing.
    {
        P2Peerio oBase;
        bOk = Declares ( "P2Peerio(bare)", &oBase, true, false ) && bOk;
    }

    // The base class WITH a cypher: the wire, doing what a wire must.
    {
        P2Peerio oBase;
        oBase.PostP2Pcrypto ( new P2PeerioGcm );
        bOk = Declares ( "P2Peerio+cypher", &oBase, true, true ) && bOk;
    }

    // DMX: the tree's one legitimate exemption, and it now says so itself.
    // Given a cypher on purpose - the point is that the answer does not move,
    // because the class would not consult one.
    {
        P2PeerioDmx oDmx;
        oDmx.PostP2Pcrypto ( new P2PeerioGcm );
        bOk = Declares ( "P2PeerioDmx", &oDmx, false, false ) && bOk;
    }

    // BSTR: the trap. Reached through Clone() because the class derives
    // PROTECTED from P2Peerio, so a P2PeerioBSTR* will not convert - which is
    // also part of why no factory in this tree could install one by accident.
    //
    // The mask is widened FIRST. Constructing this class announces what it
    // takes out of the path, and the announcement is a WARNING; the default
    // notification mask is P2Pevotn_ERROR alone, so without this line the
    // warning is raised into nothing. That is not incidental - it is how
    // this test found that every EVWRN->Display() in the tree is invisible
    // by default. Widened here rather than the default changed, because
    // what an unconfigured deployment reports is not this finding's to
    // move.
    {
        P2Pevent::Configure ( P2Pevent::ADDMASK, P2Pevotn_WARNING );
        InterlockedExchange ( &g_lBstrWarning, 0 );

        P2PeerioBSTR oBstr;
        P2Peerio    *pIO = oBstr.Clone ( );
        if ( !pIO ) { Log ( "phase 0: P2PeerioBSTR::Clone returned null" ); return false; }
        pIO -> PostP2Pcrypto ( new P2PeerioGcm );
        bOk = Declares ( "P2PeerioBSTR", pIO, true, false ) && bOk;
        delete pIO;

        const bool bWarned =
            ( g_lBstrWarning != 0 );
        std::printf ( "[confchannel] %-16s announced itself on "
                      "construction: %s   expected yes   %s\n",
                      "P2PeerioBSTR", bWarned ? "yes" : "no",
                      bWarned ? "ok" : "WRONG" );
        std::fflush ( stdout );
        bOk = bWarned && bOk;
    }

    return bOk;
}

// =========================================================================
int main ( int argc, char *argv[] )
{
    short nPort     = ( argc >= 2 ) ? (short)atoi ( argv[1] ) : 7840;
    short nPortOpen = (short)( nPort + 1 );

    std::printf ( "=== p2p_confchannel - is the cypher CONSULTED, not just installed? ===\n" );
    std::printf ( "Ports: %d (authenticating), %d (open)\n",
                  (int)nPort, (int)nPortOpen );
    std::printf ( "Asserting: a hub that requires authentication refuses to key a\n"
                  "           transport that leaves this process and will not use\n"
                  "           the cypher it is given.\n\n" );
    std::fflush ( stdout );

    P2Pevent::SetTextSink ( &DiagSink );
    std::set_terminate ( &ConfTerminate );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }
    WSADATA oWsaData;
    WSAStartup ( MAKEWORD(2,2), &oWsaData );

    // ---- Phase 0 ----------------------------------------------------------
    Log ( "--- phase 0: what each io class declares about itself ---" );
    if ( !PhaseZero ( ) )
    {
        std::printf (
          "\nRESULT: FAIL - an io class declares the wrong thing about itself.\n"
          "  The rule in P2PeerCon::KeyXDerive reads exactly these two answers,\n"
          "  so a wrong one here is the defect and not a detail: DMX answering\n"
          "  true to LeavesProcess would refuse the in-process transport, and\n"
          "  BSTR answering false would re-open F-S6-3 with the gate in place.\n" );
        WSACleanup ( );
        CleanupP2Pmsg ( );
        return 1;
    }
    Log ( "phase 0 OK - the rule's inputs are what they claim to be" );

    g_hPay1   = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hPay2   = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hPay3   = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hPay4   = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hPay5   = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hPay6   = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hLogin1 = CreateEvent ( NULL, TRUE,  FALSE, NULL );
    g_hLogin3 = CreateEvent ( NULL, TRUE,  FALSE, NULL );
    g_hLogin5 = CreateEvent ( NULL, TRUE,  FALSE, NULL );
    g_hLogin6 = CreateEvent ( NULL, TRUE,  FALSE, NULL );

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

    if ( p2pcng::AppendAllowList ( sSrvAcl.c_str ( ), "ConfChan.Client", pubCli ) != p2pcng::IdOk ||
         p2pcng::AppendAllowList ( sCliAcl.c_str ( ), "ConfChan.Server", pubSrv ) != p2pcng::IdOk )
    { Log ( "SETUP: allow-list provisioning failed" ); ScrubTempFiles ( ); return 2; }

    int nExit = 2;
    {
        // The authenticating server: RequireAuth(true), the client's key on
        // its allow-list.
        ConfHub oAuthSrv ( kAuthSrvAddr, true, 0 );
        if ( oAuthSrv.SetIdentity  ( sSrvKey.c_str ( ) ) != p2pcng::IdOk ||
             oAuthSrv.SetAllowList ( sSrvAcl.c_str ( ) ) != p2pcng::IdOk )
        { Log ( "SETUP: server auth configuration failed" ); ScrubTempFiles ( ); return 2; }
        oAuthSrv.RequireAuth ( true );
        //  RequireRevocation(false) since 2026-08-21 (Stage 3 step 19): a hub
        //  that requires auth must now hold a POSITION on revocation, and this
        //  test is not about revocation. Saying so is the documented migration
        //  and it is one line. It does NOT turn revocation off - a list named
        //  anyway is still loaded, still enforced and still fails closed.
        oAuthSrv.RequireRevocation ( false );

        // The open server: RequireAuth(false) and no identity anywhere. It
        // exists so MuteIo can be shown to work where no cypher is in play.
        ConfHub oOpenSrv ( kOpenSrvAddr, true, 0 );
        oOpenSrv.RequireAuth ( false );

        HANDLE hAuthThread = oAuthSrv.SpawnHub ( );
        HANDLE hOpenThread = oOpenSrv.SpawnHub ( );
        if ( !hAuthThread || !hOpenThread )
        { Log ( "SETUP: SpawnHub() failed" ); ScrubTempFiles ( ); return 2; }

        P2PeerConWsa *pAuthSvc = P2PeerConWsa::ServiceFactory ( kAuthDomain, nPort );
        P2PeerConWsa *pOpenSvc = P2PeerConWsa::ServiceFactory ( kOpenDomain, nPortOpen );
        if ( !pAuthSvc || !pOpenSvc )
        { Log ( "SETUP: ServiceFactory failed" ); ScrubTempFiles ( ); return 2; }
        oAuthSrv.PostP2PeerCon ( pAuthSvc );
        oOpenSrv.PostP2PeerCon ( pOpenSvc );
        Log ( "both servers listening" );
        Sleep ( 500 );

        bool bSetup  = false;
        bool bLogin1 = false, bLogin3 = false, bLogin5 = false, bLogin6 = false;

        // ---- Phase 1: positive control ----------------------------------
        Log ( "--- phase 1: stock io, RequireAuth(true) both ends (must arrive) ---" );
        bool b1 = RunPhase ( 1, kClientAddr, kAuthSrvAddr,
                             sCliKey.c_str ( ), sCliAcl.c_str ( ),
                             true, IoStock, kPay1, g_hPay1, g_hLogin1,
                             nPort, 15000, &bSetup, &bLogin1 );
        if ( bSetup ) { Log ( "SETUP: phase 1 client failed" ); ScrubTempFiles ( ); return 2; }

        if ( !b1 || !bLogin1 )
        {
            std::printf (
              "\nRESULT: INCONCLUSIVE - the legitimate peer never got through, so\n"
              "  nothing below proves anything. Check wsa_mesh and p2p_authchannel.\n" );
            nExit = 3;
        }
        else
        {
            Log ( "positive control OK" );
            bool bIgnored = false;

            // ---- Phase 2: MuteIo on an open hub -------------------------
            Log ( "--- phase 2: MuteIo, RequireAuth(false) both ends, OPEN server "
                  "(must arrive - proves the io class transports) ---" );
            bool b2 = RunPhase ( 2, kOpenCliAddr, kOpenSrvAddr, 0, 0,
                                 false, IoMute, kPay2, g_hPay2, 0,
                                 nPortOpen, 15000, &bSetup, &bIgnored );
            if ( bSetup ) { Log ( "SETUP: phase 2 client failed" ); ScrubTempFiles ( ); return 2; }

            // ---- Phase 3: the declaration gate --------------------------
            Log ( "--- phase 3: THE SAME MuteIo, RequireAuth(true), authenticating "
                  "server (must NOT get through) ---" );
            InterlockedExchange ( &g_lGateRefusal, 0 );
            bool b3 = RunPhase ( 3, kClientAddr, kAuthSrvAddr,
                                 sCliKey.c_str ( ), sCliAcl.c_str ( ),
                                 true, IoMute, kPay3, g_hPay3, g_hLogin3,
                                 nPort, 10000, &bSetup, &bLogin3 );
            if ( bSetup ) { Log ( "SETUP: phase 3 client failed" ); ScrubTempFiles ( ); return 2; }
            const bool bKeyXRefused =
                ( g_lGateRefusal != 0 );
            std::printf ( "[confchannel] phase 3: login accepted = %s, "
                          "payload delivered = %s, KeyXDerive refusal raised = %s\n",
                          bLogin3 ? "YES" : "no", b3 ? "YES" : "no",
                          bKeyXRefused ? "YES" : "no" );
            std::fflush ( stdout );

            // ---- Phase 4: control for phase 5 ---------------------------
            Log ( "--- phase 4: RawIo, RequireAuth(false) both ends, OPEN server "
                  "(must arrive - proves RawIo transports too) ---" );
            bool b4 = RunPhase ( 4, kOpenCliAddr, kOpenSrvAddr, 0, 0,
                                 false, IoRaw, kPay4, g_hPay4, 0,
                                 nPortOpen, 15000, &bSetup, &bIgnored );
            if ( bSetup ) { Log ( "SETUP: phase 4 client failed" ); ScrubTempFiles ( ); return 2; }

            // ---- Phase 5: the backstop ----------------------------------
            Log ( "--- phase 5: THE SAME RawIo, RequireAuth(true), authenticating "
                  "server - declares nothing, so only Send() can catch it ---" );
            InterlockedExchange ( &g_lSendRefusal, 0 );
            bool b5 = RunPhase ( 5, kClientAddr, kAuthSrvAddr,
                                 sCliKey.c_str ( ), sCliAcl.c_str ( ),
                                 true, IoRaw, kPay5, g_hPay5, g_hLogin5,
                                 nPort, 10000, &bSetup, &bLogin5 );
            if ( bSetup ) { Log ( "SETUP: phase 5 client failed" ); ScrubTempFiles ( ); return 2; }
            const bool bSendRefused =
                ( g_lSendRefusal != 0 );
            std::printf ( "[confchannel] phase 5: login accepted = %s, "
                          "payload delivered = %s, Send() refusal raised = %s\n",
                          bLogin5 ? "YES" : "no", b5 ? "YES" : "no",
                          bSendRefused ? "YES" : "no" );
            std::fflush ( stdout );

            // ---- Phase 6: liveness --------------------------------------
            Log ( "--- phase 6: stock io again (liveness) ---" );
            bool b6 = RunPhase ( 6, kClientAddr, kAuthSrvAddr,
                                 sCliKey.c_str ( ), sCliAcl.c_str ( ),
                                 true, IoStock, kPay6, g_hPay6, g_hLogin6,
                                 nPort, 15000, &bSetup, &bLogin6 );
            if ( bSetup ) { Log ( "SETUP: phase 6 client failed" ); ScrubTempFiles ( ); return 2; }

            if ( bLogin3 || b3 )
            {
                std::printf (
                  "\nRESULT: FAIL - A TRANSPORT THAT SAYS IT WILL NOT USE A CYPHER\n"
                  "  WAS KEYED AND ACCEPTED.\n"
                  "  The phase 3 io object declares LeavesProcess()=1 and\n"
                  "  IsCypherActive()=0 - P2PeerioBSTR word for word - and the\n"
                  "  connection ran the ECDH agreement anyway, installed the\n"
                  "  session cypher on it, and logged in. Nothing read the\n"
                  "  declaration.\n"
                  "  This phase does not itself disclose anything: MuteIo\n"
                  "  delegates to the base class, so its frames are sealed and it\n"
                  "  is only LYING about the hooks. The class whose identical\n"
                  "  declaration is TRUE is P2PeerioBSTR, and a transport wired to\n"
                  "  it would be in clear here. Phase 5 is the disclosure test.\n"
                  "  The F-S6-1 condition cannot see either of them: the agreement\n"
                  "  DID complete and m_bKeyXDone IS true.\n"
                  "  Fix: P2PeerCon::KeyXDerive must refuse when the io object\n"
                  "  answers LeavesProcess() && !IsCypherActive(), before it sets\n"
                  "  m_bKeyXDone.\n" );
                nExit = 1;
            }
            else if ( bLogin5 || b5 )
            {
                std::printf (
                  "\nRESULT: FAIL - A PLAINTEXT TRANSPORT THAT DECLARED NOTHING WAS\n"
                  "  KEYED AND ACCEPTED.\n"
                  "  The phase 5 io object overrides SendP2PeerMsg and answers\n"
                  "  neither question, so the declaration gate has nothing to read\n"
                  "  and correctly lets it past - and then it wrote a frame with a\n"
                  "  session cypher installed that nothing consulted. A rule that\n"
                  "  only catches the author who fills the form in is a\n"
                  "  convention.\n"
                  "  Fix: P2Peerio::Send must refuse bytes that its own\n"
                  "  SendP2PeerMsg recorded no sealing decision about.\n" );
                nExit = 1;
            }
            else if ( !b2 || !b4 )
            {
                std::printf (
                  "\nRESULT: INCONCLUSIVE - a gate phase did not get through, but\n"
                  "  neither did its control, which uses the SAME io class with no\n"
                  "  cypher in play and nothing to refuse it. So that io class\n"
                  "  cannot transport at all, and the silence is not the doing of\n"
                  "  any gate. This is NOT a pass - fix the harness first.\n" );
                nExit = 3;
            }
            else if ( !bSendRefused )
            {
                // Measured, not assumed: with this refusal removed the frame
                // is written, reaches the peer IN CLEAR, and the peer refuses
                // it with a Cypher exception because inbound decryption has no
                // exemption by type. So the payload does not arrive either way
                // - and confidentiality has already been lost by the time it
                // does not. Delivery is the wrong thing to read here, which is
                // step 17's lesson arriving a second time.
                std::printf (
                  "\nRESULT: FAIL - CLEARTEXT REACHED THE WIRE.\n"
                  "  Phase 5 did not get through, but Send() never refused it,\n"
                  "  and phase 4 proves the io class transports. What stopped it\n"
                  "  was the FAR END: an unsealed frame arrived on a keyed\n"
                  "  connection and the peer's decrypt refused it (look for\n"
                  "  On_ConCypherEx above). That is a delivery failure AFTER the\n"
                  "  disclosure, not instead of it - the bytes were on the\n"
                  "  network in clear.\n"
                  "  Fix: P2Peerio::Send must refuse bytes that its own\n"
                  "  SendP2PeerMsg recorded no sealing decision about, so nothing\n"
                  "  is written in the first place.\n" );
                nExit = 1;
            }
            else if ( !bKeyXRefused )
            {
                // Inconclusive rather than failed, and the asymmetry with the
                // branch above is deliberate: MuteIo delegates, so nothing was
                // disclosed. Phase 3 was stopped by something this test cannot
                // name, and a gate credited with a refusal it did not make is
                // exactly the failure step 17 recorded.
                std::printf (
                  "\nRESULT: INCONCLUSIVE - phase 3 was stopped, phase 2 proves the\n"
                  "  transport works, and yet KeyXDerive never refused it.\n"
                  "  Something OTHER than the declaration gate ended that\n"
                  "  connection, so the gate has not been measured.\n" );
                nExit = 3;
            }
            else if ( !b6 || !bLogin6 )
            {
                std::printf (
                  "\nRESULT: FAIL - the liveness control never arrived. Phases 3\n"
                  "  and 5 were refused, but so was a connection that must be\n"
                  "  accepted, so the server may simply have stopped.\n" );
                nExit = 1;
            }
            else
            {
                std::printf (
                  "\nRESULT: PASS - both halves of the rule hold. The io class that\n"
                  "  DECLARES it will not use a cypher delivered on a hub that\n"
                  "  keys nothing (phase 2) and was refused by KeyXDerive on one\n"
                  "  that requires authentication (phase 3). The io class that\n"
                  "  declares NOTHING did the same (phases 4 and 5) and was\n"
                  "  refused by Send() on the first frame after the cypher went\n"
                  "  in. Both refusals are named in the diagnostics, and stock\n"
                  "  connections before and after them were accepted. A cypher\n"
                  "  that is installed is now a cypher that is used, by rule and\n"
                  "  not by inheritance.\n" );
                nExit = 0;
            }
        }

        oAuthSrv.CloseHub ( );
        oOpenSrv.CloseHub ( );
        WaitForSingleObject ( hAuthThread, 5000 );
        WaitForSingleObject ( hOpenThread, 5000 );
        CloseHandle ( hAuthThread );
        CloseHandle ( hOpenThread );
    }

    ScrubTempFiles ( );
    WSACleanup ( );
    CleanupP2Pmsg ( );
    P2Pevent::SetTextSink ( nullptr );
    if ( g_hPay1   ) CloseHandle ( g_hPay1   );
    if ( g_hPay2   ) CloseHandle ( g_hPay2   );
    if ( g_hPay3   ) CloseHandle ( g_hPay3   );
    if ( g_hPay4   ) CloseHandle ( g_hPay4   );
    if ( g_hPay5   ) CloseHandle ( g_hPay5   );
    if ( g_hPay6   ) CloseHandle ( g_hPay6   );
    if ( g_hLogin1 ) CloseHandle ( g_hLogin1 );
    if ( g_hLogin3 ) CloseHandle ( g_hLogin3 );
    if ( g_hLogin5 ) CloseHandle ( g_hLogin5 );
    if ( g_hLogin6 ) CloseHandle ( g_hLogin6 );
    return nExit;
}
