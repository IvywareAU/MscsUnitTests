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
// p2p_sealbcast.cpp — the AUTOMATIC seal, over a real link, on the default.
//
// BACKGROUND — the question the other two seal tests do not ask.
//
//   p2p_sealhop    : a hub that ROUTES a body sealed BY HAND cannot read it.
//                    Three hubs, real sockets - and RequireSeal(false).
//   p2p_sealdefault: the v2 envelope, its reader set, its refusal, and that
//                    RequireSeal defaults to true. NO SOCKETS.
//   p2p_sealbcast  : the two halves joined - the LIBRARY seals, on its own
//                    default, and the body crosses a real link.   <-- this
//
//   EVERY socket test in this suite turns sealing off (p2p_authancestor:422,
//   p2p_bigreport:329, p2p_reportsign:502, p2p_sealhop:394 and their peers),
//   each for its own good local reason. The consequence was collective and
//   nobody chose it: P2PeerCon::SealAppMsgOutbound -> wire ->
//   P2PeerCon::OpenAppMsgInbound has never been exercised end to end by
//   anything, on the configuration every deployment gets by default.
//
// WHAT IT ASKS — three questions, in the order their answers depend on.
//
//       Bc  ---->  Bc.Mid  ---->  Bc.Mid.Leaf
//      (top)      (carrier)        (recipient)
//               holds NO keys
//
//   The carrier holds no identity, no agreement key and no allow-list, and
//   watches every body that passes through it with PeekP2PeerMsg - which the
//   pump calls BOTH on the routing path (P2PeerHub.cpp:892) and on local
//   dispatch (P2Pwin32.cpp:3550), so it sees a relayed unicast and a fanned-out
//   broadcast copy alike.
//
//   Phase 1 (RELAYED UNICAST, LONG BODY) — the top posts a body to the leaf, two
//     hops down, in clear. The library must seal it: the carrier must not be
//     able to read it, and the leaf must recover it exactly. This is
//     p2p_sealhop's property asked of the automatic path rather than a hand-made
//     seal, and it is also the control - if it fails, nothing after it means
//     anything.
//
//   Phase 2 (RELAYED UNICAST, SHORT BODY) — the same thing with a body of
//     kShortBody bytes, which is the regression guard for the growth defect
//     below.
//
//     A seal is 234 bytes of fixed overhead on top of the plaintext
//     (P2PeerSeal.h:191, one reader), and SealAppMsgOutbound writes the result
//     back over the message's own payload with SetData - so the payload has to
//     GROW by 234 bytes in place, and P3PmsgData::c_vBlob
//     (Msgcore/P2Pmsg.cpp:983) is what has to do the growing. Until 2026-08-24
//     it could not, in either of two ways, and the plaintext size chose between
//     them:
//
//       * up to 255 bytes the payload sits in a BLOB08 descriptor, whose length
//         field is a UINT08. c_vBlob REFUSED to widen it -
//               Buffer overrun (262 vs 255) blocked
//         - then threw, out of the connection's send loop, and the LINK was
//         dropped. So a relayed body of roughly 22..255 bytes could not be
//         sealed at all, and the failure was a dead link rather than the refusal
//         SealAppMsgOutbound was written to give.
//
//       * over 255 bytes it is a BLOB16, c_vBlob took its resize branch, and
//         that branch handed P2PmsgObject_NewVBLockData the BLOB SIZE where
//         c_memcpy - ten lines below it, the same shape of code - correctly
//         hands it VBLockData_Sizeof(...). The descriptor was under-allocated by
//         its own header and the copy ran off the end of the heap entry:
//               P3PmsgField::AssertValid ... Failed Containment
//               P2PmsgHeap_CollateIOMAGE ... Attempt to collate non-free entry
//
//     Both are fixed; c_vBlob now widens the type tag and sizes the allocation
//     the way c_memcpy always did. Phases 1 and 2 are the two sizes, and they
//     stay because a single-size test would guard only one of them.
//
//   Phase 3 (TREE BROADCAST) — the same tree, the same keys, the same policy,
//     routed the other way the library offers: a message named P2Pmsg_BCast
//     addressed at the top ITSELF, which is what drives
//     P2PeerHub::On_P2PeerBCast's fan-out. LAST, because today it takes the
//     carrier-to-leaf link down and anything after it would measure the wreckage.
//
//     The fan-out does not send the message that was posted. It sends a COPY
//     PER LINK, re-addressed to that link's own peer:
//
//         pMsgBCast = pMsg -> RedirectFactory ( oP2PaddrCon );   // :1393
//
//     and oP2PaddrCon is pCon->GetP2Paddress(), which returns m_oThatP2Paddr
//     (P2PeerCon.cpp:4792). The one hook that seals exempts the last hop by
//     comparing exactly those two:
//
//         if ( m_oThatP2Paddr == strDst )    // P2PeerCon.cpp:2818
//           return true;
//
//     MEASURED 2026-08-24: the exemption is true at every hop, so a broadcast is
//     never sealed, never refused, and says nothing either way. The carrier reads
//     the body in clear on the same tree, with the same keys and the same policy
//     that sealed phases 1 and 2 over the same hop. It is not blocked by the
//     confidentiality default; it is silently outside it.
//
//     THE OPPOSITE WAS ON RECORD. ProductionPlanLatest2.md item 6 and Sealing.md
//     said the two do not compose because a broadcast is REFUSED - "no agreement
//     key" - citing p2p_authancestor.cpp:417-421. That message
//     (p2p_authancestor.cpp:274) is a unicast to Anc.Mid.Leaf which happens to be
//     NAMED P2Pmsg_BCast, in a test that provisions no agreement keys anywhere on
//     purpose. It never reaches the fan-out at all.
//
//     The same re-addressing breaks the ORIGIN ATTESTATION too, and for the same
//     reason: AttestRelay digests the destination, so a copy re-addressed after
//     signing no longer verifies. The leaf refuses it with "signature does not
//     verify" and drops the link. One mechanism, two protections, both lost.
//
//   Phase 6 (THE OTHER FAN-OUT) — added 2026-09-22, when On_P2PeerUCast stopped
//     being dead code. It is the mirror of the broadcast relay: a copy per
//     PARENT link, each parent delivering it locally before relaying it on, so
//     an upcast climbs to the root and every ancestor receives it. What the
//     origin addressed is a CHAIN — no more sealable than a subtree, and
//     refused on the default for the same reason phase 3's broadcast is.
//
//     WHY IT IS A PHASE HERE RATHER THAN A NOTE SOMEWHERE. Until the relay was
//     wired up there was no P2Pmsg_UCast ID and no map entry, which is why
//     SealAppMsgOutbound's header could say TMsg_Scp was stamped by both
//     relays and be vacuously right. The obvious symmetry — stamp the same
//     scope — would have made that sentence true and the TEST beneath it
//     wrong in one commit: RequireSealBroadcast(false), a setting deployments
//     have already recorded, would have begun exempting traffic on a relay
//     that did not exist when they recorded it. So the upcast stamps TMsg_Ups
//     and RequireSealUpcast is its own switch, and this phase is what holds
//     the two apart:
//
//       6a  phase 5's policy unchanged — sealing ON, broadcasts exempt. The
//           upcast must be REFUSED at the sender; the keyless carrier never
//           holds it.
//       6b  RequireSealUpcast(false) as well. Now it is exempt and the carrier
//           reads it in clear.
//
//     6a is the guard and 6b is its control — without 6b, 6a is satisfied by
//     an upcast that could not be sent for any reason at all.
//
//     The negative check was RUN rather than assumed, 2026-09-22 before this
//     was committed: widen the exemption at P2PeerCon.cpp to IsFannedOut() —
//     which is exactly the tidier-looking mistake — and 6a turns red,
//     "CARRIED - THE EXEMPTION LEAKED".
//
//   SEALING IS NOT CONFIGURED HERE, IT IS ASSERTED. RequireSeal has been on by
//   default since 2026-08-21 (ProductionPlan.md Stage 3 step 20); this test
//   reads IsSealRequired() back on all three hubs and refuses to run if it is
//   false, so a result can never be an artefact of its own setup. It also probes
//   SealFor() by hand during setup: a sender that CANNOT seal and a library that
//   loses the message look identical from the outside, and this tells them apart
//   before a single phase runs.
//
//   AUTH IS OFF, DELIBERATELY, exactly as in p2p_sealhop: no login is proven, so
//   there is no session key and the link encrypts nothing. Anything the carrier
//   cannot read was hidden by the seal and by nothing else.
//
//   BROADCASTS ARE ENABLED BY HAND, and that is itself worth writing down:
//   ConState_BCasts is set nowhere in the library outside the P2Pexpump paths
//   (P2PeerExplorer.cpp:1382, the login grant in On_XCidConLogin, and
//   P2PeerHub.cpp:1436, the "AcceptWSA" command handler), so the fan-out
//   reaches nothing at all on a stock tree until the application sets it. This
//   test sets it on each connection as it logs in.
//
// VERDICT = process EXIT CODE:
//   0  PASS   all three phases held: the carrier could read neither the relayed
//             unicast nor the broadcast copy, both reached the leaf, and a short
//             body was relayed without killing the link
//   1  FAIL   at least one was readable at the carrier, was lost, or took the
//             connection down. The RESULT block names which.
//   2  SETUP  startup / socket / provisioning failure, or RequireSeal is not the
//             default any more, or the top cannot seal to the leaf at all
//   3  INCONCLUSIVE phase 1 never landed, so the tree is not carrying anything
//             and phases 2 and 3 would prove nothing. NOT a pass.

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConWsa.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"
#include "P2PIdentityStore.h"
#include "P2PAuthLogin.h"
#include "P2PeerSeal.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
static const P2PaddrSTR kTopAddr  = L"Bc";
static const P2PaddrSTR kMidAddr  = L"Bc.Mid";
static const P2PaddrSTR kLeafAddr = L"Bc.Mid.Leaf";
static const P2PaddrSTR kDomain   = L"Bc.*";

//  Distinct needles, so "the carrier saw it" can never be credited to the wrong
//  phase. Sent as raw bytes rather than wide text: the test is a byte search and
//  a payload should not need decoding to be recognised.
static const char kUniTag[]   = "UNICAST-secret-tarragon-5150";
static const char kBcastTag[] = "BROADCAST-secret-juniper-8802";
static const char kShortTag[] = "SHORT-secret-marjoram-3310";
static const char kUcastTag[] = "UPCAST-secret-fenugreek-6041";

//  PHASES 1 AND 2 USE A LONG BODY ON PURPOSE. Anything at or under 255 bytes is
//  held in a BLOB08 descriptor that the seal cannot grow past - which is what
//  phase 3 is for. Padding clear of that ceiling is what lets phases 1 and 2
//  reach the question they are actually about.
static const size_t kLongBody  = 400;
static const size_t kShortBody = 28;

static std::string g_sUniBody;
static std::string g_sBcastBody;
static std::string g_sShortBody;
static std::string g_sUcastBody;

static HANDLE g_hLeafUni   = NULL;   // phase 1 reached the leaf
static HANDLE g_hLeafBcast = NULL;   // phase 2 reached the leaf
static HANDLE g_hLeafShort = NULL;   // phase 3 reached the leaf
static HANDLE g_hMidUp     = NULL;   // the carrier logged in to the top
static HANDLE g_hLeafUp    = NULL;   // the leaf logged in to the carrier

//  What the carrier saw. The "SawPlain" flags are the measurement; the "Carried"
//  flags say the carrier was looking at the right traffic at all, which is what
//  stops silence being read as a pass.
//
//  ATOMIC RATHER THAN VOLATILE, AND THAT IS NOT A STYLE CHOICE. Every flag here
//  is written by a HUB THREAD inside PeekP2PeerMsg and read by MAIN after a
//  Sleep. volatile stops the compiler caching the load and supplies no
//  happens-before edge whatsoever, so the pair is a data race by the memory
//  model however long the Sleep is -- and TSan said so: run 35734775287 on
//  Targetcore master reported g_bMidCarriedUcast and g_bMidSawUcastPlain at
//  lines 398/399 against main, with usleep as the only thing between them.
//  The Sleep still decides WHEN main looks; the atomic decides that what it
//  reads is defined. Do not put volatile back: it compiled, it passed, and it
//  was wrong for two days.
static std::atomic<bool> g_bMidCarriedUni  { false };
static std::atomic<bool> g_bMidSawUniPlain { false };
static std::atomic<bool> g_bMidUniMarked   { false };
static std::atomic<bool> g_bMidCarriedBcast{ false };
static std::atomic<bool> g_bMidSawBcastPlain{ false };
static std::atomic<bool> g_bMidBcastMarked { false };
static std::atomic<bool> g_bMidSawShortPlain{ false };
//  Phase 6, the OTHER fan-out. Kept apart from the broadcast pair above and
//  not folded into them, because the whole of phase 6 is that the two are not
//  the same traffic and are not governed by the same switch.
static std::atomic<bool> g_bMidCarriedUcast{ false };
static std::atomic<bool> g_bMidSawUcastPlain{ false };
static std::atomic<bool> g_bTopSawUcast    { false };
static std::atomic<int>  g_nMidBodies     { 0 };

static std::atomic<bool> g_bLeafUniOk      { false };
static std::atomic<bool> g_bLeafUniWrong   { false };
static std::atomic<bool> g_bLeafSawBcast   { false };
static std::atomic<bool> g_bLeafSawShort   { false };

//  A connection that DIES mid-test is the failure hardest to read from silence,
//  and phase 3 is expected to cause one. Counted rather than flagged, so a phase
//  can ask "did anything close while I was running".
static std::atomic<LONG> g_nCloses { 0 };

static void Log ( const char *msg )
{
    std::printf ( "[sealbcast] %s\n", msg );
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

// The only question worth asking of a body that is supposed to be opaque.
static bool Contains ( const void *pv, size_t cb, const std::string &sNeedle )
{
    if ( !pv || sNeedle.empty() || cb < sNeedle.size() ) return false;
    const char *p = (const char *)pv;
    for ( size_t i = 0; i + sNeedle.size() <= cb; ++i )
        if ( std::memcmp ( p + i, sNeedle.data(), sNeedle.size() ) == 0 ) return true;
    return false;
}

//  Tag first so a truncated body still identifies itself, then filler to clear
//  the BLOB08 ceiling.
static std::string MakeBody ( const char *pszTag, size_t cbTotal )
{
    std::string s ( pszTag );
    if ( s.size() < cbTotal ) s.append ( cbTotal - s.size(), '.' );
    return s;
}

// ---------------------------------------------------------------------------
// Provisioning. Private keys stay in their files; only public points are
// published into the other peer's allow-list.
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
                    (unsigned long)GetCurrentProcessId() );
    s += "p2p_sealbcast_"; s += pszLeaf; s += "_"; s += szPid; s += ".tmp";
    DeleteFileA ( s.c_str() );
    g_vTempFiles.push_back ( s );
    return s;
}

static void ScrubTempFiles ( )
{
    for ( size_t i = 0; i < g_vTempFiles.size(); ++i )
        DeleteFileA ( g_vTempFiles[i].c_str() );
    g_vTempFiles.clear();
}

static bool MakeIdentity ( const std::string &sPath, unsigned char *pPubOut )
{
    p2pcng::EcdsaP256 oKey;
    if ( !oKey.Generate() )                                            return false;
    if ( p2pcng::SaveIdentity ( sPath.c_str(), oKey ) != p2pcng::IdOk ) return false;
    return oKey.ExportPublic ( pPubOut );
}

static bool MakeAgreement ( const std::string &sPath, unsigned char *pPubOut )
{
    p2pcng::EcdhP256 oKey;
    if ( !oKey.Generate() )                                             return false;
    if ( p2pcng::SaveAgreement ( sPath.c_str(), oKey ) != p2pcng::IdOk ) return false;
    return oKey.ExportPublic ( pPubOut );
}

// =========================================================================
class BcastHub : public P2PeerHub
{
public:
    enum Role { RoleTop, RoleMid, RoleLeaf };

    BcastHub ( P2PaddrSTR strAddr, Role eRole )
        : P2PeerHub ( strAddr ), m_eRole ( eRole ) { }
    virtual ~BcastHub ( ) { }

protected:
    // The carrier's window onto what it carries.
    //
    // Called from P2PeerHub::RouteP2PeerMsg (P2PeerHub.cpp:892) for a body in
    // TRANSIT, and from the pump's local-dispatch branch (P2Pwin32.cpp:3550) for
    // a body addressed to this hub - which is what a fanned-out broadcast copy
    // is, because On_P2PeerBCast re-addresses each copy to its link peer. One
    // override therefore sees both routing modes, and the DESTINATION is what
    // tells them apart.
    virtual msgRESULT PeekP2PeerMsg ( P2PeerMsg *pMsg ) override
    {
        if ( pMsg && pMsg->DataSize() > 0 && pMsg->Data() )
        {
            const void  *pv     = pMsg->Data();
            const size_t cb     = (size_t)pMsg->DataSize();
            const bool   bMark  = pMsg->IsSealed();
            const bool   bUni   = Contains ( pv, cb, g_sUniBody   );
            const bool   bBcast = Contains ( pv, cb, g_sBcastBody );
            const bool   bShort = Contains ( pv, cb, g_sShortBody );
            const bool   bUcast = Contains ( pv, cb, g_sUcastBody  );
            CString      strDst = pMsg->GetDestin() ? pMsg->GetDestin() : L"";

            //  ONLY the carrier's sightings are the measurement. The top is the
            //  sender and the leaf is the recipient, and both are entitled to the
            //  plaintext; they are logged and not counted, because a body that
            //  stops moving is the failure this test is most likely to hit and
            //  "which hub last held it" is the only thing that says where.
            if ( m_eRole == RoleMid )
            {
                g_nMidBodies++;
                if ( bShort ) g_bMidSawShortPlain = true;

                //  Which routing mode is this? A relayed unicast is still
                //  addressed at the leaf; a broadcast copy was re-addressed to
                //  this hub by the fan-out.
                //
                //  AND SO IS AN UPCAST COPY, which is why the NAME is asked
                //  first. On_P2PeerUCast re-addresses exactly the way
                //  On_P2PeerBCast does, so a phase 6 copy arrives here with
                //  Dst == kMidAddr and would otherwise be counted as a
                //  broadcast - scoring phase 6 against phase 5's flags and
                //  making both meaningless. The name is the only thing that
                //  separates two fan-outs that look identical on the wire, and
                //  it is worth saying that this is a TEST reading it: the
                //  library never does, because a name is what F-S9-1 got
                //  wrong. Here there is nothing to protect, only two phases to
                //  tell apart.
                if ( pMsg->Map_MatchName ( P2Pmsg_UCast ) )
                {
                    g_bMidCarriedUcast = true;
                    if ( bUcast ) g_bMidSawUcastPlain = true;
                }
                else if ( strDst == kLeafAddr )
                {
                    g_bMidCarriedUni = true;
                    g_bMidUniMarked  = bMark;
                    if ( bUni ) g_bMidSawUniPlain = true;
                }
                else if ( strDst == kMidAddr )
                {
                    g_bMidCarriedBcast = true;
                    g_bMidBcastMarked  = bMark;
                    if ( bBcast ) g_bMidSawBcastPlain = true;
                }
            }

            std::printf ( "[sealbcast] %s holds %s -> %s [%s], %u bytes,"
                          " sealed-marker=%s; unicast=%s broadcast=%s short=%s"
                          " upcast=%s\n",
                          RoleName(),
                          N ( pMsg->GetSource() ).c_str(),
                          N ( pMsg->GetDestin() ).c_str(),
                          N ( pMsg->c_name() ).c_str(),
                          (unsigned)cb,
                          bMark  ? "set" : "CLEAR",
                          bUni   ? "VISIBLE" : "no",
                          bBcast ? "VISIBLE" : "no",
                          bShort ? "VISIBLE" : "no",
                          bUcast ? "VISIBLE" : "no" );
            std::fflush ( stdout );
        }
        return P2PeerHub::PeekP2PeerMsg ( pMsg );
    }

    //  The OTHER fan-out, phase 6. Every role chains, including the leaf:
    //  here the leaf is the ORIGIN of the upcast rather than its recipient, so
    //  swallowing it would stop the relay at the hub that posted it. The top
    //  is the far end and records the arrival; it relays nothing onward
    //  because it has no parent, which is what reaching the root looks like.
    virtual msgRESULT On_P2PeerUCast ( P2PeerMsg *pMsg ) override
    {
        if ( m_eRole == RoleTop && pMsg && pMsg->Data ( ) &&
             Contains ( pMsg->Data ( ), (size_t)pMsg->DataSize ( ), g_sUcastBody ) )
        {
            Log ( "TOP received the upcast body" );
            g_bTopSawUcast = true;
        }
        return P2PeerHub::On_P2PeerUCast ( pMsg );
    }

public:
    //  Posts an upcast, addressed at this hub ITSELF - the same shape phase 3
    //  uses for the broadcast and for the same reason: a message addressed
    //  elsewhere is routed by address and the relay never sees it.
    void PostUpcast ( )
    {
        const P2PaddrSTR strSelf = GetP2PaddrHub ( ).c_wstr ( );
        PostP2PeerMsg ( new P2PeerMsg32 ( strSelf, strSelf, P2Pmsg_UCast,
                                          g_sUcastBody.data ( ),
                                          (P2Psize_t)g_sUcastBody.size ( ) ) );
    }

protected:
    // THE FAN-OUT UNDER TEST RUNS IN THE BASE CLASS, so the top and the carrier
    // must CHAIN rather than swallow. Every other multi-hub test here returns
    // msgHANDLED for the roles it does not care about, which is precisely why
    // none of them has ever exercised P2PeerHub::On_P2PeerBCast.
    virtual msgRESULT On_P2PeerBCast ( P2PeerMsg *pMsg ) override
    {
        if ( m_eRole != RoleLeaf )
            return P2PeerHub::On_P2PeerBCast ( pMsg );

        if ( !pMsg || !pMsg->Data() )
            return msgHANDLED;

        const void  *pv = pMsg->Data();
        const size_t cb = (size_t)pMsg->DataSize();

        //  The leaf reads PLAINTEXT: a body sealed to it was already opened by
        //  P2PeerCon::OpenAppMsgInbound before this handler ran. That is the half
        //  of each phase that stops "nobody could read it" passing for
        //  confidentiality.
        if ( Contains ( pv, cb, g_sUniBody ) )
        {
            const bool bExact = ( cb == g_sUniBody.size() );
            std::printf ( "[sealbcast] LEAF opened the relayed unicast, %u bytes,"
                          " %s\n", (unsigned)cb,
                          bExact ? "EXACTLY what was sent" : "with trailing bytes" );
            std::fflush ( stdout );
            g_bLeafUniOk = true;
            if ( !bExact ) g_bLeafUniWrong = true;
            if ( g_hLeafUni ) SetEvent ( g_hLeafUni );
        }
        else if ( Contains ( pv, cb, g_sBcastBody ) )
        {
            Log ( "LEAF received the broadcast body" );
            g_bLeafSawBcast = true;
            if ( g_hLeafBcast ) SetEvent ( g_hLeafBcast );
        }
        else if ( Contains ( pv, cb, g_sShortBody ) )
        {
            Log ( "LEAF received the short body" );
            g_bLeafSawShort = true;
            if ( g_hLeafShort ) SetEvent ( g_hLeafShort );
        }
        else
        {
            std::printf ( "[sealbcast] LEAF received a %u byte body it did not"
                          " recognise (sealed-marker=%s)\n", (unsigned)cb,
                          pMsg->IsSealed() ? "set" : "clear" );
            std::fflush ( stdout );
        }
        return msgHANDLED;
    }

    // Server side of the login. Two jobs, and the second is not cosmetic.
    //
    //   1. The top holds an IDENTITY because it must sign what it seals, and a
    //      peer that can sign also signs its LOGIN (P2PeerCon, on CanAuthSign()).
    //      The stock handler refuses a login that carries data outright, so a hub
    //      that seals needs this override - the same note is on p2p_sealhop and
    //      p2p_authancestor.
    //   2. ConState_BCasts. Nothing in the library sets it on an ordinary
    //      connection, so without this line On_P2PeerBCast enumerates the children
    //      and matches none of them, and phase 2 would measure an empty loop.
    virtual conRESULT On_ConLogin ( P2PeerCon *pCon, P2PaddrSTR strThatP2Paddr,
                                    const void *pvLoginMsg, P2Psize_t iSize ) override
    {
        std::printf ( "[sealbcast] %s: login FROM '%s' (%d bytes of payload)\n",
                      RoleName(), N ( strThatP2Paddr ).c_str(), (int)iSize );
        std::fflush ( stdout );

        if ( pCon )
            pCon -> SetState ( ConState_BCasts | ConState_UCasts, 0 );

        if ( strThatP2Paddr )
        {
            if      ( wcscmp ( strThatP2Paddr, kMidAddr  ) == 0 )
            { if ( g_hMidUp  ) SetEvent ( g_hMidUp  ); }
            else if ( wcscmp ( strThatP2Paddr, kLeafAddr ) == 0 )
            { if ( g_hLeafUp ) SetEvent ( g_hLeafUp ); }
        }

        if ( !pvLoginMsg && !iSize )
            return P2PeerHub::On_ConLogin ( pCon, strThatP2Paddr, pvLoginMsg, iSize );

        pCon -> OnLogin  ( strThatP2Paddr );
        pCon -> LoginAck ( strThatP2Paddr, 0, 0 );
        return conHANDLED;
    }

    //  The refusals on the seal path Throw() out of the connection's send loop,
    //  which drops the LINK rather than the message. Counted so "nothing arrived"
    //  can be told apart from "the link went away", and so phase 3 can say which
    //  of the two it caused.
    virtual conRESULT On_ConClose ( P2PeerCon *pCon ) override
    {
        ++g_nCloses;
        std::printf ( "[sealbcast] %s: connection to '%s' CLOSED\n", RoleName(),
                      pCon ? N ( pCon->GetP2Paddress().c_wstr() ).c_str() : "?" );
        std::fflush ( stdout );
        return P2PeerHub::On_ConClose ( pCon );
    }

    virtual conRESULT On_ConLoginAck ( P2PeerCon *pCon, P2PaddrSTR strThisP2Paddr,
                                       P2PaddrSTR strThatP2Paddr,
                                       const void *pvLoginAck, P2Psize_t iSize ) override
    {
        std::printf ( "[sealbcast] %s: login ACK - this='%s' that='%s'\n",
                      RoleName(), N ( strThisP2Paddr ).c_str(),
                      N ( strThatP2Paddr ).c_str() );
        std::fflush ( stdout );
        if ( pCon )
            pCon -> SetState ( ConState_BCasts | ConState_UCasts, 0 );
        return P2PeerHub::On_ConLoginAck ( pCon, strThisP2Paddr, strThatP2Paddr,
                                           pvLoginAck, iSize );
    }

private:
    const char *RoleName ( ) const
    {
        return m_eRole == RoleTop ? "TOP"
             : m_eRole == RoleMid ? "CARRIER" : "LEAF";
    }

    Role m_eRole;
};

// =========================================================================
int main ( int argc, char *argv[] )
{
    short nPort = ( argc >= 2 ) ? (short)atoi ( argv[1] ) : 7846;

    g_sUniBody   = MakeBody ( kUniTag,   kLongBody  );
    g_sBcastBody = MakeBody ( kBcastTag, kLongBody  );
    g_sShortBody = MakeBody ( kShortTag, kShortBody );
    g_sUcastBody = MakeBody ( kUcastTag, kLongBody  );

    std::printf ( "=== p2p_sealbcast - the automatic seal, over a real link ===\n" );
    std::printf ( "Ports : %d (top listens), %d (carrier listens)\n",
                  (int)nPort, (int)( nPort + 1 ) );
    std::printf ( "Tree  : %s -> %s -> %s, auth OFF, nothing encrypted by the link.\n",
                  N ( kTopAddr ).c_str(), N ( kMidAddr ).c_str(),
                  N ( kLeafAddr ).c_str() );
    std::printf ( "Bodies: %u bytes for phases 1-2, %u for phase 3;"
                  " a seal adds %u.\n\n",
                  (unsigned)kLongBody, (unsigned)kShortBody,
                  (unsigned)p2pseal::kSealOverhead );
    std::fflush ( stdout );

    g_hLeafUni   = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hLeafBcast = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hLeafShort = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hMidUp     = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hLeafUp    = CreateEvent ( NULL, FALSE, FALSE, NULL );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }
    WSADATA oWsaData;
    WSAStartup ( MAKEWORD ( 2, 2 ), &oWsaData );

    // ---- Provisioning -----------------------------------------------------
    // The top needs an identity to SIGN what it seals and the leaf's agreement
    // point to seal TO. The leaf needs its own agreement key and the top's
    // identity to verify with. THE CARRIER GETS NOTHING - that is the
    // experiment, and it is also what an intermediate hub is entitled to be.
    const std::string sTopKey    = TempPath ( "topkey"    );
    const std::string sLeafAgree = TempPath ( "leafagree" );
    const std::string sTopAcl    = TempPath ( "topacl"    );
    const std::string sLeafAcl   = TempPath ( "leafacl"   );

    unsigned char pubTop  [p2pcng::kEcdsaPubLen];
    unsigned char agrLeaf [p2pcng::kEcdhPubLen];
    if ( !MakeIdentity  ( sTopKey,    pubTop  ) ||
         !MakeAgreement ( sLeafAgree, agrLeaf )   )
    { Log ( "SETUP: key generation failed" ); ScrubTempFiles(); return 2; }

    //  The leaf's row in the top's allow-list carries BOTH columns - that is the
    //  file format - though only the agreement point is read here. The top's row
    //  in the leaf's list needs only the identity: that is the signature the leaf
    //  will demand, on the seal AND on the relay attestation, which is required
    //  by default since Stage 3 step 9.
    unsigned char idLeaf[p2pcng::kEcdsaPubLen];
    {
        p2pcng::EcdsaP256 oLeafId;
        if ( !oLeafId.Generate() || !oLeafId.ExportPublic ( idLeaf ) )
        { Log ( "SETUP: leaf identity failed" ); ScrubTempFiles(); return 2; }
    }
    if ( p2pcng::AppendAllowList ( sTopAcl.c_str(), "Bc.Mid.Leaf",
                                   idLeaf, agrLeaf ) != p2pcng::IdOk ||
         p2pcng::AppendAllowList ( sLeafAcl.c_str(), "Bc",
                                   pubTop ) != p2pcng::IdOk )
    { Log ( "SETUP: allow-list provisioning failed" ); ScrubTempFiles(); return 2; }

    int nExit = 2;
    {
        // ---- The top: the sender ------------------------------------------
        BcastHub oTop ( kTopAddr, BcastHub::RoleTop );
        if ( oTop.SetIdentity  ( sTopKey.c_str() ) != p2pcng::IdOk ||
             oTop.SetAllowList ( sTopAcl.c_str() ) != p2pcng::IdOk )
        { Log ( "SETUP: top configuration failed" ); ScrubTempFiles(); return 2; }
        if ( !oTop.CanSeal() )
        { Log ( "SETUP: top cannot seal" ); ScrubTempFiles(); return 2; }
        //  AUTH OFF - see the header. There is no session key, so a body the
        //  carrier cannot read was hidden by the seal alone.
        oTop.RequireAuth ( false );

        // ---- The carrier: a router with no keys ---------------------------
        BcastHub oMid ( kMidAddr, BcastHub::RoleMid );
        oMid.RequireAuth ( false );

        // ---- The leaf: can open what is sealed to it ----------------------
        BcastHub oLeaf ( kLeafAddr, BcastHub::RoleLeaf );
        if ( oLeaf.SetAgreementKey ( sLeafAgree.c_str() ) != p2pcng::IdOk ||
             oLeaf.SetAllowList    ( sLeafAcl.c_str()   ) != p2pcng::IdOk )
        { Log ( "SETUP: leaf configuration failed" ); ScrubTempFiles(); return 2; }
        if ( !oLeaf.CanOpen() )
        { Log ( "SETUP: leaf cannot open" ); ScrubTempFiles(); return 2; }
        oLeaf.RequireAuth ( false );

        //  ASSERTED, NOT SET. RequireSeal has been the default since Stage 3 step
        //  20. If it is not, every result below would be measuring this test's own
        //  configuration rather than the library's, and a PASS would mean nothing.
        if ( !oTop.IsSealRequired()  || !oMid.IsSealRequired() ||
             !oLeaf.IsSealRequired()    )
        {
            Log ( "SETUP: RequireSeal is NOT the default - step 20 has been "
                  "reverted, and this test would measure its own configuration" );
            ScrubTempFiles(); return 2;
        }
        Log ( "sealing is REQUIRED, by default, on all three hubs" );

        //  CAN the top seal to the leaf AT ALL? Asked by hand, before anything is
        //  posted, because a sender that cannot seal and a library that loses the
        //  message look identical from the outside - both end with a body that
        //  never arrives. If this succeeds, the keys and the allow-list are right
        //  and whatever happens below is the library's.
        {
            std::vector<unsigned char> vProbe (
                p2pseal::SealedSize ( g_sUniBody.size(), p2pseal::kSealMaxReaders ) );
            size_t cbOut = 0;
            p2pseal::SealResult eProbe =
                oTop.SealFor ( kTopAddr, kLeafAddr, g_sUniBody.data(),
                               g_sUniBody.size(), &vProbe[0], vProbe.size(), &cbOut );
            std::printf ( "[sealbcast] setup probe: SealFor(%s -> %s) = %s,"
                          " %u bytes in, %u out\n",
                          N ( kTopAddr ).c_str(), N ( kLeafAddr ).c_str(),
                          p2pseal::SealResultText ( eProbe ),
                          (unsigned)g_sUniBody.size(), (unsigned)cbOut );
            std::fflush ( stdout );
            if ( eProbe != p2pseal::SealOk )
            {
                Log ( "SETUP: the top cannot seal to the leaf - the allow-list or "
                      "the agreement key is wrong, and nothing below would be "
                      "measuring the library" );
                ScrubTempFiles(); return 2;
            }
        }

        HANDLE hTopThread = oTop.SpawnHub();
        if ( !hTopThread )
        { Log ( "SETUP: top SpawnHub() failed" ); ScrubTempFiles(); return 2; }
        P2PeerConWsa *pSvcTop = P2PeerConWsa::ServiceFactory ( kDomain, nPort );
        if ( !pSvcTop )
        { Log ( "SETUP: top ServiceFactory failed" ); ScrubTempFiles(); return 2; }
        oTop.PostP2PeerCon ( pSvcTop );
        Log ( "top listening" );
        Sleep ( 500 );

        HANDLE hMidThread = oMid.SpawnHub();
        P2PeerConWsa *pCliMid =
            P2PeerConWsa::ClientFactory ( kTopAddr, L"127.0.0.1", nPort );
        P2PeerConWsa *pSvcMid =
            P2PeerConWsa::ServiceFactory ( kDomain, (short)( nPort + 1 ) );
        if ( !hMidThread || !pCliMid || !pSvcMid )
        { Log ( "SETUP: carrier failed" ); ScrubTempFiles(); return 2; }
        oMid.PostP2PeerCon ( pCliMid );
        oMid.PostP2PeerCon ( pSvcMid );
        Log ( "carrier dialling the top, and listening for its own child" );

        if ( WaitForSingleObject ( g_hMidUp, 15000 ) != WAIT_OBJECT_0 )
        {
            std::printf ( "\nRESULT: SETUP - the carrier never logged in to the top.\n" );
            oMid.CloseHub(); oTop.CloseHub();
            WaitForSingleObject ( hMidThread, 3000 );
            WaitForSingleObject ( hTopThread, 3000 );
            CloseHandle ( hMidThread ); CloseHandle ( hTopThread );
            CleanupP2Pmsg(); ScrubTempFiles(); WSACleanup();
            return 2;
        }
        Sleep ( 300 );

        HANDLE hLeafThread = oLeaf.SpawnHub();
        P2PeerConWsa *pCliLeaf =
            P2PeerConWsa::ClientFactory ( kMidAddr, L"127.0.0.1", (short)( nPort + 1 ) );
        if ( !hLeafThread || !pCliLeaf )
        { Log ( "SETUP: leaf failed" ); ScrubTempFiles(); return 2; }
        oLeaf.PostP2PeerCon ( pCliLeaf );
        Log ( "leaf dialling its parent" );

        if ( WaitForSingleObject ( g_hLeafUp, 15000 ) != WAIT_OBJECT_0 )
        {
            std::printf ( "\nRESULT: SETUP - the leaf never completed a login.\n" );
            oLeaf.CloseHub(); oMid.CloseHub(); oTop.CloseHub();
            WaitForSingleObject ( hLeafThread, 3000 );
            WaitForSingleObject ( hMidThread,  3000 );
            WaitForSingleObject ( hTopThread,  3000 );
            CloseHandle ( hLeafThread ); CloseHandle ( hMidThread ); CloseHandle ( hTopThread );
            CleanupP2Pmsg(); ScrubTempFiles(); WSACleanup();
            return 2;
        }
        Sleep ( 500 );   // let the LoginAck land before posting down the tree

        // ---- Phase 1: the relayed unicast, and the control ----------------
        Log ( "--- phase 1: a relayed UNICAST, sealed by the library ---" );
        oTop.PostP2PeerMsg ( new P2PeerMsg32 ( kTopAddr, kLeafAddr, P2Pmsg_BCast,
                                               g_sUniBody.data(),
                                               (P2Psize_t)g_sUniBody.size() ) );

        const bool bUniArrived =
            ( WaitForSingleObject ( g_hLeafUni, 20000 ) == WAIT_OBJECT_0 );

        if ( !bUniArrived || !g_bMidCarriedUni )
        {
            std::printf (
              "\nRESULT: INCONCLUSIVE - the relayed unicast %s, so the tree is\n"
              "  not carrying anything and phases 2 and 3 would prove nothing.\n"
              "  This is NOT a pass.\n"
              "  Check wsa_mesh and p2p_sealhop first. Then look above for what\n"
              "  the seal did to the body on its way out:\n"
              "    'Buffer overrun (%u vs 255) blocked'  - c_vBlob would not widen\n"
              "        a BLOB08 to hold the sealed block, and threw; or\n"
              "    'Failed Containment' / 'collate non-free entry'  - c_vBlob DID\n"
              "        resize and under-allocated the descriptor.\n"
              "  Either way the seal cannot write itself back over the payload it\n"
              "  replaces, and %ld connection(s) have closed so far.\n",
              bUniArrived ? "never passed the carrier"
                          : "never reached the leaf",
              (unsigned)( kLongBody + p2pseal::kSealOverhead ),
              (long)g_nCloses.load ( ) );
            nExit = 3;
        }
        else
        {
            std::printf ( "[sealbcast] phase 1 done - the carrier held a %s body and"
                          " %s it; the leaf recovered it\n",
                          g_bMidUniMarked ? "sealed-marked" : "UNMARKED",
                          g_bMidSawUniPlain ? "COULD READ" : "could not read" );
            std::fflush ( stdout );

            // ---- Phase 2: the same relay, a SHORT body --------------------
            //  The regression guard for the growth defect. A body this size
            //  lives in a BLOB08 whose length field is a UINT08, so the sealed
            //  262 bytes only fit once c_vBlob widens the type tag. Before
            //  2026-08-24 this threw out of the send loop and took the link
            //  with it, which is why the close count is read across it.
            Log ( "--- phase 2: the same relay, a body too SHORT to hold a seal ---" );
            const LONG nClosesBeforeShort = g_nCloses;
            oTop.PostP2PeerMsg ( new P2PeerMsg32 ( kTopAddr, kLeafAddr, P2Pmsg_BCast,
                                                   g_sShortBody.data(),
                                                   (P2Psize_t)g_sShortBody.size() ) );
            WaitForSingleObject ( g_hLeafShort, 20000 );
            Sleep ( 500 );
            const LONG nClosesAfterShort = g_nCloses;

            // ---- Phase 3: the tree broadcast ------------------------------
            //  Addressed at the top ITSELF, which is what makes the pump dispatch
            //  it locally (P2Pwin32.cpp:3550) into P2PeerHub::On_P2PeerBCast
            //  rather than route it. The fan-out then re-addresses a copy to each
            //  child link.
            //
            //  WHAT THIS MEASURES NOW, and it is not what it measured first.
            //  Before the scope field (TMsg_Scp, P2PeerMsg.h) the fan-out
            //  re-addressed each copy to its own link peer, which made
            //  SealAppMsgOutbound's last-hop exemption true at EVERY hop: the
            //  carrier read a 400 byte broadcast in clear off a tree that had
            //  sealed phases 1 and 2 over the same hop with the same keys, and
            //  then refused the copy for a destination the attestation no
            //  longer covered and dropped the link. Both measured 2026-08-24.
            //
            //  The exemption now keys on the SCOPE, which the fan-out does not
            //  rewrite, so the hook fires on a broadcast for the first time -
            //  and REFUSES it, because a scope names a subtree and no single
            //  agreement key opens one. That refusal is the designed outcome
            //  of the scope fix and not a defect in it: silence became noise.
            //  This phase is therefore STILL RED, and now for the honest
            //  reason - there is no way to seal to a subtree at all. Refer
            //  ProductionPlanLatest2.md item 6, which carries that decision.
            //
            //  It is no longer LAST, because it no longer breaks anything:
            //  the message is dropped at the sender and no link closes.
            Log ( "--- phase 3: the same tree, the same keys, a tree BROADCAST ---" );
            const LONG nClosesBeforeBcast = g_nCloses;
            oTop.PostP2PeerMsg ( new P2PeerMsg32 ( kTopAddr, kTopAddr, P2Pmsg_BCast,
                                                   g_sBcastBody.data(),
                                                   (P2Psize_t)g_sBcastBody.size() ) );
            WaitForSingleObject ( g_hLeafBcast, 15000 );
            Sleep ( 500 );   // let a late copy land before reading the flags
            const LONG nClosesAfterBcast = g_nCloses;

            //  SNAPSHOT. Phase 4 sends the same body through the same handlers
            //  and would otherwise overwrite the flags phase 3 is judged on.
            const bool bP3MidCarried = g_bMidCarriedBcast;
            const bool bP3MidPlain   = g_bMidSawBcastPlain;
            const LONG nP3Closes     = nClosesAfterBcast - nClosesBeforeBcast;

            // ---- Phase 4: the same broadcast, attestation alone -----------
            //  THE HALF THE SCOPE FIX ACTUALLY REPAIRS, isolated so that
            //  something can go green on it.
            //
            //  Phase 3 cannot see it: sealing refuses the broadcast before it
            //  is sent, so the attestation path is never reached. Turn sealing
            //  off - and ONLY sealing - and the same fan-out runs with relay
            //  attestation still required, which is its default since Stage 3
            //  step 9. The top signs as the origin, the carrier forwards that
            //  block untouched (AttestAppMsgOutbound early-outs on
            //  HasRelayAttest), and the leaf verifies it in GateRelayInbound.
            //
            //  Before the scope fix this FAILED and took the link with it:
            //  AttestRelay digests the destination, the fan-out rewrote the
            //  destination after signing, and the leaf answered "signature
            //  does not verify" and dropped the connection. Now both ends read
            //  GetScopeOrDestin(), which the fan-out leaves alone.
            //
            //  A LINK-CLOSE COUNT AND NOT JUST AN ARRIVAL. A refusal in
            //  GateRelayInbound throws and drops the connection, so "arrived"
            //  and "survived" are different questions and only the pair of
            //  them says the attestation verified rather than being skipped.
            Log ( "--- phase 4: the same broadcast, sealing OFF, "
                  "relay attestation ON ---" );
            oTop .RequireSeal ( false );
            oMid .RequireSeal ( false );
            oLeaf.RequireSeal ( false );
            if ( !oTop.IsRelayAuthRequired() || !oLeaf.IsRelayAuthRequired() )
                Log ( "phase 4: WARNING - relay attestation is not required, "
                      "so this phase proves nothing" );
            const LONG nClosesBeforeAttest = g_nCloses;
            oTop.PostP2PeerMsg ( new P2PeerMsg32 ( kTopAddr, kTopAddr, P2Pmsg_BCast,
                                                   g_sBcastBody.data(),
                                                   (P2Psize_t)g_sBcastBody.size() ) );
            WaitForSingleObject ( g_hLeafBcast, 15000 );
            Sleep ( 500 );
            const LONG nClosesAfterAttest = g_nCloses;
            const bool bP4Arrived = g_bLeafSawBcast;
            const LONG nP4Closes  = nClosesAfterAttest - nClosesBeforeAttest;

            // ---- Phase 5: the exemption, and what it must NOT reach --------
            //  RequireSealBroadcast(false) is how a deployment records that
            //  its broadcasts are not confidential. Phase 3 proves the default
            //  refuses; this proves the opt-out works AND that it is confined
            //  to the traffic it names.
            //
            //  TWO MESSAGES, AND THE SECOND IS THE POINT. Sealing is back ON
            //  and only the broadcast exemption is off, so:
            //      the broadcast  MUST reach the carrier readable - exempt;
            //      the unicast    MUST still be opaque to it - untouched.
            //  A switch that exempted both would pass a test that only sent
            //  the first, and "confidentiality is off for one routing mode"
            //  and "confidentiality is off" are the two things this has to
            //  tell apart. The exemption keys on TMsg_Scp, which only the
            //  fan-out stamps, so a unicast cannot reach it by construction -
            //  and this is what holds that claim to the wire.
            //
            //  The flags are RESET rather than snapshotted: phases 3 and 4
            //  already moved them, and the same bodies and the same handlers
            //  are used again here.
            Log ( "--- phase 5: sealing ON, broadcasts exempted by policy ---" );
            //  PHASE 1's verdict is taken HERE, before the reset below wipes
            //  the flags it is made of. Reading them after phase 5 had reused
            //  the same handlers would have scored phase 5 twice and phase 1
            //  not at all - and it would have PASSED, because phase 5 requires
            //  the unicast to be sealed too.
            const bool bP1MidPlain  = g_bMidSawUniPlain;
            const bool bP1LeafWrong = g_bLeafUniWrong;
            g_bMidCarriedBcast  = false;
            g_bMidSawBcastPlain = false;
            g_bLeafSawBcast     = false;
            g_bMidCarriedUni    = false;
            g_bMidSawUniPlain   = false;
            g_bLeafUniOk        = false;
            g_bLeafUniWrong     = false;
            oTop .RequireSeal ( true );  oTop .RequireSealBroadcast ( false );
            oMid .RequireSeal ( true );  oMid .RequireSealBroadcast ( false );
            oLeaf.RequireSeal ( true );  oLeaf.RequireSealBroadcast ( false );
            if ( !oTop.IsSealRequired ( ) || oTop.IsSealBroadcastRequired ( ) )
                Log ( "phase 5: WARNING - the switches did not take, so this "
                      "phase proves nothing" );
            const LONG nClosesBeforeExempt = g_nCloses;
            oTop.PostP2PeerMsg ( new P2PeerMsg32 ( kTopAddr, kTopAddr, P2Pmsg_BCast,
                                                   g_sBcastBody.data(),
                                                   (P2Psize_t)g_sBcastBody.size() ) );
            WaitForSingleObject ( g_hLeafBcast, 15000 );
            oTop.PostP2PeerMsg ( new P2PeerMsg32 ( kTopAddr, kLeafAddr, P2Pmsg_BCast,
                                                   g_sUniBody.data(),
                                                   (P2Psize_t)g_sUniBody.size() ) );
            WaitForSingleObject ( g_hLeafUni, 20000 );
            Sleep ( 500 );
            const LONG nP5Closes    = g_nCloses - nClosesBeforeExempt;
            const bool bP5BcastOpen = g_bMidCarriedBcast && g_bMidSawBcastPlain;
            const bool bP5UniSealed = g_bMidCarriedUni   && !g_bMidSawUniPlain;
            const bool bP5UniOk     = g_bLeafUniOk       && !g_bLeafUniWrong;

            // ---- Phase 6: the OTHER fan-out, and the switch that is not
            //      allowed to cover it ------------------------------------
            //  On_P2PeerUCast is the mirror of On_P2PeerBCast: a copy per
            //  PARENT link, re-addressed to that link's own peer, and each
            //  parent delivers it locally before relaying it on. So an upcast
            //  climbs to the root and every ancestor receives it: what the
            //  origin addressed is a CHAIN, no more sealable than a subtree,
            //  and refused by default for exactly the reason phase 3's
            //  broadcast is.
            //
            //  IT WAS DEAD CODE UNTIL 2026-09-22. There was no P2Pmsg_UCast
            //  ID and no map entry, so the handler could not be reached -
            //  which is also why the header of P2PeerCon::SealAppMsgOutbound
            //  could claim that TMsg_Scp was stamped by both relays and be
            //  vacuously right. Wiring the relay up under the obvious symmetry
            //  - the same scope field - would have made that sentence true and
            //  the TEST beneath it wrong in the same commit:
            //  RequireSealBroadcast(false), a setting deployments have already
            //  recorded, would have started exempting a second class of
            //  traffic on a relay that did not exist when they recorded it.
            //
            //  So the upcast stamps TMsg_Ups, RequireSealUpcast is its own
            //  switch, and THIS IS THE PHASE THAT HOLDS THE TWO APART. It runs
            //  with phase 5's policy still in force - sealing ON, broadcasts
            //  exempted - and changes nothing else:
            //      6a  SealBcast(false) alone: the upcast must be REFUSED at
            //          the sender, so the keyless carrier never holds it;
            //      6b  SealUcast(false) as well: now it is exempt, and the
            //          carrier reads it in clear.
            //  6a is the guard. 6b is the control that stops 6a passing
            //  because an upcast cannot be sent at all - the same pairing
            //  p2p_ucastgate uses for the routing bound, and the failure it
            //  exists to prevent is the one the register hit twice.
            Log ( "--- phase 6a: sealing ON, broadcasts exempt, an UPCAST ---" );
            const LONG nClosesBeforeUcast = g_nCloses;
            if ( oLeaf.IsSealBroadcastRequired ( ) ||
                !oLeaf.IsSealUpcastRequired    ( )    )
                Log ( "phase 6a: WARNING - the switches are not what this "
                      "phase assumes, so it proves nothing" );
            oLeaf.PostUpcast ( );
            Sleep ( 3000 );
            const bool bP6aCarried = g_bMidCarriedUcast;
            const bool bP6aTop     = g_bTopSawUcast;

            Log ( "--- phase 6b: and now with RequireSealUpcast(false) ---" );
            g_bMidCarriedUcast  = false;
            g_bMidSawUcastPlain = false;
            g_bTopSawUcast      = false;
            oTop .RequireSealUpcast ( false );
            oMid .RequireSealUpcast ( false );
            oLeaf.RequireSealUpcast ( false );
            if ( oLeaf.IsSealUpcastRequired ( ) )
                Log ( "phase 6b: WARNING - the switch did not take, so this "
                      "phase proves nothing" );
            oLeaf.PostUpcast ( );
            Sleep ( 3000 );
            const bool bP6bCarried = g_bMidCarriedUcast;
            const bool bP6bPlain   = g_bMidSawUcastPlain;
            const LONG nP6Closes   = g_nCloses - nClosesBeforeUcast;

            // ---- The verdict ----------------------------------------------
            const bool bP1 = !bP1MidPlain && !bP1LeafWrong;
            const bool bP2 = g_bLeafSawShort    && !g_bMidSawShortPlain;
            //  PHASE 3 PASSES WHEN THE BROADCAST IS REFUSED. Not when it is
            //  sealed - it cannot be, a scope names a subtree and no single
            //  agreement key opens one - and emphatically not when it arrives
            //  readable, which is the defect this whole test was written for.
            //  Refused, and WITHOUT dropping a link: a refusal that also took
            //  the connection down would be a different and worse behaviour
            //  wearing the same result.
            const bool bP3 = !bP3MidCarried && nP3Closes == 0;
            const bool bP4 = bP4Arrived && nP4Closes == 0;
            const bool bP5 = bP5BcastOpen && bP5UniSealed && bP5UniOk
                          && nP5Closes == 0;
            //  PHASE 6 PASSES WHEN THE BROADCAST EXEMPTION DID NOT REACH
            //  THE UPCAST, and when turning the upcast's own switch off did.
            //  Either half alone is worthless: 6a on its own is satisfied by
            //  an upcast that cannot be sent for any reason at all, and 6b on
            //  its own says only that a switch has an effect.
            const bool bP6 = !bP6aCarried && !bP6aTop
                          && bP6bCarried && bP6bPlain
                          && nP6Closes == 0;

            std::printf ( "\n--- what the carrier could read ---\n" );
            std::printf ( "  phase 1  relayed unicast, long  (%3u bytes) : %s%s\n",
                          (unsigned)kLongBody,
                          bP1MidPlain ? "PLAINTEXT" : "opaque",
                          bP1 ? "" : "   <-- FAILED" );
            std::printf ( "  phase 2  relayed unicast, short (%3u bytes) : %s%s\n",
                          (unsigned)kShortBody,
                          !g_bLeafSawShort ? "never arrived"
                            : ( g_bMidSawShortPlain ? "PLAINTEXT" : "opaque" ),
                          bP2 ? "" : "   <-- FAILED" );
            std::printf ( "  phase 3  tree broadcast         (%3u bytes) : %s%s\n",
                          (unsigned)kLongBody,
                          !bP3MidCarried ? "REFUSED at the sender - not sent"
                            : ( bP3MidPlain ? "PLAINTEXT" : "opaque" ),
                          bP3 ? "" : "   <-- FAILED" );
            std::printf ( "  phase 4  broadcast, attest only             : %s%s\n",
                          !bP4Arrived ? "never arrived"
                            : ( nP4Closes ? "arrived, but a link closed"
                                          : "attested end to end" ),
                          bP4 ? "" : "   <-- FAILED" );
            std::printf ( "  phase 5  broadcast, exempted by policy     : %s%s\n",
                          !g_bMidCarriedBcast ? "REFUSED - the opt-out did nothing"
                            : ( g_bMidSawBcastPlain ? "readable, as configured"
                                                    : "sealed anyway" ),
                          bP5 ? "" : "   <-- FAILED" );
            std::printf ( "  phase 5  relayed unicast, same policy      : %s%s\n",
                          !g_bMidCarriedUni ? "never arrived"
                            : ( g_bMidSawUniPlain ? "PLAINTEXT - EXEMPTION LEAKED"
                                                  : "opaque" ),
                          ( bP5UniSealed && bP5UniOk ) ? "" : "   <-- FAILED" );
            std::printf ( "  phase 6a upcast, SealBcast(false) only     : %s%s\n",
                          !bP6aCarried ? "REFUSED - the exemption stayed put"
                                       : "CARRIED - THE EXEMPTION LEAKED",
                          bP6 ? "" : "   <-- FAILED" );
            std::printf ( "  phase 6b upcast, SealUcast(false) too      : %s%s\n",
                          !bP6bCarried ? "never arrived - 6a proves nothing"
                            : ( bP6bPlain ? "readable, as configured"
                                          : "sealed anyway" ),
                          bP6 ? "" : "   <-- FAILED" );
            std::printf ( "  links closed, phases 2 / 3 / 4 / 5 / 6     : %ld / %ld / %ld / %ld / %ld\n",
                          (long)( nClosesAfterShort - nClosesBeforeShort ),
                          (long)nP3Closes, (long)nP4Closes, (long)nP5Closes,
                          (long)nP6Closes );
            std::fflush ( stdout );

            if ( bP1 && bP2 && bP3 && bP4 && bP5 && bP6 )
            {
                std::printf (
                  "\nRESULT: PASS - the carrier held %d bodies. It could read no\n"
                  "  relayed unicast, at either size, under any policy tried here.\n"
                  "  Auth was OFF throughout: no login was proven and no session key\n"
                  "  exists, so the link encrypted nothing and the seal is the only\n"
                  "  thing that hid any of it.\n"
                  "\n"
                  "  A BROADCAST IS A DIFFERENT ANSWER AND THAT IS THE RESULT, not a\n"
                  "  gap in it. On the default policy it is REFUSED - a scope names a\n"
                  "  subtree and no single agreement key opens one, so there is\n"
                  "  nothing to seal it to and it does not travel. With\n"
                  "  RequireSealBroadcast(false) it travels readable, which is a\n"
                  "  deployment recording that its broadcasts are not confidential -\n"
                  "  and the relayed unicast beside it stayed sealed, so the exemption\n"
                  "  is confined to what it names. Either way the copy carries the\n"
                  "  origin's attestation over its scope: unencrypted, still\n"
                  "  unforgeable.\n"
                  "\n"
                  "  AN UPCAST IS A SECOND AUDIENCE AND A SECOND DECISION. It fans\n"
                  "  out to every ancestor, so it is no more sealable than a\n"
                  "  broadcast and is refused on the same default - but\n"
                  "  RequireSealBroadcast(false) did NOT reach it, and\n"
                  "  RequireSealUpcast(false) did. The relay is symmetrical; the\n"
                  "  consent is not, because a deployment that wrote down one of\n"
                  "  those sentences has not written down the other.\n"
                  "\n"
                  "  CONFIDENTIAL BROADCAST IS STILL NOT AVAILABLE. That is an open\n"
                  "  design question - ProductionPlanLatest2.md item 6 - and this test\n"
                  "  goes green on the decision having been MADE, not on the\n"
                  "  capability existing. The same is true of a confidential upcast,\n"
                  "  and for the same reason.\n", g_nMidBodies.load ( ) );
                nExit = 0;
            }
            else
            {
                std::printf ( "\nRESULT: FAIL\n" );
                if ( bP1MidPlain )
                    std::printf (
                      "  * THE CARRIER READ THE RELAYED UNICAST. A body addressed two\n"
                      "    hops down crossed an intermediate hub in clear on the\n"
                      "    DEFAULT policy - p2p_sealhop's property failing on the\n"
                      "    automatic path.\n" );
                if ( bP3MidPlain )
                    std::printf (
                      "  * THE CARRIER READ THE BROADCAST, which is a REGRESSION of\n"
                      "    the scope fix and not the open question below. The same\n"
                      "    tree sealed the two unicasts over the same hop with the\n"
                      "    same keys. Check that SealAppMsgOutbound compares the peer\n"
                      "    against GetScopeOrDestin() and not GetDestin(), and that\n"
                      "    On_P2PeerBCast still stamps TMsg_Scp before it fans out -\n"
                      "    if the scope is missing, the fallback silently restores\n"
                      "    exactly the defect that field exists to undo.\n" );
                else if ( bP3MidCarried )
                    std::printf (
                      "  * PHASE 3: THE BROADCAST WAS SENT ON THE DEFAULT POLICY. It\n"
                      "    must be REFUSED there - RequireSealBroadcast defaults to\n"
                      "    true and a scope names a subtree no agreement key opens.\n"
                      "    Reaching the carrier at all means the exemption fired\n"
                      "    without being asked for: check that the default is true in\n"
                      "    AuthPolicy's constructor and that phase 5's\n"
                      "    RequireSealBroadcast(false) has not leaked backwards.\n" );
                else if ( nP3Closes )
                    std::printf (
                      "  * PHASE 3: the broadcast was refused, which is right, but\n"
                      "    %ld link(s) closed doing it. A refusal drops the MESSAGE;\n"
                      "    dropping the CONNECTION is a different and worse behaviour\n"
                      "    wearing the same result.\n", (long)nP3Closes );
                if ( !bP5BcastOpen )
                    std::printf (
                      "  * PHASE 5: THE OPT-OUT DID NOT WORK. With\n"
                      "    RequireSealBroadcast(false) the broadcast must reach the\n"
                      "    carrier readable - that is what the switch is for. It %s.\n"
                      "    The exemption keys on TMsg_Scp, so check the fan-out still\n"
                      "    stamps it and that SealAppMsgOutbound tests HasScope()\n"
                      "    before it computes anything else.\n",
                      g_bMidCarriedBcast ? "arrived sealed instead"
                                         : "never arrived at all" );
                if ( !bP5UniSealed )
                    std::printf (
                      "  * PHASE 5: THE EXEMPTION LEAKED INTO RELAYED UNICAST, which\n"
                      "    is the one thing it must never do. Only broadcasts were\n"
                      "    exempted; a unicast carries no TMsg_Scp, so it cannot reach\n"
                      "    that branch by construction - unless something is stamping\n"
                      "    a scope on traffic the fan-out never touched, or the test\n"
                      "    is keyed on a message NAME rather than the field.\n" );
                if ( bP5BcastOpen && bP5UniSealed && !bP5UniOk )
                    std::printf (
                      "  * PHASE 5: the unicast stayed sealed but did not come back\n"
                      "    intact at the leaf.\n" );
                if ( nP5Closes )
                    std::printf (
                      "  * PHASE 5: %ld link(s) closed. Neither message should have\n"
                      "    cost a connection.\n", (long)nP5Closes );
                if ( !bP4Arrived )
                    std::printf (
                      "  * PHASE 4: THE ATTESTED BROADCAST NEVER REACHED THE LEAF\n"
                      "    (%ld link(s) closed). This is the half the scope fix\n"
                      "    repairs, so a failure here is a real regression. The\n"
                      "    origin's block is digested over GetScopeOrDestin() at BOTH\n"
                      "    ends - AttestAppMsgOutbound and GateRelayInbound - and a\n"
                      "    mismatch reads as 'signature does not verify' followed by\n"
                      "    a dropped connection. Look for that above.\n",
                      (long)nP4Closes );
                else if ( nP4Closes )
                    std::printf (
                      "  * PHASE 4: the broadcast arrived but %ld link(s) closed while\n"
                      "    it was in flight, so something on the path refused a copy.\n"
                      "    Arrival alone does not mean the attestation verified.\n",
                      (long)nP4Closes );
                if ( !g_bLeafSawShort )
                    std::printf (
                      "  * THE SHORT BODY NEVER ARRIVED (%ld link(s) closed while it\n"
                      "    was in flight). A seal adds %u bytes, so a %u byte body needs\n"
                      "    %u - past the 255 a BLOB08 length field can express. This is\n"
                      "    the regression guard for the c_vBlob widening fix\n"
                      "    (Msgcore/P2Pmsg.cpp:983); look above for\n"
                      "    'Buffer overrun (%u vs 255) blocked' or 'Failed Containment'.\n",
                      (long)( nClosesAfterShort - nClosesBeforeShort ),
                      (unsigned)p2pseal::kSealOverhead,
                      (unsigned)kShortBody,
                      (unsigned)( kShortBody + p2pseal::kSealOverhead ),
                      (unsigned)( kShortBody + p2pseal::kSealOverhead ) );
                if ( g_bMidSawShortPlain )
                    std::printf (
                      "  * THE CARRIER READ THE SHORT BODY - it was relayed in clear\n"
                      "    rather than sealed or refused.\n" );
                if ( g_bLeafUniWrong )
                    std::printf (
                      "  * THE LEAF OPENED THE UNICAST BUT GOT SOMETHING ELSE BACK.\n" );
                nExit = 1;
            }
        }

        Log ( "shutdown begin" );
        oLeaf.CloseHub();
        WaitForSingleObject ( hLeafThread, 3000 );
        CloseHandle ( hLeafThread );

        oMid.CloseHub();
        WaitForSingleObject ( hMidThread, 3000 );
        CloseHandle ( hMidThread );

        oTop.CloseHub();
        WaitForSingleObject ( hTopThread, 3000 );
        CloseHandle ( hTopThread );
    }

    CleanupP2Pmsg();
    ScrubTempFiles();
    if ( g_hLeafUni   ) { CloseHandle ( g_hLeafUni   ); g_hLeafUni   = NULL; }
    if ( g_hLeafBcast ) { CloseHandle ( g_hLeafBcast ); g_hLeafBcast = NULL; }
    if ( g_hLeafShort ) { CloseHandle ( g_hLeafShort ); g_hLeafShort = NULL; }
    if ( g_hMidUp     ) { CloseHandle ( g_hMidUp     ); g_hMidUp     = NULL; }
    if ( g_hLeafUp    ) { CloseHandle ( g_hLeafUp    ); g_hLeafUp    = NULL; }
    WSACleanup();

    std::printf ( "Done (exit=%d).\n", nExit );
    std::fflush ( stdout );
    return nExit;
}
