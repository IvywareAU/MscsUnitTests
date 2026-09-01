// ***************************************************************************
//  p2p_framegate - the UNTRUSTED GATE over an arriving message image.
//
//  ProductionPlan.md Stage 1 step 4.  SECURITY.md, "Wire-framing bounds
//  checks".  Everything here is PRE-AUTH: it is reachable by anyone who can
//  open a TCP connection.
//
//  WHY THIS EXISTS SEPARATELY FROM p2p_fuzzframe
//
//  p2p_fuzzframe already drives thousands of mutated frames through the same
//  parser, and its assert budget is what caught this population in the first
//  place.  But an assert budget can only ever go red in a DEBUG build - ASSERT
//  is compiled out of Release, so the tally there is zero whether the code is
//  right or wrong, and the harness says so on every Release run.
//
//  The defect this file pins was PRECISELY a Release-only one.  Stage 4 of
//  P2Peerio::RecvP2PeerMsg used to build its P2PeerMsg from a pointer alone,
//  reaching the heap-create overload that ends in
//      ASSERT(P2PmsgHeap_AssertValidIOMAGE(pHandle));
//      ASSERT(P2PmsgHeap_AssertVBlocksIOMAGE(pHandle));
//  - both block walks INSIDE the assertion.  A Debug build walked the chain
//  and threw the answer away; a Release build never walked it at all and
//  adopted whatever arrived.  Undo the fix today and the fuzz gate goes red in
//  Debug and stays GREEN IN RELEASE.  This file is the test that does not.
//
//  THE THREE PROPOSITIONS, and each is checked in whatever build it is
//  compiled into, because none of them is spelled with an assertion:
//
//    (1) POSITIVE CONTROL.  A frame the library itself built parses into
//        exactly one message, and the same image is accepted by the
//        length-validated adoption path.  Without this, a parser that refused
//        everything would pass (2) and (3) perfectly.
//
//    (2) WHAT THE GATE REFUSES, THE RECEIVE PATH REFUSES.  For every mutant
//        below, the two are compared: if adopting the image directly through
//        the length-validated path throws, then feeding the same bytes to
//        P2Peerio::RecvP2PeerMsg must not produce a P2PeerMsg.  That is the
//        one-argument constructor's defect stated as a property, and it is
//        false on the tree before the fix - in both configurations, which is
//        the point.
//
//    (3) A REFUSED IMAGE IS LEFT EXACTLY AS IT ARRIVED.  The block walks used
//        to end by writing the image's own root back into agreement with what
//        they had just counted - a validator editing the bytes it was asked to
//        judge.  On a heap this process built that is maintenance; on an
//        arriving frame it means a corrupt image was not merely mis-read, it
//        was adopted.  Every refused mutant is compared byte for byte with the
//        bytes handed in, and any difference is a failure naming the offset.
//        Accepted images are deliberately NOT compared: adoption connects a
//        reader to the image and is entitled to touch it.
//
//  HOW THE MUTANTS ARE CHOSEN - a sweep, not a hand-picked list.
//
//  Every byte of the image's control region is set to each of a few hostile
//  values in turn, one byte at a time, and the complement is repaired so the
//  frame still reaches the parser rather than dying at the checksum.  A sweep
//  is used instead of named cases for one reason: the fields that matter are
//  at offsets this test would otherwise have to know, and the two that were
//  actually wrong - a block header's step size, and the ROOT'S aAlloc LINK,
//  which neither walk looked at until 2026-08-21 - sit at offsets nobody had
//  written a case for.  A sweep cannot miss a field for want of being told
//  about it.
//
//  IT IS GUARDED AGAINST BEING VACUOUS, which a sweep needs more than a named
//  case does.  If the adoption path stopped refusing anything at all, (2) and
//  (3) would both pass trivially, so the run FAILS unless a stated minimum of
//  the sweep is refused, and it prints the count either way.
//
//  IT DOES NOT LEAK, AND THAT IS A PROPOSITION RATHER THAN A TIDY-UP.
//  p2p_fuzzframe runs with detect_leaks=0 because a throw out of stage 4
//  leaves ownership of the frame buffer undecidable from outside, and a fuzzer
//  must not risk a double free being read as a finding.  This harness has the
//  answer the fuzzer lacks: it has already asked the adoption path about the
//  same bytes, and a refusal there means the create detached the image and the
//  buffer is still ours.  So it frees, LSan stays ON, and a double free would
//  be reported as one - which makes the ownership contract the fix introduced
//  something this test checks rather than something it works around.
//
//  NO PORT, NO HUB, NO RESOURCE_LOCK.  It drives P2Peerio::RecvP2PeerMsg
//  through the same bQueued seam p2p_fuzzframe and p2p_imagegen document:
//  P2Peerio::Recv tests pOVERLAPPEDrecv->bQueued BEFORE it touches m_pCon and
//  throws if it is set, so every Recv becomes a side-effect-free "I would read
//  N bytes into P now" marker and this harness performs the copy itself.
//  Nothing is stubbed; the parser under test is the shipping one.
// ***************************************************************************

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2Peerio.h"
#include "P2PeerMsg.h"
#include "P2PmsgBSTR.h"
#include "Msgexception.h"

#include <cstdio>
#include <cstring>

static int g_nFail = 0;
static int g_nPass = 0;

static void Ok ( const char *szWhat )
{
    ++g_nPass;
    std::printf ( "  ok   : %s\n", szWhat );
    std::fflush ( stdout );
}
static void Fail ( const char *szWhat, const char *szWhy )
{
    ++g_nFail;
    std::printf ( "  FAIL : %s\n         %s\n", szWhat, szWhy );
    std::fflush ( stdout );
}

enum { kMaxWire = 8192 };

struct Wire { unsigned char b[kMaxWire]; unsigned n; };

static unsigned RdU32 ( const unsigned char *p )
{
    unsigned v = 0; std::memcpy ( &v, p, 4 ); return v;
}
static void WrU32 ( unsigned char *p, unsigned v )
{
    std::memcpy ( p, &v, 4 );
}
static unsigned SyncSizeof ( )
{
    static const VBListIOmage s_oProbe = { { 0, 0 }, 0 };
    return (unsigned)sizeof(s_oProbe.oSync);
}
static unsigned DeclaredOf ( const unsigned char *p )
{
    return RdU32(p) & 0x00FFFFFFu;
}

//  Repair uiSync2 so the frame is still "plausibly a header" to stage 2.  An
//  attacker does exactly this - MsgVBHeap says in as many words that the
//  complement is trivially forgeable - and without it most mutants would die
//  at the checksum and never reach the structure this file is about.
static void RepairComplement ( Wire &w )
{
    if ( w.n >= 8 ) WrU32 ( w.b + 4, ~RdU32 ( w.b ) );
}

// -------------------------------------------------------------------------
//  Entry point A - adopt the image directly, the way the receive path now
//  does, through the length-validated constructor.
//
//  It ADOPTS rather than copies, so ownership follows the throw: on success
//  the P3PmsgBSTR owns the buffer and frees it; on a refusal the create
//  detaches the image before closing its handle, so the buffer is still ours.
//  That contract is what P2Peerio::RecvP2PeerMsg relies on and it is exercised
//  here rather than assumed - a mistake in it shows up as a leak or a double
//  free under the sanitiser gate, which is where this test also runs.
// -------------------------------------------------------------------------
enum Adopt { ADOPT_OK, ADOPT_REFUSED, ADOPT_OTHER };

static int AdoptImage ( const Wire &w, bool *pbImageIntact )
{
    if ( pbImageIntact ) *pbImageIntact = true;

    //  +4 because that is what the receive path allocates (P2Peerio.cpp stage
    //  2, `new char[nSizeof+4]`), so the adoption sees the same slack.
    char *pBuffer = new char [ w.n + 4 ];
    std::memcpy ( pBuffer, w.b, w.n );

    try
    {
      P3PmsgBSTR oBSTR ( (VBListIOmage *)pBuffer, (VBLsize)w.n );
      return ADOPT_OK;                 // oBSTR owns pBuffer and frees it
    }
    catch ( P2Pevent *pEVT )
    {
      if ( pEVT ) pEVT->Cancel ( false );          // silent dispose, no dialog
      if ( pbImageIntact )
        *pbImageIntact = ( std::memcmp ( pBuffer, w.b, w.n ) == 0 );
      delete [] pBuffer;
      return ADOPT_REFUSED;
    }
    catch ( ... )
    {
      if ( pbImageIntact )
        *pbImageIntact = ( std::memcmp ( pBuffer, w.b, w.n ) == 0 );
      delete [] pBuffer;
      return ADOPT_OTHER;
    }
}

// -------------------------------------------------------------------------
//  Entry point B - the shipping receive path, one frame delivered whole.
// -------------------------------------------------------------------------
enum Outcome { OUT_MSG, OUT_REFUSED, OUT_STARVED, OUT_OTHER };

static bool IsRecvRequest ( P2Pevent *pEVT )
{
    if ( !pEVT ) return false;
    LPCTSTR lpszModule = pEVT->GetModule();
    if ( !lpszModule ) return false;

    LPCTSTR lpszTail = lpszModule;
    for ( LPCTSTR p = lpszModule; *p; ++p )
      if ( *p == (TCHAR)':' ) lpszTail = p + 1;

    static const TCHAR szRecv[] = { (TCHAR)'R', (TCHAR)'e', (TCHAR)'c',
                                    (TCHAR)'v', (TCHAR)0 };
    const TCHAR *a = lpszTail, *b = szRecv;
    while ( *a && *b && *a == *b ) { ++a; ++b; }
    return ( *a == 0 && *b == 0 );
}

static bool Deliver ( OVERLAPPEDcon *pOv, const Wire &oWire, unsigned *pnFed )
{
    const unsigned nSync = SyncSizeof();
    char          *pDst;
    unsigned       nWant;

    if ( (unsigned)pOv->dwBytes < nSync )
    {                                  // stage 1
      if ( !pOv->pUserDB1 ) return false;
      pDst  = pOv->pUserDB1 + pOv->dwBytes;
      nWant = nSync - (unsigned)pOv->dwBytes;
    }
    else
    {                                  // stage 3
      if ( !pOv->pUserDB1 || !pOv->pUserDB2 ) return false;
      unsigned nSizeof = DeclaredOf ( (const unsigned char *)pOv->pUserDB1 );
      if ( nSizeof <= (unsigned)pOv->dwBytes ) return false;
      pDst  = pOv->pUserDB2 + pOv->dwBytes;
      nWant = nSizeof - (unsigned)pOv->dwBytes;
    }

    unsigned nLeft = oWire.n - *pnFed;
    if ( nLeft == 0 ) return false;
    unsigned n = ( nWant < nLeft ) ? nWant : nLeft;

    std::memcpy ( pDst, oWire.b + *pnFed, n );
    pOv->dwBytes += n;                 // exactly P2PeerCon.cpp:398
    *pnFed       += n;
    return true;
}

//  bGateRefuses is what makes this harness able to free where p2p_fuzzframe
//  cannot, and the difference is worth stating because the leak it removes is
//  otherwise identical.
//
//  WHO OWNS pUserDB2 WHEN STAGE 4 THROWS.  Two cases, and they want opposite
//  treatment:
//    * the length-validated create threw.  It DETACHES the image before
//      closing its handle, precisely so the caller keeps it - so the buffer is
//      still ours and must be freed.
//    * the create succeeded and something later in the P2PeerMsg construction
//      threw.  The P3PmsgBSTR base is constructed by then, so its destructor
//      runs and P2PmsgHeap_Close deletes the image - freeing it again is a
//      double free.
//  p2p_fuzzframe cannot tell those apart from outside and says so, and it
//  LEAKS the buffer rather than risk a double free being read as a fuzz
//  finding.  That is the right call for a fuzzer and the wrong one here,
//  because this harness has already asked the adoption path about these exact
//  bytes: if the gate REFUSED them, the create will refuse them again on this
//  path and the first case is the one that happens.  So the caller passes that
//  answer in, and LSan stays ON for this test.
static int Drive ( const Wire &oWire, int *pnMsgs, bool bGateRefuses )
{
    P2Peerio      oIo;                 // m_pCon stays nullptr
    OVERLAPPEDcon oOv;
    std::memset ( &oOv, 0, sizeof(oOv) );
    oOv.bQueued = true;                // -> P2Peerio::Recv is a marker

    unsigned nFed = 0;
    int      eOut = OUT_STARVED;
    *pnMsgs = 0;

    for ( int nTurn = 0; nTurn < 96; ++nTurn )
    {
      //  The same ownership rule p2p_fuzzframe documents at length: whether
      //  the image was freed on a stage 4 throw is undecidable from out here,
      //  so one buffer is LEAKED rather than risk a double free being read as
      //  a finding.  Bounded at one frame per affected mutant.
      bool bStage4 = ( oOv.pUserDB1 && oOv.pUserDB2 &&
                       (unsigned)oOv.dwBytes >= SyncSizeof() &&
                       (unsigned)oOv.dwBytes >=
                           DeclaredOf ( (const unsigned char *)oOv.pUserDB1 ) );

      P2PeerMsg *pMsg = 0;
      try
      {
        pMsg = oIo.RecvP2PeerMsg ( INVALID_HANDLE_VALUE, &oOv );
      }
      catch ( P2Pevent *pEVT )
      {
        bool bRead = IsRecvRequest ( pEVT );
        if ( pEVT ) pEVT->Cancel ( false );
        if ( !bRead )
        {
          eOut = OUT_REFUSED;
          //  Dropped only where ownership is genuinely undecidable - see the
          //  note above Drive.  Where the gate has already refused these bytes
          //  the image is still ours and the cleanup below frees it.
          if ( bStage4 && !bGateRefuses ) oOv.pUserDB2 = 0;
          break;
        }
        if ( !Deliver ( &oOv, oWire, &nFed ) ) { eOut = OUT_STARVED; break; }
        continue;
      }
      catch ( ... )
      {
        eOut = OUT_OTHER;
        if ( bStage4 && !bGateRefuses ) oOv.pUserDB2 = 0;
        break;
      }

      if ( pMsg )
      {
        ++*pnMsgs;
        delete pMsg;
        eOut = OUT_MSG;
        if ( nFed >= oWire.n ) break;
        continue;
      }
      eOut = OUT_STARVED;
      break;
    }

    delete [] oOv.pUserDB1; oOv.pUserDB1 = 0;
    delete [] oOv.pUserDB2; oOv.pUserDB2 = 0;
    return eOut;
}

int main ( int argc, char **argv )
{
    (void)argc; (void)argv;
    std::printf ( "=== p2p_framegate - the untrusted gate over an arriving "
                  "image (Stage 1 step 4) ===\n" );

    // ---- setup: a frame the library itself calls well formed -------------
    static Wire oBase;
    std::memset ( &oBase, 0, sizeof(oBase) );
    {
      static const wchar_t *kPayload = L"framegate";
      P2Psize_t nBytes = (P2Psize_t)((wcslen(kPayload) + 1) * sizeof(wchar_t));

      P2PeerMsg32 oMsg ( L"Gate.Client", L"Gate.Server", P2Pmsg_BCast,
                         kPayload, nBytes );
      oMsg.PrepareP2Piomage ( ~(DWORD)0 );        // P2Peerio's default m_dwIFmask
      const P2Piomage *pImage = oMsg.P2Piomage();
      if ( !pImage )
      {
        std::printf ( "SETUP: P2Piomage() returned null\n" );
        return 2;
      }
      UINT nImage = P2Piomage_Sizeof ( pImage );
      if ( !nImage || nImage > (UINT)kMaxWire )
      {
        std::printf ( "SETUP: frame size %u does not fit the wire buffer\n",
                      (unsigned)nImage );
        return 2;
      }
      std::memcpy ( oBase.b, pImage, nImage );
      oBase.n = nImage;
    }
    std::printf ( "base frame built by the library: %u bytes\n", oBase.n );

    // ---- phase 1: THE POSITIVE CONTROL -----------------------------------
    //  Both entry points, because a sweep that refused everything would make
    //  every proposition below vacuous in the other direction.
    std::printf ( "\nphase 1 - positive control\n" );
    {
      int nMsgs = 0;
      if ( Drive ( oBase, &nMsgs, false ) == OUT_MSG && nMsgs == 1 )
        Ok ( "a well-formed frame parses into exactly one message" );
      else
        Fail ( "a well-formed frame parses into exactly one message",
               "the receive path refuses its own serializer's output, so every "
               "negative below is vacuous - fix this before reading any of them" );

      if ( AdoptImage ( oBase, 0 ) == ADOPT_OK )
        Ok ( "the same image is ACCEPTED by the length-validated adoption path" );
      else
        Fail ( "the same image is ACCEPTED by the length-validated adoption path",
               "the gate refuses a legitimate image, which is a defect in the "
               "other direction and nothing else here would notice" );
    }

    // ---- phase 2 and 3: the sweep ----------------------------------------
    std::printf ( "\nphase 2 - what the gate refuses, the receive path refuses\n"
                  "phase 3 - and a refused image is left exactly as it arrived\n" );
    {
      //  Hostile values rather than every value: 0x00 and 0xFF are the two
      //  ends of every length and link field, 0x01 makes a step of one, and
      //  0x80 sets the top bit of whichever byte it lands on.
      static const unsigned char kBytes[] = { 0x00, 0x01, 0x80, 0xFF };

      //  The control region.  The sync word, the root and the first few block
      //  headers all live at the front; beyond that is payload, where a
      //  mutation is a different message rather than a malformed one.  128 is
      //  comfortably past the root on either platform's addressing width.
      const unsigned nSpan = ( oBase.n < 128u ) ? oBase.n : 128u;

      unsigned nTried = 0, nRefused = 0, nAccepted = 0, nOther = 0;
      unsigned nLeaked = 0;            // refused by the gate, taken by the path
      unsigned nEdited = 0;            // refused, but the image was written to
      unsigned nFirstLeakOff = 0, nFirstEditOff = 0;

      for ( unsigned off = 0; off < nSpan; ++off )
      {
        for ( unsigned iv = 0; iv < sizeof(kBytes)/sizeof(kBytes[0]); ++iv )
        {
          Wire w = oBase;
          if ( w.b[off] == kBytes[iv] ) continue;     // not a mutation
          w.b[off] = kBytes[iv];

          //  Offsets 0-7 are the sync word itself.  Repairing the complement
          //  over a mutated size is exactly what an attacker does; leaving it
          //  broken would send the frame down the re-synchronisation path and
          //  prove nothing about the structure.
          RepairComplement ( w );

          //  A mutated declared size can point past the bytes we hold.  Stage
          //  2 refuses that on its own and the case belongs to p2p_fuzzframe;
          //  here it would only measure the length bound twice.
          if ( DeclaredOf ( w.b ) != w.n ) continue;

          ++nTried;
          bool bIntact = true;
          const int eAdopt = AdoptImage ( w, &bIntact );

          if ( eAdopt == ADOPT_OK ) { ++nAccepted; continue; }
          if ( eAdopt == ADOPT_OTHER )
          {
            ++nOther;
            continue;                  // reported below; not a refusal
          }
          ++nRefused;

          //  PHASE 3.  The gate said no; the bytes must be as they arrived.
          if ( !bIntact )
          {
            if ( !nEdited ) nFirstEditOff = off;
            ++nEdited;
          }

          //  PHASE 2.  The gate said no; so must the receive path.
          int nMsgs = 0;
          if ( Drive ( w, &nMsgs, true ) == OUT_MSG || nMsgs != 0 )
          {
            if ( !nLeaked ) nFirstLeakOff = off;
            ++nLeaked;
          }
        }
      }

      std::printf ( "  swept %u single-byte mutants over the first %u bytes: "
                    "%u refused, %u accepted, %u other\n",
                    nTried, nSpan, nRefused, nAccepted, nOther );

      //  THE VACUITY GUARD.  A sweep proves nothing about a gate that refuses
      //  nothing, and both propositions below would pass perfectly against
      //  one.  The floor is deliberately far under what is measured - 111 of
      //  409 on Windows, 2026-08-22 - because it is here to catch a gate that
      //  has STOPPED, not to pin an exact count that a legitimate change to
      //  the serializer would move.
      if ( nRefused >= 40 )
        Ok ( "the sweep is not vacuous - the gate refuses a substantial "
             "fraction of it" );
      else
        Fail ( "the sweep is not vacuous - the gate refuses a substantial "
               "fraction of it",
               "almost nothing was refused, so the two propositions below are "
               "measuring an open door" );

      if ( nOther == 0 )
        Ok ( "every refusal arrived as a P2Pevent, not as an escaped exception" );
      else
        Fail ( "every refusal arrived as a P2Pevent, not as an escaped exception",
               "an image left the adoption path through some other exception "
               "type, which no caller of it is written to catch" );

      if ( nLeaked == 0 )
        Ok ( "PHASE 2: no image the gate refuses becomes a P2PeerMsg" );
      else
      {
        char szWhy[256];
        std::snprintf ( szWhy, sizeof(szWhy),
          "%u image(s) the length-validated path REFUSED were still parsed "
          "into a message by P2Peerio::RecvP2PeerMsg (first at byte offset "
          "%u). That is stage 4 adopting an image without the length - the "
          "block walks then sit inside ASSERT() and a Release build does not "
          "run them. ProductionPlan.md Stage 1 step 4.",
          nLeaked, nFirstLeakOff );
        Fail ( "PHASE 2: no image the gate refuses becomes a P2PeerMsg", szWhy );
      }

      if ( nEdited == 0 )
        Ok ( "PHASE 3: a refused image is byte-identical to what arrived" );
      else
      {
        char szWhy[256];
        std::snprintf ( szWhy, sizeof(szWhy),
          "%u refused image(s) were MODIFIED by the walk that refused them "
          "(first at byte offset %u). A validator must not write to the bytes "
          "it was asked to judge - see the untrusted gate in MsgVBHeap.h.",
          nEdited, nFirstEditOff );
        Fail ( "PHASE 3: a refused image is byte-identical to what arrived",
               szWhy );
      }
    }

    std::printf ( "\n=== p2p_framegate: %d passed, %d failed ===\n",
                  g_nPass, g_nFail );
    return g_nFail ? 1 : 0;
}
