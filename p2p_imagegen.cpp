// ***************************************************************************
//  p2p_imagegen - the message image's layout generation, on the wire and in
//                 the store, and the fact that they answer differently.
//
//  VERSIONING.md 6, 1.0 gate 2.  ProductionPlan.md Stage 5 step 15.
//
//  WHAT THIS GATE IS FOR
//
//  The message image header is one 32-bit word and a complement of it.  Bits
//  0-23 are the size, 24-25 the addressing mode, 26-31 the sentinel.  There is
//  no room for a version field, so the SENTINEL is the version field: six bits
//  with two codes spoken for (generation 1 = 0xA4, and 0 = pre-sentinel) and
//  sixty-two free.  Stamping a new code is what turns an undetectable body
//  layout change into a refusal.
//
//  THAT MECHANISM HAS TWO DIRECTIONS AND ONLY ONE OF THEM USED TO WORK.
//  An OLD reader meeting a NEW image was always covered: an unknown pattern
//  was refused.  A NEW reader meeting an OLD image was not - it read
//  VBLockSync_Native and parsed old bytes under new rules.  Closing that is
//  what makes VBLock_SyncForm a generation CLASSIFIER rather than an equality
//  against one constant.
//
//  IT IS A FALLBACK AND NOT A REGISTRY, WHICH IS WHERE THE COVERAGE COMES
//  FROM.  One code is defined - the one this build writes - and every other
//  non-zero pattern is VBLockSync_Gen, "a layout this build does not
//  implement", refused with its code in the text.  An enumerated registry of
//  reserved codes would have named generation 2 and only generation 2, would
//  have said nothing about generation 3, and would have spent 1/64 of the
//  byte-order diagnosis (byte_order.md 4.4) on each code it listed.  Phase 2
//  below sweeps six codes, four of which no registry would ever have held.
//
//  THE ASYMMETRY IS THE DECISION, NOT AN OVERSIGHT.
//    THE WIRE takes the current generation only.  A frame is a peer, and a
//      peer can be upgraded - the same call login kVersion 2 makes when it
//      refuses v1 rather than negotiating down to it.
//    THE STORE still accepts a pre-sentinel image, and warns.  A file is data
//      somebody already has, and there is no conversation to have with it.
//  A test that only checked the wire would pass an implementation that refused
//  legacy images EVERYWHERE, which would silently invalidate stored data.
//  Phase 3 exists to fail that implementation.
//
//  WHAT GOES RED WITHOUT THE FIX, AND WHAT DOES NOT - stated because a gate
//  whose cases all pass on the broken tree measures nothing:
//    * PHASE 2 "pre-sentinel" IS the break.  Such a frame used to be ACCEPTED
//      end to end: stage 2 checks only the complement, and downstream
//      P2PmsgHeap_IsIOMAGE accepts VBLockSync_Legacy, so it parsed into a
//      P2PeerMsg.  This case goes red on the tree before the change.
//    * PHASE 2 "gen2" and "unregistered" were ALREADY refused, as corruption,
//      from inside Msgcore and after the allocation.  They do NOT go red on
//      the old tree and nothing here claims they do.  What they assert is the
//      DIAGNOSTIC: the refusal must name the generation that arrived.
//      "Invalid VBListIOmage" is the answer they used to get, and it is not
//      an answer anybody can act on.
//    * PHASE 1 is the positive control.  Without it, a stage 2 that refused
//      everything would pass every negative in this file.
//
//  HOW IT RUNS WITH NO SOCKET
//  The same seam p2p_fuzzframe documents at length: P2Peerio::Recv tests
//  pOVERLAPPEDrecv->bQueued BEFORE it touches m_pCon, and throws if it is set.
//  With bQueued pre-set every Recv is a side-effect-free "I would read N bytes
//  into P now" marker, and this harness performs the copy itself.  Nothing is
//  stubbed; the parser under test is the shipping one, unmodified.
// ***************************************************************************

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2Peerio.h"
#include "P2PeerMsg.h"
#include "P2PmsgMgr.h"
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

// TCHAR is wchar_t on both platforms here and its width is not the same on
// both, so the diagnostics are printed unit by unit rather than through a
// "%ls" that would have to agree with the CRT about encoding.  Every string
// this file inspects is ASCII by construction.
static void PrintT ( const char *szLead, LPCTSTR lpsz )
{
    std::printf ( "%s", szLead );
    for ( ; lpsz && *lpsz; ++lpsz )
      std::putchar ( (*lpsz >= 32 && *lpsz < 127) ? (char)*lpsz : '?' );
    std::putchar ( '\n' );
    std::fflush ( stdout );
}

// Substring search over TCHAR, hand-rolled for the same reason p2p_fuzzframe
// hand-rolls its module comparison: it depends on no CString shim behaviour.
static bool ContainsT ( LPCTSTR lpszHay, LPCTSTR lpszNeedle )
{
    if ( !lpszHay || !lpszNeedle ) return false;
    for ( LPCTSTR p = lpszHay; *p; ++p )
    {
      LPCTSTR a = p, b = lpszNeedle;
      while ( *a && *b && *a == *b ) { ++a; ++b; }
      if ( *b == 0 ) return true;
    }
    return false;
}

static const P2PaddrSTR kSrcAddr = L"Gen.Client";
static const P2PaddrSTR kDstAddr = L"Gen.Server";

enum { kMaxWire = 4096 };

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

static unsigned Bswap32 ( unsigned v )
{
    return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8)
         | ((v & 0x00FF0000u) >>  8) | ((v & 0xFF000000u) >> 24);
}

// Re-stamp ONLY the sentinel bits of a frame the library built, leaving the
// size and the addressing mode exactly as it wrote them.  The complement is
// repaired because stage 2 tests it first: leaving it broken would route the
// frame down the re-synchronisation path and prove nothing about this gate.
static void RestampGeneration ( Wire &w, unsigned uGenBits )
{
    unsigned s1 = RdU32 ( w.b );
    s1 = ( s1 & ~((unsigned)VBLock_SyncMask << 24) ) | ( uGenBits << 24 );
    WrU32 ( w.b + 0,  s1 );
    WrU32 ( w.b + 4, ~s1 );
}

// -------------------------------------------------------------------------
//  The driver - one frame, delivered whole, across as many turns as the
//  parser asks for.  No RNG and no short reads: this gate is about the header
//  classification, and p2p_fuzzframe already owns the accumulation cases.
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

// Drives one frame.  On a refusal the diagnostic is copied out, so a caller
// can assert WHAT it said and not merely that something was thrown.
static int Drive ( const Wire &oWire, int *pnMsgs, CString *pstrWhy )
{
    P2Peerio      oIo;                 // m_pCon stays nullptr
    OVERLAPPEDcon oOv;
    std::memset ( &oOv, 0, sizeof(oOv) );
    oOv.bQueued = true;                // -> P2Peerio::Recv is a marker

    unsigned nFed = 0;
    int      eOut = OUT_STARVED;
    *pnMsgs = 0;

    for ( int nTurn = 0; nTurn < 64; ++nTurn )
    {
      // Same ownership rule p2p_fuzzframe documents: whether the image was
      // freed on a stage 4 throw is undecidable from out here, so one buffer
      // is LEAKED rather than risk a double free being read as a finding.
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
        if ( !bRead && pstrWhy && pEVT ) *pstrWhy = pEVT->GetMessage();
        if ( pEVT ) pEVT->Cancel ( false );   // silent dispose: no dialog
        if ( !bRead )
        {
          eOut = OUT_REFUSED;
          if ( bStage4 ) oOv.pUserDB2 = 0;
          break;
        }
        if ( !Deliver ( &oOv, oWire, &nFed ) ) { eOut = OUT_STARVED; break; }
        continue;
      }
      catch ( ... )
      {
        eOut = OUT_OTHER;
        if ( bStage4 ) oOv.pUserDB2 = 0;
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

// A frame must be refused, and the refusal must NAME the generation that
// arrived.  The second half is the whole point for the codes that were
// already refused as corruption: the outcome did not move, the diagnostic did.
static void MustRefuse ( const Wire &w, const char *szWhat, LPCTSTR lpszNames )
{
    int     nMsgs = 0;
    CString strWhy;
    int     eOut = Drive ( w, &nMsgs, &strWhy );

    if ( eOut == OUT_MSG || nMsgs != 0 )
    {
      Fail ( szWhat, "the frame was ACCEPTED and parsed into a message" );
      return;
    }
    if ( eOut != OUT_REFUSED )
    {
      Fail ( szWhat, "the frame was not refused - it starved or escaped, and a "
                     "clean refusal is the only outcome this case accepts" );
      return;
    }

    LPCTSTR lpszWhy = strWhy.GetString();
    if ( !ContainsT ( lpszWhy, _T("layout generation") ) )
    {
      PrintT ( "         diagnostic was: ", lpszWhy );
      Fail ( szWhat, "refused, but NOT by the generation gate - the message "
                     "does not name a layout generation" );
      return;
    }
    if ( lpszNames && !ContainsT ( lpszWhy, lpszNames ) )
    {
      PrintT ( "         diagnostic was: ", lpszWhy );
      Fail ( szWhat, "refused by the generation gate, but the message does not "
                     "say WHICH kind of image arrived" );
      return;
    }
    Ok ( szWhat );
}

int main ( int argc, char **argv )
{
    (void)argc; (void)argv;
    std::printf ( "=== p2p_imagegen - message image layout generation "
                  "(VERSIONING.md 6, gate 2) ===\n" );

    // ---- setup: a frame the library itself calls well formed -------------
    static Wire oBase;
    std::memset ( &oBase, 0, sizeof(oBase) );
    {
      static const wchar_t *kPayload = L"imagegen";
      P2Psize_t nBytes = (P2Psize_t)((wcslen(kPayload) + 1) * sizeof(wchar_t));

      P2PeerMsg32 oMsg ( kSrcAddr, kDstAddr, P2Pmsg_BCast, kPayload, nBytes );
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
    std::printf ( "base frame built by the library: %u bytes, sentinel 0x%02X\n",
                  oBase.n,
                  (unsigned)((RdU32(oBase.b) >> 24) & VBLock_SyncMask) );

    // ---- phase 0: the mechanism is what this build thinks it is ----------
    std::printf ( "\nphase 0 - the mechanism\n" );

    if ( VBLock_SyncForm ( RdU32(oBase.b) ) == VBLockSync_Native )
      Ok ( "the library stamps the current generation on what it sends" );
    else
      Fail ( "the library stamps the current generation on what it sends",
             "a frame the library just built does not classify as Native" );

    if ( (unsigned)VBLock_SyncGenNow == (unsigned)VBLock_SyncGen1 )
      Ok ( "generation 1 is still the generation this build writes" );
    else
      Fail ( "generation 1 is still the generation this build writes",
             "VBLock_SyncGenNow has moved, so every deployed peer is now a "
             "different generation - that is a wire break and VERSIONING.md 9 "
             "has to say so" );

    // ---- phase 1: THE POSITIVE CONTROL -----------------------------------
    std::printf ( "\nphase 1 - positive control\n" );
    {
      int     nMsgs = 0;
      CString strWhy;
      int     eOut = Drive ( oBase, &nMsgs, &strWhy );
      if ( eOut == OUT_MSG && nMsgs == 1 )
        Ok ( "a current-generation frame parses into exactly one message" );
      else
      {
        if ( !strWhy.IsEmpty() )
          PrintT ( "         diagnostic was: ", strWhy.GetString() );
        Fail ( "a current-generation frame parses into exactly one message",
               "the gate refuses everything, so every negative below is "
               "vacuous - fix this before reading any of them" );
      }
    }

    // ---- phase 2: the wire takes the current generation only -------------
    std::printf ( "\nphase 2 - the wire refuses every other generation\n" );
    {
      Wire w;

      // THE BREAK.  A pre-sentinel frame used to parse end to end.
      w = oBase; RestampGeneration ( w, 0 );
      MustRefuse ( w, "a PRE-SENTINEL frame is refused (this is the break)",
                   _T("pre-sentinel") );

      // NOT OURS, whatever it is.  There is no registry of reserved codes to
      // enumerate any more, so this case sweeps the space instead of naming
      // the one code somebody had thought to reserve: every non-zero pattern
      // that is not this build's is refused as a layout it does not implement,
      // with the arriving code in the text.  A registry bought this for
      // generation 2 and said nothing about generation 3; the six codes below
      // include four no registry ever listed.
      {
        static const UINT32 kCodes[] = { 0xA8, 0xAC, 0xB0, 0x04, 0xF8, 0xFC };
        for ( size_t i = 0; i < sizeof(kCodes)/sizeof(kCodes[0]); ++i )
        {
          char szWhat[128];
          std::snprintf ( szWhat, sizeof(szWhat),
                          "a generation-0x%02X frame is refused, by its code",
                          (unsigned)kCodes[i] );
          w = oBase; RestampGeneration ( w, kCodes[i] );
          MustRefuse ( w, szWhat, _T("does not implement") );
        }
      }

      // A foreign-endian peer, which the sentinel existed for in the first
      // place.  It reaches the wire gate now instead of the block walk.
      w = oBase;
      WrU32 ( w.b + 0, Bswap32 ( RdU32 ( w.b + 0 ) ) );
      WrU32 ( w.b + 4, Bswap32 ( RdU32 ( w.b + 4 ) ) );
      MustRefuse ( w, "a BYTE-SWAPPED frame is refused as an endianness mismatch",
                   _T("opposite endianness") );
    }

    // ---- phase 3: THE STORE ANSWERS DIFFERENTLY, ON PURPOSE --------------
    //  Without this phase, "refuse legacy everywhere" passes phase 2 and
    //  silently invalidates every stored pre-sentinel image.
    std::printf ( "\nphase 3 - the store still accepts a pre-sentinel image\n" );
    {
      static const char    *kPathA = "imagegen_legacy.iom";
      static const wchar_t *kPathW = L"imagegen_legacy.iom";

      Wire w = oBase;
      RestampGeneration ( w, 0 );

      FILE *f = std::fopen ( kPathA, "wb" );
      if ( !f )
        Fail ( "a pre-sentinel image on disk still loads",
               "could not write the fixture file" );
      else
      {
        std::fwrite ( w.b, 1, w.n, f );
        std::fclose ( f );

        BOOL    bLoaded = FALSE;
        CString strWhy;
        try
        {
          P2PmsgMgr oMgr;
          bLoaded = oMgr.Load ( kPathW );
        }
        catch ( P2Pevent *pEVT )
        {
          if ( pEVT ) { strWhy = pEVT->GetMessage(); pEVT->Cancel ( false ); }
          bLoaded = FALSE;
        }
        catch ( ... ) { bLoaded = FALSE; }

        if ( bLoaded )
          Ok ( "a pre-sentinel image on disk still loads (and warns)" );
        else
        {
          if ( !strWhy.IsEmpty() )
            PrintT ( "         diagnostic was: ", strWhy.GetString() );
          Fail ( "a pre-sentinel image on disk still loads",
                 "the STORE refused a legacy image.  The wire refusing one is "
                 "the decision; the store refusing one invalidates data "
                 "somebody already has - VERSIONING.md 6" );
        }
        std::remove ( kPathA );
      }
    }

    std::printf ( "\n=== p2p_imagegen: %d passed, %d failed ===\n",
                  g_nPass, g_nFail );
    return g_nFail ? 1 : 0;
}
