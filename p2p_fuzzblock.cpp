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
// p2p_fuzzblock.cpp - FUZZ HARNESS for the AUTHENTICATED WIRE PARSERS.
//                     ProductionPlan.md Stage 6 step 16.
//
// WHAT WAS MISSING. p2p_fuzzframe attacks the FRAMING path - the eight bytes
// of oSync and the block chain behind them - and it has done so since the
// C1-class finding. Nothing attacked the four parsers that were added after
// it: the login block, the ack, the relay attestation and the revocation list.
// Step 16 records what stood in for that, and it is worth stating plainly
// because it sounds like coverage and is not: "currently 60k mutated inputs
// per change, BY HAND". A number produced by hand, once, is a measurement of
// the day it was taken.
//
// These four are not a lesser target than the framing path. Three of them
// carry a SIGNATURE and a length that the parser must range-check before it
// indexes with it, and the relay block and the revocation list both have an
// ATTACKER-CHOSEN COUNT or LENGTH in the header that addresses fields behind
// it - the exact shape the framing finding had:
//
//     relay:  cbAddr = pIn[3]<<8 | pIn[4];  everything after the attester is
//             addressed as kOffRelayAddr + cbAddr + ...
//     revoke: nCount = pIn[11]<<8 | pIn[12]; the issuer key and the signature
//             are both at kOffRevEntries + nCount * 72 + ...
//
// Both are read from bytes a stranger sent. Both are bounds-checked in the
// shipping code (P2PAuthLogin.cpp), and this harness is what keeps them so.
//
// ---------------------------------------------------------------------------
// THE ORACLE, and it is stronger than the framing harness can have
//
// p2p_fuzzframe mostly asks "did it crash, hang or escape". It cannot ask much
// more, because a mutated frame legitimately has no expected outcome.
//
// These blocks are SIGNED, which gives this harness a real oracle:
//
//     ANY CHANGE TO A SIGNED BYTE MUST NOT VERIFY.
//
// So every mutant that comes back OK is a finding, unconditionally, with no
// judgement required - unless the mutation did not actually change a byte the
// parser reads. That exception is real and is handled rather than waved at:
// three of the four parsers accept TRAILING bytes (they test `cbIn <` a
// minimum, not `cbIn ==`), so a mutation past the significant length is a
// legitimate no-op. SignificantLen() below computes that boundary per target
// from the ORIGINAL block, and the oracle is applied only when the mutated
// bytes differ from the original WITHIN it. Getting that wrong in the other
// direction would be worse than not having the oracle: a fuzzer that cries
// wolf gets switched off.
//
// It also asserts the quieter half, which is where an information leak would
// live rather than a crash:
//
//     A REFUSAL MUST PUBLISH NOTHING. VerifyRelay's pAttesterOut must be an
//     empty string on every path that does not return AuthOk - otherwise a
//     caller that ignores the return value picks up an UNVERIFIED address that
//     the block merely claimed. The shipping code empties it first for exactly
//     this reason; this is what keeps it doing so.
//
// ---------------------------------------------------------------------------
// THE POSITIVE CONTROL, per target, and why it is not optional
//
// Every target verifies its UNMUTATED block first and requires AuthOk/RevOk.
// Without it a hub that had failed to load its keys would refuse everything,
// every mutant would be "correctly refused", and the run would go green having
// measured nothing at all. That is not a hypothetical failure mode for this
// file specifically: the provisioning below is five keys, three files and an
// allow-list, and any one of them silently not landing produces exactly that.
//
// ---------------------------------------------------------------------------
// STATE, and the one target that has some
//
// ApplyRevocationList is the only parser here that MUTATES the hub: on RevOk
// it advances an epoch high-water mark and writes revoked points to disk. That
// breaks a naive loop - apply the seed once and every later application of the
// same epoch is refused as STALE, which would mask a signature check that had
// stopped working behind a freshness check that had not.
//
// So the revocation target uses TWO receivers. The positive control runs
// against one, which is then finished with; every mutant runs against the
// other, which has applied nothing and whose epoch is still 0. A mutant that
// returns RevOk is therefore saying something about the SIGNATURE and not
// about the epoch.
//
// ---------------------------------------------------------------------------
// PERSISTENCE - the half of step 16 that is not about coverage
//
// Refer fuzz_corpus.h for the argument. In short: --corpus <dir> replays every
// file in a directory before anything is mutated, and ANY finding is written
// out as a content-addressed reproducer file, which is the step's exit
// criterion - "a new finding arrives as a REPRODUCER rather than as a report".
// The crash handler writes it too, from the global holding the current input,
// so an input that kills the process still leaves the bytes behind.
//
// ---------------------------------------------------------------------------
// DETERMINISM, on the same terms as p2p_fuzzframe
//
//   * the seed is a constant or argv[1] - never the clock
//   * it is printed on every run, pass or fail
//   * each iteration's RNG comes from splitmix64 over (seed, target, iter)
//     alone, so iterations are independent and any one replays exactly:
//         p2p_fuzzblock <seed> --replay <target> <iter>
//   * the RNG is written out here rather than taken from <random>, whose
//     distributions are implementation-defined and would not agree between
//     MSVC and libstdc++
//
// USAGE
//   p2p_fuzzblock [seed] [itersPerTarget]
//                 [--replay <target> <iter>] [--corpus <dir>]
//                 [--repro-dir <dir>] [--seconds <n>] [--verbose]
//
//   --seconds <n>   run mutation rounds until n seconds have elapsed, looping
//                   over the iteration space. This is the CONTINUOUS mode; the
//                   registered ctest run does not use it and stays short.
//
//   Verdict = process EXIT CODE:
//     0  PASS   every positive control verified, and no mutant did
//     1  FAIL   see the FINDING lines; reproducers are in the repro directory
//     2  SETUP  key/list provisioning failed (test inconclusive)
//

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "Msgexception.h"
#include "P2PIdentityStore.h"
#include "P2PAuthLogin.h"

#include "fuzz_corpus.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <string>
#include <vector>

#ifdef _WIN32
#  include <crtdbg.h>
#else
#  include <csignal>
#  include <unistd.h>
#  include <pthread.h>
#endif

// ===========================================================================
//  Fixed parameters
// ===========================================================================
static const unsigned kDefaultSeed  = 0x51CEB00Du;
static const int      kDefaultIters = 400;      // per target; 4 targets

// The largest block any of these parsers accepts is the revocation list, at
// kRevFixedLen + 4096 * 72. The buffer is sized past that so an OVERSIZED
// input - the one that has to be refused rather than parsed - can be built.
static const unsigned kMaxBlock = 131072u;

// Seconds one input may spend inside a parser before it is called a hang.
// These parsers do bounded work on a bounded buffer, so this is not a budget,
// it is a claim: nothing here should take a tenth of it.
static const unsigned kHangSeconds = 10;

static const wchar_t *kAttester = L"Fuzz.Attester";
static const wchar_t *kSrcAddr  = L"Fuzz.Attester.Widget";
static const wchar_t *kDstAddr  = L"Fuzz.Receiver";
static const wchar_t *kMsgName  = L"FuzzProbe";

// ===========================================================================
//  Targets
// ===========================================================================
enum
{
    TGT_LOGIN = 0,
    TGT_ACK,
    TGT_RELAY,
    TGT_REVOKE,
    TGT__COUNT
};

static const char *kTargetName[TGT__COUNT] =
    { "login", "ack", "relay", "revoke" };

// ===========================================================================
//  Small utilities
// ===========================================================================
static void Log ( const char *msg )
{
    std::printf ( "[fuzzblock] %s\n", msg );
    std::fflush ( stdout );
}

struct Block
{
    unsigned char b[kMaxBlock];
    unsigned      n;
};

struct Rng
{
    unsigned long long s;
    void Seed ( unsigned long long x ) { s = x ? x : 0x9E3779B97F4A7C15ull; }
    unsigned long long Next ( )
    {
        s ^= s >> 12; s ^= s << 25; s ^= s >> 27;
        return s * 2685821657736338717ull;
    }
    unsigned U32 ( )             { return (unsigned)( Next ( ) >> 32 ); }
    unsigned Below ( unsigned n ){ return n ? ( U32 ( ) % n ) : 0u; }
};

static unsigned long long SplitMix ( unsigned long long x )
{
    x += 0x9E3779B97F4A7C15ull;
    x  = ( x ^ ( x >> 30 ) ) * 0xBF58476D1CE4E5B9ull;
    x  = ( x ^ ( x >> 27 ) ) * 0x94D049BB133111EBull;
    return x ^ ( x >> 31 );
}

// (seed, target, iteration) -> state. Iterations are INDEPENDENT: replaying
// one does not require replaying the ones before it.
static unsigned long long IterState ( unsigned nSeed, int nTgt, int nIter )
{
    return SplitMix ( ( (unsigned long long)nSeed << 32 )
                    ^ ( (unsigned long long)(unsigned)nTgt  * 0x100000001B3ull )
                    ^ ( (unsigned long long)(unsigned)( nIter + 1 ) * 0x9E3779B1ull ) );
}

// ===========================================================================
//  The cursor - what input is being processed RIGHT NOW.
//  Global because the crash handler and the watchdog both need it, and both
//  run when the stack that would otherwise carry it is not available.
// ===========================================================================
static int           g_nCurTgt   = -1;
static int           g_nCurIter  = -1;
static unsigned      g_nSeed     = kDefaultSeed;
static const char   *g_pszCurSrc = "(none)";   // corpus path, when replaying one
static Block         g_oCurInput;
static char          g_szReproDir[512] = { 0 };
static bool          g_bVerbose  = false;
static int           g_nFindings = 0;
static long          g_nProgress = 0;          // bumped once per input

static void DumpCursor ( std::FILE *fp )
{
    std::fprintf ( fp, "[fuzzblock] at: target=%s iter=%d seed=0x%08X source=%s\n",
                   ( g_nCurTgt >= 0 && g_nCurTgt < TGT__COUNT )
                       ? kTargetName[g_nCurTgt] : "(none)",
                   g_nCurIter, g_nSeed, g_pszCurSrc );
    std::fprintf ( fp, "[fuzzblock] replay: p2p_fuzzblock 0x%08X --replay %d %d\n",
                   g_nSeed, g_nCurTgt, g_nCurIter );
    std::fflush ( fp );
}

//  Write the current input out as a reproducer and say where it went.
//  Called from the finding path AND from the crash handler, which is the
//  whole reason the input lives in a global: an input that kills the process
//  must still leave its bytes behind, or the finding is a report again.
static void EmitRepro ( const char *pszWhy )
{
    if ( !g_szReproDir[0] || g_oCurInput.n == 0 ) return;
    char szTag[64];
    std::snprintf ( szTag, sizeof(szTag), "%s-%s",
                    ( g_nCurTgt >= 0 && g_nCurTgt < TGT__COUNT )
                        ? kTargetName[g_nCurTgt] : "unknown",
                    pszWhy );
    char szPath[1024];
    if ( FuzzWriteRepro ( g_szReproDir, szTag, g_oCurInput.b, g_oCurInput.n,
                          szPath, sizeof(szPath) ) )
    {
        std::fflush ( stdout );
        std::fprintf ( stderr, "[fuzzblock] REPRODUCER: %s (%u bytes)\n",
                       szPath, g_oCurInput.n );
        std::fprintf ( stderr, "[fuzzblock] replay it with: "
                               "p2p_fuzzblock --corpus <dir containing it>\n" );
        std::fprintf ( stderr, "[fuzzblock] promote it with: copy it into "
                               "MscsUnitTests/fuzz/corpus/ and commit\n" );
        std::fflush ( stderr );
    }
    else
        std::fprintf ( stderr, "[fuzzblock] could NOT write a reproducer into '%s'"
                               " - the finding above is a report, not a repro\n",
                       g_szReproDir );
}

static void Finding ( const char *pszWhat, const char *pszWhy )
{
    ++g_nFindings;
    std::fflush ( stdout );
    std::printf ( "\n  *** FINDING: %s ***\n", pszWhat );
    DumpCursor ( stdout );
    EmitRepro ( pszWhy );
}

// ===========================================================================
//  Crash, assert and hang handling
// ===========================================================================
#ifdef _WIN32
static int g_nAsserts = 0;

//  Count a debug ASSERT and CONTINUE. Without the hook one assert pops a modal
//  dialog on a headless ctest run and the test "hangs" rather than failing -
//  the failure mode session 22 spent itself on.
static int __cdecl AssertReportHook ( int nReportType, char *szMsg, int *pnRet )
{
    if ( nReportType == _CRT_ASSERT )
    {
        ++g_nAsserts;
        std::fflush ( stdout );
        std::fprintf ( stderr, "[fuzzblock] ASSERT: %s", szMsg ? szMsg : "(no message)" );
        DumpCursor ( stderr );
        if ( pnRet ) *pnRet = 0;
        return TRUE;
    }
    return FALSE;
}

static LONG WINAPI CrashFilter ( EXCEPTION_POINTERS *pEP )
{
    std::fflush ( stdout );
    std::fprintf ( stderr,
        "\n[fuzzblock] *** CRASH: unhandled exception 0x%08X at %p ***\n",
        (unsigned)pEP->ExceptionRecord->ExceptionCode,
        (void *)pEP->ExceptionRecord->ExceptionAddress );
    DumpCursor ( stderr );
    EmitRepro ( "crash" );
    std::fprintf ( stderr, "RESULT: FAIL - a block parser crashed on the input above.\n" );
    std::fflush ( stderr );
    return EXCEPTION_EXECUTE_HANDLER;
}

static DWORD WINAPI WatchdogThread ( LPVOID )
{
    long nLast = -1;
    unsigned nStill = 0;
    for ( ;; )
    {
        Sleep ( 1000 );
        const long nNow = InterlockedExchangeAdd ( &g_nProgress, 0 );
        if ( nNow != nLast ) { nLast = nNow; nStill = 0; continue; }
        if ( ++nStill < kHangSeconds ) continue;

        std::fflush ( stdout );
        std::fprintf ( stderr,
            "\n[fuzzblock] *** HANG: no progress for %u seconds ***\n", kHangSeconds );
        DumpCursor ( stderr );
        EmitRepro ( "hang" );
        std::fprintf ( stderr, "RESULT: FAIL - a block parser did not return.\n" );
        std::fflush ( stderr );
        TerminateProcess ( GetCurrentProcess ( ), 1 );
    }
}
#else
static void CrashSignal ( int nSig )
{
    std::fflush ( stdout );
    std::fprintf ( stderr, "\n[fuzzblock] *** CRASH: signal %d ***\n", nSig );
    DumpCursor ( stderr );
    EmitRepro ( "crash" );
    std::fprintf ( stderr, "RESULT: FAIL - a block parser crashed on the input above.\n" );
    std::fflush ( stderr );
    _exit ( 1 );
}

static void *WatchdogThread ( void * )
{
    long nLast = -1;
    unsigned nStill = 0;
    for ( ;; )
    {
        ::sleep ( 1 );
        const long nNow = __sync_fetch_and_add ( &g_nProgress, 0 );
        if ( nNow != nLast ) { nLast = nNow; nStill = 0; continue; }
        if ( ++nStill < kHangSeconds ) continue;

        std::fflush ( stdout );
        std::fprintf ( stderr,
            "\n[fuzzblock] *** HANG: no progress for %u seconds ***\n", kHangSeconds );
        DumpCursor ( stderr );
        EmitRepro ( "hang" );
        std::fprintf ( stderr, "RESULT: FAIL - a block parser did not return.\n" );
        std::fflush ( stderr );
        _exit ( 1 );
    }
    return 0;
}
#endif

static void BumpProgress ( )
{
#ifdef _WIN32
    InterlockedIncrement ( &g_nProgress );
#else
    __sync_fetch_and_add ( &g_nProgress, 1 );
#endif
}

// ===========================================================================
//  Provisioning
// ===========================================================================
static std::vector<std::string> g_vTempFiles;

static std::string TempPath ( const char *pszLeaf )
{
    char szDir[MAX_PATH + 2] = { 0 };
    DWORD n = GetTempPathA ( MAX_PATH + 1, szDir );
    std::string s = ( n > 0 && n <= MAX_PATH ) ? std::string ( szDir )
                                               : std::string ( "./" );
    char szPid[32];
    std::snprintf ( szPid, sizeof(szPid), "%lu",
                    (unsigned long)GetCurrentProcessId ( ) );
    s += "p2p_fuzzblock_"; s += pszLeaf; s += "_"; s += szPid; s += ".tmp";
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

static bool WriteEmptyRevocationList ( const std::string &sPath )
{
    std::FILE *fp = std::fopen ( sPath.c_str ( ), "wb" );
    if ( !fp ) return false;
    std::fputs ( "# TargetCore revocation list - nothing revoked yet\n", fp );
    std::fclose ( fp );
    return true;
}

//  A hub with a policy and no pump. Nothing here spawns: AttestRelay,
//  VerifyRelay, AuthBuildLogin, AuthVerifyLogin, IssueRevocationList and
//  ApplyRevocationList all take only m_oCSectionHub, which the constructor
//  initialises - so a fuzz round costs a function call and not a thread.
class BlockHub : public P2PeerHub
{
public:
    BlockHub ( P2PaddrSTR strAddr ) : P2PeerHub ( strAddr ) { }
    virtual ~BlockHub ( ) { }
};

// ===========================================================================
//  The significant length - the boundary the oracle is allowed to speak about
//
//  Three of these four parsers test `cbIn <` a minimum rather than `cbIn ==`,
//  so bytes past the block proper are IGNORED by design and a mutation landing
//  there legitimately changes nothing. The revocation list is the exception:
//  it requires an exact length, so every byte of it is significant.
//
//  Read from the ORIGINAL block, never the mutant: the mutant's own length
//  field is attacker-controlled, and asking it how much of itself matters is
//  how an oracle gets talked out of firing.
// ===========================================================================
static unsigned SignificantLen ( int nTgt, const Block &oOrig )
{
    switch ( nTgt )
    {
    case TGT_LOGIN:  return (unsigned)p2pauth::kAuthLoginLen;
    case TGT_ACK:    return (unsigned)p2pauth::kAuthAckLen;
    case TGT_RELAY:
        {
            if ( oOrig.n < p2pauth::kRelayFixedLen ) return oOrig.n;
            const unsigned cbAddr = ( (unsigned)oOrig.b[3] << 8 ) | oOrig.b[4];
            const unsigned nLen   = (unsigned)p2pauth::kRelayFixedLen + cbAddr;
            return nLen < oOrig.n ? nLen : oOrig.n;
        }
    case TGT_REVOKE: return oOrig.n;          // exact-length parser
    }
    return oOrig.n;
}

//  Did the mutation touch anything the parser reads?
static bool DiffersWithin ( const Block &a, const Block &b, unsigned nSig )
{
    const unsigned nA = a.n < nSig ? a.n : nSig;
    const unsigned nB = b.n < nSig ? b.n : nSig;
    if ( nA != nB ) return true;
    return std::memcmp ( a.b, b.b, nA ) != 0;
}

// ===========================================================================
//  The mutator
// ===========================================================================
static const unsigned char kInteresting8[] =
    { 0x00, 0x01, 0x02, 0x7F, 0x80, 0xFE, 0xFF, 'P', 'A', 'R', 'V' };

//  Big-endian, because every length and count in these blocks is. The framing
//  harness's table is little-endian for the same reason in reverse; a table
//  written in the wrong byte order is a fuzzer that never reaches the branch
//  it was aimed at.
static const unsigned short kInterestingBE16[] =
    { 0u, 1u, 2u, 255u, 256u, 4095u, 4096u, 4097u, 0x7FFFu, 0x8000u, 0xFFFFu };

static void PutBE16 ( unsigned char *p, unsigned short v )
{
    p[0] = (unsigned char)( v >> 8 ); p[1] = (unsigned char)( v & 0xFF );
}

static void Mutate ( Block *pB, Rng &oRng )
{
    unsigned nOps = 1 + oRng.Below ( 4 );
    for ( unsigned i = 0; i < nOps && pB->n > 0; ++i )
    {
        //  Biased at the HEAD, where every length, count, magic and version
        //  lives. For all four blocks that is the first 16 bytes; the rest is
        //  a key, a signature or an entry array, and a bit flipped there only
        //  ever produces a signature that does not verify.
        const unsigned nSpan = ( pB->n < 16u ) ? pB->n : 16u;
        const unsigned off   = ( oRng.Below ( 10 ) < 7 ) ? oRng.Below ( nSpan )
                                                         : oRng.Below ( pB->n );

        switch ( oRng.Below ( 6 ) )
        {
        case 0:                                        // bit flip
            pB->b[off] ^= (unsigned char)( 1u << oRng.Below ( 8 ) );
            break;
        case 1:                                        // interesting byte
            pB->b[off] = kInteresting8[oRng.Below ( (unsigned)
                             ( sizeof(kInteresting8)/sizeof(kInteresting8[0]) ) )];
            break;
        case 2:                                        // interesting BE u16
            if ( off + 2 <= pB->n )
                PutBE16 ( pB->b + off,
                          kInterestingBE16[oRng.Below ( (unsigned)
                              ( sizeof(kInterestingBE16)/sizeof(kInterestingBE16[0]) ) )] );
            break;
        case 3:                                        // truncate
            pB->n = 1 + oRng.Below ( pB->n );
            break;
        case 4:                                        // EXTEND with junk
            //  Trailing bytes are the one thing three of these parsers are
            //  documented to ignore, so growing the buffer is how that
            //  documentation gets tested rather than believed. It is also how
            //  a length field that was raised by another op gets something to
            //  address.
            {
                const unsigned nAdd = 1 + oRng.Below ( 64 );
                if ( pB->n + nAdd <= kMaxBlock )
                {
                    for ( unsigned k = 0; k < nAdd; ++k )
                        pB->b[pB->n + k] = (unsigned char)oRng.Below ( 256 );
                    pB->n += nAdd;
                }
            }
            break;
        case 5:                                        // splice a run over itself
            {
                const unsigned nRun = 1 + oRng.Below ( pB->n - off );
                const unsigned src  = oRng.Below ( pB->n - nRun + 1 );
                std::memmove ( pB->b + off, pB->b + src,
                               ( off + nRun <= pB->n ) ? nRun : ( pB->n - off ) );
            }
            break;
        }
    }
}

// ===========================================================================
//  The targets
// ===========================================================================
struct Rig
{
    BlockHub *pClient;      // holds the identity that SIGNS the login
    BlockHub *pServer;      // holds the allow-list that VERIFIES it
    BlockHub *pAttester;    // signs relay attestations
    BlockHub *pReceiver;    // verifies them; also the revocation control
    BlockHub *pRevMutant;   // revocation receiver for MUTANTS only - epoch 0
    BlockHub *pAuthority;   // issues revocation lists

    unsigned char aNonce[p2pauth::kAuthNonceLen];
};

static Rig  g_oRig;
static Block g_aSeed[TGT__COUNT];

//  The message body a relay attestation is taken over. Fixed, because the body
//  is not what is being fuzzed here - the BLOCK is - and a body that varied
//  would make a verification failure ambiguous between the two.
static const char kBody[] = "p2p_fuzzblock attested body, fixed on purpose";

// Run one input against one parser. Returns true if the parser ACCEPTED it.
static bool RunTarget ( int nTgt, const unsigned char *p, unsigned n,
                        bool bMutant, char *pszDetail, unsigned cchDetail )
{
    if ( pszDetail && cchDetail ) pszDetail[0] = 0;

    switch ( nTgt )
    {
    case TGT_LOGIN:
        {
            unsigned char aNonce[p2pauth::kAuthNonceLen];
            long nSkew = 0;
            std::memset ( aNonce, 0, sizeof(aNonce) );
            const p2pauth::AuthResult e =
                g_oRig.pServer->AuthVerifyLogin ( kAttester, kDstAddr, p, n,
                                                  aNonce, &nSkew );
            if ( pszDetail )
                std::snprintf ( pszDetail, cchDetail, "%s", p2pauth::AuthResultText ( e ) );
            return e == p2pauth::AuthOk;
        }

    case TGT_ACK:
        {
            const p2pauth::AuthResult e =
                g_oRig.pClient->AuthVerifyAck ( kDstAddr, kAttester,
                                                g_oRig.aNonce, p, n );
            if ( pszDetail )
                std::snprintf ( pszDetail, cchDetail, "%s", p2pauth::AuthResultText ( e ) );
            return e == p2pauth::AuthOk;
        }

    case TGT_RELAY:
        {
            //  Pre-poisoned, so "left untouched" and "written empty" are
            //  distinguishable. The contract is that a refusal leaves an EMPTY
            //  string; a parser that simply never wrote would pass a check
            //  against a buffer that started empty.
            wchar_t wszAtt[p2pauth::kRelayAttesterMax + 2];
            for ( size_t k = 0; k < sizeof(wszAtt)/sizeof(wszAtt[0]); ++k )
                wszAtt[k] = L'#';
            wszAtt[sizeof(wszAtt)/sizeof(wszAtt[0]) - 1] = 0;

            long nSkew = 0;
            const p2pauth::AuthResult e =
                g_oRig.pReceiver->VerifyRelay ( kSrcAddr, kDstAddr, kMsgName,
                                                kBody, sizeof(kBody) - 1,
                                                p, n,
                                                wszAtt,
                                                sizeof(wszAtt)/sizeof(wszAtt[0]),
                                                &nSkew );
            if ( pszDetail )
                std::snprintf ( pszDetail, cchDetail, "%s", p2pauth::AuthResultText ( e ) );

            //  THE QUIET HALF OF THE ORACLE. A refusal must publish nothing:
            //  the attester name on the wire is a CLAIM until the signature
            //  over it verifies, and a caller that ignores the return value
            //  must not be able to pick it up.
            if ( e != p2pauth::AuthOk && wszAtt[0] != 0 )
                Finding ( "VerifyRelay REFUSED but still published an attester name",
                          "leak" );
            return e == p2pauth::AuthOk;
        }

    case TGT_REVOKE:
        {
            //  Mutants go to the receiver that has applied NOTHING, so its
            //  epoch is still 0 and a refusal here cannot be the freshness
            //  check standing in for the signature check. Refer the header.
            BlockHub *pTo = bMutant ? g_oRig.pRevMutant : g_oRig.pReceiver;
            size_t nAdded = 0;
            const p2pauth::RevResult e = pTo->ApplyRevocationList ( p, n, &nAdded );
            if ( pszDetail )
                std::snprintf ( pszDetail, cchDetail, "%s (+%u)",
                                p2pauth::RevResultText ( e ), (unsigned)nAdded );
            return e == p2pauth::RevOk;
        }
    }
    return false;
}

// ===========================================================================
//  One mutated round
// ===========================================================================
static void RunMutant ( int nTgt, int nIter )
{
    g_nCurTgt   = nTgt;
    g_nCurIter  = nIter;
    g_pszCurSrc = "(mutated)";

    Rng oRng; oRng.Seed ( IterState ( g_nSeed, nTgt, nIter ) );

    g_oCurInput = g_aSeed[nTgt];
    Mutate ( &g_oCurInput, oRng );

    const unsigned nSig = SignificantLen ( nTgt, g_aSeed[nTgt] );
    const bool bChanged = DiffersWithin ( g_oCurInput, g_aSeed[nTgt], nSig );

    BumpProgress ( );

    char szDetail[128];
    bool bAccepted = false;
    try
    {
        bAccepted = RunTarget ( nTgt, g_oCurInput.b, g_oCurInput.n, true,
                                szDetail, sizeof(szDetail) );
    }
    catch ( P2Pevent *pEVT )
    {
        //  These parsers return codes; they do not throw. One that does has
        //  changed its contract underneath every caller in the tree, and
        //  P2PeerCon's gates do not catch here.
        pEVT->Cancel ( );
        Finding ( "a block parser raised a P2Pevent instead of returning a code",
                  "throw" );
        return;
    }
    catch ( ... )
    {
        Finding ( "a block parser let a non-P2Pevent exception escape", "escape" );
        return;
    }

    if ( g_bVerbose )
        std::printf ( "[fuzzblock] %-7s iter %5d  %4u bytes  %s%s\n",
                      kTargetName[nTgt], nIter, g_oCurInput.n, szDetail,
                      bChanged ? "" : "  (no significant change)" );

    //  THE ORACLE. A signed block that was altered where the parser looks must
    //  not verify. There is no judgement in this and no tolerance: forging one
    //  is the whole thing these signatures exist to prevent.
    if ( bAccepted && bChanged )
        Finding ( "a MUTATED signed block VERIFIED - a forgery was accepted",
                  "forged" );
}

// ===========================================================================
//  Corpus replay
// ===========================================================================
struct CorpusCtx { int nTgt; int nRun; };

static void CorpusOne ( const char *pszPath, const unsigned char *p, unsigned n,
                        void *pvUser )
{
    CorpusCtx *pCtx = (CorpusCtx *)pvUser;

    //  Every corpus file is offered to EVERY parser, and that is deliberate
    //  rather than lazy. A corpus entry saved from one target is exactly the
    //  kind of input that finds a type-confusion in another - the three magics
    //  exist because "these can never meet" is the assumption every such bug
    //  is written against (P2PAuthLogin.cpp), and the cheapest way to keep
    //  testing that assumption is to make them meet.
    for ( int t = 0; t < TGT__COUNT; ++t )
    {
        g_nCurTgt   = t;
        g_nCurIter  = -1;
        g_pszCurSrc = pszPath;

        g_oCurInput.n = n < kMaxBlock ? n : kMaxBlock;
        std::memcpy ( g_oCurInput.b, p, g_oCurInput.n );

        BumpProgress ( );

        char szDetail[128];
        bool bAccepted = false;
        try
        {
            bAccepted = RunTarget ( t, g_oCurInput.b, g_oCurInput.n, true,
                                    szDetail, sizeof(szDetail) );
        }
        catch ( P2Pevent *pEVT )
        {
            pEVT->Cancel ( );
            Finding ( "a corpus input made a block parser raise a P2Pevent", "throw" );
            continue;
        }
        catch ( ... )
        {
            Finding ( "a corpus input made a block parser throw", "escape" );
            continue;
        }

        const unsigned nSig = SignificantLen ( t, g_aSeed[t] );
        if ( bAccepted && DiffersWithin ( g_oCurInput, g_aSeed[t], nSig ) )
            Finding ( "a corpus input VERIFIED against a signature it should not have",
                      "forged" );

        if ( g_bVerbose )
            std::printf ( "[fuzzblock] corpus %-7s %s -> %s\n",
                          kTargetName[t], pszPath, szDetail );
    }
    ++pCtx->nRun;
}

// ===========================================================================
//  Seed construction - the POSITIVE CONTROLS
// ===========================================================================
static bool BuildSeeds ( )
{
    for ( int t = 0; t < TGT__COUNT; ++t ) g_aSeed[t].n = 0;

    // ---- login ------------------------------------------------------------
    {
        Block &w = g_aSeed[TGT_LOGIN];
        w.n = (unsigned)p2pauth::kAuthLoginLen;
        if ( g_oRig.pClient->AuthBuildLogin ( kAttester, kDstAddr,
                                              w.b, w.n, g_oRig.aNonce )
             != p2pauth::AuthOk )
        { Log ( "SETUP: AuthBuildLogin failed" ); return false; }
    }

    // ---- ack --------------------------------------------------------------
    {
        Block &w = g_aSeed[TGT_ACK];
        w.n = (unsigned)p2pauth::kAuthAckLen;
        if ( g_oRig.pServer->AuthBuildAck ( kDstAddr, kAttester,
                                            g_oRig.aNonce, w.b, w.n )
             != p2pauth::AuthOk )
        { Log ( "SETUP: AuthBuildAck failed" ); return false; }
    }

    // ---- relay ------------------------------------------------------------
    {
        Block &w = g_aSeed[TGT_RELAY];
        size_t cb = 0;
        if ( g_oRig.pAttester->AttestRelay ( kAttester, kSrcAddr, kDstAddr, kMsgName,
                                             kBody, sizeof(kBody) - 1,
                                             w.b, (size_t)p2pauth::kRelayMaxLen, &cb )
             != p2pauth::AuthOk )
        { Log ( "SETUP: AttestRelay failed" ); return false; }
        w.n = (unsigned)cb;
    }

    // ---- revocation list --------------------------------------------------
    {
        Block &w = g_aSeed[TGT_REVOKE];
        size_t cb = 0;
        if ( g_oRig.pAuthority->IssueRevocationList ( 7, w.b, kMaxBlock, &cb )
             != p2pauth::RevOk )
        { Log ( "SETUP: IssueRevocationList failed" ); return false; }
        w.n = (unsigned)cb;
    }

    return true;
}

// ===========================================================================
int main ( int argc, char **argv )
{
    unsigned nSeed      = kDefaultSeed;
    int      nIters     = kDefaultIters;
    int      nReplayTgt = -1, nReplayIter = -1;
    int      nSeconds   = 0;
    const char *pszCorpus = 0;
    const char *pszRepro  = "fuzz-repro";

    for ( int i = 1; i < argc; ++i )
    {
        if ( std::strcmp ( argv[i], "--replay" ) == 0 && i + 2 < argc )
        { nReplayTgt = std::atoi ( argv[i+1] ); nReplayIter = std::atoi ( argv[i+2] ); i += 2; }
        else if ( std::strcmp ( argv[i], "--corpus" ) == 0 && i + 1 < argc )
        { pszCorpus = argv[++i]; }
        else if ( std::strcmp ( argv[i], "--repro-dir" ) == 0 && i + 1 < argc )
        { pszRepro = argv[++i]; }
        else if ( std::strcmp ( argv[i], "--seconds" ) == 0 && i + 1 < argc )
        { nSeconds = std::atoi ( argv[++i] ); }
        else if ( std::strcmp ( argv[i], "--verbose" ) == 0 )
        { g_bVerbose = true; }
        else if ( argv[i][0] != '-' )
        {
            //  Positional: seed then iterations, as p2p_fuzzframe takes them.
            static int s_nPos = 0;
            if ( s_nPos == 0 ) nSeed  = (unsigned)std::strtoul ( argv[i], 0, 0 );
            else               nIters = std::atoi ( argv[i] );
            ++s_nPos;
        }
    }
    g_nSeed = nSeed;
#ifdef _WIN32
    strncpy_s ( g_szReproDir, sizeof(g_szReproDir), pszRepro, _TRUNCATE );
#else
    std::strncpy ( g_szReproDir, pszRepro, sizeof(g_szReproDir) - 1 );
#endif

    std::printf ( "=== p2p_fuzzblock - the AUTHENTICATED wire parsers ===\n" );
    std::printf ( "Seed : 0x%08X   iters/target: %d   targets: %d\n",
                  nSeed, nIters, TGT__COUNT );
    std::printf ( "Repro: %s%s%s\n", g_szReproDir,
                  pszCorpus ? "   corpus: " : "", pszCorpus ? pszCorpus : "" );
    std::printf ( "Asserting: a signed block that was ALTERED where the parser\n"
                  "           looks must never verify, and a refusal must\n"
                  "           publish nothing.  ProductionPlan.md step 16.\n\n" );
    std::fflush ( stdout );

#ifdef _WIN32
    _CrtSetReportHook ( AssertReportHook );
    _CrtSetReportMode ( _CRT_ASSERT, _CRTDBG_MODE_DEBUG );
    SetUnhandledExceptionFilter ( CrashFilter );
    CreateThread ( 0, 0, WatchdogThread, 0, 0, 0 );
#else
    std::signal ( SIGSEGV, CrashSignal );
    std::signal ( SIGBUS,  CrashSignal );
    std::signal ( SIGILL,  CrashSignal );
    std::signal ( SIGFPE,  CrashSignal );
    std::signal ( SIGABRT, CrashSignal );
    { pthread_t th; pthread_create ( &th, 0, WatchdogThread, 0 ); pthread_detach ( th ); }
#endif

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }

    int nExit = 2;
    {
        // ---- Provisioning -------------------------------------------------
        const std::string sCliKey  = TempPath ( "clikey"  );
        const std::string sSrvKey  = TempPath ( "srvkey"  );
        const std::string sAttKey  = TempPath ( "attkey"  );
        const std::string sAuthKey = TempPath ( "authkey" );
        const std::string sSrvAcl  = TempPath ( "srvacl"  );
        const std::string sCliAcl  = TempPath ( "cliacl"  );
        const std::string sRcvAcl  = TempPath ( "rcvacl"  );
        const std::string sAuthRev = TempPath ( "authrev" );
        const std::string sRcvRev  = TempPath ( "rcvrev"  );
        const std::string sMutRev  = TempPath ( "mutrev"  );

        unsigned char pubCli[p2pcng::kEcdsaPubLen];
        unsigned char pubSrv[p2pcng::kEcdsaPubLen];
        unsigned char pubAtt[p2pcng::kEcdsaPubLen];
        unsigned char pubAuth[p2pcng::kEcdsaPubLen];
        if ( !MakeIdentity ( sCliKey,  pubCli  ) ||
             !MakeIdentity ( sSrvKey,  pubSrv  ) ||
             !MakeIdentity ( sAttKey,  pubAtt  ) ||
             !MakeIdentity ( sAuthKey, pubAuth ) )
        { Log ( "SETUP: identity generation failed" ); ScrubTempFiles ( ); return 2; }

        //  The login is signed by the CLIENT as kAttester and verified by the
        //  server, so the server's allow-list carries the client's key under
        //  that name. The relay attestation is signed by a DIFFERENT hub under
        //  the same name, so the receiver's list carries the attester's key.
        //  Two hubs, one name, different keys - which is also why the two
        //  allow-lists are separate files rather than one shared one.
        if ( p2pcng::AppendAllowList ( sSrvAcl.c_str ( ), "Fuzz.Attester", pubCli ) != p2pcng::IdOk ||
             p2pcng::AppendAllowList ( sCliAcl.c_str ( ), "Fuzz.Receiver", pubSrv ) != p2pcng::IdOk ||
             p2pcng::AppendAllowList ( sRcvAcl.c_str ( ), "Fuzz.Attester", pubAtt ) != p2pcng::IdOk )
        { Log ( "SETUP: allow-list provisioning failed" ); ScrubTempFiles ( ); return 2; }

        if ( !WriteEmptyRevocationList ( sAuthRev ) ||
             !WriteEmptyRevocationList ( sRcvRev  ) ||
             !WriteEmptyRevocationList ( sMutRev  ) )
        { Log ( "SETUP: revocation file creation failed" ); ScrubTempFiles ( ); return 2; }

        //  Something to revoke, so the issued list is not empty. An empty list
        //  still signs and still verifies, but its entry array is zero bytes -
        //  and the entry array is where nCount points, which is the field this
        //  harness most wants to move.
        unsigned char pubDoomed[p2pcng::kEcdsaPubLen];
        {
            p2pcng::EcdsaP256 oDoomed;
            if ( !oDoomed.Generate ( ) || !oDoomed.ExportPublic ( pubDoomed ) )
            { Log ( "SETUP: victim key generation failed" ); ScrubTempFiles ( ); return 2; }
        }
        if ( p2pcng::AppendRevocationList ( sAuthRev.c_str ( ), pubDoomed, 0,
                                            "a victim, per p2p_fuzzblock" )
             != p2pcng::IdOk )
        { Log ( "SETUP: revocation provisioning failed" ); ScrubTempFiles ( ); return 2; }

        BlockHub oClient   ( L"Fuzz.Attester" );
        BlockHub oServer   ( L"Fuzz.Receiver" );
        BlockHub oAttester ( L"Fuzz.Attester" );
        BlockHub oReceiver ( L"Fuzz.Receiver" );
        BlockHub oRevMut   ( L"Fuzz.RevMutant" );
        BlockHub oAuthority( L"Fuzz.Authority" );

        g_oRig.pClient    = &oClient;
        g_oRig.pServer    = &oServer;
        g_oRig.pAttester  = &oAttester;
        g_oRig.pReceiver  = &oReceiver;
        g_oRig.pRevMutant = &oRevMut;
        g_oRig.pAuthority = &oAuthority;

        if ( oClient  .SetIdentity  ( sCliKey.c_str ( ) ) != p2pcng::IdOk ||
             oClient  .SetAllowList ( sCliAcl.c_str ( ) ) != p2pcng::IdOk ||
             oServer  .SetIdentity  ( sSrvKey.c_str ( ) ) != p2pcng::IdOk ||
             oServer  .SetAllowList ( sSrvAcl.c_str ( ) ) != p2pcng::IdOk ||
             oAttester.SetIdentity  ( sAttKey.c_str ( ) ) != p2pcng::IdOk ||
             oReceiver.SetAllowList ( sRcvAcl.c_str ( ) ) != p2pcng::IdOk )
        { Log ( "SETUP: hub auth configuration failed" ); ScrubTempFiles ( ); return 2; }

        if ( oAuthority.SetIdentity       ( sAuthKey.c_str ( ) ) != p2pcng::IdOk ||
             oAuthority.SetRevocationList ( sAuthRev.c_str ( ) ) != p2pcng::IdOk ||
             oReceiver .SetRevocationList ( sRcvRev .c_str ( ) ) != p2pcng::IdOk ||
             oRevMut   .SetRevocationList ( sMutRev .c_str ( ) ) != p2pcng::IdOk ||
             oReceiver .SetRevocationAuthority ( pubAuth ) != p2pcng::IdOk ||
             oRevMut   .SetRevocationAuthority ( pubAuth ) != p2pcng::IdOk )
        { Log ( "SETUP: revocation configuration failed" ); ScrubTempFiles ( ); return 2; }

        if ( !BuildSeeds ( ) ) { ScrubTempFiles ( ); return 2; }

        std::printf ( "[fuzzblock] seeds: login=%u ack=%u relay=%u revoke=%u bytes\n",
                      g_aSeed[TGT_LOGIN].n, g_aSeed[TGT_ACK].n,
                      g_aSeed[TGT_RELAY].n, g_aSeed[TGT_REVOKE].n );

        // ---- The positive controls ---------------------------------------
        //  Before anything is mutated, because everything below is meaningless
        //  if the rig cannot verify its own output.
        Log ( "--- positive controls: every seed must verify ---" );
        bool bControls = true;
        for ( int t = 0; t < TGT__COUNT; ++t )
        {
            g_nCurTgt = t; g_nCurIter = -1; g_pszCurSrc = "(seed)";
            g_oCurInput = g_aSeed[t];
            char szDetail[128];
            const bool bOk = RunTarget ( t, g_aSeed[t].b, g_aSeed[t].n, false,
                                         szDetail, sizeof(szDetail) );
            std::printf ( "[fuzzblock] control %-7s %4u bytes -> %s%s\n",
                          kTargetName[t], g_aSeed[t].n, szDetail,
                          bOk ? "" : "   <-- NOT ACCEPTED" );
            if ( !bOk ) bControls = false;
        }
        std::fflush ( stdout );

        if ( !bControls )
        {
            std::printf (
              "\nRESULT: SETUP - a positive control did not verify, so the rig\n"
              "  cannot tell a refusal from a misconfiguration and every mutant\n"
              "  below would be 'correctly refused' by a hub that refuses\n"
              "  everything.  Nothing was measured.  Check the key, allow-list\n"
              "  and revocation provisioning above.\n" );
            ScrubTempFiles ( );
            return 2;
        }

        // ---- Corpus replay ------------------------------------------------
        int nCorpusRun = 0;
        if ( pszCorpus )
        {
            Log ( "--- corpus replay ---" );
            CorpusCtx oCtx; oCtx.nTgt = 0; oCtx.nRun = 0;
            unsigned nSkipped = 0, nUnlisted = 0;
            const unsigned nFiles = FuzzCorpusRun ( pszCorpus, CorpusOne, &oCtx,
                                                    &nSkipped, &nUnlisted );
            nCorpusRun = (int)nFiles;
            std::printf ( "[fuzzblock] corpus: %u file(s) replayed against %d "
                          "target(s) each\n", nFiles, TGT__COUNT );
            //  Say what was NOT run. A fuzzer that quietly skips part of its
            //  corpus reports coverage it does not have.
            if ( nSkipped )
                std::printf ( "[fuzzblock] corpus: %u file(s) SKIPPED - unreadable, "
                              "empty, or larger than %u bytes\n", nSkipped, kFuzzCorpusMax );
            if ( nUnlisted )
                std::printf ( "[fuzzblock] corpus: %u file(s) NOT LISTED - the "
                              "directory holds more than %u entries\n",
                              nUnlisted, kFuzzCorpusMaxFiles );
            std::fflush ( stdout );
        }

        // ---- Mutation -----------------------------------------------------
        long nRuns = 0;
        if ( nReplayTgt >= 0 )
        {
            if ( nReplayTgt >= TGT__COUNT )
            { Log ( "SETUP: --replay target out of range" ); ScrubTempFiles ( ); return 2; }
            g_bVerbose = true;
            std::printf ( "--- replaying target %d (%s) iteration %d ---\n",
                          nReplayTgt, kTargetName[nReplayTgt], nReplayIter );
            RunMutant ( nReplayTgt, nReplayIter );
            nRuns = 1;
        }
        else
        {
            Log ( "--- mutation ---" );
            const time_t tStart = std::time ( 0 );
            int nRound = 0;
            for ( ;; )
            {
                for ( int t = 0; t < TGT__COUNT; ++t )
                    for ( int i = 0; i < nIters; ++i )
                    { RunMutant ( t, nRound * nIters + i ); ++nRuns; }
                ++nRound;

                //  CONTINUOUS MODE. Without --seconds this runs exactly one
                //  round, which is what the registered ctest gate wants: a
                //  gate whose duration depends on the machine is not a gate.
                //  With it, rounds keep coming and the iteration index keeps
                //  climbing, so round N is genuinely new inputs rather than
                //  the same ones again - which is the difference between a
                //  campaign and a loop.
                if ( nSeconds <= 0 ) break;
                if ( (long)( std::time ( 0 ) - tStart ) >= (long)nSeconds ) break;
            }
            std::printf ( "[fuzzblock] %d round(s) of %d iterations x %d targets\n",
                          nRound, nIters, TGT__COUNT );
        }

        g_nCurTgt = -1; g_nCurIter = -1; g_pszCurSrc = "(done)";

        // ---- Verdict ------------------------------------------------------
        std::printf ( "\n[fuzzblock] inputs=%ld corpus=%d findings=%d\n",
                      nRuns, nCorpusRun, g_nFindings );
#ifdef _WIN32
        if ( g_nAsserts )
            std::printf ( "[fuzzblock] debug ASSERTs tripped: %d\n", g_nAsserts );
#endif

        if ( g_nFindings )
        {
            std::printf (
              "\nRESULT: FAIL - %d finding(s).  Each one wrote a REPRODUCER into\n"
              "  '%s'; that file is the finding, not this text.  Replay it with\n"
              "  --corpus, and promote it into MscsUnitTests/fuzz/corpus/ so the\n"
              "  gate keeps checking it once it is fixed.\n",
              g_nFindings, g_szReproDir );
            nExit = 1;
        }
        else
        {
            std::printf (
              "\nRESULT: PASS - every seed verified, and no mutant of any of them\n"
              "  did.  %ld mutated input(s) across %d parsers, plus %d corpus\n"
              "  entry(s) replayed against every parser.  Seed 0x%08X; any\n"
              "  iteration replays exactly.\n",
              nRuns, TGT__COUNT, nCorpusRun, nSeed );
            nExit = 0;
        }
    }

    ScrubTempFiles ( );
    CleanupP2Pmsg ( );
    return nExit;
}
