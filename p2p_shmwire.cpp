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
// p2p_shmwire.cpp - is a SEALED body opaque in the shared-memory transport's MAPPING?
//
// p2p_performance.md §6.3a S2. The shm transport (P2PeerConShm / P2PeerioShm, Targetcore
// 3.10.0) moves frames through two byte rings in a mapping that BOTH processes can read
// at any time, and a ring is never zeroed after a read: the last 64 KB each way stays in
// the mapping until it is overwritten. So the mapping is a wire that keeps a recording.
// The transport hooks only IoWrite/IoRead, under the stock framing and seal path - this
// test holds it to that: what lands in the mapping must be what p2p_sealwire proved the
// socket carries (F-L4-1: one sealed body, no plaintext beside it).
//
// WHAT IT DOES - p2p_sealwire's three hubs, both links over shm, the AUTOMATIC seal.
//
//       Seal.Alice  --shm-->  Seal  --shm-->  Seal.Carol
//        (sender)           (middle)          (recipient)
//                          holds NO keys
//
//   After Carol has the body back in clear, main scans EVERY mapping of this process that
//   carries the transport's block magic ("P2SH") - Windows: VirtualQuery for MEM_MAPPED
//   regions; Linux: the memfd:p2pshm lines of /proc/self/maps. It reads the mapping, not
//   anything the API hands out.
//
//   CONTROLS (without them a scan that finds nothing proves nothing):
//     - Carol received the body exactly (the route, the seal and the open all worked);
//     - the middle forwarded it SEALED;
//     - the scan found the mappings (>= 2 blocks: two links);
//     - the scan found 32 bytes of THIS message's ciphertext, recorded by the middle as it
//       forwarded it - so the scanner reads the very ring the frame crossed.
//   THE PROBE: the plaintext pattern is nowhere in any mapping.
//   Phase 1 a 2 KB body, phase 2 20 KB (inside one 64 KB ring, so both are still there).
//
// VERDICT = process EXIT CODE:
//   0  PASS   no plaintext in any mapping, both bodies arrived
//   1  FAIL   plaintext in a mapping, or a body lost
//   2  SETUP  startup / provisioning failure, or the transport is unsupported here
//   3  INCONCLUSIVE a control failed - the probe would prove nothing

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConShm.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"
#include "P2PIdentityStore.h"
#include "P2PAuthLogin.h"
#include "P2PeerSeal.h"
#include "p2pshm.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <atomic>

// ---------------------------------------------------------------------------
static const P2PaddrSTR kAliceAddr = L"Seal.Alice";
static const P2PaddrSTR kMidAddr   = L"Seal";
static const P2PaddrSTR kCarolAddr = L"Seal.Carol";
static const P2PaddrSTR kDomain    = L"Seal.*";

//  The body is this pattern repeated, so a plaintext fragment anywhere in a mapping is
//  found whatever offset the ring put it at
static const char kNeedle[] = "PLAINTEXT-artichoke-90210-";

static HANDLE g_hCarolGot = NULL;

//  Written by the middle hub's pump, read by main after Carol's event
static std::atomic<bool> g_bMidSawSealed { false };
static unsigned char     g_aCipher[32];               // a slice of the forwarded ciphertext
static std::atomic<bool> g_bCipher       { false };   // published AFTER g_aCipher (release)
static std::atomic<bool> g_bCarolExact   { false };
static std::vector<char> g_vExpect;

static void Log ( const char *msg )
{
    std::printf ( "[shmwire] %s\n", msg );
    std::fflush ( stdout );
}

static bool Contains ( const void *pv, size_t cb, const void *pNeedle, size_t cbNeedle )
{
    if ( !pv || cb < cbNeedle || cbNeedle == 0 ) return false;
    const char *p = (const char *)pv;
    for ( size_t i = 0; i + cbNeedle <= cb; ++i )
        if ( std::memcmp ( p + i, pNeedle, cbNeedle ) == 0 ) return true;
    return false;
}

static std::vector<char> MakeBody ( size_t cb )
{
    std::vector<char> v ( cb );
    const size_t n = std::strlen ( kNeedle );
    for ( size_t i = 0; i < cb; ++i ) v[i] = kNeedle[i % n];
    return v;
}

// ---------------------------------------------------------------------------
//  Every transport mapping in this process, by its magic. Calls fn(block) for each
template <class F>
static int ForEachMapping ( F fn )
{
    int n = 0;
#if defined(_WIN32)
    MEMORY_BASIC_INFORMATION mbi;
    const BYTE *p = nullptr;
    while ( VirtualQuery ( p, &mbi, sizeof mbi ) == sizeof mbi )
    {
        if ( mbi.State == MEM_COMMIT && mbi.Type == MEM_MAPPED &&
             ( mbi.Protect & PAGE_READWRITE ) && !( mbi.Protect & PAGE_GUARD ) &&
             mbi.RegionSize >= sizeof ( p2pshm::Block ) )
        {
            const p2pshm::Block *b = (const p2pshm::Block *)mbi.BaseAddress;
            if ( b->magic == p2pshm::kMagic ) { ++n; fn ( b ); }
        }
        const BYTE *next = (const BYTE *)mbi.BaseAddress + mbi.RegionSize;
        if ( next <= p ) break;
        p = next;
    }
#else
    FILE *f = std::fopen ( "/proc/self/maps", "r" );
    if ( !f ) return 0;
    char line[1024];
    while ( std::fgets ( line, sizeof line, f ) )
    {
        if ( !std::strstr ( line, "memfd:p2pshm" ) ) continue;
        unsigned long lo = 0, hi = 0; char perms[8] = { 0 };
        if ( std::sscanf ( line, "%lx-%lx %7s", &lo, &hi, perms ) != 3 ) continue;
        if ( perms[0] != 'r' || hi - lo < sizeof ( p2pshm::Block ) ) continue;
        const p2pshm::Block *b = (const p2pshm::Block *)lo;
        if ( b->magic == p2pshm::kMagic ) { ++n; fn ( b ); }
    }
    std::fclose ( f );
#endif
    return n;
}

struct Scan { int blocks = 0; bool plain = false; bool cipher = false; };

static Scan ScanMappings ( )
{
    Scan s;
    const size_t cbNeedle = std::strlen ( kNeedle );
    //  The two rings' DATA, which is every byte a frame can occupy. Not the whole block:
    //  its control words (tail/head/parked) are atomics the live pumps still store to,
    //  and a plain memcmp over them is a data race TSan rightly reports
    s.blocks = ForEachMapping ( [&] ( const p2pshm::Block *b )
    {
        for ( const p2pshm::Ring &r : b->ring )
        {
            //  Acquire the producer's tail first, as a real reader of the ring does: the
            //  RingWrite that put a frame here released it AFTER the copy, so this orders
            //  every byte already written before the scan (TSan, 1 run in ~15, without it)
            (void)r.tail.load ( std::memory_order_acquire );
            if ( Contains ( r.data, sizeof r.data, kNeedle, cbNeedle ) ) s.plain = true;
            if ( g_bCipher && Contains ( r.data, sizeof r.data, g_aCipher, sizeof g_aCipher ) ) s.cipher = true;
        }
    } );
    return s;
}

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
    s += "p2p_shmwire_"; s += pszLeaf; s += "_"; s += szPid; s += ".tmp";
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
    if ( !oKey.Generate() )                                          return false;
    if ( p2pcng::SaveIdentity ( sPath.c_str(), oKey ) != p2pcng::IdOk ) return false;
    return oKey.ExportPublic ( pPubOut );
}

static bool MakeAgreement ( const std::string &sPath, unsigned char *pPubOut )
{
    p2pcng::EcdhP256 oKey;
    if ( !oKey.Generate() )                                           return false;
    if ( p2pcng::SaveAgreement ( sPath.c_str(), oKey ) != p2pcng::IdOk ) return false;
    return oKey.ExportPublic ( pPubOut );
}

// =========================================================================
class WireHub : public P2PeerHub
{
public:
    enum Role { RoleAlice, RoleMiddle, RoleCarol };

    WireHub ( P2PaddrSTR strAddr, Role eRole )
        : P2PeerHub ( strAddr ), m_eRole ( eRole ) { }
    virtual ~WireHub ( ) { }

protected:
    //  The middle records a slice from the middle of the sealed body it forwards: the
    //  scan's positive control (that exact ciphertext must be in a mapping)
    virtual msgRESULT PeekP2PeerMsg ( P2PeerMsg *pMsg ) override
    {
        if ( m_eRole == RoleMiddle && pMsg && pMsg->DataSize() > (int)( 2 * sizeof g_aCipher ) )
        {
            const bool bSealed = pMsg->IsSealed ( );
            if ( bSealed )
            {
                g_bMidSawSealed = true;
                const char *pd = (const char *)pMsg->Data ( );
                std::memcpy ( g_aCipher, pd + pMsg->DataSize ( ) / 2, sizeof g_aCipher );
                g_bCipher = true;
            }
            std::printf ( "[shmwire] MIDDLE forwarding: sealed=%s body=%u\n",
                          bSealed ? "yes" : "NO", (unsigned)pMsg->DataSize ( ) );
            std::fflush ( stdout );
        }
        return P2PeerHub::PeekP2PeerMsg ( pMsg );
    }

    //  Alice signs her logins because she holds an identity; the middle requires no auth,
    //  so it must accept a login that carries data (as p2p_sealhop / p2p_sealwire)
    virtual conRESULT On_ConLogin ( P2PeerCon *pCon, P2PaddrSTR strThatP2Paddr,
                                    const void *pvLoginMsg, P2Psize_t iSize ) override
    {
        if ( !pvLoginMsg && !iSize )
            return P2PeerHub::On_ConLogin ( pCon, strThatP2Paddr, pvLoginMsg, iSize );
        pCon -> OnLogin  ( strThatP2Paddr );
        pCon -> LoginAck ( strThatP2Paddr, 0, 0 );
        return conHANDLED;
    }

    virtual msgRESULT On_P2PeerBCast ( P2PeerMsg *pMsg ) override
    {
        if ( m_eRole != RoleCarol || !pMsg )
            return msgHANDLED;
        const size_t cb = (size_t)pMsg->DataSize ( );
        g_bCarolExact = !pMsg->IsSealed ( ) && cb == g_vExpect.size ( ) &&
                        std::memcmp ( pMsg->Data ( ), &g_vExpect[0], cb ) == 0;
        std::printf ( "[shmwire] CAROL received %u bytes, %s\n", (unsigned)cb,
                      g_bCarolExact ? "EXACTLY the plaintext" : "NOT what was sent" );
        std::fflush ( stdout );
        if ( g_hCarolGot ) SetEvent ( g_hCarolGot );
        return msgHANDLED;
    }

private:
    Role m_eRole;
};

static bool SendOne ( WireHub& oAlice, size_t cbBody, DWORD dwWaitMs )
{
    g_bMidSawSealed = false; g_bCipher = false; g_bCarolExact = false;
    ResetEvent ( g_hCarolGot );
    g_vExpect = MakeBody ( cbBody );
    oAlice.PostP2PeerMsg ( new P2PeerMsg32 ( kAliceAddr, kCarolAddr, P2Pmsg_BCast,
                                             &g_vExpect[0], (P2Psize_t)cbBody ) );
    return WaitForSingleObject ( g_hCarolGot, dwWaitMs ) == WAIT_OBJECT_0;
}

//  One phase: send, then scan. 0 pass, 1 fail, 3 inconclusive
static int Phase ( WireHub& oAlice, const char *name, size_t cb )
{
    std::printf ( "[shmwire] --- %s: a %u-byte body, sealed automatically ---\n", name, (unsigned)cb );
    std::fflush ( stdout );
    const bool bGot = SendOne ( oAlice, cb, 20000 );
    if ( bGot ) Sleep ( 100 );            // the middle's pump is done with the frame
    const Scan s = ScanMappings ( );
    std::printf ( "[shmwire] %s: carol-got=%s exact=%s middle-saw-sealed=%s mappings=%d"
                  " ciphertext-in-mapping=%s PLAINTEXT-in-mapping=%s\n", name,
                  bGot ? "yes" : "no", g_bCarolExact ? "yes" : "no",
                  g_bMidSawSealed ? "yes" : "no", s.blocks, s.cipher ? "yes" : "no",
                  s.plain ? "YES" : "no" );
    std::fflush ( stdout );
    if ( s.plain )
    {
        std::printf ( "FAIL: the PLAINTEXT is in a shared mapping - the peer process (or\n"
                      "      anything that can map it) reads a sealed body in clear\n" );
        return 1;
    }
    if ( !bGot || !g_bCarolExact )
    {
        std::printf ( "FAIL: the sealed body did not arrive intact\n" );
        return 1;
    }
    if ( !g_bMidSawSealed || s.blocks < 2 || !s.cipher )
    {
        std::printf ( "INCONCLUSIVE: a control failed - without the ciphertext found in a\n"
                      "      mapping, an empty plaintext scan proves nothing\n" );
        return 3;
    }
    return 0;
}

// =========================================================================
int main ( int, char *[] )
{
    std::printf ( "=== p2p_shmwire - is a sealed body opaque in the shm mapping? ===\n" );
    std::printf ( "Route: Seal.Alice -shm-> Seal -shm-> Seal.Carol, AUTOMATIC seal, auth OFF.\n\n" );
    std::fflush ( stdout );

    if ( !P2PeerConShm::IsSupported ( ) ) { Log ( "SETUP: the shm transport is unsupported here" ); return 2; }

    g_hCarolGot = CreateEvent ( NULL, TRUE, FALSE, NULL );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }

    const std::string sAliceKey   = TempPath ( "alicekey"   );
    const std::string sCarolAgree = TempPath ( "carolagree" );
    const std::string sAliceAcl   = TempPath ( "aliceacl"   );
    const std::string sCarolAcl   = TempPath ( "carolacl"   );

    unsigned char pubAlice [p2pcng::kEcdsaPubLen];
    unsigned char agrCarol [p2pcng::kEcdhPubLen];
    unsigned char idCarol  [p2pcng::kEcdsaPubLen];
    {
        p2pcng::EcdsaP256 oCarolId;
        if ( !MakeIdentity  ( sAliceKey,   pubAlice ) ||
             !MakeAgreement ( sCarolAgree, agrCarol ) ||
             !oCarolId.Generate ( ) || !oCarolId.ExportPublic ( idCarol ) )
        { Log ( "SETUP: key generation failed" ); ScrubTempFiles(); return 2; }
    }
    if ( p2pcng::AppendAllowList ( sAliceAcl.c_str(), "Seal.Carol",
                                   idCarol, agrCarol ) != p2pcng::IdOk ||
         p2pcng::AppendAllowList ( sCarolAcl.c_str(), "Seal.Alice",
                                   pubAlice ) != p2pcng::IdOk )
    { Log ( "SETUP: allow-list provisioning failed" ); ScrubTempFiles(); return 2; }

    //  The pipe name carries the pid, so parallel runs never meet
    std::string sPipe = "\\\\.\\pipe\\P2PshmWire_" + std::to_string ( (unsigned long)GetCurrentProcessId ( ) );
    std::wstring wPipe ( sPipe.begin ( ), sPipe.end ( ) );

    int nExit = 2;
    {
        WireHub oMiddle ( kMidAddr, WireHub::RoleMiddle );
        oMiddle.RequireAuth ( false );
        oMiddle.RequireSeal ( false );
        HANDLE hMidThread = oMiddle.SpawnHub();
        if ( !hMidThread ) { Log ( "SETUP: middle SpawnHub() failed" ); return 2; }
        P2PeerConShm *pSvc = P2PeerConShm::ServiceFactory ( kDomain, wPipe.c_str ( ) );
        if ( !pSvc ) { Log ( "SETUP: ServiceFactory failed" ); return 2; }
        oMiddle.PostP2PeerCon ( pSvc );
        Sleep ( 500 );

        WireHub oCarol ( kCarolAddr, WireHub::RoleCarol );
        if ( oCarol.SetAgreementKey ( sCarolAgree.c_str() ) != p2pcng::IdOk ||
             oCarol.SetAllowList    ( sCarolAcl.c_str()   ) != p2pcng::IdOk ||
             !oCarol.CanOpen ( ) )
        { Log ( "SETUP: Carol configuration failed" ); return 2; }
        oCarol.RequireAuth ( false );
        HANDLE hCarolThread = oCarol.SpawnHub();
        P2PeerConShm *pConCarol = P2PeerConShm::ClientFactory ( kMidAddr, wPipe.c_str ( ) );
        if ( !hCarolThread || !pConCarol ) { Log ( "SETUP: Carol failed" ); return 2; }
        oCarol.PostP2PeerCon ( pConCarol );
        Sleep ( 1000 );

        WireHub oAlice ( kAliceAddr, WireHub::RoleAlice );
        if ( oAlice.SetIdentity  ( sAliceKey.c_str() ) != p2pcng::IdOk ||
             oAlice.SetAllowList ( sAliceAcl.c_str() ) != p2pcng::IdOk ||
             !oAlice.CanSeal ( ) )
        { Log ( "SETUP: Alice configuration failed" ); return 2; }
        oAlice.RequireAuth ( false );
        if ( !oAlice.IsSealRequired ( ) ) { Log ( "SETUP: seal is not required" ); return 2; }
        HANDLE hAliceThread = oAlice.SpawnHub();
        P2PeerConShm *pConAlice = P2PeerConShm::ClientFactory ( kMidAddr, wPipe.c_str ( ) );
        if ( !hAliceThread || !pConAlice ) { Log ( "SETUP: Alice failed" ); return 2; }
        oAlice.PostP2PeerCon ( pConAlice );
        Sleep ( 1500 );

        nExit = Phase ( oAlice, "phase 1", 2048 );
        if ( nExit == 0 )
            nExit = Phase ( oAlice, "phase 2", 20000 );

        Log ( "shutdown begin" );
        oAlice.CloseHub();  WaitForSingleObject ( hAliceThread, 3000 ); CloseHandle ( hAliceThread );
        oCarol.CloseHub();  WaitForSingleObject ( hCarolThread, 3000 ); CloseHandle ( hCarolThread );
        oMiddle.CloseHub(); WaitForSingleObject ( hMidThread,   3000 ); CloseHandle ( hMidThread );
    }

    CleanupP2Pmsg();
    ScrubTempFiles();
    if ( g_hCarolGot ) { CloseHandle ( g_hCarolGot ); g_hCarolGot = NULL; }

    std::printf ( nExit == 0 ? "\nRESULT: PASS\n"
                : nExit == 1 ? "\nRESULT: FAIL\n" : "\nRESULT: not a verdict (exit %d)\n",
                  nExit );
    std::fflush ( stdout );
    return nExit;
}
