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
// seal_interop.cpp — does a body sealed on ONE backend open on the OTHER?
//
// crypto_kat proves each backend agrees with itself: the OpenSSL build seals and
// opens its own bodies, the CNG build seals and opens its own. That is not the
// claim the wire format makes. The claim is that a body sealed by a Windows peer
// opens on a Linux peer and back, and until this ran, nothing executed it — the
// layout was byte-compatible by inspection only, which is how the last two bugs
// in this area survived review.
//
// WHAT IS ACTUALLY AT RISK HERE, none of it visible to a single-backend test:
//
//   * wchar_t is 2 bytes under MSVC and 4 under GCC. The addresses are bound into
//     the GCM AAD and the signed transcript, so if the two ends disagreed by even
//     one byte on how an address becomes bytes, every cross-platform Open() would
//     fail the tag. P2PeerSeal converts to UTF-8 first (P2PeerSeal.cpp:69) to
//     avoid exactly this — the vectors below carry an address with a non-ASCII
//     BMP character AND one outside the BMP, so the surrogate-pair path that only
//     Windows takes and the 4-byte path that only Linux takes must agree.
//   * The 96-byte private blob X||Y||d is produced by CNG's key export and by
//     hand-rolled OpenSSL code. Same claimed layout, two authors.
//   * The identity CONTAINER on disk is written by one backend and read by the
//     other whenever a key is provisioned on a build machine and shipped.
//   * ECDSA r||s and the raw point encoding, one signing, the other verifying.
//
// USE
//   seal_interop emit   <vector-file>          seal here, write a portable vector
//   seal_interop verify <vector-file> [...]    open vectors sealed anywhere
//
// The emitted vector is plain text and carries the PRIVATE keys, which is fine
// and deliberate: they are throwaway test keys and a vector nobody can open is
// not a test. Do not point this at a real identity file.
//
// Verdict = process EXIT CODE: 0 all pass | 1 a check failed | 2 usage/setup.

#ifdef _WIN32
#include "stdafx.h"
#endif

#include "P2PCngCrypto.h"
#include "P2PIdentityStore.h"
#include "P2PeerSeal.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <map>

#ifndef _WIN32
#include <sys/stat.h>   // chmod - the store refuses a key file others can read
#endif

// ---------------------------------------------------------------- reporting
static int g_fail = 0;
static void CHECK ( bool bCond, const char *pszName )
{
    std::printf ( "    [%s] %s\n", bCond ? "PASS" : "FAIL", pszName );
    std::fflush ( stdout );
    if ( !bCond ) ++g_fail;
}

// ---------------------------------------------------------------- hex
static std::string Hex ( const unsigned char *p, size_t cb )
{
    static const char *k = "0123456789abcdef";
    std::string s;
    s.reserve ( cb * 2 );
    for ( size_t i = 0; i < cb; ++i )
    {
        s.push_back ( k[ p[i] >> 4 ] );
        s.push_back ( k[ p[i] & 0x0F ] );
    }
    return s;
}

static bool UnHex ( const std::string &sIn, std::vector<unsigned char> &vOut )
{
    if ( sIn.size ( ) % 2 ) return false;
    vOut.clear ( );
    vOut.reserve ( sIn.size ( ) / 2 );
    for ( size_t i = 0; i < sIn.size ( ); i += 2 )
    {
        int hi = -1, lo = -1;
        for ( int j = 0; j < 2; ++j )
        {
            const char c = sIn[ i + j ];
            int        v = -1;
            if      ( c >= '0' && c <= '9' ) v = c - '0';
            else if ( c >= 'a' && c <= 'f' ) v = c - 'a' + 10;
            else if ( c >= 'A' && c <= 'F' ) v = c - 'A' + 10;
            else return false;
            ( j ? lo : hi ) = v;
        }
        vOut.push_back ( (unsigned char)( ( hi << 4 ) | lo ) );
    }
    return true;
}

// ---------------------------------------------------------------- UTF-8 -> native wide
//  The vector stores addresses as UTF-8 bytes, and each platform builds its own
//  native wide string from them. That is the point: the two ends start from the
//  same bytes, hold them in different-width units, and must still transcribe the
//  same transcript. Hard-coding a wide literal instead would test nothing, and
//  would drag in the compiler's source-encoding guess as well.
static bool WideFromUtf8 ( const std::vector<unsigned char> &v, std::wstring &sOut )
{
    sOut.clear ( );
    size_t i = 0;
    while ( i < v.size ( ) )
    {
        unsigned int cp  = 0;
        size_t       cbE = 0;
        const unsigned char c = v[i];

        if      ( c < 0x80 )          { cp = c;          cbE = 0; }
        else if ( ( c & 0xE0 ) == 0xC0 ) { cp = c & 0x1F; cbE = 1; }
        else if ( ( c & 0xF0 ) == 0xE0 ) { cp = c & 0x0F; cbE = 2; }
        else if ( ( c & 0xF8 ) == 0xF0 ) { cp = c & 0x07; cbE = 3; }
        else return false;

        if ( i + cbE >= v.size ( ) ) return false;   // truncated sequence
        for ( size_t k = 1; k <= cbE; ++k )
        {
            const unsigned char cc = v[ i + k ];
            if ( ( cc & 0xC0 ) != 0x80 ) return false;
            cp = ( cp << 6 ) | ( cc & 0x3F );
        }
        i += cbE + 1;

        if ( cp > 0x10FFFF ) return false;
#if WCHAR_MAX > 0xFFFFu
        sOut.push_back ( (wchar_t)cp );
#else
        if ( cp >= 0x10000 )
        {
            cp -= 0x10000;
            sOut.push_back ( (wchar_t)( 0xD800 + ( cp >> 10 ) ) );
            sOut.push_back ( (wchar_t)( 0xDC00 + ( cp & 0x3FF ) ) );
        }
        else
            sOut.push_back ( (wchar_t)cp );
#endif
    }
    return true;
}

// ---------------------------------------------------------------- vector file
typedef std::map<std::string, std::string> Vec;

static bool ReadVector ( const char *pszPath, Vec &oOut )
{
    std::FILE *f = std::fopen ( pszPath, "rb" );
    if ( !f ) return false;
    std::string sAll;
    char        buf[4096];
    size_t      n;
    while ( ( n = std::fread ( buf, 1, sizeof(buf), f ) ) > 0 ) sAll.append ( buf, n );
    std::fclose ( f );

    size_t pos = 0;
    while ( pos < sAll.size ( ) )
    {
        size_t nl = sAll.find ( '\n', pos );
        if ( nl == std::string::npos ) nl = sAll.size ( );
        std::string sLine = sAll.substr ( pos, nl - pos );
        pos = nl + 1;
        while ( !sLine.empty ( ) && ( sLine.back ( ) == '\r' || sLine.back ( ) == ' ' ) )
            sLine.pop_back ( );
        if ( sLine.empty ( ) || sLine[0] == '#' ) continue;
        const size_t sp = sLine.find ( ' ' );
        if ( sp == std::string::npos ) continue;
        oOut[ sLine.substr ( 0, sp ) ] = sLine.substr ( sp + 1 );
    }
    return true;
}

static bool Field ( const Vec &oVec, const char *pszKey, std::string &sOut )
{
    Vec::const_iterator it = oVec.find ( pszKey );
    if ( it == oVec.end ( ) ) return false;
    sOut = it -> second;
    return true;
}

static bool FieldBytes ( const Vec &oVec, const char *pszKey,
                         std::vector<unsigned char> &vOut, size_t cbExpect = 0 )
{
    std::string s;
    if ( !Field ( oVec, pszKey, s ) )   return false;
    if ( !UnHex ( s, vOut ) )           return false;
    if ( cbExpect && vOut.size ( ) != cbExpect ) return false;
    return true;
}

// ---------------------------------------------------------------- this build
static const char *BackendTag ( )
{
#ifdef _WIN32
    return "windows-cng";
#else
    return "linux-openssl";
#endif
}

static std::string TempKeyPath ( )
{
#ifdef _WIN32
    const char *pszDir = std::getenv ( "TEMP" );
    if ( !pszDir ) pszDir = ".";
    return std::string ( pszDir ) + "\\seal_interop_container.tmp";
#else
    return "/tmp/seal_interop_container.tmp";
#endif
}

// ---------------------------------------------------------------- addresses
//  Written as explicit UTF-8 escapes, never as source-file literals, so no
//  compiler's idea of the source encoding can quietly change the vector.
//    src = "Seal.Алиса"          Cyrillic, inside the BMP  (2-byte UTF-8)
//    dst = "Seal.Carol.𝄞"        U+1D11E, OUTSIDE the BMP  (4-byte UTF-8)
//  The second one is the interesting one: MSVC holds it as a surrogate PAIR and
//  GCC as a single 4-byte wchar_t, and both must emit the same 4 UTF-8 bytes
//  into the transcript or the tag check fails.
static const char kSrcUtf8[] = "Seal.\xD0\x90\xD0\xBB\xD0\xB8\xD1\x81\xD0\xB0";
static const char kDstUtf8[] = "Seal.Carol.\xF0\x9D\x84\x9E";
static const char kPlain[]   = "sealed on one backend, opened on the other "
                               "\xE2\x80\x94 \xD0\xBF\xD1\x80\xD0\xB8\xD0\xB2\xD0\xB5\xD1\x82";

// ================================================================== emit
static int Emit ( const char *pszPath )
{
    using namespace p2pcng;

    EcdsaP256 oSender;
    EcdhP256  oRecip;
    if ( !oSender.Generate ( ) ) { std::printf ( "  ! sender keygen failed\n" ); return 2; }
    if ( !oRecip.Generate  ( ) ) { std::printf ( "  ! recipient keygen failed\n" ); return 2; }

    unsigned char senderPriv[kEcdsaPrivLen], senderPub[kEcdsaPubLen];
    unsigned char recipPriv [kEcdhPrivLen],  recipPub [kEcdhPubLen];
    if ( !oSender.ExportPrivate ( senderPriv ) || !oSender.ExportPublic ( senderPub ) ||
         !oRecip .ExportPrivate ( recipPriv  ) || !oRecip .ExportPublic ( recipPub  ) )
    {
        std::printf ( "  ! key export failed\n" );
        return 2;
    }

    std::vector<unsigned char> vSrc ( kSrcUtf8, kSrcUtf8 + std::strlen ( kSrcUtf8 ) );
    std::vector<unsigned char> vDst ( kDstUtf8, kDstUtf8 + std::strlen ( kDstUtf8 ) );
    std::wstring wSrc, wDst;
    if ( !WideFromUtf8 ( vSrc, wSrc ) || !WideFromUtf8 ( vDst, wDst ) )
    {
        std::printf ( "  ! address transcode failed\n" );
        return 2;
    }

    const size_t               cbPlain = std::strlen ( kPlain );
    std::vector<unsigned char> vSealed ( p2pseal::SealedSize ( cbPlain ) );
    size_t                     cbSealed = 0;
    p2pseal::SealResult        eSeal =
        p2pseal::Seal ( oSender, recipPub, wSrc.c_str ( ), wDst.c_str ( ),
                        kPlain, cbPlain, vSealed.data ( ), vSealed.size ( ), &cbSealed );
    if ( eSeal != p2pseal::SealOk )
    {
        std::printf ( "  ! Seal failed: %s\n", p2pseal::SealResultText ( eSeal ) );
        return 2;
    }
    vSealed.resize ( cbSealed );

    //  The container too, unprotected on purpose: DPAPI is a Windows-only
    //  wrapper and would make the file unreadable off the box by design, so
    //  what is portable is the raw container, which is what provisioning ships.
    const std::string sTmp = TempKeyPath ( );
    IdResult eSave = SaveIdentity ( sTmp.c_str ( ), oSender, IdProtect_None, true );
    if ( eSave != IdOk )
    {
        std::printf ( "  ! SaveIdentity failed: %s\n", IdResultText ( eSave ) );
        return 2;
    }
    std::vector<unsigned char> vContainer;
    {
        std::FILE *f = std::fopen ( sTmp.c_str ( ), "rb" );
        if ( !f ) { std::printf ( "  ! container read-back failed\n" ); return 2; }
        unsigned char buf[512];
        size_t        n;
        while ( ( n = std::fread ( buf, 1, sizeof(buf), f ) ) > 0 )
            vContainer.insert ( vContainer.end ( ), buf, buf + n );
        std::fclose ( f );
        std::remove ( sTmp.c_str ( ) );
    }

    std::FILE *f = std::fopen ( pszPath, "wb" );
    if ( !f ) { std::printf ( "  ! cannot write %s\n", pszPath ); return 2; }
    //  The licence notice is EMITTED, not added to the .vec by hand. These files
    //  are regenerated by `seal_interop emit` on each backend, so anything a
    //  human writes into one is erased the next time the vector is refreshed --
    //  which is exactly how a checked-in file loses its notice without anyone
    //  touching it. The short form is used because ReadVector skips '#' lines
    //  wholesale (see :185) and the vector is data, not source.
    //  The (c) is written as the explicit UTF-8 bytes \xC2\xA9 rather than as a
    //  literal character. These vectors are emitted by BOTH backends - CNG on
    //  Windows (MSVC, no /utf-8, so a literal would be narrowed to the single
    //  CP1252 byte 0xA9) and OpenSSL on Linux (GCC, which would emit UTF-8) -
    //  and both files are checked in. A literal would therefore make the two
    //  vectors differ in the one line that is supposed to be identical.
    std::fprintf ( f, "# Copyright \xC2\xA9 2026 Khrustal & Mann\n"
                      "#              MELBOURNE, VICTORIA, AUSTRALIA, 3000\n"
                      "# Licensed under the Apache License, Version 2.0. "
                      "See LICENSE for the full text.\n"
                      "#\n" );
    std::fprintf ( f, "# p2pseal cross-backend interop vector, format v1\n" );
    std::fprintf ( f, "# Sealed by the %s backend. Every other backend must open it.\n", BackendTag ( ) );
    std::fprintf ( f, "# Keys are throwaway and deliberately in the clear - a vector\n"
                      "# nobody can open proves nothing.\n" );
    std::fprintf ( f, "version 1\n" );
    std::fprintf ( f, "producer %s\n", BackendTag ( ) );
    std::fprintf ( f, "src_utf8 %s\n",     Hex ( vSrc.data ( ), vSrc.size ( ) ).c_str ( ) );
    std::fprintf ( f, "dst_utf8 %s\n",     Hex ( vDst.data ( ), vDst.size ( ) ).c_str ( ) );
    std::fprintf ( f, "plain %s\n",        Hex ( (const unsigned char *)kPlain, cbPlain ).c_str ( ) );
    std::fprintf ( f, "sender_priv %s\n",  Hex ( senderPriv, kEcdsaPrivLen ).c_str ( ) );
    std::fprintf ( f, "sender_pub %s\n",   Hex ( senderPub,  kEcdsaPubLen  ).c_str ( ) );
    std::fprintf ( f, "recip_priv %s\n",   Hex ( recipPriv,  kEcdhPrivLen  ).c_str ( ) );
    std::fprintf ( f, "recip_pub %s\n",    Hex ( recipPub,   kEcdhPubLen   ).c_str ( ) );
    std::fprintf ( f, "sealed %s\n",       Hex ( vSealed.data ( ), vSealed.size ( ) ).c_str ( ) );
    std::fprintf ( f, "container %s\n",    Hex ( vContainer.data ( ), vContainer.size ( ) ).c_str ( ) );
    std::fclose ( f );

    std::printf ( "  wrote %s (%s, %u byte body, %u byte container)\n",
                  pszPath, BackendTag ( ),
                  (unsigned)cbSealed, (unsigned)vContainer.size ( ) );
    return 0;
}

// ================================================================== verify
static int Verify ( const char *pszPath )
{
    using namespace p2pcng;

    Vec oVec;
    if ( !ReadVector ( pszPath, oVec ) )
    {
        std::printf ( "  ! cannot read %s\n", pszPath );
        return 2;
    }

    std::string sProducer = "(unknown)";
    Field ( oVec, "producer", sProducer );
    std::printf ( "  %s  [sealed by %s, opening on %s]\n",
                  pszPath, sProducer.c_str ( ), BackendTag ( ) );

    std::vector<unsigned char> vSrc, vDst, vPlain, vSealed, vContainer;
    std::vector<unsigned char> vSenderPriv, vSenderPub, vRecipPriv, vRecipPub;
    if ( !FieldBytes ( oVec, "src_utf8",    vSrc ) ||
         !FieldBytes ( oVec, "dst_utf8",    vDst ) ||
         !FieldBytes ( oVec, "plain",       vPlain ) ||
         !FieldBytes ( oVec, "sealed",      vSealed ) ||
         !FieldBytes ( oVec, "container",   vContainer ) ||
         !FieldBytes ( oVec, "sender_priv", vSenderPriv, kEcdsaPrivLen ) ||
         !FieldBytes ( oVec, "sender_pub",  vSenderPub,  kEcdsaPubLen  ) ||
         !FieldBytes ( oVec, "recip_priv",  vRecipPriv,  kEcdhPrivLen  ) ||
         !FieldBytes ( oVec, "recip_pub",   vRecipPub,   kEcdhPubLen   ) )
    {
        std::printf ( "  ! malformed vector\n" );
        return 2;
    }

    std::wstring wSrc, wDst;
    if ( !WideFromUtf8 ( vSrc, wSrc ) || !WideFromUtf8 ( vDst, wDst ) )
    {
        std::printf ( "  ! address transcode failed\n" );
        return 2;
    }

    //  1. THE claim. A foreign-sealed body, opened here.
    EcdhP256 oRecip;
    if ( !oRecip.ImportPrivate ( vRecipPriv.data ( ) ) )
    {
        CHECK ( false, "import the foreign agreement private blob" );
        return 1;   // nothing below can mean anything without it
    }
    {
        std::vector<unsigned char> vOut ( p2pseal::OpenedSize ( vSealed.size ( ) ) + 1 );
        size_t                     cbOut = 0;
        p2pseal::SealResult        e =
            p2pseal::Open ( oRecip, vSenderPub.data ( ), wSrc.c_str ( ), wDst.c_str ( ),
                            vSealed.data ( ), vSealed.size ( ),
                            vOut.data ( ), vOut.size ( ), &cbOut );
        const bool bOk = ( e == p2pseal::SealOk ) &&
                         cbOut == vPlain.size ( ) &&
                         std::memcmp ( vOut.data ( ), vPlain.data ( ), cbOut ) == 0;
        if ( !bOk && e != p2pseal::SealOk )
            std::printf ( "      Open() said: %s\n", p2pseal::SealResultText ( e ) );
        CHECK ( bOk, "open a body sealed by the other backend" );
    }

    //  2. And it is not opening everything put in front of it. One flipped bit
    //     in the ciphertext must fail, or check 1 proved nothing.
    {
        std::vector<unsigned char> vBad = vSealed;
        vBad[ p2pseal::kSealEphLen + p2pseal::kSealNonceLen ] ^= 0x01;
        std::vector<unsigned char> vOut ( p2pseal::OpenedSize ( vBad.size ( ) ) + 1 );
        size_t                     cbOut = 0;
        p2pseal::SealResult        e =
            p2pseal::Open ( oRecip, vSenderPub.data ( ), wSrc.c_str ( ), wDst.c_str ( ),
                            vBad.data ( ), vBad.size ( ),
                            vOut.data ( ), vOut.size ( ), &cbOut );
        CHECK ( e != p2pseal::SealOk, "reject the same body with one bit flipped" );
    }

    //  3. The addresses are bound in. Move the body to another pair and it must
    //     die - the property the whole AAD/transcript design exists for, checked
    //     across backends because the address encoding is where they could
    //     silently differ.
    {
        std::wstring wOther = wDst + L"X";
        std::vector<unsigned char> vOut ( p2pseal::OpenedSize ( vSealed.size ( ) ) + 1 );
        size_t                     cbOut = 0;
        p2pseal::SealResult        e =
            p2pseal::Open ( oRecip, vSenderPub.data ( ), wSrc.c_str ( ), wOther.c_str ( ),
                            vSealed.data ( ), vSealed.size ( ),
                            vOut.data ( ), vOut.size ( ), &cbOut );
        CHECK ( e != p2pseal::SealOk, "reject the body re-addressed to another destination" );
    }

    //  4. The 96-byte private blob X||Y||d means the same thing on both sides:
    //     import the foreign blobs and re-derive their public halves.
    {
        unsigned char pub[kEcdhPubLen];
        const bool bOk = oRecip.ExportPublic ( pub ) &&
                         std::memcmp ( pub, vRecipPub.data ( ), kEcdhPubLen ) == 0;
        CHECK ( bOk, "foreign agreement blob yields the same public point" );
    }
    EcdsaP256 oSender;
    {
        unsigned char pub[kEcdsaPubLen];
        const bool bOk = oSender.ImportPrivate ( vSenderPriv.data ( ) ) &&
                         oSender.ExportPublic  ( pub ) &&
                         std::memcmp ( pub, vSenderPub.data ( ), kEcdsaPubLen ) == 0;
        CHECK ( bOk, "foreign identity blob yields the same public point" );
    }

    //  5. Seal HERE with the foreign keys and open it here. Proves the imported
    //     private halves are usable, not merely well-formed - signing and ECDH
    //     both run on a key this backend did not generate.
    {
        std::vector<unsigned char> vNew ( p2pseal::SealedSize ( vPlain.size ( ) ) );
        size_t                     cbNew = 0;
        p2pseal::SealResult        e =
            p2pseal::Seal ( oSender, vRecipPub.data ( ), wSrc.c_str ( ), wDst.c_str ( ),
                            vPlain.data ( ), vPlain.size ( ),
                            vNew.data ( ), vNew.size ( ), &cbNew );
        bool bOk = ( e == p2pseal::SealOk );
        if ( bOk )
        {
            std::vector<unsigned char> vOut ( vPlain.size ( ) + 1 );
            size_t                     cbOut = 0;
            bOk = p2pseal::Open ( oRecip, vSenderPub.data ( ), wSrc.c_str ( ), wDst.c_str ( ),
                                  vNew.data ( ), cbNew,
                                  vOut.data ( ), vOut.size ( ), &cbOut ) == p2pseal::SealOk &&
                  cbOut == vPlain.size ( ) &&
                  std::memcmp ( vOut.data ( ), vPlain.data ( ), cbOut ) == 0;
        }
        CHECK ( bOk, "re-seal here with the foreign keys and open it" );
    }

    //  6. The identity container written by the other backend. Provisioning
    //     ships these between machines, so "it loads" is the whole point.
    {
        const std::string sTmp = TempKeyPath ( );
        bool bOk = false;
        std::FILE *f = std::fopen ( sTmp.c_str ( ), "wb" );
        if ( f )
        {
            const bool bWrote = vContainer.empty ( ) ||
                std::fwrite ( vContainer.data ( ), 1, vContainer.size ( ), f ) == vContainer.size ( );
            std::fclose ( f );
#ifndef _WIN32
            //  Not ceremony: the store refuses a key file that others can read
            //  (POSIX has no DPAPI, so the mode IS the protection). Writing the
            //  vector's bytes out at the default 0644 gets IdErrPermissions,
            //  which is the store working. Provisioning has to do this too.
            if ( bWrote ) chmod ( sTmp.c_str ( ), S_IRUSR | S_IWUSR );
#endif
            if ( bWrote )
            {
                EcdsaP256 oLoaded;
                IdResult  e = LoadIdentity ( sTmp.c_str ( ), oLoaded );
                if ( e == IdOk )
                {
                    unsigned char priv[kEcdsaPrivLen];
                    bOk = oLoaded.ExportPrivate ( priv ) &&
                          std::memcmp ( priv, vSenderPriv.data ( ), kEcdsaPrivLen ) == 0;
                }
                else
                    std::printf ( "      LoadIdentity said: %s\n", IdResultText ( e ) );
            }
            std::remove ( sTmp.c_str ( ) );
        }
        CHECK ( bOk, "load the identity container written by the other backend" );
    }

    return 0;
}

// ================================================================== main
int main ( int argc, char **argv )
{
    if ( argc >= 3 && std::strcmp ( argv[1], "emit" ) == 0 )
    {
        std::printf ( "=== seal_interop emit (%s) ===\n", BackendTag ( ) );
        return Emit ( argv[2] );
    }

    if ( argc >= 3 && std::strcmp ( argv[1], "verify" ) == 0 )
    {
        std::printf ( "=== seal_interop verify (this build: %s) ===\n", BackendTag ( ) );
        int nSetup = 0;
        for ( int i = 2; i < argc; ++i )
        {
            const int r = Verify ( argv[i] );
            if ( r == 2 ) nSetup = 2;
        }
        if ( nSetup ) { std::printf ( "=== seal_interop: SETUP FAILURE ===\n" ); return 2; }
        std::printf ( "=== seal_interop: %s (%d failure%s) ===\n",
                      g_fail == 0 ? "ALL PASS" : "FAILED",
                      g_fail, g_fail == 1 ? "" : "s" );
        return g_fail == 0 ? 0 : 1;
    }

    std::printf ( "usage: seal_interop emit   <vector-file>\n"
                  "       seal_interop verify <vector-file> [<vector-file> ...]\n" );
    return 2;
}
