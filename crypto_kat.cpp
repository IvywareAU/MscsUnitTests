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
// crypto_kat.cpp — cross-backend known-answer tests for the p2pcng secure-channel
// primitives (LinuxPortPlan §8 "crypto KATs green both backends", Risk #5).
//
// Every check here is a DETERMINISTIC vector both the Windows CNG backend and the Linux
// OpenSSL backend must reproduce bit-for-bit, so a green run on either platform proves
// that backend agrees with the shared wire format:
//
//   1. p2pcng::SelfTest()          — RFC 4231 HMAC-SHA256, RFC 5869 HKDF-SHA256 (published
//                                     KATs), AES-256-GCM round-trip + tamper, ECDH symmetry.
//   2. AES-256-GCM decrypt KAT     — GCM spec Test Case 16 (AES-256, McGrew/Viega): a fixed
//                                     (key, IV, AAD, ciphertext, tag) must Open() to the
//                                     reference plaintext. Proves our GCM framing byte-exact.
//   3. ECDH P-256 KAT (Linux only) — RFC 5903 §8.1: a fixed private scalar + peer public
//                                     point must derive the reference shared X coordinate,
//                                     LITTLE-ENDIAN (CNG's BCRYPT_KDF_RAW_SECRET convention).
//                                     Validates both the raw X||Y point encoding and the
//                                     LE-secret reversal — the CNG<->OpenSSL contract.
//
// Verdict = process EXIT CODE: 0 all pass | 1 a KAT failed.
//
// Registered as the `crypto_kat` CTest target (Targetcore/CMakeLists.txt); run via
//   ctest --test-dir build -R crypto_kat
// The p2pcng symbols are hidden in libtargetcore.so (resolved intra-library by the secure
// channel), so the KAT compiles the self-contained OpenSSL backend TU directly rather than
// linking the .so:
//   g++ -std=c++23 -I../Targetcore -o crypto_kat crypto_kat.cpp
//       ../Targetcore/{P2PCngCrypto_openssl,P2PIdentityStore,P2PAuthLogin,P2PeerSeal}.cpp
//       -lcrypto
// (no trailing backslashes: a line continuation inside a // comment is -Wcomment)

#include "P2PCngCrypto.h"
#include "P2PIdentityStore.h"
#include "P2PAuthLogin.h"
#include "P2PeerSeal.h"

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>

#ifndef _WIN32
namespace p2pcng { namespace test {
    bool EcdhDeriveKAT ( const unsigned char privBE[], const unsigned char peerXY[],
                         unsigned char outLE[] );
} }
#endif

// hex string ("aabb..") -> bytes
static std::vector<unsigned char> H(const char* hex)
{
    std::vector<unsigned char> v;
    auto nib = [](char c)->int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (const char* p = hex; *p; ) {
        if (*p == ' ') { ++p; continue; }
        int hi = nib(*p++); while (*p == ' ') ++p; int lo = nib(*p++);
        v.push_back((unsigned char)((hi << 4) | lo));
    }
    return v;
}

static int g_fail = 0;
static void CHECK(bool cond, const char* name)
{
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", name);
    std::fflush(stdout);
    if (!cond) ++g_fail;
}

int main()
{
    std::printf("=== crypto_kat - cross-backend known-answer tests ===\n");

    // 1. Full self-test (RFC 4231 / RFC 5869 KATs + GCM round-trip + ECDH symmetry).
    CHECK(p2pcng::SelfTest(), "p2pcng::SelfTest (HMAC/HKDF/GCM/ECDH)");

    // 1b. Identity storage: container round-trip through real files in /tmp, plus the
    //     failure paths (corruption, truncation, version, exclusive create) and the
    //     0600 rule. On this platform the identity file is stored unprotected-but-0600,
    //     so this run also proves the container is byte-compatible across backends.
    CHECK(p2pcng::StoreSelfTest(), "p2pcng::StoreSelfTest (identity file round-trip)");

    // 1c. Login authentication: the transcript, the block layout and every refusal
    //     path (unknown peer, wrong key, tampered signature, replay, skew, a login
    //     bound to another destination). The transcript IS the wire, so running this
    //     on both backends is what proves a Windows peer and a Linux peer sign and
    //     verify the same bytes - the failure the short-r/s vectors above exist for,
    //     one layer up.
    CHECK(p2pauth::AuthSelfTest(), "p2pauth::AuthSelfTest (login proof, both directions)");

    // 1d. End-to-end seal: ECIES round trip plus every refusal - wrong recipient,
    //     wrong sender, the body moved to another address pair, a bit flipped in
    //     each of the five regions, truncation. Two things make this worth running
    //     HERE rather than only on Windows: the sealed layout is wire format, so
    //     both backends must produce and accept the same bytes; and the static
    //     agreement key it depends on is exported and imported through EcdhP256,
    //     whose private-blob path exists on this backend only because it was
    //     written to mirror the CNG one - untested, that is an assertion.
    CHECK(p2pseal::SealSelfTest(), "p2pseal::SealSelfTest (end-to-end seal)");

    // 2. AES-256-GCM decrypt KAT — GCM Test Case 16 (McGrew/Viega, AES-256, 96-bit IV).
    {
        auto key = H("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        auto iv  = H("cafebabefacedbaddecaf888");
        auto aad = H("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        auto ct  = H("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                     "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662");
        auto tag = H("76fc6ece0f4e1768cddf8853bb2d551b");
        auto pt  = H("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                     "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");

        // sealed layout = [ nonce(12) | ciphertext | tag(16) ]
        std::vector<unsigned char> sealed;
        sealed.insert(sealed.end(), iv.begin(),  iv.end());
        sealed.insert(sealed.end(), ct.begin(),  ct.end());
        sealed.insert(sealed.end(), tag.begin(), tag.end());

        p2pcng::AesGcm cipher;
        bool keyed = cipher.SetKey(key.data(), key.size());
        std::vector<unsigned char> out(pt.size() + 1);
        size_t cbOut = 0;
        bool opened = keyed && cipher.Open(sealed.data(), sealed.size(),
                                           aad.data(), aad.size(),
                                           out.data(), out.size(), &cbOut);
        bool match = opened && cbOut == pt.size() &&
                     std::memcmp(out.data(), pt.data(), pt.size()) == 0;
        CHECK(match, "AES-256-GCM decrypt KAT (GCM Test Case 16)");

        // Corrupt the tag -> Open must reject.
        std::vector<unsigned char> bad = sealed;
        bad.back() ^= 0x01;
        bool rejected = keyed && !cipher.Open(bad.data(), bad.size(),
                                              aad.data(), aad.size(),
                                              out.data(), out.size(), &cbOut);
        CHECK(rejected, "AES-256-GCM tag-tamper rejection");
    }

    // 3. ECDH P-256 KAT — RFC 5903 §8.1 (Linux OpenSSL backend only; the hook is not in
    //    the shared header). Expected shared X reversed to little-endian (CNG convention).
#ifndef _WIN32
    {
        auto priv   = H("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433");
        auto peerX  = H("D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63");
        auto peerY  = H("56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB");
        auto sharedBE = H("D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE");

        std::vector<unsigned char> peerXY;
        peerXY.insert(peerXY.end(), peerX.begin(), peerX.end());
        peerXY.insert(peerXY.end(), peerY.begin(), peerY.end());

        // our backend returns the secret little-endian -> reverse the RFC's big-endian value
        std::vector<unsigned char> expectLE(sharedBE.rbegin(), sharedBE.rend());

        unsigned char out[32] = {0};
        bool derived = p2pcng::test::EcdhDeriveKAT(priv.data(), peerXY.data(), out);
        bool match = derived && std::memcmp(out, expectLE.data(), 32) == 0;
        CHECK(match, "ECDH P-256 KAT (RFC 5903 8.1, LE secret)");
    }
#else
    std::printf("  [SKIP] ECDH P-256 KAT (Linux OpenSSL backend hook only)\n");
#endif

    std::printf("=== crypto_kat: %s (%d failure%s) ===\n",
                g_fail == 0 ? "ALL PASS" : "FAILED",
                g_fail, g_fail == 1 ? "" : "s");
    return g_fail == 0 ? 0 : 1;
}
