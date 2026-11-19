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
// crypto_bench.cpp -- B3 of p2p_performance.md §3.1: every primitive the
// security posture spends its time in, timed on its own, on whichever backend
// this platform builds (Windows: CNG / BCrypt; Linux: OpenSSL 3).
//
// WHY IT EXISTS. p2p_linkcost measured the default posture at ~1,298 CPU us per
// message against ~93 with everything off, and attributed 93% to seal + relay
// attestation. T1 (§5) has to split that 1,298 into primitives before it may
// change any of them, and nothing in the tree times them in isolation across
// both backends. The cases follow the T1 table:
//
//   rng_nonce12         T1b  CngRandom(12) -- the RNG call per link-cypher frame
//   aes_gcm_setkey      T1a  the key schedule (the OpenSSL backend re-keys per op)
//   aes_gcm_seal/open   link cypher, 64 B .. 32 KB; 4,048 B is the size a
//                       one-field message actually seals today (§0 verdict 2)
//   sha256, hmac, hkdf  the KDF path
//   ecdh_generate       per message per reader in v2 seal (T1d)
//   ecdh_derive         per message per reader, both directions
//   ecdsa_sign/verify   attestation per message (T1c) and the seal signature
//   seal / open         p2pseal::SealTo / Open end to end, readers 1/2/8,
//                       payload 256 B and 4,048 B -- what the hub actually calls
//
// Built the way crypto_kat is: the backend TU and P2PeerSeal.cpp are compiled
// INTO this exe, because the AEAD/HKDF/HMAC symbols are internal to the
// Targetcore DLL. The same source therefore runs the same code the library
// runs, minus the hub around it.
//
// CORRECTNESS IS CHECKED: every Open must return the plaintext it was given,
// every Verify must accept. A primitive that silently failed would post the
// best number in the table, so a failure is exit 1, not a footnote.
//
// Usage:  crypto_bench [scale]     scale multiplies every iteration count (default 1)
// Verdict = exit code: 0 ran, 1 a correctness check failed.

#include "perf_common.h"

#include <memory>

#include "P2PCngCrypto.h"
#include "P2PeerSeal.h"

static const char *kBench = "crypto_bench";
static int g_fail = 0;

static void Run ( const char *kase, const std::string &param,
                  const perf::OpResult &r, const char *note = nullptr )
{
    if ( !r.ok )
    {
        std::printf ( "%-22s %-10s FAILED (a correctness check inside the loop)\n",
                      kase, param.c_str ( ) );
        ++g_fail;
        return;
    }
    perf::Report ( kBench, kase, param, "ns/op", r.ns, r.cpuNsPerOp, r.allocsPerOp, note );
}

int main ( int argc, char *argv[] )
{
    long scale = argc > 1 ? std::max<long> ( 1, std::atol ( argv[1] ) ) : 1;

    perf::PrintBox ( kBench );
#if defined(_WIN32)
    std::printf ( "backend: CNG (BCrypt)\n" );
#else
    std::printf ( "backend: OpenSSL\n" );
#endif
    std::printf ( "allocs/op: %s\n\n",
                  perf::AllocsCounted ( )
                      ? "counted (whole process)"
                      : "not counted on this platform (per-DLL operator new; see perf_common.h)" );

    // ---- symmetric ----------------------------------------------------
    std::printf ( "--- symmetric ---\n" );
    {
        unsigned char nonce[12];
        Run ( "rng_nonce12", "", perf::TimeOp ( [&] {
                  return p2pcng::CngRandom ( nonce, sizeof nonce ); }, 1000, 50 * scale ) );

        unsigned char key[p2pcng::kAesKeyLen];
        p2pcng::CngRandom ( key, sizeof key );
        {
            p2pcng::AesGcm g;
            Run ( "aes_gcm_setkey", "", perf::TimeOp ( [&] {
                      return g.SetKey ( key, sizeof key ); }, 200, 50 * scale ) );
        }
        //  A FRESH object per op, which is what p2pseal does: 1 + readers of
        //  these per seal, 2 per open. The case above reuses one object and so
        //  never sees a per-object provider open (T1h, 2026-11-19).
        Run ( "aes_gcm_new_setkey", "", perf::TimeOp ( [&] {
                  p2pcng::AesGcm n;
                  return n.SetKey ( key, sizeof key ); }, 200, 50 * scale ) );

        p2pcng::AesGcm g;
        if ( !g.SetKey ( key, sizeof key ) ) { std::printf ( "SETUP: SetKey failed\n" ); return 1; }
        unsigned char aad[16] = { 1, 2, 3, 4 };
        for ( size_t cb : { 64u, 256u, 1024u, 4048u, 16384u, 32768u } )
        {
            std::vector<unsigned char> plain ( cb, 0x5A ), sealed ( p2pcng::AesGcm::SealedSize ( cb ) ),
                                       back ( cb + 1 );
            size_t cbOut = 0;
            long batch = cb >= 16384 ? 50 : 500;
            std::string p = std::to_string ( cb ) + "B";
            Run ( "aes_gcm_seal", p, perf::TimeOp ( [&] {
                      return g.Seal ( plain.data ( ), cb, aad, sizeof aad,
                                      sealed.data ( ), sealed.size ( ), &cbOut ); },
                      batch, 40 * scale ) );
            Run ( "aes_gcm_open", p, perf::TimeOp ( [&] {
                      size_t n = 0;
                      return g.Open ( sealed.data ( ), cbOut, aad, sizeof aad,
                                      back.data ( ), back.size ( ), &n ) &&
                             n == cb && !std::memcmp ( back.data ( ), plain.data ( ), cb ); },
                      batch, 40 * scale ) );
        }

        std::vector<unsigned char> buf ( 4048, 0x33 );
        unsigned char out[32];
        Run ( "sha256", "4048B", perf::TimeOp ( [&] {
                  return p2pcng::Sha256 ( buf.data ( ), buf.size ( ), out ); }, 500, 40 * scale ) );
        Run ( "hmac_sha256", "256B", perf::TimeOp ( [&] {
                  return p2pcng::HmacSha256 ( key, 32, buf.data ( ), 256, out ); }, 500, 40 * scale ) );
        Run ( "hkdf_sha256", "32B", perf::TimeOp ( [&] {
                  return p2pcng::HkdfSha256 ( key, 32, nullptr, 0, aad, sizeof aad, out, 32 ); },
                  500, 40 * scale ) );
    }

    // ---- public key ---------------------------------------------------
    std::printf ( "\n--- public key (P-256) ---\n" );
    p2pcng::EcdsaP256 sender;
    if ( !sender.Generate ( ) ) { std::printf ( "SETUP: ECDSA Generate failed\n" ); return 1; }
    unsigned char senderPub[p2pcng::kEcdsaPubLen];
    sender.ExportPublic ( senderPub );

    const size_t kMaxR = p2pseal::kSealMaxReaders;
    // Array, not vector: EcdhP256 is non-copyable and owns a CNG handle.
    std::unique_ptr<p2pcng::EcdhP256[]> readers ( new p2pcng::EcdhP256[kMaxR] );
    std::vector<unsigned char> readerPubs ( kMaxR * p2pcng::kEcdhPubLen );
    for ( size_t i = 0; i < kMaxR; ++i )
        if ( !readers[i].Generate ( ) ||
             !readers[i].ExportPublic ( &readerPubs[i * p2pcng::kEcdhPubLen] ) )
        { std::printf ( "SETUP: ECDH Generate failed\n" ); return 1; }

    {
        Run ( "ecdh_generate", "", perf::TimeOp ( [] {
                  p2pcng::EcdhP256 e; return e.Generate ( ); }, 20, 20 * scale ) );
        unsigned char sec[p2pcng::kEcdhSecLen];
        Run ( "ecdh_derive", "", perf::TimeOp ( [&] {
                  return readers[0].DeriveRawSecret ( &readerPubs[p2pcng::kEcdhPubLen], sec ); },
                  20, 20 * scale ) );

        std::vector<unsigned char> msg ( 256, 0x42 );
        unsigned char sig[p2pcng::kEcdsaSigLen];
        Run ( "ecdsa_sign", "256B", perf::TimeOp ( [&] {
                  return sender.Sign ( msg.data ( ), msg.size ( ), sig ); }, 20, 20 * scale ) );
        // The imports. seal and open each take a STATIC public key as raw bytes
        // (the reader's agreement point, the sender's identity point) and so
        // import it per message; these two cases say what that costs, which is
        // the part of seal/open that derive+sign+verify does not explain.
        Run ( "ecdh_import_public", "", perf::TimeOp ( [&] {
                  p2pcng::EcdhP256 e; return e.ImportPublic ( &readerPubs[0] ); },
                  20, 20 * scale ) );
        Run ( "ecdsa_import_public", "", perf::TimeOp ( [&] {
                  p2pcng::EcdsaP256 e; return e.ImportPublic ( senderPub ); },
                  20, 20 * scale ) );

        p2pcng::EcdsaP256 verifier;
        if ( !verifier.ImportPublic ( senderPub ) ) { std::printf ( "SETUP: ImportPublic\n" ); return 1; }
        Run ( "ecdsa_verify", "256B", perf::TimeOp ( [&] {
                  return verifier.Verify ( msg.data ( ), msg.size ( ), sig ); }, 20, 20 * scale ) );
    }

    // ---- end-to-end seal (what SealAppMsgOutbound / OpenAppMsgInbound call) --
    std::printf ( "\n--- p2pseal v%u (per-message ECIES + signature) ---\n",
                  (unsigned)p2pseal::kSealVersion );
    const wchar_t *src = L"Bench.Alice", *dst = L"Bench.Carol";
    for ( size_t cb : { 256u, 4048u } )
        for ( size_t nR : { (size_t)1, (size_t)2, kMaxR } )
        {
            std::vector<unsigned char> plain ( cb, 0x77 ), sealed ( p2pseal::SealedSize ( cb, nR ) );
            std::vector<unsigned char> back ( cb + 1 );
            size_t cbSealed = 0;
            std::string p = std::to_string ( cb ) + "B/r" + std::to_string ( nR );
            Run ( "seal", p, perf::TimeOp ( [&] {
                      return p2pseal::SealTo ( sender, readerPubs.data ( ), nR, src, dst,
                                               plain.data ( ), cb, sealed.data ( ),
                                               sealed.size ( ), &cbSealed ) == p2pseal::SealOk; },
                      10, 20 * scale ) );
            // Open as the LAST reader: a reader further down the slot list
            // scans past the others first, so this is the worst slot.
            p2pcng::EcdhP256 &me = readers[nR - 1];
            Run ( "open", p, perf::TimeOp ( [&] {
                      size_t n = 0;
                      return p2pseal::Open ( me, senderPub, src, dst, sealed.data ( ), cbSealed,
                                             back.data ( ), back.size ( ), &n ) == p2pseal::SealOk &&
                             n == cb && !std::memcmp ( back.data ( ), plain.data ( ), cb ); },
                      10, 20 * scale ) );
        }

    std::printf ( "\nDone (exit=%d, %d failed case%s).\n", g_fail ? 1 : 0, g_fail,
                  g_fail == 1 ? "" : "s" );
    return g_fail ? 1 : 0;
}
