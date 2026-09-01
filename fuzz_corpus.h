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
// fuzz_corpus.h - the PERSISTENT half of fuzzing.  ProductionPlan.md Stage 6
//                 step 16.
//
// THE PROBLEM THIS SOLVES, stated as the step states it: fuzzing here ran one
// seed family for a fixed iteration budget and remembered nothing between
// runs.  Every run started from the same hand-written vectors, re-derived the
// same mutants from the same seed, and threw the result away.  A campaign that
// forgets is a campaign of length one, however many times it is run - the
// millionth iteration of run 500 is the millionth iteration of run 1.
//
// TWO THINGS MAKE IT CUMULATIVE, and they are the same mechanism seen from
// each end:
//
//   * A CORPUS DIRECTORY of raw input files, checked into the repository, that
//     every run replays before it mutates anything.  Adding a file is how a
//     campaign remembers; the files are bytes and nothing else, so a corpus
//     entry outlives the harness that produced it and can be handed to a
//     different tool.
//
//   * A REPRODUCER, written on any finding, into the same format.  This is
//     the step's exit criterion in one sentence - "a new finding arrives as a
//     REPRODUCER rather than as a report" - and the difference is not
//     cosmetic.  A report is a paragraph in a log that somebody has to
//     re-derive; a reproducer is the exact bytes, replayable with one
//     argument, and promotable into the corpus by copying it there.  Sessions
//     20-22 of Ahtung_Disaster_progress.md were spent on a failure that would
//     not reproduce, which is the whole reason this file exists.
//
// CONTENT-ADDRESSED NAMES, and this is the part that makes a corpus usable
// rather than merely large.  A reproducer is named from a hash of its own
// bytes, so:
//   * running the same campaign twice does not accumulate two copies of one
//     input - the second write lands on the same name;
//   * an entry's name is stable across machines, platforms and harness
//     versions, so a corpus file can be cited in a commit message and still
//     mean something a year later;
//   * two different findings never collide into one file.
// The hash is FNV-1a, chosen because it is eight lines and needs no
// dependency.  Nothing here is a security decision - a corpus name is a name.
//
// NO std:: CONTAINERS, for the same reason the harnesses that include it avoid
// them: the MSCS headers #define new as DEBUG_NEW, and template-heavy standard
// headers pulled in afterwards are a hazard in this tree.
//
#ifndef P2P_FUZZ_CORPUS_H
#define P2P_FUZZ_CORPUS_H

#include <cstdio>
#include <cstring>
#include <cstdlib>

#ifdef _WIN32
#  include <windows.h>
#  include <direct.h>
#else
#  include <dirent.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#endif

// The largest single corpus entry.  Bigger than any frame the library will
// accept (m_dwMaxRecvSize is 32768) with room for the deliberately-oversized
// inputs that exist to be refused, and small enough that a corpus of thousands
// is still a directory somebody can look at.
static const unsigned kFuzzCorpusMax = 131072u;

// ---------------------------------------------------------------------------
//  FNV-1a over the bytes.  A NAME, not a checksum: see the header.
// ---------------------------------------------------------------------------
inline unsigned long long FuzzContentHash ( const unsigned char *p, unsigned n )
{
    unsigned long long h = 0xCBF29CE484222325ull;
    for ( unsigned i = 0; i < n; ++i )
    {
        h ^= (unsigned long long)p[i];
        h *= 0x100000001B3ull;
    }
    //  The LENGTH is folded in as well.  Without it a truncation to a
    //  zero-filled tail can collide with the untruncated input, and truncation
    //  is one of the mutator's six operations - so the one case most likely to
    //  collide is also the one most likely to occur.
    h ^= (unsigned long long)n * 0x9E3779B97F4A7C15ull;
    return h;
}

// ---------------------------------------------------------------------------
//  Best-effort mkdir.  Returns true if the directory exists afterwards, by
//  whatever route - already there is a success, not an error, because two
//  harnesses writing into one repro directory is the normal case under a
//  parallel ctest run.
// ---------------------------------------------------------------------------
inline bool FuzzEnsureDir ( const char *pszDir )
{
    if ( !pszDir || !*pszDir ) return false;
#ifdef _WIN32
    if ( CreateDirectoryA ( pszDir, NULL ) ) return true;
    return GetLastError ( ) == ERROR_ALREADY_EXISTS;
#else
    if ( ::mkdir ( pszDir, 0775 ) == 0 ) return true;
    struct stat st;
    return ::stat ( pszDir, &st ) == 0 && S_ISDIR ( st.st_mode );
#endif
}

// ---------------------------------------------------------------------------
//  Read one file into a caller-supplied buffer.
//  Returns the byte count, or 0 on any failure INCLUDING an empty file - a
//  zero-length corpus entry carries no input and is not worth distinguishing
//  from an unreadable one.
//  Oversized files are SKIPPED rather than truncated: a truncated corpus entry
//  is a different input from the one somebody saved, and would replay as a
//  finding that does not exist or hide one that does.
// ---------------------------------------------------------------------------
inline unsigned FuzzReadFile ( const char *pszPath, unsigned char *pBuf, unsigned cbBuf )
{
    FILE *f = 0;
#ifdef _WIN32
    if ( fopen_s ( &f, pszPath, "rb" ) != 0 ) f = 0;
#else
    f = std::fopen ( pszPath, "rb" );
#endif
    if ( !f ) return 0;

    //  One byte more than the buffer, so an oversized file is DETECTED rather
    //  than silently filling it exactly.
    unsigned n = 0;
    if ( cbBuf > 0 )
        n = (unsigned)std::fread ( pBuf, 1, cbBuf, f );
    const bool bMore = std::fgetc ( f ) != EOF;
    std::fclose ( f );

    if ( bMore ) return 0;             // larger than the buffer: skip it whole
    return n;
}

// ---------------------------------------------------------------------------
//  Write bytes to a content-addressed file under pszDir.
//  Returns true on success and fills pszPathOut with what it wrote.
//  Writing over an identical existing file is deliberate and silent: the name
//  is derived from the content, so the file that is already there IS this
//  input.
// ---------------------------------------------------------------------------
inline bool FuzzWriteRepro ( const char *pszDir, const char *pszTag,
                             const unsigned char *p, unsigned n,
                             char *pszPathOut, unsigned cchPathOut )
{
    if ( pszPathOut && cchPathOut ) pszPathOut[0] = 0;
    if ( !pszDir || !*pszDir || !p || n == 0 ) return false;
    if ( !FuzzEnsureDir ( pszDir ) ) return false;

    char szPath[1024];
    std::snprintf ( szPath, sizeof(szPath), "%s/%s-%016llx.bin",
                    pszDir, pszTag ? pszTag : "input",
                    (unsigned long long)FuzzContentHash ( p, n ) );

    FILE *f = 0;
#ifdef _WIN32
    if ( fopen_s ( &f, szPath, "wb" ) != 0 ) f = 0;
#else
    f = std::fopen ( szPath, "wb" );
#endif
    if ( !f ) return false;
    const bool bOk = std::fwrite ( p, 1, n, f ) == n;
    std::fclose ( f );

    if ( bOk && pszPathOut && cchPathOut )
    {
#ifdef _WIN32
        strncpy_s ( pszPathOut, cchPathOut, szPath, _TRUNCATE );
#else
        std::strncpy ( pszPathOut, szPath, cchPathOut - 1 );
        pszPathOut[cchPathOut - 1] = 0;
#endif
    }
    return bOk;
}

// ---------------------------------------------------------------------------
//  Walk a corpus directory, handing every regular file to pfn.
//  Returns the number of files DELIVERED (not the number present): a file that
//  could not be read, or that was too big for the buffer, is skipped and
//  counted in *pnSkipped so the run can say so rather than quietly measuring
//  less than it claims.
//
//  ORDER IS SORTED BY NAME, and that is not tidiness.  A corpus replay is a
//  regression run, and a regression run that visits its inputs in filesystem
//  order reports failure N of M at a different N on a different machine - which
//  is exactly the kind of irreproducibility this whole file exists to refuse.
//  Content-addressed names make the sort stable and meaningless, which is what
//  a deterministic order should be.
// ---------------------------------------------------------------------------
typedef void (*FuzzCorpusFn) ( const char *pszPath,
                               const unsigned char *p, unsigned n,
                               void *pvUser );

//  A fixed cap on the names held for sorting.  A corpus larger than this is
//  not refused - the extra files are skipped and REPORTED, because a fuzzer
//  that quietly stops reading its corpus at entry 4096 would claim coverage it
//  does not have.  Raise it when a corpus grows into it; the number is here to
//  be seen, not to be a policy.
static const unsigned kFuzzCorpusMaxFiles = 4096u;

inline unsigned FuzzCorpusRun ( const char *pszDir, FuzzCorpusFn pfn, void *pvUser,
                                unsigned *pnSkipped, unsigned *pnUnlisted )
{
    if ( pnSkipped )  *pnSkipped  = 0;
    if ( pnUnlisted ) *pnUnlisted = 0;
    if ( !pszDir || !*pszDir || !pfn ) return 0;

    static char s_aNames[kFuzzCorpusMaxFiles][256];
    unsigned nNames = 0;

#ifdef _WIN32
    char szGlob[1024];
    std::snprintf ( szGlob, sizeof(szGlob), "%s/*", pszDir );
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA ( szGlob, &fd );
    if ( hFind == INVALID_HANDLE_VALUE ) return 0;
    do
    {
        if ( fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ) continue;
        //  Dotfiles are skipped on BOTH platforms, and the Windows half is not
        //  cosmetic: a .gitkeep in an empty corpus would otherwise be read,
        //  come back zero-length, and be counted as a SKIPPED file - so the
        //  run would report "1 file skipped" on Windows and nothing on Linux
        //  for a directory that is correctly empty on both.
        if ( fd.cFileName[0] == '.' ) continue;
        if ( nNames >= kFuzzCorpusMaxFiles ) { if ( pnUnlisted ) ++*pnUnlisted; continue; }
        strncpy_s ( s_aNames[nNames], sizeof(s_aNames[0]), fd.cFileName, _TRUNCATE );
        ++nNames;
    } while ( FindNextFileA ( hFind, &fd ) );
    FindClose ( hFind );
#else
    DIR *pDir = ::opendir ( pszDir );
    if ( !pDir ) return 0;
    for ( struct dirent *pE = ::readdir ( pDir ); pE; pE = ::readdir ( pDir ) )
    {
        if ( pE->d_name[0] == '.' ) continue;          // . .. and dotfiles
        char szFull[1024];
        std::snprintf ( szFull, sizeof(szFull), "%s/%s", pszDir, pE->d_name );
        struct stat st;
        if ( ::stat ( szFull, &st ) != 0 || !S_ISREG ( st.st_mode ) ) continue;
        if ( nNames >= kFuzzCorpusMaxFiles ) { if ( pnUnlisted ) ++*pnUnlisted; continue; }
        std::strncpy ( s_aNames[nNames], pE->d_name, sizeof(s_aNames[0]) - 1 );
        s_aNames[nNames][sizeof(s_aNames[0]) - 1] = 0;
        ++nNames;
    }
    ::closedir ( pDir );
#endif

    //  Insertion sort.  n is bounded above by kFuzzCorpusMaxFiles and a corpus
    //  is read once per run, so the simple one is the right one; qsort would
    //  need a comparator and a cast and would buy nothing measurable.
    for ( unsigned i = 1; i < nNames; ++i )
    {
        char szTmp[256];
        std::memcpy ( szTmp, s_aNames[i], sizeof(szTmp) );
        unsigned j = i;
        while ( j > 0 && std::strcmp ( s_aNames[j - 1], szTmp ) > 0 )
        {
            std::memcpy ( s_aNames[j], s_aNames[j - 1], sizeof(szTmp) );
            --j;
        }
        std::memcpy ( s_aNames[j], szTmp, sizeof(szTmp) );
    }

    static unsigned char s_aBuf[kFuzzCorpusMax];
    unsigned nRun = 0;
    for ( unsigned i = 0; i < nNames; ++i )
    {
        char szFull[1024];
        std::snprintf ( szFull, sizeof(szFull), "%s/%s", pszDir, s_aNames[i] );
        const unsigned n = FuzzReadFile ( szFull, s_aBuf, sizeof(s_aBuf) );
        if ( n == 0 ) { if ( pnSkipped ) ++*pnSkipped; continue; }
        pfn ( szFull, s_aBuf, n, pvUser );
        ++nRun;
    }
    return nRun;
}

#endif // P2P_FUZZ_CORPUS_H
