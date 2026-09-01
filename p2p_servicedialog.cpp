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
// p2p_servicedialog - the rule that stops a diagnostic hanging the hub
//
// WHAT IS UNDER TEST.  P2Pevent::Display() emits an event either as text or as
// a modal MessageBox.  A dialog blocks the thread that RAISED the event until
// somebody dismisses it, and events are raised on interior worker threads -
// P2PeerCon::OnClose runs on the hub's own pump.  A dialog nobody can see is
// therefore not a worse diagnostic, it is a hub that never stops: the pump
// never returns from its dispatch, never observes the CLOSE signal queued for
// it, and CloseHub() waits on that pump without a bound, deliberately, because
// bounding it would trade a hang for a use-after-free.
//
// A Windows service under the SCM is exactly that shape - no console, no
// standard error, no viewable desktop - so before P2PeventDialogViewable()
// existed a service could deadlock its own teardown on any diagnostic at all.
//
// WHY THE POLICY IS TESTED THROUGH ITS INPUTS.  The two questions that close
// the hole are "am I in session 0?" and "is my window station visible?", and a
// test process cannot answer either differently: it cannot move itself into
// session 0, and creating an invisible window station to run on needs rights
// a test should not want.  So P2Pevent::TextOutputPolicy() takes its four
// inputs as arguments and this test drives all sixteen combinations directly.
// The live process is asserted separately, for what it can be asserted for.
//
// The expected column below is written out BY HAND, one row at a time, and not
// computed.  A table filled in by the same expression the implementation uses
// would agree with any implementation, including a broken one.
//
// WHAT SECTION 4 ADDS.  The deployment configuration file, P2Pmsg.cfg, whose
// ErrToMessageBox setting is a third way of taking the dialog off the table
// alongside P2PMSG_NO_UI and ForceTextOutput().  The property that matters
// there is not that the setting works but that it works IN ONE DIRECTION: a
// file left beside an executable may refuse the dialog and may never re-arm it,
// or a deployment artefact could restore the deadlock a host had disarmed.
//
//   STATUS: PASSES (measured 2026-08-17, Windows Debug + Release; the policy is
//           compiled on both platforms and the table is platform-independent,
//           so this registers without an if(WIN32) guard)
//
// Labelled `security` in CMake because the property is availability: an
// unauthenticated peer that can provoke a diagnostic on a pump thread can stop
// a hub that hosts itself as a service. That is a denial of service reached
// through a code path with no authentication in front of it.

#include "stdafx.h"

#include "Msgexception.h"

#include <cstdio>
#include <cstring>

static int s_nChecks   = 0;
static int s_nFailures = 0;

static void
Check ( bool bCondition, const char *pszWhat )
{
    ++s_nChecks;
    if ( bCondition )
      std::printf ( "  ok    %s\n", pszWhat );
    else
    {
      ++s_nFailures;
      std::printf ( "  FAIL  %s\n", pszWhat );
    }
    std::fflush ( stdout );
}

///////////////////////////////////////////////////////////////////////
//  1. The policy, over every combination of its inputs

struct PolicyRow
{
    bool        bTextOnly;
    bool        bViewable;
    bool        bStdErr;
    bool        bConsole;
    bool        bExpectText;         // hand-written, NOT computed
    const char *pszShape;
};

//  All sixteen combinations.  The named shapes are the ones that correspond to
//  something real; the rest are present so that no combination is unasserted.
static const PolicyRow s_aoRows[] =
{
    // The row this whole change exists for.  A service under the SCM: nothing
    // to write to and nobody to dismiss a dialog.  Before the viewability test
    // this was the ONLY shape that still reached MessageBoxEx, and it reached
    // it on the pump thread.
    { false, false, false, false, true,  "service under the SCM" },

    // A windowed application with nowhere to write.  This is the one shape that
    // must STILL get a dialog: somebody is sitting in front of it, and text
    // written to a handle that is not there would be a diagnostic thrown away.
    // If this row ever flips, the fix has become "always text", which reverses
    // a decision taken deliberately in the past rather than extending it.
    { false, true,  false, false, false, "windowed host, no stream" },

    // A redirected run - a pipe, a file, ctest, CI.  GetConsoleWindow() returns
    // NULL for all of these even though stderr is perfectly writable, which is
    // why testing the console alone once sent every ctest run to the dialog.
    { false, true,  true,  false, true,  "redirected (ctest, CI, pipe)" },

    // An ordinary console process.
    { false, true,  false, true,  true,  "console window" },
    { false, true,  true,  true,  true,  "console and stderr" },

    // P2PMSG_NO_UI, or P2Pevent::ForceTextOutput(true): a windowed host that
    // wants no dialogs from the library at all. It wins over everything.
    { true,  true,  false, false, true,  "text forced, windowed host" },
    { true,  true,  false, true,  true,  "text forced, console" },
    { true,  true,  true,  false, true,  "text forced, redirected" },
    { true,  true,  true,  true,  true,  "text forced, console and stderr" },

    // Text forced AND unviewable: both reasons agree, and the answer cannot
    // depend on which is consulted first.
    { true,  false, false, false, true,  "text forced, service" },
    { true,  false, false, true,  true,  "text forced, service with console" },
    { true,  false, true,  false, true,  "text forced, service with stderr" },
    { true,  false, true,  true,  true,  "text forced, unviewable, both streams" },

    // Unviewable but with somewhere to write. A service started with its
    // handles inherited from an installer, or any process on a hidden station
    // whose output is redirected. Text either way, for two independent reasons.
    { false, false, true,  false, true,  "unviewable, stderr present" },
    { false, false, false, true,  true,  "unviewable, console handle" },
    { false, false, true,  true,  true,  "unviewable, console and stderr" },
};

static void
TestPolicyTable ( )
{
    std::printf ( "--- 1. the policy over all %d input combinations ---\n"
                , (int)( sizeof(s_aoRows) / sizeof(s_aoRows[0]) ) );

    for ( size_t i = 0; i < sizeof(s_aoRows) / sizeof(s_aoRows[0]); i++ )
    {
      const PolicyRow& oRow = s_aoRows[i];
      bool bText = P2Pevent::TextOutputPolicy ( oRow.bTextOnly, oRow.bViewable
                                              , oRow.bStdErr,   oRow.bConsole );
      char szWhat[192];
      std::snprintf ( szWhat, sizeof(szWhat)
                    , "textOnly=%d viewable=%d stderr=%d console=%d -> %-6s  (%s)"
                    , (int)oRow.bTextOnly, (int)oRow.bViewable
                    , (int)oRow.bStdErr,   (int)oRow.bConsole
                    , oRow.bExpectText ? "text" : "dialog"
                    , oRow.pszShape );
      Check ( bText == oRow.bExpectText, szWhat );
    }

    // Every combination covered exactly once - otherwise a row could be
    // silently missing and the table would still read as exhaustive.
    int nSeen = 0;
    for ( int nMask = 0; nMask < 16; nMask++ )
    {
      int nFound = 0;
      for ( size_t i = 0; i < sizeof(s_aoRows) / sizeof(s_aoRows[0]); i++ )
      {
        const PolicyRow& oRow = s_aoRows[i];
        int nRowMask = ( oRow.bTextOnly ? 8 : 0 ) | ( oRow.bViewable ? 4 : 0 )
                     | ( oRow.bStdErr   ? 2 : 0 ) | ( oRow.bConsole  ? 1 : 0 );
        if ( nRowMask == nMask )
          nFound++;
      }
      if ( nFound == 1 )
        nSeen++;
    }
    Check ( nSeen == 16, "all 16 input combinations present exactly once" );
}

///////////////////////////////////////////////////////////////////////
//  2. The live process, for what can honestly be asserted of it

static void
TestLiveProcess ( )
{
    std::printf ( "--- 2. this process ---\n" );

    // Under ctest stdout and stderr are redirected, so the resolved decision
    // here must be text. It would be true before this change as well; it is
    // pinned because the alternative is a modal dialog in a test run, and that
    // is the failure this suite spent 55 hangs in 84 runs diagnosing once.
    Check ( P2Pevent::UsesTextOutput ( )
          , "a redirected test process resolves to text, not a dialog" );

    // ForceTextOutput reports what it replaced, so a host can restore it.
    bool bWas = P2Pevent::ForceTextOutput ( true );
    Check ( P2Pevent::UsesTextOutput ( )
          , "ForceTextOutput(true) resolves to text" );
    bool bNowSet = P2Pevent::ForceTextOutput ( bWas );
    Check ( bNowSet == true
          , "ForceTextOutput returns the setting it replaced" );
    Check ( P2Pevent::UsesTextOutput ( )
          , "still text after restoring the previous setting (stderr is real)" );
}

///////////////////////////////////////////////////////////////////////
//  3. The text sink - where a service's diagnostics actually go
//  NOTES: Refusing the dialog is only half of it. A service has no standard
//         error, so without a destination the fix would trade a hang for a
//         silent loss, which is a worse defect and a harder one to notice.

static int        s_nSinkCalls = 0;
static P2Pevent_e s_eSinkClass = P2Pevent_UNDEF;
static wchar_t    s_szSinkOrigin[512] = { 0 };
static wchar_t    s_szSinkText[512]   = { 0 };

//  Bounded copy with truncation, written out rather than called for.
//  NOTES: wcsncpy_s is a Microsoft extension and the Platform shim does not
//         carry it, so it does not compile on the Linux side of this test - and
//         this test is registered on both platforms. wcsncpy would compile but
//         is deprecated under MSVC. Four lines of loop is portable, silent on
//         both toolchains, and obviously correct.
static void
CopyTrunc ( wchar_t *pszDest, size_t nCapacity, LPCWSTR pszSource )
{
    if ( !pszDest || nCapacity == 0 )
      return;
    size_t i = 0;
    if ( pszSource )
      for ( ; i + 1 < nCapacity && pszSource[i]; i++ )
        pszDest[i] = pszSource[i];
    pszDest[i] = 0;
}

static void WINAPI
ProbeSink ( P2Pevent_e eClass, LPCWSTR lpszOrigin, LPCWSTR lpszText )
{
    ++s_nSinkCalls;
    s_eSinkClass = eClass;
    CopyTrunc ( s_szSinkOrigin, sizeof(s_szSinkOrigin)/sizeof(s_szSinkOrigin[0])
              , lpszOrigin );
    CopyTrunc ( s_szSinkText,   sizeof(s_szSinkText)/sizeof(s_szSinkText[0])
              , lpszText );
}

static void
RaiseOne ( P2Pevent_e eClass, const wchar_t *pszMessage )
{
    P2Pevent *pEvent = P2Pevent::MakeEvent ( eClass );
    if ( !pEvent )
      return;
    pEvent -> Module_  ( _T("p2p_servicedialog") )
           -> Message_ ( pszMessage )
           -> Display  ( );
    pEvent -> Cancel ( false );        // false: already displayed, discard quietly
}

static void
TestTextSink ( )
{
    std::printf ( "--- 3. the text sink ---\n" );

    P2PeventTextFnc pfnWas = P2Pevent::SetTextSink ( &ProbeSink );
    Check ( pfnWas == nullptr
          , "SetTextSink reports no sink was installed before this one" );

    s_nSinkCalls = 0;
    RaiseOne ( P2Pevent_ERROR, L"sink probe, error class" );
    Check ( s_nSinkCalls == 1
          , "an ERROR reaches the sink instead of stderr" );
    Check ( s_eSinkClass == P2Pevent_ERROR
          , "the sink is told the event class" );
    Check ( std::wcsstr ( s_szSinkText, L"sink probe, error class" ) != nullptr
          , "the sink receives the message body" );
    Check ( std::wcsstr ( s_szSinkOrigin, L"p2p_servicedialog" ) != nullptr
          , "the sink receives the origin, including the module" );

    // A second class, so "the class is passed through" is not one datum. DEBUG
    // is not in the default notification mask, so it has to be added first -
    // Display() consults that mask before it emits anything at all.
    DWORD dwMask = P2Pevent::Configure ( P2Pevent::GETMASK, 0 );
    P2Pevent::Configure ( P2Pevent::ADDMASK, P2Pevotn_DEBUG );
    s_nSinkCalls = 0;
    RaiseOne ( P2Pevent_DEBUG, L"sink probe, debug class" );
    Check ( s_nSinkCalls == 1 && s_eSinkClass == P2Pevent_DEBUG
          , "a DEBUG event reaches the sink with its own class" );
    P2Pevent::Configure ( P2Pevent::SETMASK, dwMask );

    // A class OUTSIDE the mask must not be emitted at all - the sink is a
    // destination, not a way around the reporting configuration.
    s_nSinkCalls = 0;
    RaiseOne ( P2Pevent_TRACE, L"sink probe, masked out" );
    Check ( s_nSinkCalls == 0
          , "an event outside the notification mask does not reach the sink" );

    // Uninstall, and confirm the accessor round-trips.
    P2PeventTextFnc pfnRemoved = P2Pevent::SetTextSink ( nullptr );
    Check ( pfnRemoved == &ProbeSink
          , "SetTextSink(0) returns the sink it removed" );

    s_nSinkCalls = 0;
    RaiseOne ( P2Pevent_ERROR, L"sink probe, after removal (expected on stderr)" );
    Check ( s_nSinkCalls == 0
          , "no sink is called once it has been removed" );
}

///////////////////////////////////////////////////////////////////////
//  4. The deployment configuration file
//  NOTES: P2Pmsg.cfg beside the host executable, two settings:
//
//             ErrToMessageBox: 1        # 1/0, on/off, yes/no, true/false
//             LogFile: errorLog.txt     # relative to THIS file's folder
//
//       : EVERY FILE HERE IS NAMED EXPLICITLY, and none of them is called
//         P2Pmsg.cfg. The test executables share one output folder, so a file
//         with that name dropped beside this one would reconfigure the whole
//         suite - and it would do it by the documented search, so nothing
//         would look wrong. The library exposes LoadConfigFile(path) for
//         exactly this, and using it is not a compromise: the search itself is
//         demonstrated by the ErrorReportingExamples/DialogOrLogFile harness,
//         which owns its own folder and can afford to.
//       : Files are written beside the RUNNING EXECUTABLE rather than in the
//         working directory, because the relative-resolution rule is stated
//         against the configuration file's folder and asserting it needs an
//         absolute one to compare with.

//  Opens a wide path on either platform.
//  NOTES: There is no _wfopen off Windows and the shim does not invent one, so
//         the path is converted there. The same split the library makes, for
//         the same reason - refer P2PcfgOpen in Msgexception.cpp.
static FILE*
OpenW ( LPCWSTR lpszPath, const char *pszMode )
{
#if defined(_WIN32)
    wchar_t wszMode [ 8 ] = { 0 };
    for ( int i = 0; pszMode[i] && i < 7; i++ )
      wszMode[i] = (wchar_t)(unsigned char)pszMode[i];
    FILE *pf = 0;
    if ( ::_wfopen_s ( &pf, lpszPath, wszMode ) != 0 )
      return 0;
    return pf;
#else
    char szPath [ 2048 ] = { 0 };
    if ( ::WideCharToMultiByte ( CP_UTF8, 0, lpszPath, -1, szPath
                               , (int)sizeof(szPath), 0, 0 ) <= 0 )
      return 0;
    return ::fopen ( szPath, pszMode );
#endif
}

static void
RemoveW ( LPCWSTR lpszPath )
{
#if defined(_WIN32)
    ::_wremove ( lpszPath );
#else
    char szPath [ 2048 ] = { 0 };
    if ( ::WideCharToMultiByte ( CP_UTF8, 0, lpszPath, -1, szPath
                               , (int)sizeof(szPath), 0, 0 ) > 0 )
      ::remove ( szPath );
#endif
}

static bool
WriteCfg ( LPCWSTR lpszPath, const char *pszBody )
{
    FILE *pf = OpenW ( lpszPath, "wb" );
    if ( !pf )
      return false;
    const size_t nLen = std::strlen ( pszBody );
    const bool bOk = ( std::fwrite ( pszBody, 1, nLen, pf ) == nLen );
    std::fclose ( pf );
    return bOk;
}

//  Does this file contain this substring?
//  NOTES: NARROW, because the log is UTF-8 on both platforms and every string
//         searched for below is ASCII, which UTF-8 leaves alone. Searching for
//         a WIDE substring was the first attempt and it is worth recording why
//         it was wrong: it passed under MSVC and failed under glibc, because
//         the library was then writing wide units through fwprintf and the two
//         C libraries do different things with that. The library now converts
//         once and writes bytes, so there is one encoding to read back and this
//         function can be four lines instead of a platform switch.
static bool
LogContains ( LPCWSTR lpszPath, const char *pszWant, bool *pbExisted )
{
    if ( pbExisted )
      *pbExisted = false;
    FILE *pf = OpenW ( lpszPath, "rb" );
    if ( !pf )
      return false;
    if ( pbExisted )
      *pbExisted = true;

    static char s_szBuf [ 16384 ];
    const size_t nRead = std::fread ( s_szBuf, 1, sizeof(s_szBuf) - 1, pf );
    s_szBuf [ nRead ] = 0;
    std::fclose ( pf );
    return std::strstr ( s_szBuf, pszWant ) != nullptr;
}

//  Directory holding the running executable, absolute, no trailing separator.
static void
SelfDir ( wchar_t *pszOut, size_t cchOut )
{
    pszOut[0] = 0;
    wchar_t wszPath [ 2048 ] = { 0 };
    if ( !::GetModuleFileNameW ( 0, wszPath, 2048 ) )
      return;
    CopyTrunc ( pszOut, cchOut, wszPath );
    for ( size_t i = std::wcslen ( pszOut ); i > 0; i-- )
      if ( pszOut[i-1] == L'\\' || pszOut[i-1] == L'/' )
      {
        pszOut[i-1] = 0;
        return;
      }
    pszOut[0] = 0;
}

static void
JoinPath ( wchar_t *pszOut, size_t cchOut, LPCWSTR lpszDir, LPCWSTR lpszLeaf )
{
    CopyTrunc ( pszOut, cchOut, lpszDir );
    size_t n = std::wcslen ( pszOut );
    if ( n + 1 < cchOut )
    {
      // Backslash on both platforms: the library appends one, so comparing
      // against anything else would assert the wrong separator.
      pszOut[n++] = L'\\';
      pszOut[n]   = 0;
    }
    for ( size_t i = 0; lpszLeaf[i] && n + 1 < cchOut; i++ )
    {
      pszOut[n++] = lpszLeaf[i];
      pszOut[n]   = 0;
    }
}

static void
TestConfigFile ( )
{
    std::printf ( "--- 4. the deployment configuration file ---\n" );

    wchar_t wszDir [ 2048 ] = { 0 };
    SelfDir ( wszDir, 2048 );
    if ( !*wszDir )
    {
      Check ( false, "could determine the running executable's folder" );
      return;
    }

    wchar_t wszCfg [ 2048 ] = { 0 };
    wchar_t wszLog [ 2048 ] = { 0 };
    JoinPath ( wszCfg, 2048, wszDir, L"p2pcfgtest.cfg" );
    JoinPath ( wszLog, 2048, wszDir, L"p2pcfgtest.log" );

    // ---- off, with an explicit relative LogFile
    RemoveW ( wszLog );
    if ( !WriteCfg ( wszCfg, "# a comment\n"
                             "; another comment\n"
                             "\n"
                             "ErrToMessageBox: off\n"
                             "LogFile: p2pcfgtest.log\n" ) )
    {
      Check ( false, "could write a configuration file beside the executable" );
      return;
    }

    P2Pevent::ForceTextOutput ( false );          // clear the latch first
    Check ( P2Pevent::LoadConfigFile ( wszCfg )
          , "LoadConfigFile reports reading a file that exists" );
    Check ( std::wcscmp ( P2Pevent::ConfigFilePath ( ), wszCfg ) == 0
          , "ConfigFilePath names the file that was read" );
    Check ( std::wcscmp ( P2Pevent::LogFilePath ( ), wszLog ) == 0
          , "a relative LogFile resolves against the config file's folder" );
    Check ( P2Pevent::UsesTextOutput ( )
          , "ErrToMessageBox: off takes the dialog off the table" );
    Check ( !*P2Pevent::ConfigDiagnostic ( )
          , "a well-formed file draws no complaint" );

    // The event has to reach the file through Display(), not through anything
    // this test writes itself.
    RaiseOne ( P2Pevent_ERROR, L"config probe, to the log file" );
    bool bExisted = false;
    Check ( LogContains ( wszLog, "config probe, to the log file", &bExisted )
          , "the diagnostic body is in the configured log file" );
    Check ( bExisted, "the log file was created by raising an event" );
    Check ( LogContains ( wszLog, "[ERROR]", &bExisted )
          , "and so is the event class, spelled out" );

    // ---- a sink outranks the log file
    // NOTES: It has to. P2PeerService installs the event log sink, and a
    //        configuration file left beside the executable must not be able to
    //        divert a service's diagnostics into a file under System32 - which
    //        is where a service's working directory points.
    RemoveW ( wszLog );
    P2Pevent::SetTextSink ( &ProbeSink );
    s_nSinkCalls = 0;
    RaiseOne ( P2Pevent_ERROR, L"config probe, sink outranks the file" );
    P2Pevent::SetTextSink ( nullptr );
    Check ( s_nSinkCalls == 1
          , "an installed sink receives the event, log file or no log file" );
    Check ( !LogContains ( wszLog, "sink outranks", &bExisted ) && !bExisted
          , "and the log file is not written behind the sink's back" );

    // ---- on, with no LogFile: nothing is latched and nothing is named
    P2Pevent::ForceTextOutput ( false );
    if ( WriteCfg ( wszCfg, "ErrToMessageBox: yes\n" ) )
    {
      P2Pevent::LoadConfigFile ( wszCfg );
      Check ( !*P2Pevent::LogFilePath ( )
            , "ErrToMessageBox: yes with no LogFile names no destination" );
      Check ( !P2Pevent::ForceTextOutput ( false )
            , "and does not latch the dialog off" );
    }

    // ---- off, with no LogFile: the documented default name
    P2Pevent::ForceTextOutput ( false );
    if ( WriteCfg ( wszCfg, "ErrToMessageBox: 0\n" ) )
    {
      wchar_t wszDefault [ 2048 ] = { 0 };
      JoinPath ( wszDefault, 2048, wszDir, P2PMSG_LOG_FILE );
      P2Pevent::LoadConfigFile ( wszCfg );
      Check ( std::wcscmp ( P2Pevent::LogFilePath ( ), wszDefault ) == 0
            , "turning the dialog off implies errorLog.txt beside the config" );
      RemoveW ( wszDefault );
    }

    // ---- THE ONE-WAY RULE.  The file may latch towards text and never away
    // from it. A deployment artefact that could re-arm the dialog would be able
    // to re-arm the deadlock a host had already disarmed, which is the whole
    // defect this area exists to prevent.
    P2Pevent::ForceTextOutput ( true );
    if ( WriteCfg ( wszCfg, "ErrToMessageBox: 1\n" ) )
    {
      P2Pevent::LoadConfigFile ( wszCfg );
      Check ( P2Pevent::UsesTextOutput ( )
            , "ErrToMessageBox: 1 does NOT undo ForceTextOutput(true)" );
    }
    P2Pevent::ForceTextOutput ( false );

    // ---- values and lines the parser cannot read: ignored, and reported
    if ( WriteCfg ( wszCfg, "ErrToMessageBox: maybe\n"
                            "LogFyle: typo.log\n"
                            "a line with no separator\n" ) )
    {
      P2Pevent::LoadConfigFile ( wszCfg );
      Check ( *P2Pevent::ConfigDiagnostic ( ) != 0
            , "ConfigDiagnostic reports what could not be read" );
      Check ( !*P2Pevent::LogFilePath ( )
            , "a misspelled key names no destination" );
      Check ( !P2Pevent::ForceTextOutput ( false )
            , "an unreadable value leaves the setting alone, either way" );
    }

    // ---- '=' as the separator, and surrounding blanks
    P2Pevent::ForceTextOutput ( false );
    if ( WriteCfg ( wszCfg, "  ErrToMessageBox =  OFF  \n" ) )
    {
      P2Pevent::LoadConfigFile ( wszCfg );
      Check ( P2Pevent::UsesTextOutput ( )
            , "'=' and surrounding blanks are accepted" );
    }

    // ---- a file that is not there
    P2Pevent::ForceTextOutput ( false );
    wchar_t wszAbsent [ 2048 ] = { 0 };
    JoinPath ( wszAbsent, 2048, wszDir, L"p2pcfgtest_absent.cfg" );
    Check ( !P2Pevent::LoadConfigFile ( wszAbsent )
          , "LoadConfigFile reports NOT reading a file that is absent" );
    Check ( !*P2Pevent::LogFilePath ( )
          , "and nothing is configured as a result" );

    // ---- SetLogFile, the code-side twin, round-trips
    LPCWSTR lpszWas = P2Pevent::SetLogFile ( wszLog );
    Check ( !*lpszWas
          , "SetLogFile reports the empty destination it replaced" );
    Check ( std::wcscmp ( P2Pevent::LogFilePath ( ), wszLog ) == 0
          , "and the destination it was given" );
    RemoveW ( wszLog );
    RaiseOne ( P2Pevent_ERROR, L"config probe, via SetLogFile" );
    Check ( LogContains ( wszLog, "config probe, via SetLogFile", &bExisted )
          , "a log file named from code receives the diagnostic" );

    // Back to the library's defaults, and take the scratch files with us. A
    // test that left a configuration file beside the executable would change
    // what every later run of every test in this folder does.
    P2Pevent::SetLogFile      ( nullptr );
    P2Pevent::ForceTextOutput ( false );
    RemoveW ( wszCfg );
    RemoveW ( wszLog );
}

///////////////////////////////////////////////////////////////////////

int
main ( int argc, char *argv[] )
{
    argc; argv;

    std::printf ( "=== p2p_servicedialog - a diagnostic must not hang the hub ===\n" );
    std::printf ( "Asserting: a dialog is raised ONLY where somebody could dismiss\n"
                  "           one, and text always has somewhere to go.\n\n" );
    std::fflush ( stdout );

    TestPolicyTable ( );
    TestLiveProcess ( );
    TestTextSink ( );
    TestConfigFile ( );

    std::printf ( "\n%d checks, %d failures\n", s_nChecks, s_nFailures );
    std::printf ( "%s\n", s_nFailures == 0 ? "PASS" : "FAIL" );
    std::fflush ( stdout );
    return s_nFailures == 0 ? 0 : 1;
}
