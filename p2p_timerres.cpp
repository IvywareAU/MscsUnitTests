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
// p2p_timerres.cpp - does a 50 ms PITimer fire 50 ms after it is set?
//
// BACKGROUND - MSCS performance plan T8 (p2p_performance.md §5). Until Targetcore
// 3.7.6 every timer deadline was _time64(0)*1000 + delay: wall-clock SECONDS
// scaled to milliseconds. The pump fires a timer once deadline - now <= 0, and
// "now" only moved once a second, so a timer armed at s + f (f the fraction of
// the second already gone) with delay d < 1000 fired when the second turned:
// 1000 - f ms later, anywhere from ~0 to 1000 ms, whatever d was. A 50 ms
// keepalive could fire after 3 ms or after 990. A wall-clock step moved every
// deadline with it as well.
//
// WHAT IT DOES - a plain hub, no connections, auth off. On its own pump thread
// (RunHub) it arms a 50 ms timer; each On_PITimer records how long the timer
// took on a monotonic clock and re-arms, ten fires in all.
//
//   Positive control: the timers fire at all, ten times within 15 s. If they do
//   not, nothing below is a timing statement (INCONCLUSIVE).
//
//   The requirement: every fire lands in [49, 250] ms. 49, not 50, for one
//   millisecond of quantisation between the two clocks; 250 leaves room for a
//   loaded CI box and a 15.6 ms Windows timer tick and is still a quarter of
//   what the old clock's error could reach. On the old clock ten consecutive
//   fires all inside that window would take re-arming within ~200 ms of a
//   second's start every time - it is red there.
//
// VERDICT = process EXIT CODE:
//   0  PASS          ten fires, each 49..250 ms
//   1  FAIL          a fire outside the window
//   2  SETUP         StartupP2Pmsg / SpawnHub failed
//   3  INCONCLUSIVE  fewer than ten fires in 15 s (the positive control)

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "Msgexception.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <mutex>
#include <thread>
#include <vector>

using Clock = std::chrono::steady_clock;

static const int        kDelayMs = 50;
static const int        kFires   = 10;
static const long long  kLowMs   = 49;
static const long long  kHighMs  = 250;

static void Log ( const char *msg )
{
    std::printf ( "%s\n", msg );
    std::fflush ( stdout );
}

class TimerHub : public P2PeerHub
{
    public:
        TimerHub ( ) : P2PeerHub ( L"Timer.Res" ) { }
       ~TimerHub ( ) { CloseHub ( ); }

      std::mutex             m_oLock;
      std::vector<long long> m_vMs;          // one entry per fire, milliseconds
      std::atomic<int>       m_nFires { 0 };
      std::atomic<int>       m_nCancels { 0 };
      Clock::time_point      m_tArmed;      // pump thread only

      void Arm ( )
      {
          m_tArmed = Clock::now ( );
          SetPITimer ( kDelayMs, 0x7E57 );
      }
      virtual void RunHub ( ) override
      {
          Arm ( );                          // on the hub's own pump: pump id 0
          P2PeerHub::RunHub ( );
      }
      virtual void On_PITimer ( bool bCancel, PITimerID, DWORD dwUserKey ) override
      {
          if ( bCancel || dwUserKey != 0x7E57 )
          {
              m_nCancels.fetch_add ( 1 );
              return;
          }
          const long long ms = std::chrono::duration_cast<std::chrono::milliseconds> (
                                   Clock::now ( ) - m_tArmed ).count ( );
          {
              std::lock_guard<std::mutex> lk ( m_oLock );
              m_vMs.push_back ( ms );
          }
          if ( m_nFires.fetch_add ( 1 ) + 1 < kFires )
              Arm ( );
      }
};

int main ( int, char *[] )
{
    Log ( "p2p_timerres: a 50 ms PITimer fires 50 ms after it is set (T8)" );
    if ( !StartupP2Pmsg ( 8 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }

    TimerHub *pHub = new TimerHub ( );
    pHub -> RequireAuth ( false );
    pHub -> RequireSeal ( false );
    HANDLE hThread = pHub -> SpawnHub ( );
    if ( !hThread ) { Log ( "SETUP: SpawnHub() failed" ); delete pHub; CleanupP2Pmsg ( ); return 2; }

    const Clock::time_point tGiveUp = Clock::now ( ) + std::chrono::seconds ( 15 );
    while ( pHub->m_nFires.load ( ) < kFires && Clock::now ( ) < tGiveUp )
        std::this_thread::sleep_for ( std::chrono::milliseconds ( 10 ) );

    std::vector<long long> vMs;
    {
        std::lock_guard<std::mutex> lk ( pHub->m_oLock );
        vMs = pHub->m_vMs;
    }
    pHub -> CloseHub ( );
    delete pHub;
    WaitForSingleObject ( hThread, 5000 );
    CloseHandle ( hThread );
    CleanupP2Pmsg ( );

    if ( (int)vMs.size ( ) < kFires )
    {
        std::printf ( "INCONCLUSIVE: %d of %d timer fires in 15 s\n", (int)vMs.size ( ), kFires );
        return 3;
    }

    int nFail = 0;
    for ( size_t i = 0; i < vMs.size ( ); ++i )
    {
        const bool bOk = vMs[i] >= kLowMs && vMs[i] <= kHighMs;
        std::printf ( "  %s  fire %2d: %lld ms\n", bOk ? "ok  " : "FAIL", (int)i + 1, vMs[i] );
        if ( !bOk ) ++nFail;
    }
    std::printf ( "%d of %d fires outside [%lld, %lld] ms for a %d ms timer\n"
                , nFail, kFires, kLowMs, kHighMs, kDelayMs );
    Log ( nFail ? "FAIL" : "PASS" );
    return nFail ? 1 : 0;
}
