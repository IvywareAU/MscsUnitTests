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
// msgfield_cf.cpp -- the two things a MSG_FIELD view must REFUSE TO COMPILE
// (MsgFieldAccessPlan.md, F2), and the control that proves the refusals are
// about those two things and not about a header that does not build at all.
//
// One source, three targets (see CMakeLists.txt):
//
//   msgfield_cf_control   neither macro: must compile. It is in the normal
//                         build, so a header that stops compiling fails the
//                         build rather than making both negatives pass.
//   msgfield_cf_badtype   MSGFIELD_CF_BADTYPE: `msg->uptime = L"x"`, text into
//                         an int field.
//   msgfield_cf_longname  MSGFIELD_CF_LONGNAME: a 64-character MSG_FIELD name.
//
// The two negatives are EXCLUDE_FROM_ALL and are compiled by their ctest
// entries, which pass only when the build output contains the header's own
// static_assert sentence. That is not WILL_FAIL: a build that wrongly
// SUCCEEDS prints no such sentence and fails the test, and so does a build
// that fails for some other reason.

#include "stdafx.h"

#include "P2Pmsg.h"
#include "MsgFieldRef.hpp"

struct Telemetry : MsgView
{
    MSG_FIELD ( device, std::wstring );
    MSG_FIELD ( uptime, int );
#if defined(MSGFIELD_CF_LONGNAME)
    // 64 characters: one past what a Msgcore name holds.
    MSG_FIELD ( a234567890123456789012345678901234567890123456789012345678901234, int );
#endif
};

void MsgFieldCompileProbe ( P3PmsgItem& item )
{
    MsgViewOf<Telemetry> msg ( item );
    msg->device = L"sensor-04";
    msg->uptime = 86400;
#if defined(MSGFIELD_CF_BADTYPE)
    msg->uptime = L"x";
#endif
}
