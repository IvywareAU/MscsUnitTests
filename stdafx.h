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
// stdafx.h : precompiled header for MscsUnitTests
//
// Mirrors the include surface used by the shipped MSCS sample harnesses
// (see _TargetCore_UseExamples\LocalInMemoryTest) so the Msgcore / TargetCore
// headers compile in a consuming project.
#pragma once

#include "Targetver.h"

#pragma warning(disable:4251)   // dll-interface warnings from the exported classes

#define WIN32_LEAN_AND_MEAN

#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS
#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN
#endif

#include <afx.h>
#include <afxwin.h>
#include <afxext.h>
#include <afxmt.h>
#include <afxtempl.h>
#include <comutil.h>

// The Msgcore/TargetCore public headers now route Win32 types AND the pinned
// serialized-data element type (P2PWCHAR, LinuxPortPlan §4.2) through the platform
// shim layer. Consuming projects must include it too, exactly as Msgcore's own
// stdafx.h does, or headers like P2PmsgVBLock.h fail to compile (undefined
// P2PWCHAR). On _WIN32 platform.h is pure pass-through, so this is a no-op for the
// Windows build beyond making that typedef visible.
//
// The shim layer lives in the Msgcore repository, at Msgcore/Platform/. It was a
// repository of its own until 2026-09-03; that one is retired, and this is the only
// copy in the tree.
#include "../Msgcore/Platform/platform.h"

#include <WinSock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>

#include <stdlib.h>
#include <stdio.h>
#include <tchar.h>
#include <map>
#include <list>
#include <string>
