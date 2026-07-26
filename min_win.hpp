// SPDX-FileCopyrightText: 2026 Paracelsus83
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once


#if !defined(_68K_) && !defined(_MPPC_) && !defined(_X86_) && !defined(_IA64_) && !defined(_AMD64_)

#if defined(_M_IX86)
#define _X86_
#elif defined(_M_AMD64)
#define _AMD64_
#endif

#endif

#include <WinDef.h>
#include <WinNT.h>
