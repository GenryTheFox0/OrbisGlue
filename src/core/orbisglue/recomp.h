// SPDX-FileCopyrightText: Copyright 2026 GenryTheFox
// SPDX-License-Identifier: GPL-2.0-or-later

// Mosaic Recompilation, the runtime side: the title's functions lifted to C by OGlue's
// tools/recomp64 come in a DLL; this loads it and, in test mode, proves each lifted function
// against the original machine code it replaces.

#pragma once

#include <filesystem>

#include "common/types.h"

namespace Core::OrbisGlue::Recomp {

/// `--orbisglue-difftest <dll>`: once the title is loaded, run every lifted function of the DLL
/// against the original on random inputs, print the score, and exit.
void SetDifftest(const std::filesystem::path& dll);
bool IsDifftest();

/// Runs the test. Called where the linker would start the title.
[[noreturn]] void RunDifftest(u64 image_base);

/// `--orbisglue-mosaic <dll>`: play the title on its lifted functions. The main thread and every
/// thread the title starts enter lifted code; whatever is not lifted (and callbacks the system
/// makes into the title) still runs as the original machine code.
void SetMosaicRun(const std::filesystem::path& dll);
bool IsMosaicRun();

/// The title's entry, as the linker's RunMainEntry would make it -- on lifted code. Returns
/// (false) only when the entry is not lifted, for the original to start instead.
bool RunMainLifted(void* params, u64 entry, void* exit_func, u64 image_base);

/// A title thread's start routine on lifted code, if it is lifted (else false, `ret` untouched).
bool RunThreadLifted(void* arg, void* start, void* stack_top, void** ret);

} // namespace Core::OrbisGlue::Recomp
