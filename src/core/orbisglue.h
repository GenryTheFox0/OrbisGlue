// SPDX-FileCopyrightText: Copyright 2026 GenryTheFox
// SPDX-License-Identifier: GPL-2.0-or-later

// OrbisGlue: a PS4 title linked ahead of time into its own Windows executable.
//
// `shadPS4 --orbisglue-link Game.exe -g <game>/eboot.bin` loads the title as usual -- SELF
// unwrapped, segments mapped at a fixed base, CPU patches applied statically, imports
// relocated -- and, right before the first guest instruction would run, writes a copy of this
// executable with that linked image appended. Game.exe then maps the image back at the same
// addresses and starts the title without unwrapping, patching or translating anything at run
// time. The host executable is linked at a fixed base (/BASE, /DYNAMICBASE:NO), so every host
// address baked into the image (HLE functions, patch helpers) is the same in Game.exe.

#pragma once

#include <filesystem>
#include <span>
#include <string>
#include <vector>

#include "common/types.h"

namespace Core::OrbisGlue {

constexpr const char* Version = "0.1.0";

/// What a linked executable is, as param.sfo had it when it was linked.
struct PortIdentity {
    std::string title;
    std::string app_ver;
    std::string title_id;
};

/// The identity of this executable; empty unless it carries a linked title.
const PortIdentity& Port();

/// A linked executable, told from its footer alone: safe before main, for the static paths.
bool IsPortExecutable();

/// Where a linked executable keeps its data, apart from the emulator's: %APPDATA%/OrbisGlue/<exe>.
std::filesystem::path PortUserDir();

/// First start of a port: copies the title's saves the emulator kept, so play goes on.
void AdoptEmulatorSaves();

/// The name of who is signed in to this PC, for a port's player; empty if unknown.
std::string PlayerName();

/// Where the main executable is placed when linking: far from the low addresses Windows takes
/// differently on every start, so Game.exe finds the same range free.
constexpr u64 ExecutableBase = 0x10000000;

struct LinkedSegment {
    u64 address;
    u64 size;
    std::span<const u8> bytes;
};

struct LinkedModule {
    std::string name;
    u64 base;
    u64 aligned_base_size;
    std::vector<LinkedSegment> segments;
    std::span<const u8> trampolines;
    std::vector<u64> patched;

    const LinkedSegment* FindSegment(u64 address) const;
};

/// Reads the image appended to this executable, if there is one.
bool LoadEmbedded();
bool IsEmbedded();

/// The image's static patches are red-zone protecting ones; the run has to use the same mode.
bool LinkedWithRedZoneProtection();

/// The eboot.bin the embedded image was linked from: next to Game.exe when the exe sits in
/// the game folder, else the folder it was linked from.
std::filesystem::path EmbeddedEbootPath();

/// The linked state of a module, when Game.exe carries it.
const LinkedModule* FindModule(const std::string& name, u64 aligned_base_size);

/// Link mode: the executable to write once the title is linked.
void SetLinkOutput(const std::filesystem::path& out_exe);
bool IsLinking();

/// Link mode: an .ico to give the linked executable instead of the emulator's.
void SetLinkIcon(const std::filesystem::path& ico);

/// Records what the loader did, for the link.
void NoteModule(const std::string& name, u64 base, u64 aligned_base_size, u64 trampoline_base);
void NoteSegment(const std::string& name, u64 address, u64 size);

/// Writes the linked executable. Called once every static module is relocated.
bool WriteLinkedExecutable(const std::filesystem::path& game_folder);

} // namespace Core::OrbisGlue
