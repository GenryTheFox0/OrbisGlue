// SPDX-FileCopyrightText: Copyright 2026 GenryTheFox
// SPDX-License-Identifier: GPL-2.0-or-later

#include <cstring>
#include <fstream>
#include <iterator>
#include <mutex>

#include "common/logging/log.h"
#include "common/path_util.h"
#include "common/singleton.h"
#include "core/cpu_patches.h"
#include "core/file_format/psf.h"
#include "core/orbisglue.h"

#ifdef _WIN32
#include <windows.h>
#endif

namespace Core::OrbisGlue {

namespace {

// Image appended to the executable, then a footer: offset and size of the image, magic.
constexpr char ImageMagic[8] = {'O', 'G', 'L', 'U', 'E', 'I', 'M', 'G'};
constexpr char FooterMagic[8] = {'O', 'G', 'L', 'U', 'E', 'E', 'N', 'D'};
constexpr u32 ImageVersion = 2; // 2: the port's identity in front
constexpr u32 FlagRedZone = 1;
constexpr u64 FooterSize = 24;

struct NotedModule {
    std::string name;
    u64 base;
    u64 aligned_base_size;
    u64 trampoline_base;
    std::vector<std::pair<u64, u64>> segments;
};

std::vector<u8> s_image;
std::vector<LinkedModule> s_modules;
std::filesystem::path s_linked_folder;
u64 s_linked_tcb_key{};
u32 s_linked_flags{};
bool s_embedded{};
PortIdentity s_port;

std::filesystem::path s_link_output;
std::filesystem::path s_link_icon;
std::vector<NotedModule> s_noted;
std::mutex s_noted_mutex;

std::filesystem::path OwnExecutable() {
#ifdef _WIN32
    std::wstring path(MAX_PATH, L'\0');
    for (;;) {
        const DWORD len = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (len == 0) {
            return {};
        }
        if (len < path.size()) {
            path.resize(len);
            return path;
        }
        path.resize(path.size() * 2);
    }
#else
    std::error_code ec;
    return std::filesystem::read_symlink("/proc/self/exe", ec);
#endif
}

class Reader {
public:
    explicit Reader(std::span<const u8> data_) : data{data_} {}

    template <typename T>
    T Get() {
        T value{};
        if (pos + sizeof(T) > data.size()) {
            ok = false;
            return value;
        }
        std::memcpy(&value, data.data() + pos, sizeof(T));
        pos += sizeof(T);
        return value;
    }

    std::span<const u8> Bytes(u64 size) {
        if (size > data.size() - pos) {
            ok = false;
            return {};
        }
        auto bytes = data.subspan(pos, size);
        pos += size;
        return bytes;
    }

    std::string String() {
        const auto bytes = Bytes(Get<u32>());
        return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
    }

    bool ok{true};

private:
    std::span<const u8> data;
    u64 pos{};
};

class Writer {
public:
    template <typename T>
    void Put(const T& value) {
        const auto* p = reinterpret_cast<const u8*>(&value);
        out.insert(out.end(), p, p + sizeof(T));
    }

    void Bytes(const void* p, u64 size) {
        const auto* b = static_cast<const u8*>(p);
        out.insert(out.end(), b, b + size);
    }

    void String(const std::string& s) {
        Put(static_cast<u32>(s.size()));
        Bytes(s.data(), s.size());
    }

    std::vector<u8> out;
};

#ifdef _WIN32
// The wide resource types: this target is not built with UNICODE, RT_ICON is the narrow one.
const LPCWSTR kRtIcon = MAKEINTRESOURCEW(3);
const LPCWSTR kRtGroupIcon = MAKEINTRESOURCEW(14);
const LPCWSTR kRtVersion = MAKEINTRESOURCEW(16);

std::wstring Wide(const std::string& s) {
    if (s.empty()) {
        return {};
    }
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(n), L' ');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

// One node of a VS_VERSIONINFO tree: length, value length, type, key, value, children; every
// part on a 4-byte boundary.
std::vector<u8> VersionNode(const std::wstring& key, WORD type, const void* value,
                            WORD value_length, size_t value_bytes,
                            const std::vector<std::vector<u8>>& children) {
    std::vector<u8> b;
    const auto put16 = [&](WORD v) {
        b.push_back(static_cast<u8>(v));
        b.push_back(static_cast<u8>(v >> 8));
    };
    const auto align = [&] {
        while (b.size() % 4) {
            b.push_back(0);
        }
    };
    put16(0);
    put16(value_length);
    put16(type);
    for (const wchar_t c : key) {
        put16(static_cast<WORD>(c));
    }
    put16(0);
    align();
    if (value_bytes) {
        const auto* v = static_cast<const u8*>(value);
        b.insert(b.end(), v, v + value_bytes);
    }
    for (const auto& c : children) {
        align();
        b.insert(b.end(), c.begin(), c.end());
    }
    const WORD len = static_cast<WORD>(b.size());
    std::memcpy(b.data(), &len, 2);
    return b;
}

std::vector<u8> VersionString(const std::wstring& key, const std::wstring& value) {
    return VersionNode(key, 1, value.c_str(), static_cast<WORD>(value.size() + 1),
                       (value.size() + 1) * sizeof(wchar_t), {});
}

// The linked game's VERSIONINFO: its own name and version where the emulator's were.
std::vector<u8> PortVersionInfo(const PortIdentity& id, const std::wstring& exe_name) {
    unsigned major = 0, minor = 0;
    std::sscanf(id.app_ver.c_str(), "%u.%u", &major, &minor);
    struct {
        DWORD signature = 0xFEEF04BD, struc_version = 0x00010000;
        DWORD file_ms = 0, file_ls = 0, product_ms = 0, product_ls = 0;
        DWORD flags_mask = 0x3F, flags = 0, os = 0x40004, type = 1, subtype = 0;
        DWORD date_ms = 0, date_ls = 0;
    } fixed;
    fixed.file_ms = fixed.product_ms = (major << 16) | (minor & 0xFFFF);
    const std::wstring title = Wide(id.title.empty() ? id.title_id : id.title);
    const std::wstring ver = Wide(id.app_ver);
    const std::wstring glue = Wide(std::string("OrbisGlue ") + Version);
    const std::vector<std::vector<u8>> strings = {
        VersionString(L"CompanyName", L"OrbisGlue"),
        VersionString(L"FileDescription", title),
        VersionString(L"FileVersion", ver),
        VersionString(L"InternalName", Wide(id.title_id)),
        VersionString(L"LegalCopyright", glue + L", runtime: shadPS4 (GPL-2.0-or-later)"),
        VersionString(L"OriginalFilename", exe_name),
        VersionString(L"ProductName", title),
        VersionString(L"ProductVersion", ver),
        VersionString(L"Comments",
                      L"PlayStation 4 " + Wide(id.title_id) + L" v" + ver + L", linked by " + glue),
    };
    const DWORD translation = 0x04B00409;
    const auto table = VersionNode(L"040904b0", 1, nullptr, 0, 0, strings);
    const auto string_info = VersionNode(L"StringFileInfo", 1, nullptr, 0, 0, {table});
    const auto var = VersionNode(L"Translation", 0, &translation, 4, 4, {});
    const auto var_info = VersionNode(L"VarFileInfo", 1, nullptr, 0, 0, {var});
    return VersionNode(L"VS_VERSION_INFO", 0, &fixed, sizeof(fixed), sizeof(fixed),
                       {string_info, var_info});
}

// A resource name as Enum*/Update* take it: "#12" for an integer id, else the string itself.
LPCWSTR ResourceId(const std::wstring& name) {
    return name[0] == L'#' ? MAKEINTRESOURCEW(std::stoi(name.substr(1))) : name.c_str();
}

WORD ResourceLanguage(HMODULE module, LPCWSTR type, LPCWSTR name) {
    WORD lang = 0;
    EnumResourceLanguagesW(
        module, type, name,
        [](HMODULE, LPCWSTR, LPCWSTR, WORD l, LONG_PTR param) -> BOOL {
            *reinterpret_cast<WORD*>(param) = l;
            return FALSE;
        },
        reinterpret_cast<LONG_PTR>(&lang));
    return lang;
}

// Gives a copied executable the game's face. The icon: every RT_ICON of the original goes, the
// images of the .ico come in, the group keeps the original's name and language so Explorer finds
// it. The version: the game's name and version instead of the emulator's.
bool UpdatePortResources(const std::filesystem::path& exe, const std::filesystem::path& ico,
                         const PortIdentity& id) {
    std::vector<u8> file;
    u16 count = 0;
    if (!ico.empty()) {
        std::ifstream in{ico, std::ios::binary};
        file.assign(std::istreambuf_iterator<char>(in), {});
        if (file.size() < 6 || file[2] != 1 || file[3] != 0) {
            LOG_ERROR(Core_Linker, "OrbisGlue: {} is not an .ico", Common::FS::PathToUTF8String(ico));
        } else {
            count = static_cast<u16>(file[4] | (file[5] << 8));
            if (file.size() < 6 + 16ull * count) {
                count = 0;
            }
        }
    }

    std::wstring group_name;
    WORD group_lang = 0;
    std::vector<WORD> old_icons;
    WORD icon_lang = 0;
    WORD version_lang = 0;
    if (HMODULE src = LoadLibraryExW(exe.c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE)) {
        EnumResourceNamesW(
            src, kRtGroupIcon,
            [](HMODULE, LPCWSTR, LPWSTR name, LONG_PTR param) -> BOOL {
                auto* out = reinterpret_cast<std::wstring*>(param);
                *out = IS_INTRESOURCE(name)
                           ? L"#" + std::to_wstring(reinterpret_cast<uintptr_t>(name))
                           : std::wstring{name};
                return FALSE;
            },
            reinterpret_cast<LONG_PTR>(&group_name));
        EnumResourceNamesW(
            src, kRtIcon,
            [](HMODULE, LPCWSTR, LPWSTR name, LONG_PTR param) -> BOOL {
                if (IS_INTRESOURCE(name)) {
                    reinterpret_cast<std::vector<WORD>*>(param)->push_back(
                        static_cast<WORD>(reinterpret_cast<uintptr_t>(name)));
                }
                return TRUE;
            },
            reinterpret_cast<LONG_PTR>(&old_icons));
        if (!group_name.empty()) {
            group_lang = ResourceLanguage(src, kRtGroupIcon, ResourceId(group_name));
        }
        if (!old_icons.empty()) {
            icon_lang = ResourceLanguage(src, kRtIcon, MAKEINTRESOURCEW(old_icons.front()));
        }
        version_lang = ResourceLanguage(src, kRtVersion, MAKEINTRESOURCEW(1));
        FreeLibrary(src);
    }
    if (group_name.empty()) {
        group_name = L"IDI_ICON1";
    }

    HANDLE upd = BeginUpdateResourceW(exe.c_str(), FALSE);
    if (!upd) {
        return false;
    }
    auto version = PortVersionInfo(id, exe.filename().wstring());
    bool ok = UpdateResourceW(upd, kRtVersion, MAKEINTRESOURCEW(1), version_lang, version.data(),
                              static_cast<DWORD>(version.size())) != FALSE;
    if (count == 0) {
        return EndUpdateResourceW(upd, !ok) != FALSE && ok;
    }
    for (const WORD old : old_icons) {
        UpdateResourceW(upd, kRtIcon, MAKEINTRESOURCEW(old), icon_lang, nullptr, 0);
    }
    std::vector<u8> group(6 + 14ull * count);
    std::memcpy(group.data(), file.data(), 6);
    for (u16 i = 0; i < count && ok; i++) {
        const u8* e = file.data() + 6 + 16ull * i;
        u32 size, offset;
        std::memcpy(&size, e + 8, 4);
        std::memcpy(&offset, e + 12, 4);
        if (static_cast<u64>(offset) + size > file.size()) {
            ok = false;
            break;
        }
        const WORD icon_id = static_cast<WORD>(i + 1);
        ok = UpdateResourceW(upd, kRtIcon, MAKEINTRESOURCEW(icon_id), icon_lang, file.data() + offset,
                             size) != FALSE;
        u8* g = group.data() + 6 + 14ull * i;
        std::memcpy(g, e, 12); // width, height, colors, reserved, planes, bit count, bytes
        std::memcpy(g + 12, &icon_id, 2);
    }
    ok = ok && UpdateResourceW(upd, kRtGroupIcon, ResourceId(group_name), group_lang,
                               group.data(), static_cast<DWORD>(group.size())) != FALSE;
    return EndUpdateResourceW(upd, !ok) != FALSE && ok;
}
#endif

bool ParseImage() {
    Reader r{s_image};
    const auto magic = r.Bytes(sizeof(ImageMagic));
    if (!r.ok || std::memcmp(magic.data(), ImageMagic, sizeof(ImageMagic)) != 0) {
        return false;
    }
    if (r.Get<u32>() != ImageVersion) {
        return false;
    }
    s_port.title_id = r.String();
    s_port.title = r.String();
    s_port.app_ver = r.String();
    const u32 count = r.Get<u32>();
    s_linked_flags = r.Get<u32>();
    s_linked_tcb_key = r.Get<u64>();
    const auto folder = r.String();
    s_linked_folder = std::filesystem::path{std::u8string(folder.begin(), folder.end())};
    for (u32 i = 0; i < count && r.ok; i++) {
        auto& m = s_modules.emplace_back();
        m.name = r.String();
        m.base = r.Get<u64>();
        m.aligned_base_size = r.Get<u64>();
        const u32 segments = r.Get<u32>();
        for (u32 s = 0; s < segments && r.ok; s++) {
            const u64 address = r.Get<u64>();
            const u64 size = r.Get<u64>();
            m.segments.push_back({address, size, r.Bytes(size)});
        }
        m.trampolines = r.Bytes(r.Get<u64>());
        const u32 patched = r.Get<u32>();
        for (u32 p = 0; p < patched && r.ok; p++) {
            m.patched.push_back(r.Get<u64>());
        }
    }
    return r.ok;
}

} // namespace

const LinkedSegment* LinkedModule::FindSegment(u64 address) const {
    for (const auto& segment : segments) {
        if (segment.address == address) {
            return &segment;
        }
    }
    return nullptr;
}

bool LoadEmbedded() {
    // The TCB patches bake the host TLS slot in; take it first thing, before SDL, the Vulkan
    // driver and the rest allocate theirs, so linking and playing get the same one.
    GetPatchTcbKey();

    const auto exe = OwnExecutable();
    std::ifstream file{exe, std::ios::binary};
    if (!file) {
        return false;
    }
    file.seekg(0, std::ios::end);
    const u64 file_size = static_cast<u64>(file.tellg());
    if (file_size < FooterSize) {
        return false;
    }
    u8 footer[FooterSize];
    file.seekg(static_cast<std::streamoff>(file_size - FooterSize));
    file.read(reinterpret_cast<char*>(footer), FooterSize);
    if (!file || std::memcmp(footer + 16, FooterMagic, sizeof(FooterMagic)) != 0) {
        return false;
    }
    u64 offset, size;
    std::memcpy(&offset, footer, 8);
    std::memcpy(&size, footer + 8, 8);
    if (offset + size + FooterSize != file_size) {
        return false;
    }
    s_image.resize(size);
    file.seekg(static_cast<std::streamoff>(offset));
    file.read(reinterpret_cast<char*>(s_image.data()), static_cast<std::streamsize>(size));
    if (!file || !ParseImage()) {
        s_image.clear();
        s_modules.clear();
        return false;
    }
    s_embedded = true;
    return true;
}

bool IsEmbedded() {
    return s_embedded;
}

const PortIdentity& Port() {
    return s_port;
}

bool IsPortExecutable() {
    static const bool port = [] {
        std::ifstream file{OwnExecutable(), std::ios::binary};
        if (!file) {
            return false;
        }
        file.seekg(-static_cast<std::streamoff>(FooterSize), std::ios::end);
        u8 footer[FooterSize];
        file.read(reinterpret_cast<char*>(footer), FooterSize);
        return file && std::memcmp(footer + 16, FooterMagic, sizeof(FooterMagic)) == 0;
    }();
    return port;
}

// The title id at the front of the image, read from the file alone (before main).
static std::string ImageTitleId() {
    std::ifstream file{OwnExecutable(), std::ios::binary};
    if (!file) {
        return {};
    }
    file.seekg(-static_cast<std::streamoff>(FooterSize), std::ios::end);
    u8 footer[FooterSize];
    file.read(reinterpret_cast<char*>(footer), FooterSize);
    if (!file || std::memcmp(footer + 16, FooterMagic, sizeof(FooterMagic)) != 0) {
        return {};
    }
    u64 offset;
    std::memcpy(&offset, footer, 8);
    file.seekg(static_cast<std::streamoff>(offset));
    char magic[sizeof(ImageMagic)];
    u32 version = 0, len = 0;
    file.read(magic, sizeof(magic));
    file.read(reinterpret_cast<char*>(&version), 4);
    file.read(reinterpret_cast<char*>(&len), 4);
    if (!file || std::memcmp(magic, ImageMagic, sizeof(magic)) != 0 || version < 2 || len > 64) {
        return {};
    }
    std::string id(len, ' ');
    file.read(id.data(), len);
    return file ? id : std::string{};
}

std::filesystem::path PortUserDir() {
#ifdef _WIN32
    const wchar_t* appdata = _wgetenv(L"APPDATA");
    const std::filesystem::path root =
        appdata ? std::filesystem::path{appdata} : OwnExecutable().parent_path();
#else
    const char* home = getenv("HOME");
    const std::filesystem::path root =
        home ? std::filesystem::path{home} / ".local" / "share" : OwnExecutable().parent_path();
#endif
    // by the game's id, not the file's name: a renamed exe keeps its saves
    const auto id = ImageTitleId();
    return root / "OrbisGlue" / (id.empty() ? OwnExecutable().stem().string() : id);
}

std::string PlayerName() {
#ifdef _WIN32
    wchar_t buf[257];
    DWORD len = 257;
    if (!GetUserNameW(buf, &len) || len <= 1) {
        return {};
    }
    const int n = static_cast<int>(len - 1);
    const int bytes = WideCharToMultiByte(CP_UTF8, 0, buf, n, nullptr, 0, nullptr, nullptr);
    std::string name(static_cast<size_t>(bytes), ' ');
    WideCharToMultiByte(CP_UTF8, 0, buf, n, name.data(), bytes, nullptr, nullptr);
    return name;
#else
    const char* user = getenv("USER");
    return user ? user : "";
#endif
}

void AdoptEmulatorSaves() {
#ifdef _WIN32
    const wchar_t* appdata = _wgetenv(L"APPDATA");
    if (!appdata || s_port.title_id.empty()) {
        return;
    }
    const auto from = std::filesystem::path{appdata} / "shadPS4" / "home" / "1000" / "savedata" /
                      s_port.title_id;
    const auto to = PortUserDir() / "home" / "1000" / "savedata" / s_port.title_id;
    std::error_code ec;
    if (!std::filesystem::exists(from, ec) || std::filesystem::exists(to, ec)) {
        return;
    }
    // into a side folder first, then one rename: a copy cut short is never taken for the saves,
    // and the next start tries again. The emulator's saves stay as they are.
    auto side = to;
    side += ".adopting";
    std::filesystem::remove_all(side, ec);
    std::filesystem::create_directories(to.parent_path(), ec);
    std::filesystem::copy(from, side, std::filesystem::copy_options::recursive, ec);
    if (ec) {
        LOG_WARNING(Core_Linker, "OrbisGlue: copying the saves of {} failed: {}", s_port.title_id,
                    ec.message());
        std::filesystem::remove_all(side, ec);
        return;
    }
    std::filesystem::rename(side, to, ec);
#endif
}

bool LinkedWithRedZoneProtection() {
    return (s_linked_flags & FlagRedZone) != 0;
}

std::filesystem::path EmbeddedEbootPath() {
    const auto beside = OwnExecutable().parent_path() / "eboot.bin";
    if (std::filesystem::exists(beside)) {
        return beside;
    }
    return s_linked_folder / "eboot.bin";
}

const LinkedModule* FindModule(const std::string& name, u64 aligned_base_size) {
    if (!s_embedded) {
        return nullptr;
    }
    const u64 tcb_key = GetPatchTcbKey();
    if (tcb_key != s_linked_tcb_key) {
        static std::once_flag warned;
        std::call_once(warned, [&] {
            LOG_WARNING(Core_Linker,
                        "OrbisGlue: the image was linked for TLS slot {}, this start has {}; "
                        "loading the title the usual way",
                        s_linked_tcb_key, tcb_key);
        });
        return nullptr;
    }
    for (const auto& m : s_modules) {
        if (m.name == name && m.aligned_base_size == aligned_base_size) {
            return &m;
        }
    }
    return nullptr;
}

void SetLinkOutput(const std::filesystem::path& out_exe) {
    s_link_output = out_exe;
}

void SetLinkIcon(const std::filesystem::path& ico) {
    s_link_icon = ico;
}

bool IsLinking() {
    return !s_link_output.empty();
}

void NoteModule(const std::string& name, u64 base, u64 aligned_base_size, u64 trampoline_base) {
    if (!IsLinking()) {
        return;
    }
    std::scoped_lock lk{s_noted_mutex};
    s_noted.push_back({name, base, aligned_base_size, trampoline_base, {}});
}

void NoteSegment(const std::string& name, u64 address, u64 size) {
    if (!IsLinking()) {
        return;
    }
    std::scoped_lock lk{s_noted_mutex};
    for (auto it = s_noted.rbegin(); it != s_noted.rend(); ++it) {
        if (it->name == name) {
            it->segments.emplace_back(address, size);
            return;
        }
    }
}

bool WriteLinkedExecutable(const std::filesystem::path& game_folder) {
    std::scoped_lock lk{s_noted_mutex};
    const auto exe = OwnExecutable();
    std::error_code ec;
    if (std::filesystem::equivalent(exe, s_link_output, ec)) {
        LOG_ERROR(Core_Linker, "OrbisGlue: refusing to overwrite the running executable");
        return false;
    }

    // The port is named after the game: param.sfo as the run mounted it (with its patch, if any).
    PortIdentity id;
    if (const auto* sfo = Common::Singleton<PSF>::Instance()) {
        id.title = std::string(sfo->GetString("TITLE").value_or(""));
        id.app_ver = std::string(sfo->GetString("APP_VER").value_or(""));
        id.title_id = std::string(sfo->GetString("TITLE_ID").value_or(""));
    }

    Writer w;
    w.Bytes(ImageMagic, sizeof(ImageMagic));
    w.Put(ImageVersion);
    w.String(id.title_id);
    w.String(id.title);
    w.String(id.app_ver);
    w.Put(static_cast<u32>(s_noted.size()));
    w.Put(WindowsGuestRedZoneProtection::IsStaticPatchingEnabled() ? FlagRedZone : 0u);
    w.Put(GetPatchTcbKey());
    w.String(Common::FS::PathToUTF8String(std::filesystem::absolute(game_folder)));
    u64 code_bytes = 0;
    for (const auto& m : s_noted) {
        const auto* base_ptr = reinterpret_cast<const void*>(m.base);
        w.String(m.name);
        w.Put(m.base);
        w.Put(m.aligned_base_size);
        w.Put(static_cast<u32>(m.segments.size()));
        for (const auto& [address, size] : m.segments) {
            w.Put(address);
            w.Put(size);
            w.Bytes(reinterpret_cast<const void*>(address), size);
            code_bytes += size;
        }
        const u64 trampoline_used = GetPatchModuleTrampolineUsed(base_ptr);
        w.Put(trampoline_used);
        w.Bytes(reinterpret_cast<const void*>(m.trampoline_base), trampoline_used);
        const auto patched = GetPatchModulePatched(base_ptr);
        w.Put(static_cast<u32>(patched.size()));
        for (const u64 site : patched) {
            w.Put(site);
        }
        LOG_INFO(Core_Linker,
                 "OrbisGlue: {} at {:#x}, {} segments, {:#x} bytes of trampolines, {} patched "
                 "sites",
                 m.name, m.base, m.segments.size(), trampoline_used, patched.size());
    }

    std::filesystem::copy_file(exe, s_link_output, std::filesystem::copy_options::overwrite_existing,
                               ec);
    if (ec) {
        LOG_ERROR(Core_Linker, "OrbisGlue: cannot write {}: {}",
                  Common::FS::PathToUTF8String(s_link_output), ec.message());
        return false;
    }
#ifdef _WIN32
    // Resources are rewritten before the image goes on: updating them drops trailing data.
    if (!UpdatePortResources(s_link_output, s_link_icon, id)) {
        LOG_WARNING(Core_Linker, "OrbisGlue: could not give {} its icon and version",
                    Common::FS::PathToUTF8String(s_link_output));
    }
    // A port is a windowed program: Windows gives it no console at all (the emulator is a console
    // one). Redirected output still reaches whoever started it.
    {
        std::fstream pe{s_link_output, std::ios::binary | std::ios::in | std::ios::out};
        u32 lfanew = 0;
        pe.seekg(0x3C);
        pe.read(reinterpret_cast<char*>(&lfanew), 4);
        const u16 gui = 2; // IMAGE_SUBSYSTEM_WINDOWS_GUI
        pe.seekp(static_cast<std::streamoff>(lfanew) + 24 + 68);
        pe.write(reinterpret_cast<const char*>(&gui), 2);
    }
#endif
    std::ofstream out{s_link_output, std::ios::binary | std::ios::app};
    out.seekp(0, std::ios::end);
    const u64 offset = static_cast<u64>(out.tellp());
    const u64 size = w.out.size();
    out.write(reinterpret_cast<const char*>(w.out.data()), static_cast<std::streamsize>(size));
    out.write(reinterpret_cast<const char*>(&offset), 8);
    out.write(reinterpret_cast<const char*>(&size), 8);
    out.write(FooterMagic, sizeof(FooterMagic));
    out.close();
    if (!out) {
        LOG_ERROR(Core_Linker, "OrbisGlue: writing {} failed",
                  Common::FS::PathToUTF8String(s_link_output));
        return false;
    }
    LOG_INFO(Core_Linker, "OrbisGlue: linked {} ({} modules, {:#x} image bytes, {:#x} total)",
             Common::FS::PathToUTF8String(s_link_output), s_noted.size(), code_bytes, size);
    return true;
}

} // namespace Core::OrbisGlue
