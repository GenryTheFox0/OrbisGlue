// SPDX-FileCopyrightText: Copyright 2026 GenryTheFox
// SPDX-License-Identifier: GPL-2.0-or-later

// GENRY 2026-10-21 (Шрам): libSceLibcInternal entries that a title's own
// libc.prx imports and that HLE did not provide. Without the console's
// libSceLibcInternal.sprx they resolved to stubs returning 0 -- malloc among
// them -- and Deadpool (CUSA03528) faulted inside its libc.prx before the
// first frame. Implemented on the host CRT so no firmware file is needed.

#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>

#include "common/logging/log.h"
#include "common/va_ctx.h"
#include "core/libraries/libc_internal/libc_internal_io.h"
#include "core/libraries/libs.h"
#include "printf.h"

namespace Libraries::LibcInternal {

/* --- memory --------------------------------------------------------------- */

void* PS4_SYSV_ABI internal_malloc(size_t size) {
    return std::malloc(size ? size : 1);
}

void PS4_SYSV_ABI internal_free(void* ptr) {
    std::free(ptr);
}

/* --- formatted output ------------------------------------------------------ */

struct BoundedOut {
    char* s;
    size_t n;
};

static void OutBounded(char c, void* buffer, size_t idx, size_t) {
    auto* b = static_cast<BoundedOut*>(buffer);
    if (b->n && idx < b->n - 1)
        b->s[idx] = c;
}

static void OutString(char c, void* buffer, size_t, size_t) {
    if (c)
        static_cast<std::string*>(buffer)->push_back(c);
}

s32 PS4_SYSV_ABI internal_vsnprintf(char* s, size_t n, const char* format, Common::VaList* ap) {
    BoundedOut b{s, n};
    int len = _vsnprintf(OutBounded, reinterpret_cast<char*>(&b), format, ap);
    if (s && n)
        s[static_cast<size_t>(len) < n ? static_cast<size_t>(len) : n - 1] = 0;
    return len;
}

s32 PS4_SYSV_ABI internal_vprintf(const char* format, Common::VaList* ap) {
    std::string text;
    int len = _vsnprintf(OutString, reinterpret_cast<char*>(&text), format, ap);
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r'))
        text.pop_back();
    LOG_INFO(Lib_LibcInternal, "{}", text);
    return len;
}

s32 PS4_SYSV_ABI internal_printf(VA_ARGS) {
    VA_CTX(ctx);
    const char* format = vaArgPtr<const char>(&ctx.va_list);
    return internal_vprintf(format, &ctx.va_list);
}

/* --- time ------------------------------------------------------------------ */

// struct tm as the console's (FreeBSD) libc lays it out
struct OrbisTm {
    s32 tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year, tm_wday, tm_yday, tm_isdst;
    s64 tm_gmtoff;
    const char* tm_zone;
};

static const char kZoneLocal[] = "LOC";
static const char kZoneUtc[] = "UTC";

static void ToOrbis(const std::tm& h, OrbisTm* o, s64 gmtoff, const char* zone) {
    o->tm_sec = h.tm_sec;
    o->tm_min = h.tm_min;
    o->tm_hour = h.tm_hour;
    o->tm_mday = h.tm_mday;
    o->tm_mon = h.tm_mon;
    o->tm_year = h.tm_year;
    o->tm_wday = h.tm_wday;
    o->tm_yday = h.tm_yday;
    o->tm_isdst = h.tm_isdst;
    o->tm_gmtoff = gmtoff;
    o->tm_zone = zone;
}

static std::tm FromOrbis(const OrbisTm* o) {
    std::tm h{};
    h.tm_sec = o->tm_sec;
    h.tm_min = o->tm_min;
    h.tm_hour = o->tm_hour;
    h.tm_mday = o->tm_mday;
    h.tm_mon = o->tm_mon;
    h.tm_year = o->tm_year;
    h.tm_wday = o->tm_wday;
    h.tm_yday = o->tm_yday;
    h.tm_isdst = o->tm_isdst;
    return h;
}

static bool HostGmtime(s64 t, std::tm* out) {
    time_t tt = static_cast<time_t>(t);
#ifdef _WIN32
    return gmtime_s(out, &tt) == 0;
#else
    return gmtime_r(&tt, out) != nullptr;
#endif
}

static bool HostLocaltime(s64 t, std::tm* out) {
    time_t tt = static_cast<time_t>(t);
#ifdef _WIN32
    return localtime_s(out, &tt) == 0;
#else
    return localtime_r(&tt, out) != nullptr;
#endif
}

s64 PS4_SYSV_ABI internal_time(s64* out) {
    s64 now = static_cast<s64>(std::time(nullptr));
    if (out)
        *out = now;
    return now;
}

OrbisTm* PS4_SYSV_ABI internal_gmtime_s(const s64* timer, OrbisTm* result) {
    std::tm h{};
    if (!timer || !result || !HostGmtime(*timer, &h))
        return nullptr;
    ToOrbis(h, result, 0, kZoneUtc);
    return result;
}

OrbisTm* PS4_SYSV_ABI internal_gmtime(const s64* timer) {
    static thread_local OrbisTm tm_buf;
    return internal_gmtime_s(timer, &tm_buf);
}

OrbisTm* PS4_SYSV_ABI internal_localtime(const s64* timer) {
    static thread_local OrbisTm tm_buf;
    std::tm local{}, utc{};
    if (!timer || !HostLocaltime(*timer, &local) || !HostGmtime(*timer, &utc))
        return nullptr;
    utc.tm_isdst = local.tm_isdst;
    s64 offset = static_cast<s64>(std::mktime(&local)) - static_cast<s64>(std::mktime(&utc));
    HostLocaltime(*timer, &local);                     // mktime normalised it
    ToOrbis(local, &tm_buf, offset, kZoneLocal);
    return &tm_buf;
}

s64 PS4_SYSV_ABI internal_mktime(OrbisTm* tm) {
    if (!tm)
        return -1;
    std::tm h = FromOrbis(tm);
    s64 t = static_cast<s64>(std::mktime(&h));
    if (t != -1)
        ToOrbis(h, tm, tm->tm_gmtoff, tm->tm_zone ? tm->tm_zone : kZoneLocal);
    return t;
}

/* --- the rest -------------------------------------------------------------- */

void PS4_SYSV_ABI internal___cxa_finalize(void*) {}

static OrbisFILE g_stdout_obj{};
static s32 g_need_libc_internal = 1;

void RegisterlibSceLibcInternalGenry(Core::Loader::SymbolsResolver* sym) {
    LIB_FUNCTION("gQX+4GDQjpM", "libSceLibcInternal", 1, "libSceLibcInternal", internal_malloc);
    LIB_FUNCTION("tIhsqj0qsFE", "libSceLibcInternal", 1, "libSceLibcInternal", internal_free);
    LIB_FUNCTION("hcuQgD53UxM", "libSceLibcInternal", 1, "libSceLibcInternal", internal_printf);
    LIB_FUNCTION("GMpvxPFW924", "libSceLibcInternal", 1, "libSceLibcInternal", internal_vprintf);
    LIB_FUNCTION("Q2V+iqvjgC0", "libSceLibcInternal", 1, "libSceLibcInternal",
                 internal_vsnprintf);
    LIB_FUNCTION("wLlFkwG9UcQ", "libSceLibcInternal", 1, "libSceLibcInternal", internal_time);
    LIB_FUNCTION("n7AepwR0s34", "libSceLibcInternal", 1, "libSceLibcInternal", internal_mktime);
    LIB_FUNCTION("efhK-YSUYYQ", "libSceLibcInternal", 1, "libSceLibcInternal",
                 internal_localtime);
    LIB_FUNCTION("1mecP7RgI2A", "libSceLibcInternal", 1, "libSceLibcInternal", internal_gmtime);
    LIB_FUNCTION("5bBacGLyLOs", "libSceLibcInternal", 1, "libSceLibcInternal",
                 internal_gmtime_s);
    LIB_FUNCTION("H2e8t5ScQGc", "libSceLibcInternal", 1, "libSceLibcInternal",
                 internal___cxa_finalize);
    LIB_OBJ("2sWzhYqFH4E", "libSceLibcInternal", 1, "libSceLibcInternal", &g_stdout_obj);
    LIB_OBJ("ZT4ODD2Ts9o", "libSceLibcInternal", 1, "libSceLibcInternal", &g_need_libc_internal);
}

} // namespace Libraries::LibcInternal
