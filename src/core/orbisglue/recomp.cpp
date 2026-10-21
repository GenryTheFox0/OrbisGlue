// SPDX-FileCopyrightText: Copyright 2026 GenryTheFox
// SPDX-License-Identifier: GPL-2.0-or-later

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <float.h>
#include <immintrin.h>
#include <fmt/format.h>
#include <xbyak/xbyak.h>

#include "common/assert.h"
#include "common/logging/log.h"
#include "common/path_util.h"
#include "common/types.h"
#include "core/orbisglue/recomp.h"
#include "core/tls.h"

#ifdef _WIN32
#include <windows.h>
#endif

namespace Core::OrbisGlue::Recomp {

namespace {

// The layout of OGlue's tools/recomp64/og64.h, which the lifted DLL is built against.
struct OgCtx {
    u64 r[16];
    u8 cf, pf, af, zf, sf, of, df, pad;
    u32 mxcsr;
    u64 fs_base;
    u64 host_rsp;
    u64 pad2;
    alignas(32) u8 y[16][32];
};
static_assert(offsetof(OgCtx, cf) == 128 && offsetof(OgCtx, host_rsp) == 152 &&
              offsetof(OgCtx, y) == 192 && sizeof(OgCtx) == 704);

struct OgHost {
    void (*call_native)(OgCtx*, u64);
    void (*call_dynamic)(OgCtx*, u64);
    void (*unsupported)(OgCtx*, u64);
    void (*jump_native)(OgCtx*, u64); // into original code without a return address pushed
    u64 resume;                       // where that code's `ret` must come back to
    u64 image_base;                   // where the title is: lifted addresses are relative to it
};
struct OgEntry {
    u64 addr;
    void (*fn)(OgCtx*);
};
using EntriesFn = const OgEntry* (*)(const OgHost*, unsigned*);

constexpr int RSP = 4;

std::filesystem::path s_dll;

#ifdef _WIN32

// Machine code the test needs and C cannot say:
//  - native(ctx, target): the original code runs with the context's registers on the guest
//    stack the context points to, then the registers go back into the context;
//  - guarded(fn, arg): calls fn(arg); a fault or a hang inside is turned into a return of 1 by
//    the exception handler / the watchdog, which send execution to `recover` with the stack the
//    guard saved.
class Stubs : public Xbyak::CodeGenerator {
public:
    explicit Stubs(void* mem) : Xbyak::CodeGenerator(0x2000, mem) {
        Xbyak::Label ctx_slot, target_slot, tmp_slot, guard_slot;
        const int y = static_cast<int>(offsetof(OgCtx, y));
        const int hrsp = static_cast<int>(offsetof(OgCtx, host_rsp));
        const Xbyak::Reg64 gpr[16] = {rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi,
                                      r8,  r9,  r10, r11, r12, r13, r14, r15};
        const auto save_host = [&] {
            push(rbx); push(rbp); push(rdi); push(rsi);
            push(r12); push(r13); push(r14); push(r15);
            sub(rsp, 168);
            for (int i = 6; i < 16; i++) {
                movaps(ptr[rsp + (i - 6) * 16], Xbyak::Xmm(i));
            }
        };
        const auto restore_host = [&] {
            for (int i = 6; i < 16; i++) {
                movaps(Xbyak::Xmm(i), ptr[rsp + (i - 6) * 16]);
            }
            add(rsp, 168);
            pop(r15); pop(r14); pop(r13); pop(r12);
            pop(rsi); pop(rdi); pop(rbp); pop(rbx);
        };

        // void native(OgCtx* ctx /*rcx*/, u64 target /*rdx*/)
        align(16);
        native = getCurr<decltype(native)>();
        save_host();
        mov(ptr[rip + ctx_slot], rcx);
        mov(ptr[rip + target_slot], rdx);
        mov(ptr[rcx + hrsp], rsp);
        for (int i = 0; i < 16; i++) {
            movups(Xbyak::Xmm(i), ptr[rcx + y + i * 32]);
        }
        for (int i = 0; i < 16; i++) {
            if (i != 1) {
                mov(gpr[i], ptr[rcx + i * 8]);
            }
        }
        mov(rcx, ptr[rcx + 8]);
        call(ptr[rip + target_slot]);
        native_return = getCurr<u64>();
        mov(ptr[rip + tmp_slot], rax);
        mov(rax, ptr[rip + ctx_slot]);
        for (int i = 1; i < 16; i++) {
            mov(ptr[rax + i * 8], gpr[i]);
        }
        mov(rcx, ptr[rip + tmp_slot]);
        mov(ptr[rax], rcx);
        for (int i = 0; i < 16; i++) {
            movups(ptr[rax + y + i * 32], Xbyak::Xmm(i));
        }
        mov(rsp, ptr[rax + hrsp]);
        restore_host();
        ret();

        // void jump(OgCtx* ctx /*rcx*/, u64 target /*rdx*/): as native, but a jump -- the code
        // returns to native_return because the lifted caller put it in its return slot
        align(16);
        jump = getCurr<decltype(jump)>();
        save_host();
        mov(ptr[rip + ctx_slot], rcx);
        mov(ptr[rip + target_slot], rdx);
        mov(ptr[rcx + hrsp], rsp);
        for (int i = 0; i < 16; i++) {
            movups(Xbyak::Xmm(i), ptr[rcx + y + i * 32]);
        }
        for (int i = 0; i < 16; i++) {
            if (i != 1) {
                mov(gpr[i], ptr[rcx + i * 8]);
            }
        }
        mov(rcx, ptr[rcx + 8]);
        jmp(ptr[rip + target_slot]);

        // int guarded(void (*fn)(void*) /*rcx*/, void* arg /*rdx*/)
        align(16);
        guarded = getCurr<decltype(guarded)>();
        save_host();
        mov(ptr[rip + guard_slot], rsp);
        sub(rsp, 32); // shadow space; rsp stays 16-aligned for the call
        mov(rax, rcx);
        mov(rcx, rdx);
        call(rax);
        add(rsp, 32);
        xor_(eax, eax);
        Xbyak::Label done;
        jmp(done);
        align(16);
        recover = getCurr<u64>();
        mov(rsp, ptr[rip + guard_slot]);
        mov(eax, 1);
        L(done);
        restore_host();
        ret();

        align(8);
        L(ctx_slot); dq(0);
        L(target_slot); dq(0);
        L(tmp_slot); dq(0);
        L(guard_slot);
        guard_slot_addr = getCurr<u64>();
        dq(0);
    }

    void (*native)(OgCtx*, u64){};
    void (*jump)(OgCtx*, u64){};
    int (*guarded)(void (*)(void*), void*){};
    u64 native_return{};
    u64 recover{};
    u64 guard_slot_addr{};
};

Stubs* s_stubs;
std::atomic<bool> s_in_test{false};
std::atomic<u64> s_call_started{0};
std::atomic<u64> s_fault_rip{0};
HANDLE s_test_thread;

// The title's writable memory is write-protected while a call runs: the first write to a page
// faults, the page is noted and opened, and the call goes on. Only noted pages are compared and
// put back afterwards -- a few pages instead of the title's whole 10 MB on every run.
struct TrackedRange {
    u64 begin, end;
};
std::vector<TrackedRange> s_tracked;
std::atomic<bool> s_tracking{false};
constexpr size_t MaxDirty = 1 << 16;
u64 s_dirty[MaxDirty]; // filled from the exception handler: no allocation there
size_t s_dirty_count;
bool s_dirty_overflow;

LONG CALLBACK DifftestFaults(EXCEPTION_POINTERS* ep) {
    if (!s_in_test.load() || GetCurrentThreadId() != GetThreadId(s_test_thread)) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    const auto* rec = ep->ExceptionRecord;
    if (s_tracking.load() && rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
        rec->NumberParameters >= 2 && rec->ExceptionInformation[0] == 1) {
        const u64 a = rec->ExceptionInformation[1];
        for (const auto& t : s_tracked) {
            if (a >= t.begin && a < t.end) {
                const u64 page = a & ~0xFFFull;
                DWORD old;
                VirtualProtect(reinterpret_cast<void*>(page), 0x1000, PAGE_READWRITE, &old);
                if (s_dirty_count < MaxDirty) {
                    s_dirty[s_dirty_count++] = page;
                } else {
                    s_dirty_overflow = true;
                }
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }
    // anything under test -- access, illegal, divide, float traps the guest unmasked -- is the
    // call's failure, never the process's
    s_fault_rip = ep->ContextRecord->Rip;
    ep->ContextRecord->Rsp = *reinterpret_cast<u64*>(s_stubs->guard_slot_addr);
    ep->ContextRecord->Rip = s_stubs->recover;
    return EXCEPTION_CONTINUE_EXECUTION;
}

struct NativeArg {
    OgCtx* ctx;
    u64 target;
};
void RunNative(void* p) {
    auto* a = static_cast<NativeArg*>(p);
    s_stubs->native(a->ctx, a->target);
}
struct LiftedArg {
    OgCtx* ctx;
    void (*fn)(OgCtx*);
};
void RunLifted(void* p) {
    auto* a = static_cast<LiftedArg*>(p);
    a->fn(a->ctx);
}

int Guarded(void (*fn)(void*), void* arg) {
    const unsigned mxcsr = _mm_getcsr();
    s_call_started = static_cast<u64>(
        std::chrono::steady_clock::now().time_since_epoch() / std::chrono::microseconds(1));
    s_in_test = true;
    // the original runs on the test's guest stack: no stack probes against the host stack's TEB
    // bounds (as shadPS4's _runOnAnotherStack), back on afterwards
    u64 stack_base, stack_limit;
    asm volatile("movq %%gs:0x08, %0\n\tmovq %%gs:0x10, %1" : "=r"(stack_base), "=r"(stack_limit));
    asm volatile("movq $0, %%gs:0x08\n\tmovq $0, %%gs:0x10" ::: "memory");
    const int r = s_stubs->guarded(fn, arg);
    asm volatile("movq %0, %%gs:0x08\n\tmovq %1, %%gs:0x10" ::"r"(stack_base), "r"(stack_limit)
                 : "memory");
    s_in_test = false;
    s_call_started = 0;
    _mm_setcsr(mxcsr);
    _clearfp();
    _fpreset();
    return r;
}

// A hung call (a loop the random input never lets end) is sent to `recover` like a fault.
void Watchdog(std::stop_token stop) {
    while (!stop.stop_requested()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        const u64 started = s_call_started.load();
        const u64 now = static_cast<u64>(
            std::chrono::steady_clock::now().time_since_epoch() / std::chrono::microseconds(1));
        if (started == 0 || now - started < 250000) {
            continue;
        }
        if (SuspendThread(s_test_thread) == static_cast<DWORD>(-1)) {
            continue;
        }
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (s_call_started.load() == started && GetThreadContext(s_test_thread, &ctx)) {
            s_fault_rip = ctx.Rip | (1ull << 63); // marks a timeout
            ctx.Rsp = *reinterpret_cast<u64*>(s_stubs->guard_slot_addr);
            ctx.Rip = s_stubs->recover;
            SetThreadContext(s_test_thread, &ctx);
            s_call_started = 0;
        }
        ResumeThread(s_test_thread);
    }
}

void HostCallNative(OgCtx* c, u64 target) {
    // a lifted function calling original code: on its guest stack, as the original did
    s_stubs->native(c, target);
}
void HostCallDynamic(OgCtx* c, u64 target) {
    s_stubs->native(c, target);
}
void HostUnsupported(OgCtx*, u64 at) {
    UNREACHABLE_MSG("Mosaic: unsupported instruction at {:#x}", at);
}
void HostJumpNative(OgCtx* c, u64 target) {
    s_stubs->jump(c, target);
}
OgHost s_host{HostCallNative, HostCallDynamic, HostUnsupported, HostJumpNative, 0, 0};

#endif

} // namespace

void SetDifftest(const std::filesystem::path& dll) {
    s_dll = dll;
}

bool IsDifftest() {
    return !s_dll.empty();
}

void RunDifftest(u64 image_base) {
#ifdef _WIN32
    s_host.image_base = image_base;
    HMODULE dll = LoadLibraryW(s_dll.c_str());
    if (!dll) {
        std::printf("[Mosaic] cannot load %s (%lu)\n", Common::FS::PathToUTF8String(s_dll).c_str(),
                    GetLastError());
        std::fflush(stdout);
        std::quick_exit(2);
    }
    const auto entries = reinterpret_cast<EntriesFn>(GetProcAddress(dll, "og_entries"));
    unsigned count = 0;
    const OgEntry* table = entries ? entries(&s_host, &count) : nullptr;
    if (!table) {
        std::printf("[Mosaic] %s exports no og_entries\n", Common::FS::PathToUTF8String(s_dll).c_str());
        std::fflush(stdout);
        std::quick_exit(2);
    }

    // the emulator says nothing while the test runs: a stub that logs every call, called in a
    // loop over random data, filled the log queue and the test waited on it forever
    Common::Log::g_class_levels.fill(Common::Log::Level::Off);

    void* code = VirtualAlloc(nullptr, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    s_stubs = new Stubs(code);
    s_host.resume = s_stubs->native_return;
    s_test_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId());
    AddVectoredExceptionHandler(1, DifftestFaults);
    std::jthread watchdog{Watchdog};

    // scratch the arguments point into, and a guest stack; both refilled for every trial
    constexpr size_t HeapSize = 256u << 10, StackSize = 4u << 20;
    // Each sits in the middle of address space that is reserved and never committed, 64 GB on
    // each side: a write past it, even at an offset made from a random 32-bit value, is a fault
    // the test catches, not a quiet hit on the emulator's own memory.
    // And each starts on a 4 GB boundary, so the low 32 bits of a pointer into it are small: a
    // function that takes a size from a 32-bit register holding such a pointer (alloca of `edx`
    // bytes) asks for kilobytes, not gigabytes. A guest stack moved off into nothing is the one
    // fault Windows cannot hand back -- it ends the process.
    constexpr size_t Guard = 64ull << 30;
    const auto guarded_block = [&](size_t size) {
        constexpr u64 Align = 4ull << 30;
        // the largest guard the address space still has room for
        for (size_t guard = Guard; guard >= (8ull << 30); guard /= 2) {
            if (auto* r = static_cast<u8*>(VirtualAlloc(nullptr, guard * 2 + size + Align,
                                                        MEM_RESERVE, PAGE_NOACCESS))) {
                const u64 at = (reinterpret_cast<u64>(r) + guard + Align - 1) & ~(Align - 1);
                std::printf("[Mosaic] test buffer at %llx, %llu GB of guard\n",
                            static_cast<unsigned long long>(at),
                            static_cast<unsigned long long>(guard >> 30));
                return static_cast<u8*>(
                    VirtualAlloc(reinterpret_cast<void*>(at), size, MEM_COMMIT, PAGE_READWRITE));
            }
        }
        return static_cast<u8*>(VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    };
    auto* heap = guarded_block(HeapSize);
    auto* stack = guarded_block(StackSize);
    std::vector<u8> heap_seed(HeapSize), stack_seed(StackSize), heap_native(HeapSize),
        stack_native(StackSize);

    // the title's own writable memory (globals, .bss): every trial starts from the same state, and
    // what the original wrote there is compared too
    struct Region {
        u8* at;
        size_t size;
        std::vector<u8> pristine;
    };
    std::vector<Region> globals;
    for (u64 a = image_base; a < image_base + (1ull << 30);) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<void*>(a), &mbi, sizeof(mbi))) {
            break;
        }
        const u64 end = reinterpret_cast<u64>(mbi.BaseAddress) + mbi.RegionSize;
        const DWORD rw = PAGE_READWRITE | PAGE_WRITECOPY;
        if (mbi.State == MEM_COMMIT && (mbi.Protect & rw) && !(mbi.Protect & PAGE_GUARD)) {
            auto& g = globals.emplace_back();
            g.at = static_cast<u8*>(mbi.BaseAddress);
            g.size = mbi.RegionSize;
            g.pristine.assign(g.at, g.at + g.size);
        } else if (mbi.State == MEM_FREE && a > image_base + (256ull << 20)) {
            break;
        }
        a = end;
    }
    size_t global_bytes = 0;
    for (const auto& g : globals) {
        global_bytes += g.size;
    }
    std::printf("[Mosaic] %zu regions of the title's writable memory, %zu KB, tracked by page\n",
                globals.size(), global_bytes >> 10);
    for (const auto& g : globals) {
        s_tracked.push_back({reinterpret_cast<u64>(g.at), reinterpret_cast<u64>(g.at) + g.size});
    }
    const auto pristine_of = [&](u64 page) -> const u8* {
        for (const auto& g : globals) {
            const u64 b = reinterpret_cast<u64>(g.at);
            if (page >= b && page < b + g.size) {
                return g.pristine.data() + (page - b);
            }
        }
        return nullptr;
    };
    const auto protect = [&](DWORD prot) {
        for (const auto& g : globals) {
            DWORD old;
            VirtualProtect(g.at, g.size, prot, &old);
        }
    };
    // runs one call with the title's memory tracked; returns the pages it wrote
    const auto tracked = [&](void (*fn)(void*), void* arg, std::vector<u64>& pages) {
        s_dirty_count = 0;
        s_dirty_overflow = false;
        protect(PAGE_READONLY);
        s_tracking = true;
        const bool ok = Guarded(fn, arg) == 0;
        s_tracking = false;
        protect(PAGE_READWRITE);
        pages.assign(s_dirty, s_dirty + s_dirty_count);
        return ok;
    };
    const auto put_back = [&](const std::vector<u64>& pages) {
        for (const u64 p : pages) {
            std::memcpy(reinterpret_cast<void*>(p), pristine_of(p), 0x1000);
        }
    };
    const auto reset_globals = [&] {
        for (auto& g : globals) {
            std::memcpy(g.at, g.pristine.data(), g.size);
        }
    };
    std::vector<u64> native_pages, native_pages2, lifted_pages;
    std::vector<u8> native_page_bytes;
    const char* only = std::getenv("MOSAIC_ONLY");
    const u64 only_addr = only ? std::strtoull(only, nullptr, 16) : 0;

    int trials = 4;
    if (const char* t = std::getenv("MOSAIC_TRIALS")) {
        trials = std::max(1, std::atoi(t));
    }
    // A call stuck in a kernel wait (an HLE function waiting on an event nobody will set) cannot
    // be pulled out by the watchdog. The driver (tools/recomp64/run_difftest.py) then ends the
    // process and starts a new one from the next function: MOSAIC_FROM is where to begin, and
    // mosaic_progress.txt says which function is under test right now.
    unsigned from = 0;
    if (const char* f = std::getenv("MOSAIC_FROM")) {
        from = static_cast<unsigned>(std::strtoul(f, nullptr, 10));
    }
    unsigned passed = 0, failed = 0, untested = 0;
    std::FILE* log = std::fopen("mosaic_difftest.log", from ? "a" : "w");
    std::FILE* progress = std::fopen("mosaic_progress.txt", "w");
    for (unsigned i = from; i < count; i++) {
        OgEntry e = table[i];
        e.addr += image_base;
        if (only_addr && e.addr != only_addr) {
            continue;
        }
        std::rewind(progress);
        std::fprintf(progress, "%u %llx          \n", i, static_cast<unsigned long long>(e.addr));
        std::fflush(progress);
        if (std::getenv("MOSAIC_TRACE")) {
            std::printf("[Mosaic] test %llx\n", static_cast<unsigned long long>(e.addr));
            std::fflush(stdout);
        }
        int ok_trials = 0, nondet_trials = 0, nan_trials = 0;
        std::string why;
        for (int t = 0; t < trials && why.empty(); t++) {
            std::mt19937_64 rng(e.addr * 1315423911ull + t);
            // plausible data, not noise: small numbers and pointers back into the heap, so a size,
            // a count or an address a function reads from its arguments stays in reach
            for (size_t k = 0; k < HeapSize; k += 8) {
                const u64 roll = rng() % 4;
                const u64 v = roll == 0 ? reinterpret_cast<u64>(heap) + (rng() % HeapSize) / 16 * 16
                                        : rng() % 4096;
                std::memcpy(&heap_seed[k], &v, 8);
            }
            std::memset(stack_seed.data(), 0, StackSize);
            OgCtx base{};
            for (int r = 0; r < 16; r++) {
                const u64 roll = rng() % 8;
                // no fully random 64-bit values: one could point into the emulator's own memory
                base.r[r] = roll < 6 ? reinterpret_cast<u64>(heap) + 0x10000 + (rng() % (HeapSize - 0x20000)) / 16 * 16
                                     : rng() % 1024;
            }
            const u64 top = reinterpret_cast<u64>(stack) + StackSize - 0x10000;
            base.r[RSP] = top; // the call pushes the return address: entry sees it at 8 mod 16
            for (int x = 0; x < 16; x++) {
                for (int l = 0; l < 4; l++) {
                    const float f = static_cast<float>(static_cast<int>(rng() % 20001) - 10000) / 64.0f;
                    std::memcpy(&base.y[x][l * 4], &f, 4);
                }
            }

            // the title's memory is pristine here: the last run of the last trial put it back
            std::memcpy(heap, heap_seed.data(), HeapSize);
            std::memcpy(stack, stack_seed.data(), StackSize);
            OgCtx n = base;
            NativeArg na{&n, e.addr};
            const bool n_ok = tracked(RunNative, &na, native_pages);
            const bool n_overflow = s_dirty_overflow;
            std::memcpy(heap_native.data(), heap, HeapSize);
            std::memcpy(stack_native.data(), stack, StackSize);
            native_page_bytes.resize(native_pages.size() * 0x1000);
            for (size_t p = 0; p < native_pages.size(); p++) {
                std::memcpy(&native_page_bytes[p * 0x1000], reinterpret_cast<void*>(native_pages[p]),
                            0x1000);
            }
            put_back(native_pages);

            // the original once more: a function that reads the clock, a counter or a random seed
            // differs from itself, and that is no evidence against the lifted one
            std::memcpy(heap, heap_seed.data(), HeapSize);
            std::memcpy(stack, stack_seed.data(), StackSize);
            OgCtx n2 = base;
            NativeArg na2{&n2, e.addr};
            const bool n2_ok = tracked(RunNative, &na2, native_pages2);
            bool same = n2_ok == n_ok && !n_overflow && !s_dirty_overflow && native_pages2 == native_pages;
            for (int r = 0; r < 16 && same; r++) {
                same = n.r[r] == n2.r[r];
            }
            for (int x = 0; x < 16 && same; x++) {
                same = std::memcmp(n.y[x], n2.y[x], 16) == 0;
            }
            same = same && std::memcmp(heap_native.data(), heap, HeapSize) == 0;
            if (same) {
                const u64 live2 = std::clamp<u64>(n.r[RSP] - reinterpret_cast<u64>(stack), 0, StackSize);
                same = std::memcmp(stack_native.data() + live2, stack + live2, StackSize - live2) == 0;
            }
            for (size_t p = 0; p < native_pages.size() && same; p++) {
                same = std::memcmp(&native_page_bytes[p * 0x1000],
                                   reinterpret_cast<void*>(native_pages[p]), 0x1000) == 0;
            }
            put_back(native_pages2);
            if (!same && n_ok) {
                nondet_trials++;
                continue;
            }

            std::memcpy(heap, heap_seed.data(), HeapSize);
            std::memcpy(stack, stack_seed.data(), StackSize);
            OgCtx l = base;
            l.r[RSP] = top - 8;
            std::memcpy(reinterpret_cast<void*>(top - 8), &s_stubs->native_return, 8);
            LiftedArg la{&l, e.fn};
            const bool l_ok = tracked(RunLifted, &la, lifted_pages);
            if (n_overflow || s_dirty_overflow) {
                reset_globals(); // wrote more than the tracker holds: compare nothing, start clean
                continue;
            }
            // compare what either run wrote: the native result, or pristine where only lifted wrote
            std::string mem_why;
            for (size_t p = 0; p < native_pages.size() && mem_why.empty(); p++) {
                if (std::memcmp(&native_page_bytes[p * 0x1000],
                                reinterpret_cast<void*>(native_pages[p]), 0x1000) != 0) {
                    mem_why = fmt::format("title memory differs in page {:#x}", native_pages[p]);
                }
            }
            for (size_t p = 0; p < lifted_pages.size() && mem_why.empty(); p++) {
                if (std::find(native_pages.begin(), native_pages.end(), lifted_pages[p]) ==
                        native_pages.end() &&
                    std::memcmp(pristine_of(lifted_pages[p]), reinterpret_cast<void*>(lifted_pages[p]),
                                0x1000) != 0) {
                    mem_why = fmt::format("lifted wrote title page {:#x}, native did not",
                                          lifted_pages[p]);
                }
            }
            put_back(lifted_pages);
            put_back(native_pages);

            if (!n_ok) {
                continue; // the input was no good for the original either
            }
            if (!l_ok) {
                why = fmt::format("lifted faulted at {:#x}", s_fault_rip.load());
                break;
            }
            for (int r = 0; r < 16 && why.empty(); r++) {
                if (n.r[r] != l.r[r]) {
                    why = fmt::format("r{} native {:#x} lifted {:#x}", r, n.r[r], l.r[r]);
                }
            }
            for (int x = 0; x < 16 && why.empty(); x++) {
                if (std::memcmp(n.y[x], l.y[x], 16) == 0) {
                    continue;
                }
                // a NaN where the original has a NaN of another sign or payload: the C compiler
                // may swap the operands of a commutative operation, and x86 passes on the first
                // operand's NaN -- the same "not a number" to anything that tests it
                bool nan_only = true;
                for (int lane = 0; lane < 4 && nan_only; lane++) {
                    u32 a, b;
                    std::memcpy(&a, n.y[x] + lane * 4, 4);
                    std::memcpy(&b, l.y[x] + lane * 4, 4);
                    const auto nan = [](u32 v) { return (v & 0x7F800000u) == 0x7F800000u && (v & 0x7FFFFFu); };
                    nan_only = a == b || (nan(a) && nan(b));
                }
                if (nan_only) {
                    nan_trials++;
                } else {
                    why = fmt::format("xmm{} differs", x);
                }
            }
            if (why.empty() && std::memcmp(heap_native.data(), heap, HeapSize) != 0) {
                why = "memory behind the arguments differs";
            }
            // only the live stack: below the final rsp is dead, and the exception dispatch of the
            // write tracker leaves its frames there during the native run
            const u64 live = std::clamp<u64>(n.r[RSP] - reinterpret_cast<u64>(stack), 0, StackSize);
            if (why.empty() &&
                std::memcmp(stack_native.data() + live, stack + live, StackSize - live) != 0) {
                why = "stack differs";
            }
            if (why.empty()) {
                why = mem_why;
            }
            if (only_addr) {
                std::printf("[Mosaic] trial %d: native %s, lifted %s\n", t, n_ok ? "ok" : "faulted",
                            l_ok ? "ok" : "faulted");
                for (int r = 0; r < 16; r++) {
                    std::printf("  r%-2d in %016llx  native %016llx  lifted %016llx%s\n", r,
                                static_cast<unsigned long long>(base.r[r]),
                                static_cast<unsigned long long>(n.r[r]),
                                static_cast<unsigned long long>(l.r[r]),
                                n.r[r] != l.r[r] ? "  <--" : "");
                }
                for (int x = 0; x < 16; x++) {
                    if (std::memcmp(n.y[x], l.y[x], 16) != 0) {
                        u32 a[4], b[4], in[4];
                        std::memcpy(a, n.y[x], 16);
                        std::memcpy(b, l.y[x], 16);
                        std::memcpy(in, base.y[x], 16);
                        std::printf("  xmm%-2d in %08x %08x %08x %08x\n        native %08x %08x %08x %08x\n"
                                    "        lifted %08x %08x %08x %08x\n",
                                    x, in[0], in[1], in[2], in[3], a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]);
                    }
                }
                std::printf("  %s\n", why.empty() ? "same" : why.c_str());
                std::fflush(stdout);
            }
            if (why.empty()) {
                ok_trials++;
            }
        }
        if (!why.empty()) {
            failed++;
            std::fprintf(log, "FAIL %llx %s\n", static_cast<unsigned long long>(e.addr), why.c_str());
        } else if (ok_trials == 0 && nondet_trials > 0) {
            untested++;
            std::fprintf(log, "NONDET %llx\n", static_cast<unsigned long long>(e.addr));
        } else if (ok_trials == 0) {
            untested++;
            std::fprintf(log, "UNTESTED %llx\n", static_cast<unsigned long long>(e.addr));
        } else {
            passed++;
            std::fprintf(log, nan_trials ? "PASSNAN %llx\n" : "PASS %llx\n",
                         static_cast<unsigned long long>(e.addr));
        }
        std::fflush(log);
        if ((i + 1) % 2000 == 0) {
            std::printf("[Mosaic] %u / %u: %u proven, %u differ, %u untestable\n", i + 1, count,
                        passed, failed, untested);
            std::fflush(stdout);
        }
    }
    reset_globals();
    std::fclose(log);
    std::rewind(progress);
    std::fprintf(progress, "DONE %u          \n", count);
    std::fclose(progress);
    std::printf("[Mosaic] done: %u lifted functions, %u proven identical, %u differ, %u untestable "
                "(the original faults on every random input)\n",
                count, passed, failed, untested);
    std::fflush(stdout);
    watchdog.request_stop();
    watchdog.join();
    std::quick_exit(failed == 0 ? 0 : 1);
#else
    std::quick_exit(2);
#endif
}

// ------------------------------------------------------------------ the title on lifted code

namespace {

std::filesystem::path s_run_dll;

#ifdef _WIN32

constexpr u32 TlsSlotsOffset = 0x1480;
constexpr u32 TlsExpansionOffset = 0x1780;
DWORD s_ctx_slot = TLS_OUT_OF_INDEXES;
struct Lifted {
    void (*fn)(OgCtx*);
    u32 index;
};
std::unordered_map<u64, Lifted> s_lifted;
u8* s_off; // the DLL's og_off: 1 = that function runs as the original

bool IsOn(const Lifted& l) {
    return !s_off || !s_off[l.index];
}
std::atomic<u64> s_native_calls{0}, s_lifted_dynamic{0};

// native(ctx, target) for a title that runs: the original code runs on the guest stack with the
// context's registers, any number of threads at once, nested to any depth. The context of the
// call in flight sits in a TLS slot (the previous one is kept on the host stack), so the way back
// needs no global: the original returns to `after`, which finds its context through gs.
class RunStubs : public Xbyak::CodeGenerator {
public:
    RunStubs(void* mem, u32 slot) : Xbyak::CodeGenerator(0x1000, mem) {
        const int y = static_cast<int>(offsetof(OgCtx, y));
        // the TLS slot, as TlsGetValue reads it: the first 64 in the TEB, the rest through the
        // thread's expansion table (EnterLifted makes sure the thread has one)
        const auto tls_load = [&](const Xbyak::Reg64& dst) {
            putSeg(gs);
            if (slot < 64) {
                mov(dst, ptr[reinterpret_cast<void*>(static_cast<u64>(TlsSlotsOffset + slot * 8))]);
            } else {
                mov(dst, ptr[reinterpret_cast<void*>(static_cast<u64>(TlsExpansionOffset))]);
                mov(dst, ptr[dst + (slot - 64) * 8]);
            }
        };
        const auto tls_store = [&](const Xbyak::Reg64& src, const Xbyak::Reg64& scratch) {
            putSeg(gs);
            if (slot < 64) {
                mov(ptr[reinterpret_cast<void*>(static_cast<u64>(TlsSlotsOffset + slot * 8))], src);
            } else {
                mov(scratch, ptr[reinterpret_cast<void*>(static_cast<u64>(TlsExpansionOffset))]);
                mov(ptr[scratch + (slot - 64) * 8], src);
            }
        };
        const int hrsp = static_cast<int>(offsetof(OgCtx, host_rsp));
        Xbyak::Label after;
        const Xbyak::Reg64 gpr[16] = {rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi,
                                      r8,  r9,  r10, r11, r12, r13, r14, r15};
        // call: the target gets `after` as its return address; jump: the target returns to
        // whatever the caller left in the slot at the context's rsp (`resume`, i.e. `after`)
        const auto enter = [&](bool call) {
            push(rbx); push(rbp); push(rdi); push(rsi);
            push(r12); push(r13); push(r14); push(r15);
            sub(rsp, 184);
            for (int i = 6; i < 16; i++) {
                movaps(ptr[rsp + (i - 6) * 16], Xbyak::Xmm(i));
            }
            tls_load(rax);
            mov(ptr[rsp + 160], rax); // the outer call's context
            tls_store(rcx, r9);
            // the original code runs on the guest stack: the TEB's bounds are the host stack's, and
            // a stack probe (__chkstk in the system's C++) would walk the gap between -- off, as
            // shadPS4's own _runOnAnotherStack does, and back on in `after`
            putSeg(gs);
            mov(rax, ptr[reinterpret_cast<void*>(static_cast<u64>(0x08))]);
            mov(ptr[rsp + 168], rax);
            putSeg(gs);
            mov(rax, ptr[reinterpret_cast<void*>(static_cast<u64>(0x10))]);
            mov(ptr[rsp + 176], rax);
            xor_(eax, eax);
            putSeg(gs);
            mov(ptr[reinterpret_cast<void*>(static_cast<u64>(0x08))], rax);
            putSeg(gs);
            mov(ptr[reinterpret_cast<void*>(static_cast<u64>(0x10))], rax);
            mov(ptr[rcx + hrsp], rsp);
            // the guest stack gets the target (and for a call the way back): `ret` is the jump
            mov(rax, ptr[rcx + RSP * 8]);
            if (call) {
                lea(r8, ptr[rip + after]);
                mov(ptr[rax - 8], r8);
                mov(ptr[rax - 16], rdx);
            } else {
                mov(ptr[rax - 8], rdx);
            }
            for (int i = 0; i < 16; i++) {
                vmovups(Xbyak::Ymm(i), ptr[rcx + y + i * 32]);
            }
            for (int i = 0; i < 16; i++) {
                if (i != 1 && i != RSP) {
                    mov(gpr[i], ptr[rcx + i * 8]);
                }
            }
            mov(rsp, ptr[rcx + RSP * 8]);
            lea(rsp, ptr[rsp - (call ? 16 : 8)]); // lea, not sub: the flags stay the context's
            mov(rcx, ptr[rcx + 8]);
            ret();
        };
        align(16);
        native = getCurr<decltype(native)>();
        enter(true);
        align(16);
        jump = getCurr<decltype(jump)>();
        enter(false);

        align(16);
        L(after);
        resume = getCurr<u64>();
        push(rax);
        tls_load(rax);
        for (int i = 1; i < 16; i++) {
            if (i != RSP) {
                mov(ptr[rax + i * 8], gpr[i]);
            }
        }
        pop(rcx);
        mov(ptr[rax], rcx);
        mov(ptr[rax + RSP * 8], rsp);
        for (int i = 0; i < 16; i++) {
            vmovups(ptr[rax + y + i * 32], Xbyak::Ymm(i));
        }
        mov(rsp, ptr[rax + hrsp]);
        mov(rcx, ptr[rsp + 168]);
        putSeg(gs);
        mov(ptr[reinterpret_cast<void*>(static_cast<u64>(0x08))], rcx);
        mov(rcx, ptr[rsp + 176]);
        putSeg(gs);
        mov(ptr[reinterpret_cast<void*>(static_cast<u64>(0x10))], rcx);
        mov(rcx, ptr[rsp + 160]);
        tls_store(rcx, rdx);
        for (int i = 6; i < 16; i++) {
            movaps(Xbyak::Xmm(i), ptr[rsp + (i - 6) * 16]);
        }
        add(rsp, 184);
        pop(r15); pop(r14); pop(r13); pop(r12);
        pop(rsi); pop(rdi); pop(rbp); pop(rbx);
        vzeroupper();
        ret();
    }

    void (*native)(OgCtx*, u64){};
    void (*jump)(OgCtx*, u64){};
    u64 resume{};
};

RunStubs* s_run;

void RunCallNative(OgCtx* c, u64 target) {
    s_native_calls.fetch_add(1, std::memory_order_relaxed);
    s_run->native(c, target);
}
void RunCallDynamic(OgCtx* c, u64 target) {
    if (const auto it = s_lifted.find(target); it != s_lifted.end() && IsOn(it->second)) {
        s_lifted_dynamic.fetch_add(1, std::memory_order_relaxed);
        c->r[RSP] -= 8; // a call: the callee's `ret` takes this slot off again
        *reinterpret_cast<u64*>(c->r[RSP]) = 0;
        it->second.fn(c);
        return;
    }
    RunCallNative(c, target);
}
void RunUnsupported(OgCtx*, u64 at) {
    UNREACHABLE_MSG("Mosaic: unsupported instruction at {:#x}", at);
}
void RunJumpNative(OgCtx* c, u64 target) {
    s_native_calls.fetch_add(1, std::memory_order_relaxed);
    s_run->jump(c, target);
}
OgHost s_run_host{RunCallNative, RunCallDynamic, RunUnsupported, RunJumpNative, 0, 0};

bool LoadRun(u64 image_base) {
    static bool loaded = false;
    if (loaded) {
        return true;
    }
    HMODULE dll = LoadLibraryW(s_run_dll.c_str());
    const auto entries = dll ? reinterpret_cast<EntriesFn>(GetProcAddress(dll, "og_entries")) : nullptr;
    unsigned count = 0;
    s_run_host.image_base = image_base;
    const OgEntry* table = entries ? entries(&s_run_host, &count) : nullptr;
    s_ctx_slot = TlsAlloc();
    ASSERT_MSG(table && s_ctx_slot < 64 + 1024, "Mosaic: cannot use {} (error {}, TLS slot {})",
               Common::FS::PathToUTF8String(s_run_dll), GetLastError(), s_ctx_slot);
    s_lifted.reserve(count);
    for (unsigned i = 0; i < count; i++) {
        s_lifted.emplace(image_base + table[i].addr, Lifted{table[i].fn, i});
    }
    // MOSAIC_OFF=a-b,c,...: those table indices run as the original (bisecting a bug)
    if (const auto switches = reinterpret_cast<u8* (*)()>(GetProcAddress(dll, "og_switches"))) {
        s_off = switches();
        if (const char* off = std::getenv("MOSAIC_OFF")) {
            unsigned turned = 0;
            for (const char* p = off; *p;) {
                char* end;
                const unsigned long a = std::strtoul(p, &end, 10);
                unsigned long b = a;
                if (*end == '-') {
                    b = std::strtoul(end + 1, &end, 10);
                }
                for (unsigned long k = a; k <= b && k < count; k++) {
                    s_off[k] = 1;
                    turned++;
                }
                p = *end == ',' ? end + 1 : end;
                if (end == p && *p) {
                    break;
                }
            }
            LOG_INFO(Core, "Mosaic: {} functions sent back to the original (MOSAIC_OFF)", turned);
        }
    }
    void* code = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    s_run = new RunStubs(code, s_ctx_slot);
    s_run_host.resume = s_run->resume;
    LOG_INFO(Core, "Mosaic: {} lifted functions from {} at {}", count,
             Common::FS::PathToUTF8String(s_run_dll), fmt::ptr(dll));
    loaded = true;
    return true;
}

// a context for the current thread, entering at `fn` with the guest stack at `rsp`
void EnterLifted(void (*fn)(OgCtx*), OgCtx& c) {
    TlsSetValue(s_ctx_slot, TlsGetValue(s_ctx_slot)); // the thread's expansion table, if it needs one
    c.fs_base = reinterpret_cast<u64>(Core::GetTcbBase());
    c.mxcsr = _mm_getcsr();
    fn(&c);
}

#endif

} // namespace

void SetMosaicRun(const std::filesystem::path& dll) {
    s_run_dll = dll;
}

bool IsMosaicRun() {
    return !s_run_dll.empty();
}

bool RunMainLifted(void* params, u64 entry, void* exit_func, u64 image_base) {
#ifdef _WIN32
    LoadRun(image_base);
    const auto it = s_lifted.find(entry);
    if (it == s_lifted.end() || !IsOn(it->second)) {
        LOG_ERROR(Core, "Mosaic: the entry {:#x} is not lifted, starting the original", entry);
        return false;
    }
    // the main thread's guest stack: the host one stays for the lifted C
    constexpr size_t StackSize = 16u << 20;
    auto* stack = static_cast<u8*>(VirtualAlloc(nullptr, StackSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    u64 top = (reinterpret_cast<u64>(stack) + StackSize) & ~15ull;
    // as RunMainEntry leaves it: 8 below a 16-byte boundary, then the first two words of the
    // parameters, and the entry jumped to (nothing to return to)
    top -= 8;
    const u64* p = static_cast<const u64*>(params);
    top -= 8; *reinterpret_cast<u64*>(top) = p[1];
    top -= 8; *reinterpret_cast<u64*>(top) = p[0];
    alignas(32) static OgCtx c{};
    c.r[7] = reinterpret_cast<u64>(params);
    c.r[6] = reinterpret_cast<u64>(exit_func);
    c.r[RSP] = top;
    LOG_INFO(Core, "Mosaic: the title starts at {:#x} on lifted code", entry);
    // a pulse in the log: how often lifted code called out in the last 5 s (0 = it is stuck)
    static std::jthread pulse([](std::stop_token stop) {
        u64 last = 0;
        while (!stop.stop_requested()) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            const u64 now = s_native_calls.load();
            LOG_INFO(Core, "Mosaic pulse: {} calls out of lifted code in 5 s, {} through pointers",
                     now - last, s_lifted_dynamic.load());
            last = now;
        }
    });
    EnterLifted(it->second.fn, c);
    LOG_ERROR(Core, "Mosaic: the entry returned ({} calls to original code, {} lifted through pointers)",
              s_native_calls.load(), s_lifted_dynamic.load());
    std::quick_exit(0);
#else
    return false;
#endif
}

bool RunThreadLifted(void* arg, void* start, void* stack_top, void** ret) {
#ifdef _WIN32
    if (s_lifted.empty()) {
        return false; // the main thread loads the DLL; nothing lifted runs before it
    }
    // MOSAIC_THREADS=0: the title's own threads stay original (to tell their bugs from main's)
    static const bool threads = [] {
        const char* v = std::getenv("MOSAIC_THREADS");
        return !(v && *v == '0');
    }();
    if (!threads) {
        return false;
    }
    const auto it = s_lifted.find(reinterpret_cast<u64>(start));
    if (it == s_lifted.end() || !IsOn(it->second)) {
        return false;
    }
    alignas(32) OgCtx c{};
    c.r[7] = reinterpret_cast<u64>(arg);
    c.r[RSP] = (reinterpret_cast<u64>(stack_top) & ~15ull) - 8; // as after a call
    *reinterpret_cast<u64*>(c.r[RSP]) = 0;
    EnterLifted(it->second.fn, c);
    *ret = reinterpret_cast<void*>(c.r[0]);
    return true;
#else
    return false;
#endif
}

} // namespace Core::OrbisGlue::Recomp
