/* OrbisGlue Mosaic: what the generated C of a PS4 title builds against.
 *
 * A lifted function is `void og_f_<addr>(OgCtx* c)`: the guest's registers and flags live in the
 * context, its memory is the host's (the title is mapped at the addresses it was linked for), and
 * its stack is the guest stack c->r[RSP] points into -- every push, pop, call and ret moves it
 * exactly as the original code would, so native code and lifted code share one stack layout.
 *
 * Calls the lifter could not resolve to a lifted function go through og_host->call_native: the
 * original machine code runs with the context's registers (same ISA), and comes back.
 */
#pragma once

#include <stdint.h>
#include <string.h>
#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#ifdef _WIN32
#include <intrin.h> /* _mul128, _umul128 */
#endif
#else
/* ARM (the phone): the SSE/AVX the lifted code speaks, in NEON, from SIMDe (header-only, MIT) */
#define SIMDE_ENABLE_NATIVE_ALIASES
#include <simde/x86/avx2.h>
#include <simde/x86/sse4.2.h>
static inline int64_t _mul128(int64_t a, int64_t b, int64_t* hi) {
    __int128 p = (__int128)a * b;
    *hi = (int64_t)(p >> 64);
    return (int64_t)p;
}
static inline uint64_t _umul128(uint64_t a, uint64_t b, uint64_t* hi) {
    unsigned __int128 p = (unsigned __int128)a * b;
    *hi = (uint64_t)(p >> 64);
    return (uint64_t)p;
}
#endif

#ifdef _WIN32
#define OG_EXPORT __declspec(dllexport)
#else
#define OG_EXPORT __attribute__((visibility("default")))
#endif

typedef struct OgCtx {
    uint64_t r[16]; /* x86 order: rax rcx rdx rbx rsp rbp rsi rdi r8 .. r15 */
    uint8_t cf, pf, af, zf, sf, of, df, _pad;
    uint32_t mxcsr;
    uint64_t fs_base;
    uint64_t host_rsp; /* the host stack, while native code runs on the guest one */
    uint64_t _pad2;
    __attribute__((aligned(32))) union {
        uint8_t b[32];
        uint16_t w[16];
        uint32_t d[8];
        uint64_t q[4];
        float f[8];
        double g[4];
    } y[16];
} OgCtx;

enum { RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15 };

typedef struct OgHost {
    void (*call_native)(OgCtx* c, uint64_t target); /* pushes its own return address */
    void (*call_dynamic)(OgCtx* c, uint64_t target); /* lifted if known, else native */
    void (*unsupported)(OgCtx* c, uint64_t at);      /* an instruction the lifter left out */
    /* a jump (no return address pushed) into original code; it comes back when that code returns
     * to `resume`, which the caller has put in its return-address slot */
    void (*jump_native)(OgCtx* c, uint64_t target);
    uint64_t resume;
    uint64_t image_base; /* where the loader put the title: every guest address is og_base + va */
} OgHost;

extern const OgHost* og_host;
extern uint64_t og_base;
extern uint8_t og_off[]; /* per lifted function: 1 = run the original instead (bisecting) */

/* --- memory: flat, unaligned, may alias anything --- */
typedef uint8_t og_u8u __attribute__((aligned(1), may_alias));
typedef uint16_t og_u16u __attribute__((aligned(1), may_alias));
typedef uint32_t og_u32u __attribute__((aligned(1), may_alias));
typedef uint64_t og_u64u __attribute__((aligned(1), may_alias));
#define M8(a) (*(volatile og_u8u*)(uintptr_t)(a))
#define M16(a) (*(volatile og_u16u*)(uintptr_t)(a))
#define M32(a) (*(volatile og_u32u*)(uintptr_t)(a))
#define M64(a) (*(volatile og_u64u*)(uintptr_t)(a))

static inline __m128 og_ld128(uint64_t a) { return _mm_loadu_ps((const float*)(uintptr_t)a); }
static inline void og_st128(uint64_t a, __m128 v) { _mm_storeu_ps((float*)(uintptr_t)a, v); }
static inline __m128 og_x(OgCtx* c, int i) { return _mm_load_ps(c->y[i].f); }
/* a VEX write of an xmm register zeroes the upper half of its ymm */
static inline void og_setx(OgCtx* c, int i, __m128 v) {
    _mm_store_ps(c->y[i].f, v);
    memset(&c->y[i].b[16], 0, 16);
}

/* --- flags --- */
static inline uint8_t og_parity(uint64_t r) { return (uint8_t)(!__builtin_parity((unsigned)(r & 0xFF))); }

#define OG_LOGIC(c, res, bits)                                                                      \
    do {                                                                                            \
        uint64_t og_lr_ = (uint64_t)(res); /* not `_r`: the lifter's `_r` would read itself */      \
        (c)->cf = 0; (c)->of = 0; (c)->af = 0;                                                      \
        (c)->zf = (uint8_t)((og_lr_ & OG_MASK(bits)) == 0);                                         \
        (c)->sf = (uint8_t)((og_lr_ >> ((bits) - 1)) & 1);                                          \
        (c)->pf = og_parity(og_lr_);                                                                \
    } while (0)

#define OG_MASK(bits) ((bits) == 64 ? ~0ull : ((1ull << (bits)) - 1))

static inline void og_add_flags(OgCtx* c, uint64_t a, uint64_t b, uint64_t r, int bits, uint64_t carry_in) {
    const uint64_t m = OG_MASK(bits);
    a &= m; b &= m; r &= m;
    const int sh = bits - 1;
    c->cf = (uint8_t)(bits == 64 ? (r < a || (carry_in && r == a)) : (((a + b + carry_in) >> bits) & 1));
    c->zf = (uint8_t)(r == 0);
    c->sf = (uint8_t)((r >> sh) & 1);
    c->of = (uint8_t)((((a ^ r) & (b ^ r)) >> sh) & 1);
    c->af = (uint8_t)(((a ^ b ^ r) >> 4) & 1);
    c->pf = og_parity(r);
}

static inline void og_sub_flags(OgCtx* c, uint64_t a, uint64_t b, uint64_t r, int bits, uint64_t borrow_in) {
    const uint64_t m = OG_MASK(bits);
    a &= m; b &= m; r &= m;
    const int sh = bits - 1;
    c->cf = (uint8_t)(borrow_in ? (a <= b) : (a < b));
    c->zf = (uint8_t)(r == 0);
    c->sf = (uint8_t)((r >> sh) & 1);
    c->of = (uint8_t)((((a ^ b) & (a ^ r)) >> sh) & 1);
    c->af = (uint8_t)(((a ^ b ^ r) >> 4) & 1);
    c->pf = og_parity(r);
}

/* conditions, by the jcc/setcc/cmovcc suffix */
#define OG_O(c) ((c)->of)
#define OG_NO(c) (!(c)->of)
#define OG_B(c) ((c)->cf)
#define OG_AE(c) (!(c)->cf)
#define OG_E(c) ((c)->zf)
#define OG_NE(c) (!(c)->zf)
#define OG_BE(c) ((c)->cf || (c)->zf)
#define OG_A(c) (!(c)->cf && !(c)->zf)
#define OG_S(c) ((c)->sf)
#define OG_NS(c) (!(c)->sf)
#define OG_P(c) ((c)->pf)
#define OG_NP(c) (!(c)->pf)
#define OG_L(c) ((c)->sf != (c)->of)
#define OG_GE(c) ((c)->sf == (c)->of)
#define OG_LE(c) ((c)->zf || (c)->sf != (c)->of)
#define OG_G(c) (!(c)->zf && (c)->sf == (c)->of)

/* --- division: a zero divisor or a quotient that does not fit is #DE, as on the hardware --- */
static inline __attribute__((noreturn)) void og_divide_error(void) {
#if defined(__x86_64__) || defined(_M_X64)
    volatile int og_z_ = 0;
    volatile int og_q_ = 1 / og_z_; /* the same exception the original raises */
    (void)og_q_;
#endif
    __builtin_trap();
}
static inline uint64_t og_udiv128(uint64_t hi, uint64_t lo, uint64_t d, uint64_t* rem) {
    if (d == 0 || hi >= d) og_divide_error();
#if defined(__x86_64__) || defined(_M_X64)
    uint64_t q, r;
    __asm__("divq %4" : "=a"(q), "=d"(r) : "a"(lo), "d"(hi), "rm"(d));
    *rem = r;
    return q;
#else
    unsigned __int128 n = ((unsigned __int128)hi << 64) | lo;
    *rem = (uint64_t)(n % d);
    return (uint64_t)(n / d);
#endif
}
static inline int64_t og_idiv128(int64_t hi, uint64_t lo, int64_t d, int64_t* rem) {
#if defined(__x86_64__) || defined(_M_X64)
    if (d == 0) og_divide_error();
    int64_t q, r;
    __asm__("idivq %4" : "=a"(q), "=d"(r) : "a"(lo), "d"(hi), "rm"(d));
    *rem = r;
    return q;
#else
    __int128 n = (__int128)(((unsigned __int128)(uint64_t)hi << 64) | lo);
    if (d == 0) og_divide_error();
    __int128 q = n / d;
    if (q > INT64_MAX || q < INT64_MIN) og_divide_error();
    *rem = (int64_t)(n % d);
    return (int64_t)q;
#endif
}

/* --- the guest stack --- */
#define OG_PUSH(c, v) do { uint64_t og_pv_ = (uint64_t)(v); (c)->r[RSP] -= 8; M64((c)->r[RSP]) = og_pv_; } while (0)
#define OG_POP(c) ((c)->r[RSP] += 8, M64((c)->r[RSP] - 8))

/* A tail jump to code that is not lifted. The host's call pushes a return address of its own, so
 * ours comes off first: the callee then sees the stack exactly as after the original jmp (same
 * alignment, same frame addresses), returns past our slot, and the slot gets our address back --
 * as the original leaves it. */
#define OG_TAIL(c, how, target)                                                                     \
    do {                                                                                            \
        uint64_t og_ra_ = M64((c)->r[RSP]);                                                         \
        (c)->r[RSP] += 8;                                                                           \
        how((c), (target));                                                                         \
        M64((c)->r[RSP] - 8) = og_ra_;                                                              \
        return;                                                                                     \
    } while (0)
