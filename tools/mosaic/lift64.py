"""OrbisGlue Mosaic: lifts the functions of a PS4 executable to C (Mosaic Recompilation).

    python tools/mosaic/lift64.py <eboot.bin> <out_dir> [--switchable] [--only leaf]

Functions come from .eh_frame. A function is lifted whole or not at all: every instruction in it
must be one the lifter knows, otherwise it stays native machine code -- the title runs the same
either way, and the share of lifted functions is the mosaic's coverage.

Output: og_lifted_<n>.c (the functions), og_table.c (address -> function), report.json.
"""
import argparse
import collections
import json
import os
import struct

import capstone
from capstone import x86

REGS64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
          'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
# name -> (index, bits, shift)
GPR = {}
for i, n in enumerate(REGS64):
    GPR[n] = (i, 64, 0)
for i, n in enumerate(['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']):
    GPR[n] = (i, 32, 0)
for i, n in enumerate(['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di']):
    GPR[n] = (i, 16, 0)
for i, n in enumerate(['al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil']):
    GPR[n] = (i, 8, 0)
for i, n in enumerate(['ah', 'ch', 'dh', 'bh']):
    GPR[n] = (i, 8, 8)
for i in range(8, 16):
    GPR[f'r{i}d'] = (i, 32, 0)
    GPR[f'r{i}w'] = (i, 16, 0)
    GPR[f'r{i}b'] = (i, 8, 0)

CONDS = {'o': 'O', 'no': 'NO', 'b': 'B', 'ae': 'AE', 'e': 'E', 'ne': 'NE', 'be': 'BE', 'a': 'A',
         's': 'S', 'ns': 'NS', 'p': 'P', 'np': 'NP', 'l': 'L', 'ge': 'GE', 'le': 'LE', 'g': 'G'}

U = {8: 'uint8_t', 16: 'uint16_t', 32: 'uint32_t', 64: 'uint64_t'}
S = {8: 'int8_t', 16: 'int16_t', 32: 'int32_t', 64: 'int64_t'}
M = {8: 'M8', 16: 'M16', 32: 'M32', 64: 'M64'}


class Unsupported(Exception):
    pass


MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
MD.detail = True


# ------------------------------------------------------------------ the executable

class Eboot:
    """A plaintext SELF (or plain ELF) seen at the addresses OrbisGlue loads it to."""

    def __init__(self, path, base):
        d = open(path, 'rb').read()
        self.base = base
        if d[:4] == b'\x7fELF':
            self._from_elf(d)
        else:
            self._from_self(d)
        self._functions()

    def _from_self(self, d):
        n, = struct.unpack_from('<H', d, 0x18)
        ents = [struct.unpack_from('<QQQQ', d, 0x20 + i * 0x20) for i in range(n)]
        eo = 0x20 + n * 0x20
        phoff, = struct.unpack_from('<Q', d, eo + 0x20)
        phnum, = struct.unpack_from('<H', d, eo + 0x38)
        self.ph = [struct.unpack_from('<IIQQQQQQ', d, eo + phoff + i * 0x38) for i in range(phnum)]
        self.segs = {}
        for e in ents:
            if e[0] & 0x800:
                idx = (e[0] >> 20) & 0xFFF
                self.segs[idx] = d[e[1]:e[1] + e[2]]

    def _from_elf(self, d):
        phoff, = struct.unpack_from('<Q', d, 0x20)
        phnum, = struct.unpack_from('<H', d, 0x38)
        self.ph = [struct.unpack_from('<IIQQQQQQ', d, phoff + i * 0x38) for i in range(phnum)]
        self.segs = {i: d[p[2]:p[2] + p[5]] for i, p in enumerate(self.ph)}

    def _functions(self):
        ci = next(i for i, p in enumerate(self.ph) if p[0] == 1 and (p[1] & 1))
        self.code_va = self.ph[ci][3]
        self.code = self.segs[ci]
        eh = next(p for p in self.ph if p[0] == 0x6474E550)
        eh_va = eh[3]
        h = self.read(eh_va, eh[6])

        def enc(pos, e):
            fmt, app = e & 0x0F, e & 0x70
            if fmt == 0x0B:
                v, = struct.unpack_from('<i', h, pos); size = 4
            elif fmt == 0x03:
                v, = struct.unpack_from('<I', h, pos); size = 4
            else:
                raise ValueError('eh_frame_hdr encoding %x' % e)
            if app == 0x10:
                v += eh_va + pos
            elif app == 0x30:
                v += eh_va
            return v, size

        pos = 4
        _, s = enc(pos, h[1]); pos += s
        count, s = enc(pos, h[2]); pos += s
        self.funcs = []
        for _ in range(count):
            _, s = enc(pos, h[3]); pos += s
            fde, s = enc(pos, h[3]); pos += s
            off = fde - self.code_va
            pc_begin, = struct.unpack_from('<i', self.code, off + 8)
            pc_range, = struct.unpack_from('<I', self.code, off + 12)
            self.funcs.append((fde + 8 + pc_begin, pc_range))
        self.funcs.sort()
        self.func_starts = {f for f, _ in self.funcs}

    def read(self, va, size):
        off = va - self.code_va
        return self.code[off:off + size]

    PRIVILEGED = {'sti', 'cli', 'in', 'out', 'insb', 'insw', 'insd', 'outsb', 'outsw', 'outsd', 'iret',
                  'iretd', 'iretq', 'retf', 'hlt', 'lgdt', 'lidt', 'lldt', 'ltr', 'invd', 'wbinvd', 'rdmsr',
                  'wrmsr', 'clts', 'sysret', 'sysexit', 'enter'}

    def noreturn(self):
        """Callees that never come back (__stack_chk_fail and friends): what follows a call to
        one is padding and then data. Found by what sits after their call sites -- the end of the
        function, bytes that do not decode, or instructions no user code has."""
        if hasattr(self, '_noreturn'):
            return self._noreturn
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        # one site proves nothing: after a call on a path the compiler knows to be undefined it
        # emits nothing either (the game's Free ends a few functions that way, and returns). A
        # callee is noreturn when nearly all of its call sites are followed by no code.
        sites = collections.Counter()
        found = collections.Counter()
        for start, size in self.funcs:
            blob = self.read(start, size)
            end = start + size
            for ins in md.disasm(blob, start):
                if ins.mnemonic != 'call' or not ins.op_str.startswith('0x'):
                    continue
                t = int(ins.op_str, 16)
                sites[t] += 1
                a = ins.address + ins.size
                while True:
                    if a >= end:
                        found[t] += 1
                        break
                    d = list(md.disasm(blob[a - start:], a, 1))
                    if not d or d[0].mnemonic in self.PRIVILEGED:
                        found[t] += 1
                        break
                    if d[0].mnemonic.startswith('nop') or d[0].mnemonic == 'int3':
                        a += d[0].size
                        continue
                    break
        self._noreturn = {t for t, n in found.items() if n * 10 >= sites[t] * 9}
        return self._noreturn

    def read_va(self, va, size):
        """Bytes at a vaddr in any loaded segment (jump tables live in .rodata), or b''."""
        for i, p in enumerate(self.ph):
            if p[0] == 1 and p[3] <= va and va + size <= p[3] + p[5] and i in self.segs:
                seg = self.segs[i]
                off = va - p[3]
                return seg[off:off + size] if off + size <= len(seg) else b''
        return b''


# ------------------------------------------------------------------ lifting one function

class FuncLifter:
    def __init__(self, eb, start, size, lifted_set):
        self.eb = eb
        self.start = start
        self.size = size
        self.lifted = lifted_set  # guest vaddrs that will be lifted (for direct calls)
        self.index_of = {}  # with --switchable: lifted vaddr -> its og_off switch
        self.out = []
        self.labels = set()
        self.calls = 0

    # --- operands -------------------------------------------------------------
    def rt(self, va):
        """A guest vaddr as the runtime address it has once loaded: the image goes wherever the
        loader finds room (og_base), so no address is baked in."""
        return f'(og_base + 0x{va:X}ull)'

    def reg_read(self, name):
        if name not in GPR:
            raise Unsupported('reg ' + name)
        i, bits, sh = GPR[name]
        if bits == 64:
            return f'c->r[{i}]'
        if sh:
            return f'(uint8_t)(c->r[{i}] >> 8)'
        return f'({U[bits]})c->r[{i}]'

    def reg_write(self, name, val):
        i, bits, sh = GPR[name]
        if bits == 64:
            return f'c->r[{i}] = (uint64_t)({val});'
        if bits == 32:
            return f'c->r[{i}] = (uint32_t)({val});'  # zero-extends, as x86-64 does
        mask = 0xFF << sh if bits == 8 else 0xFFFF
        return f'c->r[{i}] = (c->r[{i}] & ~0x{mask:X}ull) | ((uint64_t)({U[bits]})({val}) << {sh});'

    def addr(self, ins, op):
        m = op.mem
        if m.segment == x86.X86_REG_FS:
            parts = ['c->fs_base']
        elif m.segment not in (0, x86.X86_REG_INVALID):
            raise Unsupported('segment')
        else:
            parts = []
        if m.base == x86.X86_REG_RIP:
            return self.rt(ins.address + ins.size + m.disp)
        if m.base:
            parts.append(f'c->r[{GPR[ins.reg_name(m.base)][0]}]')
        if m.index:
            idx = f'c->r[{GPR[ins.reg_name(m.index)][0]}]'
            parts.append(f'{idx} * {m.scale}' if m.scale > 1 else idx)
        if m.disp:
            parts.append(f'(uint64_t)(int64_t){m.disp}')
        return '(' + ' + '.join(parts or ['0']) + ')'

    def read(self, ins, op, bits=None):
        if op.type == x86.X86_OP_REG:
            return self.reg_read(ins.reg_name(op.reg))
        if op.type == x86.X86_OP_IMM:
            b = bits or op.size * 8
            v = op.imm & ((1 << b) - 1) if b < 64 else op.imm & ((1 << 64) - 1)
            return f'({U[b]})0x{v:X}ull'
        if op.type == x86.X86_OP_MEM:
            return f'{M[op.size * 8]}({self.addr(ins, op)})'
        raise Unsupported('operand')

    def write(self, ins, op, val):
        if op.type == x86.X86_OP_REG:
            n = ins.reg_name(op.reg)
            if n not in GPR:
                raise Unsupported('reg ' + n)
            return self.reg_write(n, val)
        if op.type == x86.X86_OP_MEM:
            return f'{M[op.size * 8]}({self.addr(ins, op)}) = ({U[op.size * 8]})({val});'
        raise Unsupported('write')

    def xreg(self, ins, op):
        n = ins.reg_name(op.reg)
        if not (n.startswith('xmm') or n.startswith('ymm')):
            raise Unsupported('xreg ' + n)
        return int(n[3:])

    def emit(self, s):
        self.out.append('    ' + s)

    # --- one instruction ----------------------------------------------------------
    def lift_insn(self, ins, next_va):
        mn = ins.mnemonic
        ops = ins.operands
        e = self.emit
        w = ops[0].size * 8 if ops else 0

        if mn == 'nop' or mn == 'endbr64' or mn.startswith('nop'):
            return
        if mn == 'mov' or mn == 'movabs':
            e(self.write(ins, ops[0], self.read(ins, ops[1], w)))
            return
        if mn == 'movzx':
            e(self.write(ins, ops[0], f'(uint64_t){self.read(ins, ops[1])}'))
            return
        if mn in ('movsx', 'movsxd'):
            sb = ops[1].size * 8
            e(self.write(ins, ops[0], f'(uint64_t)(int64_t)({S[sb]}){self.read(ins, ops[1])}'))
            return
        if mn == 'lea':
            e(self.write(ins, ops[0], self.addr(ins, ops[1])))
            return
        if mn in ('add', 'sub', 'adc', 'sbb', 'cmp'):
            a = self.read(ins, ops[0])
            b = self.read(ins, ops[1], w)
            e('{')
            e(f'  uint64_t _a = (uint64_t){a}, _b = (uint64_t)({U[w]})({S[ops[1].size*8] if ops[1].type == x86.X86_OP_IMM else U[w]}){b};')
            carry = 'c->cf' if mn in ('adc', 'sbb') else '0'
            if mn in ('add', 'adc'):
                e(f'  uint64_t _r = _a + _b + {carry};')
                e(f'  og_add_flags(c, _a, _b, _r, {w}, {carry});')
            else:
                e(f'  uint64_t _r = _a - _b - {carry};')
                e(f'  og_sub_flags(c, _a, _b, _r, {w}, {carry});')
            if mn != 'cmp':
                e('  ' + self.write(ins, ops[0], '_r'))
            e('}')
            return
        if mn in ('and', 'or', 'xor', 'test'):
            a = self.read(ins, ops[0])
            b = self.read(ins, ops[1], w)
            op = {'and': '&', 'or': '|', 'xor': '^', 'test': '&'}[mn]
            if mn == 'xor' and ops[0].type == x86.X86_OP_REG and ops[1].type == x86.X86_OP_REG \
                    and ops[0].reg == ops[1].reg:
                e(self.write(ins, ops[0], '0'))
                e(f'OG_LOGIC(c, 0, {w});')
                return
            imm_s = ops[1].type == x86.X86_OP_IMM
            e('{')
            e(f'  uint64_t _r = (uint64_t)({U[w]})({a} {op} ({U[w]})({S[ops[1].size*8] if imm_s else U[w]}){b});')
            e(f'  OG_LOGIC(c, _r, {w});')
            if mn != 'test':
                e('  ' + self.write(ins, ops[0], '_r'))
            e('}')
            return
        if mn in ('inc', 'dec'):
            a = self.read(ins, ops[0])
            e('{')
            e(f'  uint8_t _cf = c->cf; uint64_t _a = (uint64_t){a};')
            if mn == 'inc':
                e('  uint64_t _r = _a + 1;')
                e(f'  og_add_flags(c, _a, 1, _r, {w}, 0);')
            else:
                e('  uint64_t _r = _a - 1;')
                e(f'  og_sub_flags(c, _a, 1, _r, {w}, 0);')
            e('  c->cf = _cf;')
            e('  ' + self.write(ins, ops[0], '_r'))
            e('}')
            return
        if mn == 'neg':
            a = self.read(ins, ops[0])
            e('{')
            e(f'  uint64_t _a = (uint64_t){a}; uint64_t _r = 0 - _a;')
            e(f'  og_sub_flags(c, 0, _a, _r, {w}, 0);')
            e('  ' + self.write(ins, ops[0], '_r'))
            e('}')
            return
        if mn == 'not':
            e(self.write(ins, ops[0], f'~{self.read(ins, ops[0])}'))
            return
        if mn in ('shl', 'sal', 'shr', 'sar'):
            a = self.read(ins, ops[0])
            if len(ops) == 1:
                cnt = '1'
            else:
                cnt = self.read(ins, ops[1], 8)
            m = 0x3F if w == 64 else 0x1F
            e('{')
            e(f'  unsigned _n = (unsigned)({cnt}) & {m}; uint64_t _a = (uint64_t){a};')
            e('  if (_n) {')
            if mn in ('shl', 'sal'):
                e(f'    uint64_t _r = _a << _n;')
                e(f'    c->cf = (uint8_t)((_a >> ({w} - _n)) & 1);')
                e(f'    OG_SHIFT_FLAGS(c, _r, {w}); if (_n == 1) c->of = (uint8_t)(((_r >> ({w}-1)) & 1) ^ c->cf);')
            elif mn == 'shr':
                e(f'    uint64_t _r = (_a & OG_MASK({w})) >> _n;')
                e('    c->cf = (uint8_t)((_a >> (_n - 1)) & 1);')
                e(f'    OG_SHIFT_FLAGS(c, _r, {w}); if (_n == 1) c->of = (uint8_t)((_a >> ({w}-1)) & 1);')
            else:
                e(f'    uint64_t _r = (uint64_t)((int64_t)({S[w]})_a >> _n);')
                e('    c->cf = (uint8_t)(((int64_t)(' + S[w] + ')_a >> (_n - 1)) & 1);')
                e(f'    OG_SHIFT_FLAGS(c, _r, {w}); if (_n == 1) c->of = 0;')
            e('    ' + self.write(ins, ops[0], '_r'))
            e('  }')
            e('}')
            return
        if mn == 'imul' and len(ops) >= 2:
            dst = ops[0]
            if len(ops) == 2:
                a, b = self.read(ins, ops[0]), self.read(ins, ops[1])
            else:
                a, b = self.read(ins, ops[1]), self.read(ins, ops[2], w)
            e('{')
            if w == 64:
                e(f'  int64_t _hi; int64_t _r = _mul128((int64_t){a}, (int64_t)({S[64]}){b}, &_hi);')
                e('  c->cf = c->of = (uint8_t)(_hi != (_r >> 63));')
            else:
                e(f'  int64_t _r = (int64_t)({S[w]}){a} * (int64_t)({S[w]}){b};')
                e(f'  c->cf = c->of = (uint8_t)(_r != (int64_t)({S[w]})_r);')
            e('  ' + self.write(ins, dst, '_r'))
            e('}')
            return
        if mn in ('cdqe', 'cwde', 'cbw'):
            if mn == 'cdqe':
                e('c->r[0] = (uint64_t)(int64_t)(int32_t)c->r[0];')
            elif mn == 'cwde':
                e('c->r[0] = (uint32_t)(int32_t)(int16_t)c->r[0];')
            else:
                e("c->r[0] = (c->r[0] & ~0xFFFFull) | (uint16_t)(int16_t)(int8_t)c->r[0];")
            return
        if mn in ('cdq', 'cqo'):
            if mn == 'cqo':
                e('c->r[2] = (uint64_t)((int64_t)c->r[0] >> 63);')
            else:
                e('c->r[2] = (uint32_t)((int32_t)c->r[0] >> 31);')
            return
        if mn.startswith('set') and mn[3:] in CONDS:
            e(self.write(ins, ops[0], f'OG_{CONDS[mn[3:]]}(c) ? 1 : 0'))
            return
        if mn.startswith('cmov') and mn[4:] in CONDS:
            # a 32-bit cmov zero-extends its destination even when the condition is false
            src = self.read(ins, ops[1])
            dst_cur = self.read(ins, ops[0])
            e(self.write(ins, ops[0], f'OG_{CONDS[mn[4:]]}(c) ? {src} : {dst_cur}'))
            return
        if mn == 'push':
            e(f'OG_PUSH(c, (uint64_t)(int64_t)({S[ops[0].size*8] if ops[0].type == x86.X86_OP_IMM else U[64]}){self.read(ins, ops[0], 64 if ops[0].type != x86.X86_OP_IMM else None)});')
            return
        if mn == 'pop':
            e('{ uint64_t _v = OG_POP(c); ' + self.write(ins, ops[0], '_v') + ' }')
            return
        if mn == 'leave':
            e('c->r[RSP] = c->r[RBP]; c->r[RBP] = OG_POP(c);')
            return
        if mn == 'ret':
            n = ops[0].imm if ops else 0
            e(f'c->r[RSP] += 8 + {n}; return;')
            return
        if mn == 'jmp':
            if ops[0].type != x86.X86_OP_IMM:
                # a switch (through a jump table found in decode) or a tail call through a pointer.
                # A target inside the function the tables did not name: the original code goes on
                # from there in this very frame, and its `ret` comes back through og_host->resume
                # put in our return slot -- only an all-lifted build needs every target known.
                self.calls += 1
                self.uses_sp0 = True
                e(f'{{ uint64_t _t = (uint64_t){self.read(ins, ops[0], 64)};')
                if self.table_targets:
                    e('  switch (_t - og_base) {')
                    for t in sorted(self.table_targets):
                        self.labels.add(t)
                        e(f'  case 0x{t:X}ull: goto L_{t:X};')
                    e('  default: break; }')
                e(f'  if (_t - {self.rt(self.start)} < 0x{self.size:X}ull) {{')
                e('    uint64_t _ra = M64(og_sp0); M64(og_sp0) = og_host->resume;')
                e('    og_host->jump_native(c, _t); M64(og_sp0) = _ra; return; }')
                e('  OG_TAIL(c, og_host->call_dynamic, _t); }')
                return
            t = ops[0].imm
            if self.start <= t < self.start + self.size:
                self.labels.add(t)
                e(f'goto L_{t:X};')
            else:
                # a tail call: the callee returns with our return address
                self.calls += 1
                if t in self.lifted:
                    i = self.index_of.get(t)
                    if i is None:
                        e(f'og_f_{t:X}(c); return;')
                    else:  # switchable: og_off[i] sends the call to the original instead
                        e(f'if (!og_off[{i}]) {{ og_f_{t:X}(c); return; }}')
                        e(f'OG_TAIL(c, og_host->call_native, {self.rt(t)});')
                else:
                    e(f'OG_TAIL(c, og_host->call_native, {self.rt(t)});')
            return
        if mn.startswith('j') and mn[1:] in CONDS:
            t = ops[0].imm
            if not (self.start <= t < self.start + self.size):
                raise Unsupported('jcc out of function')
            self.labels.add(t)
            e(f'if (OG_{CONDS[mn[1:]]}(c)) goto L_{t:X};')
            return
        if mn == 'call':
            self.calls += 1
            if ops[0].type == x86.X86_OP_IMM:
                t = ops[0].imm
                if t in self.lifted:
                    i = self.index_of.get(t)
                    if i is None:
                        e(f'OG_PUSH(c, {self.rt(next_va)}); og_f_{t:X}(c);')
                    else:
                        e(f'if (!og_off[{i}]) {{ OG_PUSH(c, {self.rt(next_va)}); og_f_{t:X}(c); }}')
                        e(f'else og_host->call_native(c, {self.rt(t)});')
                else:
                    e(f'og_host->call_native(c, {self.rt(t)});')
            else:
                e(f'og_host->call_dynamic(c, (uint64_t){self.read(ins, ops[0], 64)});')
            return

        if self.lift_int(ins, mn, ops, w):
            return
        # --- scalar / packed float (VEX and legacy SSE encodings) ---
        if self.lift_fp(ins, mn, ops):
            return
        if self.lift_simd(ins, mn, ops):
            return
        raise Unsupported(mn)

    # --- integer extras: bits, rotates, division, strings, atomics -------------------
    def mem_ptr(self, ins, op, bits):
        return f'(({U[bits]}*)(uintptr_t){self.addr(ins, op)})'

    def lift_int(self, ins, mn, ops, w):
        e = self.emit
        R, I, Mm = x86.X86_OP_REG, x86.X86_OP_IMM, x86.X86_OP_MEM
        if mn in ('prefetcht0', 'prefetcht1', 'prefetcht2', 'prefetchnta', 'prefetchw', 'prefetch'):
            return True
        if mn in ('mfence', 'lfence', 'sfence'):
            e('__atomic_thread_fence(__ATOMIC_SEQ_CST);')
            return True
        if mn == 'pause':
            e('_mm_pause();')
            return True
        if mn in ('ud2', 'int3', 'hlt', 'ud1', 'ud0', 'int', 'int1', 'into'):
            e('__builtin_trap();')  # the original stops here with an exception too
            return True
        if mn == 'pushfq':
            e('OG_PUSH(c, (uint64_t)c->cf | 2u | (uint64_t)c->pf << 2 | (uint64_t)c->af << 4 | (uint64_t)c->zf << 6 '
              '| (uint64_t)c->sf << 7 | 0x200u | (uint64_t)c->df << 10 | (uint64_t)c->of << 11);')
            return True
        if mn == 'popfq':
            e('{ uint64_t _f = OG_POP(c); c->cf = _f & 1; c->pf = (_f >> 2) & 1; c->af = (_f >> 4) & 1; '
              'c->zf = (_f >> 6) & 1; c->sf = (_f >> 7) & 1; c->df = (_f >> 10) & 1; c->of = (_f >> 11) & 1; }')
            return True
        if mn in ('clc', 'stc', 'cmc', 'cld', 'std'):
            e({'clc': 'c->cf = 0;', 'stc': 'c->cf = 1;', 'cmc': 'c->cf ^= 1;',
               'cld': 'c->df = 0;', 'std': 'c->df = 1;'}[mn])
            return True
        if mn == 'lahf':
            e('c->r[0] = (c->r[0] & ~0xFF00ull) | ((uint64_t)(c->sf << 7 | c->zf << 6 | c->af << 4 | c->pf << 2 | 2 | c->cf) << 8);')
            return True
        if mn == 'sahf':
            e('{ uint8_t _h = (uint8_t)(c->r[0] >> 8); c->sf = (_h >> 7) & 1; c->zf = (_h >> 6) & 1; '
              'c->af = (_h >> 4) & 1; c->pf = (_h >> 2) & 1; c->cf = _h & 1; }')
            return True
        if mn == 'cwd':
            e('c->r[2] = (c->r[2] & ~0xFFFFull) | (uint16_t)((int16_t)c->r[0] >> 15);')
            return True
        if mn == 'bswap':
            v = self.read(ins, ops[0])
            e(self.write(ins, ops[0], f'__builtin_bswap{w}({v})' if w in (32, 64) else v))
            return True
        if mn == 'movbe':
            bits = ops[0].size * 8
            e(self.write(ins, ops[0], f'__builtin_bswap{bits}({self.read(ins, ops[1])})'))
            return True
        if mn == 'xchg' and len(ops) == 2:
            a, b = ops
            if a.type == R and b.type == R:
                e('{ uint64_t _x = (uint64_t)' + self.read(ins, a) + ', _y = (uint64_t)' + self.read(ins, b) + '; '
                  + self.write(ins, a, '_y') + ' ' + self.write(ins, b, '_x') + ' }')
                return True
            m, r = (a, b) if a.type == Mm else (b, a)
            e(f'{{ {U[w]} _o = __atomic_exchange_n({self.mem_ptr(ins, m, w)}, ({U[w]}){self.read(ins, r)}, __ATOMIC_SEQ_CST); '
              + self.write(ins, r, '_o') + ' }')
            return True
        if mn in ('andn',):
            e('{')
            e(f'  uint64_t _r = (uint64_t)(({U[w]})~{self.read(ins, ops[1])} & ({U[w]}){self.read(ins, ops[2])});')
            e(f'  OG_LOGIC(c, _r, {w});')
            e('  ' + self.write(ins, ops[0], '_r'))
            e('}')
            return True
        if mn in ('blsi', 'blsr', 'blsmsk'):
            e('{')
            e(f'  uint64_t _s = (uint64_t)({U[w]}){self.read(ins, ops[1])}, _r;')
            if mn == 'blsi':
                e(f'  _r = (_s & (0 - _s)) & OG_MASK({w}); OG_LOGIC(c, _r, {w}); c->cf = (uint8_t)(_s != 0);')
            elif mn == 'blsr':
                e(f'  _r = (_s & (_s - 1)) & OG_MASK({w}); OG_LOGIC(c, _r, {w}); c->cf = (uint8_t)(_s == 0);')
            else:
                e(f'  _r = (_s ^ (_s - 1)) & OG_MASK({w}); OG_LOGIC(c, _r, {w}); c->cf = (uint8_t)(_s == 0);')
            e('  ' + self.write(ins, ops[0], '_r'))
            e('}')
            return True
        if mn == 'bextr':
            e('{')
            e(f'  uint64_t _s = (uint64_t)({U[w]}){self.read(ins, ops[1])}; unsigned _ctl = (unsigned){self.read(ins, ops[2])};')
            e(f'  unsigned _st = _ctl & 0xFF, _ln = (_ctl >> 8) & 0xFF;')
            e(f'  uint64_t _r = _st >= {w} ? 0 : _s >> _st; if (_ln < {w}) _r &= (1ull << _ln) - 1;')
            e(f'  OG_LOGIC(c, _r, {w});')
            e('  ' + self.write(ins, ops[0], '_r'))
            e('}')
            return True
        if mn in ('lzcnt', 'tzcnt', 'popcnt'):
            e('{')
            e(f'  uint64_t _s = (uint64_t)({U[w]}){self.read(ins, ops[1])}; uint64_t _r;')
            if mn == 'lzcnt':
                e(f'  _r = _s ? (uint64_t)(__builtin_clzll(_s) - (64 - {w})) : {w}; c->cf = (uint8_t)(_s == 0); c->zf = (uint8_t)(_r == 0);')
            elif mn == 'tzcnt':
                e(f'  _r = _s ? (uint64_t)__builtin_ctzll(_s) : {w}; c->cf = (uint8_t)(_s == 0); c->zf = (uint8_t)(_r == 0);')
            else:
                e('  _r = (uint64_t)__builtin_popcountll(_s); c->zf = (uint8_t)(_s == 0); '
                  'c->cf = c->of = c->sf = c->af = c->pf = 0;')
            e('  ' + self.write(ins, ops[0], '_r'))
            e('}')
            return True
        if mn in ('bsf', 'bsr'):
            # a zero source leaves the destination as it was (AMD, and Jaguar is one)
            e('{')
            e(f'  uint64_t _s = (uint64_t)({U[w]}){self.read(ins, ops[1])};')
            e('  c->zf = (uint8_t)(_s == 0);')
            fn = '(uint64_t)__builtin_ctzll(_s)' if mn == 'bsf' else '(uint64_t)(63 - __builtin_clzll(_s))'
            e('  if (_s) { ' + self.write(ins, ops[0], fn) + ' }')
            e('}')
            return True
        if mn in ('bt', 'bts', 'btr', 'btc') or (mn.startswith('lock ') and mn[5:] in ('bts', 'btr', 'btc')):
            locked = mn.startswith('lock ')
            op = mn[5:] if locked else mn
            d, s = ops
            e('{')
            if d.type == R or s.type == I:
                e(f'  unsigned _b = (unsigned)({self.read(ins, s)}) & {w - 1};')
                if d.type == Mm:
                    e(f'  {U[w]}* _p = {self.mem_ptr(ins, d, w)};')
            else:
                shift = {16: 4, 32: 5, 64: 6}[w]
                e(f'  int64_t _o = (int64_t)({S[w]}){self.read(ins, s)}; unsigned _b = (unsigned)(_o & {w - 1});')
                e(f'  {U[w]}* _p = ({U[w]}*)(uintptr_t)({self.addr(ins, d)} + (uint64_t)((_o >> {shift}) * {w // 8}));')
            if d.type == R:
                e(f'  uint64_t _v = (uint64_t){self.read(ins, d)}; c->cf = (uint8_t)((_v >> _b) & 1);')
                if op != 'bt':
                    nv = {'bts': '_v | (1ull << _b)', 'btr': '_v & ~(1ull << _b)', 'btc': '_v ^ (1ull << _b)'}[op]
                    e('  ' + self.write(ins, d, nv))
            elif op == 'bt':
                e('  c->cf = (uint8_t)((*(volatile ' + U[w] + '*)_p >> _b) & 1);')
            elif locked:
                fn = {'bts': '__atomic_fetch_or', 'btr': '__atomic_fetch_and', 'btc': '__atomic_fetch_xor'}[op]
                m = f'({U[w]})(1ull << _b)' if op != 'btr' else f'({U[w]})~(1ull << _b)'
                e(f'  {U[w]} _v = {fn}(_p, {m}, __ATOMIC_SEQ_CST); c->cf = (uint8_t)((_v >> _b) & 1);')
            else:
                e(f'  {U[w]} _v = *_p; c->cf = (uint8_t)((_v >> _b) & 1);')
                nv = {'bts': '_v | (1ull << _b)', 'btr': '_v & ~(1ull << _b)', 'btc': '_v ^ (1ull << _b)'}[op]
                e(f'  *_p = ({U[w]})({nv});')
            e('}')
            return True
        if mn in ('rol', 'ror'):
            cnt = '1' if len(ops) == 1 else self.read(ins, ops[1], 8)
            m = 0x3F if w == 64 else 0x1F
            e('{')
            e(f'  unsigned _n = (unsigned)({cnt}) & {m}; uint64_t _a = (uint64_t)({U[w]}){self.read(ins, ops[0])};')
            e(f'  if (_n) {{ unsigned _k = _n % {w}; uint64_t _r = _k ? ((_a << _k) | (_a >> ({w} - _k))) & OG_MASK({w}) : _a;'
              if mn == 'rol' else
              f'  if (_n) {{ unsigned _k = _n % {w}; uint64_t _r = _k ? ((_a >> _k) | (_a << ({w} - _k))) & OG_MASK({w}) : _a;')
            if mn == 'rol':
                e(f'    c->cf = (uint8_t)(_r & 1); if (_n == 1) c->of = (uint8_t)(((_r >> {w - 1}) & 1) ^ c->cf);')
            else:
                e(f'    c->cf = (uint8_t)((_r >> {w - 1}) & 1); if (_n == 1) c->of = (uint8_t)(c->cf ^ ((_r >> {w - 2}) & 1));')
            e('    ' + self.write(ins, ops[0], '_r') + ' }')
            e('}')
            return True
        if mn in ('shld', 'shrd') and w in (32, 64):
            m = 0x3F if w == 64 else 0x1F
            e('{')
            e(f'  unsigned _n = (unsigned)({self.read(ins, ops[2], 8)}) & {m};')
            e(f'  uint64_t _d = (uint64_t)({U[w]}){self.read(ins, ops[0])}, _s = (uint64_t)({U[w]}){self.read(ins, ops[1])};')
            e('  if (_n) {')
            if mn == 'shld':
                e(f'    uint64_t _r = ((_d << _n) | (_s >> ({w} - _n))) & OG_MASK({w});')
                e(f'    c->cf = (uint8_t)((_d >> ({w} - _n)) & 1);')
            else:
                e(f'    uint64_t _r = ((_d >> _n) | (_s << ({w} - _n))) & OG_MASK({w});')
                e('    c->cf = (uint8_t)((_d >> (_n - 1)) & 1);')
            e(f'    OG_SHIFT_FLAGS(c, _r, {w}); if (_n == 1) c->of = (uint8_t)(((_r ^ _d) >> {w - 1}) & 1);')
            e('    ' + self.write(ins, ops[0], '_r'))
            e('  }')
            e('}')
            return True
        if mn in ('mul', 'imul') and len(ops) == 1:
            s = self.read(ins, ops[0])
            sg = mn == 'imul'
            e('{')
            if w == 64:
                if sg:
                    e(f'  int64_t _hi; int64_t _lo = _mul128((int64_t)c->r[0], (int64_t){s}, &_hi);')
                    e('  c->cf = c->of = (uint8_t)(_hi != (_lo >> 63));')
                else:
                    e(f'  uint64_t _hi; uint64_t _lo = _umul128(c->r[0], (uint64_t){s}, &_hi);')
                    e('  c->cf = c->of = (uint8_t)(_hi != 0);')
                e('  c->r[0] = (uint64_t)_lo; c->r[2] = (uint64_t)_hi;')
            else:
                t = S if sg else U
                e(f'  int64_t _p = (int64_t)({t[w]})c->r[0] * (int64_t)({t[w]}){s};' if sg else
                  f'  uint64_t _p = (uint64_t)({t[w]})c->r[0] * (uint64_t)({t[w]}){s};')
                if sg:
                    e(f'  c->cf = c->of = (uint8_t)(_p != (int64_t)({S[w]})_p);')
                else:
                    e(f'  c->cf = c->of = (uint8_t)((_p >> {w}) != 0);')
                if w == 8:
                    e('  c->r[0] = (c->r[0] & ~0xFFFFull) | ((uint64_t)_p & 0xFFFF);')
                elif w == 16:
                    e('  c->r[0] = (c->r[0] & ~0xFFFFull) | ((uint64_t)_p & 0xFFFF); '
                      'c->r[2] = (c->r[2] & ~0xFFFFull) | (((uint64_t)_p >> 16) & 0xFFFF);')
                else:
                    e('  c->r[0] = (uint32_t)(uint64_t)_p; c->r[2] = (uint32_t)((uint64_t)_p >> 32);')
            e('}')
            return True
        if mn in ('div', 'idiv'):
            s = self.read(ins, ops[0])
            e('{')
            if mn == 'div':
                if w == 64:
                    e(f'  uint64_t _d = (uint64_t){s}, _q, _m;')
                    e('  if (c->r[2] == 0) { if (!_d) og_divide_error(); _q = c->r[0] / _d; _m = c->r[0] % _d; }')
                    e('  else _q = og_udiv128(c->r[2], c->r[0], _d, &_m);')
                    e('  c->r[0] = _q; c->r[2] = _m;')
                else:
                    num = {8: '(uint64_t)(uint16_t)c->r[0]', 16: '(((uint64_t)(uint16_t)c->r[2] << 16) | (uint16_t)c->r[0])',
                           32: '(((uint64_t)(uint32_t)c->r[2] << 32) | (uint32_t)c->r[0])'}[w]
                    e(f'  uint64_t _d = (uint64_t)({U[w]}){s}, _n = {num};')
                    e(f'  if (!_d || _n / _d > OG_MASK({w})) og_divide_error();')
                    e('  uint64_t _q = _n / _d, _m = _n % _d;')
            else:
                if w == 64:
                    e(f'  int64_t _d = (int64_t){s}, _q, _m;')
                    e('  if ((int64_t)c->r[2] == ((int64_t)c->r[0] >> 63)) {')
                    e('    if (!_d || ((int64_t)c->r[0] == INT64_MIN && _d == -1)) og_divide_error();')
                    e('    _q = (int64_t)c->r[0] / _d; _m = (int64_t)c->r[0] % _d; }')
                    e('  else _q = og_idiv128((int64_t)c->r[2], c->r[0], _d, &_m);')
                    e('  c->r[0] = (uint64_t)_q; c->r[2] = (uint64_t)_m;')
                else:
                    num = {8: '(int64_t)(int16_t)c->r[0]', 16: '(int64_t)(int32_t)(((uint32_t)(uint16_t)c->r[2] << 16) | (uint16_t)c->r[0])',
                           32: '(int64_t)(((uint64_t)(uint32_t)c->r[2] << 32) | (uint32_t)c->r[0])'}[w]
                    e(f'  int64_t _d = (int64_t)({S[w]}){s}, _n = {num};')
                    e('  if (!_d || (_n == INT64_MIN && _d == -1)) og_divide_error();')
                    e(f'  int64_t _q = _n / _d, _m = _n % _d;')
                    e(f'  if (_q != (int64_t)({S[w]})_q) og_divide_error();')
            if w != 64:
                if w == 8:
                    e('  c->r[0] = (c->r[0] & ~0xFFFFull) | ((uint64_t)(uint8_t)_q) | ((uint64_t)(uint8_t)_m << 8);')
                elif w == 16:
                    e('  c->r[0] = (c->r[0] & ~0xFFFFull) | (uint16_t)_q; c->r[2] = (c->r[2] & ~0xFFFFull) | (uint16_t)_m;')
                else:
                    e('  c->r[0] = (uint32_t)_q; c->r[2] = (uint32_t)_m;')
            e('}')
            return True
        if mn.startswith('rep ') and mn[4:] in ('movsb', 'movsw', 'movsd', 'movsq', 'stosb', 'stosw', 'stosd', 'stosq'):
            k = mn[4:]
            n = {'b': 1, 'w': 2, 'd': 4, 'q': 8}[k[-1]]
            e('{')
            e(f'  uint64_t _cnt = c->r[RCX]; int64_t _st = c->df ? -{n} : {n};')
            if k.startswith('movs'):
                e(f'  if (!c->df && (c->r[RDI] + _cnt * {n} <= c->r[RSI] || c->r[RSI] + _cnt * {n} <= c->r[RDI])) {{')
                e(f'    memcpy((void*)(uintptr_t)c->r[RDI], (const void*)(uintptr_t)c->r[RSI], _cnt * {n});')
                e(f'    c->r[RDI] += _cnt * {n}; c->r[RSI] += _cnt * {n}; c->r[RCX] = 0;')
                e('  } else {')
                e(f'    while (c->r[RCX]) {{ M{n * 8}(c->r[RDI]) = M{n * 8}(c->r[RSI]); c->r[RDI] += _st; c->r[RSI] += _st; c->r[RCX]--; }}')
                e('  }')
            else:
                val = f'({U[n * 8]})c->r[0]'
                if n == 1:
                    e('  if (!c->df) { memset((void*)(uintptr_t)c->r[RDI], (uint8_t)c->r[0], _cnt); c->r[RDI] += _cnt; c->r[RCX] = 0; }')
                e(f'  while (c->r[RCX]) {{ M{n * 8}(c->r[RDI]) = {val}; c->r[RDI] += _st; c->r[RCX]--; }}')
            e('}')
            return True
        if mn.startswith('lock '):
            op = mn[5:]
            d = ops[0]
            if d.type != Mm:
                raise Unsupported(mn)
            p = self.mem_ptr(ins, d, w)
            e('{')
            if op in ('inc', 'dec'):
                fn = '__atomic_fetch_add' if op == 'inc' else '__atomic_fetch_sub'
                e(f'  uint8_t _cf = c->cf; uint64_t _a = (uint64_t){fn}({p}, 1, __ATOMIC_SEQ_CST);')
                if op == 'inc':
                    e(f'  og_add_flags(c, _a, 1, _a + 1, {w}, 0);')
                else:
                    e(f'  og_sub_flags(c, _a, 1, _a - 1, {w}, 0);')
                e('  c->cf = _cf;')
            elif op in ('add', 'sub', 'xadd'):
                src = ops[1]
                b = self.read(ins, src, w)
                bv = f'({U[w]})({S[src.size * 8]}){b}' if src.type == I else f'({U[w]}){b}'
                fn = '__atomic_fetch_sub' if op == 'sub' else '__atomic_fetch_add'
                e(f'  uint64_t _b = (uint64_t){bv}; uint64_t _a = (uint64_t){fn}({p}, ({U[w]})_b, __ATOMIC_SEQ_CST);')
                if op == 'sub':
                    e(f'  og_sub_flags(c, _a, _b, _a - _b, {w}, 0);')
                else:
                    e(f'  og_add_flags(c, _a, _b, _a + _b, {w}, 0);')
                if op == 'xadd':
                    e('  ' + self.write(ins, src, '_a'))
            elif op in ('and', 'or', 'xor'):
                src = ops[1]
                b = self.read(ins, src, w)
                bv = f'({U[w]})({S[src.size * 8]}){b}' if src.type == I else f'({U[w]}){b}'
                sym = {'and': '&', 'or': '|', 'xor': '^'}[op]
                e(f'  {U[w]} _b = {bv}; {U[w]} _a = __atomic_fetch_{op}({p}, _b, __ATOMIC_SEQ_CST);')
                e(f'  OG_LOGIC(c, (uint64_t)({U[w]})(_a {sym} _b), {w});')
            elif op == 'cmpxchg':
                acc = {8: 'al', 16: 'ax', 32: 'eax', 64: 'rax'}[w]
                e(f'  {U[w]} _e = ({U[w]})c->r[0], _o = _e;')
                e(f'  int _ok = __atomic_compare_exchange_n({p}, &_o, ({U[w]}){self.read(ins, ops[1])}, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);')
                e(f'  og_sub_flags(c, _e, _o, (uint64_t)_e - (uint64_t)_o, {w}, 0);')
                e('  if (!_ok) { ' + self.reg_write(acc, '_o') + ' }')
            elif op in ('neg', 'not'):
                raise Unsupported(mn)
            else:
                raise Unsupported(mn)
            e('}')
            return True
        if mn == 'cmpxchg' and ops[0].type == Mm:
            acc = {8: 'al', 16: 'ax', 32: 'eax', 64: 'rax'}[w]
            p = self.mem_ptr(ins, ops[0], w)
            e('{')
            e(f'  {U[w]} _e = ({U[w]})c->r[0], _o = *(volatile {U[w]}*){p};')
            e(f'  og_sub_flags(c, _e, _o, (uint64_t)_e - (uint64_t)_o, {w}, 0);')
            e(f'  if (_e == _o) *{p} = ({U[w]}){self.read(ins, ops[1])}; else {{ ' + self.reg_write(acc, '_o') + ' }')
            e('}')
            return True
        return False

    def lift_fp(self, ins, mn, ops):
        e = self.emit
        base = mn[1:] if mn.startswith('v') else mn
        vex = mn.startswith('v')
        if base in ('movss', 'movsd') and len(ops) == 2:
            lane = 4 if base == 'movss' else 8
            d, s = ops
            if d.type == x86.X86_OP_REG and s.type == x86.X86_OP_MEM:
                xi = self.xreg(ins, d)
                e(f'{{ __m128 _v = _mm_setzero_ps(); memcpy(&_v, (void*)(uintptr_t){self.addr(ins, s)}, {lane}); '
                  + (f'og_setx(c, {xi}, _v); }}' if vex else f'_mm_store_ps(c->y[{xi}].f, _v); }}'))
                return True
            if d.type == x86.X86_OP_MEM and s.type == x86.X86_OP_REG:
                xi = self.xreg(ins, s)
                e(f'memcpy((void*)(uintptr_t){self.addr(ins, d)}, c->y[{xi}].b, {lane});')
                return True
            if d.type == x86.X86_OP_REG and s.type == x86.X86_OP_REG and not vex:
                di, si = self.xreg(ins, d), self.xreg(ins, s)
                e(f'memcpy(c->y[{di}].b, c->y[{si}].b, {lane});')
                return True
            return False
        if base in ('movss', 'movsd') and len(ops) == 3 and vex:
            d, a, b = (self.xreg(ins, o) for o in ops)
            lane = 4 if base == 'movss' else 8
            e(f'{{ __m128 _v = og_x(c, {a}); memcpy(&_v, c->y[{b}].b, {lane}); og_setx(c, {d}, _v); }}')
            return True
        if base in ('movaps', 'movups', 'movapd', 'movupd', 'movdqa', 'movdqu') and len(ops) == 2:
            d, s = ops
            if d.size != 16 or s.size != 16:
                return False
            if d.type == x86.X86_OP_REG and s.type == x86.X86_OP_MEM:
                xi = self.xreg(ins, d)
                e(f'og_setx(c, {xi}, og_ld128({self.addr(ins, s)}));' if vex else
                  f'_mm_store_ps(c->y[{xi}].f, og_ld128({self.addr(ins, s)}));')
                return True
            if d.type == x86.X86_OP_MEM and s.type == x86.X86_OP_REG:
                e(f'og_st128({self.addr(ins, d)}, og_x(c, {self.xreg(ins, s)}));')
                return True
            if d.type == x86.X86_OP_REG and s.type == x86.X86_OP_REG:
                e(f'og_setx(c, {self.xreg(ins, d)}, og_x(c, {self.xreg(ins, s)}));' if vex else
                  f'_mm_store_ps(c->y[{self.xreg(ins, d)}].f, og_x(c, {self.xreg(ins, s)}));')
                return True
            return False
        arith = {'addss': '_mm_add_ss', 'subss': '_mm_sub_ss', 'mulss': '_mm_mul_ss', 'divss': '_mm_div_ss',
                 'minss': '_mm_min_ss', 'maxss': '_mm_max_ss', 'sqrtss': None,
                 'addps': '_mm_add_ps', 'subps': '_mm_sub_ps', 'mulps': '_mm_mul_ps', 'divps': '_mm_div_ps',
                 'minps': '_mm_min_ps', 'maxps': '_mm_max_ps',
                 'andps': '_mm_and_ps', 'andnps': '_mm_andnot_ps', 'orps': '_mm_or_ps', 'xorps': '_mm_xor_ps',
                 'unpcklps': '_mm_unpacklo_ps', 'unpckhps': '_mm_unpackhi_ps'}
        if base in arith and arith[base] and ops[0].size == 16 or (base in arith and arith[base] and base.endswith('ss')):
            fn = arith[base]
            scalar = base.endswith('ss')
            if vex and len(ops) == 3:
                d = self.xreg(ins, ops[0]); a = f'og_x(c, {self.xreg(ins, ops[1])})'; src = ops[2]
            elif not vex and len(ops) == 2:
                d = self.xreg(ins, ops[0]); a = f'og_x(c, {d})'; src = ops[1]
            else:
                return False
            if src.type == x86.X86_OP_REG:
                b = f'og_x(c, {self.xreg(ins, src)})'
            elif scalar:
                b = f'_mm_load_ss((const float*)(uintptr_t){self.addr(ins, src)})'
            else:
                b = f'og_ld128({self.addr(ins, src)})'
            if vex:
                e(f'og_setx(c, {d}, {fn}({a}, {b}));')
            else:
                e(f'_mm_store_ps(c->y[{d}].f, {fn}({a}, {b}));')
            return True
        if base in ('ucomiss', 'comiss') and len(ops) == 2:
            a = f'og_x(c, {self.xreg(ins, ops[0])})'
            src = ops[1]
            b = f'og_x(c, {self.xreg(ins, src)})' if src.type == x86.X86_OP_REG else \
                f'_mm_load_ss((const float*)(uintptr_t){self.addr(ins, src)})'
            e(f'{{ float _a = _mm_cvtss_f32({a}), _b = _mm_cvtss_f32({b});')
            e('  if (_a != _a || _b != _b) { c->zf = c->pf = c->cf = 1; }')
            e('  else { c->zf = (uint8_t)(_a == _b); c->pf = 0; c->cf = (uint8_t)(_a < _b); }')
            e('  c->of = c->sf = c->af = 0; }')
            return True
        return False

    # --- more SSE/AVX: conversions, compares, shuffles, integer vectors ---------------
    def isx(self, ins, op):
        return op.type == x86.X86_OP_REG and ins.reg_name(op.reg)[:3] in ('xmm', 'ymm')

    def xsrc(self, ins, op):
        """An xmm operand (or the memory it may be) as __m128; a narrow load fills only the low lane."""
        if op.type == x86.X86_OP_REG:
            return f'og_x(c, {self.xreg(ins, op)})'
        if op.type == x86.X86_OP_MEM:
            a = self.addr(ins, op)
            if op.size == 4:
                return f'_mm_load_ss((const float*)(uintptr_t){a})'
            if op.size == 8:
                return f'_mm_castpd_ps(_mm_load_sd((const double*)(uintptr_t){a}))'
            if op.size == 16:
                return f'og_ld128({a})'
        raise Unsupported('xsrc')

    def xdst(self, d, v, vex):
        return f'og_setx(c, {d}, {v});' if vex else f'_mm_store_ps(c->y[{d}].f, {v});'

    def x3(self, ins, ops, vex, n_imm=0):
        """dst, first source, second source of `op dst, src` (legacy) or `vop dst, a, src` (VEX)."""
        if vex and len(ops) == 3 + n_imm:
            return self.xreg(ins, ops[0]), f'og_x(c, {self.xreg(ins, ops[1])})', ops[2]
        if not vex and len(ops) == 2 + n_imm:
            d = self.xreg(ins, ops[0])
            return d, f'og_x(c, {d})', ops[1]
        raise Unsupported('form')

    # predicates of cmpss/cmpsd/cmpps by mnemonic infix, as the AVX imm8 encodes them
    CMP_PRED = ['eq', 'lt', 'le', 'unord', 'neq', 'nlt', 'nle', 'ord', 'eq_uq', 'nge', 'ngt', 'false',
                'neq_oq', 'ge', 'gt', 'true', 'eq_os', 'lt_oq', 'le_oq', 'unord_s', 'neq_us', 'nlt_uq',
                'nle_uq', 'ord_s', 'eq_us', 'nge_uq', 'ngt_uq', 'false_os', 'neq_os', 'ge_oq', 'gt_oq', 'true_us']

    SIMD_BIN = {  # name: (expression on _a, _b as __m128, kind of a narrow memory source)
        'addsd': ('_mm_castpd_ps(_mm_add_sd(_mm_castps_pd(_a), _mm_castps_pd(_b)))', 8),
        'subsd': ('_mm_castpd_ps(_mm_sub_sd(_mm_castps_pd(_a), _mm_castps_pd(_b)))', 8),
        'mulsd': ('_mm_castpd_ps(_mm_mul_sd(_mm_castps_pd(_a), _mm_castps_pd(_b)))', 8),
        'divsd': ('_mm_castpd_ps(_mm_div_sd(_mm_castps_pd(_a), _mm_castps_pd(_b)))', 8),
        'minsd': ('_mm_castpd_ps(_mm_min_sd(_mm_castps_pd(_a), _mm_castps_pd(_b)))', 8),
        'maxsd': ('_mm_castpd_ps(_mm_max_sd(_mm_castps_pd(_a), _mm_castps_pd(_b)))', 8),
        'sqrtss': ('_mm_move_ss(_a, _mm_sqrt_ss(_b))', 4),
        'sqrtsd': ('_mm_castpd_ps(_mm_sqrt_sd(_mm_castps_pd(_a), _mm_castps_pd(_b)))', 8),
        'rcpss': ('_mm_move_ss(_a, _mm_rcp_ss(_b))', 4),
        'rsqrtss': ('_mm_move_ss(_a, _mm_rsqrt_ss(_b))', 4),
        'cvtss2sd': ('_mm_castpd_ps(_mm_cvtss_sd(_mm_castps_pd(_a), _b))', 4),
        'cvtsd2ss': ('_mm_cvtsd_ss(_a, _mm_castps_pd(_b))', 8),
        'addpd': ('_mm_castpd_ps(_mm_add_pd(_mm_castps_pd(_a), _mm_castps_pd(_b)))', 16),
        'subpd': ('_mm_castpd_ps(_mm_sub_pd(_mm_castps_pd(_a), _mm_castps_pd(_b)))', 16),
        'mulpd': ('_mm_castpd_ps(_mm_mul_pd(_mm_castps_pd(_a), _mm_castps_pd(_b)))', 16),
        'divpd': ('_mm_castpd_ps(_mm_div_pd(_mm_castps_pd(_a), _mm_castps_pd(_b)))', 16),
        'andpd': ('_mm_and_ps(_a, _b)', 16), 'andnpd': ('_mm_andnot_ps(_a, _b)', 16),
        'orpd': ('_mm_or_ps(_a, _b)', 16), 'xorpd': ('_mm_xor_ps(_a, _b)', 16),
        'unpcklpd': ('_mm_castpd_ps(_mm_unpacklo_pd(_mm_castps_pd(_a), _mm_castps_pd(_b)))', 16),
        'unpckhpd': ('_mm_castpd_ps(_mm_unpackhi_pd(_mm_castps_pd(_a), _mm_castps_pd(_b)))', 16),
        'movhlps': ('_mm_movehl_ps(_a, _b)', 16), 'movlhps': ('_mm_movelh_ps(_a, _b)', 16),
        'haddps': ('_mm_hadd_ps(_a, _b)', 16), 'hsubps': ('_mm_hsub_ps(_a, _b)', 16),
        'haddpd': ('_mm_castpd_ps(_mm_hadd_pd(_mm_castps_pd(_a), _mm_castps_pd(_b)))', 16),
        'minpd': ('_mm_castpd_ps(_mm_min_pd(_mm_castps_pd(_a), _mm_castps_pd(_b)))', 16),
        'maxpd': ('_mm_castpd_ps(_mm_max_pd(_mm_castps_pd(_a), _mm_castps_pd(_b)))', 16),
        'addsubps': ('_mm_addsub_ps(_a, _b)', 16),
        'pxor': ('_mm_xor_ps(_a, _b)', 16), 'pand': ('_mm_and_ps(_a, _b)', 16),
        'por': ('_mm_or_ps(_a, _b)', 16), 'pandn': ('_mm_andnot_ps(_a, _b)', 16),
    }
    SIMD_INT = {  # integer vector ops: __m128i intrinsic on (_a, _b)
        'paddb': '_mm_add_epi8', 'paddw': '_mm_add_epi16', 'paddd': '_mm_add_epi32', 'paddq': '_mm_add_epi64',
        'psubb': '_mm_sub_epi8', 'psubw': '_mm_sub_epi16', 'psubd': '_mm_sub_epi32', 'psubq': '_mm_sub_epi64',
        'paddusb': '_mm_adds_epu8', 'paddusw': '_mm_adds_epu16', 'psubusb': '_mm_subs_epu8', 'psubusw': '_mm_subs_epu16',
        'paddsb': '_mm_adds_epi8', 'paddsw': '_mm_adds_epi16', 'psubsb': '_mm_subs_epi8', 'psubsw': '_mm_subs_epi16',
        'pcmpeqb': '_mm_cmpeq_epi8', 'pcmpeqw': '_mm_cmpeq_epi16', 'pcmpeqd': '_mm_cmpeq_epi32', 'pcmpeqq': '_mm_cmpeq_epi64',
        'pcmpgtb': '_mm_cmpgt_epi8', 'pcmpgtw': '_mm_cmpgt_epi16', 'pcmpgtd': '_mm_cmpgt_epi32', 'pcmpgtq': '_mm_cmpgt_epi64',
        'pmullw': '_mm_mullo_epi16', 'pmulld': '_mm_mullo_epi32', 'pmulhw': '_mm_mulhi_epi16', 'pmulhuw': '_mm_mulhi_epu16',
        'pmuludq': '_mm_mul_epu32', 'pmuldq': '_mm_mul_epi32', 'pmaddwd': '_mm_madd_epi16',
        'pminsb': '_mm_min_epi8', 'pmaxsb': '_mm_max_epi8', 'pminsw': '_mm_min_epi16', 'pmaxsw': '_mm_max_epi16',
        'pminsd': '_mm_min_epi32', 'pmaxsd': '_mm_max_epi32', 'pminub': '_mm_min_epu8', 'pmaxub': '_mm_max_epu8',
        'pminuw': '_mm_min_epu16', 'pmaxuw': '_mm_max_epu16', 'pminud': '_mm_min_epu32', 'pmaxud': '_mm_max_epu32',
        'pavgb': '_mm_avg_epu8', 'pavgw': '_mm_avg_epu16',
        'punpcklbw': '_mm_unpacklo_epi8', 'punpckhbw': '_mm_unpackhi_epi8',
        'punpcklwd': '_mm_unpacklo_epi16', 'punpckhwd': '_mm_unpackhi_epi16',
        'punpckldq': '_mm_unpacklo_epi32', 'punpckhdq': '_mm_unpackhi_epi32',
        'punpcklqdq': '_mm_unpacklo_epi64', 'punpckhqdq': '_mm_unpackhi_epi64',
        'packsswb': '_mm_packs_epi16', 'packssdw': '_mm_packs_epi32', 'packuswb': '_mm_packus_epi16',
        'packusdw': '_mm_packus_epi32', 'pshufb': '_mm_shuffle_epi8',
        'phaddd': '_mm_hadd_epi32', 'phaddw': '_mm_hadd_epi16', 'phsubd': '_mm_hsub_epi32', 'phsubw': '_mm_hsub_epi16',
        'pmaddubsw': '_mm_maddubs_epi16', 'pmulhrsw': '_mm_mulhrs_epi16',
        'psignb': '_mm_sign_epi8', 'psignw': '_mm_sign_epi16', 'psignd': '_mm_sign_epi32',
        'psllw': '_mm_sll_epi16', 'pslld': '_mm_sll_epi32', 'psllq': '_mm_sll_epi64',
        'psrlw': '_mm_srl_epi16', 'psrld': '_mm_srl_epi32', 'psrlq': '_mm_srl_epi64',
        'psraw': '_mm_sra_epi16', 'psrad': '_mm_sra_epi32',
    }
    SIMD_SHIFT_IMM = {'psllw': '_mm_slli_epi16', 'pslld': '_mm_slli_epi32', 'psllq': '_mm_slli_epi64',
                      'psrlw': '_mm_srli_epi16', 'psrld': '_mm_srli_epi32', 'psrlq': '_mm_srli_epi64',
                      'psraw': '_mm_srai_epi16', 'psrad': '_mm_srai_epi32',
                      'pslldq': '_mm_slli_si128', 'psrldq': '_mm_srli_si128'}
    SIMD_UN = {  # one source: expression on _b
        'cvtdq2ps': '_mm_cvtepi32_ps(_mm_castps_si128(_b))',
        'cvtps2dq': '_mm_castsi128_ps(_mm_cvtps_epi32(_b))',
        'cvttps2dq': '_mm_castsi128_ps(_mm_cvttps_epi32(_b))',
        'cvtps2pd': '_mm_castpd_ps(_mm_cvtps_pd(_b))',
        'cvtpd2ps': '_mm_cvtpd_ps(_mm_castps_pd(_b))',
        'cvtdq2pd': '_mm_castpd_ps(_mm_cvtepi32_pd(_mm_castps_si128(_b)))',
        'sqrtps': '_mm_sqrt_ps(_b)', 'rcpps': '_mm_rcp_ps(_b)', 'rsqrtps': '_mm_rsqrt_ps(_b)',
        'sqrtpd': '_mm_castpd_ps(_mm_sqrt_pd(_mm_castps_pd(_b)))',
        'movsldup': '_mm_moveldup_ps(_b)', 'movshdup': '_mm_movehdup_ps(_b)',
        'movddup': '_mm_castpd_ps(_mm_movedup_pd(_mm_castps_pd(_b)))',
        'pabsb': '_mm_castsi128_ps(_mm_abs_epi8(_mm_castps_si128(_b)))',
        'pabsw': '_mm_castsi128_ps(_mm_abs_epi16(_mm_castps_si128(_b)))',
        'pabsd': '_mm_castsi128_ps(_mm_abs_epi32(_mm_castps_si128(_b)))',
        'pmovzxbw': '_mm_castsi128_ps(_mm_cvtepu8_epi16(_mm_castps_si128(_b)))',
        'pmovzxbd': '_mm_castsi128_ps(_mm_cvtepu8_epi32(_mm_castps_si128(_b)))',
        'pmovzxwd': '_mm_castsi128_ps(_mm_cvtepu16_epi32(_mm_castps_si128(_b)))',
        'pmovzxdq': '_mm_castsi128_ps(_mm_cvtepu32_epi64(_mm_castps_si128(_b)))',
        'pmovsxbw': '_mm_castsi128_ps(_mm_cvtepi8_epi16(_mm_castps_si128(_b)))',
        'pmovsxbd': '_mm_castsi128_ps(_mm_cvtepi8_epi32(_mm_castps_si128(_b)))',
        'pmovsxwd': '_mm_castsi128_ps(_mm_cvtepi16_epi32(_mm_castps_si128(_b)))',
        'pmovsxdq': '_mm_castsi128_ps(_mm_cvtepi32_epi64(_mm_castps_si128(_b)))',
        'pmovzxbq': '_mm_castsi128_ps(_mm_cvtepu8_epi64(_mm_castps_si128(_b)))',
        'pmovzxwq': '_mm_castsi128_ps(_mm_cvtepu16_epi64(_mm_castps_si128(_b)))',
        'pmovsxbq': '_mm_castsi128_ps(_mm_cvtepi8_epi64(_mm_castps_si128(_b)))',
        'pmovsxwq': '_mm_castsi128_ps(_mm_cvtepi16_epi64(_mm_castps_si128(_b)))',
    }

    def lift_simd(self, ins, mn, ops):
        e = self.emit
        vex = mn.startswith('v')
        base = mn[1:] if vex else mn
        R, I, Mm = x86.X86_OP_REG, x86.X86_OP_IMM, x86.X86_OP_MEM
        if vex and base in ('movaps', 'movups', 'movdqa', 'movdqu', 'movapd', 'movupd') and len(ops) == 2 \
                and ops[0].type == Mm and ops[1].type == R and ins.reg_name(ops[1].reg).startswith('ymm'):
            e(f'memcpy((void*)(uintptr_t){self.addr(ins, ops[0])}, c->y[{self.xreg(ins, ops[1])}].b, 32);')
            return True
        if vex and base == 'extractf128' and len(ops) == 3:
            half = 16 if ops[2].imm & 1 else 0
            si = self.xreg(ins, ops[1])
            if ops[0].type == Mm:
                e(f'memcpy((void*)(uintptr_t){self.addr(ins, ops[0])}, &c->y[{si}].b[{half}], 16);')
            else:
                di = self.xreg(ins, ops[0])
                e(f'{{ __m128 _t; memcpy(&_t, &c->y[{si}].b[{half}], 16); og_setx(c, {di}, _t); }}')
            return True
        if base in ('stmxcsr', 'ldmxcsr') and len(ops) == 1:
            a = self.addr(ins, ops[0])
            e(f'M32({a}) = _mm_getcsr();' if base == 'stmxcsr' else f'_mm_setcsr(M32({a}));')
            return True
        if ops and ops[0].type == R and ins.reg_name(ops[0].reg).startswith('ymm'):
            return self.lift_ymm(ins, base, ops, vex)
        if vex and base == 'zeroupper':
            e('for (int _i = 0; _i < 16; _i++) memset(&c->y[_i].b[16], 0, 16);')
            return True
        if vex and base == 'zeroall':
            e('memset(c->y, 0, sizeof c->y);')
            return True
        if base in ('movd', 'movq') and len(ops) == 2:
            width = 4 if base == 'movd' else 8
            d, s = ops
            if self.isx(ins, d):
                di = self.xreg(ins, d)
                if self.isx(ins, s):
                    if width != 8:
                        raise Unsupported('movd x,x')
                    src = f'c->y[{self.xreg(ins, s)}].q[0]'
                elif s.type == R:
                    src = self.read(ins, s)
                elif s.type == Mm:
                    src = f'M{width * 8}({self.addr(ins, s)})'
                else:
                    raise Unsupported(mn)
                e(f'{{ uint64_t _v = (uint64_t)({src}); memset(c->y[{di}].b, 0, {32 if vex else 16}); '
                  f'memcpy(c->y[{di}].b, &_v, {width}); }}')
                return True
            if self.isx(ins, s):
                si = self.xreg(ins, s)
                if d.type == R:
                    e(self.write(ins, d, f'c->y[{si}].q[0]' if width == 8 else f'c->y[{si}].d[0]'))
                    return True
                if d.type == Mm:
                    e(f'memcpy((void*)(uintptr_t){self.addr(ins, d)}, c->y[{si}].b, {width});')
                    return True
            raise Unsupported(mn)
        if base in ('cvtsi2ss', 'cvtsi2sd'):
            if vex and len(ops) == 3:
                d, a, src = self.xreg(ins, ops[0]), f'og_x(c, {self.xreg(ins, ops[1])})', ops[2]
            elif not vex and len(ops) == 2:
                d = self.xreg(ins, ops[0]); a = f'og_x(c, {d})'; src = ops[1]
            else:
                raise Unsupported(mn)
            bits = src.size * 8
            iv = f'(int64_t){self.read(ins, src)}' if bits == 64 else f'(int32_t){self.read(ins, src)}'
            n = '64' if bits == 64 else '32'
            v = (f'_mm_cvtsi{n}_ss({a}, {iv})' if base == 'cvtsi2ss' else
                 f'_mm_castpd_ps(_mm_cvtsi{n}_sd(_mm_castps_pd({a}), {iv}))')
            e(self.xdst(d, v, vex))
            return True
        if base in ('cvttss2si', 'cvtss2si', 'cvttsd2si', 'cvtsd2si') and len(ops) == 2:
            bits = ops[0].size * 8
            n = '64' if bits == 64 else '32'
            x = self.xsrc(ins, ops[1])
            fn = {'cvttss2si': f'_mm_cvttss_si{n}({x})', 'cvtss2si': f'_mm_cvtss_si{n}({x})',
                  'cvttsd2si': f'_mm_cvttsd_si{n}(_mm_castps_pd({x}))', 'cvtsd2si': f'_mm_cvtsd_si{n}(_mm_castps_pd({x}))'}[base]
            e(self.write(ins, ops[0], f'(uint64_t)(int64_t){fn}' if bits == 64 else f'(uint32_t){fn}'))
            return True
        if base in ('ucomisd', 'comisd') and len(ops) == 2:
            a = f'og_x(c, {self.xreg(ins, ops[0])})'
            b = self.xsrc(ins, ops[1])
            e(f'{{ double _a = _mm_cvtsd_f64(_mm_castps_pd({a})), _b = _mm_cvtsd_f64(_mm_castps_pd({b}));')
            e('  if (_a != _a || _b != _b) { c->zf = c->pf = c->cf = 1; }')
            e('  else { c->zf = (uint8_t)(_a == _b); c->pf = 0; c->cf = (uint8_t)(_a < _b); }')
            e('  c->of = c->sf = c->af = 0; }')
            return True
        if base.startswith('cmp') and base[-2:] in ('ss', 'sd', 'ps', 'pd') and base[3:-2] in self.CMP_PRED:
            pred = self.CMP_PRED.index(base[3:-2])
            if not vex and pred > 7:
                raise Unsupported(mn)
            d, a, src = self.x3(ins, ops, vex)
            b = self.xsrc(ins, src)
            k = base[-2:]
            if ops[0].size != 16 and k in ('ps', 'pd'):
                raise Unsupported(mn)
            v = {'ss': f'_mm_cmp_ss({a}, {b}, {pred})', 'ps': f'_mm_cmp_ps({a}, {b}, {pred})',
                 'sd': f'_mm_castpd_ps(_mm_cmp_sd(_mm_castps_pd({a}), _mm_castps_pd({b}), {pred}))',
                 'pd': f'_mm_castpd_ps(_mm_cmp_pd(_mm_castps_pd({a}), _mm_castps_pd({b}), {pred}))'}[k]
            e(self.xdst(d, v, vex))
            return True
        if base in self.SIMD_BIN:
            expr, _ = self.SIMD_BIN[base]
            d, a, src = self.x3(ins, ops, vex)
            e(f'{{ __m128 _a = {a}, _b = {self.xsrc(ins, src)}; ' + self.xdst(d, expr, vex) + ' }')
            return True
        if base in self.SIMD_INT and not (base in self.SIMD_SHIFT_IMM and ops[-1].type == I):
            d, a, src = self.x3(ins, ops, vex)
            fn = self.SIMD_INT[base]
            e(f'{{ __m128i _a = _mm_castps_si128({a}), _b = _mm_castps_si128({self.xsrc(ins, src)}); '
              + self.xdst(d, f'_mm_castsi128_ps({fn}(_a, _b))', vex) + ' }')
            return True
        if base in self.SIMD_SHIFT_IMM and ops[-1].type == I:
            n = ops[-1].imm & 0xFF
            if vex and len(ops) == 3:
                d, src = self.xreg(ins, ops[0]), ops[1]
            elif not vex and len(ops) == 2:
                d = self.xreg(ins, ops[0]); src = ops[0]
            else:
                raise Unsupported(mn)
            e(self.xdst(d, f'_mm_castsi128_ps({self.SIMD_SHIFT_IMM[base]}(_mm_castps_si128({self.xsrc(ins, src)}), {n}))', vex))
            return True
        if base in self.SIMD_UN and len(ops) == 2 and ops[0].size == 16:
            d = self.xreg(ins, ops[0])
            src = ops[1]
            if src.type == Mm and base.startswith('pmov'):
                b = f'_mm_castsi128_ps(_mm_loadl_epi64((const __m128i*)(uintptr_t){self.addr(ins, src)}))'
                if src.size == 4:
                    b = f'_mm_castsi128_ps(_mm_cvtsi32_si128(M32({self.addr(ins, src)})))'
                elif src.size == 2:
                    b = f'_mm_castsi128_ps(_mm_cvtsi32_si128(M16({self.addr(ins, src)})))'
            else:
                b = self.xsrc(ins, src)
            e(f'{{ __m128 _b = {b}; ' + self.xdst(d, self.SIMD_UN[base], vex) + ' }')
            return True
        if base in ('pshufd', 'pshuflw', 'pshufhw') and len(ops) == 3:
            fn = {'pshufd': '_mm_shuffle_epi32', 'pshuflw': '_mm_shufflelo_epi16', 'pshufhw': '_mm_shufflehi_epi16'}[base]
            d = self.xreg(ins, ops[0])
            e(self.xdst(d, f'_mm_castsi128_ps({fn}(_mm_castps_si128({self.xsrc(ins, ops[1])}), {ops[2].imm & 0xFF}))', vex))
            return True
        if base == 'permilpd' and ops[0].size == 16 and len(ops) == 3 and ops[2].type == I:
            d = self.xreg(ins, ops[0])
            e(self.xdst(d, f'_mm_castpd_ps(_mm_permute_pd(_mm_castps_pd({self.xsrc(ins, ops[1])}), {ops[2].imm & 3}))', True))
            return True
        if base == 'permilps' and ops[0].size == 16:
            d = self.xreg(ins, ops[0])
            if ops[-1].type == I and len(ops) == 3:
                e(self.xdst(d, f'_mm_permute_ps({self.xsrc(ins, ops[1])}, {ops[2].imm & 0xFF})', True))
            elif len(ops) == 3:
                e(self.xdst(d, f'_mm_permutevar_ps({self.xsrc(ins, ops[1])}, _mm_castps_si128({self.xsrc(ins, ops[2])}))', True))
            else:
                raise Unsupported(mn)
            return True
        if base in ('shufps', 'blendps', 'dpps', 'insertps', 'roundss', 'roundsd', 'shufpd', 'blendpd', 'palignr', 'pblendw'):
            d, a, src = self.x3(ins, ops, vex, 1)
            n = ops[-1].imm & 0xFF
            if base == 'insertps' and src.type == Mm:
                b = f'_mm_load_ss((const float*)(uintptr_t){self.addr(ins, src)})'
                n &= 0x3F
            else:
                b = self.xsrc(ins, src)
            v = {'shufps': f'_mm_shuffle_ps({a}, {b}, {n})', 'blendps': f'_mm_blend_ps({a}, {b}, {n})',
                 'dpps': f'_mm_dp_ps({a}, {b}, {n})', 'insertps': f'_mm_insert_ps({a}, {b}, {n})',
                 'roundss': f'_mm_round_ss({a}, {b}, {n})',
                 'roundsd': f'_mm_castpd_ps(_mm_round_sd(_mm_castps_pd({a}), _mm_castps_pd({b}), {n}))',
                 'shufpd': f'_mm_castpd_ps(_mm_shuffle_pd(_mm_castps_pd({a}), _mm_castps_pd({b}), {n}))',
                 'blendpd': f'_mm_castpd_ps(_mm_blend_pd(_mm_castps_pd({a}), _mm_castps_pd({b}), {n}))',
                 'palignr': f'_mm_castsi128_ps(_mm_alignr_epi8(_mm_castps_si128({a}), _mm_castps_si128({b}), {n}))',
                 'pblendw': f'_mm_castsi128_ps(_mm_blend_epi16(_mm_castps_si128({a}), _mm_castps_si128({b}), {n}))'}[base]
            e(self.xdst(d, v, vex))
            return True
        if base in ('roundps', 'roundpd') and len(ops) == 3:
            d = self.xreg(ins, ops[0])
            n = ops[2].imm & 0xFF
            v = (f'_mm_round_ps({self.xsrc(ins, ops[1])}, {n})' if base == 'roundps' else
                 f'_mm_castpd_ps(_mm_round_pd(_mm_castps_pd({self.xsrc(ins, ops[1])}), {n}))')
            e(self.xdst(d, v, vex))
            return True
        if base in ('blendvps', 'blendvpd', 'pblendvb'):
            if vex and len(ops) == 4:
                d, a, src, msk = self.xreg(ins, ops[0]), f'og_x(c, {self.xreg(ins, ops[1])})', ops[2], f'og_x(c, {self.xreg(ins, ops[3])})'
            elif not vex and len(ops) in (2, 3):
                d = self.xreg(ins, ops[0]); a = f'og_x(c, {d})'; src = ops[1]; msk = 'og_x(c, 0)'
            else:
                raise Unsupported(mn)
            b = self.xsrc(ins, src)
            v = {'blendvps': f'_mm_blendv_ps({a}, {b}, {msk})',
                 'blendvpd': f'_mm_castpd_ps(_mm_blendv_pd(_mm_castps_pd({a}), _mm_castps_pd({b}), _mm_castps_pd({msk})))',
                 'pblendvb': f'_mm_castsi128_ps(_mm_blendv_epi8(_mm_castps_si128({a}), _mm_castps_si128({b}), _mm_castps_si128({msk})))'}[base]
            e(self.xdst(d, v, vex))
            return True
        if base in ('extractps', 'pextrd', 'pextrq', 'pextrb', 'pextrw') and len(ops) == 3:
            si = self.xreg(ins, ops[1])
            n = ops[2].imm
            lane = {'extractps': ('d', 4, 3), 'pextrd': ('d', 4, 3), 'pextrq': ('q', 8, 1),
                    'pextrb': ('b', 1, 15), 'pextrw': ('w', 2, 7)}[base]
            v = f'c->y[{si}].{lane[0]}[{n & lane[2]}]'
            if ops[0].type == Mm:
                e(f'{M[lane[1] * 8]}({self.addr(ins, ops[0])}) = {v};')
            else:
                e(self.write(ins, ops[0], f'(uint64_t){v}'))
            return True
        if base in ('pinsrd', 'pinsrq', 'pinsrb', 'pinsrw'):
            if vex and len(ops) == 4:
                d, a, src = self.xreg(ins, ops[0]), self.xreg(ins, ops[1]), ops[2]
            elif not vex and len(ops) == 3:
                d = a = self.xreg(ins, ops[0]); src = ops[1]
            else:
                raise Unsupported(mn)
            n = ops[-1].imm
            lane = {'pinsrd': ('d', 32, 3), 'pinsrq': ('q', 64, 1), 'pinsrb': ('b', 8, 15), 'pinsrw': ('w', 16, 7)}[base]
            sv = self.read(ins, src) if src.type == R else f'{M[lane[1]]}({self.addr(ins, src)})'
            e(f'{{ __m128 _t = og_x(c, {a}); {U[lane[1]]} _v = ({U[lane[1]]})({sv}); memcpy((uint8_t*)&_t + {(n & lane[2]) * lane[1] // 8}, &_v, {lane[1] // 8}); '
              + self.xdst(d, '_t', vex) + ' }')
            return True
        if base in ('movmskps', 'movmskpd', 'pmovmskb') and len(ops) == 2:
            x = self.xsrc(ins, ops[1])
            fn = {'movmskps': f'_mm_movemask_ps({x})', 'movmskpd': f'_mm_movemask_pd(_mm_castps_pd({x}))',
                  'pmovmskb': f'_mm_movemask_epi8(_mm_castps_si128({x}))'}[base]
            e(self.write(ins, ops[0], f'(uint32_t){fn}'))
            return True
        if base in ('broadcastss',) and ops[0].size == 16:
            d = self.xreg(ins, ops[0])
            e(self.xdst(d, f'_mm_shuffle_ps({self.xsrc(ins, ops[1])}, {self.xsrc(ins, ops[1])}, 0)', True))
            return True
        if base in ('movhps', 'movlps', 'movhpd', 'movlpd') and len(ops) in (2, 3):
            hi = base[3] == 'h'
            if ops[0].type == Mm:
                si = self.xreg(ins, ops[-1])
                e(f'memcpy((void*)(uintptr_t){self.addr(ins, ops[0])}, &c->y[{si}].b[{8 if hi else 0}], 8);')
                return True
            if vex and len(ops) == 3:
                d, a, src = self.xreg(ins, ops[0]), self.xreg(ins, ops[1]), ops[2]
            elif not vex and len(ops) == 2:
                d = a = self.xreg(ins, ops[0]); src = ops[1]
            else:
                raise Unsupported(mn)
            e(f'{{ __m128 _t = og_x(c, {a}); memcpy((uint8_t*)&_t + {8 if hi else 0}, (const void*)(uintptr_t){self.addr(ins, src)}, 8); '
              + self.xdst(d, '_t', vex) + ' }')
            return True
        if base in ('lddqu', 'movntdqa', 'movntps', 'movntdq', 'movntpd') and len(ops) == 2:
            d, s = ops
            if d.type == R:
                e(self.xdst(self.xreg(ins, d), f'og_ld128({self.addr(ins, s)})', vex))
            else:
                e(f'og_st128({self.addr(ins, d)}, og_x(c, {self.xreg(ins, s)}));')
            return True
        return False

    def lift_ymm(self, ins, base, ops, vex):
        """256-bit forms: the bitwise ops, moves and zeroing idioms -- done lane by lane."""
        e = self.emit
        R, I, Mm = x86.X86_OP_REG, x86.X86_OP_IMM, x86.X86_OP_MEM
        if not vex:
            raise Unsupported('ymm legacy')
        d = self.xreg(ins, ops[0])
        if base == 'insertf128' and len(ops) == 4:
            a = self.xreg(ins, ops[1])
            s = ops[2]
            src = f'(const void*)(uintptr_t){self.addr(ins, s)}' if s.type == Mm else f'c->y[{self.xreg(ins, s)}].b'
            half = 16 if ops[3].imm & 1 else 0
            e(f'{{ uint8_t _t[32]; memcpy(_t, c->y[{a}].b, 32); memcpy(_t + {half}, {src}, 16); memcpy(c->y[{d}].b, _t, 32); }}')
            return True
        if base in ('movaps', 'movups', 'movdqa', 'movdqu', 'movapd', 'movupd') and len(ops) == 2:
            s = ops[1]
            if s.type == Mm:
                e(f'memcpy(c->y[{d}].b, (const void*)(uintptr_t){self.addr(ins, s)}, 32);')
            else:
                e(f'memmove(c->y[{d}].b, c->y[{self.xreg(ins, s)}].b, 32);')
            return True
        if base in ('xorps', 'andps', 'orps', 'andnps', 'xorpd', 'andpd', 'orpd', 'andnpd', 'pxor', 'pand', 'por', 'pandn') and len(ops) == 3:
            a = self.xreg(ins, ops[1])
            s = ops[2]
            src = f'c->y[{self.xreg(ins, s)}].q' if s.type == R else f'((const og_u64u*)(uintptr_t){self.addr(ins, s)})'
            op = base[:-2] if base.endswith(('ps', 'pd')) else base[1:]
            ex = {'xor': '_x ^ _y', 'and': '_x & _y', 'or': '_x | _y', 'andn': '~_x & _y'}[op]
            e(f'{{ uint64_t _o[4]; for (int _i = 0; _i < 4; _i++) {{ uint64_t _x = c->y[{a}].q[_i], _y = {src}[_i]; _o[_i] = {ex}; }} '
              f'memcpy(c->y[{d}].q, _o, 32); }}')
            return True
        if base == 'broadcastss' and len(ops) == 2:
            s = ops[1]
            v = f'M32({self.addr(ins, s)})' if s.type == Mm else f'c->y[{self.xreg(ins, s)}].d[0]'
            e(f'{{ uint32_t _v = {v}; for (int _i = 0; _i < 8; _i++) c->y[{d}].d[_i] = _v; }}')
            return True

        # everything else 256-bit here works within each 128-bit lane: the xmm operation, twice
        def half(op, h):
            if op.type == R:
                return f'_mm_loadu_ps(&c->y[{self.xreg(ins, op)}].f[{4 * h}])'
            return f'og_ld128({self.addr(ins, op)} + {16 * h})'

        fp2 = {'addps': '_mm_add_ps(_a, _b)', 'subps': '_mm_sub_ps(_a, _b)', 'mulps': '_mm_mul_ps(_a, _b)',
               'divps': '_mm_div_ps(_a, _b)', 'minps': '_mm_min_ps(_a, _b)', 'maxps': '_mm_max_ps(_a, _b)',
               'unpcklps': '_mm_unpacklo_ps(_a, _b)', 'unpckhps': '_mm_unpackhi_ps(_a, _b)',
               'minpd': '_mm_castpd_ps(_mm_min_pd(_mm_castps_pd(_a), _mm_castps_pd(_b)))',
               'maxpd': '_mm_castpd_ps(_mm_max_pd(_mm_castps_pd(_a), _mm_castps_pd(_b)))'}
        fp2.update({k: v[0] for k, v in self.SIMD_BIN.items() if v[1] == 16})
        exprs = None
        if base in fp2 and len(ops) == 3:
            exprs = [(half(ops[1], h), half(ops[2], h), '_a', fp2[base]) for h in (0, 1)]
        elif base.startswith('cmp') and base[-2:] in ('ps', 'pd') and base[3:-2] in self.CMP_PRED and len(ops) == 3:
            p = self.CMP_PRED.index(base[3:-2])
            x = (f'_mm_cmp_ps(_a, _b, {p})' if base[-2:] == 'ps' else
                 f'_mm_castpd_ps(_mm_cmp_pd(_mm_castps_pd(_a), _mm_castps_pd(_b), {p}))')
            exprs = [(half(ops[1], h), half(ops[2], h), '_a', x) for h in (0, 1)]
        elif base in self.SIMD_UN and len(ops) == 2 and not base.startswith('pmov') \
                and base not in ('cvtps2pd', 'cvtpd2ps', 'cvtdq2pd'):
            exprs = [('_mm_setzero_ps()', half(ops[1], h), '_a', self.SIMD_UN[base]) for h in (0, 1)]
        elif base in ('shufps', 'blendps', 'shufpd', 'blendpd') and len(ops) == 4 and ops[3].type == I:
            n = ops[3].imm & 0xFF
            per = {'shufps': (n, n), 'blendps': (n & 0xF, n >> 4), 'shufpd': (n & 3, (n >> 2) & 3),
                   'blendpd': (n & 3, (n >> 2) & 3)}[base]
            fn = {'shufps': '_mm_shuffle_ps(_a, _b, {})', 'blendps': '_mm_blend_ps(_a, _b, {})',
                  'shufpd': '_mm_castpd_ps(_mm_shuffle_pd(_mm_castps_pd(_a), _mm_castps_pd(_b), {}))',
                  'blendpd': '_mm_castpd_ps(_mm_blend_pd(_mm_castps_pd(_a), _mm_castps_pd(_b), {}))'}[base]
            exprs = [(half(ops[1], h), half(ops[2], h), '_a', fn.format(per[h])) for h in (0, 1)]
        elif base in ('roundps', 'permilps') and len(ops) == 3 and ops[2].type == I:
            n = ops[2].imm & 0xFF
            x = f'_mm_round_ps(_b, {n})' if base == 'roundps' else f'_mm_permute_ps(_b, {n})'
            exprs = [('_mm_setzero_ps()', half(ops[1], h), '_a', x) for h in (0, 1)]
        elif base == 'permilps' and len(ops) == 3:
            exprs = [(half(ops[1], h), half(ops[2], h), '_a', '_mm_permutevar_ps(_a, _mm_castps_si128(_b))') for h in (0, 1)]
        elif base == 'blendvps' and len(ops) == 4:
            exprs = [(half(ops[1], h), half(ops[2], h), half(ops[3], h), '_mm_blendv_ps(_a, _b, _m)') for h in (0, 1)]
        if exprs is None:
            raise Unsupported('ymm ' + base)
        e('{ __m128 _r0, _r1;')
        for h, (a, b, m, x) in enumerate(exprs):
            e(f'  {{ __m128 _a = {a}, _b = {b}, _m = {m}; (void)_m; _r{h} = {x}; }}')
        e(f'  _mm_storeu_ps(&c->y[{d}].f[0], _r0); _mm_storeu_ps(&c->y[{d}].f[4], _r1); }}')
        return True

    # --- the whole function -------------------------------------------------------
    def decode(self):
        """The function's instructions by following its control flow, not by a linear sweep:
        clang puts switch tables right after the code, inside the function's range, and a sweep
        reads them as instructions. Jump tables found on the way give an indirect jmp its targets."""
        start, end = self.start, self.start + self.size
        blob = self.eb.read(start, self.size)
        noret = self.eb.noreturn()
        insns = {}
        self.dead_ends = set()   # undecodable bytes reached by falling through (after noreturn calls)
        self.table_targets = set()
        tables = {}
        work = [start]
        while work:
            while work:
                a = work.pop()
                while start <= a < end and a not in insns:
                    d = list(MD.disasm(blob[a - start:], a, 1))
                    if not d or a + d[0].size > end or any(t0 <= a < t1 for t0, t1 in tables.items()):
                        self.dead_ends.add(a)
                        break
                    ins = d[0]
                    insns[a] = ins
                    mn, ops = ins.mnemonic, ins.operands
                    if mn.startswith('j'):
                        if ops and ops[0].type == x86.X86_OP_IMM and start <= ops[0].imm < end:
                            work.append(ops[0].imm)
                        if mn == 'jmp':
                            break
                    elif mn in ('ret', 'ud2', 'int3', 'hlt') or mn.startswith('ret'):
                        break
                    elif mn == 'call' and ops and ops[0].type == x86.X86_OP_IMM and ops[0].imm in noret:
                        break
                    a += ins.size
            if not any(i.mnemonic == 'jmp' and i.operands and i.operands[0].type != x86.X86_OP_IMM
                       for i in insns.values()):
                break
            # clang's PIC switch: movsxd rX,[rT + rI*4]; add rX,rT; jmp rX, with rT from a
            # `lea rT,[rip+table]` -- next to it, or hoisted out of a loop far above
            order = sorted(insns)
            pos = {a: i for i, a in enumerate(order)}
            leas = collections.defaultdict(set)
            for ins in insns.values():
                if ins.mnemonic == 'lea' and ins.operands[1].mem.base == x86.X86_REG_RIP:
                    leas[ins.operands[0].reg].add(ins.address + ins.size + ins.operands[1].mem.disp)
            for use in list(insns.values()):
                if use.mnemonic != 'movsxd' or use.operands[1].type != x86.X86_OP_MEM:
                    continue
                m = use.operands[1].mem
                if m.scale != 4 or not m.index or m.base in (0, x86.X86_REG_RIP) or m.disp:
                    continue
                i0 = pos[use.address]
                # the bound: `cmp rI, n` + `ja` shortly before (n + 1 entries)
                limit = 4096
                prev = [insns[a] for a in order[max(0, i0 - 12):i0]]
                for j in range(len(prev) - 1):
                    p, q = prev[j], prev[j + 1]
                    if p.mnemonic == 'cmp' and p.operands[1].type == x86.X86_OP_IMM and q.mnemonic in ('ja', 'jae') \
                            and p.operands[0].type == x86.X86_OP_REG:
                        limit = p.operands[1].imm + (1 if q.mnemonic == 'ja' else 0)
                for t0 in leas.get(m.base, ()):
                    if t0 in tables:
                        continue
                    k = 0
                    while k < limit:  # 32-bit offsets from the table itself
                        b = self.eb.read_va(t0 + 4 * k, 4)
                        if len(b) < 4:
                            break
                        t = t0 + struct.unpack('<i', b)[0]
                        if not (start <= t < end) or t0 <= t < t0 + 4 * (k + 1):
                            break
                        self.table_targets.add(t)
                        if t not in insns:
                            work.append(t)
                        k += 1
                    tables[t0] = t0 + 4 * k
        self.insns = [insns[a] for a in sorted(insns)]
        for x, y in zip(self.insns, self.insns[1:]):
            if x.address + x.size > y.address:
                raise Unsupported('overlapping instructions')
        self.insn_addrs = set(insns)
        self.table_targets &= self.insn_addrs
        for ins in self.insns:
            if ins.mnemonic.startswith('j') and ins.operands and ins.operands[0].type == x86.X86_OP_IMM:
                t = ins.operands[0].imm
                if start <= t < end and t not in self.insn_addrs:
                    raise Unsupported('branch into undecodable bytes')
        if not self.insns:
            raise Unsupported('data in function')

    def prepare(self):
        """For the census: the decode does the work now."""
        self.decode()

    def lift(self):
        self.decode()
        insns = self.insns
        body = []
        for i, ins in enumerate(insns):
            next_va = ins.address + ins.size
            self.out = []
            self.lift_insn(ins, next_va)
            mn = ins.mnemonic
            falls = not (mn in ('jmp', 'ret', 'ud2', 'int3', 'hlt') or mn.startswith('ret'))
            if falls and next_va not in self.insn_addrs:
                # nothing decodable follows: the call before was a noreturn one
                self.out.append('    __builtin_trap();')
            body.append((ins, self.out))
        lines = [f'void og_f_{self.start:X}(OgCtx* c) {{']
        if getattr(self, 'uses_sp0', False):
            lines.append('    const uint64_t og_sp0 = c->r[RSP]; /* our return-address slot */')
        for ins, stmts in body:
            if ins.address in self.labels:
                lines.append(f'L_{ins.address:X}:;')
            lines.append(f'    /* {ins.address:X}: {ins.mnemonic} {ins.op_str} */')
            lines.extend(stmts)
        lines.append('}')
        return '\n'.join(lines), len(insns)


# ------------------------------------------------------------------ driver

HEADER = '''/* generated by OrbisGlue tools/mosaic/lift64.py -- Mosaic Recompilation */
#include "og64.h"
#define OG_SHIFT_FLAGS(c, r, bits) do { (c)->zf = (uint8_t)(((r) & OG_MASK(bits)) == 0); \\
    (c)->sf = (uint8_t)(((r) >> ((bits) - 1)) & 1); (c)->pf = og_parity(r); } while (0)
'''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('eboot')
    ap.add_argument('out')
    ap.add_argument('--base', type=lambda s: int(s, 0), default=0x10000000)
    ap.add_argument('--only', choices=['all', 'leaf'], default='all')
    ap.add_argument('--chunk', type=int, default=2000)
    ap.add_argument('--switchable', action='store_true',
                    help='every lifted call checks og_off[i]: the host can send any function back to '
                         'the original (to bisect a bug down to one function)')
    args = ap.parse_args()

    eb = Eboot(args.eboot, args.base)
    os.makedirs(args.out, exist_ok=True)

    # pass 1: what lifts on its own (so pass 2 can call lifted functions directly)
    ok = {}
    why = collections.Counter()
    for start, size in eb.funcs:
        try:
            fl = FuncLifter(eb, start, size, set())
            code, n = fl.lift()
            if args.only == 'leaf' and fl.calls:
                why['has calls (leaf only)'] += 1
                continue
            ok[start] = n
        except Unsupported as ex:
            why[str(ex).split(' ')[0] if str(ex).startswith('reg') else str(ex)] += 1
        except Exception as ex:  # a capstone corner the lifter does not model
            why['error: ' + type(ex).__name__] += 1

    lifted = set(ok)
    # the table index of each lifted function (eh_frame order), for the switches
    index_of = {start: i for i, start in enumerate(s for s, _ in eb.funcs if s in lifted)}
    funcs = []
    for start, size in eb.funcs:
        if start in lifted:
            fl = FuncLifter(eb, start, size, lifted)
            if args.switchable:
                fl.index_of = index_of
            code, n = fl.lift()
            funcs.append((start, code))

    for k in range(0, len(funcs), args.chunk):
        with open(os.path.join(args.out, f'og_lifted_{k // args.chunk}.c'), 'w', newline='\n') as f:
            f.write(HEADER)
            for start, _ in funcs:
                f.write(f'void og_f_{start:X}(OgCtx* c);\n')
            for _, code in funcs[k:k + args.chunk]:
                f.write(code + '\n\n')
    with open(os.path.join(args.out, 'og_table.c'), 'w', newline='\n') as f:
        f.write(HEADER)
        for start, _ in funcs:
            f.write(f'void og_f_{start:X}(OgCtx* c);\n')
        # addresses relative to the image: the host adds the base the loader chose
        f.write('const struct OgEntry { uint64_t addr; void (*fn)(OgCtx*); } og_table[] = {\n')
        for start, _ in funcs:
            f.write(f'    {{0x{start:X}ull, og_f_{start:X}}},\n')
        f.write('    {0, 0}\n};\n')
        f.write(f'const unsigned og_table_count = {len(funcs)};\n')
        f.write('const OgHost* og_host;\n')
        f.write('uint64_t og_base;\n')
        # 1 = that function runs as the original (lifted calls check it with --switchable)
        f.write(f'uint8_t og_off[{len(funcs) + 1}];\n')
        f.write('OG_EXPORT uint8_t* og_switches(void) { return og_off; }\n')
        f.write('OG_EXPORT const struct OgEntry* og_entries(const OgHost* host, unsigned* count) '
                '{ og_host = host; og_base = host->image_base; *count = og_table_count; return og_table; }\n')

    total = len(eb.funcs)
    report = {
        'functions': total,
        'lifted': len(funcs),
        'mosaic_percent': round(100.0 * len(funcs) / total, 2),
        'not_lifted_because': dict(why.most_common(40)),
    }
    with open(os.path.join(args.out, 'report.json'), 'w') as f:
        json.dump(report, f, indent=2)
    print(json.dumps({k: report[k] for k in ('functions', 'lifted', 'mosaic_percent')}))
    for k, v in why.most_common(25):
        print(f'  {v:6d}  {k}')


if __name__ == '__main__':
    main()
