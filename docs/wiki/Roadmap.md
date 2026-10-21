# Roadmap · Что готовится

## 1. Android (ARM64) — the main goal

On a PC the original code is always there to fall back to. On a phone it is not — the PS4's x86-64
code cannot run on ARM at all. Other PS4-on-Android projects translate it **while the game runs**
(a JIT, FEX). Mosaic does it **ahead of time**: the game's code is already C, and C compiles for ARM.

Done:
- The lifted C compiles for `aarch64-linux-android` with the Android NDK: x86 SIMD intrinsics map
  to NEON through SIMDe, 128-bit multiply/divide through `__int128`.
- Lifted code is position-independent (`og_base`), as a phone's address space needs.

Next:
- 100 % lifting and every indirect target known — no fallback exists on ARM.
- The runtime on Android: shadPS4's system libraries built for ARM64, calls from lifted code into
  them through an x86-ABI to ARM-ABI bridge, callbacks back into lifted code.
- The GPU path: shadPS4's Vulkan renderer on phones — **Mali as well as Adreno** (block-compressed
  textures decoded where the GPU has no BC support).
- Memory order: x86 sees other threads' writes in order, ARM does not — fences where it matters.
- First target: Deadpool on a mid-range phone (Dimensity 8400, Mali-G720, 8 GB).

## 2. Speed

- Optimised builds (`/O2`), and dropping flag computations nobody reads.
- A shader cache against first-time stutter.

## 3. Proof and coverage

- The full difftest on every release; functions the random inputs cannot reach proven in a running
  game.

## 4. More games and the launcher

- More titles through the same pipeline, per-game notes in this wiki.
- The GenryPS4 launcher: a "Recompile" button next to "Play".

---

## Русский

**1. Андроид (ARM64) — главная цель.** На ПК под рукой всегда есть оригинальный код, на телефоне —
нет: x86-64 код PS4 на ARM не запустится вообще. Другие проекты PS4 на Андроиде переводят его **во
время игры** (JIT, FEX). Mosaic делает это **заранее**: код игры уже C, а C собирается под ARM.

Уже сделано: переведённый C собирается NDK под `aarch64-linux-android` (SIMD через SIMDe, 128-битное
умножение и деление через `__int128`), код не привязан к адресу.

Дальше: 100 % перевода и все косвенные переходы известны; рантайм (системные библиотеки shadPS4) под
ARM64 с мостом вызовов x86-ABI → ARM-ABI и обратными вызовами в переведённый код; графика — **не
только Adreno, но и Mali** (распаковка BC-текстур там, где их нет); порядок памяти между потоками
(барьеры там, где нужно). Первая цель — Дэдпул на телефоне среднего уровня (Dimensity 8400, Mali-G720,
8 ГБ).

**2. Скорость:** оптимизированная сборка, меньше лишней работы с флагами, кэш шейдеров.
**3. Доказательство:** полная проверка на каждом релизе. **4. Новые игры и кнопка «Перевести» в
лаунчере GenryPS4.**
