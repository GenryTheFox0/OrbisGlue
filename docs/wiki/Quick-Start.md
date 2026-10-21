# Quick start · Быстрый старт

## Install once

| What | Why |
|---|---|
| OrbisGlue (release zip, or build this repository like shadPS4) | the runtime that plays the game |
| Python 3.10+ and `pip install capstone` | the lifter |
| [LLVM](https://github.com/llvm/llvm-project/releases) 18+ (`clang-cl`, `lld-link`) | compiles the lifted C |
| Visual Studio Build Tools, workload "Desktop development with C++" | headers and libraries for clang-cl |
| A GPU with Vulkan 1.3 | the game itself |

`build_mosaic.py` finds LLVM and Visual Studio on its own; if they live elsewhere, set
`MOSAIC_LLVM` (the `bin` folder) and `MOSAIC_VCVARS` (`vcvars64.bat`).

## Recompile and play

```
python tools/mosaic/mosaic.py "D:\Games\CUSA03528" --play
```

| Step | Takes (Deadpool, 6 cores) | Result |
|---|---|---|
| lift | ~6 min | `<game>\_mosaic\og_lifted_*.c` (~840 MB of C), `report.json` |
| build | ~6 min | `<game>\_mosaic\mosaic.dll` (~110 MB) |
| play | — | the game on lifted code |

Later, without recompiling:

```
OrbisGlue.exe --orbisglue-mosaic "D:\Games\CUSA03528\_mosaic\mosaic.dll" -g "D:\Games\CUSA03528\eboot.bin"
```

## Useful switches

| | |
|---|---|
| `--difftest` (mosaic.py) | prove every lifted function against the original first — hours; see [Difftest](Difftest) |
| `--jobs N` | compilers at once (default 6; the C is huge, keep it modest if your PC overheats) |
| `--switchable` | every lifted function can be sent back to the original: `MOSAIC_OFF=100-200,4711` |
| `MOSAIC_THREADS=0` | only the main thread on lifted code, the game's own threads original |
| `tools/mosaic/census64.py eboot.bin` | which instructions still keep functions from lifting |

The log shows `Mosaic: the title starts at ... on lifted code` and, every 5 s, a `Mosaic pulse`
(calls out of lifted code) — 0 there for long means the game is stuck.

---

## Русский

Поставить один раз: OrbisGlue (zip из релиза или сборка этого репо как shadPS4), Python 3.10+ и
`pip install capstone`, LLVM 18+ (clang-cl, lld-link), Visual Studio Build Tools с C++, видеокарта с
Vulkan 1.3. Если LLVM или Visual Studio не в стандартных местах — переменные `MOSAIC_LLVM` (папка
`bin`) и `MOSAIC_VCVARS` (`vcvars64.bat`).

Перевести и играть: `python tools/mosaic/mosaic.py "D:\Games\CUSA03528" --play` — перевод ~6 минут,
сборка ~6 минут (на Дэдпуле, 6 ядер). Потом запускать без перевода:
`OrbisGlue.exe --orbisglue-mosaic "<игра>\_mosaic\mosaic.dll" -g "<игра>\eboot.bin"`.
`--difftest` — сначала доказать функции (часы), `--jobs N` — сколько компиляторов сразу,
`--switchable` + `MOSAIC_OFF=...` — вернуть выбранные функции оригиналу (искать баг делением пополам).
