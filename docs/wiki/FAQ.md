# FAQ · Вопросы

**The PS4 is x86-64, like a PC. Why recompile x86 to x86?**
On a PC alone, for three reasons: the game's code becomes C you can read, patch and fix (60 FPS
patches, bug fixes, mods) instead of byte patches; every function can be proven against the
original; and it is the road to **ARM** — phones, where the original code cannot run at all. That
last one is the point. Speed on a PC is the same as the original, not better.

**Is it an emulator?**
The CPU part is not emulated at all: the game's code is either lifted C or the original machine code
running natively. The system libraries and the GPU come from shadPS4's runtime (HLE and a Vulkan
renderer).

**Which games work?**
Deadpool is taken all the way. The lifter is not written for one game, but other games are untested
— tell us in Issues what you tried (the game, `report.json`, the log).

**Can I share the lifted C or the DLL?**
No. It is made from the game's code, which belongs to its owners. Share the tool, not the output.

**Where do I get games?**
From your own PS4 — see [Getting the game](Getting-the-game).

**Who made it?**
GenryTheFox, with Shram — an AI (Claude) that writes the code with him.

---

## Русский

**PS4 — это x86-64, как ПК. Зачем переводить x86 в x86?** На самом ПК — ради трёх вещей: код игры
становится C, который можно читать и править (патчи 60 FPS, фиксы, моды) вместо байт-патчей; каждую
функцию можно доказать против оригинала; и это дорога на **ARM** — телефоны, где оригинальный код не
запустится вообще. Последнее — главное. Скорость на ПК такая же, как у оригинала, не выше.

**Это эмулятор?** Процессор не эмулируется: код игры — либо переведённый C, либо родной машинный код.
Системные библиотеки и видеокарта — из рантайма shadPS4.

**Можно раздавать переведённый C или DLL?** Нет — это сделано из кода игры. Делимся инструментом, а не
результатом. **Где брать игры?** Со своей PS4 — см. [Откуда взять игру](Getting-the-game).
**Кто сделал?** GenryTheFox вместе со Шрамом — ИИ (Claude), который пишет с ним код.
