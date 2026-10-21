![OrbisGlue](https://raw.githubusercontent.com/GenryTheFox0/OrbisGlue/main/.github/orbisglue-banner.png)

# OrbisGlue — PS4 recompilation project

**English** · [Русский](#русский)

OrbisGlue turns a PS4 game you own into a native Windows program. Its recompiler, **Mosaic**,
lifts the game's x86-64 code to C and builds it; the OrbisGlue runtime (a fork of shadPS4) plays the
game on the lifted code. What is not lifted yet runs as the original code, so a game works whole at
every stage.

| Page | What is in it |
|---|---|
| [Getting the game](Getting-the-game) | Where the game folder (`eboot.bin`) comes from |
| [Quick start](Quick-Start) | Tools to install, one command to recompile and play |
| [How Mosaic works](How-Mosaic-works) | Lifting, the bridge to original code, threads, addresses |
| [Difftest](Difftest) | How every lifted function is proven against the original |
| [Status](Status) | Deadpool numbers, what stays original, known issues |
| [Roadmap](Roadmap) | Android first, then speed, shader cache, more games |
| [FAQ](FAQ) | "Why recompile x86 to x86?" and other questions |

---

## Русский

OrbisGlue превращает твою PS4-игру в программу для Windows. Рекомпилятор **Mosaic** переводит
код игры (x86-64) в C и собирает его, а рантайм OrbisGlue (форк shadPS4) запускает игру на
переведённом коде. То, что ещё не переведено, работает как оригинал — игра цела на каждом этапе.

| Страница | Что там |
|---|---|
| [Откуда взять игру](Getting-the-game) | Откуда берётся папка с `eboot.bin` |
| [Быстрый старт](Quick-Start) | Что поставить и одна команда: перевести и играть |
| [Как устроен Mosaic](How-Mosaic-works) | Перевод, мост к оригиналу, потоки, адреса |
| [Проверка (difftest)](Difftest) | Как каждая функция доказывается против оригинала |
| [Статус](Status) | Цифры по Дэдпулу, что остаётся оригиналом, известные баги |
| [Что готовится](Roadmap) | Сначала Андроид, потом скорость, кэш шейдеров, новые игры |
| [Вопросы](FAQ) | «Зачем переводить x86 в x86?» и другое |
