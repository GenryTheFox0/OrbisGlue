# Status · Статус

## Deadpool (CUSA03528, base 1.00 + update)

| | |
|---|---|
| Functions | 123,409 |
| Lifted | **123,375 (99.98 %)** |
| Not lifted | 30 overlapping-instruction cases, 2 MMX, 1 `rdtsc`, 1 `cpuid` |
| Plays on lifted code | yes: boot, logos, menus, the first level, autosave and checkpoints |
| FPS | 30 — the game's cap, as the original |
| Lifted calls | ~250,000 calls a second out to original/system code, ~27 million a second inside lifted code |

The proof run over all lifted functions on the release build is in progress; its numbers will be
added here.

## Known issues (runtime, not the recompiler)

They show the same way without Mosaic, in plain OrbisGlue:

- Some UI panels (the backdrop under dialogs) and button icons are not drawn, so a dialog and the
  menu under it overlap.
- First-time shader compilation stutters (a shader cache is on the [Roadmap](Roadmap)).
- Russian title font of the Russian package lacks "Й" (game data).
- Gamepad input needs the game window focused.

---

## Русский

**Дэдпул:** 123 409 функций, переведено **123 375 (99,98 %)**, игра идёт на переводе — загрузка,
логотипы, меню, первый уровень, автосохранения и чекпоинты; 30 FPS — потолок игры, как в оригинале.
Цифры полной проверки на релизной сборке будут добавлены.

**Известные баги рантайма (без перевода — так же):** не рисуются подложки окон и значки кнопок (окно
накладывается на меню), подвисания при первой компиляции шейдеров, в заголовочном шрифте русского
пакета нет «Й», геймпад работает только когда окно игры в фокусе.
