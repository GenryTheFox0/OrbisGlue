# Getting the game · Откуда взять игру

OrbisGlue needs the game as a **folder**: `eboot.bin`, `sce_module/`, `sce_sys/` and the game's
data — the way it sits on a PS4 after installation. Nothing of any game comes with OrbisGlue.

## 1. Dump it from your PS4 (the main way)

A PS4 with homebrew (GoldHEN) dumps installed games to a USB drive — Itemzflow and similar
dumpers write exactly the folder OrbisGlue wants (base game, and the update merged on top if the
game has one). Point `mosaic.py` at that folder.

## 2. You have a `.pkg` backup of your game

OrbisGlue does not unpack packages itself (and carries no keys). Open-source PKG tools do — look
for **LibOrbisPkg** (its **PkgTool** / PkgEditor). Extract the whole package, including `sce_sys`
(some tools leave it out — without `param.sfo` the game has no title ID), then merge the update
package over the base game the same way, and you have the folder.

## Checks

- `eboot.bin` must be **decrypted** (an ELF / plain SELF). A dump from a console is.
- `sce_sys/param.sfo` must be there.
- Updates matter: lift the `eboot.bin` you will actually play (base + update merged).

---

## Русский

OrbisGlue нужна игра **папкой**: `eboot.bin`, `sce_module/`, `sce_sys/` и данные игры — как она
лежит на PS4 после установки. В OrbisGlue нет ничего ни от одной игры.

1. **Дамп со своей PS4 (основной путь).** PS4 с GoldHEN выгружает установленные игры на флешку —
   Itemzflow и похожие дамперы пишут ровно такую папку (базовая игра и обновление поверх).
2. **Есть `.pkg`-бэкап твоей игры.** Сам OrbisGlue пакеты не распаковывает и ключей не содержит. Это
   делают открытые программы — ищи **LibOrbisPkg** (**PkgTool** / PkgEditor). Распакуй пакет целиком,
   вместе с `sce_sys` (некоторые программы его пропускают, а без `param.sfo` у игры нет ID), потом так
   же распакуй обновление поверх базы — и папка готова.

Проверь: `eboot.bin` расшифрован (дамп с консоли — да), `sce_sys/param.sfo` на месте, и переводишь
тот `eboot.bin`, на котором будешь играть (база + обновление).
