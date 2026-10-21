# Difftest · Проверка бит в бит

`OrbisGlue.exe --orbisglue-difftest mosaic.dll -g eboot.bin` (or `mosaic.py --difftest`, or
`tools/mosaic/run_difftest.py`) loads the game as for playing, stops before its first instruction,
and runs **every lifted function twice — the original and the lifted one — on the same inputs**:

- registers: plausible values (small numbers, pointers into a scratch heap) rather than noise, so
  sizes and addresses the function reads from its arguments stay in reach;
- the scratch heap and the guest stack sit in the middle of reserved address space with 64 GB of
  guard on each side, so a stray write is a caught fault, not damage;
- the game's own writable memory is write-protected during each call: pages written are noted,
  compared and put back — the original's side effects on globals are checked too;
- a hang is broken by a watchdog; a call stuck in the kernel makes the driver restart the process
  from the next function (logged `HANG` / `CRASH`).

Compared after each run: all 16 registers, the vector registers, the scratch heap, the live part of
the stack and every page of game memory either run wrote.

| Result | Meaning |
|---|---|
| `PASS` | identical to the original on every trial that the original survived |
| `PASSNAN` | identical, except a NaN came out with another sign or payload (the C compiler may swap the operands of a commutative operation; x86 passes on the first operand's NaN) |
| `NONDET` | the original differs from itself (clock, counters, the system's state) — no evidence either way |
| `UNTESTED` | the original faults on every random input (it needs real objects — such functions get proven in a running game instead) |
| `FAIL` | a real difference — a bug to fix |

The difftest found and pinned every bug fixed so far: a tail call that left the stack 8 bytes off,
switch tables the lifter missed, a "noreturn" callee that returns.

---

## Русский

Стенд грузит игру как для запуска, останавливается до её первой команды и гоняет **каждую
переведённую функцию дважды — оригинал и перевод — на одних входах**: правдоподобные регистры, куча и
стек посреди зарезервированной памяти с 64 ГБ защиты, память игры под защитой записи (тронутые
страницы сравниваются и откатываются), сторож на зависания, перезапуск процесса на «вечном» ожидании.
Сравниваются все регистры, векторные регистры, куча, живой стек и все тронутые страницы.

`PASS` — совпало; `PASSNAN` — совпало, кроме знака у «не числа» (NaN); `NONDET` — оригинал сам с
собой не совпадает (часы, счётчики); `UNTESTED` — оригинал падает на любых случайных входах (нужны
настоящие объекты); `FAIL` — настоящая разница, баг.
