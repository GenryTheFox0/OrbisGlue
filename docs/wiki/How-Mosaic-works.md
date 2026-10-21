# How Mosaic works · Как устроен Mosaic

## Lifting

- **Functions** come from the game's `.eh_frame` (every compiled function has an unwind record).
- **Decoding follows control flow**, not a linear sweep: clang puts switch tables inside a
  function's range, and a sweep would read them as instructions. Jump tables are found by their
  pattern (`movsxd r, [table + i*4]; add r, table; jmp r`, the bound from the `cmp`/`ja` before it);
  calls that never return (`__stack_chk_fail` and friends) are recognised by what follows nearly
  all of their call sites.
- **A function is lifted whole or not at all.** Each instruction becomes C on a context: 16
  registers, the flags, 16 vector registers; memory is the host's (the game lives in the same
  address space). Integer, SSE/AVX (with 256-bit forms lane by lane), atomics (`lock`), division,
  BMI, string instructions — all of Deadpool except 30 functions.
- **Addresses are relative** to wherever the loader put the game (`og_base + offset`).

## Running

- The runtime loads `mosaic.dll`; the game's entry and every thread it starts run their lifted
  function if there is one.
- **The guest stack is the game's own**, separate from the C code's stack; pushes, calls and
  returns move it exactly as the original would, so lifted and original code share frames.
- **A call to code that is not lifted** goes through a bridge: registers in, the original code runs
  on the guest stack, registers back. The bridge is re-entrant (the context of the call in flight
  sits in a TLS slot) and switches the TEB stack bounds off meanwhile, as shadPS4 does for guest
  stacks.
- **A tail jump** into original code takes the return slot off first, so the callee sees the stack
  exactly as after the original `jmp`.

## Why it is safe to be incomplete

Every function that could not be lifted, every indirect target the tables did not name, every
callback from the system — all of it runs as the original code, which is right there. The game
never depends on the lifter being finished. On a phone (no original code to fall back to) that
changes, which is why 100 % and the proof matter: see [Roadmap](Roadmap).

---

## Русский

- **Функции** берутся из `.eh_frame` игры. **Разбор идёт по потоку управления**, а не подряд: clang
  кладёт таблицы switch внутрь функции. Таблицы находятся по шаблону, «невозвратные» вызовы — по тому,
  что стоит после почти всех их мест вызова.
- **Функция переводится целиком или никак.** Каждая команда — C над контекстом (регистры, флаги,
  векторные регистры); память общая с хостом. Адреса — от места, куда загрузили игру.
- **Стек игры — свой**, отдельно от стека C; push/call/ret двигают его как в оригинале.
- **Вызов непереведённого кода** — через мост: регистры туда, оригинал работает на стеке игры,
  регистры обратно. Мост реентерабелен (контекст — в TLS-слоте) и на время вызова отключает границы
  стека в TEB, как shadPS4.
- **Почему не страшно, что перевод неполный:** всё непереведённое работает как оригинал, он рядом.
  На телефоне оригинала не будет — поэтому там нужны 100 % и доказательство.
