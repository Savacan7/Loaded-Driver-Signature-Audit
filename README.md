# ldsa — loaded driver signature audit

`ldsa` lists the kernel-mode drivers that are loaded on a Windows machine right
now and checks, driver by driver, whether the file behind it is backed by a
trusted Authenticode signature. Anything that isn't gets surfaced.

It reads only. It enumerates modules, opens their files, and verifies
signatures — it never writes, never loads a driver, and never reaches into
another process.

## Background

A kernel-mode cheat needs code running in ring 0, which means a driver. The
same is true of most rootkits and of the "bring your own vulnerable driver"
(BYOVD) pattern. On a machine whose integrity is intact, that driver cannot
load unless it is signed — so enumerating the loaded drivers and asking *"is
every one of these signed, and by whom?"* is a cheap question with a loud
answer.

## Build & run

MSVC with the C++ toolset, x64.

```
build.bat
```

`build.bat` finds the Visual Studio environment on its own (via vswhere); you
don't need a Developer Command Prompt. If you'd rather call the compiler
yourself:

```
cl /std:c++17 /O2 /EHsc /MT main.cpp /link psapi.lib wintrust.lib crypt32.lib user32.lib
```

Then:

```
main.exe
```

Run it elevated so every driver's file path resolves.

## How the verification works

1. `EnumDeviceDrivers` gives the base address of every loaded driver;
   `GetDeviceDriverFileName` maps each to its file on disk (translated from the
   native `\SystemRoot\...` / `\??\...` form to a normal path).
2. Each file is checked the way the loader itself trusts a driver:
   - the **embedded** Authenticode signature inside the `.sys` (`WinVerifyTrust`);
   - if there is none, the **detached security catalog** that covers it
     (`CryptCATAdmin*` + `WINTRUST_CATALOG_INFO`).
3. The signer is read off the verified chain, and each driver lands in one of:
   `signed`, `unsigned`, `unverifiable`, or `expected`.

Catalog signing is the part that matters. Skip it and almost every genuine
Microsoft driver looks unsigned — the catalog step is the difference between an
audit and a pile of false alarms.

## Reading the result

The program prints a one-line tally, then lists every driver that isn't
cleanly `signed` (with its path and, where available, its signer), then a
final line:

| State    | Exit | Meaning                                                        |
|----------|:----:|---------------------------------------------------------------|
| `PASS`   |  0   | every loaded driver is signed                                 |
| `REVIEW` |  1   | something couldn't be verified — the report is partial        |
| `FAIL`   |  2   | an unsigned / untrusted kernel driver is loaded               |

The exit code is there so the tool slots into a bigger script or pipeline.

### A note on not crying wolf

- `unverifiable` is **not** `unsigned`. If a file can't be found or opened, the
  tool says so and the result drops to `REVIEW` — never a false accusation and
  never a false all-clear.
- `expected` covers the crash-dump stack (`dump_*.sys`): the kernel clones
  those into memory with no file on disk by design, so they are recognized
  instead of being mislabeled as missing.
- `unsigned` is a statement about a file, not a verdict about a person — some
  legitimate (usually developer) drivers are unsigned. The tool reports the
  fact and leaves the call to you.

## Scope & limits

- Runs in user mode. A kernel-mode attacker who is already resident can hide a
  module from enumeration or lie about a file; `ldsa` catches the ordinary case
  — an unsigned driver loaded in plain sight — and raises the bar.
- Verifies the file on disk, not the exact bytes mapped in kernel memory.
- A signed-but-vulnerable driver (textbook BYOVD) correctly reads as `signed`;
  cross-referencing a known-vulnerable-driver list is the obvious next layer.

## License

MIT — see [LICENSE](LICENSE).
