# ctfdbg

A Windows-first graphical debugger for legal CTF, reverse engineering, and
authorized exploit-development workflows. Inspired by the Binary Ninja
Debugger, x64dbg, WinDbg, pwndbg and IDA, but written from scratch in Rust
with an [`egui`](https://github.com/emilk/egui) interface.

(Formerly `pwn-ui-debugger`.)

> **Important — legal use only.** This tool is intended exclusively for
> analyzing software you own, software you have explicit written
> authorization to test, CTF challenges, malware-free RE practice
> binaries, and your own exploit-development targets. Do not use it
> against systems or binaries you are not authorized to debug.

## Features

- Real Windows debug backend built on the Win32 Debug API
  (`CreateProcess` + `DEBUG_PROCESS`, `DebugActiveProcess`,
  `WaitForDebugEvent`, `ContinueDebugEvent`)
- Software breakpoints (`int3` byte-patching with original-byte restore +
  single-step + reinsert)
- Single-step / step-into / step-over / step-return / pause / continue /
  run-to-address
- Process attach with PID picker (toolhelp32 enumeration, sysinfo
  fallback)
- x86_64 register read/write, IP override, dereference hints
- ReadProcessMemory / WriteProcessMemory wrappers, hex view, stack view
- Disassembly via [`capstone`](https://github.com/capstone-rust/capstone-rs)
  with current-PC and breakpoint highlighting, right-click breakpoint
  toggle, jump to IP, run to here, copy address / instruction
- PE / ELF / Mach-O / raw-shellcode parsing via [`goblin`](https://github.com/m4b/goblin),
  with security feature reporting (ASLR, DEP/NX, CFG, SafeSEH,
  HighEntropyVA)
- pwntools-compatible helpers: `cyclic`, `cyclic_find`, `p8/p16/p32/p64`,
  `u8_/u16_/u32_/u64_`, `hexdump`, calling-convention argument extractor
  (Windows x64, SysV AMD64, x86 cdecl/stdcall, AArch64 AAPCS)
- Linear ROP gadget scanner
- Debugger console with parser supporting `b *0xaddr`, `c`, `si`, `n`,
  `setreg`, `setip`, `x/16gx 0xaddr`, `cyclic 200`, `checksec`, `rop`,
  `vmmap`, `symbols`, `imports`, `exports`, etc.

## Build

Requires a recent stable Rust toolchain (Rust 1.79+ recommended) and the
MSVC toolchain on Windows.

```powershell
cargo build --release
```

The first build pulls a number of dependencies (egui/eframe, windows
crate, goblin, capstone) and may take several minutes.

## Run

Launch the GUI with no target:

```powershell
cargo run --release
```

Or pass a target binary on the command line:

```powershell
cargo run --release -- C:\path\to\target.exe --args "1 2 3" --break-entry
```

Attach to a running process:

```powershell
cargo run --release -- --pid 1234
```

Headless mode (parses commands from a script and exits — useful for
automation and CI):

```powershell
cargo run --release -- --headless --script C:\path\to\commands.txt
```

### Common command-line options

| Flag                   | Description                                         |
| ---------------------- | --------------------------------------------------- |
| `--args "..."`         | Quoted argument string passed to the target         |
| `--pid <N>`            | Attach to existing process                          |
| `--script <FILE>`      | Run console commands from a file at startup        |
| `--arch auto|x86|x86_64|arm|aarch64|riscv64` | Architecture override        |
| `--format auto|pe|elf|macho|raw` | File format override                      |
| `--platform auto|windows|linux|macos|freebsd` | Platform override            |
| `--base-address 0xHEX` | Override loaded image base                          |
| `--break-entry`        | Break at the binary's entry point                   |
| `--working-directory <PATH>` | Working directory for launched target         |
| `--backend auto|windows|linux` | Force a specific debug backend            |
| `--log-level info|debug|trace` | tracing verbosity                         |
| `--headless`           | Run without opening the GUI                         |

## Keyboard shortcuts

| Key            | Action                       |
| -------------- | ---------------------------- |
| F2             | Toggle breakpoint at cursor  |
| F5 / F9        | Resume                       |
| F6             | Launch                       |
| F7             | Step Into                    |
| F8             | Step Over                    |
| F12            | Pause                        |
| Ctrl+F9        | Step Return                  |

## Supported file formats

- PE / PE32+ (Windows executables, DLLs)
- ELF (Linux executables; analysis only — Linux ptrace backend is a stub)
- Mach-O (analysis only)
- Raw shellcode (`--format raw --arch x86_64 --base-address 0x...`)

## Supported console commands

```
run | r              continue | c        pause
stepi | si           step | n            step-return | finish
break | b *0xADDR    delete <id>         enable <id>      disable <id>
condition <id> EXPR  regs                setreg <name> <value>
ip                   setip <addr>        x/<count><fmt> <addr>
threads              modules             vmmap            symbols
imports              exports             checksec
disasm | u <addr>    search <pattern>
cyclic <n>           cyclic-find <hex|ascii>              rop
iat                  got                 plt
quit | q | exit
# comment
```

## Known limitations / TODOs

- Hardware breakpoints are not yet wired (DR0..DR3 + DR7). The dialog is
  in place but currently logs `Unsupported`.
- Conditional-breakpoint expressions are stored but not yet evaluated by
  the backend (TODO: hook `expressions` into stop handling).
- Symbol resolution from PDBs is not implemented; only PE export/import
  symbols and section labels are surfaced.
- The Linux ptrace backend is a stub returning `Unsupported`.
- Step Over / Step Return are implemented as repeated single-steps with
  heuristics; full call-frame-aware stepping is a TODO.
- Standard-input redirection to the launched target is not yet wired
  (the Target Console panel only shows captured output).
- Only x86_64 register set is fully wired through the Windows
  `CONTEXT` reader; x86_32 needs a parallel implementation.
- No native file picker dependency — paths are typed in the Adapter
  Settings dialog.

## Project layout

```
src/
  cli.rs                      CLI parsing
  config.rs                   DebugConfig / BackendKind
  error.rs                    DbgError / DbgResult
  target/                     Binary models, PE/ELF/Mach-O/raw parsers
  debugger/                   Backend trait + Windows backend
    windows/                  Win32 debug-API implementation
    linux/                    ptrace stub
  analysis/                   capstone disasm, ROP, checksec, hints
  commands/                   Console AST + parser + executor
  pwn/                        cyclic, packing, hexdump, calling conv
  gui/                        egui frontend
    widgets/                  toolbar, sidebar, status bar, hex view
    panels/                   disassembly, registers, breakpoints,
                              memory, stack, debugger info, console,
                              modules, stack trace, logs
    dialogs/                  attach, adapter settings, override IP,
                              add/edit/hardware breakpoint
tests/                        integration tests for cyclic, packing,
                              hexdump, command parser, format detection
```

## Safety / ethical use

This software is provided for defensive research, CTF challenges,
reverse engineering of binaries you own or are authorized to analyze,
and authorized exploit-development work. The maintainers do not condone
or assist with creating malware, conducting unauthorized intrusions, or
bypassing security controls without permission.

## License

MIT — see crate metadata.
