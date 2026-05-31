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
- **Multi-architecture disassembly** via
  [`capstone`](https://github.com/capstone-rust/capstone-rs), driven by a
  Rust port of the binutils/BFD architecture registry (see
  [Architecture support](#architecture-support)) — ~80 BFD families
  described, 13 with live decoders across both byte orders. Current-PC and
  breakpoint highlighting, right-click breakpoint toggle, jump to IP, run to
  here, copy address / instruction
- PE / ELF / Mach-O / raw-shellcode parsing via [`goblin`](https://github.com/m4b/goblin),
  with security feature reporting (ASLR, DEP/NX, CFG, SafeSEH,
  HighEntropyVA) and BFD-aware ELF `e_machine` → architecture mapping
- pwntools-compatible helpers: `cyclic`, `cyclic_find`, `p8/p16/p32/p64`,
  `u8_/u16_/u32_/u64_`, `hexdump`, calling-convention argument extractor
  (Windows x64, SysV AMD64, x86 cdecl/stdcall, AArch64 AAPCS)
- **CTF / RE / pwn toolkit** (all exposed as one-click plugins and console
  commands):
  - ROP/JOP gadget search with free-text queries (`pop rdi ; ret`),
    `pop reg ; ret` enumeration, and raw syscall-site location
  - Shannon entropy / packer detection (per-section + sliding-window
    high-entropy region finder)
  - Crypto-constant fingerprinting (AES S-boxes, SHA-256/MD5/SHA-1
    constants, CRC32 polynomial, zlib headers) and hash-format identification
  - Flag / IoC extraction (CTF flag formats, URLs, IPv4, e-mail, Base64)
  - Multi-codec auto-decoder (Base64/Base32/hex/URL/ASCII85/ROT-N) that peels
    nested encoding layers
  - Repeating-key XOR breaker (Hamming-distance key-size detection +
    per-column frequency solve)
- **Deobfuscation with mathematics:** a Mixed Boolean-Arithmetic (MBA)
  simplifier — parses integer expressions, applies algebraic + MBA identities,
  and *synthesizes the simplest equivalent expression*, verifying equivalence
  over the 64-bit ring by sampling (see [Deobfuscation](#deobfuscation-with-math))
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
| `--arch <name>`        | Architecture override (any BFD name/alias, e.g. `mips64el`, `ppc64`, `aarch64`, `sparc:v9`, `riscv32`) |
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

## Architecture support

ctfdbg ships a Rust port of the binutils/BFD architecture descriptor table
(`src/target/bfd.rs`), modelled on BFD's `bfd_arch_info_type`. It describes
~80 architecture families — name, aliases, word/address/byte width, default
byte order, and ELF `e_machine` number — so the debugger can *recognise and
describe* essentially the full binutils target set.

Of those, 13 families have a **live disassembler** (the capstone backends
available in this build), each reachable in both byte orders where the
architecture allows:

> x86 (16/32/64) · ARM / Thumb · AArch64 · MIPS (32/64/R6) · PowerPC (32/64) ·
> SPARC (v8/v9) · SystemZ (s390x) · m68k · m680x · XCore · TMS320C64x · EVM ·
> RISC-V (32/64)

The remaining families (Alpha, PA-RISC, IA-64, SuperH, ARC, AVR, MSP430,
Xtensa, LoongArch, MicroBlaze, OpenRISC, …) are described at the registry
level; the disassembler reports them honestly as "descriptor known, no live
decoder in this build" rather than failing opaquely. Use the `arch-list`,
`arch-info`, and `disasm-arch` plugins to explore them.

> *Note:* "porting binutils" here means porting BFD's **architecture
> descriptors** into Rust and wiring decoding through capstone (itself derived
> from LLVM). The multi-million-line `opcodes/` instruction tables are not
> transliterated from C — capstone provides the decoding.

## Deobfuscation with math

The `deobf` plugin (and `analysis::deobfuscate` module) tackles Mixed
Boolean-Arithmetic obfuscation. It parses an integer expression over 64-bit
wrapping arithmetic (variables `a`–`z`, operators `+ - * & | ^ ~ << >>`),
simplifies it algebraically, then searches a bounded space of small candidate
expressions for the **simplest equivalent form**, proving equivalence by
sampling hundreds of assignments (including carry/borrow edge cases) across
the whole 64-bit ring. For example:

```
deobf (x ^ y) + 2 * (x & y)      =>  x + y
deobf (x | y) - (~x & y)         =>  x
deobf ((1 << 8) | 0xff) ^ 0x0f   =>  255   (constant fold)
```

Equivalence is probabilistic (sampling), which is reliable in practice for
the linear MBA seen in CTF and malware.

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

## Built-in plugins / tools

Run from the **Plugins** panel, or type the plugin id (with optional argument)
into the Debugger Console.

| id              | Category      | Purpose                                              |
| --------------- | ------------- | ---------------------------------------------------- |
| `auto-analyze`  | Analysis      | Re-run function/string/hint analysis                 |
| `checksec`      | Analysis      | Binary mitigation summary                            |
| `entropy`       | Analysis      | Per-section + windowed Shannon entropy / packer scan |
| `arch-list`     | Reverse Eng.  | List the BFD architecture set (filterable)           |
| `arch-info`     | Reverse Eng.  | Describe one architecture by name/alias              |
| `disasm-arch`   | Reverse Eng.  | Disassemble memory for *any* named architecture      |
| `iocs`          | Reverse Eng.  | Extract flags / URLs / IPv4 / e-mail / Base64        |
| `crypto-id`     | Crypto        | Fingerprint AES/SHA/MD5/CRC32 constants              |
| `hash-id`       | Crypto        | Identify a hash by length/format                     |
| `deobf`         | Deobfuscation | Simplify / synthesize an MBA expression              |
| `decode`        | Deobfuscation | Auto-peel Base64/hex/Base32/ASCII85/URL layers       |
| `xor-key`       | Deobfuscation | Break repeating-key XOR over the memory window       |
| `rop-scan`      | Analysis      | Linear ROP gadget scan                               |
| `gadget`        | Pwn           | Gadget search by query + `pop reg ; ret`             |
| `syscall-sites` | Pwn           | Locate `syscall` / `int 0x80` / `sysenter`           |
| `cyclic` / `cyclic-find` | Pwn  | de Bruijn pattern generate / offset lookup           |
| `fmtstr-probe`  | Pwn           | Build a `%p` format-string probe                     |
| `xor-brute`     | Pwn           | Single-byte XOR brute over the memory window         |
| `hexdump`       | Pwn           | Hex/ASCII dump of the memory window                  |
| `disasm`        | Analysis      | Disassemble at an address                            |
| `shellcode-list`| Pwn           | List bundled educational shellcode templates         |

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
    bfd.rs                    BFD architecture registry (~80 families)
    arch.rs                   Architecture enum + register models
  debugger/                   Backend trait + Windows backend
    windows/                  Win32 debug-API implementation
    linux/                    ptrace stub
  analysis/                   multi-arch disasm, ROP, checksec, hints,
                              entropy, crypto-id, IoC/flag extraction,
                              MBA deobfuscation
  commands/                   Console AST + parser + executor
  pwn/                        cyclic, packing, hexdump, calling conv,
                              encoding codecs, XOR breaker, gadget search
  plugins/                    built-in plugin registry + tools
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
