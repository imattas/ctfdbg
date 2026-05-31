//! CPU architecture, endian, and register-role metadata.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Architecture {
    #[default]
    Auto,
    X86,
    X86_64,
    Arm,
    Thumb,
    AArch64,
    Riscv32,
    Riscv64,
    Mips,
    Mips64,
    PowerPc,
    PowerPc64,
    Sparc,
    Sparc64,
    SystemZ,
    M68k,
    SuperH,
    /// Architecture recognised at the descriptor level (see [`crate::target::bfd`])
    /// but without a live debugger/register model in this build.
    Unsupported,
}

impl Architecture {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "x86" | "i386" | "i686" => Self::X86,
            "x86_64" | "x64" | "amd64" => Self::X86_64,
            "arm" | "arm32" | "armv7" => Self::Arm,
            "thumb" | "thumb2" => Self::Thumb,
            "aarch64" | "arm64" => Self::AArch64,
            "riscv32" | "rv32" => Self::Riscv32,
            "riscv64" | "riscv" | "rv64" => Self::Riscv64,
            "mips" | "mips32" | "mipsel" | "mipseb" => Self::Mips,
            "mips64" | "mips64el" => Self::Mips64,
            "ppc" | "powerpc" | "ppc32" => Self::PowerPc,
            "ppc64" | "powerpc64" | "ppc64le" => Self::PowerPc64,
            "sparc" | "sparc32" => Self::Sparc,
            "sparc64" | "sparcv9" => Self::Sparc64,
            "s390" | "s390x" | "systemz" | "sysz" => Self::SystemZ,
            "m68k" | "68000" | "68040" => Self::M68k,
            "sh" | "sh4" | "superh" => Self::SuperH,
            // Fall back to the broader BFD table before giving up.
            other => crate::target::bfd::lookup(other)
                .map(|a| a.arch)
                .unwrap_or(Self::Auto),
        }
    }

    pub fn pointer_size(self) -> usize {
        match self {
            Self::X86 | Self::Arm | Self::Thumb | Self::Riscv32 | Self::Mips
            | Self::PowerPc | Self::Sparc | Self::SuperH | Self::M68k => 4,
            Self::X86_64 | Self::AArch64 | Self::Riscv64 | Self::Mips64
            | Self::PowerPc64 | Self::Sparc64 | Self::SystemZ => 8,
            Self::Auto => 8,
            Self::Unsupported => 8,
        }
    }

    pub fn is_64bit(self) -> bool {
        self.pointer_size() == 8
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Arm => "arm",
            Self::Thumb => "thumb",
            Self::AArch64 => "aarch64",
            Self::Riscv32 => "riscv32",
            Self::Riscv64 => "riscv64",
            Self::Mips => "mips",
            Self::Mips64 => "mips64",
            Self::PowerPc => "powerpc",
            Self::PowerPc64 => "powerpc64",
            Self::Sparc => "sparc",
            Self::Sparc64 => "sparc64",
            Self::SystemZ => "s390x",
            Self::M68k => "m68k",
            Self::SuperH => "sh",
            Self::Unsupported => "unsupported",
        }
    }
}

impl fmt::Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Auto,
    Little,
    Big,
}

impl Endian {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "little" | "le" => Self::Little,
            "big" | "be" => Self::Big,
            _ => Self::Auto,
        }
    }

    pub fn for_arch(arch: Architecture) -> Self {
        // Use the BFD descriptor's default byte order when we have one.
        crate::target::bfd::for_architecture(arch)
            .map(|a| a.byte_order.to_endian())
            .unwrap_or(Self::Little)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterRole {
    ProgramCounter,
    StackPointer,
    FramePointer,
    ReturnValue,
    Argument(u8),
    Flags,
    General,
}

#[derive(Debug, Clone)]
pub struct RegisterMeta {
    pub name: &'static str,
    pub role: RegisterRole,
    pub bit_width: u16,
}

impl Architecture {
    /// Canonical register set for the architecture (used by the GUI).
    pub fn registers(self) -> &'static [RegisterMeta] {
        use RegisterRole::*;
        match self {
            Architecture::X86_64 | Architecture::Auto => &[
                RegisterMeta { name: "rax", role: ReturnValue, bit_width: 64 },
                RegisterMeta { name: "rbx", role: General, bit_width: 64 },
                RegisterMeta { name: "rcx", role: Argument(0), bit_width: 64 },
                RegisterMeta { name: "rdx", role: Argument(1), bit_width: 64 },
                RegisterMeta { name: "rsi", role: General, bit_width: 64 },
                RegisterMeta { name: "rdi", role: General, bit_width: 64 },
                RegisterMeta { name: "rbp", role: FramePointer, bit_width: 64 },
                RegisterMeta { name: "rsp", role: StackPointer, bit_width: 64 },
                RegisterMeta { name: "r8",  role: Argument(2), bit_width: 64 },
                RegisterMeta { name: "r9",  role: Argument(3), bit_width: 64 },
                RegisterMeta { name: "r10", role: General, bit_width: 64 },
                RegisterMeta { name: "r11", role: General, bit_width: 64 },
                RegisterMeta { name: "r12", role: General, bit_width: 64 },
                RegisterMeta { name: "r13", role: General, bit_width: 64 },
                RegisterMeta { name: "r14", role: General, bit_width: 64 },
                RegisterMeta { name: "r15", role: General, bit_width: 64 },
                RegisterMeta { name: "rip", role: ProgramCounter, bit_width: 64 },
                RegisterMeta { name: "rflags", role: Flags, bit_width: 64 },
            ],
            Architecture::X86 => &[
                RegisterMeta { name: "eax", role: ReturnValue, bit_width: 32 },
                RegisterMeta { name: "ebx", role: General, bit_width: 32 },
                RegisterMeta { name: "ecx", role: General, bit_width: 32 },
                RegisterMeta { name: "edx", role: General, bit_width: 32 },
                RegisterMeta { name: "esi", role: General, bit_width: 32 },
                RegisterMeta { name: "edi", role: General, bit_width: 32 },
                RegisterMeta { name: "ebp", role: FramePointer, bit_width: 32 },
                RegisterMeta { name: "esp", role: StackPointer, bit_width: 32 },
                RegisterMeta { name: "eip", role: ProgramCounter, bit_width: 32 },
                RegisterMeta { name: "eflags", role: Flags, bit_width: 32 },
            ],
            Architecture::AArch64 => &[
                RegisterMeta { name: "x0",  role: Argument(0), bit_width: 64 },
                RegisterMeta { name: "x1",  role: Argument(1), bit_width: 64 },
                RegisterMeta { name: "x2",  role: Argument(2), bit_width: 64 },
                RegisterMeta { name: "x3",  role: Argument(3), bit_width: 64 },
                RegisterMeta { name: "x4",  role: Argument(4), bit_width: 64 },
                RegisterMeta { name: "x5",  role: Argument(5), bit_width: 64 },
                RegisterMeta { name: "x6",  role: Argument(6), bit_width: 64 },
                RegisterMeta { name: "x7",  role: Argument(7), bit_width: 64 },
                RegisterMeta { name: "fp",  role: FramePointer, bit_width: 64 },
                RegisterMeta { name: "lr",  role: General, bit_width: 64 },
                RegisterMeta { name: "sp",  role: StackPointer, bit_width: 64 },
                RegisterMeta { name: "pc",  role: ProgramCounter, bit_width: 64 },
            ],
            Architecture::Arm => &[
                RegisterMeta { name: "r0",  role: Argument(0), bit_width: 32 },
                RegisterMeta { name: "r1",  role: Argument(1), bit_width: 32 },
                RegisterMeta { name: "r2",  role: Argument(2), bit_width: 32 },
                RegisterMeta { name: "r3",  role: Argument(3), bit_width: 32 },
                RegisterMeta { name: "sp",  role: StackPointer, bit_width: 32 },
                RegisterMeta { name: "lr",  role: General, bit_width: 32 },
                RegisterMeta { name: "pc",  role: ProgramCounter, bit_width: 32 },
            ],
            Architecture::Riscv64 => &[
                RegisterMeta { name: "ra", role: General, bit_width: 64 },
                RegisterMeta { name: "sp", role: StackPointer, bit_width: 64 },
                RegisterMeta { name: "gp", role: General, bit_width: 64 },
                RegisterMeta { name: "tp", role: General, bit_width: 64 },
                RegisterMeta { name: "s0", role: FramePointer, bit_width: 64 },
                RegisterMeta { name: "a0", role: Argument(0), bit_width: 64 },
                RegisterMeta { name: "a1", role: Argument(1), bit_width: 64 },
                RegisterMeta { name: "a2", role: Argument(2), bit_width: 64 },
                RegisterMeta { name: "a3", role: Argument(3), bit_width: 64 },
                RegisterMeta { name: "a4", role: Argument(4), bit_width: 64 },
                RegisterMeta { name: "a5", role: Argument(5), bit_width: 64 },
                RegisterMeta { name: "a6", role: Argument(6), bit_width: 64 },
                RegisterMeta { name: "a7", role: Argument(7), bit_width: 64 },
                RegisterMeta { name: "pc", role: ProgramCounter, bit_width: 64 },
            ],
            Architecture::Riscv32 => &[
                RegisterMeta { name: "ra", role: General, bit_width: 32 },
                RegisterMeta { name: "sp", role: StackPointer, bit_width: 32 },
                RegisterMeta { name: "gp", role: General, bit_width: 32 },
                RegisterMeta { name: "s0", role: FramePointer, bit_width: 32 },
                RegisterMeta { name: "a0", role: Argument(0), bit_width: 32 },
                RegisterMeta { name: "a1", role: Argument(1), bit_width: 32 },
                RegisterMeta { name: "a2", role: Argument(2), bit_width: 32 },
                RegisterMeta { name: "a3", role: Argument(3), bit_width: 32 },
                RegisterMeta { name: "pc", role: ProgramCounter, bit_width: 32 },
            ],
            Architecture::Thumb => &[
                RegisterMeta { name: "r0",  role: Argument(0), bit_width: 32 },
                RegisterMeta { name: "r1",  role: Argument(1), bit_width: 32 },
                RegisterMeta { name: "r2",  role: Argument(2), bit_width: 32 },
                RegisterMeta { name: "r3",  role: Argument(3), bit_width: 32 },
                RegisterMeta { name: "r7",  role: FramePointer, bit_width: 32 },
                RegisterMeta { name: "sp",  role: StackPointer, bit_width: 32 },
                RegisterMeta { name: "lr",  role: General, bit_width: 32 },
                RegisterMeta { name: "pc",  role: ProgramCounter, bit_width: 32 },
            ],
            Architecture::Mips | Architecture::Mips64 => {
                // o32/n64 share these argument-register names; width differs only
                // in how the debugger renders them, so we report the common set.
                if matches!(self, Architecture::Mips64) {
                    &[
                        RegisterMeta { name: "zero", role: General, bit_width: 64 },
                        RegisterMeta { name: "v0", role: ReturnValue, bit_width: 64 },
                        RegisterMeta { name: "a0", role: Argument(0), bit_width: 64 },
                        RegisterMeta { name: "a1", role: Argument(1), bit_width: 64 },
                        RegisterMeta { name: "a2", role: Argument(2), bit_width: 64 },
                        RegisterMeta { name: "a3", role: Argument(3), bit_width: 64 },
                        RegisterMeta { name: "gp", role: General, bit_width: 64 },
                        RegisterMeta { name: "sp", role: StackPointer, bit_width: 64 },
                        RegisterMeta { name: "fp", role: FramePointer, bit_width: 64 },
                        RegisterMeta { name: "ra", role: General, bit_width: 64 },
                        RegisterMeta { name: "pc", role: ProgramCounter, bit_width: 64 },
                    ]
                } else {
                    &[
                        RegisterMeta { name: "zero", role: General, bit_width: 32 },
                        RegisterMeta { name: "v0", role: ReturnValue, bit_width: 32 },
                        RegisterMeta { name: "a0", role: Argument(0), bit_width: 32 },
                        RegisterMeta { name: "a1", role: Argument(1), bit_width: 32 },
                        RegisterMeta { name: "a2", role: Argument(2), bit_width: 32 },
                        RegisterMeta { name: "a3", role: Argument(3), bit_width: 32 },
                        RegisterMeta { name: "gp", role: General, bit_width: 32 },
                        RegisterMeta { name: "sp", role: StackPointer, bit_width: 32 },
                        RegisterMeta { name: "fp", role: FramePointer, bit_width: 32 },
                        RegisterMeta { name: "ra", role: General, bit_width: 32 },
                        RegisterMeta { name: "pc", role: ProgramCounter, bit_width: 32 },
                    ]
                }
            }
            Architecture::PowerPc => &[
                RegisterMeta { name: "r1", role: StackPointer, bit_width: 32 },
                RegisterMeta { name: "r3", role: Argument(0), bit_width: 32 },
                RegisterMeta { name: "r4", role: Argument(1), bit_width: 32 },
                RegisterMeta { name: "r5", role: Argument(2), bit_width: 32 },
                RegisterMeta { name: "r6", role: Argument(3), bit_width: 32 },
                RegisterMeta { name: "r31", role: FramePointer, bit_width: 32 },
                RegisterMeta { name: "lr", role: General, bit_width: 32 },
                RegisterMeta { name: "ctr", role: General, bit_width: 32 },
                RegisterMeta { name: "pc", role: ProgramCounter, bit_width: 32 },
            ],
            Architecture::PowerPc64 => &[
                RegisterMeta { name: "r1", role: StackPointer, bit_width: 64 },
                RegisterMeta { name: "r3", role: Argument(0), bit_width: 64 },
                RegisterMeta { name: "r4", role: Argument(1), bit_width: 64 },
                RegisterMeta { name: "r5", role: Argument(2), bit_width: 64 },
                RegisterMeta { name: "r6", role: Argument(3), bit_width: 64 },
                RegisterMeta { name: "r31", role: FramePointer, bit_width: 64 },
                RegisterMeta { name: "lr", role: General, bit_width: 64 },
                RegisterMeta { name: "ctr", role: General, bit_width: 64 },
                RegisterMeta { name: "pc", role: ProgramCounter, bit_width: 64 },
            ],
            Architecture::Sparc => &[
                RegisterMeta { name: "g0", role: General, bit_width: 32 },
                RegisterMeta { name: "o0", role: Argument(0), bit_width: 32 },
                RegisterMeta { name: "o1", role: Argument(1), bit_width: 32 },
                RegisterMeta { name: "o2", role: Argument(2), bit_width: 32 },
                RegisterMeta { name: "sp", role: StackPointer, bit_width: 32 },
                RegisterMeta { name: "fp", role: FramePointer, bit_width: 32 },
                RegisterMeta { name: "pc", role: ProgramCounter, bit_width: 32 },
            ],
            Architecture::Sparc64 => &[
                RegisterMeta { name: "g0", role: General, bit_width: 64 },
                RegisterMeta { name: "o0", role: Argument(0), bit_width: 64 },
                RegisterMeta { name: "o1", role: Argument(1), bit_width: 64 },
                RegisterMeta { name: "o2", role: Argument(2), bit_width: 64 },
                RegisterMeta { name: "sp", role: StackPointer, bit_width: 64 },
                RegisterMeta { name: "fp", role: FramePointer, bit_width: 64 },
                RegisterMeta { name: "pc", role: ProgramCounter, bit_width: 64 },
            ],
            Architecture::SystemZ => &[
                RegisterMeta { name: "r0",  role: General, bit_width: 64 },
                RegisterMeta { name: "r1",  role: General, bit_width: 64 },
                RegisterMeta { name: "r2",  role: Argument(0), bit_width: 64 },
                RegisterMeta { name: "r3",  role: Argument(1), bit_width: 64 },
                RegisterMeta { name: "r4",  role: Argument(2), bit_width: 64 },
                RegisterMeta { name: "r5",  role: Argument(3), bit_width: 64 },
                RegisterMeta { name: "r11", role: FramePointer, bit_width: 64 },
                RegisterMeta { name: "r14", role: General, bit_width: 64 },
                RegisterMeta { name: "r15", role: StackPointer, bit_width: 64 },
                RegisterMeta { name: "pc",  role: ProgramCounter, bit_width: 64 },
            ],
            Architecture::M68k => &[
                RegisterMeta { name: "d0", role: ReturnValue, bit_width: 32 },
                RegisterMeta { name: "d1", role: General, bit_width: 32 },
                RegisterMeta { name: "d2", role: General, bit_width: 32 },
                RegisterMeta { name: "a0", role: General, bit_width: 32 },
                RegisterMeta { name: "a1", role: General, bit_width: 32 },
                RegisterMeta { name: "a6", role: FramePointer, bit_width: 32 },
                RegisterMeta { name: "a7", role: StackPointer, bit_width: 32 },
                RegisterMeta { name: "pc", role: ProgramCounter, bit_width: 32 },
            ],
            Architecture::SuperH => &[
                RegisterMeta { name: "r0",  role: ReturnValue, bit_width: 32 },
                RegisterMeta { name: "r4",  role: Argument(0), bit_width: 32 },
                RegisterMeta { name: "r5",  role: Argument(1), bit_width: 32 },
                RegisterMeta { name: "r6",  role: Argument(2), bit_width: 32 },
                RegisterMeta { name: "r7",  role: Argument(3), bit_width: 32 },
                RegisterMeta { name: "r14", role: FramePointer, bit_width: 32 },
                RegisterMeta { name: "r15", role: StackPointer, bit_width: 32 },
                RegisterMeta { name: "pr",  role: General, bit_width: 32 },
                RegisterMeta { name: "pc",  role: ProgramCounter, bit_width: 32 },
            ],
            Architecture::Unsupported => &[],
        }
    }
}
