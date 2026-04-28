//! CPU architecture, endian, and register-role metadata.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Architecture {
    #[default]
    Auto,
    X86,
    X86_64,
    Arm,
    AArch64,
    Riscv64,
}

impl Architecture {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "x86" | "i386" | "i686" => Self::X86,
            "x86_64" | "x64" | "amd64" => Self::X86_64,
            "arm" | "arm32" | "armv7" => Self::Arm,
            "aarch64" | "arm64" => Self::AArch64,
            "riscv64" | "riscv" => Self::Riscv64,
            _ => Self::Auto,
        }
    }

    pub fn pointer_size(self) -> usize {
        match self {
            Self::X86 | Self::Arm => 4,
            Self::X86_64 | Self::AArch64 | Self::Riscv64 => 8,
            Self::Auto => 8,
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
            Self::AArch64 => "aarch64",
            Self::Riscv64 => "riscv64",
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
        // All currently-supported targets are little-endian by default.
        let _ = arch;
        Self::Little
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
                RegisterMeta { name: "ra",  role: General, bit_width: 64 },
                RegisterMeta { name: "sp",  role: StackPointer, bit_width: 64 },
                RegisterMeta { name: "gp",  role: General, bit_width: 64 },
                RegisterMeta { name: "tp",  role: General, bit_width: 64 },
                RegisterMeta { name: "a0",  role: Argument(0), bit_width: 64 },
                RegisterMeta { name: "a1",  role: Argument(1), bit_width: 64 },
                RegisterMeta { name: "pc",  role: ProgramCounter, bit_width: 64 },
            ],
        }
    }
}
