use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFormat {
    Auto,
    Pe,
    Elf,
    MachO,
    Raw,
    Unknown,
}

impl FileFormat {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "pe" | "coff" => Self::Pe,
            "elf" => Self::Elf,
            "macho" | "mach-o" => Self::MachO,
            "raw" | "shellcode" => Self::Raw,
            _ => Self::Auto,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Pe => "PE",
            Self::Elf => "ELF",
            Self::MachO => "Mach-O",
            Self::Raw => "raw",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for FileFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}
