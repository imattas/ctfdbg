use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Auto,
    Windows,
    Linux,
    MacOs,
    Unknown,
}

impl Platform {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "windows" | "win" => Self::Windows,
            "linux" => Self::Linux,
            "macos" | "darwin" | "osx" => Self::MacOs,
            _ => Self::Auto,
        }
    }

    pub fn host() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else {
            Self::Unknown
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::MacOs => "macos",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}
