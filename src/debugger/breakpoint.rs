//! Breakpoint model.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BreakpointId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointKind {
    /// Software breakpoint (int3 / 0xCC on x86).
    Software,
    /// Hardware execution breakpoint.
    HardwareExecute,
    /// Hardware read watchpoint.
    HardwareRead,
    /// Hardware write watchpoint.
    HardwareWrite,
    /// Hardware access (read/write) watchpoint.
    HardwareAccess,
}

impl BreakpointKind {
    pub fn short_tag(self) -> &'static str {
        match self {
            Self::Software => "S",
            Self::HardwareExecute => "HE",
            Self::HardwareRead => "HR",
            Self::HardwareWrite => "HW",
            Self::HardwareAccess => "HA",
        }
    }
}

#[derive(Debug, Clone)]
pub struct BreakpointInfo {
    pub id: BreakpointId,
    pub address: u64,
    pub enabled: bool,
    pub kind: BreakpointKind,
    pub size: u8,
    pub condition: Option<String>,
    /// e.g. "module.exe+0x1234"
    pub location_label: String,
    pub hit_count: u64,
    /// Original byte for software breakpoints.
    pub original_byte: Option<u8>,
}

impl BreakpointInfo {
    pub fn new_software(id: BreakpointId, address: u64, location_label: String) -> Self {
        Self {
            id,
            address,
            enabled: true,
            kind: BreakpointKind::Software,
            size: 1,
            condition: None,
            location_label,
            hit_count: 0,
            original_byte: None,
        }
    }
}
