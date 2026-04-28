use crate::target::binary::BinaryInfo;

pub struct ChecksecReport {
    pub lines: Vec<(String, String)>, // (label, status)
}

pub fn checksec(info: &BinaryInfo) -> ChecksecReport {
    let s = &info.security;
    let lines = vec![
        ("Format".into(), info.format.to_string()),
        ("Arch".into(), info.architecture.to_string()),
        ("ASLR / DYNAMIC_BASE".into(), yn(s.aslr)),
        ("DEP / NX".into(), yn(s.dep_nx)),
        ("CFG".into(), yn(s.cfg)),
        ("SafeSEH".into(), yn(s.safe_seh)),
        ("HighEntropyVA".into(), yn(s.high_entropy_va)),
        ("Entry".into(), format!("0x{:x}", info.entry_point)),
        ("Image base".into(), format!("0x{:x}", info.preferred_image_base)),
    ];
    ChecksecReport { lines }
}

fn yn(b: bool) -> String { if b { "yes".into() } else { "no".into() } }
