//! Bundled shellcode payloads.  These are *educational* templates intended
//! for use in lab/CTF environments only.  No remote-shell or persistence
//! payloads are included.

#[derive(Debug, Clone, Copy)]
pub struct Shellcode {
    pub name: &'static str,
    pub arch: &'static str,
    pub os: &'static str,
    pub description: &'static str,
    pub bytes: &'static [u8],
}

/// `int3` — debug-break trap (every arch listed where it's a single-byte op).
pub const INT3_X86: Shellcode = Shellcode {
    name: "int3",
    arch: "x86/x86_64",
    os: "any",
    description: "Single-byte INT3 software breakpoint trap (0xCC).",
    bytes: &[0xCC],
};

/// Linux x86_64 `exit(0)` — `xor edi, edi; mov eax, 60; syscall`.
pub const LINUX_X86_64_EXIT: Shellcode = Shellcode {
    name: "linux-x86_64-exit",
    arch: "x86_64",
    os: "linux",
    description: "exit(0) via syscall 60.",
    bytes: &[0x31, 0xFF, 0xB8, 0x3C, 0x00, 0x00, 0x00, 0x0F, 0x05],
};

/// Linux i386 `exit(0)` — `xor ebx, ebx; mov eax, 1; int 0x80`.
pub const LINUX_I386_EXIT: Shellcode = Shellcode {
    name: "linux-i386-exit",
    arch: "i386",
    os: "linux",
    description: "exit(0) via int 0x80 / sys_exit (1).",
    bytes: &[0x31, 0xDB, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xCD, 0x80],
};

/// Windows x86_64 `ExitProcess`-style infinite loop (jmp $) — useful as a
/// safe pause when the debugger is attached. `EB FE`.
pub const X86_INFINITE_LOOP: Shellcode = Shellcode {
    name: "infinite-loop",
    arch: "x86/x86_64",
    os: "any",
    description: "JMP $ — pause execution forever (great for testing breakpoints).",
    bytes: &[0xEB, 0xFE],
};

pub const ALL: &[Shellcode] = &[
    INT3_X86,
    X86_INFINITE_LOOP,
    LINUX_X86_64_EXIT,
    LINUX_I386_EXIT,
];

pub fn find(name: &str) -> Option<Shellcode> {
    ALL.iter().copied().find(|s| s.name.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn lookup_works() {
        assert_eq!(find("int3").unwrap().bytes, &[0xCC]);
        assert!(find("nonexistent").is_none());
    }
}
