//! Linux syscall number tables for the common architectures, with name <->
//! number lookup. A curated set covering the syscalls that matter most for
//! exploitation and reversing (I/O, memory, process, sockets).

use crate::target::arch::Architecture;

/// (name, x86_64, x86/i386, aarch64) — `-1` means "not in this table for arch".
struct Row {
    name: &'static str,
    x64: i32,
    x86: i32,
    arm64: i32,
}

const TABLE: &[Row] = &[
    Row { name: "read",        x64: 0,   x86: 3,   arm64: 63 },
    Row { name: "write",       x64: 1,   x86: 4,   arm64: 64 },
    Row { name: "open",        x64: 2,   x86: 5,   arm64: -1 },
    Row { name: "close",       x64: 3,   x86: 6,   arm64: 57 },
    Row { name: "stat",        x64: 4,   x86: 106, arm64: -1 },
    Row { name: "fstat",       x64: 5,   x86: 108, arm64: 80 },
    Row { name: "lseek",       x64: 8,   x86: 19,  arm64: 62 },
    Row { name: "mmap",        x64: 9,   x86: 90,  arm64: 222 },
    Row { name: "mprotect",    x64: 10,  x86: 125, arm64: 226 },
    Row { name: "munmap",      x64: 11,  x86: 91,  arm64: 215 },
    Row { name: "brk",         x64: 12,  x86: 45,  arm64: 214 },
    Row { name: "rt_sigaction",x64: 13,  x86: 174, arm64: 134 },
    Row { name: "ioctl",       x64: 16,  x86: 54,  arm64: 29 },
    Row { name: "access",      x64: 21,  x86: 33,  arm64: -1 },
    Row { name: "pipe",        x64: 22,  x86: 42,  arm64: -1 },
    Row { name: "dup",         x64: 32,  x86: 41,  arm64: 23 },
    Row { name: "dup2",        x64: 33,  x86: 63,  arm64: -1 },
    Row { name: "dup3",        x64: 292, x86: 330, arm64: 24 },
    Row { name: "socket",      x64: 41,  x86: -1,  arm64: 198 },
    Row { name: "connect",     x64: 42,  x86: -1,  arm64: 203 },
    Row { name: "accept",      x64: 43,  x86: -1,  arm64: 202 },
    Row { name: "sendto",      x64: 44,  x86: -1,  arm64: 206 },
    Row { name: "recvfrom",    x64: 45,  x86: -1,  arm64: 207 },
    Row { name: "bind",        x64: 49,  x86: -1,  arm64: 200 },
    Row { name: "listen",      x64: 50,  x86: -1,  arm64: 201 },
    Row { name: "socketcall",  x64: -1,  x86: 102, arm64: -1 },
    Row { name: "clone",       x64: 56,  x86: 120, arm64: 220 },
    Row { name: "fork",        x64: 57,  x86: 2,   arm64: -1 },
    Row { name: "execve",      x64: 59,  x86: 11,  arm64: 221 },
    Row { name: "exit",        x64: 60,  x86: 1,   arm64: 93 },
    Row { name: "wait4",       x64: 61,  x86: 114, arm64: 260 },
    Row { name: "kill",        x64: 62,  x86: 37,  arm64: 129 },
    Row { name: "getpid",      x64: 39,  x86: 20,  arm64: 172 },
    Row { name: "getuid",      x64: 102, x86: 24,  arm64: 174 },
    Row { name: "setuid",      x64: 105, x86: 23,  arm64: 146 },
    Row { name: "setgid",      x64: 106, x86: 46,  arm64: 144 },
    Row { name: "chmod",       x64: 90,  x86: 15,  arm64: -1 },
    Row { name: "ptrace",      x64: 101, x86: 26,  arm64: 117 },
    Row { name: "personality", x64: 135, x86: 136, arm64: 92 },
    Row { name: "openat",      x64: 257, x86: 295, arm64: 56 },
    Row { name: "execveat",    x64: 322, x86: 358, arm64: 281 },
    Row { name: "exit_group",  x64: 231, x86: 252, arm64: 94 },
];

fn num_for(row: &Row, arch: Architecture) -> i32 {
    match arch {
        Architecture::X86_64 | Architecture::Auto => row.x64,
        Architecture::X86 => row.x86,
        Architecture::AArch64 => row.arm64,
        _ => -1,
    }
}

/// Look up a syscall number by name for an architecture.
pub fn number(name: &str, arch: Architecture) -> Option<i32> {
    let n = name.trim().to_ascii_lowercase();
    TABLE.iter().find(|r| r.name == n).map(|r| num_for(r, arch)).filter(|&v| v >= 0)
}

/// Look up the syscall name for a number on an architecture.
pub fn name(num: i32, arch: Architecture) -> Option<&'static str> {
    TABLE.iter().find(|r| num_for(r, arch) == num).map(|r| r.name)
}

/// All known (name, number) pairs for an architecture, sorted by number.
pub fn table(arch: Architecture) -> Vec<(&'static str, i32)> {
    let mut v: Vec<(&'static str, i32)> = TABLE
        .iter()
        .filter_map(|r| {
            let n = num_for(r, arch);
            if n >= 0 { Some((r.name, n)) } else { None }
        })
        .collect();
    v.sort_by_key(|&(_, n)| n);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_numbers() {
        assert_eq!(number("execve", Architecture::X86_64), Some(59));
        assert_eq!(number("execve", Architecture::X86), Some(11));
        assert_eq!(number("execve", Architecture::AArch64), Some(221));
        assert_eq!(number("write", Architecture::X86_64), Some(1));
        assert_eq!(name(0, Architecture::X86_64), Some("read"));
        assert_eq!(name(59, Architecture::X86_64), Some("execve"));
        // open does not exist on aarch64 (openat only).
        assert_eq!(number("open", Architecture::AArch64), None);
    }

    #[test]
    fn table_is_sorted() {
        let t = table(Architecture::X86_64);
        assert!(t.windows(2).all(|w| w[0].1 <= w[1].1));
        assert!(!t.is_empty());
    }
}
