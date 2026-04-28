//! Calling-convention argument helpers used by the Debugger Info panel.

use crate::debugger::registers::RegisterFile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConvention {
    WindowsX64,
    SysVAmd64,
    X86Cdecl,
    X86Stdcall,
    AArch64Aapcs,
}

#[derive(Debug, Clone)]
pub struct CallArg {
    pub name: String,
    pub value: u64,
    pub source: String,
}

const STACK_ARGS_TO_SHOW: usize = 4;

pub fn extract_args(
    cc: CallingConvention,
    regs: &RegisterFile,
    read_mem_qword: impl Fn(u64) -> Option<u64>,
) -> Vec<CallArg> {
    fn reg(rf: &RegisterFile, n: &str) -> u64 { rf.get(n).unwrap_or(0) }
    let sp = regs.sp().unwrap_or(0);
    match cc {
        CallingConvention::WindowsX64 => {
            let mut v = vec![
                CallArg { name: "arg1".into(), value: reg(regs, "rcx"), source: "rcx".into() },
                CallArg { name: "arg2".into(), value: reg(regs, "rdx"), source: "rdx".into() },
                CallArg { name: "arg3".into(), value: reg(regs, "r8"),  source: "r8".into()  },
                CallArg { name: "arg4".into(), value: reg(regs, "r9"),  source: "r9".into()  },
            ];
            // Stack args start at [rsp+0x28] on Win64 (after shadow space + return).
            for i in 0..STACK_ARGS_TO_SHOW {
                let addr = sp.wrapping_add(0x28 + (i as u64) * 8);
                let val = read_mem_qword(addr).unwrap_or(0);
                v.push(CallArg { name: format!("arg{}", 5 + i), value: val, source: format!("[rsp+0x{:x}]", 0x28 + i * 8) });
            }
            v
        }
        CallingConvention::SysVAmd64 => {
            let mut v = vec![
                CallArg { name: "arg1".into(), value: reg(regs, "rdi"), source: "rdi".into() },
                CallArg { name: "arg2".into(), value: reg(regs, "rsi"), source: "rsi".into() },
                CallArg { name: "arg3".into(), value: reg(regs, "rdx"), source: "rdx".into() },
                CallArg { name: "arg4".into(), value: reg(regs, "rcx"), source: "rcx".into() },
                CallArg { name: "arg5".into(), value: reg(regs, "r8"),  source: "r8".into()  },
                CallArg { name: "arg6".into(), value: reg(regs, "r9"),  source: "r9".into()  },
            ];
            for i in 0..STACK_ARGS_TO_SHOW {
                let addr = sp.wrapping_add(0x8 + (i as u64) * 8);
                let val = read_mem_qword(addr).unwrap_or(0);
                v.push(CallArg { name: format!("arg{}", 7 + i), value: val, source: format!("[rsp+0x{:x}]", 8 + i * 8) });
            }
            v
        }
        CallingConvention::X86Cdecl | CallingConvention::X86Stdcall => {
            (0..6).map(|i| {
                let addr = sp.wrapping_add(0x4 + (i as u64) * 4);
                CallArg {
                    name: format!("arg{}", i + 1),
                    value: read_mem_qword(addr).unwrap_or(0) & 0xFFFF_FFFF,
                    source: format!("[esp+0x{:x}]", 4 + i * 4),
                }
            }).collect()
        }
        CallingConvention::AArch64Aapcs => {
            (0..8).map(|i| CallArg {
                name: format!("arg{}", i + 1),
                value: reg(regs, &format!("x{i}")),
                source: format!("x{i}"),
            }).collect()
        }
    }
}
