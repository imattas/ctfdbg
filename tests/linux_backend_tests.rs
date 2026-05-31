//! End-to-end tests for the real Linux ptrace backend.
//!
//! These actually fork/exec `/bin/true`, drive it through launch → breakpoint
//! → single-step → run-to-exit, and verify register/memory access.  Gated to
//! Linux x86-64 (the host these run on); other arches are exercised by the
//! cross-compile + QEMU step in CI.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux_x86_64 {
    use ctfdbg::debugger::backend::{DebugBackend, DebugTarget};
    use ctfdbg::debugger::events::DebuggerEvent;
    use ctfdbg::debugger::linux::backend::LinuxPtraceBackend;
    use ctfdbg::debugger::state::TargetState;
    use std::path::{Path, PathBuf};

    fn target(path: &str) -> DebugTarget {
        DebugTarget { executable: Some(PathBuf::from(path)), ..Default::default() }
    }

    #[test]
    fn full_debug_cycle() {
        if !Path::new("/bin/true").exists() {
            eprintln!("skipping: /bin/true not present");
            return;
        }
        let mut be = LinuxPtraceBackend::new();
        be.launch(&target("/bin/true")).expect("launch");
        assert_eq!(be.state(), TargetState::Stopped);
        assert!(be.pid().is_some());

        // Stopped at the loader entry: registers and memory must be readable.
        let regs = be.read_registers(None).expect("registers");
        let rip = regs.pc().expect("pc");
        assert!(rip != 0, "pc should be nonzero at entry");

        let code = be.read_memory(rip, 8).expect("read code");
        assert_eq!(code.len(), 8);

        // Modules from /proc/<pid>/maps should include at least one entry.
        let mods = be.list_modules().expect("modules");
        assert!(!mods.is_empty(), "expected mapped modules");

        // A breakpoint at the current PC must be hidden from memory reads...
        let id = be.set_breakpoint(rip).expect("set breakpoint");
        let after = be.read_memory(rip, 1).expect("read after bp");
        assert_eq!(after[0], code[0], "breakpoint byte must be hidden");

        // ...and continuing should hit it immediately.
        match be.continue_exec().expect("continue") {
            DebuggerEvent::BreakpointHit { address, id: hit, .. } => {
                assert_eq!(address, rip);
                assert_eq!(hit, id.0);
            }
            other => panic!("expected BreakpointHit, got {other:?}"),
        }
        // PC is rewound to the breakpoint address.
        assert_eq!(be.read_registers(None).unwrap().pc().unwrap(), rip);

        // Step over the breakpoint (re-arms it under the hood).
        match be.single_step().expect("single step") {
            DebuggerEvent::SingleStep { .. } | DebuggerEvent::ProcessExited { .. } => {}
            other => panic!("expected SingleStep/Exit, got {other:?}"),
        }

        be.remove_breakpoint(id).unwrap();

        // Run to completion.
        let mut exited = false;
        for _ in 0..100_000 {
            match be.continue_exec() {
                Ok(DebuggerEvent::ProcessExited { .. }) => {
                    exited = true;
                    break;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        assert!(exited, "process should run to exit");
        assert_eq!(be.state(), TargetState::Exited);
    }

    #[test]
    fn register_write_round_trips() {
        if !Path::new("/bin/true").exists() {
            return;
        }
        let mut be = LinuxPtraceBackend::new();
        be.launch(&target("/bin/true")).unwrap();
        // Write a value into a scratch register and read it back.
        be.write_register(None, "r15", 0xdead_beef_cafe_babe).expect("write r15");
        let v = be.read_registers(None).unwrap().get("r15").unwrap();
        assert_eq!(v, 0xdead_beef_cafe_babe);
        let _ = be.kill();
        assert_eq!(be.state(), TargetState::Exited);
    }

    #[test]
    fn memory_write_round_trips() {
        if !Path::new("/bin/true").exists() {
            return;
        }
        let mut be = LinuxPtraceBackend::new();
        be.launch(&target("/bin/true")).unwrap();
        // Find a writable region: the stack pointer points into one.
        let sp = be.read_registers(None).unwrap().sp().unwrap();
        let addr = sp - 64;
        let payload = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        be.write_memory(addr, &payload).expect("write mem");
        let back = be.read_memory(addr, payload.len()).expect("read mem");
        assert_eq!(back, payload);
        let _ = be.kill();
    }
}
