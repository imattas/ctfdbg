//! Frame-pointer stack unwinding shared by the debugger backends.
//!
//! This performs a conventional frame-pointer walk: each frame stores the
//! caller's saved frame pointer at `[fp]` and the return address at
//! `[fp + ptr_size]`. It is exact for frame-pointer-preserving code (the
//! common case for unoptimised / `-fno-omit-frame-pointer` builds) and stops
//! cleanly when the chain becomes implausible. Full CFI/PDATA-based unwinding
//! of frame-pointer-omitting code is a separate, larger effort.

/// One recovered call frame: its program counter and frame pointer.
#[derive(Debug, Clone, Copy)]
pub struct UnwoundFrame {
    pub pc: u64,
    pub fp: u64,
}

/// Walk the frame-pointer chain starting from `(pc, fp)`.
///
/// `read_ptr` reads a pointer-sized little-endian value from target memory,
/// returning `None` if the address is unreadable. `ptr_size` is 4 or 8.
/// Returns up to `max_frames` frames including the initial one.
pub fn frame_pointer_unwind(
    pc: u64,
    fp: u64,
    ptr_size: usize,
    max_frames: usize,
    mut read_ptr: impl FnMut(u64) -> Option<u64>,
) -> Vec<UnwoundFrame> {
    let mut frames = vec![UnwoundFrame { pc, fp }];
    let ptr = ptr_size as u64;
    let mut cur_fp = fp;
    while frames.len() < max_frames {
        if cur_fp == 0 || !cur_fp.is_multiple_of(ptr) {
            break;
        }
        let Some(saved_fp) = read_ptr(cur_fp) else { break };
        let Some(ret) = read_ptr(cur_fp + ptr) else { break };
        // Stop on a null/zero return, or a frame pointer that does not advance
        // up the stack (which would loop or run backwards).
        if ret == 0 || saved_fp <= cur_fp {
            break;
        }
        frames.push(UnwoundFrame { pc: ret, fp: saved_fp });
        cur_fp = saved_fp;
    }
    frames
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn walks_a_synthetic_chain() {
        // Build three stacked frames at increasing fp values.
        // frame0 fp=0x1000 -> saved fp 0x1100, ret 0xA
        // frame1 fp=0x1100 -> saved fp 0x1200, ret 0xB
        // frame2 fp=0x1200 -> saved fp 0 (stop)
        let mut mem: HashMap<u64, u64> = HashMap::new();
        mem.insert(0x1000, 0x1100);
        mem.insert(0x1008, 0xA);
        mem.insert(0x1100, 0x1200);
        mem.insert(0x1108, 0xB);
        mem.insert(0x1200, 0x0);
        mem.insert(0x1208, 0xC);
        let frames = frame_pointer_unwind(0x4000, 0x1000, 8, 16, |a| mem.get(&a).copied());
        let pcs: Vec<u64> = frames.iter().map(|f| f.pc).collect();
        assert_eq!(pcs, vec![0x4000, 0xA, 0xB]);
    }

    #[test]
    fn stops_on_unreadable() {
        let frames = frame_pointer_unwind(0x4000, 0x1000, 8, 16, |_| None);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].pc, 0x4000);
    }
}
