//! Control-flow Graph panel: a block-structured view of the function at the
//! current disassembly address, with clickable branch/fall-through edges.

use egui::{RichText, Ui};

use crate::analysis::cfg::{build_cfg, EdgeKind};
use crate::analysis::disasm::Disassembler;
use crate::gui::actions::Action;
use crate::gui::state::AppState;
use crate::gui::theme::color;
use crate::gui::widgets::disasm_syntax;
use crate::target::arch::Architecture;

pub fn show(ui: &mut Ui, state: &mut AppState, actions: &mut Vec<Action>) {
    let addr = state.selected_address.unwrap_or(state.disasm_address);
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("Function @ 0x{addr:x}")).strong());
        ui.label(RichText::new("(graph follows the selected/disassembly address)").color(color::MUTED).small());
    });
    ui.separator();

    let arch = state.binary.as_ref().map(|b| b.architecture).unwrap_or(Architecture::X86_64);
    let bytes = state.image_bytes(addr, 4096);
    if bytes.is_empty() {
        ui.label(RichText::new("(load a binary or stop the target to graph a function)").color(color::MUTED));
        return;
    }
    let dis = match Disassembler::new(arch) {
        Ok(d) => d,
        Err(e) => { ui.label(format!("disasm init failed: {e}")); return; }
    };
    let conv: Vec<crate::pwn::asm::DisasmInsn> =
        dis.disassemble_all(&bytes, addr).unwrap_or_default().into_iter().map(Into::into).collect();
    // Walk the function body, following forward branches past early returns.
    let func = crate::analysis::cfg::function_slice(&conv, addr, 1024);
    if func.is_empty() {
        ui.label(RichText::new("(no instructions to graph here)").color(color::MUTED));
        return;
    }
    let cfg = build_cfg(&func);
    ui.label(RichText::new(format!("{} basic block(s)", cfg.blocks.len())).color(color::MUTED).small());

    egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
        for block in &cfg.blocks {
            egui::Frame::none()
                .stroke(egui::Stroke::new(1.0, color::HEADER))
                .inner_margin(egui::Margin::same(6.0))
                .outer_margin(egui::Margin::symmetric(2.0, 4.0))
                .rounding(4.0)
                .show(ui, |ui| {
                    // Block header (clickable -> navigate).
                    if ui.add(egui::Label::new(
                        RichText::new(format!("loc_{:x}:", block.start)).color(color::ADDRESS).strong(),
                    ).sense(egui::Sense::click())).clicked() {
                        actions.push(Action::NavigateTo(block.start));
                    }
                    // Instructions.
                    for ins in &block.insns {
                        ui.horizontal(|ui| {
                            ui.monospace(RichText::new(format!("{:x}", ins.address)).color(color::MUTED));
                            ui.monospace(
                                RichText::new(format!("{:<7}", ins.mnemonic))
                                    .color(disasm_syntax::mnemonic_color(&ins.mnemonic)).strong(),
                            );
                            if !ins.operands.is_empty() {
                                ui.label(disasm_syntax::operand_job(&ins.operands, 12.5));
                            }
                        });
                    }
                    // Outgoing edges.
                    if block.succ.is_empty() {
                        ui.label(RichText::new("\u{2193} exit").color(color::MUTED).small());
                    } else {
                        ui.horizontal(|ui| {
                            for (t, kind) in &block.succ {
                                let (label, c) = match kind {
                                    EdgeKind::Branch => (format!("\u{2192} branch loc_{t:x}"), color::ACCENT),
                                    EdgeKind::Fallthrough => (format!("\u{2193} loc_{t:x}"), color::MUTED),
                                };
                                if ui.add(egui::Label::new(RichText::new(label).color(c).small())
                                    .sense(egui::Sense::click())).clicked()
                                {
                                    actions.push(Action::NavigateTo(*t));
                                }
                            }
                        });
                    }
                });
        }
    });
}
