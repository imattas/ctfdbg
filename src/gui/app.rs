//! Main eframe::App. Owns AppState and lays out panels.

use crate::config::DebugConfig;
use crate::debugger::events::DebuggerEvent;
use crate::debugger::state::TargetState;
use crate::gui::actions::Action;
use crate::gui::state::{spawn_worker, AppState, BackendUpdate, DebugCommand};

pub struct App {
    pub state: AppState,
    pub pending_actions: Vec<Action>,
}

impl App {
    pub fn new(cfg: DebugConfig) -> Self {
        let (cmd_tx, upd_rx) = spawn_worker(&cfg);
        let mut state = AppState::new(cfg, cmd_tx, upd_rx);
        if let Some(path) = state.cfg.target.clone() {
            state.try_load_binary(path);
        }
        Self { state, pending_actions: vec![] }
    }

    fn drain_backend_updates(&mut self) {
        while let Ok(u) = self.state.update_rx.try_recv() {
            self.apply_update(u);
        }
    }

    fn apply_update(&mut self, u: BackendUpdate) {
        match u {
            BackendUpdate::State(s) => {
                self.state.state = s;
                self.state.status_message = s.label().to_string();
            }
            BackendUpdate::Pid(p) => self.state.pid = p,
            BackendUpdate::Event(ev) => {
                self.state.last_event_label = ev.short_label();
                self.state.console_output.push(format!("[event] {}", ev.short_label()));
                match &ev {
                    DebuggerEvent::Stopped { thread_id, address, .. }
                    | DebuggerEvent::BreakpointHit { thread_id, address, .. }
                    | DebuggerEvent::SingleStep { thread_id, address }
                    | DebuggerEvent::Exception { thread_id, address, .. } => {
                        self.state.active_thread = Some(*thread_id);
                        if self.state.disasm_following_pc {
                            self.state.disasm_address = *address;
                        }
                        self.state.selected_address = Some(*address);
                    }
                    DebuggerEvent::ProcessExited { .. } => {
                        self.state.state = TargetState::Exited;
                    }
                    _ => {}
                }
            }
            BackendUpdate::Registers(rf) => {
                let prev: std::collections::HashMap<String, u64> = self.state.registers.values.clone().into_iter().collect();
                self.state.previous_registers = prev;
                self.state.registers = rf;
                if let Some(sp) = self.state.registers.sp() { self.state.stack_base = sp; }
            }
            BackendUpdate::Threads(t) => {
                if self.state.active_thread.is_none() {
                    self.state.active_thread = t.first().map(|x| x.thread_id);
                }
                self.state.threads = t;
            }
            BackendUpdate::Modules(m) => self.state.modules = m,
            BackendUpdate::Breakpoints(b) => self.state.breakpoints = b,
            BackendUpdate::StackTrace(s) => self.state.stack_trace = s,
            BackendUpdate::MemoryAt(addr, data) => {
                self.state.memory_view_address = addr;
                self.state.memory_bytes = data;
            }
            BackendUpdate::Log(l) => self.state.logs.push(crate::gui::state::LogLine {
                level: tracing::Level::INFO, text: l,
            }),
            BackendUpdate::Error(e) => {
                self.state.last_error = Some(e.clone());
                self.state.console_output.push(format!("[!] {e}"));
            }
        }
    }

    fn dispatch_pending(&mut self) {
        let actions = std::mem::take(&mut self.pending_actions);
        for a in actions { self.dispatch(a); }
    }

    fn dispatch(&mut self, action: Action) {
        match action {
            Action::Launch => {
                let target = self.state.adapter_target.clone();
                if target.executable.is_none() {
                    self.state.last_error = Some("No executable set. Open a file or fill in Adapter Settings.".into());
                } else {
                    self.state.send(DebugCommand::Launch(target));
                }
            }
            Action::Restart => {
                self.state.send(DebugCommand::Kill);
                let target = self.state.adapter_target.clone();
                self.state.send(DebugCommand::Launch(target));
            }
            Action::Pause => self.state.send(DebugCommand::Pause),
            Action::Resume => self.state.send(DebugCommand::Continue),
            Action::StepInto => self.state.send(DebugCommand::StepInto),
            Action::StepOver => self.state.send(DebugCommand::StepOver),
            Action::StepReturn => self.state.send(DebugCommand::StepReturn),
            Action::Detach => self.state.send(DebugCommand::Detach),
            Action::Kill => self.state.send(DebugCommand::Kill),
            Action::AttachDialog => { self.state.show_attach_dialog = true; refresh_processes(&mut self.state); }
            Action::AdapterSettingsDialog => self.state.show_adapter_settings = true,
            Action::AddBreakpointDialog => self.state.show_add_breakpoint = true,
            Action::HardwareBreakpointDialog => self.state.show_hw_breakpoint = true,
            Action::EditConditionDialog(id) => self.state.show_edit_condition_for = Some(id),
            Action::OverrideIpDialog => self.state.show_override_ip = true,
            Action::JumpToIp => {
                if let Some(ip) = self.state.registers.pc() {
                    self.state.disasm_address = ip;
                    self.state.selected_address = Some(ip);
                }
            }
            Action::ToggleBreakpointAt(addr) => {
                if let Some(bp) = self.state.breakpoints.iter().find(|b| b.address == addr) {
                    self.state.send(DebugCommand::RemoveBreakpoint(bp.id.0));
                } else {
                    self.state.send(DebugCommand::SetBreakpoint(addr));
                }
            }
            Action::SetHardwareBreakpoint { address, kind, size } => {
                self.state.send(DebugCommand::SetHardwareBreakpoint(address, kind, size));
            }
            Action::RunToAddress(a) => self.state.send(DebugCommand::RunToAddress(a)),
            Action::NavigateTo(a) => {
                self.state.disasm_address = a;
                self.state.selected_address = Some(a);
            }
            Action::SetActiveThread(tid) => self.state.active_thread = Some(tid),
            Action::ConsoleCommand(line) => crate::gui::panels::debugger_console::execute(&mut self.state, &line),
            Action::RunPlugin(id) => {
                // Take the registry out so the plugin can borrow &AppState while
                // we then mutate the console; restore it afterwards.
                let registry = std::mem::take(&mut self.state.plugins);
                match registry.get(&id) {
                    Some(p) => {
                        let out = p.run(&self.state, None);
                        for line in out.lines {
                            self.state.console_output.push(format!("[{id}] {line}"));
                        }
                        self.pending_actions.extend(out.actions);
                    }
                    None => self.state.console_output.push(format!("[!] unknown plugin: {id}")),
                }
                self.state.plugins = registry;
            }
            Action::OpenFileDialog => {
                if let Some(p) = rfd::FileDialog::new()
                    .add_filter("Binaries", &["exe", "dll", "sys", "elf", "so", "bin"])
                    .add_filter("All files", &["*"])
                    .pick_file()
                {
                    self.state.try_load_binary(p);
                } else {
                    // User cancelled — fall back to letting them type the path.
                    self.state.show_adapter_settings = true;
                }
            }
            Action::OpenFile(p) => self.state.try_load_binary(p),
            Action::Quit => std::process::exit(0),
        }
    }
}

fn refresh_processes(state: &mut AppState) {
    state.processes_cache.clear();
    #[cfg(windows)]
    {
        if let Ok(list) = crate::debugger::windows::process::list_system_processes() {
            for p in list { state.processes_cache.push((p.pid, p.name)); }
            return;
        }
    }
    // Cross-platform fallback via sysinfo.
    let mut sys = sysinfo::System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    for (pid, p) in sys.processes() {
        state.processes_cache.push((pid.as_u32(), p.name().to_string_lossy().into_owned()));
    }
    state.processes_cache.sort_by_key(|p| p.0);
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(std::time::Duration::from_millis(150));
        self.drain_backend_updates();

        // Top menu bar
        crate::gui::widgets::toolbar::menu_bar(ctx, &mut self.state, &mut self.pending_actions);
        // Top toolbar
        crate::gui::widgets::toolbar::top_toolbar(ctx, &mut self.state, &mut self.pending_actions);

        // Status bar (bottom)
        crate::gui::widgets::status_bar::show(ctx, &self.state);

        // Left vertical activity bar
        crate::gui::widgets::sidebar::activity_bar(ctx, &mut self.state, &mut self.pending_actions);

        // Optional debugger sidebar (control buttons + register/breakpoint quick widgets).
        if self.state.debugger_sidebar_open {
            egui::SidePanel::left("debugger_sidebar")
                .resizable(true)
                .min_width(260.0)
                .default_width(310.0)
                .show(ctx, |ui| {
                    crate::gui::widgets::sidebar::debugger_sidebar(ui, &mut self.state, &mut self.pending_actions);
                });
        }

        // Central area: a dockable workspace. All other panels (disassembly,
        // memory, stack, console, etc.) live here as draggable tabs that can
        // be split, rearranged, or closed and re-opened from the View menu.
        egui::CentralPanel::default()
            .frame(egui::Frame::central_panel(&ctx.style()).inner_margin(0.0))
            .show(ctx, |ui| {
                let style = crate::gui::docking::dock_style(ctx);
                let mut dock = std::mem::replace(
                    &mut self.state.dock,
                    egui_dock::DockState::new(vec![]),
                );
                {
                    let mut viewer = crate::gui::docking::PanelTabs {
                        state: &mut self.state,
                        actions: &mut self.pending_actions,
                    };
                    egui_dock::DockArea::new(&mut dock)
                        .style(style)
                        .show_close_buttons(true)
                        .show_add_buttons(false)
                        .draggable_tabs(true)
                        .tab_context_menus(true)
                        .show_inside(ui, &mut viewer);
                }
                self.state.dock = dock;
            });

        // Dialogs
        crate::gui::dialogs::attach_process::show(ctx, &mut self.state, &mut self.pending_actions);
        crate::gui::dialogs::adapter_settings::show(ctx, &mut self.state, &mut self.pending_actions);
        crate::gui::dialogs::add_breakpoint::show(ctx, &mut self.state, &mut self.pending_actions);
        crate::gui::dialogs::hardware_breakpoint::show(ctx, &mut self.state, &mut self.pending_actions);
        crate::gui::dialogs::override_ip::show(ctx, &mut self.state, &mut self.pending_actions);
        crate::gui::dialogs::edit_condition::show(ctx, &mut self.state, &mut self.pending_actions);

        self.dispatch_pending();
    }
}
