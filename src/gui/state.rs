//! Shared GUI state. Owns the debugger backend on a worker thread plus
//! all GUI-visible model data.

use crate::config::DebugConfig;
use crate::debugger::backend::{DebugBackend, DebugTarget};
use crate::debugger::breakpoint::BreakpointInfo;
use crate::debugger::events::DebuggerEvent;
use crate::debugger::modules::DebugModule;
use crate::debugger::registers::RegisterFile;
use crate::debugger::stacktrace::StackFrame;
use crate::debugger::state::TargetState;
use crate::debugger::threads::DebugThread;
use crate::error::DbgResult;
use crate::analysis::auto::AutoAnalysis;
use crate::gui::docking::{default_layout, PanelKind};
use crate::plugins::PluginRegistry;
use crate::target::binary::BinaryInfo;

use crossbeam_channel::{unbounded, Receiver, Sender};
use egui_dock::DockState;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

/// Commands sent UI -> backend worker.
#[derive(Debug, Clone)]
pub enum DebugCommand {
    Launch(DebugTarget),
    Attach(u32),
    Detach,
    Kill,
    Continue,
    Pause,
    StepInto,
    StepOver,
    StepReturn,
    RunToAddress(u64),
    SetBreakpoint(u64),
    SetHardwareBreakpoint(u64, crate::debugger::breakpoint::BreakpointKind, u8),
    RemoveBreakpoint(u64),
    EnableBreakpoint(u64, bool),
    SetCondition(u64, Option<String>),
    WriteMemory(u64, Vec<u8>),
    ReadMemory(u64, usize),
    /// Send bytes to the target's standard input.
    SendStdin(Vec<u8>),
    WriteRegister(String, u64),
    SetIp(u64),
    /// Refresh registers/threads/modules without changing run state.
    Refresh,
}

/// Information sent backend -> UI.
#[derive(Debug, Clone)]
pub enum BackendUpdate {
    State(TargetState),
    Pid(Option<u32>),
    Event(DebuggerEvent),
    Registers(RegisterFile),
    Threads(Vec<DebugThread>),
    Modules(Vec<DebugModule>),
    Breakpoints(Vec<BreakpointInfo>),
    StackTrace(Vec<StackFrame>),
    MemoryAt(u64, Vec<u8>),
    /// Bytes captured from the target's stdout/stderr.
    TargetOutput(Vec<u8>),
    Log(String),
    Error(String),
}

pub struct LogLine {
    pub level: tracing::Level,
    pub text: String,
}

pub struct AppState {
    pub cfg: DebugConfig,
    pub binary: Option<BinaryInfo>,
    pub binary_bytes: Option<Vec<u8>>,
    pub auto_analysis: Option<AutoAnalysis>,
    pub plugins: PluginRegistry,
    pub state: TargetState,
    pub pid: Option<u32>,
    pub registers: RegisterFile,
    pub previous_registers: HashMap<String, u64>,
    pub edited_registers: HashMap<String, u64>,
    pub threads: Vec<DebugThread>,
    pub active_thread: Option<u32>,
    pub modules: Vec<DebugModule>,
    pub breakpoints: Vec<BreakpointInfo>,
    pub stack_trace: Vec<StackFrame>,
    pub memory_view_address: u64,
    pub memory_bytes: Vec<u8>,
    pub stack_bytes: Vec<u8>,
    pub stack_base: u64,
    pub disasm_address: u64,
    pub selected_address: Option<u64>,
    pub console_input: String,
    pub console_history: Vec<String>,
    pub console_output: Vec<String>,
    pub target_console: Vec<String>,
    /// True when the last target-output chunk didn't end in a newline, so the
    /// next chunk continues the same console line.
    pub target_console_open_line: bool,
    /// Pending text typed into the Target Console stdin box.
    pub target_stdin_input: String,
    /// `KEY=VALUE` lines edited in the adapter-settings Environment box.
    pub adapter_env_text: String,
    pub logs: Vec<LogLine>,
    pub status_message: String,
    pub last_event_label: String,
    pub last_error: Option<String>,
    pub show_attach_dialog: bool,
    pub show_adapter_settings: bool,
    pub show_add_breakpoint: bool,
    pub show_hw_breakpoint: bool,
    pub show_override_ip: bool,
    pub show_edit_condition_for: Option<u64>,
    pub debugger_sidebar_open: bool,
    pub hide_zero_registers: bool,
    pub register_search: String,
    pub modules_search: String,
    pub processes_search: String,
    pub processes_cache: Vec<(u32, String)>,
    pub selected_pid: Option<u32>,
    pub mem_search: String,
    pub mem_patch_addr: String,
    pub mem_patch_bytes: String,
    pub adapter_target: DebugTarget,
    pub graph_mode: bool,
    pub disasm_following_pc: bool,

    /// Dockable panel layout. Tabs can be dragged between regions, split,
    /// or closed; the View / Window menu re-opens any closed panel.
    pub dock: DockState<PanelKind>,

    pub command_tx: Sender<DebugCommand>,
    pub update_rx: Receiver<BackendUpdate>,
}

impl AppState {
    pub fn new(cfg: DebugConfig, command_tx: Sender<DebugCommand>, update_rx: Receiver<BackendUpdate>) -> Self {
        let target = DebugTarget {
            executable: cfg.target.clone(),
            arguments: cfg.args.clone().unwrap_or_default(),
            working_directory: cfg.working_directory.clone(),
            environment: vec![],
            launch_in_external_terminal: false,
            break_on_entry: cfg.break_entry,
            break_on_tls_callbacks: false,
        };
        Self {
            cfg,
            binary: None,
            binary_bytes: None,
            auto_analysis: None,
            plugins: crate::plugins::default_plugins(),
            state: TargetState::NotStarted,
            pid: None,
            registers: RegisterFile::default(),
            previous_registers: HashMap::new(),
            edited_registers: HashMap::new(),
            threads: vec![],
            active_thread: None,
            modules: vec![],
            breakpoints: vec![],
            stack_trace: vec![],
            memory_view_address: 0,
            memory_bytes: vec![],
            stack_bytes: vec![],
            stack_base: 0,
            disasm_address: 0,
            selected_address: None,
            console_input: String::new(),
            console_history: vec![],
            console_output: vec!["ctfdbg console. Type 'help' or use the toolbar.".into()],
            target_console: vec![],
            target_console_open_line: false,
            target_stdin_input: String::new(),
            adapter_env_text: String::new(),
            logs: vec![],
            status_message: "Ready".into(),
            last_event_label: String::new(),
            last_error: None,
            show_attach_dialog: false,
            show_adapter_settings: false,
            show_add_breakpoint: false,
            show_hw_breakpoint: false,
            show_override_ip: false,
            show_edit_condition_for: None,
            debugger_sidebar_open: true,
            hide_zero_registers: true,
            register_search: String::new(),
            modules_search: String::new(),
            processes_search: String::new(),
            processes_cache: vec![],
            selected_pid: None,
            mem_search: String::new(),
            mem_patch_addr: String::new(),
            mem_patch_bytes: String::new(),
            adapter_target: target,
            graph_mode: false,
            disasm_following_pc: true,
            dock: default_layout(),
            command_tx,
            update_rx,
        }
    }

    pub fn try_load_binary(&mut self, path: PathBuf) {
        match crate::target::parser::parse_file(
            &path,
            self.cfg.format,
            self.cfg.arch,
            self.cfg.base_address,
        ) {
            Ok(info) => {
                let bytes = std::fs::read(&path).unwrap_or_default();
                self.disasm_address = info.entry_point;
                self.adapter_target.executable = Some(path.clone());
                self.cfg.target = Some(path);
                self.console_output.push("[+] Binary loaded".into());
                // Auto-analysis runs immediately on load.
                let analysis = crate::analysis::auto::analyze(&info, &bytes);
                self.console_output.push(format!(
                    "[auto] {} func, {} strings, {} hint(s)",
                    analysis.functions.len(), analysis.strings.len(), analysis.hints.len()
                ));
                for h in &analysis.hints {
                    self.console_output.push(format!("[auto] {h}"));
                }
                self.binary = Some(info);
                self.binary_bytes = Some(bytes);
                self.auto_analysis = Some(analysis);
            }
            Err(e) => {
                self.last_error = Some(e.to_string());
                self.console_output.push(format!("[!] failed to load binary: {e}"));
            }
        }
    }

    /// Re-run auto-analysis using the currently loaded binary + bytes.
    pub fn rerun_auto_analysis(&mut self) {
        if let (Some(info), Some(bytes)) = (self.binary.as_ref(), self.binary_bytes.as_ref()) {
            let a = crate::analysis::auto::analyze(info, bytes);
            self.console_output.push(format!(
                "[auto] re-analyzed: {} func, {} strings",
                a.functions.len(), a.strings.len()
            ));
            self.auto_analysis = Some(a);
        } else {
            self.console_output.push("[!] no binary loaded".into());
        }
    }

    pub fn send(&self, cmd: DebugCommand) {
        if let Err(e) = self.command_tx.send(cmd) {
            tracing::error!("failed to send command: {e}");
        }
    }
}

pub fn spawn_worker(cfg: &DebugConfig) -> (Sender<DebugCommand>, Receiver<BackendUpdate>) {
    let (cmd_tx, cmd_rx) = unbounded::<DebugCommand>();
    let (upd_tx, upd_rx) = unbounded::<BackendUpdate>();
    let cfg2 = cfg.clone();
    std::thread::Builder::new()
        .name("debugger-worker".into())
        .spawn(move || worker_main(cfg2, cmd_rx, upd_tx))
        .expect("failed to spawn debugger worker");
    (cmd_tx, upd_rx)
}

fn worker_main(cfg: DebugConfig, cmd_rx: Receiver<DebugCommand>, upd_tx: Sender<BackendUpdate>) {
    let mut backend: Box<dyn DebugBackend + Send> = match crate::debugger::make_backend(&cfg) {
        Ok(b) => b,
        Err(e) => {
            let _ = upd_tx.send(BackendUpdate::Error(e.to_string()));
            return;
        }
    };
    let _ = upd_tx.send(BackendUpdate::Log(format!("backend: {}", backend.name())));

    // Stream the target's stdout/stderr into the Target Console.
    {
        let sink_tx = upd_tx.clone();
        backend.set_output_sink(Arc::new(move |bytes| {
            let _ = sink_tx.send(BackendUpdate::TargetOutput(bytes));
        }));
    }

    let send_state = |b: &dyn DebugBackend, tx: &Sender<BackendUpdate>| {
        let _ = tx.send(BackendUpdate::State(b.state()));
        let _ = tx.send(BackendUpdate::Pid(b.pid()));
    };
    let publish_after_stop = |b: &mut Box<dyn DebugBackend + Send>, tx: &Sender<BackendUpdate>| {
        send_state(b.as_ref(), tx);
        if let Ok(rf) = b.read_registers(None) { let _ = tx.send(BackendUpdate::Registers(rf)); }
        if let Ok(t) = b.list_threads() { let _ = tx.send(BackendUpdate::Threads(t)); }
        if let Ok(m) = b.list_modules() { let _ = tx.send(BackendUpdate::Modules(m)); }
        if let Ok(st) = b.stack_trace(0) { let _ = tx.send(BackendUpdate::StackTrace(st)); }
        let _ = tx.send(BackendUpdate::Breakpoints(b.list_breakpoints()));
    };

    while let Ok(cmd) = cmd_rx.recv() {
        let res: DbgResult<()> = (|| -> DbgResult<()> {
            match cmd {
                DebugCommand::Launch(target) => {
                    backend.launch(&target)?;
                    publish_after_stop(&mut backend, &upd_tx);
                    let _ = upd_tx.send(BackendUpdate::Event(DebuggerEvent::Launched {
                        pid: backend.pid().unwrap_or(0),
                    }));
                }
                DebugCommand::Attach(pid) => {
                    backend.attach(pid)?;
                    publish_after_stop(&mut backend, &upd_tx);
                    let _ = upd_tx.send(BackendUpdate::Event(DebuggerEvent::Attached { pid }));
                }
                DebugCommand::Detach => { backend.detach()?; send_state(backend.as_ref(), &upd_tx); }
                DebugCommand::Kill => { backend.kill()?; send_state(backend.as_ref(), &upd_tx); }
                DebugCommand::Continue => {
                    // Honour conditional breakpoints: if we stop at a breakpoint
                    // whose condition evaluates to false, resume automatically.
                    let mut ev = backend.continue_exec()?;
                    while let DebuggerEvent::BreakpointHit { id, .. } = ev {
                        if breakpoint_condition_met(backend.as_ref(), id) {
                            break;
                        }
                        ev = backend.continue_exec()?;
                    }
                    let _ = upd_tx.send(BackendUpdate::Event(ev));
                    publish_after_stop(&mut backend, &upd_tx);
                }
                DebugCommand::Pause => {
                    let ev = backend.pause()?;
                    let _ = upd_tx.send(BackendUpdate::Event(ev));
                    publish_after_stop(&mut backend, &upd_tx);
                }
                DebugCommand::StepInto => {
                    let ev = backend.single_step()?;
                    let _ = upd_tx.send(BackendUpdate::Event(ev));
                    publish_after_stop(&mut backend, &upd_tx);
                }
                DebugCommand::StepOver => {
                    let ev = backend.step_over()?;
                    let _ = upd_tx.send(BackendUpdate::Event(ev));
                    publish_after_stop(&mut backend, &upd_tx);
                }
                DebugCommand::StepReturn => {
                    let ev = backend.step_return()?;
                    let _ = upd_tx.send(BackendUpdate::Event(ev));
                    publish_after_stop(&mut backend, &upd_tx);
                }
                DebugCommand::RunToAddress(a) => {
                    let ev = backend.run_to_address(a)?;
                    let _ = upd_tx.send(BackendUpdate::Event(ev));
                    publish_after_stop(&mut backend, &upd_tx);
                }
                DebugCommand::SetBreakpoint(a) => { backend.set_breakpoint(a)?; let _ = upd_tx.send(BackendUpdate::Breakpoints(backend.list_breakpoints())); }
                DebugCommand::SetHardwareBreakpoint(a, kind, size) => { backend.set_hardware_breakpoint(a, kind, size)?; let _ = upd_tx.send(BackendUpdate::Breakpoints(backend.list_breakpoints())); }
                DebugCommand::RemoveBreakpoint(id) => { backend.remove_breakpoint(crate::debugger::breakpoint::BreakpointId(id))?; let _ = upd_tx.send(BackendUpdate::Breakpoints(backend.list_breakpoints())); }
                DebugCommand::EnableBreakpoint(id, e) => { backend.enable_breakpoint(crate::debugger::breakpoint::BreakpointId(id), e)?; let _ = upd_tx.send(BackendUpdate::Breakpoints(backend.list_breakpoints())); }
                DebugCommand::SetCondition(id, c) => { backend.set_breakpoint_condition(crate::debugger::breakpoint::BreakpointId(id), c)?; let _ = upd_tx.send(BackendUpdate::Breakpoints(backend.list_breakpoints())); }
                DebugCommand::WriteMemory(a, d) => { backend.write_memory(a, &d)?; }
                DebugCommand::ReadMemory(a, n) => {
                    let data = backend.read_memory(a, n)?;
                    let _ = upd_tx.send(BackendUpdate::MemoryAt(a, data));
                }
                DebugCommand::SendStdin(data) => { backend.write_stdin(&data)?; }
                DebugCommand::WriteRegister(name, val) => { backend.write_register(None, &name, val)?; if let Ok(rf) = backend.read_registers(None) { let _ = upd_tx.send(BackendUpdate::Registers(rf)); } }
                DebugCommand::SetIp(a) => { backend.set_instruction_pointer(None, a)?; if let Ok(rf) = backend.read_registers(None) { let _ = upd_tx.send(BackendUpdate::Registers(rf)); } }
                DebugCommand::Refresh => publish_after_stop(&mut backend, &upd_tx),
            }
            Ok(())
        })();
        if let Err(e) = res {
            let _ = upd_tx.send(BackendUpdate::Error(e.to_string()));
        }
    }
}

/// Adapter so breakpoint-condition expressions can dereference target memory.
struct BackendMemory<'a>(&'a (dyn DebugBackend + Send));
impl crate::debugger::expressions::MemoryReader for BackendMemory<'_> {
    fn read(&self, address: u64, size: usize) -> DbgResult<Vec<u8>> {
        self.0.read_memory(address, size)
    }
}

/// Evaluate a breakpoint's condition (if any) against the current state.
/// Returns `true` (stop) when there is no condition, the condition can't be
/// evaluated, or it evaluates to a non-zero value.
fn breakpoint_condition_met(backend: &(dyn DebugBackend + Send), id: u64) -> bool {
    let bps = backend.list_breakpoints();
    let Some(bp) = bps.iter().find(|b| b.id.0 == id) else { return true };
    let Some(cond) = bp.condition.as_ref().filter(|c| !c.trim().is_empty()) else { return true };
    let Ok(expr) = crate::debugger::expressions::parse(cond) else { return true };
    let Ok(regs) = backend.read_registers(None) else { return true };
    let ptr = regs.architecture.pointer_size();
    match crate::debugger::expressions::evaluate(&expr, &regs, &BackendMemory(backend), ptr) {
        Ok(v) => v != 0,
        Err(_) => true,
    }
}

// Bring shared mutex helper into scope so panels can share editable buffers.
pub type Shared<T> = Arc<Mutex<T>>;
