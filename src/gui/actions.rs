//! Action enum sent from UI elements to the central dispatcher.

#[derive(Debug, Clone)]
pub enum Action {
    Launch,
    Restart,
    Pause,
    Resume,
    StepInto,
    StepOver,
    StepReturn,
    Detach,
    Kill,
    AttachDialog,
    AdapterSettingsDialog,
    AddBreakpointDialog,
    HardwareBreakpointDialog,
    EditConditionDialog(u64),
    OverrideIpDialog,
    JumpToIp,
    ToggleBreakpointAt(u64),
    RunToAddress(u64),
    NavigateTo(u64),
    SetActiveThread(u32),
    ConsoleCommand(String),
    OpenFile(std::path::PathBuf),
    OpenFileDialog,
    Quit,
}
