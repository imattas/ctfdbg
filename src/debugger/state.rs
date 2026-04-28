//! Debugger high-level state.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TargetState {
    #[default]
    NotStarted,
    Running,
    Stopped,
    Exited,
    Error,
}

impl TargetState {
    pub fn label(self) -> &'static str {
        match self {
            Self::NotStarted => "Not started",
            Self::Running => "Running",
            Self::Stopped => "Stopped",
            Self::Exited => "Exited",
            Self::Error => "Error",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct StopInfo {
    pub reason: String,
    pub address: u64,
    pub thread_id: u32,
    pub exit_code: Option<i32>,
}
