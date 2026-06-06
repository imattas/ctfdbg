//! Dockable panel layout backed by `egui_dock`.

use egui_dock::{DockState, NodeIndex, Style};

use crate::gui::actions::Action;
use crate::gui::state::AppState;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PanelKind {
    Disassembly,
    DebuggerInfo,
    Registers,
    Breakpoints,
    Memory,
    Stack,
    TargetConsole,
    DebuggerConsole,
    StackTrace,
    Modules,
    Logs,
    Functions,
    Strings,
    Plugins,
    Graph,
}

impl PanelKind {
    pub const ALL: &'static [PanelKind] = &[
        PanelKind::Disassembly,
        PanelKind::DebuggerInfo,
        PanelKind::Registers,
        PanelKind::Breakpoints,
        PanelKind::Memory,
        PanelKind::Stack,
        PanelKind::TargetConsole,
        PanelKind::DebuggerConsole,
        PanelKind::StackTrace,
        PanelKind::Modules,
        PanelKind::Logs,
        PanelKind::Functions,
        PanelKind::Strings,
        PanelKind::Plugins,
        PanelKind::Graph,
    ];

    pub fn title(self) -> &'static str {
        match self {
            PanelKind::Disassembly      => "Disassembly",
            PanelKind::DebuggerInfo     => "Debugger Info",
            PanelKind::Registers        => "Registers",
            PanelKind::Breakpoints      => "Breakpoints",
            PanelKind::Memory           => "Memory",
            PanelKind::Stack            => "Stack",
            PanelKind::TargetConsole    => "Target Console",
            PanelKind::DebuggerConsole  => "Debugger Console",
            PanelKind::StackTrace       => "Stack Trace",
            PanelKind::Modules          => "Modules",
            PanelKind::Logs             => "Logs",
            PanelKind::Functions        => "Functions",
            PanelKind::Strings          => "Strings",
            PanelKind::Plugins          => "Plugins",
            PanelKind::Graph            => "Graph",
        }
    }
}

/// Build the default dock layout.
pub fn default_layout() -> DockState<PanelKind> {
    let mut state = DockState::new(vec![PanelKind::Disassembly, PanelKind::DebuggerInfo]);
    {
        let surface = state.main_surface_mut();
        let _ = surface.split_left(
            NodeIndex::root(),
            0.22,
            vec![PanelKind::Registers, PanelKind::Breakpoints],
        );
    }
    {
        let surface = state.main_surface_mut();
        let _ = surface.split_right(
            NodeIndex::root(),
            0.72,
            vec![PanelKind::Memory, PanelKind::Stack],
        );
    }
    {
        let surface = state.main_surface_mut();
        let _ = surface.split_below(
            NodeIndex::root(),
            0.7,
            vec![
                PanelKind::DebuggerConsole,
                PanelKind::TargetConsole,
                PanelKind::Functions,
                PanelKind::Strings,
                PanelKind::Plugins,
                PanelKind::StackTrace,
                PanelKind::Modules,
                PanelKind::Logs,
            ],
        );
    }
    state
}

/// Tab viewer that dispatches to existing per-panel `show()` functions.
pub struct PanelTabs<'a> {
    pub state: &'a mut AppState,
    pub actions: &'a mut Vec<Action>,
}

impl<'a> egui_dock::TabViewer for PanelTabs<'a> {
    type Tab = PanelKind;

    fn title(&mut self, tab: &mut Self::Tab) -> egui::WidgetText {
        (*tab).title().into()
    }

    fn id(&mut self, tab: &mut Self::Tab) -> egui::Id {
        egui::Id::new(("panel", *tab as u8))
    }

    fn ui(&mut self, ui: &mut egui::Ui, tab: &mut Self::Tab) {
        match *tab {
            PanelKind::Disassembly      => crate::gui::panels::disassembly::show(ui, self.state, self.actions),
            PanelKind::DebuggerInfo     => crate::gui::panels::debugger_info::show(ui, self.state),
            PanelKind::Registers        => crate::gui::panels::registers::show(ui, self.state, self.actions),
            PanelKind::Breakpoints      => crate::gui::panels::breakpoints::show(ui, self.state, self.actions),
            PanelKind::Memory           => crate::gui::panels::memory::show(ui, self.state, self.actions),
            PanelKind::Stack            => crate::gui::panels::stack::show(ui, self.state, self.actions),
            PanelKind::TargetConsole    => crate::gui::panels::target_console::show(ui, self.state),
            PanelKind::DebuggerConsole  => crate::gui::panels::debugger_console::show_console(ui, self.state, self.actions),
            PanelKind::StackTrace       => crate::gui::panels::stack_trace::show(ui, self.state, self.actions),
            PanelKind::Modules          => crate::gui::panels::modules::show(ui, self.state, self.actions),
            PanelKind::Logs             => crate::gui::panels::logs::show(ui, self.state),
            PanelKind::Functions        => crate::gui::panels::functions::show(ui, self.state, self.actions),
            PanelKind::Strings          => crate::gui::panels::strings::show(ui, self.state, self.actions),
            PanelKind::Plugins          => crate::gui::panels::plugins::show(ui, self.state, self.actions),
            PanelKind::Graph            => crate::gui::panels::graph::show(ui, self.state, self.actions),
        }
    }
}

/// Add the given panel kind back into the dock state if it is currently closed.
pub fn ensure_panel_visible(dock: &mut DockState<PanelKind>, kind: PanelKind) {
    if dock.iter_all_tabs().any(|(_, t)| *t == kind) {
        return;
    }
    dock.push_to_focused_leaf(kind);
}

pub fn dock_style(ctx: &egui::Context) -> Style {
    let mut s = Style::from_egui(&ctx.style());
    s.tab_bar.height = 24.0;
    s
}
