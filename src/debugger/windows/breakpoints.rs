//! Windows breakpoint handling.
//!
//! The breakpoint engine (saved original bytes, `int3` patching, single-step
//! re-insert, and trap-flag handling) is implemented inline in
//! [`super::backend`] so it can share mutable state with the debug-event loop.
//! This module is kept as the documented home for that responsibility in the
//! project layout; there is no separate state to expose here.
