//! Shared types + helpers for the laptop ↔ bot FROST signing protocol.
//!
//! Both the bot service (`frost-bot`) and the laptop simulator
//! (`frost-laptop-sim`) depend on this; once we wire into the main TUI we
//! re-export the protocol and share types from here.

pub mod config;
pub mod protocol;
pub mod share;
