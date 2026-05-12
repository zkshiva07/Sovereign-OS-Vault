//! Centralized colors + styles. All UI imports from here so theming is single-source.
//!
//! Aesthetic: cypherpunk monospace. Dark bg, neon accents. The eye should land on
//! exactly one thing per screen.

use ratatui::style::{Color, Modifier, Style};

// ── Brand ────────────────────────────────────────────────────────────────────
pub const BRAND:     Color = Color::Rgb(0, 255, 200);   // primary cyan-mint
pub const BRAND_DIM: Color = Color::Rgb(0, 160, 130);

// ── Status ───────────────────────────────────────────────────────────────────
pub const ARMED:   Color = Color::Rgb(80, 250, 123);    // green
pub const WARN:    Color = Color::Rgb(255, 184, 108);   // amber
pub const DANGER:  Color = Color::Rgb(255, 85, 85);     // red
pub const NEUTRAL: Color = Color::Rgb(189, 147, 249);   // purple (unknown / pending)

// ── Text ─────────────────────────────────────────────────────────────────────
pub const TEXT:     Color = Color::Rgb(248, 248, 242);  // primary white
pub const TEXT_DIM: Color = Color::Rgb(120, 120, 130);  // secondary
pub const TEXT_MUT: Color = Color::Rgb(80, 80, 95);     // tertiary

// ── Backgrounds ──────────────────────────────────────────────────────────────
pub const BG_PANEL: Color = Color::Rgb(20, 22, 28);

// ── Style helpers ────────────────────────────────────────────────────────────
pub fn brand_bold() -> Style {
    Style::default().fg(BRAND).add_modifier(Modifier::BOLD)
}
pub fn armed() -> Style {
    Style::default().fg(ARMED).add_modifier(Modifier::BOLD)
}
pub fn warn() -> Style {
    Style::default().fg(WARN).add_modifier(Modifier::BOLD)
}
pub fn danger() -> Style {
    Style::default().fg(DANGER).add_modifier(Modifier::BOLD)
}
pub fn dim() -> Style {
    Style::default().fg(TEXT_DIM)
}
pub fn mute() -> Style {
    Style::default().fg(TEXT_MUT)
}
pub fn label() -> Style {
    Style::default().fg(TEXT).add_modifier(Modifier::BOLD)
}
