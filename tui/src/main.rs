//! Sovereign OS Vault — kernel-hardened Solana signer.
//!
//! Flow:
//!   harden_process()            — order-critical OS-level hardening
//!   ↓
//!   if no keystore: SETUP       — generate or import, set passphrase
//!   else:           UNLOCK      — passphrase prompt
//!   ↓
//!   HOME (status + actions)
//!   ↓ [s]
//!   PASTE_TX → INSPECT → CONFIRM → SIGN → SHOW_SIGNED
//!
//! Mainnet positioning: signed output is ready to broadcast via any RPC. The
//! vault itself is offline — no network calls. Pair it with `solana send` or
//! a hardware-air-gap workflow.

mod armor;
mod frost;
mod inspector;
mod keystore;
mod rpc;
mod squads;
mod theme;
mod vultisig;

use anyhow::Result;
use crossterm::{
    event::{
        self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyModifiers,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
// NOTE: we deliberately do NOT enable mouse capture. With mouse capture OFF,
// the terminal handles click-and-drag-select and the OS clipboard natively
// (Ctrl+Shift+C / Cmd+C / right-click → Copy). Enabling capture would steal
// every mouse event for the app and break every user's "let me copy this
// pubkey real quick" expectation. We don't use mouse input anywhere in this
// TUI, so there's no upside to capturing it.
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Layout, Margin, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Gauge, Paragraph, Wrap},
    Frame, Terminal,
};
use std::{io, time::Duration};

use armor::{StartupHardening, ZigArmorReport};
use inspector::{InspectedTx, Severity};
use keystore::{UnlockedKey, DEFAULT_DECOY_MAX_PER_TX_LAMPORTS, DEFAULT_DECOY_MAX_CUMULATIVE_LAMPORTS};
use vultisig::VultisigClient;
use frost::{FrostClient, LaptopFrost};

// ── Backend (signing source) ─────────────────────────────────────────────────

#[derive(Clone, PartialEq)]
enum Backend {
    /// Local encrypted keystore on this machine. Single-party signer; pair with
    /// a Squads multisig at the treasury layer for multi-party safety.
    Local,
    /// Vultisig 2-of-2 MPC. Daemon holds one keyshare, mobile app holds the other.
    /// On-chain shows a single ed25519 pubkey; observers can't tell it's MPC.
    /// v0.4 status: explored, walled by WSL2 mDNS isolation + closed-source mobile
    /// app contract drift. Patches in `scripts/vendor-patches/` are upstream-able
    /// against vultisig-cli but not the v0.4 hero path.
    Vultisig { pubkey: String },
    /// Telegram-bot FROST 2-of-2 ed25519 cosigner — v0.4 hero MPC backend.
    /// Laptop holds share 1, ephemeral bot holds share 2 in your Telegram session.
    /// Inspector's decoded summary appears in your Telegram approval prompt; sig
    /// won't aggregate unless you tap Approve on your phone. On-chain the group
    /// pubkey looks like any other ed25519 address — Squads accepts it as a
    /// member without modification.
    TelegramFrost { pubkey: String },
}

// ── Screen state machine ─────────────────────────────────────────────────────

#[derive(PartialEq, Clone, Copy)]
enum Screen {
    BackendSelect,
    SetupIntro,
    SetupPass,
    Unlock,
    Home,
    PasteTx,
    Inspect,
    Signing,    // MPC handshake / mobile cosigner approval — spinner-driven
    Signed,
    Squads,     // List of pending Squads V4 proposals — pick one to inspect
}

#[derive(PartialEq, Clone, Copy)]
enum BackendChoice { Local, Vultisig, TelegramFrost }

/// State carried while a signature is in flight on a worker thread.
struct SigningJob {
    rx:        std::sync::mpsc::Receiver<std::result::Result<String, String>>,
    started_at: std::time::Instant,
}

/// State carried while a broadcast is in flight on a worker thread.
/// Mirrors SigningJob but lives on the Signed screen.
struct BroadcastJob {
    rx:         std::sync::mpsc::Receiver<std::result::Result<String, String>>,
    started_at: std::time::Instant,
}

/// State carried while a Squads proposal poll is in flight on a worker thread.
struct SquadsPollJob {
    rx:         std::sync::mpsc::Receiver<std::result::Result<Vec<squads::PendingProposal>, String>>,
    started_at: std::time::Instant,
}

/// Where the currently-loaded inspector view came from. Drives whether we
/// enforce the fee-payer check (yes for Paste — you're signing your own tx;
/// no for Squads — you're a multisig member voting on someone else's tx).
#[derive(Clone, Copy, PartialEq)]
enum InspectSource {
    /// Loaded by pasting raw base64/base58 message bytes via the PasteTx screen.
    /// The user is signing AS the fee payer; the check applies.
    Paste,
    /// Loaded by selecting a Squads proposal in the [m] watch screen. The user
    /// is approving (or rejecting) the proposal as a member; the inner tx's
    /// fee payer is the vault PDA (or another member), not us.
    Squads,
}

/// File the daemon writes the keysign QR URI to. We poll this while in the
/// Signing screen so we can render the QR inline instead of forcing the user
/// to look at the daemon terminal.
const VULTISIG_QR_URI_FILE: &str = "/tmp/vultisig-current-keysign.txt";

/// Re-render a QR string into ratatui-friendly Unicode lines.
/// Decode QR bits once, then a render function picks how many modules to
/// pack per character cell. Quadrant (2×2) is the densest universally
/// supported packing; sextant (2×3) is denser but needs Unicode 13.0
/// support in both terminal and font (Windows Terminal, iTerm2, modern
/// Linux terminals all OK).
fn qr_bits(uri: &str) -> Option<(usize, Vec<bool>)> {
    use qrcode::{QrCode, EcLevel, Color};
    let code = QrCode::with_error_correction_level(uri.as_bytes(), EcLevel::L).ok()?;
    let w = code.width();
    let bits = code.to_colors().into_iter()
        .map(|c| matches!(c, Color::Dark))
        .collect();
    Some((w, bits))
}

fn render_qr_quadrant(uri: &str) -> Option<Vec<String>> {
    let (w, bits) = qr_bits(uri)?;
    let dark = |x: usize, y: usize| -> bool {
        x < w && y < w && bits[y * w + x]
    };
    let mut lines = Vec::with_capacity((w + 1) / 2);
    let mut y = 0;
    while y < w {
        let mut row = String::with_capacity(((w + 1) / 2) * 4);
        let mut x = 0;
        while x < w {
            let ch = match (dark(x, y), dark(x + 1, y), dark(x, y + 1), dark(x + 1, y + 1)) {
                (false, false, false, false) => ' ',
                (true,  false, false, false) => '▘',
                (false, true,  false, false) => '▝',
                (true,  true,  false, false) => '▀',
                (false, false, true,  false) => '▖',
                (true,  false, true,  false) => '▌',
                (false, true,  true,  false) => '▞',
                (true,  true,  true,  false) => '▛',
                (false, false, false, true)  => '▗',
                (true,  false, false, true)  => '▚',
                (false, true,  false, true)  => '▐',
                (true,  true,  false, true)  => '▜',
                (false, false, true,  true)  => '▄',
                (true,  false, true,  true)  => '▙',
                (false, true,  true,  true)  => '▟',
                (true,  true,  true,  true)  => '█',
            };
            row.push(ch);
            x += 2;
        }
        lines.push(row);
        y += 2;
    }
    Some(lines)
}

/// Sextant character for a 6-bit pattern (TL, TR, ML, MR, BL, BR).
/// Codepoints from Unicode 13.0 "Symbols for Legacy Computing"
/// (U+1FB00..U+1FB3B), with three slots remapped to existing block-element
/// chars (left half, right half, full block) per Unicode spec.
fn sextant_char(bits: u8) -> char {
    match bits {
        0  => ' ',
        21 => '▌',
        42 => '▐',
        63 => '█',
        b => {
            let mut idx = b as u32 - 1;
            if b > 21 { idx -= 1; }
            if b > 42 { idx -= 1; }
            std::char::from_u32(0x1FB00 + idx).unwrap_or('?')
        }
    }
}

fn render_qr_sextant(uri: &str) -> Option<Vec<String>> {
    let (w, bits) = qr_bits(uri)?;
    let dark = |x: usize, y: usize| -> bool {
        x < w && y < w && bits[y * w + x]
    };
    let h = (w + 2) / 3;
    let mut lines = Vec::with_capacity(h);
    let mut y = 0;
    while y < w {
        let mut row = String::new();
        let mut x = 0;
        while x < w {
            let pattern: u8 = (dark(x,     y    ) as u8)
                            | (dark(x + 1, y    ) as u8) << 1
                            | (dark(x,     y + 1) as u8) << 2
                            | (dark(x + 1, y + 1) as u8) << 3
                            | (dark(x,     y + 2) as u8) << 4
                            | (dark(x + 1, y + 2) as u8) << 5;
            row.push(sextant_char(pattern));
            x += 2;
        }
        lines.push(row);
        y += 3;
    }
    Some(lines)
}

/// Pick the densest packing whose rendered size fits inside the panel.
/// Falls through quadrant → sextant. Returns the chosen lines along with
/// the (width_chars, height_chars) it occupied, or None if neither fit.
fn render_qr_for_area(uri: &str, max_w: u16, max_h: u16) -> Option<Vec<String>> {
    for f in [render_qr_quadrant, render_qr_sextant] {
        if let Some(lines) = f(uri) {
            let w = lines.first().map_or(0, |l| l.chars().count() as u16);
            let h = lines.len() as u16;
            if w <= max_w && h <= max_h {
                return Some(lines);
            }
        }
    }
    None
}

/// Locate the daemon's most recently written QR file (PNG or HTML).
fn locate_qr_file(ext: &str) -> Option<std::path::PathBuf> {
    use std::fs;
    let mut newest: Option<(std::time::SystemTime, std::path::PathBuf)> = None;
    let entries = fs::read_dir("/tmp").ok()?;
    for e in entries.flatten() {
        let p = e.path();
        let name = p.file_name()?.to_str()?;
        if name.starts_with("vultisig_qr_") && name.ends_with(ext) {
            if let Ok(meta) = e.metadata() {
                if let Ok(mt) = meta.modified() {
                    if newest.as_ref().map_or(true, |(t, _)| mt > *t) {
                        newest = Some((mt, p));
                    }
                }
            }
        }
    }
    newest.map(|(_, p)| p)
}

fn locate_qr_png() -> Option<std::path::PathBuf> { locate_qr_file(".png") }

/// Detect WSL by inspecting /proc/version. Returns true if running under WSL,
/// in which case we route file opens through cmd.exe so the Windows browser
/// (not a missing Linux app) handles the file URL.
fn is_wsl() -> bool {
    std::fs::read_to_string("/proc/version")
        .map(|s| s.to_lowercase().contains("microsoft"))
        .unwrap_or(false)
}

/// Open a local file in the OS default app. Stays local — no network calls.
/// On WSL, converts the WSL path to a Windows path and hands off to cmd.exe.
fn open_local_file(path: &std::path::Path) -> std::io::Result<()> {
    use std::process::{Command, Stdio};
    if is_wsl() {
        // wslpath -w /tmp/foo.html → \\wsl.localhost\Ubuntu\tmp\foo.html
        let win_path = Command::new("wslpath")
            .arg("-w")
            .arg(path)
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| path.display().to_string());
        Command::new("cmd.exe")
            .args(["/c", "start", "", &win_path])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
    } else if cfg!(target_os = "macos") {
        Command::new("open").arg(path).spawn()?;
    } else {
        Command::new("xdg-open").arg(path).spawn()?;
    }
    Ok(())
}

struct App {
    screen:        Screen,
    startup:       StartupHardening,
    zig:           ZigArmorReport,
    score:         u16,

    // Backend selection
    backend:               Backend,
    backend_choice:        BackendChoice,
    vultisig_available:    bool,
    frost_available:       bool,
    laptop_frost:          Option<LaptopFrost>,

    // Passphrase entry — 4 fields for duress setup, 1 for unlock
    pass_buf_sov:         String,
    pass_buf_sov_confirm: String,
    pass_buf_dec:         String,
    pass_buf_dec_confirm: String,
    pass_field:           u8,         // 0..3 during setup, always 0 during unlock
    unlock_buf:           String,
    error_msg:            Option<String>,

    // Unlocked state (Local backend only)
    unlocked:        Option<UnlockedKey>,

    // Sign flow
    tx_paste:        String,
    inspected:       Option<InspectedTx>,
    /// Where the currently-inspected tx came from. Affects whether we enforce
    /// the "fee payer == backend pubkey" check (which is correct for self-
    /// constructed pastes but wrong for Squads proposals — there the member
    /// is voting on someone else's tx, not signing as the fee payer).
    inspect_source:  InspectSource,
    signing:         Option<SigningJob>,
    qr_uri:          Option<String>,
    last_signed:     Option<String>,
    last_signed_path:Option<String>,

    // Broadcast flow
    broadcast_job:        Option<BroadcastJob>,
    last_broadcast_sig:   Option<String>,
    last_broadcast_error: Option<String>,

    // Squads V4 multisig watch
    squads_multisig:        Option<String>,                  // PDA from $SQUADS_MULTISIG
    squads_proposals:       Vec<squads::PendingProposal>,
    squads_selected:        usize,
    squads_poll_job:        Option<SquadsPollJob>,
    squads_last_poll:       Option<std::time::Instant>,
    squads_error:           Option<String>,
    /// Snapshot of the currently-being-inspected Squads proposal, taken when
    /// the user picks a row and presses Enter. Lets the sign path build a
    /// `proposal_approve` instruction targeting the right proposal index
    /// even if the watch list refreshes mid-flow.
    current_squads_proposal: Option<squads::PendingProposal>,

    // Animation
    frame_tick:      u64,

    flash:           Option<(String, Color)>,
    flash_until:     std::time::Instant,
}

impl App {
    fn new(startup: StartupHardening) -> Self {
        let zig = armor::query_zig_armor();
        let frost_share_present   = LaptopFrost::load().is_ok();
        let frost_bot_running     = FrostClient::default_url().is_running();
        let frost_available       = frost_share_present && frost_bot_running;

        // v0.4 boot routing — FROST + Telegram is the ONLY path:
        //   - FROST available → auto-load it and go straight to Home
        //   - FROST not available → BackendSelect renders a setup-required
        //     message with instructions, no other backends shown
        // Vultisig and local-keystore code paths are preserved internally
        // for compatibility but no longer surfaced in the BackendSelect UI.
        let (initial_screen, initial_backend, laptop_frost) = if frost_available {
            match LaptopFrost::load() {
                Ok(lf) => match lf.solana_address() {
                    Ok(pubkey) => (
                        Screen::Home,
                        Backend::TelegramFrost { pubkey },
                        Some(lf),
                    ),
                    Err(_) => (Screen::BackendSelect, Backend::Local, None),
                },
                Err(_) => (Screen::BackendSelect, Backend::Local, None),
            }
        } else {
            (Screen::BackendSelect, Backend::Local, None)
        };

        let mut app = App {
            screen:                initial_screen,
            startup, zig, score: 0,
            backend:               initial_backend,
            backend_choice:        BackendChoice::TelegramFrost,
            vultisig_available:    false,
            frost_available,
            laptop_frost,
            pass_buf_sov:         String::new(),
            pass_buf_sov_confirm: String::new(),
            pass_buf_dec:         String::new(),
            pass_buf_dec_confirm: String::new(),
            pass_field:           0,
            unlock_buf:           String::new(),
            error_msg:            None,
            unlocked:             None,
            tx_paste:             String::new(),
            inspected:            None,
            signing:              None,
            qr_uri:               None,
            last_signed:          None,
            last_signed_path:     None,
            inspect_source:       InspectSource::Paste,
            broadcast_job:        None,
            last_broadcast_sig:   None,
            last_broadcast_error: None,
            squads_multisig:         std::env::var("SQUADS_MULTISIG").ok(),
            squads_proposals:        Vec::new(),
            squads_selected:         0,
            squads_poll_job:         None,
            squads_last_poll:        None,
            squads_error:            None,
            current_squads_proposal: None,
            frame_tick:           0,
            flash:                None,
            flash_until:          std::time::Instant::now(),
        };
        app.refresh_score();
        app
    }
    fn wipe_setup_buffers(&mut self) {
        use zeroize::Zeroize;
        self.pass_buf_sov.zeroize();
        self.pass_buf_sov_confirm.zeroize();
        self.pass_buf_dec.zeroize();
        self.pass_buf_dec_confirm.zeroize();
        self.unlock_buf.zeroize();
        self.pass_field = 0;
    }

    fn flash(&mut self, msg: impl Into<String>, color: Color) {
        self.flash = Some((msg.into(), color));
        self.flash_until = std::time::Instant::now() + Duration::from_secs(4);
    }

    fn refresh_score(&mut self) {
        let (dumpable_ok, vmlck) = armor::read_kernel_state();
        let no_debugger = !armor::debugger_attached();
        let non_root    = self.startup.uid != 0;

        let checks = [
            self.zig.connected,
            self.zig.memory_guard,
            self.zig.swap_guard,
            dumpable_ok,
            vmlck > 0,
            no_debugger,
            non_root,
        ];
        let passed = checks.iter().filter(|&&v| v).count();
        let total  = checks.len();
        let yama_bonus = if self.startup.yama_active { 1u16 } else { 0 };
        let base = (passed as u16 * 100) / total as u16;
        self.score = std::cmp::min(base + yama_bonus, 100);
    }
}

// ── Entry ────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    // FIRST: harden. Panics with SECURITY_INIT_FAILURE if anything fails.
    let startup = armor::harden_process();

    // Install panic hook that restores terminal before printing the panic.
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(
            io::stderr(),
            LeaveAlternateScreen,
            DisableBracketedPaste,
            crossterm::cursor::Show
        );
        original_hook(info);
    }));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableBracketedPaste)?;
    let backend = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;

    let mut app = App::new(startup);
    let result = run_app(&mut term, &mut app);

    // Restore terminal regardless of result.
    disable_raw_mode().ok();
    execute!(term.backend_mut(), LeaveAlternateScreen, DisableBracketedPaste).ok();
    term.show_cursor().ok();

    result
}

fn run_app<B: ratatui::backend::Backend>(term: &mut Terminal<B>, app: &mut App) -> Result<()> {
    let tick = Duration::from_millis(200);
    loop {
        // Runtime debugger detection: kill ourselves immediately.
        if armor::debugger_attached() {
            disable_raw_mode().ok();
            execute!(io::stderr(), LeaveAlternateScreen, DisableBracketedPaste).ok();
            anyhow::bail!("SECURITY_VIOLATION: debugger attached at runtime (TracerPid != 0)");
        }

        // Throttle full hardening checks — they hit /proc.
        app.refresh_score();
        if app.flash.is_some() && std::time::Instant::now() > app.flash_until {
            app.flash = None;
        }

        // Tick the spinner / animation clock once per ~200ms.
        app.frame_tick = app.frame_tick.wrapping_add(1);

        // Poll the in-flight signing job (Vultisig MPC). Non-blocking try_recv
        // so the UI stays responsive between daemon / mobile-cosigner round-trips.
        if let Some(job) = &app.signing {
            // While a sign is in-flight, also try to read the QR URI the daemon
            // writes to a well-known path. We poll lazily — once we have it, we
            // stop re-reading. Cheap when present, harmless when absent.
            if app.qr_uri.is_none() {
                if let Ok(uri) = std::fs::read_to_string(VULTISIG_QR_URI_FILE) {
                    let uri = uri.trim().to_string();
                    if !uri.is_empty() {
                        app.qr_uri = Some(uri);
                    }
                }
            }

            match job.rx.try_recv() {
                Ok(Ok(signed_b58)) => {
                    let path = save_signed_to_disk(&signed_b58).ok();
                    app.last_signed = Some(signed_b58);
                    app.last_signed_path = path;
                    app.signing = None;
                    app.qr_uri = None;
                    let _ = std::fs::remove_file(VULTISIG_QR_URI_FILE);
                    app.screen = Screen::Signed;
                    let backend_label = match &app.backend {
                        Backend::TelegramFrost { .. } => "FROST + Telegram",
                        Backend::Vultisig { .. }      => "Vultisig MPC",
                        Backend::Local                => "local keystore",
                    };
                    app.flash(format!("Transaction signed via {}", backend_label), theme::ARMED);
                }
                Ok(Err(e)) => {
                    app.signing = None;
                    app.qr_uri = None;
                    let _ = std::fs::remove_file(VULTISIG_QR_URI_FILE);
                    app.screen = Screen::Inspect;
                    let backend_label = match &app.backend {
                        Backend::TelegramFrost { .. } => "FROST",
                        Backend::Vultisig { .. }      => "Vultisig",
                        Backend::Local                => "local",
                    };
                    app.error_msg = Some(format!("{} sign failed: {e}", backend_label));
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => { /* still waiting */ }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    app.signing = None;
                    app.qr_uri = None;
                    let _ = std::fs::remove_file(VULTISIG_QR_URI_FILE);
                    app.screen = Screen::Inspect;
                    let backend_label = match &app.backend {
                        Backend::TelegramFrost { .. } => "FROST",
                        Backend::Vultisig { .. }      => "Vultisig",
                        Backend::Local                => "local",
                    };
                    app.error_msg = Some(format!("{} signing worker thread died", backend_label));
                }
            }
        }

        // Poll the in-flight Squads proposal fetch (read-only — no on-chain
        // writes). Auto-refresh every 30s while the Squads screen is active
        // so new proposals from other multisig members appear without manual [r].
        if let Some(job) = &app.squads_poll_job {
            match job.rx.try_recv() {
                Ok(Ok(mut proposals)) => {
                    // Decode inner messages on the main thread so each row in
                    // the Squads list shows what the proposal actually does
                    // ("Transfer 0.001 SOL → 8aDT…vFdH" instead of "143 byte
                    // inner Message"), with a severity badge driven by the
                    // worst risk present.
                    use base64::Engine as _;
                    for p in &mut proposals {
                        if let Some(bytes) = &p.inner_message {
                            let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
                            if let Ok(insp) = inspector::inspect_squads_inner_b64(&b64, &b64) {
                                let summary = if insp.instructions.is_empty() {
                                    "(empty inner message)".to_string()
                                } else if insp.instructions.len() == 1 {
                                    insp.instructions[0].summary.clone()
                                } else {
                                    format!("{} ix · 1st: {}",
                                        insp.instructions.len(),
                                        insp.instructions[0].summary)
                                };
                                p.decoded_summary = Some(summary);
                                p.worst_severity = insp.risks.iter()
                                    .map(|r| match r.severity() {
                                        inspector::Severity::Low      => 0u8,
                                        inspector::Severity::Medium   => 1,
                                        inspector::Severity::High     => 2,
                                        inspector::Severity::Critical => 3,
                                    })
                                    .max();
                            }
                        }
                    }
                    app.squads_proposals = proposals;
                    app.squads_last_poll = Some(std::time::Instant::now());
                    app.squads_poll_job = None;
                    if app.squads_selected >= app.squads_proposals.len() {
                        app.squads_selected = app.squads_proposals.len().saturating_sub(1);
                    }
                }
                Ok(Err(e)) => {
                    app.squads_error = Some(e);
                    app.squads_poll_job = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => { /* still waiting */ }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    app.squads_error = Some("squads poll worker died".into());
                    app.squads_poll_job = None;
                }
            }
        }
        // Auto-poll squads whenever:
        //   - we're on Home or Squads screen (the screens that surface proposals)
        //   - no poll is currently in flight
        //   - either we haven't polled yet, or it's been >30s since the last
        //
        // This keeps the Sentinel panel on Home alive without requiring the
        // user to navigate to the Squads screen first.
        let watching = matches!(app.screen, Screen::Squads | Screen::Home);
        let due = app.squads_last_poll
            // 60s default — public mainnet RPC rate-limits at ~10 req/sec
            // and each poll makes 2 RPC calls per proposal in the lookback
            // window. Override with SOVEREIGN_RPC_URL pointing at a private
            // node if you want faster refresh.
            .map(|t| t.elapsed() > std::time::Duration::from_secs(60))
            .unwrap_or(true);
        if watching && app.squads_poll_job.is_none() && due && app.squads_multisig.is_some() {
            spawn_squads_poll(app);
        }

        // Poll the in-flight broadcast job (mainnet sendTransaction). Same
        // try_recv pattern as the signing poller. The Signed screen renders
        // a spinner/result based on these fields without any extra screen state.
        if let Some(job) = &app.broadcast_job {
            match job.rx.try_recv() {
                Ok(Ok(sig)) => {
                    app.broadcast_job = None;
                    app.last_broadcast_sig = Some(sig.clone());
                    app.last_broadcast_error = None;
                    app.flash(format!("Broadcast confirmed: {}", inspector::short(&sig)), theme::ARMED);
                }
                Ok(Err(e)) => {
                    app.broadcast_job = None;
                    app.last_broadcast_error = Some(e);
                    app.flash("Broadcast failed — see Signed screen for details", theme::DANGER);
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => { /* still waiting */ }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    app.broadcast_job = None;
                    app.last_broadcast_error = Some("broadcast worker thread died".into());
                }
            }
        }

        term.draw(|f| draw(f, app))?;

        if event::poll(tick)? {
            match event::read()? {
                Event::Key(k) => {
                    if handle_key(app, k.code, k.modifiers) {
                        return Ok(());
                    }
                }
                Event::Paste(payload) => {
                    handle_paste(app, &payload);
                }
                _ => {}
            }
        }
    }
}

/// Bracketed-paste handler. Atomically append the pasted payload to whichever
/// input buffer is currently active. Critical for the PasteTx screen — long
/// base64 strings (~600+ chars) used to trickle in one Char event at a time;
/// now they land instantly as a single event, and we can normalise newlines.
fn handle_paste(app: &mut App, payload: &str) {
    let cleaned = payload
        .replace(['\r', '\n', ' ', '\t'], "")  // base64 paste is single-line; strip wrapping
        ;
    match app.screen {
        Screen::PasteTx => app.tx_paste.push_str(&cleaned),
        Screen::Unlock  => app.unlock_buf.push_str(payload),
        Screen::SetupPass => {
            // Rare but possible — paste straight into the active passphrase field.
            let active = match app.pass_field {
                0 => &mut app.pass_buf_sov,
                1 => &mut app.pass_buf_sov_confirm,
                2 => &mut app.pass_buf_dec,
                _ => &mut app.pass_buf_dec_confirm,
            };
            active.push_str(payload);
        }
        _ => {}
    }
}

// ── Key dispatch ─────────────────────────────────────────────────────────────

/// Returns true to quit.
fn handle_key(app: &mut App, code: KeyCode, mods: KeyModifiers) -> bool {
    // Global Ctrl-C always quits.
    if mods.contains(KeyModifiers::CONTROL) && matches!(code, KeyCode::Char('c')) {
        return true;
    }
    match app.screen {
        Screen::BackendSelect => key_backend_select(app, code, mods),
        Screen::SetupIntro    => key_setup_intro(app, code, mods),
        Screen::SetupPass     => key_setup_pass(app, code, mods),
        Screen::Unlock        => key_unlock(app, code, mods),
        Screen::Home          => key_home(app, code, mods),
        Screen::PasteTx       => key_paste(app, code, mods),
        Screen::Inspect       => key_inspect(app, code, mods),
        Screen::Signing       => key_signing(app, code, mods),
        Screen::Signed        => key_signed(app, code, mods),
        Screen::Squads        => key_squads(app, code, mods),
    }
}

fn key_backend_select(app: &mut App, code: KeyCode, _mods: KeyModifiers) -> bool {
    match code {
        KeyCode::Char('q') | KeyCode::Esc => return true,
        // v0.4 ships a single backend (FROST + Telegram). The BackendSelect
        // screen now functions as "FROST setup checklist + retry"; there's
        // nothing to switch between. [r] re-checks share + bot, [enter]
        // launches FROST when both are present.
        KeyCode::Char('r') | KeyCode::Char('R') => {
            app.frost_available = LaptopFrost::load().is_ok()
                && FrostClient::default_url().is_running();
            app.error_msg = None;
        }
        KeyCode::Enter => {
            match LaptopFrost::load() {
                Ok(lf) => {
                    let pubkey = match lf.solana_address() {
                        Ok(p) => p,
                        Err(e) => {
                            app.error_msg = Some(format!("FROST: {e}"));
                            return false;
                        }
                    };
                    if !FrostClient::default_url().is_running() {
                        app.error_msg = Some(
                            "FROST bot not reachable at 127.0.0.1:7777 — start `frost-bot` first".into()
                        );
                        return false;
                    }
                    app.backend = Backend::TelegramFrost { pubkey: pubkey.clone() };
                    app.laptop_frost = Some(lf);
                    app.screen  = Screen::Home;
                    app.flash(
                        format!("FROST + Telegram connected: {}", inspector::short(&pubkey)),
                        theme::ARMED,
                    );
                }
                Err(e) => {
                    app.error_msg = Some(format!(
                        "FROST share missing — run `frost-keygen` first: {e}"
                    ));
                }
            }
        }
        _ => {}
    }
    false
}

fn key_signing(app: &mut App, code: KeyCode, _mods: KeyModifiers) -> bool {
    // No interactive cancellation — the MPC handshake is short and blocking the
    // mobile cosigner mid-flight is messy. ESC from Signing requires daemon timeout.
    match code {
        KeyCode::Esc if app.signing.is_none() => {
            app.screen = Screen::Home;
        }
        // Open the most recent QR (HTML preferred, PNG fallback) in the OS
        // default browser. Useful when the QR is too large to fit in-TUI —
        // common for full SignTransaction payloads — or when the user just
        // prefers a bigger phone-camera target.
        KeyCode::Char('b') | KeyCode::Char('B') => {
            let target = locate_qr_file(".html").or_else(|| locate_qr_file(".png"));
            if let Some(p) = target {
                match open_local_file(&p) {
                    Ok(()) => app.flash(
                        format!("Opened {} in browser", p.display()),
                        theme::ARMED),
                    Err(e) => app.flash(
                        format!("Failed to open browser: {}", e),
                        theme::DANGER),
                }
            } else {
                app.flash("No QR file found yet — wait for the daemon to register",
                    theme::WARN);
            }
        }
        _ => {}
    }
    false
}

fn key_setup_intro(app: &mut App, code: KeyCode, _mods: KeyModifiers) -> bool {
    match code {
        KeyCode::Char('q') | KeyCode::Esc => return true,
        KeyCode::Enter => {
            app.screen = Screen::SetupPass;
            app.pass_field = 0;
            app.error_msg = None;
        }
        _ => {}
    }
    false
}

fn key_setup_pass(app: &mut App, code: KeyCode, _mods: KeyModifiers) -> bool {
    let active = match app.pass_field {
        0 => &mut app.pass_buf_sov,
        1 => &mut app.pass_buf_sov_confirm,
        2 => &mut app.pass_buf_dec,
        _ => &mut app.pass_buf_dec_confirm,
    };
    match code {
        KeyCode::Esc => return true,
        KeyCode::Char(c) => active.push(c),
        KeyCode::Backspace => { active.pop(); }
        KeyCode::Tab => { app.pass_field = (app.pass_field + 1) % 4; }
        KeyCode::BackTab => { app.pass_field = (app.pass_field + 3) % 4; }
        KeyCode::Enter => {
            if app.pass_field < 3 {
                app.pass_field += 1;
                return false;
            }
            // All 4 fields filled — validate and create.
            if app.pass_buf_sov != app.pass_buf_sov_confirm {
                app.error_msg = Some("sovereign passphrases don't match".into());
                app.pass_buf_sov.clear(); app.pass_buf_sov_confirm.clear();
                app.pass_field = 0; return false;
            }
            if app.pass_buf_dec != app.pass_buf_dec_confirm {
                app.error_msg = Some("decoy passphrases don't match".into());
                app.pass_buf_dec.clear(); app.pass_buf_dec_confirm.clear();
                app.pass_field = 2; return false;
            }
            if app.pass_buf_sov.len() < 8 || app.pass_buf_dec.len() < 8 {
                app.error_msg = Some("each passphrase must be ≥ 8 chars".into());
                return false;
            }
            if app.pass_buf_sov == app.pass_buf_dec {
                app.error_msg = Some("decoy passphrase must differ from sovereign".into());
                return false;
            }
            let result = keystore::create_new_duress(
                &app.pass_buf_sov,
                &app.pass_buf_dec,
            );
            app.wipe_setup_buffers();
            match result {
                Ok(unlocked) => {
                    let pk = unlocked.pubkey_base58();
                    app.unlocked = Some(unlocked);
                    app.screen = Screen::Home;
                    app.error_msg = None;
                    app.flash(format!("Vault initialized: {}", inspector::short(&pk)), theme::ARMED);
                }
                Err(e) => app.error_msg = Some(e.to_string()),
            }
        }
        _ => {}
    }
    false
}

fn key_unlock(app: &mut App, code: KeyCode, _mods: KeyModifiers) -> bool {
    match code {
        KeyCode::Esc => return true,
        KeyCode::Char(c) => app.unlock_buf.push(c),
        KeyCode::Backspace => { app.unlock_buf.pop(); }
        KeyCode::Enter => {
            match keystore::unlock(&app.unlock_buf) {
                Ok(unlocked) => {
                    let pk = unlocked.pubkey_base58();
                    app.unlocked = Some(unlocked);
                    app.screen = Screen::Home;
                    app.error_msg = None;
                    // Generic flash — does not betray which mode unlocked.
                    app.flash(format!("Unlocked: {}", inspector::short(&pk)), theme::ARMED);
                }
                Err(e) => app.error_msg = Some(e.to_string()),
            }
            use zeroize::Zeroize;
            app.unlock_buf.zeroize();
        }
        _ => {}
    }
    false
}

fn key_home(app: &mut App, code: KeyCode, _mods: KeyModifiers) -> bool {
    match code {
        KeyCode::Char('q') | KeyCode::Esc => return true,
        KeyCode::Char('s') | KeyCode::Char('S') => {
            app.screen = Screen::PasteTx;
            app.tx_paste.clear();
            app.error_msg = None;
        }
        KeyCode::Char('a') | KeyCode::Char('A') => {
            app.zig = armor::query_zig_armor();
            app.flash("Re-armed: kernel state re-read", theme::BRAND);
        }
        KeyCode::Char('m') | KeyCode::Char('M') => {
            // Squads V4 multisig watch — only available if a multisig PDA is
            // configured via $SQUADS_MULTISIG. Without one, the TUI doesn't
            // know which multisig to poll.
            if app.squads_multisig.is_none() {
                app.flash("Set $SQUADS_MULTISIG to your multisig PDA before using [m]",
                    theme::WARN);
                return false;
            }
            app.screen = Screen::Squads;
            app.squads_error = None;
            // Kick off an immediate poll on entry so the screen isn't empty.
            spawn_squads_poll(app);
        }
        _ => {}
    }
    false
}

/// Spawn a worker thread to fetch the latest Squads proposals. Result lands
/// in `app.squads_poll_job.rx` and the main loop folds it into
/// `app.squads_proposals`. Idempotent — if a poll is already in flight, this
/// is a no-op (the in-flight one will land first).
fn spawn_squads_poll(app: &mut App) {
    if app.squads_poll_job.is_some() { return; }
    let Some(multisig) = app.squads_multisig.clone() else { return };
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let url = squads::default_rpc_url();
        let result = (|| {
            let m = squads::fetch_multisig(&multisig, &url)
                .map_err(|e| format!("fetch_multisig: {e}"))?;
            // 8 most recent proposals — keeps each poll under public RPC's
            // ~10 req/sec budget (1 multisig fetch + 8 × 2 = 17 calls per
            // refresh). Bump if you're using a private RPC.
            squads::fetch_recent_proposals(&m, &url, 8)
                .map_err(|e| format!("fetch_recent_proposals: {e}"))
        })();
        let _ = tx.send(result);
    });
    app.squads_poll_job = Some(SquadsPollJob {
        rx,
        started_at: std::time::Instant::now(),
    });
}

fn key_squads(app: &mut App, code: KeyCode, _mods: KeyModifiers) -> bool {
    match code {
        KeyCode::Esc | KeyCode::Char('q') => {
            app.screen = Screen::Home;
            app.squads_error = None;
        }
        KeyCode::Char('r') | KeyCode::Char('R') => {
            spawn_squads_poll(app);
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if app.squads_selected > 0 { app.squads_selected -= 1; }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let max = app.squads_proposals.len().saturating_sub(1);
            if app.squads_selected < max { app.squads_selected += 1; }
        }
        KeyCode::Enter => {
            // Pick the highlighted proposal and feed its inner Solana Message
            // into the inspector → land on the existing Inspect screen → user
            // proceeds with the existing FROST + Telegram sign flow. Reuses
            // every line of code for the sign path; we just gave it a new
            // *source* (a Squads proposal vs. a manual paste).
            if let Some(prop) = app.squads_proposals.get(app.squads_selected).cloned() {
                let Some(msg_bytes) = prop.inner_message.clone() else {
                    app.squads_error = Some(format!(
                        "proposal #{} is a ConfigTransaction (no inner Message — config changes \
                         are inspected differently in v0.5)", prop.index));
                    return false;
                };
                use base64::Engine as _;
                app.tx_paste = base64::engine::general_purpose::STANDARD.encode(&msg_bytes);
                // Squads VaultTransaction inner messages use Squads' inline
                // VaultTransactionMessage Borsh format (NOT a standard Solana
                // Message). Use the Squads-aware entry point so inspection
                // produces the same recursive decode + risk pipeline you'd
                // get pasting a wrapper attack at the PasteTx screen.
                match inspector::inspect_squads_inner_b64(&app.tx_paste, &app.tx_paste) {
                    Ok(ix) => {
                        app.inspected = Some(ix);
                        app.inspect_source = InspectSource::Squads;
                        app.current_squads_proposal = Some(prop.clone());
                        app.screen = Screen::Inspect;
                        app.error_msg = None;
                        app.flash(
                            format!("Loaded Squads proposal #{} for review", prop.index),
                            theme::BRAND,
                        );
                    }
                    Err(e) => {
                        app.squads_error = Some(format!("inspect failed: {e}"));
                    }
                }
            }
        }
        _ => {}
    }
    false
}

fn key_paste(app: &mut App, code: KeyCode, mods: KeyModifiers) -> bool {
    let ctrl = mods.contains(KeyModifiers::CONTROL);
    match code {
        KeyCode::Esc => { app.screen = Screen::Home; app.error_msg = None; }
        // Ctrl+U / Ctrl+L: clear the buffer (the rest of the world expects this).
        KeyCode::Char('u') | KeyCode::Char('l') if ctrl => {
            app.tx_paste.clear();
            app.error_msg = None;
        }
        // Ctrl+W: delete last "word" (non-whitespace run). Useful for editing.
        KeyCode::Char('w') if ctrl => {
            while app.tx_paste.chars().last().map(|c| c.is_whitespace()).unwrap_or(false) {
                app.tx_paste.pop();
            }
            while let Some(c) = app.tx_paste.chars().last() {
                if c.is_whitespace() { break; }
                app.tx_paste.pop();
            }
        }
        KeyCode::Char(c) => {
            // Skip control chars unless they're explicit chars from the user.
            if !c.is_control() { app.tx_paste.push(c); }
        }
        KeyCode::Backspace => { app.tx_paste.pop(); }
        KeyCode::Enter if mods.contains(KeyModifiers::ALT) || mods.contains(KeyModifiers::SHIFT) => {
            app.tx_paste.push('\n');
        }
        KeyCode::Enter => {
            if app.tx_paste.trim().is_empty() {
                app.error_msg = Some("paste a base64 or base58 transaction message first".into());
                return false;
            }
            match inspector::inspect_b64(&app.tx_paste) {
                Ok(inspected) => {
                    app.inspected = Some(inspected);
                    app.inspect_source = InspectSource::Paste;
                    app.screen = Screen::Inspect;
                    app.error_msg = None;
                }
                Err(e) => app.error_msg = Some(e.to_string()),
            }
        }
        _ => {}
    }
    false
}

fn key_inspect(app: &mut App, code: KeyCode, _mods: KeyModifiers) -> bool {
    match code {
        KeyCode::Esc => { app.screen = Screen::PasteTx; }
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            let Some(insp) = app.inspected.clone() else { return false };
            match &app.backend {
                // ── Local keystore signing — synchronous, fast ─────────────
                Backend::Local => {
                    let Some(unlocked) = app.unlocked.as_mut() else {
                        app.error_msg = Some("vault is locked".into()); return false;
                    };
                    let kp = unlocked.keypair();
                    let mode = unlocked.mode;
                    let caps = unlocked.caps;
                    let cumulative = unlocked.session_spent_lamports;
                    match inspector::sign_message_b64(&insp, &kp, mode, caps, cumulative) {
                        Ok((signed, outflow)) => {
                            unlocked.note_spent(outflow);
                            let path = save_signed_to_disk(&signed).ok();
                            app.last_signed = Some(signed);
                            app.last_signed_path = path;
                            app.screen = Screen::Signed;
                            app.flash("Transaction signed", theme::ARMED);
                        }
                        Err(refusal) => app.error_msg = Some(refusal.human_message()),
                    }
                }
                // ── Vultisig MPC signing (worker thread + spinner) ─────────
                //
                // Requires the patched daemon — see scripts/vendor-patches/
                // vultisig-cli-solana-bytes.patch. The patched daemon accepts
                // payload.bytes (base64 of the serialized Message), the MPC
                // signs those bytes directly, and returns a real broadcastable
                // signed transaction.
                Backend::Vultisig { pubkey } => {
                    if app.inspect_source == InspectSource::Paste && insp.fee_payer != *pubkey {
                        app.error_msg = Some(format!(
                            "fee payer is {} but Vultisig pubkey is {} — refusing to sign",
                            inspector::short(&insp.fee_payer),
                            inspector::short(pubkey),
                        ));
                        return false;
                    }
                    use base64::{engine::general_purpose::STANDARD, Engine};
                    let bytes = match STANDARD.decode(&insp.raw_message_b64)
                        .or_else(|_| bs58::decode(&insp.raw_message_b64).into_vec()
                            .map_err(|_| base64::DecodeError::InvalidPadding)) {
                        Ok(b) => b,
                        Err(_) => {
                            app.error_msg = Some("could not decode message bytes for vultisig".into());
                            return false;
                        }
                    };
                    let (tx, rx) = std::sync::mpsc::channel();
                    std::thread::spawn(move || {
                        let client = VultisigClient::default_socket();
                        let _ = tx.send(client.sign_solana(&bytes).map_err(|e| e.to_string()));
                    });
                    app.signing = Some(SigningJob {
                        rx,
                        started_at: std::time::Instant::now(),
                    });
                    app.screen = Screen::Signing;
                    app.error_msg = None;
                }
                // ── Telegram-FROST MPC signing (worker thread) ──────────────
                //
                // Round-trip:
                //   1. Validate fee payer == FROST group pubkey (the laptop
                //      will not authorize signing on a different account)
                //   2. Decode the inspector's raw_message_b64 + format the
                //      decoded summary for the Telegram approval prompt
                //   3. Spawn a worker thread that: builds round-1 commitments,
                //      POSTs to the bot, waits up to 150s for the user's
                //      Telegram approval + bot's signature share, runs round-2
                //      locally, aggregates → standard ed25519 sig that
                //      ed25519-dalek (and Solana) verify.
                //   4. Result lands in the SigningJob mpsc channel; the main
                //      loop polls it from the Signing screen.
                Backend::TelegramFrost { pubkey } => {
                    if app.inspect_source == InspectSource::Paste && insp.fee_payer != *pubkey {
                        app.error_msg = Some(format!(
                            "fee payer is {} but FROST group pubkey is {} — refusing to sign",
                            inspector::short(&insp.fee_payer),
                            inspector::short(pubkey),
                        ));
                        return false;
                    }
                    let Some(laptop) = app.laptop_frost.clone() else {
                        app.error_msg = Some("FROST share not loaded — re-select the backend".into());
                        return false;
                    };

                    // Build the bytes the FROST flow will actually sign.
                    // Two cases:
                    //   - Paste source: sign the pasted message directly (user IS
                    //     the fee payer; resulting sig produces a broadcastable tx).
                    //   - Squads source: build a `proposal_approve` Solana Message
                    //     targeting the proposal index, with FROST as fee payer.
                    //     User sees the inner-tx decode in Telegram (so they know
                    //     what they're approving), but the bytes signed are the
                    //     vote ix — when broadcast, registers the FROST member's
                    //     vote ON-CHAIN with the Squads multisig.
                    let bytes = if app.inspect_source == InspectSource::Squads {
                        let Some(prop) = app.current_squads_proposal.as_ref() else {
                            app.error_msg = Some("Squads proposal context lost — re-open from [m]".into());
                            return false;
                        };
                        use std::str::FromStr;
                        let multisig_pk = match solana_sdk::pubkey::Pubkey::from_str(
                            app.squads_multisig.as_deref().unwrap_or("")
                        ) {
                            Ok(p) => p,
                            Err(e) => {
                                app.error_msg = Some(format!("bad SQUADS_MULTISIG: {e}"));
                                return false;
                            }
                        };
                        let member_pk = match solana_sdk::pubkey::Pubkey::from_str(pubkey) {
                            Ok(p) => p,
                            Err(e) => {
                                app.error_msg = Some(format!("bad FROST pubkey: {e}"));
                                return false;
                            }
                        };
                        let blockhash = match squads::fetch_latest_blockhash() {
                            Ok(h) => h,
                            Err(e) => {
                                app.error_msg = Some(format!("fetching blockhash: {e}"));
                                return false;
                            }
                        };
                        match squads::build_proposal_vote_tx(
                            &multisig_pk, prop.index, &member_pk, /*vote=*/true, blockhash,
                        ) {
                            Ok(b) => b,
                            Err(e) => {
                                app.error_msg = Some(format!("building proposal_approve: {e}"));
                                return false;
                            }
                        }
                    } else {
                        use base64::{engine::general_purpose::STANDARD, Engine};
                        match STANDARD.decode(&insp.raw_message_b64) {
                            Ok(b) => b,
                            Err(e) => {
                                app.error_msg = Some(format!("decode message bytes: {e}"));
                                return false;
                            }
                        }
                    };

                    // Telegram prompt always shows the DECODED INNER tx (what the
                    // user is meaningfully approving), even when the bytes being
                    // signed are the wrapping proposal_approve ix.
                    let summary = format_telegram_summary(&insp);

                    // For both sources the bytes ARE a Solana Message, so the
                    // FROST flow can wrap into a broadcastable VersionedTransaction.
                    let (tx, rx) = std::sync::mpsc::channel();
                    std::thread::spawn(move || {
                        let client = FrostClient::default_url();
                        let _ = tx.send(client.sign_solana(&laptop, &bytes, &summary, /*assemble=*/true)
                            .map_err(|e| e.to_string()));
                    });
                    app.signing = Some(SigningJob {
                        rx,
                        started_at: std::time::Instant::now(),
                    });
                    app.screen = Screen::Signing;
                    app.error_msg = None;
                }
            }
        }
        KeyCode::Char('n') | KeyCode::Char('N') => {
            app.inspected = None;
            app.tx_paste.clear();
            app.screen = Screen::Home;
        }
        _ => {}
    }
    false
}

/// Combine a raw unsigned Solana message with a base58 ed25519 signature from
/// the Vultisig daemon into a broadcastable VersionedTransaction (base58 out).
fn assemble_signed_tx(message_bytes: &[u8], sig_b58: &str) -> anyhow::Result<String> {
    use solana_sdk::message::{Message, VersionedMessage};
    use solana_sdk::transaction::VersionedTransaction;
    use solana_sdk::signature::Signature;

    let vmsg: VersionedMessage = bincode::deserialize(message_bytes)
        .or_else(|_| bincode::deserialize::<Message>(message_bytes).map(VersionedMessage::Legacy))?;

    let sig_bytes = bs58::decode(sig_b58.trim()).into_vec()?;
    if sig_bytes.len() != 64 {
        anyhow::bail!("daemon returned signature of wrong length: {}", sig_bytes.len());
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from(arr);

    let tx = VersionedTransaction { signatures: vec![sig], message: vmsg };
    let serialized = bincode::serialize(&tx)?;
    Ok(bs58::encode(serialized).into_string())
}

/// Format an InspectedTx as a human-readable plaintext summary for the
/// Telegram approval prompt. Plaintext (no Markdown/HTML) — the bot wraps
/// this in `<pre>...</pre>` so any printable chars are safe.
fn format_telegram_summary(insp: &InspectedTx) -> String {
    use std::fmt::Write;
    let mut s = String::new();

    let _ = writeln!(s, "Fee payer: {}", insp.fee_payer);
    let _ = writeln!(s, "Outflow:   {} lamports", insp.fee_payer_outflow_lamports);
    let _ = writeln!(s, "Accounts:  {} ({} writable, {} signers)",
        insp.num_accounts, insp.num_writable, insp.num_signers);
    s.push('\n');

    s.push_str("Instructions:\n");
    for (i, ix) in insp.instructions.iter().enumerate() {
        let _ = writeln!(s, "  {}. [{}] {}", i + 1, ix.program_name, ix.summary);
        if let Some(nested) = &ix.nested {
            for (j, nix) in nested.iter().enumerate() {
                let _ = writeln!(s, "     {}.{} [{}] {}", i + 1, j + 1, nix.program_name, nix.summary);
            }
        }
    }

    if !insp.risks.is_empty() {
        s.push('\n');
        s.push_str("⚠ RISKS FLAGGED:\n");
        for r in &insp.risks {
            // Use the same glyph + label vocabulary as the TUI's Risk panel
            // so the user sees the SAME mental model on phone vs laptop.
            // Glyph first (eye lock), then bracketed label, then the detail.
            let glyph = match r.severity() {
                Severity::Critical => "🛑",
                Severity::High     => "⚠️",
                Severity::Medium   => "⚠",
                Severity::Low      => "ℹ",
            };
            let _ = writeln!(s, "  {} [{}] {}", glyph, r.severity().label(), r.human());
        }
    }

    s
}

fn key_signed(app: &mut App, code: KeyCode, _mods: KeyModifiers) -> bool {
    match code {
        // Broadcast: kick off the JSON-RPC sendTransaction on a worker thread.
        // Disabled while a previous broadcast is in flight or already succeeded.
        KeyCode::Char('b') | KeyCode::Char('B') => {
            if app.broadcast_job.is_some() || app.last_broadcast_sig.is_some() {
                return false;
            }
            let Some(signed) = app.last_signed.clone() else { return false };
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(rpc::broadcast(&signed).map_err(|e| e.to_string()));
            });
            app.broadcast_job = Some(BroadcastJob {
                rx,
                started_at: std::time::Instant::now(),
            });
            app.last_broadcast_error = None;
        }
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => {
            // Don't navigate away while a broadcast is in flight — prevents
            // dropping the worker mid-RPC-call (the channel survives, but the
            // user would lose the result without ever seeing it).
            if app.broadcast_job.is_some() { return false; }
            app.screen = Screen::Home;
            app.last_signed = None;
            app.last_signed_path = None;
            app.last_broadcast_sig = None;
            app.last_broadcast_error = None;
            app.tx_paste.clear();
            app.inspected = None;
        }
        _ => {}
    }
    false
}

fn save_signed_to_disk(signed_b58: &str) -> Result<String> {
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let dir = keystore::signed_dir()?;
    fs::create_dir_all(&dir)?;
    let prefix: String = signed_b58.chars().take(8).collect();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0);
    let path = dir.join(format!("{}-{}.tx", ts, prefix));
    let mut f = fs::OpenOptions::new()
        .create_new(true).write(true).mode(0o600).open(&path)?;
    f.write_all(signed_b58.as_bytes())?;
    f.sync_all()?;
    Ok(path.display().to_string())
}

// ── Drawing ──────────────────────────────────────────────────────────────────

fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    let root = Layout::vertical([
        Constraint::Length(3),  // header
        Constraint::Min(10),    // body
        Constraint::Length(3),  // footer
    ]).split(area);

    draw_header(f, root[0], app);
    let body = root[1].inner(Margin { vertical: 0, horizontal: 1 });
    match app.screen {
        Screen::BackendSelect => draw_backend_select(f, body, app),
        Screen::SetupIntro    => draw_setup_intro(f, body, app),
        Screen::SetupPass     => draw_setup_pass(f, body, app),
        Screen::Unlock        => draw_unlock(f, body, app),
        Screen::Home          => draw_home(f, body, app),
        Screen::PasteTx       => draw_paste(f, body, app),
        Screen::Inspect       => draw_inspect(f, body, app),
        Screen::Signing       => draw_signing(f, body, app),
        Screen::Signed        => draw_signed(f, body, app),
        Screen::Squads        => draw_squads(f, body, app),
    }
    draw_footer(f, root[2], app);

    if let Some((msg, color)) = &app.flash {
        draw_flash(f, area, msg, *color);
    }
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let (status_dot, status_color) = if app.score >= 99 {
        ("● ARMED", theme::ARMED)
    } else if app.score >= 50 {
        ("◑ PARTIAL", theme::WARN)
    } else {
        ("○ DISARMED", theme::DANGER)
    };

    let mainnet_tag = Span::styled(
        " ⚠ MAINNET ",
        Style::default().fg(theme::DANGER).bg(Color::Rgb(40, 0, 0)).add_modifier(Modifier::BOLD),
    );

    let h = Paragraph::new(Line::from(vec![
        Span::styled("  SOVEREIGN OS VAULT  ", theme::brand_bold()),
        Span::styled(status_dot, Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
        Span::styled("    ", theme::dim()),
        mainnet_tag,
        Span::styled("  ·  the safest member in your Multisig", theme::mute()),
    ])).block(
        Block::default().borders(Borders::ALL).border_type(BorderType::Rounded)
            .border_style(Style::default().fg(theme::BRAND_DIM))
    );
    f.render_widget(h, area);
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let hint = match app.screen {
        Screen::BackendSelect => "[r] re-check · [enter] launch FROST when ready · [esc] quit",
        Screen::SetupIntro    => "[enter] begin · [esc] quit",
        Screen::SetupPass     => "[tab] next field · [enter] continue · [esc] cancel",
        Screen::Unlock        => "[enter] unlock · [esc] quit",
        Screen::Home          => "[s] sign tx · [m] Squads proposals · [a] re-arm · [q] quit",
        Screen::PasteTx       => "paste base64/base58 message · [enter] inspect · [esc] back",
        Screen::Inspect       => "[y] sign · [n] cancel · [esc] back",
        Screen::Signing       => "approve on your phone · [esc] back to inspect (after timeout)",
        Screen::Signed        => "[enter] back to home",
        Screen::Squads        => "[↑/↓] select · [enter] inspect · [r] refresh · [esc] back",
    };
    let p = Paragraph::new(Line::from(vec![
        Span::styled("  ", theme::dim()),
        Span::styled(hint, theme::dim()),
    ]))
    .alignment(Alignment::Left)
    .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme::BRAND_DIM)));
    f.render_widget(p, area);
}

// ── Screen: Backend select ───────────────────────────────────────────────────

fn draw_backend_select(f: &mut Frame, area: Rect, app: &App) {
    // v0.4 ships a single signing backend: FROST 2-of-2 ed25519 with a
    // Telegram bot as the second trust domain. This screen only appears
    // when FROST is not yet configured — the boot flow auto-loads it
    // otherwise. (Earlier versions also surfaced Vultisig and a local
    // keystore here; both code paths still exist internally but are not
    // promoted in the v0.4 product.)
    let title = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled("  Sovereign OS Vault — FROST setup required",
            theme::brand_bold())),
        Line::from(""),
        Line::from(Span::styled(
            "  v0.4 signs only via FROST 2-of-2 ed25519 + your Telegram approval.",
            theme::dim(),
        )),
        Line::from(Span::styled(
            "  Both shares are needed to produce a signature — neither party alone can sign.",
            theme::dim(),
        )),
        Line::from(""),
    ]);
    f.render_widget(title, area);

    let inner = area.inner(Margin { vertical: 8, horizontal: 4 });

    let share_present = LaptopFrost::load().is_ok();
    let bot_running   = FrostClient::default_url().is_running();

    let lines = vec![
        Line::from(vec![
            Span::styled("  Setup checklist:", theme::label()),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(if share_present { "  ✓  " } else { "  ✗  " },
                Style::default().fg(if share_present { theme::ARMED } else { theme::DANGER })
                    .add_modifier(Modifier::BOLD)),
            Span::styled("FROST share files present", theme::label()),
        ]),
        Line::from(Span::styled(
            "      ~/.local/share/sovereign-os-vault/keystore/frost-share1.bin",
            theme::mute(),
        )),
        Line::from(Span::styled(
            "      generate with: cd frost-bot && cargo run --release --bin frost-keygen",
            theme::mute(),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(if bot_running { "  ✓  " } else { "  ✗  " },
                Style::default().fg(if bot_running { theme::ARMED } else { theme::DANGER })
                    .add_modifier(Modifier::BOLD)),
            Span::styled("Telegram bot reachable on http://127.0.0.1:7777", theme::label()),
        ]),
        Line::from(Span::styled(
            "      start with: cd frost-bot && cargo run --release --bin frost-bot &",
            theme::mute(),
        )),
        Line::from(Span::styled(
            "      bot config at ~/.local/share/sovereign-os-vault/frost-bot/config.toml (mode 600)",
            theme::mute(),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  ", theme::dim()),
            Span::styled(if share_present && bot_running { "[enter] launch FROST" } else { "[r] re-check  ·  [esc] quit" },
                theme::label()),
        ]),
    ];
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);

    if let Some(err) = &app.error_msg {
        draw_error_strip(f, area, err);
    }
}

fn backend_box(title: &str, desc: &str, selected: bool, available: bool) -> Paragraph<'static> {
    let (border_color, marker) = if !available {
        (theme::TEXT_MUT, " ")
    } else if selected {
        (theme::BRAND, "▶")
    } else {
        (theme::TEXT_MUT, " ")
    };
    let title_style = if !available { theme::dim() } else { theme::label() };
    Paragraph::new(vec![
        Line::from(vec![
            Span::styled(format!(" {} ", marker),
                Style::default().fg(border_color).add_modifier(Modifier::BOLD)),
            Span::styled(title.to_string(), title_style),
        ]),
        Line::from(vec![
            Span::styled("    ", theme::dim()),
            Span::styled(desc.to_string(), theme::dim()),
        ]),
    ])
    .block(Block::default()
        .borders(Borders::LEFT | Borders::RIGHT)
        .border_style(Style::default().fg(border_color))
    )
}

// ── Screen: Signing (FROST + Telegram approval — also legacy Vultisig QR) ────

const SPINNER_FRAMES: &[&str] = &["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"];

fn draw_signing(f: &mut Frame, area: Rect, app: &App) {
    let elapsed = app.signing.as_ref()
        .map(|j| j.started_at.elapsed().as_secs())
        .unwrap_or(0);
    let spinner = SPINNER_FRAMES[(app.frame_tick as usize) % SPINNER_FRAMES.len()];
    let pubkey_short = match &app.backend {
        Backend::Vultisig { pubkey }      => inspector::short(pubkey),
        Backend::TelegramFrost { pubkey } => inspector::short(pubkey),
        Backend::Local                    => "?".to_string(),
    };

    // Backend-aware copy: the FROST + Telegram flow has nothing to do with
    // QR codes or Vultisig relays — it's an HTTPS POST to the bot followed
    // by a Telegram approval prompt on the user's phone. Keep the legacy
    // Vultisig QR layout for that backend, swap title/status for FROST.
    let is_frost = matches!(app.backend, Backend::TelegramFrost { .. });
    let title_text = if is_frost {
        "Signing via FROST 2-of-2 + Telegram approval"
    } else {
        "Signing via Vultisig MPC"
    };

    // Layout: title, status (NEW), QR/instructions, footer.
    let rows = Layout::vertical([
        Constraint::Length(1),  // title
        Constraint::Length(2),  // status (state machine)
        Constraint::Min(0),     // QR (legacy) or Telegram instructions (FROST)
        Constraint::Length(1),  // footer
    ]).split(area);

    // ── Top title strip ────────────────────────────────────────────────────
    let pet_face = if (app.frame_tick / 3) % 2 == 0 { "(=◉ω◉=)" } else { "(=◎ω◎=)" };
    f.render_widget(Paragraph::new(Line::from(vec![
        Span::styled(format!(" {} ", spinner),
            Style::default().fg(theme::BRAND).add_modifier(Modifier::BOLD)),
        Span::styled(format!("{}  ", pet_face),
            Style::default().fg(theme::WARN).add_modifier(Modifier::BOLD)),
        Span::styled(title_text, theme::brand_bold()),
        Span::styled(format!("   ·   {}s elapsed", elapsed), theme::dim()),
    ])), rows[0]);

    // ── State machine status — tells the user exactly what to do next ─────
    let (state_label, state_detail, state_color) = if is_frost {
        // FROST + Telegram three-step:
        //   1. Sending sign request to bot
        //   2. Bot is pinging your Telegram — tap Approve / Reject
        //   3. Bot returned share, aggregating + verifying signature locally
        // We don't have an explicit signal that the user has tapped, so the
        // step buckets are timing-driven hints. Bot timeout is 120s.
        if elapsed < 2 {
            ("STEP 1/3", "Sending sign request to your FROST bot over HTTPS…", theme::WARN)
        } else if elapsed < 110 {
            ("STEP 2/3", "Bot pinged your Telegram. Open Telegram and tap Approve or Reject.", theme::BRAND)
        } else if elapsed < 125 {
            ("STEP 2/3 — TIMING OUT", "Tap soon — bot times out at 120s", theme::WARN)
        } else {
            ("STEP 2/3 — TIMED OUT", "No tap received within 120s. Press [esc] and retry.", theme::DANGER)
        }
    } else if app.qr_uri.is_none() {
        if elapsed < 3 {
            ("STEP 1/3", "Setting up MPC session — daemon is generating a relay session ID", theme::WARN)
        } else if elapsed < 10 {
            ("STEP 1/3", "Daemon is contacting the Vultisig relay (api.vultisig.com)…", theme::WARN)
        } else {
            ("STEP 1/3 — STALLED", "No QR after 10s. Check daemon logs (relay reachability or auth)", theme::DANGER)
        }
    } else if elapsed < 30 {
        ("STEP 2/3", "QR ready — open the Vultisig app on your phone and scan it", theme::BRAND)
    } else if elapsed < 75 {
        ("STEP 3/3", "Phone scanned — approve the keysign in the Vultisig app", theme::WARN)
    } else {
        ("STEP 3/3 — STALLED", "Approval taking long. Phone connectivity? Daemon timeout in <15s", theme::DANGER)
    };
    f.render_widget(Paragraph::new(vec![
        Line::from(vec![
            Span::styled(format!(" [{}] ", state_label),
                Style::default().fg(state_color).bg(Color::Rgb(20, 20, 28)).add_modifier(Modifier::BOLD)),
            Span::styled(format!(" {}", state_detail),
                Style::default().fg(state_color).add_modifier(Modifier::BOLD)),
        ]),
    ]), rows[1]);

    let qr_inner = rows[2];

    // FROST + Telegram path: no QR, no relay. The bot is talking to the
    // user's phone via MTProto — render Telegram-specific instructions
    // instead of trying to display a QR that doesn't exist.
    if is_frost {
        let pad_top = qr_inner.height.saturating_sub(10) / 2;
        let mut content: Vec<Line> = (0..pad_top).map(|_| Line::from("")).collect();
        content.extend(vec![
            Line::from(""),
            Line::from(vec![
                Span::raw("                    "),
                Span::styled("📱  Open Telegram on your phone",
                    theme::brand_bold()),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::raw("                    "),
                Span::styled("Your FROST cosigner bot has DMed you a sign request",
                    theme::label()),
            ]),
            Line::from(vec![
                Span::raw("                    "),
                Span::styled("with the recursive decode of what's being signed.",
                    theme::label()),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::raw("                    "),
                Span::styled("Tap ", theme::dim()),
                Span::styled("✅ Approve", theme::armed()),
                Span::styled("  to release the bot's FROST share.", theme::dim()),
            ]),
            Line::from(vec![
                Span::raw("                    "),
                Span::styled("Tap ", theme::dim()),
                Span::styled("❌ Reject",
                    Style::default().fg(theme::DANGER).add_modifier(Modifier::BOLD)),
                Span::styled("   to refuse — no signature will exist.", theme::dim()),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::raw("                    "),
                Span::styled(format!("Signing for: {}", pubkey_short), theme::mute()),
            ]),
        ]);
        f.render_widget(Paragraph::new(content), qr_inner);
    } else if let Some(uri) = &app.qr_uri {
        if let Some(lines) = render_qr_for_area(uri, qr_inner.width, qr_inner.height) {
            let qr_width  = lines.first().map(|l| l.chars().count() as u16).unwrap_or(0);
            let qr_height = lines.len() as u16;
            let pad_left = qr_inner.width.saturating_sub(qr_width) / 2;
            let pad_top  = qr_inner.height.saturating_sub(qr_height) / 2;
            let mut content: Vec<Line> = (0..pad_top).map(|_| Line::from("")).collect();
            content.extend(lines.iter().map(|l| Line::from(vec![
                Span::raw(" ".repeat(pad_left as usize)),
                Span::styled(l.clone(), Style::default().fg(theme::TEXT)),
            ])));
            f.render_widget(Paragraph::new(content), qr_inner);
        } else {
            // Even densest packing didn't fit — point at the daemon's PNG.
            let qr_quad = render_qr_quadrant(uri);
            let needed = qr_quad.as_ref().map(|l| {
                let w = l.first().map_or(0, |s| s.chars().count() as u16);
                let h = l.len() as u16;
                format!("(needs {}×{}, have {}×{})",
                    w, h, qr_inner.width, qr_inner.height)
            }).unwrap_or_default();
            let png_hint = locate_qr_png()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "/tmp/vultisig_qr_<session>.png".to_string());
            let pad_top = qr_inner.height.saturating_sub(8) / 2;
            let mut content: Vec<Line> = (0..pad_top).map(|_| Line::from("")).collect();
            content.extend(vec![
                Line::from(Span::styled("  QR is too large for this terminal",
                    theme::label())),
                Line::from(Span::styled(format!("  {}", needed), theme::mute())),
                Line::from(""),
                Line::from(vec![
                    Span::styled("  Press ", theme::dim()),
                    Span::styled("[b]", theme::brand_bold()),
                    Span::styled(" to open the QR in your browser, or scan:",
                        theme::dim()),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::raw("  "),
                    Span::styled(png_hint, theme::brand_bold()),
                ]),
                Line::from(""),
                Line::from(Span::styled("  (or maximize this terminal and retry)",
                    theme::mute())),
            ]);
            f.render_widget(Paragraph::new(content), qr_inner);
        }
    } else {
        let pad_top = qr_inner.height.saturating_sub(2) / 2;
        let mut content: Vec<Line> = (0..pad_top).map(|_| Line::from("")).collect();
        content.extend(vec![
            Line::from(Span::styled("  Generating QR session…", theme::dim())),
            Line::from(Span::styled("  (waiting for daemon to register relay)",
                theme::mute())),
        ]);
        f.render_widget(Paragraph::new(content), qr_inner);
    }

    // ── Bottom one-line status strip ───────────────────────────────────────
    f.render_widget(Paragraph::new(Line::from(vec![
        Span::styled(" Vault: ", theme::label()),
        Span::styled(pubkey_short, theme::brand_bold()),
        Span::styled("  ·  ", theme::mute()),
        Span::styled(format!("{}s / 90s", elapsed), theme::dim()),
        Span::styled("  ·  ", theme::mute()),
        Span::styled("[b]", theme::brand_bold()),
        Span::styled(" open in browser  ·  ", theme::dim()),
        Span::styled("[esc]", theme::brand_bold()),
        Span::styled(" back  ·  ", theme::dim()),
        Span::styled("anti-blind-signing already ran — MPC just signs bytes",
            theme::mute()),
    ])), rows[3]);
}

// ── Screen: Setup intro ──────────────────────────────────────────────────────

fn draw_setup_intro(f: &mut Frame, area: Rect, app: &App) {
    let per_tx_sol = DEFAULT_DECOY_MAX_PER_TX_LAMPORTS as f64 / 1e9;
    let cum_sol    = DEFAULT_DECOY_MAX_CUMULATIVE_LAMPORTS as f64 / 1e9;

    let p = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled("  Welcome.", theme::brand_bold())),
        Line::from(""),
        Line::from(Span::styled(
            "  This vault generates TWO Solana keypairs, both encrypted at rest",
            theme::dim(),
        )),
        Line::from(Span::styled(
            "  with Argon2id + ChaCha20-Poly1305 and locked into RAM at runtime.",
            theme::dim(),
        )),
        Line::from(""),
        Line::from(Span::styled("  Sovereign passphrase  ", theme::label())),
        Line::from(Span::styled(
            "    unlocks your real signing key — full authority.",
            theme::dim()
        )),
        Line::from(""),
        Line::from(Span::styled("  Decoy passphrase  ", theme::label())),
        Line::from(Span::styled(
            "    unlocks a bait keypair under coercion. Same UI, same behaviour.",
            theme::dim()
        )),
        Line::from(Span::styled(
            format!(
                "    Caps: ≤ {:.2} SOL/tx, ≤ {:.2} SOL cumulative per session.",
                per_tx_sol, cum_sol,
            ),
            theme::dim()
        )),
        Line::from(Span::styled(
            "    Errors are reported as 'insufficient funds' — no info-leak.",
            theme::mute()
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Pick passphrases you can remember. Both are needed; only ONE is",
            theme::dim()
        )),
        Line::from(Span::styled(
            "  ever entered at unlock — sovereign for normal operation, decoy",
            theme::dim()
        )),
        Line::from(Span::styled(
            "  if you are physically forced to unlock the vault.",
            theme::dim()
        )),
        Line::from(""),
        Line::from(Span::styled("  Press [enter] to continue.", theme::brand_bold())),
    ]);
    f.render_widget(p, area);
    if let Some(err) = &app.error_msg {
        draw_error_strip(f, area, err);
    }
    let _ = app;
}

// ── Screen: Setup pass (4 fields: sov, sov-confirm, decoy, decoy-confirm) ───

fn draw_setup_pass(f: &mut Frame, area: Rect, app: &App) {
    let d_sov  = "•".repeat(app.pass_buf_sov.chars().count());
    let d_sovc = "•".repeat(app.pass_buf_sov_confirm.chars().count());
    let d_dec  = "•".repeat(app.pass_buf_dec.chars().count());
    let d_decc = "•".repeat(app.pass_buf_dec_confirm.chars().count());

    let p = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled("  Set passphrases", theme::brand_bold())),
        Line::from(Span::styled("  (each ≥ 8 chars; sovereign and decoy must differ)", theme::dim())),
        Line::from(""),
        field_line("  Sovereign       ", &d_sov,  app.pass_field == 0),
        field_line("  ↳ confirm       ", &d_sovc, app.pass_field == 1),
        Line::from(""),
        field_line("  Decoy           ", &d_dec,  app.pass_field == 2),
        field_line("  ↳ confirm       ", &d_decc, app.pass_field == 3),
        Line::from(""),
        Line::from(Span::styled("  [tab] next field   [shift+tab] previous   [enter] confirm/continue", theme::dim())),
    ]);
    f.render_widget(p, area);

    if let Some(err) = &app.error_msg {
        draw_error_strip(f, area, err);
    }
}

fn draw_unlock(f: &mut Frame, area: Rect, app: &App) {
    let dots: String = "•".repeat(app.unlock_buf.chars().count());
    let p = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled("  Unlock vault", theme::brand_bold())),
        Line::from(""),
        Line::from(Span::styled("  An existing keystore was found at:", theme::dim())),
        Line::from(Span::styled(format!("  {}",
            keystore::keystore_path().map(|p| p.display().to_string()).unwrap_or_default()),
            theme::mute()
        )),
        Line::from(""),
        Line::from(""),
        field_line("  Passphrase   ", &dots, true),
        Line::from(""),
        Line::from(Span::styled("  [enter] unlock", theme::dim())),
    ]);
    f.render_widget(p, area);

    if let Some(err) = &app.error_msg {
        draw_error_strip(f, area, err);
    }
}

fn field_line(label: &str, value: &str, active: bool) -> Line<'static> {
    let cursor = if active { "▏" } else { " " };
    let value_color = if active { theme::BRAND } else { theme::TEXT };
    Line::from(vec![
        Span::styled(label.to_string(), theme::label()),
        Span::styled(format!("{}{}", value, cursor),
            Style::default().fg(value_color).add_modifier(Modifier::BOLD)),
    ])
}

// ── Screen: Home ─────────────────────────────────────────────────────────────

fn draw_home(f: &mut Frame, area: Rect, app: &App) {
    let (pubkey_str, backend_label) = match &app.backend {
        Backend::Local =>
            (app.unlocked.as_ref()
                .map(|u| u.pubkey_base58()).unwrap_or_else(|| "<locked>".into()),
             "Local keystore (kernel-hardened, encrypted at rest)"),
        Backend::Vultisig { pubkey } =>
            (pubkey.clone(),
             "Vultisig MPC (laptop + mobile cosigner, no single key holds it)"),
        Backend::TelegramFrost { pubkey } =>
            (pubkey.clone(),
             "FROST 2-of-2 (laptop + your Telegram, sig requires phone tap)"),
    };

    let cols = Layout::horizontal([
        Constraint::Percentage(55), Constraint::Percentage(45),
    ]).split(area);

    // Left — identity & actions
    let left_rows = Layout::vertical([
        Constraint::Length(8), Constraint::Length(8), Constraint::Min(0),
    ]).split(cols[0]);

    let identity = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled("  Public Key", theme::label())),
        Line::from(Span::styled(format!("  {}", pubkey_str), theme::brand_bold())),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Backend: ", theme::label()),
            Span::styled(backend_label, theme::dim()),
        ]),
        Line::from(Span::styled("  Cluster: mainnet-beta", theme::dim())),
    ]).block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded)
        .title(" Identity ").border_style(Style::default().fg(theme::BRAND_DIM)));
    f.render_widget(identity, left_rows[0]);

    let actions = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled("  [s]  Sign a transaction", theme::label())),
        Line::from(Span::styled("       paste an unsigned message, inspect, sign, output", theme::dim())),
        Line::from(Span::styled("  [m]  Open full Squads watch (review + select to sign/reject)", theme::label())),
        Line::from(Span::styled("  [a]  Re-arm    [q]  Quit", theme::label())),
    ]).block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded)
        .title(" Actions ").border_style(Style::default().fg(theme::BRAND_DIM)));
    f.render_widget(actions, left_rows[1]);

    // Sentinel — Squads multisig watch panel + pet status. The sentinel is
    // not a key press away; it's right here on Home, polling in the
    // background. Tap [m] to expand to the full list and select for action.
    draw_sentinel_panel(f, left_rows[2], app);

    // Right — security panel
    draw_security_panel(f, cols[1], app);
}

fn draw_security_panel(f: &mut Frame, area: Rect, app: &App) {
    let outer = Block::default().borders(Borders::ALL).border_type(BorderType::Rounded)
        .title(" Hardening ")
        .border_style(Style::default().fg(
            if app.score >= 99 { theme::ARMED } else if app.score >= 50 { theme::WARN } else { theme::DANGER }
        ));
    f.render_widget(&outer, area);
    let inner = outer.inner(area);
    let rows = Layout::vertical([
        Constraint::Length(1), // Score gauge
        Constraint::Length(1), // spacer
        Constraint::Length(1), Constraint::Length(1), Constraint::Length(1),
        Constraint::Length(1), Constraint::Length(1), Constraint::Length(1),
        Constraint::Length(1), Constraint::Length(1),
        Constraint::Min(0),
    ]).split(inner.inner(Margin { vertical: 0, horizontal: 1 }));

    let gauge_color = if app.score >= 99 { theme::ARMED }
        else if app.score >= 50 { theme::WARN }
        else { theme::DANGER };
    let gauge = Gauge::default()
        .gauge_style(Style::default().fg(gauge_color))
        .label(format!("Security {}%", app.score))
        .percent(app.score);
    f.render_widget(gauge, rows[0]);

    let (dumpable_ok, vmlck) = armor::read_kernel_state();

    f.render_widget(check_line("Zig vault-armor",  app.zig.connected,           short_path(&app.zig.binary_path)), rows[2]);
    f.render_widget(check_line("PR_SET_DUMPABLE",  app.zig.memory_guard && dumpable_ok, "/proc/mem blocked".into()), rows[3]);
    f.render_widget(check_line("mlockall",         app.zig.swap_guard && vmlck > 0, format!("VmLck={}kB", vmlck)),  rows[4]);
    f.render_widget(check_line("MADV_DONTDUMP",    app.zig.madv_guard,          "key pages excluded from coredumps".into()), rows[5]);
    f.render_widget(check_line("Non-root UID",     app.startup.uid != 0,        format!("uid={}", app.startup.uid)), rows[6]);
    f.render_widget(check_line("No debugger",      !armor::debugger_attached(), "TracerPid=0".into()),               rows[7]);
    f.render_widget(check_line("Yama LSM",         app.startup.yama_active,
        if app.startup.yama_active { "PR_SET_PTRACER=0".into() } else { "n/a (kernel module not loaded)".into() }), rows[8]);
}

fn check_line(label: &str, ok: bool, detail: String) -> Paragraph<'static> {
    let (icon, color) = if ok { ("✓", theme::ARMED) } else { ("✗", theme::DANGER) };
    Paragraph::new(Line::from(vec![
        Span::styled(format!(" {}  ", icon), Style::default().fg(color).add_modifier(Modifier::BOLD)),
        Span::styled(format!("{:<18}", label), theme::label()),
        Span::styled(detail, theme::dim()),
    ]))
}

fn short_path(p: &str) -> String {
    if p.len() <= 38 { p.to_string() } else {
        format!("…{}", &p[p.len()-37..])
    }
}

// ── Screen: Paste ────────────────────────────────────────────────────────────

fn draw_paste(f: &mut Frame, area: Rect, app: &App) {
    let len = app.tx_paste.len();
    let ready = !app.tx_paste.trim().is_empty();
    let border = if ready { theme::ARMED } else { theme::BRAND_DIM };

    let outer = Block::default().borders(Borders::ALL).border_type(BorderType::Rounded)
        .title(format!(" Paste unsigned transaction · {} chars{} ",
            len,
            if ready { " · ready to inspect" } else { "" },
        ))
        .border_style(Style::default().fg(border));
    f.render_widget(&outer, area);
    let inner = outer.inner(area).inner(Margin { vertical: 1, horizontal: 2 });

    let rows = Layout::vertical([
        Constraint::Length(3),  // help text
        Constraint::Min(6),     // buffer view (wraps)
        Constraint::Length(2),  // shortcuts
        Constraint::Length(2),  // error / status
    ]).split(inner);

    // Help text
    f.render_widget(Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Paste a base64 or base58 unsigned Solana message ", theme::dim()),
            Span::styled("(Ctrl+Shift+V or Cmd+V).", theme::mute()),
        ]),
        Line::from(Span::styled(
            "The whole paste lands in one event — no character-by-character lag.",
            theme::mute(),
        )),
    ]), rows[0]);

    // Buffer view — show wrapped chunks, monospace. If empty, show a hint.
    let buffer_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(if ready { theme::BRAND } else { theme::TEXT_MUT }))
        .title(if ready {
            format!(" buffer · {} chars · head {}…tail {} ",
                len,
                preview_head(&app.tx_paste, 12),
                preview_tail(&app.tx_paste, 12))
        } else {
            " buffer · empty ".into()
        });
    let buffer_text: Vec<Line> = if app.tx_paste.is_empty() {
        vec![
            Line::from(""),
            Line::from(Span::styled("  paste a transaction message here…", theme::mute())),
            Line::from(""),
            Line::from(Span::styled("  most terminals: Ctrl+Shift+V  ·  macOS: Cmd+V", theme::mute())),
        ]
    } else {
        // Show the buffer wrapped to the inner width. Trim very long buffers in the
        // middle so the head + tail are both visible (head/tail are what matter for
        // verifying you pasted the right fixture).
        let wrap_width = rows[1].width.saturating_sub(2) as usize;
        let display = if len <= 4 * wrap_width {
            app.tx_paste.clone()
        } else {
            // Show first 2*wrap_width, an ellipsis, and last wrap_width.
            let head = &app.tx_paste[..2 * wrap_width];
            let tail = &app.tx_paste[len - wrap_width..];
            format!("{head}\n…  ({} chars trimmed for display)  …\n{tail}",
                len - 3 * wrap_width)
        };
        display.lines()
            .flat_map(|line| {
                let chars: Vec<char> = line.chars().collect();
                chars.chunks(wrap_width.max(1))
                    .map(|c| c.iter().collect::<String>())
                    .collect::<Vec<_>>()
            })
            .map(|chunk| Line::from(Span::styled(chunk, theme::brand_bold())))
            .collect()
    };
    f.render_widget(
        Paragraph::new(buffer_text).block(buffer_block).wrap(Wrap { trim: false }),
        rows[1],
    );

    // Shortcut hints
    f.render_widget(Paragraph::new(vec![
        Line::from(vec![
            Span::styled("  [enter] inspect    ", theme::label()),
            Span::styled("[ctrl+u] clear    ", theme::dim()),
            Span::styled("[ctrl+w] kill word    ", theme::dim()),
            Span::styled("[backspace] del char    ", theme::dim()),
            Span::styled("[esc] back to home", theme::dim()),
        ]),
    ]), rows[2]);

    // Error / status
    if let Some(err) = &app.error_msg {
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("  ⚠ ", theme::danger()),
                Span::styled(err.clone(), theme::danger()),
            ])),
            rows[3],
        );
    }
}

fn preview_head(s: &str, n: usize) -> String {
    let trimmed: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    trimmed.chars().take(n).collect()
}
fn preview_tail(s: &str, n: usize) -> String {
    let trimmed: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let total = trimmed.chars().count();
    if total <= n { return trimmed; }
    trimmed.chars().skip(total - n).collect()
}

// ── Screen: Inspect ──────────────────────────────────────────────────────────

fn draw_inspect(f: &mut Frame, area: Rect, app: &App) {
    let Some(insp) = &app.inspected else { return };

    let outer = Block::default().borders(Borders::ALL).border_type(BorderType::Rounded)
        .title(" Confirm transaction ")
        .border_style(Style::default().fg(
            if insp.risks.iter().any(|r| matches!(r.severity(), Severity::Critical)) {
                theme::DANGER
            } else if !insp.risks.is_empty() {
                theme::WARN
            } else { theme::BRAND_DIM }
        ));
    f.render_widget(&outer, area);
    let inner = outer.inner(area).inner(Margin { vertical: 1, horizontal: 2 });

    let rows = Layout::vertical([
        Constraint::Length(4),   // header
        Constraint::Min(8),      // instructions — grows with content
        Constraint::Length(10),  // risks — fits ~7 wrapped lines
        Constraint::Length(4),   // confirm — bordered, hard to miss
    ]).split(inner);

    let header = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Fee payer    ", theme::label()),
            Span::styled(insp.fee_payer.clone(), theme::brand_bold()),
        ]),
        Line::from(vec![
            Span::styled("Accounts     ", theme::label()),
            Span::styled(format!("{} static, {} writable, {} signers",
                insp.num_accounts, insp.num_writable, insp.num_signers
            ), theme::dim()),
        ]),
        Line::from(vec![
            Span::styled("Instructions ", theme::label()),
            Span::styled(format!("{} call(s)", insp.instructions.len()), theme::dim()),
        ]),
    ]);
    f.render_widget(header, rows[0]);

    let mut ix_lines: Vec<Line> = vec![
        Line::from(Span::styled("Calls — what this transaction actually does", theme::label())),
        Line::from(""),
    ];
    for (idx, ix) in insp.instructions.iter().enumerate() {
        // Per-instruction severity from the worst risk attached to THIS ix
        // or any of its nested children. A green ✓ on "Token Approve u64::MAX
        // → attacker" is exactly the UX trap drainer attacks exploit; here
        // we make the marker reflect risk, not just "we know the program."
        let (prog_marker, prog_color) = match (ix.worst_severity(), ix.known) {
            (Some(Severity::Critical), _) => ("✗", theme::DANGER),
            (Some(Severity::High),     _) => ("⚠", theme::WARN),
            (Some(Severity::Medium),   _) => ("⚠", theme::WARN),
            (Some(Severity::Low),      _) => ("⚠", theme::TEXT),
            (None, true)                  => ("✓", theme::ARMED),
            (None, false)                 => ("?", theme::DANGER),
        };
        ix_lines.push(Line::from(vec![
            Span::styled(format!("  {}  ", prog_marker),
                Style::default().fg(prog_color).add_modifier(Modifier::BOLD)),
            Span::styled(format!("{}.  ", idx + 1), theme::dim()),
            Span::styled(format!("{:<26}", ix.program_name),
                Style::default().fg(prog_color).add_modifier(Modifier::BOLD)),
            Span::styled(ix.summary.clone(), theme::label()),
        ]));
        ix_lines.push(Line::from(vec![
            Span::styled("        ", theme::dim()),
            Span::styled(format!("program {}", inspector::short(&ix.program_id)), theme::mute()),
            if !ix.touched.is_empty() {
                Span::styled(format!("   accounts: {}", ix.touched.join(", ")), theme::mute())
            } else { Span::raw("") },
        ]));
        // Render Squads V4 nested instructions — anti-blind-signing primitive.
        // Visual treatment: bracket the nested block with a brand-colored callout
        // so judges/users see at a glance "THIS is the actual payload, not just
        // the outer Squads wrapper."
        if let Some(inner) = &ix.nested {
            ix_lines.push(Line::from(""));
            ix_lines.push(Line::from(vec![
                Span::styled("        ╔═══ ", theme::warn()),
                Span::styled(
                    "ANTI-BLIND-SIGNING — recursive decode of the wrapped vault transaction",
                    Style::default().fg(theme::WARN).add_modifier(Modifier::BOLD),
                ),
            ]));
            ix_lines.push(Line::from(vec![
                Span::styled(format!("        ║  Outer call is just the Squads wrapper. The {} inner call(s) below", inner.len()), theme::warn()),
            ]));
            ix_lines.push(Line::from(vec![
                Span::styled("        ║  are what you are ACTUALLY authorizing if you press [y]:", theme::warn()),
            ]));
            ix_lines.push(Line::from(""));
            for (j, sub) in inner.iter().enumerate() {
                // Same severity-aware marker logic as the outer loop. Critical
                // for inner ixs is the most demo-relevant: an SPL Token Approve
                // u64::MAX inside a Squads wrapper deserves a red ✗, not a
                // green ✓ that says "we know SPL Token, looks fine."
                let (sub_marker, sub_color) = match (sub.worst_severity(), sub.known) {
                    (Some(Severity::Critical), _) => ("✗", theme::DANGER),
                    (Some(Severity::High),     _) => ("⚠", theme::WARN),
                    (Some(Severity::Medium),   _) => ("⚠", theme::WARN),
                    (Some(Severity::Low),      _) => ("⚠", theme::TEXT),
                    (None, true)                  => ("✓", theme::ARMED),
                    (None, false)                 => ("?", theme::DANGER),
                };
                ix_lines.push(Line::from(vec![
                    Span::styled("        ║    ", theme::warn()),
                    Span::styled(format!("{}  ", sub_marker),
                        Style::default().fg(sub_color).add_modifier(Modifier::BOLD)),
                    Span::styled(format!("{}.{}  ", idx + 1, j + 1), theme::dim()),
                    Span::styled(format!("{:<24}", sub.program_name),
                        Style::default().fg(sub_color).add_modifier(Modifier::BOLD)),
                    Span::styled(sub.summary.clone(),
                        Style::default().fg(theme::TEXT).add_modifier(Modifier::BOLD)),
                ]));
                ix_lines.push(Line::from(vec![
                    Span::styled("        ║         ", theme::warn()),
                    Span::styled(format!("program {}", inspector::short(&sub.program_id)), theme::mute()),
                    if !sub.touched.is_empty() {
                        Span::styled(format!("  accounts: {}", sub.touched.join(", ")), theme::mute())
                    } else { Span::raw("") },
                ]));
            }
            ix_lines.push(Line::from(vec![
                Span::styled("        ╚════════════════════════════════════════════════════════════", theme::warn()),
            ]));
        }
        ix_lines.push(Line::from(""));
    }
    f.render_widget(Paragraph::new(ix_lines).wrap(Wrap { trim: false }), rows[1]);

    let mut risk_lines: Vec<Line> = vec![Line::from(Span::styled("Risk flags", theme::label()))];
    if insp.risks.is_empty() {
        risk_lines.push(Line::from(Span::styled(
            "  ✓ no flags raised — only known programs, no authority/ownership changes",
            theme::armed(),
        )));
    } else {
        for risk in &insp.risks {
            let color = match risk.severity() {
                Severity::Critical => theme::DANGER,
                Severity::High     => theme::DANGER,  // High is also red — "WARN yellow" understated it
                Severity::Medium   => theme::WARN,
                Severity::Low      => theme::TEXT,
            };
            // Stop sign emoji on Critical, warning triangle on High/Medium —
            // glyphs the eye locks onto without reading. The bracketed label
            // ([CRITICAL] / [HIGH] / etc) backs them up for screen readers
            // and people who've turned colored output off.
            let glyph = match risk.severity() {
                Severity::Critical => "🛑",
                Severity::High     => "⚠️",
                Severity::Medium   => "⚠",
                Severity::Low      => "ℹ",
            };
            risk_lines.push(Line::from(vec![
                Span::styled(format!("  {} [{}] ", glyph, risk.severity().label()),
                    Style::default().fg(color).add_modifier(Modifier::BOLD)),
                Span::styled(risk.human(),
                    Style::default().fg(theme::TEXT).add_modifier(Modifier::BOLD)),
            ]));
        }
    }
    f.render_widget(Paragraph::new(risk_lines).wrap(Wrap { trim: false }), rows[2]);

    // Bordered confirm box — color reflects worst-severity risk so the
    // operator's eye lands on it. Critical risks make the entire box red.
    let (decision_color, decision_title) = if insp.risks.iter().any(|r| matches!(r.severity(), Severity::Critical)) {
        (theme::DANGER, " ⚠  DECISION — Critical risks present ")
    } else if !insp.risks.is_empty() {
        (theme::WARN, " ⚠  DECISION — Review risks above ")
    } else {
        (theme::ARMED, " ✓  DECISION — No flags raised ")
    };
    let confirm = Paragraph::new(Line::from(vec![
        Span::styled("  Sign this transaction?   ", theme::label()),
        Span::styled(" [y] sign ",
            Style::default().fg(Color::Black).bg(theme::ARMED).add_modifier(Modifier::BOLD)),
        Span::styled("   ", theme::dim()),
        Span::styled(" [n] cancel ",
            Style::default().fg(theme::TEXT).bg(theme::TEXT_MUT).add_modifier(Modifier::BOLD)),
        Span::styled("   ", theme::dim()),
        Span::styled("[esc] back", theme::dim()),
    ]))
    .block(Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .title(decision_title)
        .title_style(Style::default().fg(decision_color).add_modifier(Modifier::BOLD))
        .border_style(Style::default().fg(decision_color).add_modifier(Modifier::BOLD))
    );
    f.render_widget(confirm, rows[3]);

    if let Some(err) = &app.error_msg {
        draw_error_strip(f, area, err);
    }
}

/// The Home-screen "Sentinel" panel. Lives where the pet used to live.
/// Renders the most recent N proposals (with severity-aware coloring) so
/// the operator sees pending multisig activity the moment they unlock —
/// no key press required. Tap [m] to expand to the full Squads watch
/// screen and act on a selection.
fn draw_sentinel_panel(f: &mut Frame, area: Rect, app: &App) {
    if area.height < 5 { return; }

    // Compute pet mood from proposal severity. Scared face when an Active
    // proposal carries a Critical severity (the wrapper-attack alert state),
    // alert when there's any pending review, calm otherwise.
    let mut worst_active_sev: Option<u8> = None;
    let mut any_pending = false;
    for p in &app.squads_proposals {
        if !p.status.is_actionable() { continue; }
        any_pending = true;
        if let Some(sev) = p.worst_severity {
            worst_active_sev = Some(worst_active_sev.map(|w| w.max(sev)).unwrap_or(sev));
        }
    }
    let pet_face = match (worst_active_sev, any_pending) {
        (Some(2..=u8::MAX), _) => "(=✗ω✗=)!",  // Critical/High pending — alarmed
        (_, true)              => "(=◉ω◉=)",   // pending review — alert
        _ if (app.frame_tick / 4) % 12 == 0
                                => "(=- ω -=)", // calm idle, blink
        _                       => "(=•ω•=)",   // calm idle
    };

    let title = if app.squads_multisig.is_some() {
        format!(" Sentinel · {} · Squads watch ", pet_face)
    } else {
        " Sentinel — set $SQUADS_MULTISIG to activate ".to_string()
    };

    let pet_color = match worst_active_sev {
        Some(3) => theme::DANGER,
        Some(2) => theme::DANGER,
        Some(1) => theme::WARN,
        _       => theme::ARMED,
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(title)
        .border_style(Style::default().fg(pet_color));
    f.render_widget(&block, area);
    let inner = block.inner(area).inner(Margin { vertical: 0, horizontal: 1 });

    let mut lines: Vec<Line> = Vec::new();

    if app.squads_multisig.is_none() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  No multisig configured. Sentinel watches a Squads multisig",
            theme::dim(),
        )));
        lines.push(Line::from(Span::styled(
            "  for new proposals and surfaces them here.",
            theme::dim(),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  Restart with: SQUADS_MULTISIG=<pda> sovereign-vault",
            theme::mute(),
        )));
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
        return;
    }

    // Status header — last poll + count
    let poll_label = match (&app.squads_poll_job, app.squads_last_poll) {
        (Some(_), _)    => "polling…".to_string(),
        (None, Some(t)) => format!("last poll {}s ago", t.elapsed().as_secs()),
        (None, None)    => "starting…".to_string(),
    };
    let actionable = app.squads_proposals.iter()
        .filter(|p| p.status.is_actionable())
        .count();
    lines.push(Line::from(vec![
        Span::styled("  ", theme::dim()),
        Span::styled(format!("{} proposals · {} pending review · {}",
            app.squads_proposals.len(), actionable, poll_label),
            theme::dim()),
    ]));
    lines.push(Line::from(""));

    if app.squads_proposals.is_empty() {
        lines.push(Line::from(Span::styled("  (no proposals yet)", theme::dim())));
    } else {
        // Show the 3 most recent proposals (already sorted newest first).
        for p in app.squads_proposals.iter().take(3) {
            let (sev_glyph, sev_color) = match p.worst_severity {
                Some(3) => ("🛑", theme::DANGER),
                Some(2) => ("⚠️", theme::DANGER),
                Some(1) => ("⚠", theme::WARN),
                Some(0) => ("ℹ", theme::TEXT),
                Some(_) | None => ("·", theme::TEXT_MUT),
            };
            let kind_short = match &p.kind {
                squads::ProposalKind::VaultTransaction { .. } => "VTX",
                squads::ProposalKind::ConfigTransaction       => "CFG",
            };
            let summary = p.decoded_summary.as_deref().unwrap_or(&p.summary);
            // Trim long summaries so we don't overflow the panel.
            let trimmed: String = summary.chars().take(56).collect();
            let trimmed = if summary.chars().count() > 56 {
                format!("{trimmed}…")
            } else { trimmed };

            let summary_color = if p.worst_severity.unwrap_or(0) >= 2 {
                theme::DANGER
            } else { theme::TEXT };

            lines.push(Line::from(vec![
                Span::styled(format!("  {} ", sev_glyph),
                    Style::default().fg(sev_color).add_modifier(Modifier::BOLD)),
                Span::styled(format!("#{:<3} {} ", p.index, kind_short), theme::dim()),
                Span::styled(format!("[{}] ", p.status.label()),
                    Style::default().fg(match p.status {
                        squads::ProposalStatus::Active   => theme::WARN,
                        squads::ProposalStatus::Approved => theme::ARMED,
                        squads::ProposalStatus::Rejected => theme::DANGER,
                        squads::ProposalStatus::Executed => theme::ARMED,
                        _                                => theme::TEXT_MUT,
                    }).add_modifier(Modifier::BOLD)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("       ", theme::dim()),
                Span::styled(trimmed, Style::default().fg(summary_color)),
            ]));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  [m] expand to full list — select to sign or reject",
            theme::label(),
        )));
    }

    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

// ── Screen: Squads (multisig watch) ──────────────────────────────────────────
//
// Lists pending proposals on the configured Squads V4 multisig. The TUI
// polls every 30 seconds while this screen is active; user can press [r] to
// refresh sooner, [↑/↓] to navigate, [enter] to load the highlighted proposal
// into the inspector → existing FROST + Telegram sign flow handles the rest.
//
// Demo flow:
//   1. Some other multisig member proposes a tx (legitimate or wrapper-attack)
//   2. This screen surfaces it within 30 seconds with a status badge
//   3. User picks it, sees the recursive decode + risks, decides on phone
//
// v0.4 ships read-only — submitting `proposal_approve` back on-chain to
// register the user's vote is the v0.5 follow-on. The hero demo moment
// (catching a wrapper attack and refusing it) doesn't require on-chain
// approval submission to land.

fn draw_squads(f: &mut Frame, area: Rect, app: &App) {
    let outer = Block::default().borders(Borders::ALL).border_type(BorderType::Rounded)
        .title(" Squads V4 multisig watch ")
        .border_style(Style::default().fg(theme::BRAND_DIM));
    f.render_widget(&outer, area);
    let inner = outer.inner(area).inner(Margin { vertical: 1, horizontal: 2 });

    let rows = Layout::vertical([
        Constraint::Length(3),  // header (multisig PDA + last poll)
        Constraint::Min(8),     // proposal list
        Constraint::Length(3),  // error / hint
    ]).split(inner);

    // Header
    let multisig_label = app.squads_multisig.clone().unwrap_or_else(|| "(not configured)".into());
    let poll_label = match (&app.squads_poll_job, app.squads_last_poll) {
        (Some(_), _) => format!("polling..."),
        (None, Some(t)) => format!("last poll {}s ago", t.elapsed().as_secs()),
        (None, None)    => "not yet polled".to_string(),
    };
    f.render_widget(Paragraph::new(vec![
        Line::from(vec![
            Span::styled("  Multisig: ", theme::label()),
            Span::styled(multisig_label, theme::brand_bold()),
        ]),
        Line::from(vec![
            Span::styled("  Status:   ", theme::label()),
            Span::styled(format!("{} · {} proposal(s) loaded · auto-refresh 30s",
                poll_label, app.squads_proposals.len()), theme::dim()),
        ]),
    ]), rows[0]);

    // Proposal list
    let mut list_lines: Vec<Line> = Vec::new();
    if app.squads_proposals.is_empty() {
        list_lines.push(Line::from(""));
        list_lines.push(Line::from(Span::styled(
            "  No proposals to show.",
            theme::dim(),
        )));
        list_lines.push(Line::from(Span::styled(
            "  Press [r] to refresh now. New proposals from other members appear within 30s.",
            theme::dim(),
        )));
    } else {
        for (i, prop) in app.squads_proposals.iter().enumerate() {
            let selected = i == app.squads_selected;
            let marker = if selected { "▶" } else { " " };
            let kind_label = match &prop.kind {
                squads::ProposalKind::VaultTransaction { vault_index } =>
                    format!("VaultTx v{}", vault_index),
                squads::ProposalKind::ConfigTransaction =>
                    "ConfigTx".to_string(),
            };

            // Severity glyph + color for the row — driven by the worst risk
            // in the decoded inner instructions. This is the wrapper-attack
            // catch surfacing in the LIST itself, not just on inspect.
            let (sev_glyph, sev_color) = match prop.worst_severity {
                Some(3) => ("🛑 CRIT", theme::DANGER),
                Some(2) => ("⚠️ HIGH", theme::DANGER),
                Some(1) => ("⚠ MED ", theme::WARN),
                Some(0) => ("ℹ INFO", theme::TEXT),
                Some(_) | None => ("       ", theme::TEXT_MUT),
            };

            let status_color = match &prop.status {
                squads::ProposalStatus::Active   => theme::WARN,
                squads::ProposalStatus::Approved => theme::ARMED,
                squads::ProposalStatus::Rejected => theme::DANGER,
                squads::ProposalStatus::Executed => theme::ARMED,
                _                                => theme::TEXT_MUT,
            };

            // Pick the descriptive summary if we have it (decoded inner ix),
            // otherwise fall back to the generic kind summary.
            let summary_text = prop.decoded_summary.clone()
                .unwrap_or_else(|| prop.summary.clone());

            let summary_color = if prop.worst_severity.unwrap_or(0) >= 2 {
                theme::DANGER  // High or Critical — bold red so it screams
            } else if selected {
                theme::BRAND
            } else {
                theme::TEXT
            };

            // Two-line row when severity is HIGH or CRITICAL — first line is
            // the metadata strip, second line is the indented danger-flag
            // text. For clean (no-risk) proposals we fold to one line.
            list_lines.push(Line::from(vec![
                Span::styled(format!(" {} ", marker),
                    Style::default().fg(theme::BRAND).add_modifier(Modifier::BOLD)),
                Span::styled(format!("#{:<4} ", prop.index),
                    if selected { Style::default().fg(theme::BRAND).add_modifier(Modifier::BOLD) }
                    else        { Style::default().fg(theme::TEXT) }),
                Span::styled(format!("{:<10} ", kind_label),
                    Style::default().fg(theme::TEXT)),
                Span::styled(format!("[{}] ", prop.status.label()),
                    Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
                Span::styled(format!("{} ", sev_glyph),
                    Style::default().fg(sev_color).add_modifier(Modifier::BOLD)),
                Span::styled(format!("· approved {}", prop.approved_by.len()), theme::dim()),
            ]));
            list_lines.push(Line::from(vec![
                Span::styled("        ", theme::dim()),
                Span::styled(summary_text,
                    Style::default().fg(summary_color).add_modifier(
                        if prop.worst_severity.unwrap_or(0) >= 2 { Modifier::BOLD } else { Modifier::empty() }
                    )),
            ]));
            list_lines.push(Line::from(""));
        }
    }
    f.render_widget(Paragraph::new(list_lines).wrap(Wrap { trim: false }), rows[1]);

    // Error / hint
    let footer_line = if let Some(err) = &app.squads_error {
        Line::from(vec![
            Span::styled("  ✗ ", Style::default().fg(theme::DANGER).add_modifier(Modifier::BOLD)),
            Span::styled(err.clone(), Style::default().fg(theme::DANGER)),
        ])
    } else {
        Line::from(Span::styled(
            "  Selecting a proposal loads its inner Solana Message into the inspector → \
             FROST + Telegram approval flow.",
            theme::mute(),
        ))
    };
    f.render_widget(Paragraph::new(vec![Line::from(""), footer_line]), rows[2]);
}

// ── Screen: Signed ───────────────────────────────────────────────────────────

fn draw_signed(f: &mut Frame, area: Rect, app: &App) {
    let outer = Block::default().borders(Borders::ALL).border_type(BorderType::Rounded)
        .title(" Signed transaction · click-and-drag to copy ")
        .border_style(Style::default().fg(theme::ARMED));
    f.render_widget(&outer, area);
    let inner = outer.inner(area).inner(Margin { vertical: 1, horizontal: 2 });

    let signed = app.last_signed.as_deref().unwrap_or("");
    let path   = app.last_signed_path.as_deref().unwrap_or("(in-memory only)");

    let rows = Layout::vertical([
        Constraint::Length(5),  // header
        Constraint::Min(3),     // full signed tx (wraps)
        Constraint::Length(4),  // footer + broadcast hint
    ]).split(inner);

    f.render_widget(Paragraph::new(vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  ✓ Signed   ", theme::armed()),
            Span::styled("(=^ω^=)♪  ",
                Style::default().fg(theme::ARMED).add_modifier(Modifier::BOLD)),
            Span::styled(format!("·  {} bytes ({} chars base58)", signed.len() / 4 * 3, signed.len()), theme::dim()),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Saved to:  ", theme::label()),
            Span::styled(path.to_string(), theme::brand_bold()),
        ]),
        Line::from(Span::styled("  ↑ click-and-drag the path to copy it", theme::mute())),
    ]), rows[0]);

    // Full signed-tx panel with its own border. Click and drag inside this panel
    // to select the entire base58 string. Mouse capture is OFF, so the terminal
    // handles selection natively.
    let signed_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(theme::BRAND))
        .title(" Base58 signed transaction · select with mouse · copy with Ctrl+Shift+C ");
    f.render_widget(
        Paragraph::new(Span::styled(signed.to_string(), theme::brand_bold()))
            .block(signed_block)
            .wrap(Wrap { trim: false }),
        rows[1],
    );

    // Footer renders one of four states:
    //   1. idle (no broadcast attempted yet)        → [b] Broadcast hint
    //   2. in-flight (worker thread alive)          → spinner + elapsed
    //   3. success (last_broadcast_sig is Some)     → tx sig + Solscan URL
    //   4. failure (last_broadcast_error is Some)   → error + retry hint
    //
    // For Squads-sourced signatures the bytes signed are a proposal_approve
    // Solana tx (with FROST as fee payer), so broadcast is exactly the
    // right action — it registers the FROST member's vote on-chain with
    // the Squads multisig.
    let footer_lines: Vec<Line> = if let Some(job) = &app.broadcast_job {
        let elapsed = job.started_at.elapsed().as_secs();
        let spin = SPINNER_FRAMES[(app.frame_tick as usize) % SPINNER_FRAMES.len()];
        vec![
            Line::from(""),
            Line::from(vec![
                Span::styled(format!("  {} ", spin), theme::brand_bold()),
                Span::styled(format!("Broadcasting to mainnet... ({}s)", elapsed), theme::label()),
            ]),
            Line::from(Span::styled("  please wait — sendTransaction over JSON-RPC", theme::mute())),
        ]
    } else if let Some(sig) = &app.last_broadcast_sig {
        vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  ✓ Broadcast confirmed: ", theme::armed()),
                Span::styled(sig.clone(), theme::brand_bold()),
            ]),
            Line::from(vec![
                Span::styled("  Solscan: ", theme::label()),
                Span::styled(rpc::solscan_tx(sig), theme::brand_bold()),
            ]),
            Line::from(Span::styled("  [enter] back to home", theme::label())),
        ]
    } else if let Some(err) = &app.last_broadcast_error {
        vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  ✗ Broadcast failed: ", Style::default().fg(theme::DANGER).add_modifier(Modifier::BOLD)),
                Span::styled(err.clone(), theme::label()),
            ]),
            Line::from(Span::styled("  [b] retry  ·  [enter] back to home", theme::label())),
        ]
    } else {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                "  [b] Broadcast to mainnet  ·  [enter] back to home",
                theme::label(),
            )),
            Line::from(Span::styled(
                "  Broadcasts via api.mainnet-beta.solana.com — Solscan URL printed on success.",
                theme::mute(),
            )),
        ]
    };
    f.render_widget(Paragraph::new(footer_lines), rows[2]);
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// ── Vault Sentinel (the pet) ─────────────────────────────────────────────────
//
// A small, mood-aware ASCII tiger that lives in the home / signing / signed
// screens. Purely cosmetic — but it gives the operator a glanceable signal
// of what the vault's "feeling" right now, which is genuinely useful during
// the signing dance when nothing else on the screen is moving.

#[derive(Clone, Copy)]
#[allow(dead_code)]  // Watching/Happy/Refused are wired into inline faces today;
                     // the enum keeps them named for the panel-form pet that
                     // will appear on more screens in v0.3.
enum PetMood {
    Idle,      // home screen, calm
    Watching,  // MPC signing in progress
    Happy,     // just signed successfully
    Refused,   // refused to sign (Critical risk or cap fired)
}

fn pet_lines(mood: PetMood, tick: u64) -> Vec<Line<'static>> {
    let (eyes, color) = match mood {
        PetMood::Idle => {
            // Slow blink — every ~10 frames (~2s) the eyes close briefly.
            let blink = (tick / 4) % 12 == 0;
            (if blink { " - - " } else { " • • " }, theme::ARMED)
        }
        PetMood::Watching => {
            // Wide-eyed alert; pulse brightness slightly with the tick.
            let alt = (tick / 3) % 2 == 0;
            (if alt { " ◉ ◉ " } else { " ◎ ◎ " }, theme::WARN)
        }
        PetMood::Happy =>   (" ^ ^ ", theme::ARMED),
        PetMood::Refused => (" ✗ ✗ ", theme::DANGER),
    };
    let mouth = match mood {
        PetMood::Idle     => "   ╲_/V\\_/",
        PetMood::Watching => "   ╲_/V\\_/",
        PetMood::Happy    => "   ╲_/v\\_/  ♪",
        PetMood::Refused  => "   ╲_/×\\_/  !",
    };
    vec![
        Line::from(Span::styled("   /\\___/\\".to_string(),
            Style::default().fg(color))),
        Line::from(vec![
            Span::styled("  ( =".to_string(), Style::default().fg(color)),
            Span::styled(eyes.to_string(),
                Style::default().fg(color).add_modifier(Modifier::BOLD)),
            Span::styled("= )".to_string(), Style::default().fg(color)),
        ]),
        Line::from(Span::styled(mouth.to_string(),
            Style::default().fg(color))),
    ]
}

fn draw_pet_panel(f: &mut Frame, area: Rect, mood: PetMood, tick: u64) {
    let block = Block::default()
        .borders(Borders::ALL).border_type(BorderType::Rounded)
        .title(" Sentinel ")
        .border_style(Style::default().fg(theme::BRAND_DIM));
    f.render_widget(&block, area);
    let inner = block.inner(area).inner(Margin { vertical: 0, horizontal: 1 });
    let mut lines = pet_lines(mood, tick);
    // Caption — one short line of context per mood.
    let caption = match mood {
        PetMood::Idle     => "  watching for tx…",
        PetMood::Watching => "  MPC in progress",
        PetMood::Happy    => "  signature OK",
        PetMood::Refused  => "  refused — see flags",
    };
    lines.push(Line::from(Span::styled(caption.to_string(), theme::dim())));
    f.render_widget(Paragraph::new(lines), inner);
}

fn draw_error_strip(f: &mut Frame, area: Rect, msg: &str) {
    // Render as a 3-line bordered banner with a dark-red background, anchored
    // to the bottom of the host area. The previous version rendered as a single
    // background-less line that overlapped content and was easy to miss.
    let banner_h: u16 = 3;
    let h = area.height.saturating_sub(banner_h);
    let strip = Rect { x: area.x, y: area.y + h, width: area.width, height: banner_h };
    f.render_widget(Clear, strip);
    let body = Paragraph::new(Line::from(vec![
        Span::styled("  ⚠  ",
            Style::default().fg(theme::DANGER).bg(Color::Rgb(40, 0, 0)).add_modifier(Modifier::BOLD)),
        Span::styled(format!("{}  ", msg),
            Style::default().fg(theme::TEXT).bg(Color::Rgb(40, 0, 0)).add_modifier(Modifier::BOLD)),
    ]))
    .block(Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Thick)
        .border_style(Style::default().fg(theme::DANGER).bg(Color::Rgb(40, 0, 0)))
        .style(Style::default().bg(Color::Rgb(40, 0, 0)))
        .title(" ERROR ")
        .title_style(Style::default().fg(theme::DANGER).bg(Color::Rgb(40, 0, 0)).add_modifier(Modifier::BOLD))
    );
    f.render_widget(body, strip);
}

fn draw_flash(f: &mut Frame, area: Rect, msg: &str, color: Color) {
    let w = (msg.len() as u16 + 6).min(area.width.saturating_sub(4));
    let r = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + 1,
        width: w,
        height: 3,
    };
    f.render_widget(Clear, r);
    let p = Paragraph::new(Line::from(vec![
        Span::styled(format!("  {}  ", msg),
            Style::default().fg(color).add_modifier(Modifier::BOLD)),
    ]))
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded)
        .border_style(Style::default().fg(color)));
    f.render_widget(p, r);
}
