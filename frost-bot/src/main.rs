//! Sovereign OS Vault — Telegram FROST cosigner bot.
//!
//! Architecture:
//!   - axum HTTP server on `listen_addr` accepts POST /sign from the laptop
//!   - teloxide dispatcher delivers approve/reject callback queries from your
//!     Telegram account (allowlisted by user ID)
//!   - HTTP handler ↔ Telegram handler talk through a shared state map of
//!     pending sign sessions, each holding a oneshot channel for the user's
//!     decision
//!
//! v0.4 demo notes:
//!   - The bot's FROST share lives plaintext at the path in config.toml.
//!     v0.5 wraps it with the laptop's Argon2id keystore (require a passphrase
//!     to start the bot). This is intentional scope-cutting for the deadline.
//!   - The bot binds 127.0.0.1 by default — local laptop demo. Move to Fly.io
//!     / VPS / RPi for a real second trust domain.
//!   - User allowlist is by Telegram numeric ID. Unlisted users hitting the bot
//!     get a polite refusal and are never shown sign prompts.

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::Json as RJson,
    routing::post,
    Json, Router,
};
use frost_ed25519 as frost;
use sovereign_frost_bot::{
    config::BotConfig,
    protocol::{LaptopDecision, SignError, SignErrorKind, SignRequest, SignResponse},
    share,
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::Duration,
};
use teloxide::{
    payloads::SendMessageSetters,
    prelude::*,
    types::{InlineKeyboardButton, InlineKeyboardMarkup, ParseMode},
};
use tokio::sync::{oneshot, Mutex};

const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);

struct AppState {
    bot: Bot,
    config: BotConfig,
    bot_key_package: frost::keys::KeyPackage,
    bot_pubkey_package: frost::keys::PublicKeyPackage,
    /// session_id → channel that a callback handler signals when user decides
    pending: Mutex<HashMap<String, oneshot::Sender<bool>>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,sovereign_frost_bot=debug")))
        .init();

    let config = BotConfig::load_default()?;
    let bot_key_package = share::load_key_package(&config.share_path)
        .context("loading bot's FROST share — run `frost-keygen` first")?;
    let bot_pubkey_package = share::load_pubkey_package(&config.pubkey_path)?;

    let pubkey_hex = hex::encode(bot_pubkey_package.verifying_key().serialize()?);
    let solana_addr = bs58::encode(bot_pubkey_package.verifying_key().serialize()?).into_string();
    tracing::info!(group_pubkey = %pubkey_hex, solana_addr = %solana_addr, "bot starting");

    let bot = Bot::new(&config.bot_token);
    let listen_addr = config.listen_addr.clone();

    let state = Arc::new(AppState {
        bot: bot.clone(),
        config,
        bot_key_package,
        bot_pubkey_package,
        pending: Mutex::new(HashMap::new()),
    });

    let app = Router::new()
        .route("/sign", post(sign_handler))
        .route("/health", axum::routing::get(|| async { "ok" }))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(&listen_addr).await
        .with_context(|| format!("binding {}", listen_addr))?;
    tracing::info!(addr = %listen_addr, "HTTP server listening");

    let http_task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let dispatcher_state = state.clone();
    let dispatcher_task = tokio::spawn(async move {
        let handler = dptree::entry()
            .branch(Update::filter_message().endpoint(message_handler))
            .branch(Update::filter_callback_query().endpoint(callback_handler));
        Dispatcher::builder(bot, handler)
            .dependencies(dptree::deps![dispatcher_state])
            .enable_ctrlc_handler()
            .build()
            .dispatch()
            .await;
    });

    tokio::select! {
        _ = http_task => tracing::warn!("HTTP server exited"),
        _ = dispatcher_task => tracing::warn!("Telegram dispatcher exited"),
    }
    Ok(())
}

async fn sign_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SignRequest>,
) -> Result<RJson<SignResponse>, (StatusCode, RJson<SignError>)> {
    match handle_sign_inner(state, req).await {
        Ok(resp) => Ok(RJson(resp)),
        Err((code, err)) => Err((code, RJson(err))),
    }
}

async fn handle_sign_inner(
    state: Arc<AppState>,
    req: SignRequest,
) -> Result<SignResponse, (StatusCode, SignError)> {
    use base64::Engine as _;

    if matches!(req.laptop_decision, LaptopDecision::Red) {
        return Err((
            StatusCode::FORBIDDEN,
            SignError {
                kind: SignErrorKind::LaptopRefused,
                message: "laptop inspector returned RED — bot will not prompt user".into(),
            },
        ));
    }

    let message_bytes = base64::engine::general_purpose::STANDARD
        .decode(&req.message_b64)
        .map_err(|e| bad_request(format!("message_b64 decode: {e}")))?;

    let laptop_commitments_bytes = hex::decode(&req.laptop_commitments_hex)
        .map_err(|e| bad_request(format!("laptop_commitments_hex decode: {e}")))?;
    let laptop_commitments = frost::round1::SigningCommitments::deserialize(&laptop_commitments_bytes)
        .map_err(|e| bad_request(format!("FROST commitments parse: {e}")))?;

    let laptop_identifier_bytes = hex::decode(&req.laptop_identifier_hex)
        .map_err(|e| bad_request(format!("laptop_identifier_hex decode: {e}")))?;
    let laptop_identifier = frost::Identifier::deserialize(&laptop_identifier_bytes)
        .map_err(|e| bad_request(format!("FROST identifier parse: {e}")))?;

    let session_id = format!("{:016x}", rand::random::<u64>());

    let approval_msg = build_approval_message(&req, &session_id);
    let keyboard = InlineKeyboardMarkup::new(vec![vec![
        InlineKeyboardButton::callback("✅ Approve", format!("approve:{}", session_id)),
        InlineKeyboardButton::callback("❌ Reject", format!("reject:{}", session_id)),
    ]]);

    let (tx, rx) = oneshot::channel::<bool>();
    state.pending.lock().await.insert(session_id.clone(), tx);

    for &user_id in &state.config.authorized_users {
        let chat_id = ChatId(user_id);
        if let Err(e) = state.bot.send_message(chat_id, &approval_msg)
            .parse_mode(ParseMode::Html)
            .reply_markup(keyboard.clone())
            .await
        {
            tracing::warn!(user_id, error = ?e, "failed to send approval prompt to user");
        }
    }

    let approved = match tokio::time::timeout(APPROVAL_TIMEOUT, rx).await {
        Ok(Ok(decision)) => decision,
        Ok(Err(_)) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                SignError {
                    kind: SignErrorKind::Internal,
                    message: "approval channel closed unexpectedly".into(),
                },
            ));
        }
        Err(_) => {
            state.pending.lock().await.remove(&session_id);
            return Err((
                StatusCode::REQUEST_TIMEOUT,
                SignError {
                    kind: SignErrorKind::UserTimeout,
                    message: format!("user did not respond within {:?}", APPROVAL_TIMEOUT),
                },
            ));
        }
    };

    if !approved {
        return Err((
            StatusCode::FORBIDDEN,
            SignError {
                kind: SignErrorKind::UserRejected,
                message: "user rejected the sign request in Telegram".into(),
            },
        ));
    }

    let bot_identifier = bot_identifier_from_pubkey_package(&state.bot_pubkey_package, &laptop_identifier)
        .map_err(|e| internal(format!("identifying bot's FROST id: {e}")))?;

    let mut rng = rand::thread_rng();
    let (bot_nonces, bot_commitments) = frost::round1::commit(
        state.bot_key_package.signing_share(),
        &mut rng,
    );

    let mut commitments_map = BTreeMap::new();
    commitments_map.insert(laptop_identifier, laptop_commitments);
    commitments_map.insert(bot_identifier, bot_commitments);

    let signing_package = frost::SigningPackage::new(commitments_map, &message_bytes);
    let bot_share = frost::round2::sign(&signing_package, &bot_nonces, &state.bot_key_package)
        .map_err(|e| internal(format!("FROST round2 sign: {e}")))?;

    Ok(SignResponse {
        bot_commitments_hex: hex::encode(bot_commitments.serialize()
            .map_err(|e| internal(format!("serialize bot commitments: {e}")))?),
        bot_signature_share_hex: hex::encode(bot_share.serialize()),
        bot_identifier_hex: hex::encode(bot_identifier.serialize()),
    })
}

fn bot_identifier_from_pubkey_package(
    pubkey_package: &frost::keys::PublicKeyPackage,
    laptop_identifier: &frost::Identifier,
) -> Result<frost::Identifier> {
    pubkey_package.verifying_shares().keys()
        .find(|id| *id != laptop_identifier)
        .copied()
        .ok_or_else(|| anyhow!("could not find bot's identifier in pubkey package"))
}

fn bad_request(msg: String) -> (StatusCode, SignError) {
    (StatusCode::BAD_REQUEST, SignError { kind: SignErrorKind::BadRequest, message: msg })
}
fn internal(msg: String) -> (StatusCode, SignError) {
    (StatusCode::INTERNAL_SERVER_ERROR, SignError { kind: SignErrorKind::Internal, message: msg })
}

fn build_approval_message(req: &SignRequest, session_id: &str) -> String {
    let decision_label = match req.laptop_decision {
        LaptopDecision::Green  => "🟢 GREEN",
        LaptopDecision::Yellow => "🟡 YELLOW",
        LaptopDecision::Red    => "🔴 RED",
    };
    format!(
        "<b>Sovereign OS Vault — sign request</b>\n\n\
         <b>Inspector decision:</b> {}\n\n\
         <b>Decoded transaction:</b>\n<pre>{}</pre>\n\n\
         <i>Session:</i> <code>{}</code>\n\
         <i>Tap Approve to release the bot's FROST share. Tap Reject if anything looks wrong.</i>",
        html_escape(decision_label),
        html_escape(&req.decoded_summary),
        html_escape(session_id),
    )
}

/// HTML escape for Telegram's HTML parse mode — only `&`, `<`, `>` are special.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

async fn message_handler(bot: Bot, msg: Message, state: Arc<AppState>) -> ResponseResult<()> {
    let user_id = msg.from.as_ref().map(|u| u.id.0 as i64).unwrap_or(0);
    if !state.config.authorized_users.contains(&user_id) {
        let _ = bot.send_message(msg.chat.id,
            "This is a private Sovereign OS Vault cosigner bot. Your Telegram ID is not on the allowlist."
        ).await;
        tracing::warn!(user_id, "rejected message from unauthorized user");
        return Ok(());
    }
    let pubkey_hex = state.bot_pubkey_package.verifying_key()
        .serialize().map(hex::encode).unwrap_or_else(|_| "(error)".into());
    let solana_addr = state.bot_pubkey_package.verifying_key()
        .serialize().map(|b| bs58::encode(b).into_string()).unwrap_or_else(|_| "(error)".into());
    let greeting = format!(
        "<b>Sovereign OS Vault</b> — FROST cosigner\n\n\
         Bot is online and you are authorized.\n\n\
         <b>Group public key:</b>\n<code>{}</code>\n\n\
         <b>Solana address:</b>\n<code>{}</code>\n\n\
         <i>When the laptop submits a sign request, you'll see an Approve/Reject prompt here.</i>",
        html_escape(&pubkey_hex), html_escape(&solana_addr),
    );
    bot.send_message(msg.chat.id, greeting)
        .parse_mode(ParseMode::Html)
        .await?;
    Ok(())
}

async fn callback_handler(bot: Bot, q: CallbackQuery, state: Arc<AppState>) -> ResponseResult<()> {
    let user_id = q.from.id.0 as i64;
    if !state.config.authorized_users.contains(&user_id) {
        bot.answer_callback_query(&q.id)
            .text("Not authorized")
            .show_alert(true)
            .await?;
        tracing::warn!(user_id, "rejected callback from unauthorized user");
        return Ok(());
    }

    let data = q.data.as_deref().unwrap_or("");
    let (action, session_id) = data.split_once(':').unwrap_or(("", ""));
    if session_id.is_empty() {
        bot.answer_callback_query(&q.id).text("Malformed").await?;
        return Ok(());
    }

    let approved = match action {
        "approve" => true,
        "reject"  => false,
        _ => {
            bot.answer_callback_query(&q.id).text("Unknown action").await?;
            return Ok(());
        }
    };

    let maybe_tx = state.pending.lock().await.remove(session_id);
    if let Some(tx) = maybe_tx {
        let _ = tx.send(approved);
        bot.answer_callback_query(&q.id)
            .text(if approved { "✅ Approved — releasing FROST share" } else { "❌ Rejected — sign aborted" })
            .await?;
        if let Some(message) = q.message {
            let final_text = if approved {
                "<b>Sovereign OS Vault</b>\n\n✅ <b>Approved</b> — FROST share released, signature returned to laptop."
            } else {
                "<b>Sovereign OS Vault</b>\n\n❌ <b>Rejected</b> — sign aborted, no signature produced."
            };
            let _ = bot.edit_message_text(message.chat().id, message.id(), final_text)
                .parse_mode(ParseMode::Html)
                .await;
        }
    } else {
        bot.answer_callback_query(&q.id)
            .text("Session expired or already decided")
            .await?;
    }
    Ok(())
}
