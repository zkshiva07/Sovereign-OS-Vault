//! Vultisig daemon client — sync Unix-socket JSON-RPC.
//!
//! Wire format mirrors `packages/vultisig-sol-signer/src/index.ts`:
//!   request:  { id: u64, method: "get_address"|"sign", params: { ... } }\n
//!   response: { id: u64, result: { ... } }\n     OR { id: u64, error: { ... } }\n
//!
//! We deliberately use sync I/O (no tokio) so this composes with ratatui's
//! event loop without dragging in an async runtime. Call from a worker thread
//! when waiting on a mobile cosigner — the UI thread should stay responsive.
//!
//! Threat model boundaries:
//!   - We trust that /tmp/vultisig.sock is owned by our UID (POSIX socket perms
//!     mean other UIDs can't connect). The daemon enforces this.
//!   - We do NOT trust the daemon to handle our key material — it doesn't have
//!     it. The keyshare lives in `.vult` (encrypted at rest) loaded by the daemon
//!     under its own passphrase. We just talk wire protocol.
//!   - Wrong fee-payer / unintended payload protection happens BEFORE we hand
//!     bytes to the daemon — that's the inspector's job.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const DEFAULT_SOCKET_PATH: &str = "/tmp/vultisig.sock";

/// Generous default — mobile cosigner involves human approval.
pub const SIGN_TIMEOUT: Duration = Duration::from_secs(120);
/// Quick — just confirms the daemon is alive.
pub const HEALTH_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Serialize)]
struct RpcRequest<'a, P: Serialize> {
    id:     u64,
    method: &'a str,
    params: P,
}

#[derive(Debug, Deserialize)]
struct RpcResponse<R> {
    #[serde(default)]
    #[allow(dead_code)]
    id:     Option<u64>,
    #[serde(default)]
    result: Option<R>,
    #[serde(default)]
    error:  Option<RpcError>,
}

/// Some daemon responses tunnel errors INSIDE result rather than using the
/// top-level `error` field — `{"result":{"status":"error","error":"...","session_id":"..."}}`.
/// We pre-parse with this generic shape to detect that pattern and surface a
/// helpful error before the typed-result parse blows up.
#[derive(Debug, Deserialize, Default)]
struct DaemonResultEnvelope {
    #[serde(default)]
    status:     Option<String>,
    #[serde(default)]
    error:      Option<String>,
    #[serde(default)]
    session_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RpcError {
    #[allow(dead_code)]
    pub code:    Option<i64>,
    pub message: Option<String>,
}

#[derive(Debug, Serialize)]
struct AddressParams<'a> {
    scheme:  &'a str,
    curve:   &'a str,
    network: &'a str,
}

#[derive(Debug, Deserialize, Default)]
struct AddressResult {
    /// Current daemon API returns `address`. Older docs/sol-signer.ts use `pubkey`.
    /// Accept either so we're forward/backward compatible.
    #[serde(default)]
    address: String,
    #[serde(default)]
    pubkey:  String,
}

impl AddressResult {
    fn pick(&self) -> Option<String> {
        if !self.address.is_empty() { Some(self.address.clone()) }
        else if !self.pubkey.is_empty() { Some(self.pubkey.clone()) }
        else { None }
    }
}

#[derive(Debug, Serialize)]
struct SignParams<'a> {
    scheme:       &'a str,
    curve:        &'a str,
    network:      &'a str,
    #[serde(rename = "messageType")]
    message_type: &'a str,
    payload:      SignPayload,
}

#[derive(Debug, Serialize)]
struct SignPayload {
    bytes: String, // base64
}

#[derive(Debug, Deserialize, Default)]
struct SignResult {
    signature: String,
}

/// A connected Vultisig daemon client. Cheap to construct; one connection per request.
pub struct VultisigClient {
    socket_path: PathBuf,
}

impl VultisigClient {
    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        Self { socket_path: path.into() }
    }

    pub fn default_socket() -> Self {
        Self::new(DEFAULT_SOCKET_PATH)
    }

    /// True if the daemon socket exists and accepts a connection within HEALTH_TIMEOUT.
    /// Does not send any payload — purely a connectivity probe.
    pub fn is_running(&self) -> bool {
        if !Path::new(&self.socket_path).exists() {
            return false;
        }
        UnixStream::connect(&self.socket_path)
            .map(|s| {
                let _ = s.set_read_timeout(Some(HEALTH_TIMEOUT));
                true
            })
            .unwrap_or(false)
    }

    /// Fetch the Solana address (base58 ed25519 pubkey) from the daemon.
    /// Fast — no MPC handshake required for address derivation.
    pub fn solana_address(&self) -> Result<String> {
        let resp: RpcResponse<AddressResult> = self.request(
            "get_address",
            AddressParams { scheme: "eddsa", curve: "ed25519", network: "sol" },
            HEALTH_TIMEOUT * 5, // ~10s — derivation is fast but daemon may be busy
        )?;
        if let Some(err) = resp.error {
            bail!("daemon error: {}", err.message.unwrap_or_else(|| "(no message)".into()));
        }
        resp.result.and_then(|r| r.pick())
            .ok_or_else(|| anyhow!("daemon returned no address/pubkey field"))
    }

    /// Sign a serialized Solana `Message` (legacy or v0) via the daemon's MPC.
    ///
    /// Wire format (matches the patched daemon — see vendor-patches/vultisig-cli-solana-bytes.patch):
    ///
    ///   request:  payload.bytes = base64(serialized_message)
    ///   response: result.raw_tx = base64(signed_tx_wire_bytes)
    ///             result.signature = base58(64-byte ed25519 sig)
    ///             result.tx_hash = base58 (alias for signature, what explorers display)
    ///
    /// Returns the FULL signed transaction in **base58** so it lines up with
    /// the Local backend's output format and can be saved to the same on-disk
    /// place + broadcast via the same downstream tooling.
    ///
    /// If the daemon you're talking to is the unpatched upstream (commit 9f805de
    /// or earlier), `result.raw_tx` won't be present and we surface that as
    /// "daemon may need patching" so it's debuggable.
    pub fn sign_solana(&self, message_bytes: &[u8]) -> Result<String> {
        use base64::Engine as _;
        // Mode = "relay" for Fast Vault (server-assisted: the second MPC party
        // is VultiServer at api.vultisig.com/router). The daemon's "local"
        // mode is for Secure Vault P2P over LAN+mDNS; that needs a paired
        // device on the network and a different keyshare topology. Most
        // user-facing Vultisig vaults are Fast Vaults (`...Vultiserver.vult`),
        // so relay is the right default.
        //
        // We do NOT pass session_id — the daemon auto-generates a proper
        // UUIDv4. api.vultisig.com requires UUID-format session IDs (returns
        // 400 Bad Request otherwise; verified empirically with curl probes).
        let raw: serde_json::Value = self.request_raw(
            "sign",
            serde_json::json!({
                "network":   "sol",
                "mode":      "relay",
                "payload":   {
                    "bytes": base64::engine::general_purpose::STANDARD.encode(message_bytes),
                },
                "broadcast": false,
            }),
            SIGN_TIMEOUT,
        )?;
        if let Some(top_err) = raw.get("error") {
            bail!("daemon error: {}", top_err);
        }
        let result = raw.get("result")
            .ok_or_else(|| anyhow!("daemon returned no result field"))?;
        let env: DaemonResultEnvelope = serde_json::from_value(result.clone()).unwrap_or_default();
        if env.status.as_deref() == Some("error") {
            bail!("daemon refused signature: {}",
                  env.error.unwrap_or_else(|| "(daemon set status=error but no message)".into()));
        }
        let raw_tx_b64 = result.get("raw_tx").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!(
                "daemon response missing 'raw_tx' field — your daemon may be the unpatched \
                 upstream which can't produce real Solana transactions. \
                 Apply scripts/vendor-patches/vultisig-cli-solana-bytes.patch and rebuild."
            ))?;
        let raw_tx_bytes = base64::engine::general_purpose::STANDARD.decode(raw_tx_b64)
            .context("decoding raw_tx from daemon response")?;
        Ok(bs58::encode(raw_tx_bytes).into_string())
    }

    /// Lower-level: send a generic JSON-RPC call and return the raw response.
    fn request_raw(
        &self,
        method:  &str,
        params:  serde_json::Value,
        timeout: Duration,
    ) -> Result<serde_json::Value> {
        let stream = UnixStream::connect(&self.socket_path)
            .with_context(|| format!("connecting to {}", self.socket_path.display()))?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(HEALTH_TIMEOUT))?;
        let req = serde_json::json!({
            "id":     next_id(),
            "method": method,
            "params": params,
        });
        let mut writer = &stream;
        writeln!(writer, "{}", req)?;
        writer.flush().ok();
        let mut br = BufReader::new(&stream);
        let mut line = String::new();
        br.read_line(&mut line)?;
        if line.trim().is_empty() {
            bail!("daemon closed without sending a response");
        }
        Ok(serde_json::from_str(&line)?)
    }

    /// One-shot request: connect, write a JSON line, read a JSON line, close.
    fn request<P: Serialize, R: serde::de::DeserializeOwned + Default>(
        &self,
        method:  &str,
        params:  P,
        timeout: Duration,
    ) -> Result<RpcResponse<R>> {
        let stream = UnixStream::connect(&self.socket_path)
            .with_context(|| format!("connecting to {}", self.socket_path.display()))?;
        stream.set_read_timeout(Some(timeout))
            .context("setting read timeout")?;
        stream.set_write_timeout(Some(HEALTH_TIMEOUT))
            .context("setting write timeout")?;

        let req = RpcRequest { id: next_id(), method, params };
        let mut writer = &stream;
        writeln!(writer, "{}", serde_json::to_string(&req)?)
            .context("writing request")?;
        writer.flush().ok();

        let reader = BufReader::new(&stream);
        let mut line = String::new();
        let mut br   = reader;
        br.read_line(&mut line).context("reading response")?;
        if line.trim().is_empty() {
            bail!("daemon closed without sending a response");
        }
        serde_json::from_str(&line).with_context(|| format!("parsing response: {}", line.trim()))
    }
}

/// Monotonically increasing request id within the process.
fn next_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ── Tests ────────────────────────────────────────────────────────────────────
//
// We test the wire-protocol client against a stub daemon spun up on a temp
// Unix socket. This catches:
//   - request framing / JSON shape
//   - response parsing for both `result` and `error` shapes
//   - daemon-down detection
//   - timeout behaviour on a hung daemon
//
// Real end-to-end test against the live vultisig daemon is in
// `tests/integration_vultisig.rs` (gated on VULTISIG_DAEMON=1).

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::net::{UnixListener, UnixStream as StdUnixStream};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    /// Spawn a stub daemon that accepts one request, returns a canned reply.
    /// Hardened: read until newline (not just one read), reply, then keep the
    /// connection alive until the test drops the (path, rx) tuple. This avoids
    /// the broken-pipe race we hit with eager `drop(conn)`.
    fn stub_daemon(reply: &'static str) -> (PathBuf, mpsc::Receiver<String>) {
        let dir = std::env::temp_dir().join(format!("sov-vultisig-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(format!("sock-{}", next_id()));
        let _ = std::fs::remove_file(&path);

        let listener = UnixListener::bind(&path).expect("bind socket");
        let (tx, rx) = mpsc::channel();
        let path_clone = path.clone();

        thread::spawn(move || {
            let (conn, _) = match listener.accept() {
                Ok(v)  => v,
                Err(_) => return,
            };
            // Read the request line up to '\n'.
            let mut br = std::io::BufReader::new(conn.try_clone().expect("clone"));
            let mut req_line = String::new();
            let _ = br.read_line(&mut req_line);
            let _ = tx.send(req_line.trim().to_string());

            // Write the canned reply.
            let mut writer = &conn;
            let _ = writer.write_all(reply.as_bytes());
            let _ = writer.write_all(b"\n");
            let _ = writer.flush();

            // Keep the connection open for a beat so the client's read_line
            // can complete before EOF. shutdown(Write) signals "no more data
            // coming" without invalidating the read side.
            std::thread::sleep(Duration::from_millis(50));
            let _ = conn.shutdown(std::net::Shutdown::Both);
            let _ = std::fs::remove_file(&path_clone);
        });
        (path, rx)
    }

    #[test]
    fn is_running_false_when_no_socket() {
        let client = VultisigClient::new("/tmp/sov-no-such-socket-xyzzy.sock");
        assert!(!client.is_running());
    }

    #[test]
    fn solana_address_parses_result_with_address_field() {
        // Current daemon shape (verified end-to-end against vultisig-cli at
        // commit 9f805de): { result: { address, network } }.
        let reply = r#"{"id":1,"jsonrpc":"2.0","result":{"address":"11111111111111111111111111111111","network":"sol"}}"#;
        let (path, _rx) = stub_daemon(reply);
        let client = VultisigClient::new(path);
        let addr = client.solana_address().expect("address");
        assert_eq!(addr, "11111111111111111111111111111111");
    }

    #[test]
    fn solana_address_parses_result_with_legacy_pubkey_field() {
        // Older sol-signer.ts shape we initially coded against. Keep accepting
        // it so a daemon update doesn't silently break us.
        let reply = r#"{"id":1,"result":{"pubkey":"22222222222222222222222222222222"}}"#;
        let (path, _rx) = stub_daemon(reply);
        let client = VultisigClient::new(path);
        let addr = client.solana_address().expect("address");
        assert_eq!(addr, "22222222222222222222222222222222");
    }

    #[test]
    fn missing_both_address_and_pubkey_yields_error() {
        let reply = r#"{"id":1,"result":{"network":"sol"}}"#;
        let (path, _rx) = stub_daemon(reply);
        let client = VultisigClient::new(path);
        let err = client.solana_address().unwrap_err();
        assert!(format!("{}", err).contains("no address/pubkey"));
    }

    #[test]
    fn solana_address_request_shape() {
        let reply = r#"{"id":1,"result":{"pubkey":"x"}}"#;
        let (path, rx) = stub_daemon(reply);
        let client = VultisigClient::new(path);
        let _ = client.solana_address();
        let req = rx.recv_timeout(Duration::from_secs(2)).expect("request");
        // Verify the daemon receives the exact wire shape sol-signer.ts uses.
        assert!(req.contains("\"method\":\"get_address\""));
        assert!(req.contains("\"scheme\":\"eddsa\""));
        assert!(req.contains("\"curve\":\"ed25519\""));
        assert!(req.contains("\"network\":\"sol\""));
    }

    #[test]
    fn sign_request_uses_bytes_payload_shape() {
        // Patched-daemon shape: result.raw_tx is the full signed transaction
        // in base64 (1-byte sig count + 64-byte sig + serialized message).
        // Synthesize: 65 bytes = [0x01] + [0xAA; 64]  (sig prefix + dummy sig,
        // no message because for the test we just want round-trip parsing).
        let mut wire = vec![0x01u8];
        wire.extend_from_slice(&[0xAA; 64]);
        wire.extend_from_slice(&[0xBB; 12]);
        use base64::Engine as _;
        let raw_tx_b64 = base64::engine::general_purpose::STANDARD.encode(&wire);
        let reply = format!(
            r#"{{"id":1,"jsonrpc":"2.0","result":{{"status":"success","raw_tx":"{}","signature":"sig"}}}}"#,
            raw_tx_b64
        );
        let reply_static: &'static str = Box::leak(reply.into_boxed_str());

        let (path, rx) = stub_daemon(reply_static);
        let client = VultisigClient::new(path);
        let message = b"hello-mainnet-message";
        let signed_b58 = client.sign_solana(message).expect("sign");
        // Returned value is base58 of the bytes returned by the daemon.
        let decoded = bs58::decode(&signed_b58).into_vec().expect("b58 decode");
        assert_eq!(decoded, wire);

        let req = rx.recv_timeout(Duration::from_secs(2)).expect("request");
        assert!(req.contains("\"method\":\"sign\""));
        assert!(req.contains("\"network\":\"sol\""));
        // Mode = relay because Fast Vault's second party is VultiServer.
        assert!(req.contains("\"mode\":\"relay\""), "expected mode=relay, got: {}", req);
        // base64("hello-mainnet-message") = "aGVsbG8tbWFpbm5ldC1tZXNzYWdl"
        assert!(req.contains("aGVsbG8tbWFpbm5ldC1tZXNzYWdl"),
            "missing base64-encoded message bytes in payload: {}", req);
        assert!(req.contains("\"broadcast\":false"));
        // We deliberately do NOT send session_id — the daemon auto-generates
        // a UUIDv4, which is what api.vultisig.com/router requires.
        assert!(!req.contains("\"session_id\""),
            "session_id should be omitted; daemon generates it: {}", req);
    }

    #[test]
    fn missing_raw_tx_in_response_surfaces_unpatched_daemon_hint() {
        // Old-shape daemon response — has signature but no raw_tx. We surface
        // a clear "daemon may be unpatched" message instead of silently dying.
        let reply = r#"{"id":1,"jsonrpc":"2.0","result":{"signature":"deadbeef"}}"#;
        let (path, _rx) = stub_daemon(reply);
        let client = VultisigClient::new(path);
        let err = client.sign_solana(b"x").unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("missing 'raw_tx'"), "got: {}", msg);
        assert!(msg.contains("unpatched"), "got: {}", msg);
    }

    #[test]
    fn tunnelled_result_status_error_is_surfaced() {
        // Real daemon shape we observed end-to-end at vultisig-cli @ 9f805de:
        // errors are tunnelled INSIDE result with {status:"error", error:"..."}.
        let reply = r#"{"id":1,"jsonrpc":"2.0","result":{"error":"Missing 'toPubkey' field in Solana transaction","session_id":"abc","status":"error"}}"#;
        let (path, _rx) = stub_daemon(reply);
        let client = VultisigClient::new(path);
        let err = client.sign_solana(b"x").unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("Missing 'toPubkey' field"),
            "expected tunnelled daemon error to be surfaced, got: {}", msg);
        assert!(msg.contains("daemon refused"),
            "expected 'daemon refused' prefix, got: {}", msg);
    }

    #[test]
    fn top_level_error_field_also_surfaces() {
        let reply = r#"{"id":1,"error":{"code":-32000,"message":"oh no"}}"#;
        let (path, _rx) = stub_daemon(reply);
        let client = VultisigClient::new(path);
        let err = client.sign_solana(b"x").unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("daemon error"), "got: {}", msg);
    }

    #[test]
    fn missing_result_and_error_yields_helpful_error() {
        let reply = r#"{"id":1}"#;
        let (path, _rx) = stub_daemon(reply);
        let client = VultisigClient::new(path);
        let err = client.solana_address().unwrap_err();
        assert!(format!("{}", err).contains("no address/pubkey"));
    }

    /// Verify our health-check connects without sending data and doesn't disturb
    /// the daemon. We bind a listener that NEVER reads — if the client wrote
    /// anything, the test would still pass (we just check connect succeeds), but
    /// the contract is "no payload sent during health check".
    #[test]
    fn is_running_true_when_socket_exists_and_accepts() {
        let dir = std::env::temp_dir().join(format!("sov-health-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(format!("sock-{}", next_id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind");
        let path_clone = path.clone();
        thread::spawn(move || {
            // Accept + immediately drop — proves the connect succeeded.
            if let Ok((conn, _)) = listener.accept() {
                drop(conn);
            }
            let _ = std::fs::remove_file(&path_clone);
        });
        let client = VultisigClient::new(&path);
        assert!(client.is_running(), "expected daemon detected as running");
    }

    /// Tiny sanity check that next_id() stays unique across calls.
    #[test]
    fn next_id_is_monotonic() {
        let a = next_id();
        let b = next_id();
        let c = next_id();
        assert!(b > a && c > b);
    }

    // Quiet unused warnings from cfg(test)-only types.
    #[allow(dead_code)]
    fn _unused(_: StdUnixStream) {}
}
