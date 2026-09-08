use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use localscale_agent_protocol::{ClientConfig, HostInvitation};
use localscale_agent_transport::stored_transport_key_from_invitation_secret;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};

pub mod host_registry;
pub mod tor_runtime;

pub use host_registry::{HostPeerEntry, HostPeerRegistry, LocalVirtualIpStore};

const VERSION: &str = "0.1.0";
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const MAX_CONNECTIONS: usize = 16;
const INVITATION_PREFIX: &str = "lsinv1.";
// 10 minutes was tight for a manually-copied invite (walking between two
// physical machines, reading/typing a long string, or just being slower on
// one side) — long enough to feel "fresh" but easy to blow through in
// practice, producing a confusing 410 on a convite the user just generated.
const DEFAULT_INVITATION_TTL_SECS: u64 = 1800;
const MIN_INVITATION_TTL_SECS: u64 = 60;
const MAX_INVITATION_TTL_SECS: u64 = 86_400;
const MAX_INVITATION_CLOCK_SKEW_SECS: u64 = 60;

fn lock_recover<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn remaining_budget(
    started: std::time::Instant,
    total: std::time::Duration,
    now: std::time::Instant,
) -> Option<std::time::Duration> {
    let elapsed = now.saturating_duration_since(started);
    (elapsed < total).then(|| total - elapsed)
}

pub fn health_response() -> &'static str {
    r#"{"status":"ok","service":"localscale"}"#
}

pub fn configuration_html() -> &'static str {
    r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>LocalScale</title>
  <style>
    :root {
      --bg-primary: #0b0f19;
      --bg-surface: #111827;
      --bg-surface-elevated: #1e293b;
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --accent-primary: #3b82f6;
      --accent-hover: #2563eb;
      --accent-active: #1d4ed8;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --border: #334155;
      --border-focus: #60a5fa;
      --radius-sm: 6px;
      --radius-md: 10px;
      --radius-lg: 16px;
      --shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg-primary);
      color: var(--text-primary);
      line-height: 1.5;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 2rem 1rem;
    }
    .container {
      width: 100%;
      max-width: 680px;
      display: flex;
      flex-direction: column;
      gap: 1.5rem;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 1rem;
      border-bottom: 1px solid var(--border);
    }
    .logo-group {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }
    .logo-badge {
      width: 38px;
      height: 38px;
      border-radius: var(--radius-md);
      background: linear-gradient(135deg, var(--accent-primary), #8b5cf6);
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      color: #fff;
      font-size: 1.15rem;
      box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
    }
    h1 {
      font-size: 1.5rem;
      font-weight: 700;
      letter-spacing: -0.025em;
    }
    .subtitle {
      font-size: 0.875rem;
      color: var(--text-muted);
    }
    .badge-refresh {
      background: var(--bg-surface-elevated);
      color: var(--text-secondary);
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 0.35rem 0.75rem;
      font-size: 0.8rem;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      transition: all 0.2s ease;
    }
    .badge-refresh:hover {
      background: var(--border);
      color: var(--text-primary);
    }
    .card {
      background: var(--bg-surface);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      padding: 1.5rem;
      box-shadow: var(--shadow);
      display: flex;
      flex-direction: column;
      gap: 1.25rem;
    }
    .card-title {
      font-size: 1rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-secondary);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .status-row {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }
    .pulse-indicator {
      width: 12px;
      height: 12px;
      border-radius: 50%;
      background-color: var(--text-muted);
      position: relative;
    }
    .pulse-indicator.running {
      background-color: var(--success);
      box-shadow: 0 0 10px var(--success);
    }
    .pulse-indicator.starting, .pulse-indicator.stopping {
      background-color: var(--warning);
      box-shadow: 0 0 10px var(--warning);
    }
    .pulse-indicator.error {
      background-color: var(--danger);
      box-shadow: 0 0 10px var(--danger);
    }
    .status-text {
      font-size: 1.2rem;
      font-weight: 600;
      text-transform: capitalize;
    }
    .mode-toggle-group {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 0.75rem;
    }
    .mode-btn {
      background: var(--bg-surface-elevated);
      color: var(--text-secondary);
      border: 2px solid transparent;
      padding: 0.85rem;
      border-radius: var(--radius-md);
      font-weight: 600;
      font-size: 0.95rem;
      cursor: pointer;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 0.25rem;
      transition: all 0.2s ease;
    }
    .mode-btn span.mode-desc {
      font-size: 0.75rem;
      font-weight: 400;
      color: var(--text-muted);
    }
    .mode-btn:hover {
      background: #253349;
      color: var(--text-primary);
    }
    .mode-btn.active {
      border-color: var(--accent-primary);
      background: rgba(59, 130, 246, 0.15);
      color: #93c5fd;
    }
    .mode-btn.active span.mode-desc {
      color: #bfdbfe;
    }
    .action-group {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
    }
    .btn {
      flex: 1;
      min-width: 110px;
      padding: 0.75rem 1rem;
      font-size: 0.9rem;
      font-weight: 600;
      border-radius: var(--radius-md);
      border: none;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      transition: all 0.2s ease;
    }
    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }
    .btn-primary {
      background: var(--accent-primary);
      color: #fff;
    }
    .btn-primary:hover:not(:disabled) {
      background: var(--accent-hover);
    }
    .btn-secondary {
      background: var(--bg-surface-elevated);
      color: var(--text-primary);
      border: 1px solid var(--border);
    }
    .btn-secondary:hover:not(:disabled) {
      background: var(--border);
    }
    .btn-danger {
      background: rgba(239, 68, 68, 0.15);
      color: #fca5a5;
      border: 1px solid rgba(239, 68, 68, 0.3);
    }
    .btn-danger:hover:not(:disabled) {
      background: rgba(239, 68, 68, 0.25);
    }
    .field-group {
      display: flex;
      flex-direction: column;
      gap: 0.4rem;
    }
    .field-label {
      font-size: 0.8rem;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .input-with-action {
      display: flex;
      gap: 0.5rem;
    }
    .input-text {
      flex: 1;
      background: var(--bg-surface-elevated);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      padding: 0.65rem 0.85rem;
      color: var(--text-primary);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.85rem;
      outline: none;
    }
    .input-text:focus {
      border-color: var(--border-focus);
    }
    .btn-icon {
      background: var(--bg-surface-elevated);
      border: 1px solid var(--border);
      color: var(--text-secondary);
      border-radius: var(--radius-md);
      padding: 0.65rem 1rem;
      font-weight: 500;
      font-size: 0.85rem;
      cursor: pointer;
      transition: all 0.2s ease;
    }
    .btn-icon:hover {
      background: var(--border);
      color: var(--text-primary);
    }
    .toast-message {
      padding: 0.75rem 1rem;
      border-radius: var(--radius-md);
      font-size: 0.85rem;
      background: rgba(59, 130, 246, 0.1);
      border: 1px solid rgba(59, 130, 246, 0.25);
      color: #93c5fd;
      display: none;
    }
    .toast-message.error {
      background: rgba(239, 68, 68, 0.1);
      border-color: rgba(239, 68, 68, 0.25);
      color: #fca5a5;
    }
    details {
      background: var(--bg-surface-elevated);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      padding: 0.75rem 1rem;
      font-size: 0.85rem;
    }
    summary {
      cursor: pointer;
      font-weight: 600;
      color: var(--text-secondary);
    }
    summary:hover {
      color: var(--text-primary);
    }
    pre {
      margin-top: 0.75rem;
      overflow-x: auto;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.78rem;
      color: #94a3b8;
    }
    footer {
      text-align: center;
      font-size: 0.75rem;
      color: var(--text-muted);
      margin-top: 1rem;
    }
  </style>
</head>
<body>
  <main class="container">
    <header>
      <div class="logo-group">
        <div class="logo-badge">LS</div>
        <div>
          <h1>LocalScale</h1>
          <div class="subtitle">Local-First Secure Agent Control</div>
        </div>
      </div>
      <button class="badge-refresh" id="refreshBtn" onclick="refreshStatus()">
        <span>↻</span> Refresh
      </button>
    </header>

    <div id="toastMessage" class="toast-message"></div>

    <section class="card">
      <div class="card-title">
        <span>Operating Status</span>
        <span id="versionLabel" class="subtitle">v0.1.0</span>
      </div>
      <div class="status-row">
        <div id="statusIndicator" class="pulse-indicator"></div>
        <div id="statusText" class="status-text">Connecting...</div>
      </div>

      <div class="field-group">
        <div class="field-label">Node Role</div>
        <div class="mode-toggle-group">
          <button type="button" class="mode-btn" id="modeBtnHost" onclick="selectMode('host')">
            <span>Host Mode</span>
            <span class="mode-desc">Publishes Tor v3 Onion service</span>
          </button>
          <button type="button" class="mode-btn" id="modeBtnCliente" onclick="selectMode('cliente')">
            <span>Cliente Mode</span>
            <span class="mode-desc">Connects outbound to Host</span>
          </button>
        </div>
      </div>

      <div class="field-group" id="endpointGroup">
        <div class="field-label">Public Onion Endpoint</div>
        <div class="input-with-action">
          <input type="text" id="onionEndpoint" class="input-text" readonly placeholder="Available in Host mode when running" />
          <button type="button" class="btn-icon" id="copyBtn" onclick="copyEndpoint()">Copy</button>
        </div>
      </div>

      <div class="action-group">
        <button type="button" class="btn btn-primary" id="btnStart" onclick="callServiceAction('start')">▶ Start</button>
        <button type="button" class="btn btn-danger" id="btnStop" onclick="callServiceAction('stop')">⏹ Stop</button>
        <button type="button" class="btn btn-secondary" id="btnSync" onclick="callServiceAction('sync')">⟳ Sync</button>
      </div>
    </section>

    <section class="card">
      <div class="card-title">
        <span>Onion Network & Virtual IP</span>
        <span class="subtitle" style="color: var(--success); font-size: 0.75rem;">🧅 Tor-Only Isolation</span>
      </div>

      <div class="field-group">
        <div class="field-label">Local Virtual IP (Mesh Overlay)</div>
        <div class="input-with-action">
          <input type="text" id="virtualIpInput" class="input-text" placeholder="e.g. 10.42.0.1" />
          <button type="button" class="btn-icon" onclick="saveVirtualIp()">Salvar IP</button>
        </div>
        <span class="subtitle" style="font-size: 0.75rem; margin-top: 0.25rem;">Tráfego 100% via rede Onion. Nenhuma conexão aberta na LAN local.</span>
      </div>

      <div class="field-group">
        <div class="field-label">Dispositivos na Rede Onion</div>
        <div id="devicesContainer" style="display: flex; flex-direction: column; gap: 0.5rem; font-size: 0.85rem;">
          <div style="color: var(--text-muted);">Carregando dispositivos...</div>
        </div>
      </div>
    </section>

    <details>
      <summary>Agent Diagnostics & Safety Info</summary>
      <pre id="diagJson">Fetching diagnostics...</pre>
    </details>

    <footer>
      Protected by strict loopback policy. Administrative interface is never exposed over external or Onion networks.
    </footer>
  </main>

  <script>
    let currentMode = 'cliente';
    let currentState = 'stopped';

    function showToast(msg, isError = false) {
      const toast = document.getElementById('toastMessage');
      toast.textContent = msg;
      toast.className = 'toast-message' + (isError ? ' error' : '');
      toast.style.display = 'block';
      setTimeout(() => { toast.style.display = 'none'; }, 4000);
    }

    // Device values come from the local peer store and must never become HTML.
    // textContent performs the escaping before the value is read back as HTML.
    function escapeHtml(value) {
      const element = document.createElement('div');
      element.textContent = String(value ?? '');
      return element.innerHTML;
    }

    function updateUi(status) {
      currentState = status.state || 'stopped';
      currentMode = status.mode || 'cliente';

      const indicator = document.getElementById('statusIndicator');
      indicator.className = 'pulse-indicator ' + currentState;

      document.getElementById('statusText').textContent = currentState;

      const hostBtn = document.getElementById('modeBtnHost');
      const clienteBtn = document.getElementById('modeBtnCliente');
      if (currentMode === 'host') {
        hostBtn.classList.add('active');
        clienteBtn.classList.remove('active');
      } else {
        clienteBtn.classList.add('active');
        hostBtn.classList.remove('active');
      }

      const onionInput = document.getElementById('onionEndpoint');
      onionInput.value = status.onion_endpoint || '';

      const isRunning = currentState === 'running';
      document.getElementById('btnStart').disabled = isRunning || currentState === 'starting';
      document.getElementById('btnStop').disabled = currentState === 'stopped' || currentState === 'stopping';
    }

    async function refreshStatus() {
      try {
        const res = await fetch('/api/v1/status');
        if (!res.ok) throw new Error('Status HTTP ' + res.status);
        const data = await res.json();
        updateUi(data);
      } catch (err) {
        document.getElementById('statusText').textContent = 'Agent unreachable';
        document.getElementById('statusIndicator').className = 'pulse-indicator error';
      }
      loadDiagnostics();
    }

    async function selectMode(mode) {
      try {
        const res = await fetch('/api/v1/mode', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mode: mode })
        });
        if (!res.ok) throw new Error('Mode update HTTP ' + res.status);
        const data = await res.json();
        updateUi(data);
        showToast('Mode switched to ' + mode);
      } catch (err) {
        showToast('Failed to switch mode: ' + err.message, true);
      }
    }

    async function callServiceAction(action) {
      try {
        const url = action === 'sync' ? '/api/v1/sync' : '/api/v1/service/' + action;
        const res = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' }
        });
        if (!res.ok) throw new Error('Action HTTP ' + res.status);
        const data = await res.json();
        updateUi(data);
        showToast('Service ' + action + ' requested');
      } catch (err) {
        showToast('Service ' + action + ' failed: ' + err.message, true);
      }
    }

    async function loadDiagnostics() {
      try {
        const res = await fetch('/diagnostics');
        if (res.ok) {
          const data = await res.json();
          document.getElementById('diagJson').textContent = JSON.stringify(data, null, 2);
        }
      } catch (_) {}
    }

    async function loadDevices() {
      try {
        const res = await fetch('/api/v1/devices');
        if (!res.ok) return;
        const data = await res.json();
        const container = document.getElementById('devicesContainer');
        const local = data.local_device;
        const peers = data.remote_peers || [];
        
        const virtualIpInput = document.getElementById('virtualIpInput');
        if (local && local.virtual_ip && document.activeElement !== virtualIpInput) {
          virtualIpInput.value = local.virtual_ip;
        }

        let html = '';
        if (local) {
          html += '<div style="background: var(--bg-surface-elevated); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 0.6rem 0.8rem; display: flex; justify-content: space-between; align-items: center;">';
          html += '<div><strong>💻 ' + escapeHtml(local.node_id || 'Este Dispositivo') + '</strong> <span style="color: var(--accent-primary); font-size: 0.75rem;">(' + escapeHtml(local.role) + ')</span><br><span style="color: var(--text-muted); font-size: 0.75rem;">IP Virtual: ' + escapeHtml(local.virtual_ip || 'não atribuído') + '</span></div>';
          html += '<span style="background: rgba(16, 185, 129, 0.15); color: var(--success); padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem;">● Local</span>';
          html += '</div>';
        }

        if (peers.length === 0) {
          html += '<div style="color: var(--text-muted); font-size: 0.8rem; font-style: italic; padding: 0.4rem 0;">Nenhum outro peer emparelhado na rede Onion ainda.</div>';
        } else {
          for (const peer of peers) {
            html += '<div style="background: var(--bg-surface-elevated); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 0.6rem 0.8rem; display: flex; justify-content: space-between; align-items: center;">';
            html += '<div><strong>🔗 ' + escapeHtml(peer.node_id || 'Peer Remoto') + '</strong> <span style="color: var(--accent-primary); font-size: 0.75rem;">(' + escapeHtml(peer.role) + ')</span><br><span style="color: var(--text-muted); font-size: 0.75rem;">IP Virtual: ' + escapeHtml(peer.virtual_ip || 'auto') + ' | Onion: ' + escapeHtml(peer.onion_endpoint ? peer.onion_endpoint.substring(0, 16) + '...' : '-') + '</span></div>';
            html += '<span style="background: rgba(59, 130, 246, 0.15); color: #93c5fd; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem;">' + escapeHtml(peer.status) + '</span>';
            html += '</div>';
          }
        }
        container.innerHTML = html;
      } catch (_) {}
    }

    async function saveVirtualIp() {
      const input = document.getElementById('virtualIpInput');
      const ip = input.value.trim();
      try {
        const res = await fetch('/api/v1/peer/virtual-ip', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ virtual_ip: ip })
        });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        showToast('IP Virtual ' + (ip ? ip : 'removido') + ' salvo com sucesso!');
        loadDevices();
      } catch (err) {
        showToast('Falha ao salvar IP Virtual: ' + err.message, true);
      }
    }

    refreshStatus();
    loadDevices();
    setInterval(refreshStatus, 4000);
    setInterval(loadDevices, 4000);
  </script>
</body>
</html>"#
}

#[derive(Clone)]
struct AgentState {
    mode: Arc<Mutex<String>>,
    service_state: Arc<Mutex<String>>,
    peer: Arc<Mutex<PeerState>>,
    peer_store: Option<Arc<Mutex<PeerStore>>>,
    role_store: Option<Arc<Mutex<RoleStore>>>,
    peer_transport_enabled: Arc<AtomicBool>,
    peer_transport_status: PeerTransportStatus,
    peer_transport_restart_required: Arc<AtomicBool>,
    runtime_restart: RuntimeRestart,
    // Host role only — an arbitrary number of invited/paired Clientes (see
    // `host_registry` module docs). `None` when this device has never run
    // as Host (or in tests that don't exercise multi-peer pairing).
    host_registry: Option<Arc<Mutex<HostPeerRegistry>>>,
    host_local_virtual_ip: Option<Arc<Mutex<LocalVirtualIpStore>>>,
    // Live (never persisted) per-Cliente connection status, keyed by node
    // id — one `PeerTransportStatus` per currently-or-previously-connected
    // device this process has seen since it started, so `devices_status()`
    // can report "offline" (last seen, but not currently connected)
    // instead of a device silently vanishing from the list.
    host_peer_live: Arc<Mutex<std::collections::HashMap<String, PeerTransportStatus>>>,
}

/// Coordinates a process restart without letting an HTTP request handler call
/// `process::exit`. The binary owns the actual exit code; tests can inspect
/// these flags without terminating the test runner.
#[derive(Clone, Default)]
struct RuntimeRestart {
    scheduled: Arc<AtomicBool>,
    dispatched: Arc<AtomicBool>,
    requested: Arc<AtomicBool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportState {
    Unavailable = 0,
    Connecting = 1,
    Connected = 2,
    Retrying = 3,
    Disabled = 4,
    RestartRequired = 5,
    WaitingForInvitation = 6,
}

const PEER_ACTIVITY_TTL_SECS: u64 = 15;

#[derive(Clone, Debug)]
pub struct PeerTransportStatus {
    state: Arc<std::sync::atomic::AtomicU8>,
    last_peer_activity_unix: Arc<AtomicU64>,
    messages_exchanged: Arc<AtomicU64>,
    // The peer node id actually learned from a completed, authenticated
    // handshake (see `AuthenticatedStream::peer_node_id`). This is distinct
    // from `PeerState::host_node_id`, which is only ever populated for the
    // Cliente role (the Host's approved-peer record intentionally omits it,
    // see `validate_approved_peer_record`). Without this, `devices_status()`
    // had no way to learn the real identity of a connected client and fell
    // back to a generic "remote-client" label forever.
    remote_node_id: Arc<Mutex<Option<String>>>,
    // The peer's own configured virtual/overlay IP, learned the same way as
    // `remote_node_id` — piggybacked on the ping/pong heartbeat (see
    // `heartbeat_frame` in the transport crate) — since nothing else ever
    // told either side what address the other actually chose. Without this,
    // `devices_status()` either fabricated a guess (swapping the last IP
    // octet between .1/.2) or, once that was removed, showed nothing at all.
    remote_virtual_ip: Arc<Mutex<Option<String>>>,
    // This device's own configured virtual IP, mirrored here so the running
    // transport thread (host accept-loop or client dial-loop) can read the
    // *current* value on every heartbeat instead of the value it captured
    // once at thread-spawn time. Without this, changing the virtual IP while
    // already connected silently did nothing until the next restart, even
    // though nothing about applying it actually requires tearing down the
    // Tor/peer connection — see `set_virtual_ip_handler`, which updates this
    // alongside the persisted record.
    local_virtual_ip: Arc<Mutex<String>>,
}

impl Default for PeerTransportStatus {
    fn default() -> Self {
        Self {
            state: Arc::new(std::sync::atomic::AtomicU8::new(
                TransportState::Unavailable as u8,
            )),
            last_peer_activity_unix: Arc::new(AtomicU64::new(0)),
            messages_exchanged: Arc::new(AtomicU64::new(0)),
            remote_node_id: Arc::new(Mutex::new(None)),
            remote_virtual_ip: Arc::new(Mutex::new(None)),
            local_virtual_ip: Arc::new(Mutex::new(String::new())),
        }
    }
}

impl PeerTransportStatus {
    pub fn set(&self, state: TransportState) {
        self.state.store(state as u8, Ordering::Release);
    }

    pub fn get(&self) -> TransportState {
        match self.state.load(Ordering::Acquire) {
            1 => TransportState::Connecting,
            2 => TransportState::Connected,
            3 => TransportState::Retrying,
            4 => TransportState::Disabled,
            5 => TransportState::RestartRequired,
            6 => TransportState::WaitingForInvitation,
            _ => TransportState::Unavailable,
        }
    }

    pub fn record_peer_activity(&self, messages: u64) {
        self.messages_exchanged
            .fetch_add(messages, Ordering::AcqRel);
        self.last_peer_activity_unix
            .store(unix_time_secs().unwrap_or(0), Ordering::Release);
        self.set(TransportState::Connected);
    }

    pub fn last_peer_activity_unix(&self) -> u64 {
        self.last_peer_activity_unix.load(Ordering::Acquire)
    }

    pub fn messages_exchanged(&self) -> u64 {
        self.messages_exchanged.load(Ordering::Acquire)
    }

    pub fn is_connected(&self) -> bool {
        self.get() == TransportState::Connected
            && self.last_peer_activity_unix() != 0
            && unix_time_secs()
                .unwrap_or(0)
                .saturating_sub(self.last_peer_activity_unix())
                <= PEER_ACTIVITY_TTL_SECS
    }

    fn label(&self) -> &'static str {
        match self.get() {
            TransportState::Unavailable => "unavailable",
            TransportState::Connecting => "connecting",
            TransportState::Connected => "connected",
            TransportState::Retrying => "retrying",
            TransportState::Disabled => "disabled",
            TransportState::RestartRequired => "restart_required",
            TransportState::WaitingForInvitation => "waiting_for_invitation",
        }
    }

    /// Records the peer node id authenticated during the most recent
    /// handshake (Host side: the connecting Cliente's real node id).
    pub fn set_remote_node_id(&self, node_id: impl Into<String>) {
        *lock_recover(&self.remote_node_id) = Some(node_id.into());
    }

    /// Clears any handshake-learned remote node id, e.g. on peer reset.
    pub fn clear_remote_node_id(&self) {
        *lock_recover(&self.remote_node_id) = None;
    }

    pub fn remote_node_id(&self) -> Option<String> {
        lock_recover(&self.remote_node_id).clone()
    }

    /// Records the peer's own advertised virtual IP from the most recent
    /// heartbeat. An empty string means the peer authenticated but has no
    /// virtual IP configured, which is treated the same as unknown.
    pub fn set_remote_virtual_ip(&self, virtual_ip: impl Into<String>) {
        let virtual_ip = virtual_ip.into();
        *lock_recover(&self.remote_virtual_ip) = if virtual_ip.is_empty() {
            None
        } else {
            Some(virtual_ip)
        };
    }

    /// Clears any handshake-learned remote virtual IP, e.g. on peer reset.
    pub fn clear_remote_virtual_ip(&self) {
        *lock_recover(&self.remote_virtual_ip) = None;
    }

    pub fn remote_virtual_ip(&self) -> Option<String> {
        lock_recover(&self.remote_virtual_ip).clone()
    }

    /// Updates this device's own virtual IP for any already-running
    /// transport thread to pick up on its next heartbeat — no restart.
    pub fn set_local_virtual_ip(&self, virtual_ip: impl Into<String>) {
        *lock_recover(&self.local_virtual_ip) = virtual_ip.into();
    }

    pub fn local_virtual_ip(&self) -> String {
        lock_recover(&self.local_virtual_ip).clone()
    }
}

#[derive(Clone, Default)]
struct PeerState {
    configured: bool,
    node_id: Option<String>,
    host_node_id: Option<String>,
    endpoint: Option<String>,
    virtual_ip: Option<String>,
    transport: &'static str,
    approved: bool,
    revoked: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PeerRecord {
    pub role: String,
    pub node_id: String,
    pub host_node_id: Option<String>,
    pub endpoint: String,
    pub invitation_secret: String,
    pub virtual_ip: Option<String>,
    pub approved: bool,
    pub revoked: bool,
}

impl std::fmt::Debug for PeerRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PeerRecord")
            .field("role", &self.role)
            .field("node_id", &self.node_id)
            .field("host_node_id", &self.host_node_id)
            .field("endpoint", &self.endpoint)
            .field("invitation_secret", &"[REDACTED]")
            .field("virtual_ip", &self.virtual_ip)
            .field("approved", &self.approved)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone)]
pub struct PeerStore {
    path: PathBuf,
    record: Option<PeerRecord>,
}

#[derive(Clone, Debug)]
pub struct RoleStore {
    path: PathBuf,
    role: Option<String>,
}

impl RoleStore {
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let role = match std::fs::read_to_string(&path) {
            Ok(value) => {
                let role = value.trim();
                if !matches!(role, "host" | "cliente") {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid role store",
                    ));
                }
                Some(role.to_owned())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if path.exists() {
            PeerStore::validate_file(&path, &std::fs::symlink_metadata(&path)?)?;
        }
        Ok(Self { path, role })
    }

    pub fn role(&self) -> Option<&str> {
        self.role.as_deref()
    }

    pub fn set(&mut self, role: &str) -> std::io::Result<bool> {
        if !matches!(role, "host" | "cliente") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid role",
            ));
        }
        if self.role.as_deref() == Some(role) {
            return Ok(false);
        }
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;
        let tmp = self.path.with_extension("tmp");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(role.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        std::fs::rename(&tmp, &self.path)?;
        self.role = Some(role.to_owned());
        Ok(true)
    }
}

impl std::fmt::Debug for PeerStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PeerStore")
            .field("path", &self.path)
            .field("record", &self.record)
            .finish()
    }
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

impl PeerStore {
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let record = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => {
                Self::validate_file(&path, &metadata)?;
                let (record, legacy_secret) = Self::read_record(&path)?;
                let store = Self {
                    path: path.clone(),
                    record: Some(record.clone()),
                };
                if legacy_secret {
                    store.write_record(&record)?;
                }
                Some(record)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        Ok(Self { path, record })
    }
    pub fn record(&self) -> Option<&PeerRecord> {
        self.record.as_ref()
    }
    pub fn ephemeral() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "localscale-peer-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        Self::open(path)
    }
    pub fn configure(&mut self, mut record: PeerRecord) -> std::io::Result<()> {
        if !record.invitation_secret.starts_with("key-v1-") {
            record.invitation_secret =
                stored_transport_key_from_invitation_secret(&record.invitation_secret);
        }
        self.write_record(&record)?;
        self.record = Some(record);
        Ok(())
    }

    pub fn clear(&mut self) -> std::io::Result<()> {
        if self.path.exists() {
            std::fs::remove_file(&self.path)?;
        }
        self.record = None;
        Ok(())
    }
    fn consume_invitation_id(&self, invitation_id: &str) -> std::io::Result<bool> {
        // invitation_id is validated as base64url before reaching this method,
        // so it cannot escape the peer-store directory or alter the suffix.
        let file_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("peer-record.json");
        let marker = self
            .path
            .with_file_name(format!("{file_name}.consumed-{invitation_id}"));
        if let Some(parent) = marker.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker)
        {
            Ok(mut file) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600))?;
                }
                file.write_all(b"consumed\n")?;
                file.sync_all()?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(error),
        }
    }
    pub fn set_approval(&mut self, approved: bool) -> std::io::Result<()> {
        let Some(mut record) = self.record.clone() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "peer is not configured",
            ));
        };
        record.approved = approved;
        record.revoked = !approved;
        self.write_record(&record)?;
        self.record = Some(record);
        Ok(())
    }
    pub fn set_virtual_ip(&mut self, virtual_ip: Option<String>) -> std::io::Result<()> {
        let mut record = self.record.clone().unwrap_or_else(|| PeerRecord {
            role: "cliente".into(),
            node_id: "local-node".into(),
            host_node_id: None,
            endpoint: "pending.onion".into(),
            invitation_secret: "unconfigured".into(),
            virtual_ip: None,
            approved: false,
            revoked: false,
        });
        record.virtual_ip = virtual_ip;
        self.write_record(&record)?;
        self.record = Some(record);
        Ok(())
    }
    fn validate_file(path: &Path, metadata: &std::fs::Metadata) -> std::io::Result<()> {
        if !metadata.file_type().is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "peer store must be a regular file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // Root already has unrestricted access to every file on the
            // system regardless of this check, so it protects nothing when
            // the daemon itself runs as root (e.g. the opt-in TUN bridge on
            // macOS, which needs root to open a `utun` socket) — only
            // exempt uid 0 here, every other uid still must own the file.
            if metadata.uid() != effective_uid() && effective_uid() != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "peer store has the wrong owner",
                ));
            }
            if metadata.mode() & 0o044 != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "peer store is readable by group or other users",
                ));
            }
        }
        let _ = path;
        Ok(())
    }
    fn read_record(path: &Path) -> std::io::Result<(PeerRecord, bool)> {
        let body = std::fs::read_to_string(path)?;
        let fields = parse_json_fields(&body).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid peer store")
        })?;
        let role = fields.get("role").cloned().unwrap_or_default();
        let node_id = fields.get("node_id").cloned().unwrap_or_default();
        let endpoint = fields.get("endpoint").cloned().unwrap_or_default();
        let legacy_secret = fields.get("invitation_secret").cloned();
        let invitation_secret = fields
            .get("transport_key")
            .cloned()
            .or_else(|| {
                legacy_secret
                    .as_ref()
                    .map(|secret| stored_transport_key_from_invitation_secret(secret))
            })
            .unwrap_or_default();
        let approved = fields.get("approved").map(|v| v == "true").unwrap_or(false);
        let revoked = fields.get("revoked").map(|v| v == "true").unwrap_or(true);
        let host_node_id = fields
            .get("host_node_id")
            .cloned()
            .filter(|v| !v.is_empty());
        let virtual_ip = fields.get("virtual_ip").cloned().filter(|v| !v.is_empty());
        if role.is_empty()
            || node_id.is_empty()
            || endpoint.is_empty()
            || invitation_secret.is_empty()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "incomplete peer store",
            ));
        }
        Ok((
            PeerRecord {
                role,
                node_id,
                host_node_id,
                endpoint,
                invitation_secret,
                virtual_ip,
                approved,
                revoked,
            },
            legacy_secret.is_some(),
        ))
    }
    fn write_record(&self, record: &PeerRecord) -> std::io::Result<()> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;
        let tmp = self.path.with_extension("tmp");
        let body = format!(
            "{{\"role\":{},\"node_id\":{},\"host_node_id\":{},\"endpoint\":{},\"transport_key\":{},\"virtual_ip\":{},\"approved\":{},\"revoked\":{}}}",
            json_string(&record.role),
            json_string(&record.node_id),
            json_string(record.host_node_id.as_deref().unwrap_or("")),
            json_string(&record.endpoint),
            json_string(&record.invitation_secret),
            json_string(record.virtual_ip.as_deref().unwrap_or("")),
            record.approved,
            record.revoked
        );
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(body.as_bytes())?;
        file.sync_all()?;
        #[cfg(unix)]
        {
            let metadata = std::fs::symlink_metadata(&tmp)?;
            Self::validate_file(&tmp, &metadata)?;
        }
        std::fs::rename(&tmp, &self.path)?;
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    }
}

impl Default for AgentState {
    fn default() -> Self {
        Self {
            mode: Arc::new(Mutex::new("cliente".to_string())),
            // The agent has no real "stopped" mode of its own: it always
            // starts and starts serving immediately, and whether a peer
            // connection is actually up is governed entirely by
            // `peer_transport_enabled`/approval, not by this cosmetic label.
            // Defaulting it to "stopped" meant that every process restart
            // (which happens routinely — approving a peer, importing an
            // invitation, or just reloading config) made the UI flash
            // "Stopped" even though the daemon and any approved peer
            // connection kept working exactly as before, which reads as a
            // spurious outage to anyone actually depending on the agent
            // staying reachable.
            service_state: Arc::new(Mutex::new("running".to_string())),
            peer: Arc::new(Mutex::new(PeerState {
                transport: "unavailable",
                ..PeerState::default()
            })),
            peer_store: PeerStore::ephemeral().ok().map(|s| Arc::new(Mutex::new(s))),
            role_store: RoleStore::open(std::env::temp_dir().join(format!(
                    "localscale-role-{}-{}.txt",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos()
                )))
            .ok()
            .map(|s| Arc::new(Mutex::new(s))),
            peer_transport_enabled: Arc::new(AtomicBool::new(true)),
            peer_transport_status: PeerTransportStatus::default(),
            peer_transport_restart_required: Arc::new(AtomicBool::new(false)),
            runtime_restart: RuntimeRestart::default(),
            host_registry: HostPeerRegistry::open(std::env::temp_dir().join(format!(
                    "localscale-host-registry-{}-{}.json",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos()
                )))
            .ok()
            .map(|r| Arc::new(Mutex::new(r))),
            host_local_virtual_ip: LocalVirtualIpStore::open(std::env::temp_dir().join(format!(
                    "localscale-host-local-ip-{}-{}.txt",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos()
                )))
            .ok()
            .map(|s| Arc::new(Mutex::new(s))),
            host_peer_live: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }
}

pub fn serve(listener: TcpListener) -> std::io::Result<()> {
    serve_with_state(listener, None, None, None)
}

pub fn serve_with_peer_transport_gate(
    listener: TcpListener,
    gate: Arc<AtomicBool>,
) -> std::io::Result<()> {
    serve_with_state(listener, Some(gate), None, None)
}

pub fn serve_with_peer_transport(
    listener: TcpListener,
    gate: Arc<AtomicBool>,
    status: PeerTransportStatus,
) -> std::io::Result<()> {
    serve_with_state(listener, Some(gate), Some(status), None)
}

/// Same as `serve_with_peer_transport`, plus the Host-role multi-peer
/// state — shared with `start_peer_transport`'s accept loop (spawned
/// earlier in the *same* process/`main()`, not a separate one) so a
/// device this HTTP API just invited or removed is immediately visible to
/// the next handshake attempt, and a connection that loop just accepted
/// is immediately visible to `devices_status()` — no restart needed for
/// either direction, unlike the legacy single-peer Cliente role's
/// file-based `PeerStore` handoff (see `mark_peer_changed`).
pub fn serve_with_peer_transport_and_host_registry(
    listener: TcpListener,
    gate: Arc<AtomicBool>,
    status: PeerTransportStatus,
    host_registry: Arc<Mutex<HostPeerRegistry>>,
    host_local_virtual_ip: Arc<Mutex<LocalVirtualIpStore>>,
    host_peer_live: Arc<Mutex<std::collections::HashMap<String, PeerTransportStatus>>>,
) -> std::io::Result<()> {
    serve_with_state(
        listener,
        Some(gate),
        Some(status),
        Some((host_registry, host_local_virtual_ip, host_peer_live)),
    )
}

#[allow(clippy::type_complexity)]
fn serve_with_state(
    listener: TcpListener,
    gate: Option<Arc<AtomicBool>>,
    status: Option<PeerTransportStatus>,
    host_shared: Option<(
        Arc<Mutex<HostPeerRegistry>>,
        Arc<Mutex<LocalVirtualIpStore>>,
        Arc<Mutex<std::collections::HashMap<String, PeerTransportStatus>>>,
    )>,
) -> std::io::Result<()> {
    let peer_store = match std::env::var_os("LOCALSCALE_PEER_STORE") {
        Some(path) => {
            match PeerStore::open(path) {
                Ok(store) => Some(store),
                Err(error) => {
                    eprintln!("LocalScale peer store unavailable; control API remains available ({error})");
                    None
                }
            }
        }
        None => PeerStore::ephemeral().ok(),
    };
    let role_path = std::env::var_os("LOCALSCALE_ROLE_STORE")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("LOCALSCALE_PEER_STORE")
                .map(|path| PathBuf::from(path).with_file_name("selected-role"))
        });
    let role_store = role_path.and_then(|path| RoleStore::open(path).ok());
    // Sibling files next to the peer store's own path, same pattern as
    // `role_path` above — so a real (non-ephemeral) `LOCALSCALE_PEER_STORE`
    // gives the Host registry and its own virtual IP a real, persistent
    // home too, instead of falling back to `AgentState::default()`'s
    // per-process temp files (fine for tests, wrong for a real daemon).
    let host_registry_path = std::env::var_os("LOCALSCALE_PEER_STORE")
        .map(|path| PathBuf::from(path).with_file_name("host-peers.json"));
    let host_local_virtual_ip_path = std::env::var_os("LOCALSCALE_PEER_STORE")
        .map(|path| PathBuf::from(path).with_file_name("host-local-virtual-ip"));
    let state = AgentState {
        peer_store: peer_store.map(|s| Arc::new(Mutex::new(s))),
        role_store: role_store.map(|s| Arc::new(Mutex::new(s))),
        peer_transport_enabled: gate.unwrap_or_else(|| Arc::new(AtomicBool::new(true))),
        peer_transport_status: status.unwrap_or_default(),
        host_registry: host_shared
            .as_ref()
            .map(|(registry, _, _)| registry.clone())
            .or_else(|| {
                host_registry_path
                    .and_then(|path| HostPeerRegistry::open(path).ok())
                    .map(|r| Arc::new(Mutex::new(r)))
            }),
        host_local_virtual_ip: host_shared
            .as_ref()
            .map(|(_, local_ip, _)| local_ip.clone())
            .or_else(|| {
                host_local_virtual_ip_path
                    .and_then(|path| LocalVirtualIpStore::open(path).ok())
                    .map(|s| Arc::new(Mutex::new(s)))
            }),
        host_peer_live: host_shared
            .as_ref()
            .map(|(_, _, live)| live.clone())
            .unwrap_or_else(|| Arc::new(Mutex::new(std::collections::HashMap::new()))),
        ..AgentState::default()
    };
    if let Some(store) = &state.role_store {
        if let Some(role) = lock_recover(store).role() {
            *lock_recover(&state.mode) = role.to_owned();
        }
    }
    if let Some(store) = &state.peer_store {
        if let Some(record) = lock_recover(store).record().cloned() {
            let mut peer = lock_recover(&state.peer);
            peer.configured = true;
            peer.node_id = Some(record.node_id);
            peer.host_node_id = record.host_node_id;
            peer.endpoint = Some(record.endpoint);
            peer.virtual_ip = record.virtual_ip;
            peer.approved = record.approved;
            peer.revoked = record.revoked;
        }
    }
    let active = Arc::new(Mutex::new(0usize));
    listener.set_nonblocking(true)?;
    loop {
        if state.runtime_restart.requested.load(Ordering::Acquire) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "runtime restart requested",
            ));
        }
        let stream = match listener.accept() {
            Ok((stream, _)) => {
                // Accepted sockets can inherit the listener's non-blocking
                // mode on some platforms. Request parsing relies on its
                // deadline-based blocking reads, so restore that mode before
                // handing the stream to a connection worker.
                if let Err(error) = stream.set_nonblocking(false) {
                    eprintln!("LocalScale accepted connection setup failed: {error}");
                    continue;
                }
                stream
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }
            Err(error) => {
                eprintln!("LocalScale connection failed: {error}");
                continue;
            }
        };
        let accepted_at = std::time::Instant::now();
        let mut count = lock_recover(&active);
        if *count >= MAX_CONNECTIONS {
            drop(count);
            let mut stream = stream;
            let _ = stream.write_all(
                http_response(
                    "503 Service Unavailable",
                    "text/plain; charset=utf-8",
                    "connection limit reached",
                )
                .as_bytes(),
            );
            continue;
        }
        *count += 1;
        drop(count);
        let state = state.clone();
        let active = active.clone();
        std::thread::spawn(move || {
            let _guard = ConnectionGuard { active };
            if let Err(error) = handle_connection(stream, &state, accepted_at) {
                eprintln!("LocalScale request failed: {error}");
            }
        });
    }
}

struct ConnectionGuard {
    active: Arc<Mutex<usize>>,
}
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let mut active = lock_recover(&self.active);
        *active = active.saturating_sub(1);
    }
}

fn handle_connection(
    mut stream: TcpStream,
    state: &AgentState,
    accepted_at: std::time::Instant,
) -> std::io::Result<()> {
    let mut request = Vec::with_capacity(4096);
    let mut buffer = [0_u8; 1024];
    while request.len() < MAX_REQUEST_BYTES {
        let elapsed = accepted_at.elapsed();
        if elapsed >= REQUEST_TIMEOUT {
            return Ok(());
        }
        stream.set_read_timeout(Some(REQUEST_TIMEOUT - elapsed))?;
        let read = match stream.read(&mut buffer) {
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => return Ok(()),
            Err(error) => return Err(error),
        };
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
            let header = String::from_utf8_lossy(&request[..header_end]);
            let content_length = header
                .lines()
                .find_map(|line| {
                    line.strip_prefix("Content-Length:")
                        .and_then(|value| value.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            if content_length > MAX_REQUEST_BYTES
                || header_end + 4 + content_length > MAX_REQUEST_BYTES
            {
                return stream.write_all(
                    http_response(
                        "413 Payload Too Large",
                        "text/plain; charset=utf-8",
                        "request too large",
                    )
                    .as_bytes(),
                );
            }
            if request.len() >= header_end + 4 + content_length {
                break;
            }
        }
    }
    let request = String::from_utf8_lossy(&request);
    let restart_request = request.split("\r\n").next().is_some_and(|line| {
        let mut parts = line.split_whitespace();
        parts.next() == Some("POST") && parts.next() == Some("/api/v1/runtime/restart")
    });
    let response = response_for_request_with_state(&request, state);
    let Some(write_budget) =
        remaining_budget(accepted_at, REQUEST_TIMEOUT, std::time::Instant::now())
    else {
        return Ok(());
    };
    stream.set_write_timeout(Some(write_budget))?;
    let result = stream.write_all(response.as_bytes());
    // Do not begin the shutdown delay until the accepting restart response
    // has been handed to the socket. A client that did not receive 202 must
    // not be left guessing whether the agent will disappear.
    if result.is_ok() && restart_request {
        dispatch_runtime_restart(&state.runtime_restart);
    }
    result
}

pub fn response_for_request(request: &str) -> String {
    response_for_request_with_state(request, &AgentState::default())
}

fn response_for_request_with_state(request: &str, state: &AgentState) -> String {
    let mut sections = request.splitn(2, "\r\n\r\n");
    let head = sections.next().unwrap_or("");
    let body = sections.next().unwrap_or("");
    let mut fields = head.split("\r\n");
    let request_line = fields.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    let headers: Vec<(&str, &str)> = fields
        .filter_map(|line| {
            line.split_once(':')
                .map(|(name, value)| (name, value.trim()))
        })
        .collect();
    let host = headers
        .iter()
        .find_map(|(name, value)| name.eq_ignore_ascii_case("host").then_some(*value))
        .unwrap_or("");

    if !is_loopback_host(host) {
        return http_response(
            "403 Forbidden",
            "text/plain; charset=utf-8",
            "local requests only",
        );
    }
    if is_state_changing_method(method) && !has_same_origin_proof(&headers, host) {
        return http_response(
            "403 Forbidden",
            "text/plain; charset=utf-8",
            "csrf validation failed",
        );
    }
    // Once an accepted runtime reload is waiting to exit, retain the persisted
    // configuration unchanged. This prevents a second local request from
    // replacing or revoking the record in the small window before shutdown.
    if state.runtime_restart.scheduled.load(Ordering::Acquire)
        && is_state_changing_method(method)
        && path != "/api/v1/runtime/restart"
    {
        return http_response(
            "409 Conflict",
            "application/json",
            r#"{"error":"runtime_restart_scheduled"}"#,
        );
    }
    match (method, path) {
        ("GET", "/api/v1/status") => service_status(state),
        ("GET", "/api/v1/peer/status") => peer_status(state),
        ("POST", "/api/v1/invitations/generate") => generate_invitation(body, state),
        ("POST", "/api/v1/invitations/import") => import_invitation(body, state),
        ("POST", "/api/v1/peer/config") => set_peer_config(body, state),
        ("POST", "/api/v1/peer/approve") => set_peer_approval(true, state),
        ("POST", "/api/v1/peer/revoke") => set_peer_approval(false, state),
        ("POST", "/api/v1/peer/reset") => reset_peer(state),
        ("POST", "/api/v1/peer/remove") => remove_host_peer(body, state),
        ("POST", "/api/v1/peer/virtual-ip") => set_virtual_ip_handler(body, state),
        ("POST", "/api/v1/runtime/restart") => request_runtime_restart(state),
        ("GET", "/api/v1/devices") => devices_status(state),
        ("GET", "/api/v1/logs") => agent_logs(state),
        ("POST", "/api/v1/mode") => set_mode(body, state, true),
        ("POST", "/api/v1/service/start") => set_service_state("running", state),
        ("POST", "/api/v1/service/stop") => set_service_state("stopped", state),
        ("POST", "/api/v1/sync") => service_status(state),
        ("GET", "/") | ("GET", "/config") => {
            http_response("200 OK", "text/html; charset=utf-8", configuration_html())
        }
        ("GET", "/health") => http_response("200 OK", "application/json", health_response()),
        ("GET", "/version") => http_response(
            "200 OK",
            "application/json",
            &format!(r#"{{"version":"{VERSION}","service":"localscale"}}"#),
        ),
        ("GET", "/status") => service_status(state),
        ("GET", "/mode") => {
            let mode = lock_recover(&state.mode).clone();
            http_response(
                "200 OK",
                "application/json",
                &format!(r#"{{"mode":"{mode}"}}"#),
            )
        }
        ("POST", "/mode") => set_mode(body, state, false),
        ("GET", "/onion") => http_response(
            "200 OK",
            "application/json",
            r#"{"enabled":false,"address":null}"#,
        ),
        ("GET", "/diagnostics") | ("GET", "/api/v1/diagnostics") => diagnostics_status(state),
        _ => http_response("404 Not Found", "text/plain; charset=utf-8", "not found"),
    }
}

/// Stable, persisted identity for *this* machine, independent of the
/// current Host/Cliente mode. Previously `devices_status()` fell back to a
/// hardcoded, mode-dependent name ("host-mac" / "cliente-linux") whenever no
/// peer record had a `node_id` set yet, which made the local device appear to
/// rename itself every time the user switched mode. This generates a name
/// once (hostname + short random suffix), persists it to disk, and reuses it
/// forever after, regardless of mode.
static LOCAL_DEVICE_ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Backend event log, persisted to a plain file so real dial/handshake/Tor
/// errors survive regardless of how `localscaled` was launched (systemd
/// captures stdout/stderr via journald, but the desktop app spawns it
/// detached, which discards them entirely — this file is the one place
/// those errors are guaranteed to land). Read back by `GET /api/v1/logs` so
/// the desktop UI's event log panel can show them, not just local UI-side
/// state changes.
static AGENT_LOG_LOCK: Mutex<()> = Mutex::new(());

fn agent_log_path() -> std::path::PathBuf {
    if let Some(path) = std::env::var_os("LOCALSCALE_LOG_FILE") {
        return std::path::PathBuf::from(path);
    }
    local_identity_path()
        .parent()
        .map(|dir| dir.join("agent.log"))
        .unwrap_or_else(|| std::env::temp_dir().join("localscale-agent.log"))
}

/// Appends one timestamped line to the backend log file. Best-effort: a
/// logging failure must never take down the agent, so errors are swallowed.
pub fn log_event(message: &str) {
    let path = agent_log_path();
    let _guard = lock_recover(&AGENT_LOG_LOCK);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let now = unix_time_secs().unwrap_or(0);
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(file, "{now} {message}");
    }
}

const MAX_LOG_RESPONSE_BYTES: usize = 64 * 1024;

fn agent_logs(_state: &AgentState) -> String {
    let path = agent_log_path();
    let contents = std::fs::read_to_string(&path).unwrap_or_default();
    let tail = if contents.len() > MAX_LOG_RESPONSE_BYTES {
        let start = contents.len() - MAX_LOG_RESPONSE_BYTES;
        contents[start..].splitn(2, '\n').nth(1).unwrap_or("")
    } else {
        contents.as_str()
    };
    http_response(
        "200 OK",
        "application/json",
        &format!("{{\"lines\":{}}}", json_string(tail)),
    )
}

fn local_identity_path() -> std::path::PathBuf {
    if let Some(path) = std::env::var_os("LOCALSCALE_DEVICE_IDENTITY_FILE") {
        return std::path::PathBuf::from(path);
    }
    let base = std::env::var_os("LOCALSCALE_TOR_DATA_DIR")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("XDG_STATE_HOME")
                .map(std::path::PathBuf::from)
                .map(|p| p.join("localscale"))
        })
        .or_else(|| {
            std::env::var_os("HOME")
                .map(|home| std::path::PathBuf::from(home).join(".local/state/localscale"))
        })
        .unwrap_or_else(|| std::env::temp_dir().join("localscale"));
    base.join("device-identity.json")
}

fn generate_local_device_name() -> String {
    let hostname = std::env::var("LOCALSCALE_DEVICE_HOSTNAME")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| {
            Command::new("hostname")
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "localscale-device".to_string());
    let suffix = unix_time_secs().unwrap_or(0) % 100_000;
    format!("{hostname}-{suffix:05}")
}

fn load_or_create_local_device_id() -> String {
    let path = local_identity_path();
    if let Ok(contents) = std::fs::read_to_string(&path) {
        if let Some(fields) = parse_json_fields(&contents) {
            if let Some(id) = fields.get("node_id") {
                if !id.is_empty() {
                    return id.clone();
                }
            }
        }
    }
    let node_id = generate_local_device_name();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let payload = format!(r#"{{"node_id":{}}}"#, json_string(&node_id));
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, payload).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        let _ = std::fs::rename(&tmp, &path);
    }
    node_id
}

pub fn local_device_id() -> &'static str {
    LOCAL_DEVICE_ID.get_or_init(load_or_create_local_device_id)
}

fn detect_local_onion_endpoint() -> Option<String> {
    if let Ok(endpoint) = std::env::var("LOCALSCALE_ONION_ENDPOINT") {
        let ep = endpoint.trim();
        if !ep.is_empty() {
            return Some(ep.to_string());
        }
    }
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let mut candidates = Vec::new();
    if let Some(data_dir) =
        std::env::var_os("LOCALSCALE_TOR_DATA_DIR").map(std::path::PathBuf::from)
    {
        candidates.push(data_dir.join("hidden_service").join("hostname"));
        candidates.push(data_dir.join("onion").join("hostname"));
    }
    if let Some(ref h) = home {
        // NOTE: this used to also probe `~/.local/state/hermes-bridge-test/*`
        // paths — leftover from early bootstrapping against an unrelated Tor
        // project on the same dev machine. Since those candidates were
        // checked *before* LocalScale's own state path, whenever both
        // happened to exist (e.g. the Linux dev box), this function silently
        // advertised hermes-bridge's onion address as LocalScale's own. Every
        // invitation generated from that host then pointed at a hidden
        // service LocalScale never controlled, which explains descriptor
        // lookups failing forever ("No more HSDir available to query") no
        // matter how long the real peer connection was left running.
        candidates.push(h.join(".local/state/localscale/tor/hidden_service/hostname"));
        candidates.push(h.join(".local/state/localscale/tor/onion/hostname"));
        candidates.push(h.join(".local/share/localscale/tor/hidden_service/hostname"));
    }
    candidates.push(std::path::PathBuf::from(
        "/var/lib/tor/hidden_service/hostname",
    ));

    for candidate in candidates {
        if let Ok(content) = std::fs::read_to_string(&candidate) {
            let line = content.lines().next().unwrap_or("").trim();
            if line.ends_with(".onion") && line.len() >= 20 {
                return Some(line.to_string());
            }
        }
    }
    None
}

fn service_status(state: &AgentState) -> String {
    let mode = lock_recover(&state.mode).clone();
    let service_state = lock_recover(&state.service_state).clone();
    let peer = lock_recover(&state.peer);
    // A Cliente never runs a hidden service — `render_torrc` only ever
    // writes a `HiddenServiceDir` section for the Host role — so it has no
    // onion of its own, full stop. This used to fall back to `peer.endpoint`
    // (actually the *Host's* onion — see `ImportInvitationRequest`), and
    // even after fixing that to call `detect_local_onion_endpoint()` in both
    // modes, a Cliente machine that had *previously* run as Host still had a
    // stale `hidden_service/hostname` file on disk from that (Tor no longer
    // publishes it without a `HiddenServiceDir` line, but the file survives),
    // so the scan kept finding and reporting a dead address. Only look at
    // all in Host mode, where an onion is actually possible.
    let endpoint = if mode == "host" {
        detect_local_onion_endpoint()
            .as_deref()
            .or(peer.endpoint.as_deref())
            .map(String::from)
    } else {
        None
    };
    let onion_endpoint = optional_json(&endpoint);
    http_response(
        "200 OK",
        "application/json",
        &format!(
            r#"{{"mode":{},"state":{},"onion_endpoint":{},"peer_configured":{},"peer_transport":{}}}"#,
            json_string(&mode),
            json_string(&service_state),
            onion_endpoint,
            peer.configured,
            json_string(state.peer_transport_status.label())
        ),
    )
}

fn peer_status(state: &AgentState) -> String {
    let peer = lock_recover(&state.peer);
    let detected = detect_local_onion_endpoint();
    let endpoint = peer.endpoint.clone().or(detected);
    let json = format!(
        r#"{{"configured":{},"node_id":{},"host_node_id":{},"onion_endpoint":{},"virtual_ip":{},"transport":{},"connected":{},"last_peer_activity_unix":{},"messages_exchanged":{},"approved":{},"revoked":{}}}"#,
        peer.configured,
        optional_json(&peer.node_id),
        optional_json(&peer.host_node_id),
        optional_json(&endpoint),
        optional_json(&peer.virtual_ip),
        json_string(state.peer_transport_status.label()),
        state.peer_transport_status.is_connected(),
        state.peer_transport_status.last_peer_activity_unix(),
        state.peer_transport_status.messages_exchanged(),
        peer.approved,
        peer.revoked
    );
    http_response("200 OK", "application/json", &json)
}

fn set_virtual_ip_handler(body: &str, state: &AgentState) -> String {
    let fields = match parse_json_fields(body) {
        Some(fields) => fields,
        None => {
            return http_response(
                "400 Bad Request",
                "application/json",
                r#"{"error":"invalid_payload"}"#,
            )
        }
    };
    let virtual_ip = fields
        .get("virtual_ip")
        .cloned()
        .filter(|v| !v.trim().is_empty());
    // The heartbeat now piggybacks this value to the peer as a
    // pipe-delimited field (see `heartbeat_frame` in the transport crate);
    // a '|' or line break here would corrupt that frame and break the
    // peer's own liveness parsing, not just this side's.
    if let Some(value) = &virtual_ip {
        if value.bytes().any(|b| b == b'|' || b == b'\n' || b == b'\r') {
            return http_response(
                "400 Bad Request",
                "application/json",
                r#"{"error":"invalid_virtual_ip"}"#,
            );
        }
    }
    let Some(store) = &state.peer_store else {
        return http_response(
            "503 Service Unavailable",
            "application/json",
            r#"{"error":"peer_store_unavailable"}"#,
        );
    };
    if lock_recover(store)
        .set_virtual_ip(virtual_ip.clone())
        .is_err()
    {
        return http_response(
            "404 Not Found",
            "application/json",
            r#"{"error":"peer_not_configured"}"#,
        );
    }
    let mut peer = lock_recover(&state.peer);
    peer.virtual_ip = virtual_ip.clone();
    drop(peer);
    // Applying a new virtual IP is deliberately NOT restart-required: unlike
    // approval/invitation changes, it doesn't change who we're talking to or
    // invalidate any key, so there is no reason to tear down a live Tor
    // connection just to pick it up. The running transport thread reads this
    // fresh on its next heartbeat (see `PeerTransportStatus::local_virtual_ip`).
    state
        .peer_transport_status
        .set_local_virtual_ip(virtual_ip.unwrap_or_default());
    peer_status(state)
}

fn devices_status(state: &AgentState) -> String {
    let mode = lock_recover(&state.mode).clone();
    let peer = lock_recover(&state.peer);
    // Use the stable, persisted local device identity rather than a
    // mode-dependent hardcoded fallback ("host-mac"/"cliente-linux"), which
    // used to make the local device appear to rename itself on every
    // Host/Cliente mode switch (see `local_device_id`).
    let local_node_id = peer.node_id.as_deref().unwrap_or_else(|| local_device_id());
    let local_ip = peer.virtual_ip.as_deref().unwrap_or("");
    let detected_endpoint = detect_local_onion_endpoint();

    let local_onion = if mode == "host" {
        detected_endpoint.as_deref().unwrap_or("")
    } else {
        ""
    };

    let remote_onion = if mode == "cliente" {
        peer.endpoint.as_deref().unwrap_or("")
    } else {
        ""
    };

    let local_json = format!(
        r#"{{"node_id":{},"role":{},"onion_endpoint":{},"virtual_ip":{},"status":"active"}}"#,
        json_string(local_node_id), json_string(&mode), json_string(local_onion), json_string(local_ip)
    );

    // Host: every invited/paired Cliente from the registry, each merged
    // with its own live connection state — a device that connected before
    // but isn't right now reports "offline" instead of disappearing from
    // the list (the bug this replaced), and one nobody has connected with
    // yet reports "pending".
    //
    // Cliente: unchanged single-peer behavior (a Cliente only ever has one
    // Host to report).
    let remote_peers = if mode == "host" {
        let entries: Vec<HostPeerEntry> = state
            .host_registry
            .as_ref()
            .map(|registry| lock_recover(registry).entries().to_vec())
            .unwrap_or_default();
        let live = state.host_peer_live.clone();
        let peer_jsons: Vec<String> = entries
            .iter()
            .filter(|entry| !entry.revoked)
            .map(|entry| {
                let live_status = entry
                    .node_id
                    .as_deref()
                    .and_then(|node_id| lock_recover(&live).get(node_id).cloned());
                let connected = live_status
                    .as_ref()
                    .map(PeerTransportStatus::is_connected)
                    .unwrap_or(false);
                let remote_id = entry.node_id.clone().unwrap_or_else(|| {
                    format!(
                        "convite-pendente-{}",
                        &entry.invitation_id[..8.min(entry.invitation_id.len())]
                    )
                });
                let status = if connected {
                    "connected"
                } else if entry.node_id.is_none() {
                    "pending"
                } else {
                    "offline"
                };
                format!(
                    r#"{{"node_id":{},"role":"cliente","onion_endpoint":"","virtual_ip":{},"status":{},"approved":true,"revoked":false}}"#,
                    json_string(&remote_id),
                    json_string(&entry.virtual_ip),
                    json_string(status),
                )
            })
            .collect();
        format!("[{}]", peer_jsons.join(","))
    } else if peer.configured {
        // Prefer the node id actually learned from a completed, authenticated
        // handshake. Falling back to `peer.host_node_id` (always populated
        // for the Cliente role) keeps this working before the first
        // handshake ever completes.
        let handshake_remote_id = state.peer_transport_status.remote_node_id();
        let remote_id = handshake_remote_id
            .as_deref()
            .or(peer.host_node_id.as_deref())
            .unwrap_or("remote-host");
        // The peer's real virtual IP, learned from its own heartbeat (see
        // `PeerTransportStatus::remote_virtual_ip`) — this used to guess by
        // swapping the last octet between .1 and .2 (or hardcoding
        // 10.42.0.1/.2), which silently fabricated an address that had
        // nothing to do with whatever the user actually typed on the other
        // machine. Empty until the peer has sent at least one heartbeat
        // carrying a configured address.
        let remote_ip = state.peer_transport_status.remote_virtual_ip().unwrap_or_default();
        // Report the actual transport state rather than the local approval
        // flag alone. Previously this showed "approved" forever once a peer
        // was approved, even when the two agents never actually established
        // real communication (no transport handshake, dead onion service,
        // wrong node id, etc). That made "approved" look like "connected" to
        // the user when it was not, and gave no visibility into what stage
        // the transport was actually stuck in (connecting/retrying/needs a
        // restart/etc).
        let status = if peer.revoked {
            "revoked"
        } else if !peer.approved {
            "pending"
        } else if state.peer_transport_status.is_connected() {
            "connected"
        } else {
            state.peer_transport_status.label()
        };
        format!(
            r#"[{{"node_id":{},"role":"host","onion_endpoint":{},"virtual_ip":{},"status":{},"approved":{},"revoked":{}}}]"#,
            json_string(remote_id),
            json_string(remote_onion),
            json_string(&remote_ip),
            json_string(status),
            peer.approved,
            peer.revoked
        )
    } else {
        "[]".to_string()
    };

    http_response(
        "200 OK",
        "application/json",
        &format!(
            r#"{{"transport":"Tor v3 Onion (Strict Isolation)","isolation":"tor_only_no_lan","local_device":{},"remote_peers":{}}}"#,
            local_json, remote_peers
        ),
    )
}
fn diagnostics_status(state: &AgentState) -> String {
    let peer = lock_recover(&state.peer);
    let json = format!(
        r#"{{"service":{},"loopback":true,"external_network":false,"peer_configured":{},"peer_transport":{},"peer_connected":{},"last_peer_activity_unix":{},"messages_exchanged":{}}}"#,
        json_string("localscale"),
        peer.configured,
        json_string(state.peer_transport_status.label()),
        state.peer_transport_status.is_connected(),
        state.peer_transport_status.last_peer_activity_unix(),
        state.peer_transport_status.messages_exchanged()
    );
    http_response("200 OK", "application/json", &json)
}

fn json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0c}' => escaped.push_str("\\f"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            // Keep JSON telemetry inert even if a future consumer renders a
            // response body in an HTML context by mistake.
            '<' => escaped.push_str("\\u003c"),
            '>' => escaped.push_str("\\u003e"),
            '&' => escaped.push_str("\\u0026"),
            character if (character as u32) < 0x20 => {
                escaped.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => escaped.push(character),
        }
    }
    format!("\"{escaped}\"")
}

fn optional_json(value: &Option<String>) -> String {
    value
        .as_deref()
        .map(json_string)
        .unwrap_or_else(|| "null".into())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InvitationEnvelopeV1 {
    version: u8,
    invitation_id: String,
    host_node_id: String,
    onion_endpoint: String,
    invitation_secret: String,
    issued_at: u64,
    expires_at: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerateInvitationRequest {
    node_id: String,
    #[serde(default = "default_invitation_ttl")]
    ttl_seconds: u64,
    #[serde(default)]
    virtual_ip: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportInvitationRequest {
    node_id: String,
    invitation: String,
    #[serde(default)]
    virtual_ip: Option<String>,
}

fn default_invitation_ttl() -> u64 {
    DEFAULT_INVITATION_TTL_SECS
}

fn unix_time_secs() -> Result<u64, ()> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ())
}

fn random_base64(bytes: usize) -> Result<String, ()> {
    let mut random = vec![0_u8; bytes];
    getrandom::getrandom(&mut random).map_err(|_| ())?;
    Ok(URL_SAFE_NO_PAD.encode(random))
}

fn valid_invitation_id(value: &str) -> bool {
    value.len() == 22
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn mark_peer_changed(record: PeerRecord, state: &AgentState) -> Result<(), ()> {
    let Some(store) = &state.peer_store else {
        return Err(());
    };
    lock_recover(store)
        .configure(record.clone())
        .map_err(|_| ())?;
    let mut peer = lock_recover(&state.peer);
    peer.configured = true;
    peer.node_id = Some(record.node_id);
    peer.host_node_id = record.host_node_id;
    peer.endpoint = Some(record.endpoint);
    peer.virtual_ip = record.virtual_ip;
    peer.transport = "unavailable";
    peer.approved = false;
    peer.revoked = false;
    drop(peer);
    state.peer_transport_enabled.store(false, Ordering::Release);
    state
        .peer_transport_restart_required
        .store(true, Ordering::Release);
    state
        .peer_transport_status
        .set(TransportState::RestartRequired);
    // A reconfigured peer (new invitation/approval) invalidates any node id
    // learned from a previous handshake; otherwise a stale remote name could
    // survive across a device swap until the next successful handshake.
    state.peer_transport_status.clear_remote_node_id();
    state.peer_transport_status.clear_remote_virtual_ip();
    Ok(())
}

fn reset_peer(state: &AgentState) -> String {
    let Some(store) = &state.peer_store else {
        return http_response(
            "503 Service Unavailable",
            "application/json",
            r#"{"error":"peer_store_unavailable"}"#,
        );
    };
    if lock_recover(store).clear().is_err() {
        return http_response(
            "500 Internal Server Error",
            "application/json",
            r#"{"error":"peer_store_clear_failed"}"#,
        );
    }
    let mut peer = lock_recover(&state.peer);
    peer.configured = false;
    peer.node_id = None;
    peer.host_node_id = None;
    peer.endpoint = None;
    peer.virtual_ip = None;
    peer.approved = false;
    peer.revoked = false;
    drop(peer);
    state.peer_transport_enabled.store(false, Ordering::Release);
    state.peer_transport_status.set(TransportState::Disabled);
    // Fixes the "removed device still shows in the list" bug: without this,
    // the handshake-learned remote node id (see `PeerTransportStatus`)
    // survived a reset and `devices_status()` kept reporting the old device.
    state.peer_transport_status.clear_remote_node_id();
    state.peer_transport_status.clear_remote_virtual_ip();
    peer_status(state)
}

/// Network prefix ("a.b.c" of "a.b.c.d") every virtual IP on this Host's
/// side of the mesh is drawn from — the Host itself always gets `.1`;
/// `HostPeerRegistry::next_free_virtual_ip` hands out `.2..254` to each
/// Cliente in the order it's invited. Derived from whatever the Host's own
/// address already is if one was configured (so an existing deployment
/// isn't silently renumbered), defaulting to `10.0.0` otherwise.
fn host_network_prefix(state: &AgentState) -> String {
    let existing = state
        .host_local_virtual_ip
        .as_ref()
        .and_then(|store| lock_recover(store).get().map(str::to_string));
    if let Some(existing) = existing {
        if let Some((prefix, _)) = existing.rsplit_once('.') {
            return prefix.to_string();
        }
    }
    "10.0.0".to_string()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoveHostPeerRequest {
    node_id: String,
}

/// Removes one specific device from a Host's registry — the multi-peer
/// counterpart to `reset_peer` (which clears the Cliente role's single
/// Host pairing entirely). Frees that device's virtual IP for reuse by
/// the next invitation and, if it's currently connected, its live status
/// entry so it stops being reported at all rather than lingering as
/// "offline" for a device the user explicitly removed.
fn remove_host_peer(body: &str, state: &AgentState) -> String {
    let request: RemoveHostPeerRequest = match serde_json::from_str(body) {
        Ok(request) => request,
        Err(_) => {
            return http_response(
                "400 Bad Request",
                "application/json",
                r#"{"error":"invalid_request"}"#,
            )
        }
    };
    let Some(registry) = &state.host_registry else {
        return http_response(
            "503 Service Unavailable",
            "application/json",
            r#"{"error":"peer_store_unavailable"}"#,
        );
    };
    if lock_recover(registry).remove(&request.node_id).is_err() {
        return http_response(
            "500 Internal Server Error",
            "application/json",
            r#"{"error":"peer_store_remove_failed"}"#,
        );
    }
    lock_recover(&state.host_peer_live).remove(&request.node_id);
    http_response("200 OK", "application/json", r#"{"removed":true}"#)
}

fn generate_invitation(body: &str, state: &AgentState) -> String {
    let request: GenerateInvitationRequest = match serde_json::from_str(body) {
        Ok(request) => request,
        Err(_) => return invitation_error("400 Bad Request", "invalid_invitation_request"),
    };
    if !(MIN_INVITATION_TTL_SECS..=MAX_INVITATION_TTL_SECS).contains(&request.ttl_seconds) {
        return invitation_error("400 Bad Request", "invalid_invitation_ttl");
    }
    let Some(onion_endpoint) = detect_local_onion_endpoint() else {
        return invitation_error("409 Conflict", "onion_endpoint_not_ready");
    };
    let Some(registry) = &state.host_registry else {
        return invitation_error("503 Service Unavailable", "peer_store_unavailable");
    };
    let now = match unix_time_secs() {
        Ok(now) => now,
        Err(_) => return invitation_error("500 Internal Server Error", "clock_unavailable"),
    };
    let invitation_id = match random_base64(16) {
        Ok(value) => value,
        Err(_) => return invitation_error("500 Internal Server Error", "randomness_unavailable"),
    };
    let invitation_secret_raw = match random_base64(32) {
        Ok(value) => value,
        Err(_) => return invitation_error("500 Internal Server Error", "randomness_unavailable"),
    };
    if HostInvitation::new(&request.node_id, &onion_endpoint, &invitation_secret_raw).is_err() {
        return invitation_error("400 Bad Request", "invalid_invitation_request");
    }
    let expires_at = match now.checked_add(request.ttl_seconds) {
        Some(value) => value,
        None => return invitation_error("400 Bad Request", "invalid_invitation_ttl"),
    };

    // The Host's own address is assigned once, the first time it ever
    // generates an invitation (`.1` in its network prefix) — every
    // subsequently invited Cliente draws a *different* free address from
    // the same registry (see `HostPeerRegistry::next_free_virtual_ip`), so
    // two devices can never end up sharing one.
    let network_prefix = host_network_prefix(state);
    if let Some(local_ip_store) = &state.host_local_virtual_ip {
        let mut local_ip_store = lock_recover(local_ip_store);
        if local_ip_store.get().is_none() {
            let own_ip = request
                .virtual_ip
                .clone()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| format!("{network_prefix}.1"));
            if local_ip_store.set(&own_ip).is_ok() {
                state.peer_transport_status.set_local_virtual_ip(own_ip.clone());
                let mut peer = lock_recover(&state.peer);
                peer.virtual_ip = Some(own_ip);
            }
        }
    }
    // The device's own display name (what the wizard's "name this
    // computer" step collected) — purely local bookkeeping now, since a
    // Host's remote-peer identities live in the registry instead of the
    // legacy singular `peer` record.
    {
        let mut peer = lock_recover(&state.peer);
        peer.configured = true;
        peer.node_id = Some(request.node_id.clone());
    }

    let assigned_ip = lock_recover(registry).next_free_virtual_ip(&network_prefix);
    let invitation_secret = stored_transport_key_from_invitation_secret(&invitation_secret_raw);
    if lock_recover(registry)
        .add_pending(invitation_id.clone(), invitation_secret, assigned_ip, now)
        .is_err()
    {
        return invitation_error("503 Service Unavailable", "peer_store_unavailable");
    }

    let envelope = InvitationEnvelopeV1 {
        version: 1,
        invitation_id,
        // The Cliente authenticates the Host's handshake response against
        // this exact node id (see `ClienteTransport::connect`'s
        // `response_env.open(&self.key, Role::Host, &self.host_node_id)`),
        // and `HostTransport` (main.rs) always seals that response using
        // `local_device_id()` as its own transport identity — never the
        // cosmetic display name the user typed in the wizard. Embedding
        // that display name here instead used to make every handshake
        // response fail AEAD verification (surfacing as
        // `Crypto(AuthenticationFailed)`, retried forever) unless it
        // happened to be identical to the stable device id by coincidence.
        host_node_id: local_device_id().to_string(),
        onion_endpoint,
        invitation_secret: invitation_secret_raw,
        issued_at: now,
        expires_at,
    };
    let encoded = match serde_json::to_vec(&envelope) {
        Ok(json) => format!("{INVITATION_PREFIX}{}", URL_SAFE_NO_PAD.encode(json)),
        Err(_) => return invitation_error("500 Internal Server Error", "encoding_failed"),
    };
    // Unlike the original single-peer design, adding a new invitation never
    // needs a restart: the Host's accept loop already reads the registry
    // live (via the shared `Arc<Mutex<..>>`) on every handshake, so a
    // pending invitation generated while already running is immediately
    // usable. A restart is only ever needed for a genuine role/config
    // change (see `mark_peer_changed`, still used by the Cliente role).
    http_response(
        "200 OK",
        "application/json",
        &format!(
            "{{\"version\":1,\"invitation\":{},\"expires_at\":{expires_at}}}",
            json_string(&encoded)
        ),
    )
}

fn decode_invitation(value: &str, now: u64) -> Result<InvitationEnvelopeV1, &'static str> {
    let encoded = value
        .strip_prefix(INVITATION_PREFIX)
        .ok_or("invalid_invitation")?;
    if encoded.len() > 4096 {
        return Err("invalid_invitation");
    }
    let json = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| "invalid_invitation")?;
    let envelope: InvitationEnvelopeV1 =
        serde_json::from_slice(&json).map_err(|_| "invalid_invitation")?;
    if envelope.version != 1
        || !valid_invitation_id(&envelope.invitation_id)
        || envelope.issued_at > now.saturating_add(MAX_INVITATION_CLOCK_SKEW_SECS)
        || envelope.expires_at <= now
        || envelope.expires_at <= envelope.issued_at
        || envelope.expires_at - envelope.issued_at > MAX_INVITATION_TTL_SECS
        || HostInvitation::new(
            &envelope.host_node_id,
            &envelope.onion_endpoint,
            &envelope.invitation_secret,
        )
        .is_err()
    {
        return Err(if envelope.expires_at <= now {
            "invitation_expired"
        } else {
            "invalid_invitation"
        });
    }
    Ok(envelope)
}

fn import_invitation(body: &str, state: &AgentState) -> String {
    let request: ImportInvitationRequest = match serde_json::from_str(body) {
        Ok(request) => request,
        Err(_) => return invitation_error("400 Bad Request", "invalid_invitation_request"),
    };
    let now = match unix_time_secs() {
        Ok(now) => now,
        Err(_) => return invitation_error("500 Internal Server Error", "clock_unavailable"),
    };
    let envelope = match decode_invitation(&request.invitation, now) {
        Ok(envelope) => envelope,
        Err("invitation_expired") => return invitation_error("410 Gone", "invitation_expired"),
        Err(error) => return invitation_error("400 Bad Request", error),
    };
    if ClientConfig::client(
        &request.node_id,
        &envelope.host_node_id,
        &envelope.onion_endpoint,
        &envelope.invitation_secret,
    )
    .is_err()
    {
        return invitation_error("400 Bad Request", "invalid_invitation_request");
    }
    let Some(store) = &state.peer_store else {
        return invitation_error("503 Service Unavailable", "peer_store_unavailable");
    };
    match lock_recover(store).consume_invitation_id(&envelope.invitation_id) {
        Ok(true) => {}
        Ok(false) => return invitation_error("409 Conflict", "invitation_already_consumed"),
        Err(_) => return invitation_error("503 Service Unavailable", "replay_store_unavailable"),
    }
    let record = PeerRecord {
        role: "cliente".into(),
        node_id: request.node_id,
        host_node_id: Some(envelope.host_node_id),
        endpoint: envelope.onion_endpoint,
        invitation_secret: envelope.invitation_secret,
        virtual_ip: request.virtual_ip.filter(|value| !value.trim().is_empty()),
        approved: false,
        revoked: false,
    };
    if mark_peer_changed(record, state).is_err() {
        return invitation_error("500 Internal Server Error", "peer_store_write_failed");
    }
    peer_status(state)
}

fn invitation_error(status: &str, error: &str) -> String {
    // Unlike the transport thread's errors (dial/handshake failures, wired
    // to the same log via `log_event` in main.rs), invitation generate/
    // import failures happen entirely inside this HTTP handler and never
    // reached the backend log — so a 410/409/400 the user hit while pairing
    // left no trace anywhere but a snackbar that had already disappeared by
    // the time anyone asked what went wrong.
    log_event(&format!("invitation {status}: {error}"));
    http_response(
        status,
        "application/json",
        &format!("{{\"error\":{}}}", json_string(error)),
    )
}

fn set_peer_config(body: &str, state: &AgentState) -> String {
    let fields = match parse_json_fields(body) {
        Some(fields) => fields,
        None => {
            return http_response(
                "400 Bad Request",
                "application/json",
                r#"{"error":"invalid_peer_config"}"#,
            )
        }
    };
    let role = fields.get("role").map(String::as_str).unwrap_or("");
    let result: Result<(String, Option<String>, String), ()> = match role {
        "host" => HostInvitation::new(
            fields.get("node_id").map(String::as_str).unwrap_or(""),
            fields
                .get("onion_endpoint")
                .map(String::as_str)
                .unwrap_or(""),
            fields
                .get("invitation_secret")
                .map(String::as_str)
                .unwrap_or(""),
        )
        .map(|invitation| {
            (
                invitation.host_node_id().to_string(),
                None,
                invitation.public_endpoint().to_string(),
            )
        })
        .map_err(|_| ()),
        "cliente" => {
            let invitation = HostInvitation::new(
                fields.get("host_node_id").map(String::as_str).unwrap_or(""),
                fields
                    .get("onion_endpoint")
                    .map(String::as_str)
                    .unwrap_or(""),
                fields
                    .get("invitation_secret")
                    .map(String::as_str)
                    .unwrap_or(""),
            )
            .map_err(|_| ());
            match invitation {
                Ok(invitation) => ClientConfig::from_invitation(
                    &invitation,
                    fields.get("node_id").map(String::as_str).unwrap_or(""),
                )
                .map(|config| {
                    (
                        fields.get("node_id").cloned().unwrap_or_default(),
                        Some(config.host_node_id().to_string()),
                        config.public_endpoint().to_string(),
                    )
                })
                .map_err(|_| ()),
                Err(error) => Err(error),
            }
        }
        _ => Err(()),
    };
    let Ok((node_id, host_node_id, endpoint)) = result else {
        return http_response(
            "400 Bad Request",
            "application/json",
            r#"{"error":"invalid_peer_config"}"#,
        );
    };
    let Some(store) = &state.peer_store else {
        return http_response(
            "503 Service Unavailable",
            "application/json",
            r#"{"error":"peer_store_unavailable"}"#,
        );
    };
    let virtual_ip = fields
        .get("virtual_ip")
        .cloned()
        .filter(|v| !v.trim().is_empty());
    let record = PeerRecord {
        role: role.to_string(),
        node_id: node_id.clone(),
        host_node_id: host_node_id.clone(),
        endpoint: endpoint.clone(),
        invitation_secret: stored_transport_key_from_invitation_secret(
            fields
                .get("invitation_secret")
                .map(String::as_str)
                .unwrap_or_default(),
        ),
        virtual_ip: virtual_ip.clone(),
        approved: false,
        revoked: false,
    };
    // Re-applying the exact invitation from an opt-in desktop test profile
    // must not revoke the already approved peer or force a daemon restart on
    // every application launch. A changed invitation remains deliberately
    // unapproved and requires a new runtime bootstrap.
    if lock_recover(store)
        .record()
        .is_some_and(|existing| same_peer_configuration(existing, &record))
    {
        return peer_status(state);
    }
    if lock_recover(store).configure(record).is_err() {
        return http_response(
            "500 Internal Server Error",
            "application/json",
            r#"{"error":"peer_store_write_failed"}"#,
        );
    }
    let mut peer = lock_recover(&state.peer);
    peer.configured = true;
    peer.node_id = Some(node_id);
    peer.host_node_id = host_node_id;
    peer.endpoint = Some(endpoint);
    peer.virtual_ip = virtual_ip;
    peer.transport = "unavailable";
    peer.approved = false;
    peer.revoked = false;
    drop(peer);
    state.peer_transport_enabled.store(false, Ordering::Release);
    state
        .peer_transport_restart_required
        .store(true, Ordering::Release);
    state
        .peer_transport_status
        .set(TransportState::RestartRequired);
    peer_status(state)
}

fn same_peer_configuration(existing: &PeerRecord, candidate: &PeerRecord) -> bool {
    existing.role == candidate.role
        && existing.node_id == candidate.node_id
        && existing.host_node_id == candidate.host_node_id
        && existing.endpoint == candidate.endpoint
        && existing.invitation_secret == candidate.invitation_secret
        && existing.virtual_ip == candidate.virtual_ip
}

fn set_peer_approval(approved: bool, state: &AgentState) -> String {
    let Some(store) = &state.peer_store else {
        return http_response(
            "503 Service Unavailable",
            "application/json",
            r#"{"error":"peer_store_unavailable"}"#,
        );
    };
    if lock_recover(store).set_approval(approved).is_err() {
        return http_response(
            "404 Not Found",
            "application/json",
            r#"{"error":"peer_not_configured"}"#,
        );
    }
    let mut peer = lock_recover(&state.peer);
    peer.approved = approved;
    peer.revoked = !approved;
    drop(peer);
    let restart_required = state
        .peer_transport_restart_required
        .load(Ordering::Acquire);
    state
        .peer_transport_enabled
        .store(approved && !restart_required, Ordering::Release);
    state.peer_transport_status.set(if restart_required {
        TransportState::RestartRequired
    } else if approved {
        TransportState::Unavailable
    } else {
        TransportState::Disabled
    });
    peer_status(state)
}

fn request_runtime_restart(state: &AgentState) -> String {
    // Restart is intentionally narrow: it is only available to apply a peer
    // configuration that this process explicitly marked restart-required.
    // The request has already passed the loopback and same-origin checks in
    // `response_for_request_with_state`.
    if !state
        .peer_transport_restart_required
        .load(Ordering::Acquire)
    {
        return http_response(
            "409 Conflict",
            "application/json",
            r#"{"error":"restart_not_required"}"#,
        );
    }
    state
        .runtime_restart
        .scheduled
        .store(true, Ordering::Release);
    http_response(
        "202 Accepted",
        "application/json",
        r#"{"restart":"scheduled"}"#,
    )
}

fn dispatch_runtime_restart(restart: &RuntimeRestart) {
    if restart.dispatched.swap(true, Ordering::AcqRel) {
        return;
    }
    let restart = restart.clone();
    std::thread::spawn(move || {
        // The 202 response has already been written by the request handler.
        // This short delay lets the peer consume its socket buffer before the
        // binary exits and the desktop-side health observer takes over.
        std::thread::sleep(std::time::Duration::from_millis(150));
        restart.requested.store(true, Ordering::Release);
    });
}

fn parse_json_fields(body: &str) -> Option<std::collections::HashMap<String, String>> {
    let mut output = std::collections::HashMap::new();
    let body = body.trim().strip_prefix('{')?.strip_suffix('}')?.trim();
    if body.is_empty() {
        return Some(output);
    }
    for item in body.split(',') {
        let (key, value) = item.split_once(':')?;
        let key = key.trim().strip_prefix('"')?.strip_suffix('"')?;
        let value = value.trim();
        let value = if let Some(value) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
            value
        } else if matches!(value, "true" | "false") {
            value
        } else {
            return None;
        };
        if key.is_empty() || value.bytes().any(|byte| byte < 0x20 || byte == b'\\') {
            return None;
        }
        output.insert(key.to_string(), value.to_string());
    }
    Some(output)
}

fn set_service_state(service_state: &str, state: &AgentState) -> String {
    *lock_recover(&state.service_state) = service_state.to_string();
    service_status(state)
}

fn set_mode(body: &str, state: &AgentState, contract: bool) -> String {
    let mode = parse_mode(body, contract);
    let Some(mode) = mode else {
        return http_response(
            "400 Bad Request",
            "text/plain; charset=utf-8",
            "mode must be host or cliente",
        );
    };
    let persisted_mode = if mode == "client" { "cliente" } else { mode };
    let changed = if let Some(store) = &state.role_store {
        match lock_recover(store).set(persisted_mode) {
            Ok(changed) => changed,
            Err(_) => {
                return http_response(
                    "500 Internal Server Error",
                    "application/json",
                    r#"{"error":"role_store_write_failed"}"#,
                )
            }
        }
    } else {
        false
    };
    *lock_recover(&state.mode) = mode.to_string();
    if changed {
        if let Some(store) = &state.peer_store {
            let _ = lock_recover(store).clear();
        }
        *lock_recover(&state.peer) = PeerState::default();
        state.peer_transport_enabled.store(false, Ordering::Release);
        state
            .peer_transport_restart_required
            .store(true, Ordering::Release);
        state
            .peer_transport_status
            .set(TransportState::RestartRequired);
    }
    if contract {
        service_status(state)
    } else {
        http_response(
            "200 OK",
            "application/json",
            &format!(r#"{{"mode":"{mode}"}}"#),
        )
    }
}

fn parse_mode(body: &str, contract: bool) -> Option<&'static str> {
    let body = body.trim().strip_prefix('{')?.strip_suffix('}')?.trim();
    let body = body.strip_prefix('"')?;
    let key_end = body.find('"')?;
    if &body[..key_end] != "mode" {
        return None;
    }
    let rest = body[key_end + 1..]
        .trim_start()
        .strip_prefix(':')?
        .trim_start();
    let rest = rest.strip_prefix('"')?;
    let value_end = rest.find('"')?;
    let value = &rest[..value_end];
    // Valid modes contain no quotes, backslashes, or controls, so JSON interpolation stays escaped-safe.
    if value.bytes().any(|byte| byte == b'\\' || byte < 0x20) {
        return None;
    }
    if !rest[value_end + 1..].trim().is_empty() {
        return None;
    }
    match value {
        "host" => Some("host"),
        "cliente" => Some("cliente"),
        "client" if !contract => Some("client"),
        _ => None,
    }
}

fn is_state_changing_method(method: &str) -> bool {
    !matches!(method, "" | "GET" | "HEAD" | "OPTIONS")
}

fn has_same_origin_proof(headers: &[(&str, &str)], host: &str) -> bool {
    let origins: Vec<&str> = headers
        .iter()
        .filter_map(|(name, value)| name.eq_ignore_ascii_case("Origin").then_some(value.trim()))
        .collect();
    if !origins.is_empty() {
        return origins.len() == 1 && origin_matches_host(origins[0], host);
    }
    let referers: Vec<&str> = headers
        .iter()
        .filter_map(|(name, value)| name.eq_ignore_ascii_case("Referer").then_some(value.trim()))
        .collect();
    referers.len() == 1 && origin_matches_host(referers[0], host)
}

fn origin_matches_host(value: &str, host: &str) -> bool {
    let Some(scheme_end) = value.find("://") else {
        return false;
    };
    let authority_start = scheme_end + 3;
    let authority = value[authority_start..].split('/').next().unwrap_or("");
    if authority.is_empty() || !value[..scheme_end].eq_ignore_ascii_case("http") {
        return false;
    }
    authority.eq_ignore_ascii_case(host)
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim();
    let host = if let Some(stripped) = host.strip_prefix('[') {
        stripped.split(']').next().unwrap_or("")
    } else if host.matches(':').count() == 1 {
        host.split(':').next().unwrap_or("")
    } else {
        host
    };
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}

fn http_response(status: &str, content_type: &str, body: &str) -> String {
    format!("HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
}

#[cfg(test)]
mod tests {
    use super::{configuration_html, health_response};
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    #[test]
    fn version_endpoint_returns_local_scale_version() {
        let response =
            super::response_for_request("GET /version HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"version\":\"0.1.0\""));
    }

    #[test]
    fn mode_endpoint_rejects_non_loopback_host() {
        let response =
            super::response_for_request("GET /mode HTTP/1.1\r\nHost: example.test\r\n\r\n");
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
    }

    #[test]
    fn state_changing_routes_require_a_same_origin_proof() {
        let rejected = super::response_for_request(
            "POST /api/v1/service/start HTTP/1.1\r\nHost: 127.0.0.1:8765\r\n\r\n",
        );
        assert!(rejected.starts_with("HTTP/1.1 403 Forbidden"), "{rejected}");

        let cross_origin = super::response_for_request(
            "POST /api/v1/service/start HTTP/1.1\r\nHost: 127.0.0.1:8765\r\nOrigin: http://127.0.0.1:9999\r\n\r\n");
        assert!(
            cross_origin.starts_with("HTTP/1.1 403 Forbidden"),
            "{cross_origin}"
        );

        let accepted = super::response_for_request(
            "POST /api/v1/service/start HTTP/1.1\r\nHost: 127.0.0.1:8765\r\nOrigin: http://127.0.0.1:8765\r\n\r\n");
        assert!(accepted.starts_with("HTTP/1.1 200 OK"), "{accepted}");

        let referer = super::response_for_request(
            "POST /api/v1/service/stop HTTP/1.1\r\nHost: 127.0.0.1:8765\r\nReferer: http://127.0.0.1:8765/config\r\n\r\n");
        assert!(referer.starts_with("HTTP/1.1 200 OK"), "{referer}");
    }

    #[test]
    fn mode_endpoint_accepts_client_mode() {
        let response = super::response_for_request("POST /mode HTTP/1.1\r\nHost: 127.0.0.1:8765\r\nOrigin: http://127.0.0.1:8765\r\nContent-Length: 17\r\n\r\n{\"mode\":\"client\"}");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"mode\":\"client\""));
    }

    #[test]
    fn changing_mode_persists_role_and_requires_restart() {
        let state = super::AgentState::default();
        let response = super::response_for_request_with_state(
            "POST /api/v1/mode HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n{\"mode\":\"host\"}",
            &state,
        );
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains("\"mode\":\"host\""));
        assert!(response.contains("\"peer_transport\":\"restart_required\""));
        assert_eq!(
            super::lock_recover(state.role_store.as_ref().unwrap()).role(),
            Some("host")
        );
    }

    #[test]
    fn control_page_status_contract_defaults_to_cliente_running() {
        // The agent has no meaningful "stopped" mode of its own — it always
        // starts serving immediately, and every internal restart (approving
        // a peer, importing an invitation) must not read back as an outage.
        let response =
            super::response_for_request("GET /api/v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains(r#""mode":"cliente""#));
        assert!(response.contains(r#""state":"running""#));
        // `onion_endpoint` for an unconfigured Cliente now depends only on
        // `detect_local_onion_endpoint()` (real local Tor state), not on
        // `AgentState::default()` — deliberately, since it used to fall back
        // to the peer record's `endpoint` field, which for a Cliente is the
        // *Host's* onion, not this device's own (see `service_status`). That
        // makes it environment-dependent rather than a fixed default, so
        // this test only pins the two properties above that must always
        // hold on any machine.
    }

    #[test]
    fn control_page_routes_return_service_status_and_cliente_is_accepted() {
        let state = super::AgentState::default();
        let mode = super::response_for_request_with_state(
            "POST /api/v1/mode HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n{\"mode\":\"host\"}", &state);
        assert!(mode.starts_with("HTTP/1.1 200 OK"), "{mode}");
        assert!(mode.contains(r#""mode":"host""#));
        assert!(mode.contains(r#""state":"running""#));

        let start = super::response_for_request_with_state(
            "POST /api/v1/service/start HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n", &state);
        assert!(start.contains(r#""state":"running""#));
        let status = super::response_for_request_with_state(
            "GET /api/v1/status HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n", &state);
        assert!(status.contains(r#""mode":"host""#));
        assert!(status.contains(r#""state":"running""#));
    }

    #[test]
    fn peer_config_routes_store_safe_host_and_cliente_contract_without_secret_leakage() {
        let hostname = "abcdefghijklmnopqrstuvwxabcdefghijklmnopqrstuvwxyz234567.onion";
        let secret = "secret-token-123456";
        let state = super::AgentState::default();
        let host = super::response_for_request_with_state(&format!(
            "POST /api/v1/peer/config HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n{{\"role\":\"host\",\"node_id\":\"host-01\",\"onion_endpoint\":\"{hostname}\",\"invitation_secret\":\"{secret}\"}}"), &state);
        assert!(host.starts_with("HTTP/1.1 200 OK"), "{host}");
        assert!(host.contains("\"transport\":\"restart_required\""));
        assert!(!host.contains(secret));
        let status = super::response_for_request_with_state("GET /api/v1/peer/status HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n", &state);
        assert!(status.contains(hostname));
        assert!(!status.contains(secret));
        let cliente = super::response_for_request_with_state(&format!(
            "POST /api/v1/peer/config HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n{{\"role\":\"cliente\",\"node_id\":\"client-01\",\"host_node_id\":\"host-01\",\"onion_endpoint\":\"{hostname}\",\"invitation_secret\":\"{secret}\"}}"), &state);
        assert!(cliente.starts_with("HTTP/1.1 200 OK"), "{cliente}");
    }

    fn test_invitation(expires_at: u64) -> String {
        use base64::Engine as _;
        let envelope = super::InvitationEnvelopeV1 {
            version: 1,
            invitation_id: "AQIDBAUGBwgJCgsMDQ4PEA".into(),
            host_node_id: "linux-host".into(),
            onion_endpoint: "abcdefghijklmnopqrstuvwxabcdefghijklmnopqrstuvwxyz234567.onion".into(),
            invitation_secret: "test-invitation-secret-0123456789".into(),
            issued_at: expires_at.saturating_sub(600),
            expires_at,
        };
        format!(
            "{}{}",
            super::INVITATION_PREFIX,
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&envelope).unwrap())
        )
    }

    #[test]
    fn invitation_import_is_one_use_restart_required_and_secret_free() {
        let now = super::unix_time_secs().unwrap();
        let invitation = test_invitation(now + 600);
        let secret = "test-invitation-secret-0123456789";
        let state = super::AgentState::default();
        let request = format!(
            "POST /api/v1/invitations/import HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n{{\"node_id\":\"mac-client\",\"virtual_ip\":\"10.42.0.1\",\"invitation\":{}}}",
            super::json_string(&invitation)
        );
        let imported = super::response_for_request_with_state(&request, &state);
        assert!(imported.starts_with("HTTP/1.1 200 OK"), "{imported}");
        assert!(imported.contains("\"transport\":\"restart_required\""));
        assert!(imported.contains("\"host_node_id\":\"linux-host\""));
        assert!(!imported.contains(secret) && !imported.contains(&invitation));

        let replay = super::response_for_request_with_state(&request, &state);
        assert!(replay.starts_with("HTTP/1.1 409 Conflict"), "{replay}");
        assert!(replay.contains("invitation_already_consumed"));
        assert!(!replay.contains(secret) && !replay.contains(&invitation));
    }

    #[test]
    fn invitation_import_rejects_expired_tampered_and_cross_origin_values() {
        let now = super::unix_time_secs().unwrap();
        let expired = test_invitation(now);
        let state = super::AgentState::default();
        let request = |origin: &str, invitation: &str| {
            format!(
            "POST /api/v1/invitations/import HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: {origin}\r\n\r\n{{\"node_id\":\"mac-client\",\"invitation\":{}}}",
            super::json_string(invitation)
        )
        };
        let response = super::response_for_request_with_state(
            &request("http://localhost:8765", &expired),
            &state,
        );
        assert!(response.starts_with("HTTP/1.1 410 Gone"), "{response}");
        let response = super::response_for_request_with_state(
            &request("http://localhost:8765", "lsinv1.not-base64!"),
            &state,
        );
        assert!(
            response.starts_with("HTTP/1.1 400 Bad Request"),
            "{response}"
        );
        let response = super::response_for_request_with_state(
            &request("http://evil.example", &test_invitation(now + 600)),
            &state,
        );
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"), "{response}");
    }

    #[test]
    fn identical_peer_config_preserves_approval_and_restart_state() {
        let hostname = "abcdefghijklmnopqrstuvwxabcdefghijklmnopqrstuvwxyz234567.onion";
        let secret = "secret-token-123456";
        let state = super::AgentState::default();
        let request = format!(
            "POST /api/v1/peer/config HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n{{\"role\":\"host\",\"node_id\":\"host-01\",\"onion_endpoint\":\"{hostname}\",\"invitation_secret\":\"{secret}\"}}"
        );
        let first = super::response_for_request_with_state(&request, &state);
        assert!(first.contains("\"approved\":false"), "{first}");
        let approved = super::response_for_request_with_state(
            "POST /api/v1/peer/approve HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n",
            &state,
        );
        assert!(approved.contains("\"approved\":true"), "{approved}");

        let repeated = super::response_for_request_with_state(&request, &state);
        assert!(repeated.contains("\"approved\":true"), "{repeated}");
        assert!(repeated.contains("\"transport\":\"restart_required\""));
        assert!(!repeated.contains(secret));
    }

    #[test]
    fn runtime_restart_is_loopback_scoped_and_only_scheduled_when_required() {
        let state = super::AgentState::default();
        let unnecessary = super::response_for_request_with_state(
            "POST /api/v1/runtime/restart HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n",
            &state,
        );
        assert!(
            unnecessary.starts_with("HTTP/1.1 409 Conflict"),
            "{unnecessary}"
        );
        assert!(!state.runtime_restart.scheduled.load(Ordering::Acquire));

        state
            .peer_transport_restart_required
            .store(true, Ordering::Release);
        let scheduled = super::response_for_request_with_state(
            "POST /api/v1/runtime/restart HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n",
            &state,
        );
        assert!(
            scheduled.starts_with("HTTP/1.1 202 Accepted"),
            "{scheduled}"
        );
        assert!(state.runtime_restart.scheduled.load(Ordering::Acquire));
        assert!(!state.runtime_restart.requested.load(Ordering::Acquire));
        let mutation = super::response_for_request_with_state(
            "POST /api/v1/service/start HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n",
            &state,
        );
        assert!(mutation.starts_with("HTTP/1.1 409 Conflict"), "{mutation}");
        super::dispatch_runtime_restart(&state.runtime_restart);
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(state.runtime_restart.requested.load(Ordering::Acquire));

        let remote = super::response_for_request_with_state(
            "POST /api/v1/runtime/restart HTTP/1.1\r\nHost: example.test\r\nOrigin: http://example.test\r\n\r\n",
            &state,
        );
        assert!(remote.starts_with("HTTP/1.1 403 Forbidden"), "{remote}");
    }

    #[test]
    fn peer_config_rejects_invalid_onion_and_non_loopback_admin_requests() {
        let invalid = super::response_for_request("POST /api/v1/peer/config HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n{\"role\":\"cliente\",\"node_id\":\"client-01\",\"host_node_id\":\"host-01\",\"onion_endpoint\":\"/var/lib/tor/hostname\",\"invitation_secret\":\"secret-token-123456\"}");
        assert!(invalid.starts_with("HTTP/1.1 400 Bad Request"), "{invalid}");
        let remote = super::response_for_request(
            "GET /api/v1/peer/status HTTP/1.1\r\nHost: example.test\r\n\r\n",
        );
        assert!(remote.starts_with("HTTP/1.1 403 Forbidden"), "{remote}");
    }

    #[test]
    fn missing_or_non_loopback_host_is_rejected() {
        for host in ["", "example.test"] {
            let request = if host.is_empty() {
                "GET /api/v1/status HTTP/1.1\r\n\r\n".to_string()
            } else {
                format!("GET /api/v1/status HTTP/1.1\r\nHost: {host}\r\n\r\n")
            };
            let response = super::response_for_request(&request);
            assert!(
                response.starts_with("HTTP/1.1 403 Forbidden"),
                "{host}: {response}"
            );
        }
    }

    #[test]
    fn loopback_host_matching_is_case_insensitive_and_supports_ports() {
        for host in ["LOCALHOST:8765", "127.0.0.1:9", "[::1]:8765"] {
            let response = super::response_for_request(&format!(
                "GET /api/v1/status HTTP/1.1\r\nHost: {host}\r\n\r\n"
            ));
            assert!(
                response.starts_with("HTTP/1.1 200 OK"),
                "{host}: {response}"
            );
        }
    }

    #[test]
    fn malformed_mode_json_is_rejected() {
        let response = super::response_for_request(
            "POST /api/v1/mode HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\nnot-json{\"mode\":\"host\"}");
        assert!(
            response.starts_with("HTTP/1.1 400 Bad Request"),
            "{response}"
        );

        let response = super::response_for_request(
            "POST /api/v1/mode HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n{\"mode\":\"client\"}");
        assert!(
            response.starts_with("HTTP/1.1 400 Bad Request"),
            "{response}"
        );
    }

    #[test]
    fn peer_store_persists_approval_and_revocation_without_status_secret() {
        let path =
            std::env::temp_dir().join(format!("localscale-peer-test-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut store = super::PeerStore::open(&path).unwrap();
        store
            .configure(super::PeerRecord {
                role: "cliente".into(),
                node_id: "client-01".into(),
                host_node_id: Some("host-01".into()),
                endpoint: "abc.onion".into(),
                invitation_secret: "secret-value".into(),
                virtual_ip: None,
                approved: false,
                revoked: false,
            })
            .unwrap();
        let persisted = std::fs::read_to_string(&path).unwrap();
        assert!(!persisted.contains("secret-value"));
        assert!(!persisted.contains("invitation_secret"));
        assert!(persisted.contains("transport_key"));
        assert!(
            !super::PeerStore::open(&path)
                .unwrap()
                .record()
                .unwrap()
                .approved
        );
        store.set_approval(true).unwrap();
        let reloaded = super::PeerStore::open(&path).unwrap();
        assert!(reloaded.record().unwrap().approved);
        store.set_approval(false).unwrap();
        let revoked = super::PeerStore::open(&path).unwrap();
        assert!(revoked.record().unwrap().revoked);
        let state = super::AgentState {
            peer_store: Some(std::sync::Arc::new(std::sync::Mutex::new(revoked))),
            ..super::AgentState::default()
        };
        let status = super::response_for_request_with_state(
            "GET /api/v1/peer/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
            &state,
        );
        assert!(!status.contains("secret-value"));
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn peer_store_migrates_legacy_invitation_secret_without_retaining_it() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!(
            "localscale-peer-legacy-{}-{}.json",
            std::process::id(),
            super::unix_time_secs().unwrap()
        ));
        let _ = std::fs::remove_file(&path);
        let legacy_secret = "legacy-invitation-secret-012345";
        std::fs::write(
            &path,
            format!(r#"{{"role":"cliente","node_id":"client-01","host_node_id":"host-01","endpoint":"abcdefghijklmnopqrstuvwxabcdefghijklmnopqrstuvwxyz234567.onion","invitation_secret":"{legacy_secret}","virtual_ip":"","approved":true,"revoked":false}}"#),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let store = super::PeerStore::open(&path).unwrap();
        assert!(store
            .record()
            .unwrap()
            .invitation_secret
            .starts_with("key-v1-"));
        let migrated = std::fs::read_to_string(&path).unwrap();
        assert!(migrated.contains("transport_key"));
        assert!(!migrated.contains("invitation_secret"));
        assert!(!migrated.contains(legacy_secret));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn peer_store_rejects_malformed_startup_state() {
        let path =
            std::env::temp_dir().join(format!("localscale-peer-bad-{}.json", std::process::id()));
        std::fs::write(&path, "not-json").unwrap();
        assert!(super::PeerStore::open(&path).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn peer_store_rejects_existing_symlink() {
        use std::os::unix::fs::symlink;
        let path = std::env::temp_dir().join(format!(
            "localscale-peer-symlink-{}.json",
            std::process::id()
        ));
        let target = std::env::temp_dir().join(format!(
            "localscale-peer-target-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&target);
        symlink(&target, &path).unwrap();
        assert!(super::PeerStore::open(&path).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn peer_store_rejects_group_or_other_readable_existing_file() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!(
            "localscale-peer-readable-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, r#"{"role":"cliente","node_id":"client-01","endpoint":"abc.onion","invitation_secret":"secret-value","approved":false,"revoked":true}"#).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(super::PeerStore::open(&path).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn peer_store_creates_regular_user_private_file() {
        use std::os::unix::fs::MetadataExt;
        let path = std::env::temp_dir().join(format!(
            "localscale-peer-private-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut store = super::PeerStore::open(&path).unwrap();
        store
            .configure(super::PeerRecord {
                role: "cliente".into(),
                node_id: "client-01".into(),
                host_node_id: None,
                endpoint: "abc.onion".into(),
                invitation_secret: "secret-value".into(),
                virtual_ip: None,
                approved: false,
                revoked: false,
            })
            .unwrap();
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.uid(), super::effective_uid());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn peer_store_serializes_untrusted_values_as_valid_json() {
        let path =
            std::env::temp_dir().join(format!("localscale-peer-json-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut store = super::PeerStore::open(&path).unwrap();
        store
            .configure(super::PeerRecord {
                role: "cliente\"<script>".into(),
                node_id: "node\\\"\n".into(),
                host_node_id: Some("host\"><img src=x>".into()),
                endpoint: "endpoint.onion\\\"".into(),
                invitation_secret: "opaque\\secret".into(),
                virtual_ip: Some("10.42.0.1\n".into()),
                approved: false,
                revoked: false,
            })
            .unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        let document: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(document["role"], "cliente\"<script>");
        assert_eq!(document["node_id"], "node\\\"\n");
        assert_eq!(document["host_node_id"], "host\"><img src=x>");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn peer_debug_output_redacts_invitation_secret() {
        let record = super::PeerRecord {
            role: "cliente".into(),
            node_id: "client-01".into(),
            host_node_id: None,
            endpoint: "abc.onion".into(),
            invitation_secret: "secret-value".into(),
            virtual_ip: None,
            approved: false,
            revoked: false,
        };
        let store = super::PeerStore {
            path: std::path::PathBuf::from("peer.json"),
            record: Some(record.clone()),
        };
        assert!(!format!("{record:?}").contains("secret-value"));
        assert!(!format!("{store:?}").contains("secret-value"));
    }

    #[test]
    fn health_endpoint_returns_ok_json() {
        assert_eq!(
            health_response(),
            r#"{"status":"ok","service":"localscale"}"#
        );
    }

    #[test]
    fn mode_parser_accepts_json_whitespace_but_rejects_extra_fields_and_escapes() {
        for body in [" { \"mode\" : \"host\" } ", "{\n\t\"mode\":\"cliente\"\n}"] {
            let response = super::response_for_request(&format!(
                "POST /api/v1/mode HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n{body}"));
            assert!(
                response.starts_with("HTTP/1.1 200 OK"),
                "{body}: {response}"
            );
        }
        for body in [
            "{\"mode\":\"host\",\"other\":true}",
            "{\"mode\":\"ho\\u0073t\"}",
        ] {
            let response = super::response_for_request(&format!(
                "POST /api/v1/mode HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n{body}"));
            assert!(
                response.starts_with("HTTP/1.1 400 Bad Request"),
                "{body}: {response}"
            );
        }
    }

    #[test]
    fn write_budget_is_remaining_after_reading() {
        let started = std::time::Instant::now();
        let total = std::time::Duration::from_secs(5);
        let after_reading = started + std::time::Duration::from_secs(3);
        assert_eq!(
            super::remaining_budget(started, total, after_reading),
            Some(std::time::Duration::from_secs(2))
        );
        assert_eq!(
            super::remaining_budget(started, total, started + total),
            None
        );
    }

    #[test]
    fn poisoned_state_lock_is_recovered_for_request_handling() {
        let state = super::AgentState::default();
        let mode = state.mode.clone();
        let _ = std::panic::catch_unwind(move || {
            let _guard = mode.lock().unwrap();
            panic!("poison test");
        });
        let response = super::response_for_request_with_state(
            "GET /mode HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n",
            &state,
        );
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains(r#""mode":"cliente""#));
    }

    #[test]
    fn server_survives_connection_errors_and_slow_clients() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || super::serve(listener).unwrap());
        let slow = TcpStream::connect(address).unwrap();
        thread::sleep(Duration::from_millis(50));
        let mut broken = TcpStream::connect(address).unwrap();
        broken.write_all(b"GET /health HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n").unwrap();
        drop(broken);
        let mut fast = TcpStream::connect(address).unwrap();
        fast.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        fast.write_all(b"GET /health HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n").unwrap();
        let mut response = String::new();
        fast.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        drop(slow);
    }

    #[test]
    fn slowloris_connection_has_a_total_deadline() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || super::serve(listener).unwrap());
        let mut slow = std::net::TcpStream::connect(address).unwrap();
        slow.set_read_timeout(Some(Duration::from_secs(7))).unwrap();
        slow.write_all(b"G").unwrap();
        thread::sleep(Duration::from_secs(6));
        let mut response = Vec::new();
        let result = slow.read_to_end(&mut response);
        assert!(result.is_ok() || result.unwrap_err().kind() == std::io::ErrorKind::UnexpectedEof);
        assert!(
            response.is_empty(),
            "slow client unexpectedly got response: {response:?}"
        );
    }

    #[test]
    fn connection_limit_rejects_excess_clients() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || super::serve(listener).unwrap());
        let mut held = Vec::new();
        for _ in 0..super::MAX_CONNECTIONS {
            let mut stream = std::net::TcpStream::connect(address).unwrap();
            stream.write_all(b"G").unwrap();
            held.push(stream);
        }
        let mut excess = std::net::TcpStream::connect(address).unwrap();
        excess
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut response = String::new();
        excess.read_to_string(&mut response).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 503 Service Unavailable"),
            "{response}"
        );
    }

    #[test]
    fn revoking_peer_disables_running_transport_gate() {
        let state = super::AgentState::default();
        super::lock_recover(state.peer_store.as_ref().unwrap())
            .configure(super::PeerRecord {
                role: "host".into(),
                node_id: "host-01".into(),
                host_node_id: None,
                endpoint: format!("{}.onion", "a".repeat(56)),
                invitation_secret: "secret".into(),
                virtual_ip: None,
                approved: true,
                revoked: false,
            })
            .unwrap();
        assert!(state
            .peer_transport_enabled
            .load(std::sync::atomic::Ordering::Acquire));
        let response = super::response_for_request_with_state(
            "POST /api/v1/peer/revoke HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nContent-Length: 0\r\n\r\n", &state);
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(!state
            .peer_transport_enabled
            .load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(
            state.peer_transport_status.get(),
            super::TransportState::Disabled
        );
    }

    #[test]
    fn transport_telemetry_drives_peer_and_diagnostics_connected_flags() {
        let state = super::AgentState::default();
        state.peer_transport_status.record_peer_activity(2);
        let peer = super::peer_status(&state);
        let diagnostics = super::diagnostics_status(&state);
        assert!(peer.contains("\"transport\":\"connected\""));
        assert!(peer.contains("\"connected\":true"));
        assert!(peer.contains("\"messages_exchanged\":2"));
        assert!(diagnostics.contains("\"peer_connected\":true"));
        assert!(diagnostics.contains("\"messages_exchanged\":2"));
    }

    #[test]
    fn connected_flag_expires_without_a_recent_ack() {
        let status = super::PeerTransportStatus::default();
        status.set(super::TransportState::Connected);
        status.last_peer_activity_unix.store(
            super::unix_time_secs().unwrap().saturating_sub(16),
            std::sync::atomic::Ordering::Release,
        );
        assert!(!status.is_connected());
    }

    #[test]
    fn set_virtual_ip_persists_and_updates_devices() {
        let path =
            std::env::temp_dir().join(format!("localscale-peer-vip-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut store = super::PeerStore::open(&path).unwrap();
        store
            .configure(super::PeerRecord {
                role: "host".into(),
                node_id: "host-node".into(),
                host_node_id: None,
                endpoint: "test.onion".into(),
                invitation_secret: "secret".into(),
                virtual_ip: None,
                approved: true,
                revoked: false,
            })
            .unwrap();
        let state = super::AgentState {
            peer_store: Some(std::sync::Arc::new(std::sync::Mutex::new(store))),
            ..super::AgentState::default()
        };
        // Initial devices check
        let devices = super::response_for_request_with_state(
            "GET /api/v1/devices HTTP/1.1\r\nHost: localhost\r\n\r\n",
            &state,
        );
        assert!(devices.starts_with("HTTP/1.1 200 OK"), "{devices}");
        assert!(devices.contains("Tor v3 Onion (Strict Isolation)"));

        // Set virtual IP
        let update = super::response_for_request_with_state(
            "POST /api/v1/peer/virtual-ip HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\n\r\n{\"virtual_ip\":\"10.42.0.1\"}", &state);
        assert!(update.starts_with("HTTP/1.1 200 OK"), "{update}");
        assert!(update.contains("\"virtual_ip\":\"10.42.0.1\""));

        // Reload store from disk
        let reloaded = super::PeerStore::open(&path).unwrap();
        assert_eq!(
            reloaded.record().unwrap().virtual_ip.as_deref(),
            Some("10.42.0.1")
        );

        // Devices now contains virtual IP
        let devices_after = super::response_for_request_with_state(
            "GET /api/v1/devices HTTP/1.1\r\nHost: localhost\r\n\r\n",
            &state,
        );
        assert!(devices_after.contains("\"virtual_ip\":\"10.42.0.1\""));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn configuration_page_has_product_title() {
        assert!(configuration_html().contains("<title>LocalScale</title>"));
    }

    #[test]
    fn json_string_escapes_structural_and_control_characters() {
        let encoded = super::json_string("quote\" slash\\ newline\n tab\t");
        assert_eq!(encoded, r#""quote\" slash\\ newline\n tab\t""#);
        assert_eq!(
            serde_json::from_str::<String>(&encoded).unwrap(),
            "quote\" slash\\ newline\n tab\t"
        );
    }

    #[test]
    fn devices_response_is_valid_json_with_untrusted_values() {
        let state = super::AgentState::default();
        {
            let mut peer = super::lock_recover(&state.peer);
            peer.configured = true;
            peer.node_id = Some(r#"local\"><script>alert(1)</script>"#.into());
            peer.host_node_id = Some(r#"remote\"><img src=x onerror=alert(1)>"#.into());
            peer.endpoint =
                Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"><script>".into());
            peer.virtual_ip = Some("10.42.0.1\n<script>".into());
            peer.approved = true;
        }
        let response = super::devices_status(&state);
        let body = response.split_once("\r\n\r\n").unwrap().1;
        let document: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(
            document["local_device"]["node_id"],
            r#"local\"><script>alert(1)</script>"#
        );
        assert_eq!(
            document["remote_peers"][0]["node_id"],
            r#"remote\"><img src=x onerror=alert(1)>"#
        );
        assert!(!body.contains("<script>"));
        assert!(!body.contains("<img"));
    }

    #[test]
    fn configuration_page_escapes_peer_values_before_inner_html() {
        let html = super::configuration_html();
        assert!(html.contains("function escapeHtml(value)"));
        assert!(html.contains("escapeHtml(local.node_id"));
        assert!(html.contains("escapeHtml(peer.node_id"));
        assert!(html.contains("escapeHtml(peer.status)"));
    }
}
