use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::path::{Path, PathBuf};
use localscale_control_plane::{AuthRequest, AuthResponse};
use localscale_agent_protocol::{ClientConfig, HostInvitation};

pub mod tor_runtime;

pub trait AuthHandler: Send {
    fn handle(&mut self, request: AuthRequest) -> AuthResponse;
}

impl<P: localscale_control_plane::AuthProvider + Send> AuthHandler
    for localscale_control_plane::AuthService<P>
{
    fn handle(&mut self, request: AuthRequest) -> AuthResponse {
        localscale_control_plane::AuthService::handle(self, request)
    }
}

type SharedAuth = Arc<Mutex<Box<dyn AuthHandler>>>;

const VERSION: &str = "0.1.0";
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const MAX_CONNECTIONS: usize = 16;

fn lock_recover<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn remaining_budget(started: std::time::Instant, total: std::time::Duration, now: std::time::Instant) -> Option<std::time::Duration> {
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
          html += '<div><strong>💻 ' + (local.node_id || 'Este Dispositivo') + '</strong> <span style="color: var(--accent-primary); font-size: 0.75rem;">(' + local.role + ')</span><br><span style="color: var(--text-muted); font-size: 0.75rem;">IP Virtual: ' + (local.virtual_ip || 'não atribuído') + '</span></div>';
          html += '<span style="background: rgba(16, 185, 129, 0.15); color: var(--success); padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem;">● Local</span>';
          html += '</div>';
        }

        if (peers.length === 0) {
          html += '<div style="color: var(--text-muted); font-size: 0.8rem; font-style: italic; padding: 0.4rem 0;">Nenhum outro peer emparelhado na rede Onion ainda.</div>';
        } else {
          for (const peer of peers) {
            html += '<div style="background: var(--bg-surface-elevated); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 0.6rem 0.8rem; display: flex; justify-content: space-between; align-items: center;">';
            html += '<div><strong>🔗 ' + (peer.node_id || 'Peer Remoto') + '</strong> <span style="color: var(--accent-primary); font-size: 0.75rem;">(' + peer.role + ')</span><br><span style="color: var(--text-muted); font-size: 0.75rem;">IP Virtual: ' + (peer.virtual_ip || 'auto') + ' | Onion: ' + (peer.onion_endpoint ? peer.onion_endpoint.substring(0, 16) + '...' : '-') + '</span></div>';
            html += '<span style="background: rgba(59, 130, 246, 0.15); color: #93c5fd; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem;">' + peer.status + '</span>';
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
    auth: Option<SharedAuth>,
    peer_store: Option<Arc<Mutex<PeerStore>>>,
    peer_transport_enabled: Arc<AtomicBool>,
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
        formatter.debug_struct("PeerRecord")
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
pub struct PeerStore { path: PathBuf, record: Option<PeerRecord> }

impl std::fmt::Debug for PeerStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("PeerStore")
            .field("path", &self.path)
            .field("record", &self.record)
            .finish()
    }
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    unsafe extern "C" { fn geteuid() -> u32; }
    unsafe { geteuid() }
}

impl PeerStore {
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let record = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => {
                Self::validate_file(&path, &metadata)?;
                Some(Self::read_record(&path)?)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        Ok(Self { path, record })
    }
    pub fn record(&self) -> Option<&PeerRecord> { self.record.as_ref() }
    pub fn ephemeral() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!("localscale-peer-{}-{}.json", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos()));
        Self::open(path)
    }
    pub fn configure(&mut self, record: PeerRecord) -> std::io::Result<()> {
        self.write_record(&record)?; self.record = Some(record); Ok(())
    }
    pub fn set_approval(&mut self, approved: bool) -> std::io::Result<()> {
        let Some(mut record) = self.record.clone() else { return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "peer is not configured")); };
        record.approved = approved; record.revoked = !approved;
        self.write_record(&record)?; self.record = Some(record); Ok(())
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
        self.write_record(&record)?; self.record = Some(record); Ok(())
    }
    fn validate_file(path: &Path, metadata: &std::fs::Metadata) -> std::io::Result<()> {
        if !metadata.file_type().is_file() {
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "peer store must be a regular file"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != effective_uid() {
                return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "peer store has the wrong owner"));
            }
            if metadata.mode() & 0o044 != 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "peer store is readable by group or other users"));
            }
        }
        let _ = path;
        Ok(())
    }
    fn read_record(path: &Path) -> std::io::Result<PeerRecord> {
        let body = std::fs::read_to_string(path)?;
        let fields = parse_json_fields(&body).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid peer store"))?;
        let role = fields.get("role").cloned().unwrap_or_default();
        let node_id = fields.get("node_id").cloned().unwrap_or_default();
        let endpoint = fields.get("endpoint").cloned().unwrap_or_default();
        let invitation_secret = fields.get("invitation_secret").cloned().unwrap_or_default();
        let approved = fields.get("approved").map(|v| v == "true").unwrap_or(false);
        let revoked = fields.get("revoked").map(|v| v == "true").unwrap_or(true);
        let host_node_id = fields.get("host_node_id").cloned().filter(|v| !v.is_empty());
        let virtual_ip = fields.get("virtual_ip").cloned().filter(|v| !v.is_empty());
        if role.is_empty() || node_id.is_empty() || endpoint.is_empty() || invitation_secret.is_empty() { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "incomplete peer store")); }
        Ok(PeerRecord { role, node_id, host_node_id, endpoint, invitation_secret, virtual_ip, approved, revoked })
    }
    fn write_record(&self, record: &PeerRecord) -> std::io::Result<()> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;
        let tmp = self.path.with_extension("tmp");
        let virtual_ip_str = record.virtual_ip.as_deref().unwrap_or("");
        let body = format!("{{\"role\":\"{}\",\"node_id\":\"{}\",\"host_node_id\":\"{}\",\"endpoint\":\"{}\",\"invitation_secret\":\"{}\",\"virtual_ip\":\"{}\",\"approved\":{},\"revoked\":{}}}", record.role, record.node_id, record.host_node_id.as_deref().unwrap_or(""), record.endpoint, record.invitation_secret, virtual_ip_str, record.approved, record.revoked);
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?; }
        file.write_all(body.as_bytes())?; file.sync_all()?;
        #[cfg(unix)] {
            let metadata = std::fs::symlink_metadata(&tmp)?;
            Self::validate_file(&tmp, &metadata)?;
        }
        std::fs::rename(&tmp, &self.path)?;
        if let Ok(dir) = std::fs::File::open(parent) { let _ = dir.sync_all(); }
        Ok(())
    }
}

impl Default for AgentState {
    fn default() -> Self {
        Self {
            mode: Arc::new(Mutex::new("cliente".to_string())),
            service_state: Arc::new(Mutex::new("stopped".to_string())),
            peer: Arc::new(Mutex::new(PeerState { transport: "unavailable", ..PeerState::default() })),
            auth: None,
            peer_store: PeerStore::ephemeral().ok().map(|s| Arc::new(Mutex::new(s))),
            peer_transport_enabled: Arc::new(AtomicBool::new(true)),
        }
    }
}

pub fn serve(listener: TcpListener) -> std::io::Result<()> {
    serve_with_auth_handler(listener, None, None)
}

pub fn serve_with_auth(listener: TcpListener, auth: Box<dyn AuthHandler>) -> std::io::Result<()> {
    serve_with_auth_handler(listener, Some(Arc::new(Mutex::new(auth))), None)
}

pub fn serve_with_peer_transport_gate(listener: TcpListener, gate: Arc<AtomicBool>) -> std::io::Result<()> {
    serve_with_auth_handler(listener, None, Some(gate))
}

pub fn serve_with_auth_and_peer_transport_gate(listener: TcpListener, auth: Box<dyn AuthHandler>, gate: Arc<AtomicBool>) -> std::io::Result<()> {
    serve_with_auth_handler(listener, Some(Arc::new(Mutex::new(auth))), Some(gate))
}

fn serve_with_auth_handler(listener: TcpListener, auth: Option<SharedAuth>, gate: Option<Arc<AtomicBool>>) -> std::io::Result<()> {
    let peer_store = match std::env::var_os("LOCALSCALE_PEER_STORE") {
        Some(path) => match PeerStore::open(path) {
            Ok(store) => Some(store),
            Err(error) => {
                eprintln!("LocalScale peer store unavailable; control API remains available ({error})");
                None
            }
        },
        None => PeerStore::ephemeral().ok(),
    };
    let state = AgentState {
        auth,
        peer_store: peer_store.map(|s| Arc::new(Mutex::new(s))),
        peer_transport_enabled: gate.unwrap_or_else(|| Arc::new(AtomicBool::new(true))),
        ..AgentState::default()
    };
    if let Some(store) = &state.peer_store {
        if let Some(record) = lock_recover(store).record().cloned() {
            let mut peer = lock_recover(&state.peer);
            peer.configured = true; peer.node_id = Some(record.node_id); peer.host_node_id = record.host_node_id; peer.endpoint = Some(record.endpoint);
            peer.virtual_ip = record.virtual_ip;
            peer.approved = record.approved; peer.revoked = record.revoked;
        }
    }
    let active = Arc::new(Mutex::new(0usize));
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
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
            let _ = stream.write_all(http_response("503 Service Unavailable", "text/plain; charset=utf-8", "connection limit reached").as_bytes());
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
    Ok(())
}

struct ConnectionGuard { active: Arc<Mutex<usize>> }
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let mut active = lock_recover(&self.active);
        *active = active.saturating_sub(1);
    }
}

fn handle_connection(mut stream: TcpStream, state: &AgentState, accepted_at: std::time::Instant) -> std::io::Result<()> {
    let mut request = Vec::with_capacity(4096);
    let mut buffer = [0_u8; 1024];
    while request.len() < MAX_REQUEST_BYTES {
        let elapsed = accepted_at.elapsed();
        if elapsed >= REQUEST_TIMEOUT { return Ok(()); }
        stream.set_read_timeout(Some(REQUEST_TIMEOUT - elapsed))?;
        let read = match stream.read(&mut buffer) {
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => return Ok(()),
            Err(error) => return Err(error),
        };
        if read == 0 { break; }
        request.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
            let header = String::from_utf8_lossy(&request[..header_end]);
            let content_length = header.lines().find_map(|line| {
                line.strip_prefix("Content-Length:").and_then(|value| value.trim().parse::<usize>().ok())
            }).unwrap_or(0);
            if content_length > MAX_REQUEST_BYTES || header_end + 4 + content_length > MAX_REQUEST_BYTES {
                return stream.write_all(http_response("413 Payload Too Large", "text/plain; charset=utf-8", "request too large").as_bytes());
            }
            if request.len() >= header_end + 4 + content_length { break; }
        }
    }
    let request = String::from_utf8_lossy(&request);
    let response = response_for_request_with_state(&request, state);
    let Some(write_budget) = remaining_budget(accepted_at, REQUEST_TIMEOUT, std::time::Instant::now()) else { return Ok(()); };
    stream.set_write_timeout(Some(write_budget))?;
    stream.write_all(response.as_bytes())
}

pub fn response_for_request(request: &str) -> String {
    response_for_request_with_state(request, &AgentState::default())
}

pub fn response_for_request_with_auth<A: AuthHandler>(request: &str, auth: &mut A) -> String {
    let head = request.split("\r\n\r\n").next().unwrap_or("");
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let (path, query_string) = target.split_once('?').unwrap_or((target, ""));
    let headers: Vec<(&str, &str)> = lines.filter_map(|line| line.split_once(':').map(|(name, value)| (name, value.trim()))).collect();
    let host = headers.iter().find_map(|(name, value)| name.eq_ignore_ascii_case("host").then_some(*value)).unwrap_or("");
    if !is_loopback_host(host) { return http_response("403 Forbidden", "text/plain; charset=utf-8", "local requests only"); }
    let query = match parse_query(query_string) { Ok(query) => query, Err(()) => return http_response("400 Bad Request", "text/plain; charset=utf-8", "malformed query") };
    let request_headers = headers.into_iter().map(|(name, value)| {
        let name = if name.eq_ignore_ascii_case("cookie") { "Cookie" } else if name.eq_ignore_ascii_case("x-csrf-token") { "X-CSRF-Token" } else { name };
        (name.to_owned(), value.to_owned())
    }).collect();
    auth_http_response(auth.handle(AuthRequest { method: method.to_owned(), path: path.to_owned(), query, headers: request_headers }))
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
    let (path, query_string) = target.split_once('?').unwrap_or((target, ""));
    let headers: Vec<(&str, &str)> = fields.filter_map(|line| line.split_once(':').map(|(name, value)| (name, value.trim()))).collect();
    let host = headers.iter().find_map(|(name, value)| name.eq_ignore_ascii_case("host").then_some(*value)).unwrap_or("");

    if !is_loopback_host(host) {
        return http_response("403 Forbidden", "text/plain; charset=utf-8", "local requests only");
    }
    if matches!(path, "/oauth/google/start" | "/oauth/google/callback" | "/auth/session" | "/auth/session/bridge" | "/auth/logout") {
        let Some(auth) = &state.auth else {
            return http_response("503 Service Unavailable", "text/plain; charset=utf-8", "authentication unavailable");
        };
        let query = match parse_query(query_string) {
            Ok(query) => query,
            Err(()) => return http_response("400 Bad Request", "text/plain; charset=utf-8", "malformed query"),
        };
        let request_headers = headers.into_iter().map(|(name, value)| {
            let name = if name.eq_ignore_ascii_case("cookie") { "Cookie" } else if name.eq_ignore_ascii_case("x-csrf-token") { "X-CSRF-Token" } else { name };
            (name.to_owned(), value.to_owned())
        }).collect();
        let response = lock_recover(auth).handle(AuthRequest { method: method.to_owned(), path: path.to_owned(), query, headers: request_headers });
        return auth_http_response(response);
    }
    if is_state_changing_method(method) && !has_same_origin_proof(&headers, host) {
        return http_response("403 Forbidden", "text/plain; charset=utf-8", "csrf validation failed");
    }
    match (method, path) {
        ("GET", "/api/v1/status") => service_status(state),
        ("GET", "/api/v1/peer/status") => peer_status(state),
        ("POST", "/api/v1/peer/config") => set_peer_config(body, state),
        ("POST", "/api/v1/peer/approve") => set_peer_approval(true, state),
        ("POST", "/api/v1/peer/revoke") => set_peer_approval(false, state),
        ("POST", "/api/v1/peer/virtual-ip") => set_virtual_ip_handler(body, state),
        ("GET", "/api/v1/devices") => devices_status(state),
        ("POST", "/api/v1/mode") => set_mode(body, state, true),
        ("POST", "/api/v1/service/start") => set_service_state("running", state),
        ("POST", "/api/v1/service/stop") => set_service_state("stopped", state),
        ("POST", "/api/v1/sync") => service_status(state),
        ("GET", "/") | ("GET", "/config") => http_response("200 OK", "text/html; charset=utf-8", configuration_html()),
        ("GET", "/health") => http_response("200 OK", "application/json", health_response()),
        ("GET", "/version") => http_response("200 OK", "application/json", &format!(r#"{{"version":"{VERSION}","service":"localscale"}}"#)),
        ("GET", "/status") => service_status(state),
        ("GET", "/mode") => {
            let mode = lock_recover(&state.mode).clone();
            http_response("200 OK", "application/json", &format!(r#"{{"mode":"{mode}"}}"#))
        }
        ("POST", "/mode") => set_mode(body, state, false),
        ("GET", "/onion") => http_response("200 OK", "application/json", r#"{"enabled":false,"address":null}"#),
        ("GET", "/diagnostics") | ("GET", "/api/v1/diagnostics") => diagnostics_status(state),
        _ => http_response("404 Not Found", "text/plain; charset=utf-8", "not found"),
    }
}

fn parse_query(query: &str) -> Result<std::collections::HashMap<String, String>, ()> {
    let mut result = std::collections::HashMap::new();
    if query.is_empty() { return Ok(result); }
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        result.insert(strict_decode(key)?, strict_decode(value)?);
    }
    Ok(result)
}

fn strict_decode(input: &str) -> Result<String, ()> {
    let mut bytes = Vec::with_capacity(input.len());
    let raw = input.as_bytes();
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b'+' => bytes.push(b' '),
            b'%' if i + 2 < raw.len() => {
                let hi = (raw[i + 1] as char).to_digit(16).ok_or(())?;
                let lo = (raw[i + 2] as char).to_digit(16).ok_or(())?;
                bytes.push((hi * 16 + lo) as u8); i += 2;
            }
            b'%' => return Err(()),
            byte => bytes.push(byte),
        }
        i += 1;
    }
    String::from_utf8(bytes).map_err(|_| ())
}

fn auth_http_response(response: AuthResponse) -> String {
    let status = match response.status {
        200 => "200 OK", 204 => "204 No Content", 302 => "302 Found", 303 => "303 See Other",
        400 => "400 Bad Request", 401 => "401 Unauthorized", 403 => "403 Forbidden", 502 => "502 Bad Gateway",
        _ => "500 Internal Server Error",
    };
    let mut output = format!("HTTP/1.1 {status}\r\n");
    for (name, value) in response.headers { output.push_str(&format!("{name}: {value}\r\n")); }
    output.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n{}", response.body.len(), response.body));
    output
}

fn service_status(state: &AgentState) -> String {
    let mode = lock_recover(&state.mode).clone();
    let service_state = lock_recover(&state.service_state).clone();
    let peer = lock_recover(&state.peer);
    http_response("200 OK", "application/json", &format!(
        r#"{{"mode":"{mode}","state":"{service_state}","onion_endpoint":null,"peer_configured":{},"peer_transport":"{}"}}"#,
        peer.configured, peer.transport))
}

fn peer_status(state: &AgentState) -> String {
    let peer = lock_recover(&state.peer);
    let json = format!(r#"{{"configured":{},"node_id":{},"host_node_id":{},"onion_endpoint":{},"virtual_ip":{},"transport":"{}","connected":false,"approved":{},"revoked":{}}}"#,
        peer.configured, optional_json(&peer.node_id), optional_json(&peer.host_node_id), optional_json(&peer.endpoint), optional_json(&peer.virtual_ip), peer.transport, peer.approved, peer.revoked);
    http_response("200 OK", "application/json", &json)
}

fn set_virtual_ip_handler(body: &str, state: &AgentState) -> String {
    let fields = match parse_json_fields(body) {
        Some(fields) => fields,
        None => return http_response("400 Bad Request", "application/json", r#"{"error":"invalid_payload"}"#),
    };
    let virtual_ip = fields.get("virtual_ip").cloned().filter(|v| !v.trim().is_empty());
    let Some(store) = &state.peer_store else {
        return http_response("503 Service Unavailable", "application/json", r#"{"error":"peer_store_unavailable"}"#);
    };
    if lock_recover(store).set_virtual_ip(virtual_ip.clone()).is_err() {
        return http_response("404 Not Found", "application/json", r#"{"error":"peer_not_configured"}"#);
    }
    let mut peer = lock_recover(&state.peer);
    peer.virtual_ip = virtual_ip;
    drop(peer);
    peer_status(state)
}

fn devices_status(state: &AgentState) -> String {
    let mode = lock_recover(&state.mode).clone();
    let peer = lock_recover(&state.peer);
    let local_node_id = peer.node_id.as_deref().unwrap_or("local-node");
    let local_ip = peer.virtual_ip.as_deref().unwrap_or("");
    let local_endpoint = peer.endpoint.as_deref().unwrap_or("");

    let mut peers_json = String::new();
    if peer.configured {
        let peer_role = if mode == "host" { "cliente" } else { "host" };
        let remote_id = peer.host_node_id.as_deref().unwrap_or("remote-node");
        let remote_ip = if local_ip.ends_with(".1") {
            let prefix = &local_ip[..local_ip.len() - 2];
            format!("{prefix}.2")
        } else if local_ip.ends_with(".2") {
            let prefix = &local_ip[..local_ip.len() - 2];
            format!("{prefix}.1")
        } else {
            String::new()
        };
        let status = if peer.approved { "approved" } else if peer.revoked { "revoked" } else { "pending" };
        peers_json = format!(
            r#"{{"node_id":"{remote_id}","role":"{peer_role}","onion_endpoint":"{local_endpoint}","virtual_ip":"{remote_ip}","status":"{status}","approved":{},"revoked":{}}}"#,
            peer.approved, peer.revoked
        );
    }

    let json = format!(
        r#"{{"transport":"Tor v3 Onion (Strict Isolation)","isolation":"tor_only_no_lan","local_device":{{"node_id":"{local_node_id}","role":"{mode}","onion_endpoint":"{local_endpoint}","virtual_ip":"{local_ip}","status":"active"}},"remote_peers":[{}]}}"#,
        peers_json
    );
    http_response("200 OK", "application/json", &json)
}

fn diagnostics_status(state: &AgentState) -> String {
    let peer = lock_recover(&state.peer);
    let json = format!(r#"{{"service":"localscale","loopback":true,"external_network":false,"peer_configured":{},"peer_transport":"{}","peer_connected":false}}"#, peer.configured, peer.transport);
    http_response("200 OK", "application/json", &json)
}

fn optional_json(value: &Option<String>) -> String {
    value.as_ref().map(|value| format!("\"{}\"", value)).unwrap_or_else(|| "null".into())
}

fn set_peer_config(body: &str, state: &AgentState) -> String {
    let fields = match parse_json_fields(body) { Some(fields) => fields, None => return http_response("400 Bad Request", "application/json", r#"{"error":"invalid_peer_config"}"#) };
    let role = fields.get("role").map(String::as_str).unwrap_or("");
    let result: Result<(String, Option<String>, String), ()> = match role {
        "host" => HostInvitation::new(
            fields.get("node_id").map(String::as_str).unwrap_or(""),
            fields.get("onion_endpoint").map(String::as_str).unwrap_or(""),
            fields.get("invitation_secret").map(String::as_str).unwrap_or(""),
        ).map(|invitation| (invitation.host_node_id().to_string(), None, invitation.public_endpoint().to_string())).map_err(|_| ()),
        "cliente" => {
            let invitation = HostInvitation::new(
                fields.get("host_node_id").map(String::as_str).unwrap_or(""),
                fields.get("onion_endpoint").map(String::as_str).unwrap_or(""),
                fields.get("invitation_secret").map(String::as_str).unwrap_or(""),
            ).map_err(|_| ());
            match invitation {
                Ok(invitation) => ClientConfig::from_invitation(&invitation, fields.get("node_id").map(String::as_str).unwrap_or(""))
                    .map(|config| (fields.get("node_id").cloned().unwrap_or_default(), Some(config.host_node_id().to_string()), config.public_endpoint().to_string())).map_err(|_| ()),
                Err(error) => Err(error),
            }
        }
        _ => Err(()),
    };
    let Ok((node_id, host_node_id, endpoint)) = result else { return http_response("400 Bad Request", "application/json", r#"{"error":"invalid_peer_config"}"#) };
    let Some(store) = &state.peer_store else { return http_response("503 Service Unavailable", "application/json", r#"{"error":"peer_store_unavailable"}"#) };
    let virtual_ip = fields.get("virtual_ip").cloned().filter(|v| !v.trim().is_empty());
    let record = PeerRecord { role: role.to_string(), node_id: node_id.clone(), host_node_id: host_node_id.clone(), endpoint: endpoint.clone(), invitation_secret: fields.get("invitation_secret").cloned().unwrap_or_default(), virtual_ip: virtual_ip.clone(), approved: false, revoked: false };
    if lock_recover(store).configure(record).is_err() { return http_response("500 Internal Server Error", "application/json", r#"{"error":"peer_store_write_failed"}"#); }
    let mut peer = lock_recover(&state.peer);
    peer.configured = true; peer.node_id = Some(node_id); peer.host_node_id = host_node_id; peer.endpoint = Some(endpoint); peer.virtual_ip = virtual_ip; peer.transport = "unavailable"; peer.approved = false; peer.revoked = false;
    drop(peer);
    peer_status(state)
}

fn set_peer_approval(approved: bool, state: &AgentState) -> String {
    let Some(store) = &state.peer_store else { return http_response("503 Service Unavailable", "application/json", r#"{"error":"peer_store_unavailable"}"#) };
    if lock_recover(store).set_approval(approved).is_err() { return http_response("404 Not Found", "application/json", r#"{"error":"peer_not_configured"}"#); }
    let mut peer = lock_recover(&state.peer); peer.approved = approved; peer.revoked = !approved; drop(peer);
    state.peer_transport_enabled.store(approved, Ordering::Release);
    peer_status(state)
}

fn parse_json_fields(body: &str) -> Option<std::collections::HashMap<String, String>> {
    let mut output = std::collections::HashMap::new();
    let body = body.trim().strip_prefix('{')?.strip_suffix('}')?.trim();
    if body.is_empty() { return Some(output); }
    for item in body.split(',') {
        let (key, value) = item.split_once(':')?;
        let key = key.trim().strip_prefix('"')?.strip_suffix('"')?;
        let value = value.trim();
        let value = if let Some(value) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) { value } else if matches!(value, "true" | "false") { value } else { return None };
        if key.is_empty() || value.bytes().any(|byte| byte < 0x20 || byte == b'\\') { return None; }
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
        return http_response("400 Bad Request", "text/plain; charset=utf-8", "mode must be host or cliente")
    };
    *lock_recover(&state.mode) = mode.to_string();
    if contract { service_status(state) } else {
        http_response("200 OK", "application/json", &format!(r#"{{"mode":"{mode}"}}"#))
    }
}

fn parse_mode(body: &str, contract: bool) -> Option<&'static str> {
    let body = body.trim().strip_prefix('{')?.strip_suffix('}')?.trim();
    let body = body.strip_prefix('"')?;
    let key_end = body.find('"')?;
    if &body[..key_end] != "mode" { return None; }
    let rest = body[key_end + 1..].trim_start().strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let value_end = rest.find('"')?;
    let value = &rest[..value_end];
    // Valid modes contain no quotes, backslashes, or controls, so JSON interpolation stays escaped-safe.
    if value.bytes().any(|byte| byte == b'\\' || byte < 0x20) { return None; }
    if !rest[value_end + 1..].trim().is_empty() { return None; }
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
    let origins: Vec<&str> = headers.iter().filter_map(|(name, value)| {
        name.eq_ignore_ascii_case("Origin").then_some(value.trim())
    }).collect();
    if !origins.is_empty() {
        return origins.len() == 1 && origin_matches_host(origins[0], host);
    }
    let referers: Vec<&str> = headers.iter().filter_map(|(name, value)| {
        name.eq_ignore_ascii_case("Referer").then_some(value.trim())
    }).collect();
    referers.len() == 1 && origin_matches_host(referers[0], host)
}

fn origin_matches_host(value: &str, host: &str) -> bool {
    let Some(scheme_end) = value.find("://") else { return false; };
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
    use localscale_control_plane::{google_oidc::{PkceTransaction, TokenResponse, ValidatedIdentity}, AuthError, AuthProvider, AuthService};
    use std::time::Duration;

    #[derive(Default)]
    struct DeterministicProvider;
    impl AuthProvider for DeterministicProvider {
        fn authorization_url(&self, tx: &PkceTransaction) -> Result<String, AuthError> {
            Ok(format!("https://accounts.google.com/auth?state={}", tx.state()))
        }
        fn exchange_code(&mut self, _: &PkceTransaction, _: &str) -> Result<TokenResponse, AuthError> {
            Ok(TokenResponse { access_token: "access-secret".into(), id_token: "id-secret".into(), token_type: "Bearer".into() })
        }
        fn validate_id_token(&mut self, _: &str, _: &str, _: i64) -> Result<ValidatedIdentity, AuthError> {
            Ok(ValidatedIdentity { issuer: "https://accounts.google.com".into(), subject: "subject".into() })
        }
        fn transaction_ttl(&self) -> Duration { Duration::from_secs(60) }
    }

    fn auth_service() -> AuthService<DeterministicProvider> {
        AuthService::new(DeterministicProvider, Duration::from_secs(60), "http://127.0.0.1:8765/oauth/google/callback")
    }

    #[test]
    fn auth_start_redirects_through_root_http_adapter() {
        let mut auth = auth_service();
        let response = super::response_for_request_with_auth(
            "GET /oauth/google/start HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", &mut auth);
        assert!(response.starts_with("HTTP/1.1 302 Found"), "{response}");
        assert!(response.contains("Location: https://accounts.google.com/auth?state="));
    }

    #[test]
    fn auth_callback_session_logout_use_actual_http_translation() {
        let mut auth = auth_service();
        let start = super::response_for_request_with_auth(
            "GET /oauth/google/start HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n", &mut auth);
        let location = start.lines().find(|line| line.starts_with("Location: ")).unwrap();
        let state = location.split("state=").nth(1).unwrap();
        let callback = super::response_for_request_with_auth(
            &format!("GET /oauth/google/callback?code=provider-code&state={state} HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n"), &mut auth);
        assert!(callback.starts_with("HTTP/1.1 303 See Other"), "{callback}");
        let cookie = callback.lines().find(|line| line.starts_with("Set-Cookie: ")).unwrap().strip_prefix("Set-Cookie: ").unwrap().split(';').next().unwrap();
        assert!(callback.contains("Location: /\r\n"));
        assert!(callback.contains("HttpOnly") && callback.contains("Secure") && callback.contains("SameSite=Strict"));
        let replay = super::response_for_request_with_auth(&format!("GET /oauth/google/callback?code=provider-code&state={state} HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n"), &mut auth);
        assert!(replay.starts_with("HTTP/1.1 400 Bad Request"));
        let session = super::response_for_request_with_auth(&format!("GET /auth/session HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\nCookie: {cookie}\r\n\r\n"), &mut auth);
        assert!(session.starts_with("HTTP/1.1 200 OK"));
        let missing_csrf = super::response_for_request_with_auth(&format!("POST /auth/logout HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\nCookie: {cookie}\r\n\r\n"), &mut auth);
        assert!(missing_csrf.starts_with("HTTP/1.1 403 Forbidden"));
        let sid = cookie.strip_prefix("localscale_session=").unwrap();
        let logout = super::response_for_request_with_auth(&format!("POST /auth/logout HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\nCookie: {cookie}\r\nX-CSRF-Token: {sid}\r\n\r\n"), &mut auth);
        assert!(logout.starts_with("HTTP/1.1 204 No Content"));
        assert!(!callback.contains("provider-code") && !callback.contains("access-secret") && !callback.contains("id-secret"));
    }

    #[test]
    fn handoff_exchange_is_reachable_through_root_http_adapter() {
        let mut auth = auth_service();
        let app_callback = "http://127.0.0.1:43123/oauth/callback";
        let flutter_state = "flutter-state-root";
        let start = super::response_for_request_with_auth(&format!("GET /oauth/google/start?app_callback={app_callback}&state={flutter_state} HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n"), &mut auth);
        let server_state = start.lines().find(|line| line.starts_with("Location: ")).unwrap().split("state=").nth(1).unwrap();
        assert_ne!(server_state, flutter_state);
        let callback = super::response_for_request_with_auth(&format!("GET /oauth/google/callback?code=provider-code&state={server_state} HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n"), &mut auth);
        let location = callback.lines().find(|line| line.starts_with("Location: ")).unwrap().strip_prefix("Location: ").unwrap();
        assert!(location.starts_with(app_callback));
        let query = location.split('?').nth(1).unwrap();
        let params: std::collections::HashMap<_, _> = query.split('&').filter_map(|pair| pair.split_once('=')).collect();
        let handoff = params.get("handoff").unwrap();
        let exchange = format!("GET /auth/session/bridge?handoff={handoff}&callback={app_callback}&state={flutter_state} HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n");
        let response = super::response_for_request_with_auth(&exchange, &mut auth);
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(!response.contains("access-secret") && !response.contains("id-secret"));
    }

    #[test]
    fn auth_start_is_exposed_by_the_loopback_tcp_server() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(|| super::serve_with_auth(listener, Box::new(auth_service())).unwrap());
        let mut stream = std::net::TcpStream::connect(address).unwrap();
        stream.write_all(b"GET /oauth/google/start HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 302 Found"), "{response}");
    }

    #[test]
    fn auth_adapter_rejects_non_loopback_and_malformed_queries() {
        let mut auth = auth_service();
        assert!(super::response_for_request_with_auth("GET /oauth/google/start HTTP/1.1\r\nHost: example.test\r\n\r\n", &mut auth).starts_with("HTTP/1.1 403 Forbidden"));
        assert!(super::response_for_request_with_auth("GET /oauth/google/callback?state=%ZZ&code=x HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n", &mut auth).starts_with("HTTP/1.1 400 Bad Request"));
    }

    #[test]
    fn auth_adapter_fails_closed_when_unconfigured() {
        for request in [
            "GET /oauth/google/start HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n",
            "GET /oauth/google/callback?code=x&state=y HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n",
            "GET /auth/session HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n",
            "GET /auth/session/bridge?handoff=x&callback=http%3A%2F%2F127.0.0.1%3A1234%2Foauth%2Fcallback&state=y HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n",
            "POST /auth/logout HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n",
        ] {
            assert!(super::response_for_request(request).starts_with("HTTP/1.1 503 Service Unavailable"));
        }
    }


    #[test]
    fn version_endpoint_returns_local_scale_version() {
        let response = super::response_for_request("GET /version HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"version\":\"0.1.0\""));
    }

    #[test]
    fn mode_endpoint_rejects_non_loopback_host() {
        let response = super::response_for_request("GET /mode HTTP/1.1\r\nHost: example.test\r\n\r\n");
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
    }

    #[test]
    fn state_changing_routes_require_a_same_origin_proof() {
        let rejected = super::response_for_request(
            "POST /api/v1/service/start HTTP/1.1\r\nHost: 127.0.0.1:8765\r\n\r\n");
        assert!(rejected.starts_with("HTTP/1.1 403 Forbidden"), "{rejected}");

        let cross_origin = super::response_for_request(
            "POST /api/v1/service/start HTTP/1.1\r\nHost: 127.0.0.1:8765\r\nOrigin: http://127.0.0.1:9999\r\n\r\n");
        assert!(cross_origin.starts_with("HTTP/1.1 403 Forbidden"), "{cross_origin}");

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
    fn control_page_status_contract_defaults_to_cliente_stopped() {
        let response = super::response_for_request("GET /api/v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains(r#""mode":"cliente""#));
        assert!(response.contains(r#""state":"stopped""#));
        assert!(response.contains(r#""onion_endpoint":null"#));
    }

    #[test]
    fn control_page_routes_return_service_status_and_cliente_is_accepted() {
        let state = super::AgentState::default();
        let mode = super::response_for_request_with_state(
            "POST /api/v1/mode HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n{\"mode\":\"host\"}", &state);
        assert!(mode.starts_with("HTTP/1.1 200 OK"), "{mode}");
        assert!(mode.contains(r#""mode":"host""#));
        assert!(mode.contains(r#""state":"stopped""#));

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
        assert!(host.contains("\"transport\":\"unavailable\""));
        assert!(!host.contains(secret));
        let status = super::response_for_request_with_state("GET /api/v1/peer/status HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n", &state);
        assert!(status.contains(hostname));
        assert!(!status.contains(secret));
        let cliente = super::response_for_request_with_state(&format!(
            "POST /api/v1/peer/config HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n{{\"role\":\"cliente\",\"node_id\":\"client-01\",\"host_node_id\":\"host-01\",\"onion_endpoint\":\"{hostname}\",\"invitation_secret\":\"{secret}\"}}"), &state);
        assert!(cliente.starts_with("HTTP/1.1 200 OK"), "{cliente}");
    }

    #[test]
    fn peer_config_rejects_invalid_onion_and_non_loopback_admin_requests() {
        let invalid = super::response_for_request("POST /api/v1/peer/config HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n{\"role\":\"cliente\",\"node_id\":\"client-01\",\"host_node_id\":\"host-01\",\"onion_endpoint\":\"/var/lib/tor/hostname\",\"invitation_secret\":\"secret-token-123456\"}");
        assert!(invalid.starts_with("HTTP/1.1 400 Bad Request"), "{invalid}");
        let remote = super::response_for_request("GET /api/v1/peer/status HTTP/1.1\r\nHost: example.test\r\n\r\n");
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
            assert!(response.starts_with("HTTP/1.1 403 Forbidden"), "{host}: {response}");
        }
    }

    #[test]
    fn loopback_host_matching_is_case_insensitive_and_supports_ports() {
        for host in ["LOCALHOST:8765", "127.0.0.1:9", "[::1]:8765"] {
            let response = super::response_for_request(&format!(
                "GET /api/v1/status HTTP/1.1\r\nHost: {host}\r\n\r\n"));
            assert!(response.starts_with("HTTP/1.1 200 OK"), "{host}: {response}");
        }
    }

    #[test]
    fn malformed_mode_json_is_rejected() {
        let response = super::response_for_request(
            "POST /api/v1/mode HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\nnot-json{\"mode\":\"host\"}");
        assert!(response.starts_with("HTTP/1.1 400 Bad Request"), "{response}");

        let response = super::response_for_request(
            "POST /api/v1/mode HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n{\"mode\":\"client\"}");
        assert!(response.starts_with("HTTP/1.1 400 Bad Request"), "{response}");
    }

    #[test]
    fn peer_store_persists_approval_and_revocation_without_status_secret() {
        let path = std::env::temp_dir().join(format!("localscale-peer-test-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut store = super::PeerStore::open(&path).unwrap();
        store.configure(super::PeerRecord { role: "cliente".into(), node_id: "client-01".into(), host_node_id: Some("host-01".into()), endpoint: "abc.onion".into(), invitation_secret: "secret-value".into(), virtual_ip: None, approved: false, revoked: false }).unwrap();
        assert!(!super::PeerStore::open(&path).unwrap().record().unwrap().approved);
        store.set_approval(true).unwrap();
        let reloaded = super::PeerStore::open(&path).unwrap();
        assert!(reloaded.record().unwrap().approved);
        store.set_approval(false).unwrap();
        let revoked = super::PeerStore::open(&path).unwrap();
        assert!(revoked.record().unwrap().revoked);
        let state = super::AgentState { peer_store: Some(std::sync::Arc::new(std::sync::Mutex::new(revoked))), ..super::AgentState::default() };
        let status = super::response_for_request_with_state("GET /api/v1/peer/status HTTP/1.1\r\nHost: localhost\r\n\r\n", &state);
        assert!(!status.contains("secret-value"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn peer_store_rejects_malformed_startup_state() {
        let path = std::env::temp_dir().join(format!("localscale-peer-bad-{}.json", std::process::id()));
        std::fs::write(&path, "not-json").unwrap();
        assert!(super::PeerStore::open(&path).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn peer_store_rejects_existing_symlink() {
        use std::os::unix::fs::symlink;
        let path = std::env::temp_dir().join(format!("localscale-peer-symlink-{}.json", std::process::id()));
        let target = std::env::temp_dir().join(format!("localscale-peer-target-{}.json", std::process::id()));
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
        let path = std::env::temp_dir().join(format!("localscale-peer-readable-{}.json", std::process::id()));
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
        let path = std::env::temp_dir().join(format!("localscale-peer-private-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut store = super::PeerStore::open(&path).unwrap();
        store.configure(super::PeerRecord { role: "cliente".into(), node_id: "client-01".into(), host_node_id: None, endpoint: "abc.onion".into(), invitation_secret: "secret-value".into(), virtual_ip: None, approved: false, revoked: false }).unwrap();
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.uid(), super::effective_uid());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn peer_debug_output_redacts_invitation_secret() {
        let record = super::PeerRecord { role: "cliente".into(), node_id: "client-01".into(), host_node_id: None, endpoint: "abc.onion".into(), invitation_secret: "secret-value".into(), virtual_ip: None, approved: false, revoked: false };
        let store = super::PeerStore { path: std::path::PathBuf::from("peer.json"), record: Some(record.clone()) };
        assert!(!format!("{record:?}").contains("secret-value"));
        assert!(!format!("{store:?}").contains("secret-value"));
    }

    #[test]
    fn health_endpoint_returns_ok_json() {
        assert_eq!(health_response(), r#"{"status":"ok","service":"localscale"}"#);
    }

    #[test]
    fn mode_parser_accepts_json_whitespace_but_rejects_extra_fields_and_escapes() {
        for body in [" { \"mode\" : \"host\" } ", "{\n\t\"mode\":\"cliente\"\n}"] {
            let response = super::response_for_request(&format!(
                "POST /api/v1/mode HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n{body}"));
            assert!(response.starts_with("HTTP/1.1 200 OK"), "{body}: {response}");
        }
        for body in ["{\"mode\":\"host\",\"other\":true}", "{\"mode\":\"ho\\u0073t\"}"] {
            let response = super::response_for_request(&format!(
                "POST /api/v1/mode HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n{body}"));
            assert!(response.starts_with("HTTP/1.1 400 Bad Request"), "{body}: {response}");
        }
    }

    #[test]
    fn write_budget_is_remaining_after_reading() {
        let started = std::time::Instant::now();
        let total = std::time::Duration::from_secs(5);
        let after_reading = started + std::time::Duration::from_secs(3);
        assert_eq!(super::remaining_budget(started, total, after_reading), Some(std::time::Duration::from_secs(2)));
        assert_eq!(super::remaining_budget(started, total, started + total), None);
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
            "GET /mode HTTP/1.1\r\nHost: localhost:8765\r\nOrigin: http://localhost:8765\r\n\r\n", &state);
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
        fast.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
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
        assert!(response.is_empty(), "slow client unexpectedly got response: {response:?}");
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
        excess.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut response = String::new();
        excess.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 503 Service Unavailable"), "{response}");
    }

    #[test]
    fn revoking_peer_disables_running_transport_gate() {
        let state = super::AgentState::default();
        super::lock_recover(state.peer_store.as_ref().unwrap()).configure(super::PeerRecord {
            role: "host".into(), node_id: "host-01".into(), host_node_id: None,
            endpoint: format!("{}.onion", "a".repeat(56)), invitation_secret: "secret".into(), virtual_ip: None, approved: true, revoked: false,
        }).unwrap();
        assert!(state.peer_transport_enabled.load(std::sync::atomic::Ordering::Acquire));
        let response = super::response_for_request_with_state(
            "POST /api/v1/peer/revoke HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nContent-Length: 0\r\n\r\n", &state);
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(!state.peer_transport_enabled.load(std::sync::atomic::Ordering::Acquire));
    }

    #[test]
    fn set_virtual_ip_persists_and_updates_devices() {
        let path = std::env::temp_dir().join(format!("localscale-peer-vip-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut store = super::PeerStore::open(&path).unwrap();
        store.configure(super::PeerRecord {
            role: "host".into(),
            node_id: "host-node".into(),
            host_node_id: None,
            endpoint: "test.onion".into(),
            invitation_secret: "secret".into(),
            virtual_ip: None,
            approved: true,
            revoked: false,
        }).unwrap();
        let state = super::AgentState {
            peer_store: Some(std::sync::Arc::new(std::sync::Mutex::new(store))),
            ..super::AgentState::default()
        };
        // Initial devices check
        let devices = super::response_for_request_with_state(
            "GET /api/v1/devices HTTP/1.1\r\nHost: localhost\r\n\r\n", &state);
        assert!(devices.starts_with("HTTP/1.1 200 OK"), "{devices}");
        assert!(devices.contains("Tor v3 Onion (Strict Isolation)"));

        // Set virtual IP
        let update = super::response_for_request_with_state(
            "POST /api/v1/peer/virtual-ip HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\n\r\n{\"virtual_ip\":\"10.42.0.1\"}", &state);
        assert!(update.starts_with("HTTP/1.1 200 OK"), "{update}");
        assert!(update.contains("\"virtual_ip\":\"10.42.0.1\""));

        // Reload store from disk
        let reloaded = super::PeerStore::open(&path).unwrap();
        assert_eq!(reloaded.record().unwrap().virtual_ip.as_deref(), Some("10.42.0.1"));

        // Devices now contains virtual IP
        let devices_after = super::response_for_request_with_state(
            "GET /api/v1/devices HTTP/1.1\r\nHost: localhost\r\n\r\n", &state);
        assert!(devices_after.contains("\"virtual_ip\":\"10.42.0.1\""));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn configuration_page_has_product_title() {
        assert!(configuration_html().contains("<title>LocalScale</title>"));
    }
}
