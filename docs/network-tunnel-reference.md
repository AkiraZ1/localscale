# Hermes Private Tunnel — Rede Privada Self-Hosted

**Autor:** Hermes Ponte Celular
**Status:** Implementação
**Motivação:** Substituir o acesso via Tor/`.onion` (não alcançável pelo Hermes
Desktop por falta de proxy SOCKS e falha `ENOTFOUND`) por uma rede privada
self-hosted, controlada inteiramente via SSH no Linux, que atravessa redes
corporativas restritas sem depender de Tailscale nem de terceiros.

---

## 1. Objetivo

Estabelecer um enlace privado ponto-a-ponto **Mac ↔ Linux(100.65.65.60)** que
apresente ao Hermes Desktop o Bridge remoto (`127.0.0.1:45125`) como um
endereço acessível nativamente (sem proxy, sem DNS `.onion`), com
autenticação por chave e configuração 100% via SSH.

## 2. Requisitos

| # | Requisito | Critério de aceite |
|---|-----------|--------------------|
| R1 | Rede privada própria (sem terceiros) | Nenhum serviço externo no caminho de dados |
| R2 | Configuração remota via SSH | Todos os passos executáveis por `ssh jemerson@100.65.65.60` |
| R3 | Funciona em redes restritas | Porta 443/TCP (ou 51820/UDP) de saída disponível |
| R4 | Transparente para o app | Hermes conecta em `http://127.0.0.1:45125` sem proxy |
| R5 | Persistente | Reconexão automática após queda |

## 3. Comparativo de soluções candidatas

| Solução | Rede privada | Atravessa firewall restrito | Config via SSH | Dependência 3º | Veredito |
|---------|-------------|----------------------------|----------------|----------------|----------|
| Tor `.onion` | Sim | Sim (pouco comum) | Não | Tor | **Bloqueada** (ENOTFOUND no app) |
| Tailscale | Sim | Não | Parcial | Sim | **Bloqueada** pela rede |
| WireGuard | Sim | Sim (UDP 51820) / TLS 443 | Sim | Não | **Escolhida** |
| Túnel SSH `-R` | Sim | Parcial (porta 22) | Sim | Não | Fallback |

## 4. Arquitetura escolhida — WireGuard self-hosted

```
            Internet / WAN restrita
                              │
┌────────────┐       ┌────────────────────┐
│ Hermes App │       │ Linux 100.65.65.60  │
│ (Mac)      │◄──────│ WireGuard Server    │
│ wg0 cli    │  tunel│ 10.0.0.1/24         │
│ 10.0.0.2   │  51820│ Bridge 127.0.0.1:45125│
└────────────┘       └────────────────────┘
     │  http://10.0.0.1:45125
```

- **Linux**: servidor WireGuard `10.0.0.1/24`, escuta `51820/UDP`,
  publica `10.0.0.0/24`. Bridge continua em `127.0.0.1:45125`.
- **Mac**: cliente WireGuard `10.0.0.2`, rota só para `10.0.0.0/24`.
- **Hermes App** aponta para `http://10.0.0.1:45125` (token interno do bridge).

### Segurança
- Chaves `wg` geradas no servidor; peer Mac com `AllowedIPs = 10.0.0.2/32`.
- `PersistentKeepalive = 25` para atravessar NAT/firewall.
- Bridge mantém autenticação de aplicação (Bearer token) em cima do túnel.

### Fallback (porta 443 sem UDP)
Se `51820/UDP` for bloqueada, WireGuard sobre TLS via `udp2raw` → `443/TCP`,
ou túnel SSH `-R 45125:127.0.0.1:45125` como medida imediata.

---

## 5. Plano de execução (etapas)

1. **E1 — Inventário**: `uname`, Linux distro/version, `ip route`, acesso SUDO,
   porta 51820 livre, Bridge ativo em `127.0.0.1:45125`, versão `wg`.
2. **E2 — Servidor**: instalar `wireguard-tools`, gerar `privatekey`,
   criar `/etc/wireguard/wg0.conf`, habilitar `wg-quick@wg0`, `ufw allow 51820`.
3. **E3 — Peer Mac**: gerar keypair no Mac, adicionar `PublicKey` ao peer do
   servidor, instalar WireGuard client (App Store ou `brew install wireguard-tools`).
4. **E4 — Validação**: `ping 10.0.0.1`; `curl http://10.0.0.1:45125/api/v1/health`.
5. **E5 — Hermes**: configurar gateway remoto com `http://10.0.0.1:45125`
   + token; confirmar `200` e luz verde.
6. **E6 — Persistência**: `wg-quick@wg0` no Linux; no Mac, perfil WireGuard
   auto-connect + script/LaunchAgent.

## 6. Comandos-chave

```bash
# Servidor Linux (via ssh jemerson@100.65.65.60)
sudo apt install -y wireguard-tools
wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey
chmod 600 /etc/wireguard/privatekey
sysctl -w net.ipv4.ip_forward=1   # persistir em /etc/sysctl.conf

# wg0.conf
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = <private do servidor>
[Peer]
PublicKey = <public do Mac>
AllowedIPs = 10.0.0.2/32
PersistentKeepalive = 25

sudo systemctl enable --now wg-quick@wg0

# Peer Mac (via terminal local)
wg genkey | tee ~/.wg/mac.private | wg pubkey
# colocar PublicKey do Mac no [Peer] do servidor

# Validação
curl http://10.0.0.1:45125/api/v1/health
```

## 7. Riscos e mitigações

| Risco | Mitigação |
|-------|-----------|
| UDP 51820 bloqueado | Fallback `udp2raw`→443/TCP ou túnel SSH |
| IP público traseiro dinâmico | Fermata/Tailscale excluído; usar IP fixo ou DDNS |
| SUDO remoto pendente | Usuário digita senha em sessão SSH interativa |
| Bridge sem auth | Manter Bearer token no app; não expor além do tunnel |

## 8. Saída esperada

- Túnel `10.0.0.1 ↔ 10.0.0.2` estável.
- Hermes conecta em `http://10.0.0.1:45125` com `200` e chat funcional.
- Sem erro `ENOTFOUND`; sem proxy; sem Tor no Mac.

---

## 9. Dashboard + API na porta 80 (sem porta na URL)

Arquivos prontos em `deploy/hermes-bridge/` (gerados neste repo, a copiar pro
servidor via `scp`):

- `bridge.py` → `/var/lib/hermes-bridge/bridge.py` (entrypoint, importa o
  FastAPI real de `hermes_bridge.main` e monta o dashboard)
- `dashboard.py` → `/var/lib/hermes-bridge/dashboard.py` (rotas `/`,
  `/dashboard/api/status|start|stop|restart|logs`)
- `hermes-bridge.service` → `/etc/systemd/system/hermes-bridge.service`
- `nginx-hermes-bridge.conf` → `/etc/nginx/sites-available/hermes-bridge`
- `sudoers-hermes-bridge` → `/etc/sudoers.d/hermes-bridge`

**Decisão de arquitetura**: nginx assume a porta 80 (bind em `10.0.0.1:80`,
só na interface WireGuard) e faz proxy pra `127.0.0.1:45125`, onde o bridge
continua rodando sem privilégio elevado. Evita dar `CAP_NET_BIND_SERVICE`
ou rodar Python como root só pra abrir porta 80 — mais simples e mais
seguro que authbind/setcap no processo da app.

### Passo a passo (via `ssh jemerson@100.65.65.60`)

1. **Criar usuário e diretório de serviço**
   ```bash
   sudo useradd -r -m -d /var/lib/hermes-bridge -s /usr/sbin/nologin hermes-bridge
   sudo mkdir -p /var/lib/hermes-bridge
   sudo chown hermes-bridge:hermes-bridge /var/lib/hermes-bridge
   ```

2. **Copiar os arquivos do Mac pro servidor**
   ```bash
   scp deploy/hermes-bridge/bridge.py deploy/hermes-bridge/dashboard.py \
       jemerson@100.65.65.60:/tmp/
   scp deploy/hermes-bridge/hermes-bridge.service jemerson@100.65.65.60:/tmp/
   scp deploy/hermes-bridge/nginx-hermes-bridge.conf jemerson@100.65.65.60:/tmp/
   scp deploy/hermes-bridge/sudoers-hermes-bridge jemerson@100.65.65.60:/tmp/
   ```

3. **Instalar o pacote `hermes_bridge` no servidor** (venv dedicada)
   ```bash
   sudo -u hermes-bridge python3 -m venv /var/lib/hermes-bridge/venv
   sudo -u hermes-bridge /var/lib/hermes-bridge/venv/bin/pip install fastapi uvicorn httpx pyyaml
   # copiar bridge/src/hermes_bridge/ (deste repo) pro servidor e instalar:
   scp -r bridge/src/hermes_bridge jemerson@100.65.65.60:/tmp/hermes_bridge
   sudo mv /tmp/hermes_bridge /var/lib/hermes-bridge/
   sudo chown -R hermes-bridge:hermes-bridge /var/lib/hermes-bridge/hermes_bridge
   ```

4. **Mover bridge.py/dashboard.py pro lugar final**
   ```bash
   sudo mv /tmp/bridge.py /tmp/dashboard.py /var/lib/hermes-bridge/
   sudo chown hermes-bridge:hermes-bridge /var/lib/hermes-bridge/{bridge,dashboard}.py
   ```

5. **Instalar systemd unit + sudoers**
   ```bash
   sudo mv /tmp/hermes-bridge.service /etc/systemd/system/
   sudo visudo -cf /tmp/sudoers-hermes-bridge && \
     sudo install -m 0440 /tmp/sudoers-hermes-bridge /etc/sudoers.d/hermes-bridge
   sudo systemctl daemon-reload
   sudo systemctl enable --now hermes-bridge.service
   sudo systemctl status hermes-bridge.service
   ```

6. **Nginx: instalar, configurar, restringir à interface WireGuard**
   ```bash
   sudo apt install -y nginx
   sudo mv /tmp/nginx-hermes-bridge.conf /etc/nginx/sites-available/hermes-bridge
   sudo ln -s /etc/nginx/sites-available/hermes-bridge /etc/nginx/sites-enabled/
   sudo rm -f /etc/nginx/sites-enabled/default
   sudo nginx -t && sudo systemctl reload nginx
   sudo ufw allow in on wg0 to any port 80 proto tcp
   ```
   Confirme que `wg0` já tem IP `10.0.0.1/24` (seção 4) antes deste passo —
   nginx falha o bind se a interface ainda não existir.

7. **Validar do Mac** (dentro do túnel, `10.0.0.2`)
   ```bash
   curl http://10.0.0.1/api/v1/health
   open http://10.0.0.1/          # dashboard no browser
   ```

8. **Apontar o Hermes** para `http://10.0.0.1/` (sem `:45125`), mesmo
   Bearer token de antes (`~/.hermes/bridge_token` no servidor).

### Uso do painel

- `http://10.0.0.1/` pede o Bearer token uma vez (salvo em `localStorage`
  do navegador) e mostra estado do serviço (`active`/`inactive`/`failed`),
  botões **Start/Stop/Restart** e as últimas 200 linhas de log
  (`journalctl -u hermes-bridge`).
- Start/Stop/Restart chamam `sudo -n systemctl <ação> hermes-bridge.service`
  — só funciona porque o usuário `hermes-bridge` tem a regra NOPASSWD restrita
  do passo 5, limitada a essas três subcomandos exatos.
- Endpoint `GET /dashboard/api/status` é público (sem token) — só
  status/estado, não vaza log nem controla nada; `/dashboard/api/logs` e
  as ações POST exigem o Bearer token do bridge.

### Rollback

```bash
sudo systemctl disable --now hermes-bridge.service
sudo rm /etc/nginx/sites-enabled/hermes-bridge
sudo systemctl reload nginx
```
Bridge volta a ficar acessível só via `127.0.0.1:45125` (SSH `-L`/`-R`) como
antes desta mudança.