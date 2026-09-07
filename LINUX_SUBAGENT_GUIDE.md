# Guia de Operação e Subagentes no Linux (Debian / KDE Plasma)

Este guia descreve como controlar a máquina Linux remotamente, quais interfaces de terminal funcionam, como interagir com a interface gráfica Wayland/KDE, e como orquestrar subagentes locais ou remotos via SSH.

---

## 1. Conexão SSH e Acesso ao Linux

A máquina Linux está acessível na rede local sem necessidade de senha (autenticação por chave SSH autorizada):

- **Host**: `192.168.15.102`
- **Usuário**: `jemerson`
- **Comando SSH Padrão**:
  ```bash
  ssh jemerson@192.168.15.102 "<comando>"
  ```
- **Execução Interativa (com TTY)**:
  ```bash
  ssh -t jemerson@192.168.15.102 "bash -l"
  ```

---

## 2. Interfaces de Terminal Funcionais

### A. Terminal Remoto SSH (Recomendado para Automação / Subagentes)
Qualquer comando bash pode ser disparado do Mac para o Linux. Para carregar o PATH completo com Rust e Flutter:
```bash
ssh jemerson@192.168.15.102 "source ~/.profile; source ~/.bashrc; which cargo flutter"
```
- **Cargo / Rust**: `/home/jemerson/.cargo/bin/cargo`
- **Flutter SDK**: `/home/jemerson/development/flutter/bin/flutter`

### B. Konsole do KDE (Terminal Gráfico Local)
O KDE Plasma roda o `konsole`. Se precisar disparar um terminal gráfico visível na tela do Linux:
```bash
ssh jemerson@192.168.15.102 "export WAYLAND_DISPLAY=wayland-0 DISPLAY=:1 XDG_RUNTIME_DIR=/run/user/1000; konsole &"
```

### C. Antigravity CLI (`agy`) no Linux
Se o binário ou pacote do Antigravity CLI estiver disponível:
```bash
ssh jemerson@192.168.15.102 "export PATH=\$HOME/.local/bin:\$PATH; which agy"
```
Você pode invocar tarefas remotas do Antigravity rodando subprocessos em background via SSH.

---

## 3. Ambiente Gráfico KDE Wayland (Screenshots e Controle GUI)

Para qualquer comando gráfico ou ferramenta de inspeção rodar via SSH, é **obrigatório** exportar as variáveis da sessão Wayland do usuário `jemerson`:

```bash
export WAYLAND_DISPLAY=wayland-0
export DISPLAY=:1
export XDG_RUNTIME_DIR=/run/user/1000
export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/1000/bus"
```

### Captura de Screenshot da Tela do Linux
Utilize a ferramenta nativa `spectacle` (sem exibir janela de confirmação):
```bash
ssh jemerson@192.168.15.102 "export WAYLAND_DISPLAY=wayland-0 DISPLAY=:1 XDG_RUNTIME_DIR=/run/user/1000; spectacle -b -n -o /tmp/screen_current.png"
```
Para copiar o screenshot para o Mac e inspecionar:
```bash
scp jemerson@192.168.15.102:/tmp/screen_current.png ./linux_screen.png
```

### Controle do App Flutter Desktop no Linux
- **Iniciar o app no display gráfico**:
  ```bash
  ssh jemerson@192.168.15.102 "export WAYLAND_DISPLAY=wayland-0 DISPLAY=:1 XDG_RUNTIME_DIR=/run/user/1000; nohup ~/.local/opt/localscale-desktop/localscale_desktop > /tmp/desktop.log 2>&1 &"
  ```
- **Encerrar o app**:
  ```bash
  ssh jemerson@192.168.15.102 "pkill -f localscale_desktop"
  ```
- **Verificar logs da interface desktop**:
  ```bash
  ssh jemerson@192.168.15.102 "cat /tmp/desktop.log"
  ```

---

## 4. Controle do Daemon do Agente (`systemd --user`)

O daemon `localscaled` no Linux é gerenciado por serviço de usuário systemd:

- **Verificar status**:
  ```bash
  ssh jemerson@192.168.15.102 "systemctl --user status localscale-agent --no-pager"
  ```
- **Reiniciar o serviço**:
  ```bash
  ssh jemerson@192.168.15.102 "systemctl --user restart localscale-agent"
  ```
- **Ver logs em tempo real**:
  ```bash
  ssh jemerson@192.168.15.102 "journalctl --user -u localscale-agent -n 40 --no-pager"
  ```
- **Definição do serviço**:
  Arquivo: `~/.config/systemd/user/localscale-agent.service`
  Executa: `/usr/bin/python3 /home/jemerson/.local/opt/localscale-agent/start-agent-linux.py`

---

## 5. Sincronização Rápida de Código (Mac → Linux)

Para sincronizar o código modificado no Mac diretamente para a pasta do Linux sem precisar commitar:
```bash
rsync -avz --delete \
  --exclude 'target' \
  --exclude 'build' \
  --exclude '.dart_tool' \
  --exclude '.git' \
  /Users/jemerson.barros/LocalScale/ \
  jemerson@192.168.15.102:~/localscale/
```

Ou via Git (branch `localscale`):
```bash
# No Mac:
git commit -am "feat: update onion network and virtual ip fixes"
git push origin localscale

# No Linux:
ssh jemerson@192.168.15.102 "cd ~/localscale && git pull origin localscale"
```

---

## 6. Como Orquestrar Subagentes em Paralelo (bootstrap apenas)

Os subagentes podem preparar builds, observar logs e capturar evidências, mas
não devem substituir as ações do usuário no app. O teste de aceite de
pareamento ocorre nos dois aplicativos, sem `curl`, POST manual, `nohup` ou
alteração direta de `peer-record.json`.

Ao usar múltiplos subagentes no Antigravity 2.0:
- **Subagente 1 (Linux Host)**: conecta via SSH para compilar/instalar o agente e o app, reiniciar o supervisor e deixar o Linux pronto para abrir a UI.
- **Subagente 2 (macOS Cliente)**: executa os builds locais e deixa o app pronto para abrir a UI do Cliente.
- **Subagente 3 (Verificador)**: observa `/diagnostics`, logs redigidos e screenshots depois do teste. Não transforma `approved` em `connected` e não injeta configuração por API.

---

## 7. Pareamento e automação pela interface (Linux Host → macOS Cliente)

O cenário vigente usa o Linux como `Host` (`10.42.0.1`) e o macOS como
`Cliente` (`10.42.0.2`). Com os dois apps abertos:

1. No app Linux, selecione `Host`, espere o endpoint Onion atual e acione
   **Gerar convite**.
2. Use **Copiar convite** ou **(QR é roadmap)** no app Linux; não copie estado do
   disco e não use segredo predefinido.
3. No app macOS, selecione `Cliente`, use **Colar convite** ou **(QR é roadmap)**,
   confira o fingerprint e confirme.
4. Aguarde na UI `configured → dialing → handshaking → connected`; então execute
   o ping/sync oferecido pelo app e confirme o evento nos dois lados.
5. Tente importar o mesmo convite uma segunda vez. A UI deve informar replay,
   sem aprovar o peer. Reinicie os apps e confirme que a sessão persistida usa
   apenas chaves locais protegidas.

Para um teste automatizado reproduzível, selecione o fixture de desenvolvimento
pela própria UI. O app precisa gerar um convite novo por execução, com nonce,
expiração e token aleatórios. Um fixture não pode conter
um `invitation_secret` legado, segredo em texto puro, token
OAuth ou chave privada. Fixtures são proibidos no perfil de produção.

### Validação correta

- `loopback=true` e `external_network=false` comprovam isolamento da API local.
- `peer_configured=true` e `approved=true` comprovam somente configuração e política.
- Só mostrar `connected` quando `peer_transport=connected`, `peer_connected=true`,
  handshake/role estiverem validados e houver troca de dados recente.
- Registre evento de sync/ping, horário do handshake e erro redigido nos dois
  apps. `/api/v1/devices`, screenshot ou um `200` de `/health`, isoladamente,
  não comprovam conexão.

Chamadas de API são úteis apenas para diagnóstico de desenvolvimento e devem
usar a mesma origem loopback. Elas não fazem parte deste aceite e nunca devem
receber convites, tokens ou segredos em argumentos, arquivos versionados ou
logs.

### Evolução sem backend próprio

Usar a mesma conta Google como namespace e o Drive `appDataFolder` como caixa
postal de manifestos de descoberta gerados. O escopo
`https://www.googleapis.com/auth/drive.appdata` deve ser solicitado apenas por
consentimento incremental e opt-in; o login base não precisa dele. OAuth
sozinho autentica; ele não sincroniza computadores. O manifesto serve apenas
para descoberta/troca de chaves e o tráfego real continua pelo Tor v3 Onion.

Nunca publicar no Drive tokens OAuth, refresh tokens, chaves privadas ou
`invitation_secret`. O manifesto deve ter TTL, assinatura, nonce/replay
protection e revogação. O Cliente confirma o primeiro pareamento na UI.
