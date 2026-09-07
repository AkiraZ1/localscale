# LocalScale — Documento de Handover (Transição para Antigravity 2.0)

Este documento reúne o estado atual da aplicação, decisões de arquitetura, configurações de nós (macOS e Linux), correções efetuadas e o plano de validação. O cenário de teste vigente é **Linux Host → macOS Cliente**. Qualquer hostname Onion abaixo é apenas uma observação de ambiente e deve ser relido pela interface no início de cada execução; hostname antigo nunca é uma credencial.

---

## 1. Visão Geral da Aplicação

**LocalScale** é uma plataforma distribuída de agentes locais com arquitetura **Local-First** e isolamento estrito via rede **Tor v3 Onion (P2P)**.
- **Backend Rust (`localscaled`)**: Daemon de controle local (`crates/` e `src/`), escutando estritamente em loopback (`127.0.0.1`).
  - macOS porta padrão: `18765`
  - Linux porta padrão: `8765`
- **Frontend Flutter Desktop (`localscale_desktop`)**: Aplicativo nativo em `apps/desktop/` para gerenciamento do agente, autenticação OIDC via Google, controle de nós e visualização da malha Onion com IPs virtuais privados.
- **Rede P2P Isolada**: Todo o tráfego inter-máquinas é roteado via serviços ocultos Tor v3 (endereços `.onion` de 56 caracteres). **Nenhuma porta física é aberta na rede local (LAN)**.

---

## 2. Nós da Rede e Endereços Tor Ativos

### Nó 1: Linux (Host de teste atual)
- **Máquina**: Debian/KDE Plasma (`192.168.15.102`)
- **SSH de manutenção**: `ssh jemerson@192.168.15.102` (não faz parte do aceite pela UI)
- **Caminho do Projeto**: `/home/jemerson/localscale` (branch `localscale`)
- **Flutter SDK**: `/mnt/win_check/toolchains/flutter/bin/flutter`
- **Porta do Agente**: `8765` (`http://127.0.0.1:8765`)
- **Endereço Onion Tor v3 Host observado**: `kcbvccrt7wwv3gdrflb4mvduhvnotaiafan4wabclbzdb5om7ayufoyd.onion`
  - *Origem do hostname*: `/home/jemerson/.local/state/hermes-bridge-test/linux/tor/onion/hostname`
  - *Regra*: o app deve reler o hostname publicado no runtime; não reutilize este valor se o serviço tiver sido recriado.
- **IP Virtual P2P (Overlay)**: `10.42.0.1`
- **Instalação do Agente**: `/home/jemerson/.local/opt/localscale-agent/localscaled`
- **Instalação do App Desktop**: `/home/jemerson/.local/opt/localscale-desktop/localscale_desktop`
- **Serviço Systemd de Usuário**: `localscale-agent.service` (somente bootstrap/supervisão)

### Nó 2: macOS (Cliente de teste atual)
- **Máquina**: Apple Silicon (macOS)
- **Caminho do Projeto**: `/Users/jemerson.barros/LocalScale`
- **Flutter SDK**: `/Users/jemerson.barros/develop/flutter/bin/flutter`
- **Porta do Agente**: `18765` (`http://127.0.0.1:18765`)
- **Onion local**: não deve ser publicado no modo Cliente; o Cliente usa somente o endpoint público do Linux Host.
- **IP Virtual P2P (Overlay)**: `10.42.0.2`
- **Instalação do App Desktop**: `/Users/jemerson.barros/Applications/LocalScale.app`

---

## 3. Descobertas Críticas e O Que Foi Corrigido Nesta Sessão

### A. Erro "503 authentication unavailable" no Linux
- **Causa**: O `localscaled` no Linux estava sendo rodado diretamente sem as variáveis de ambiente OAuth (`LOCALSCALE_GOOGLE_CLIENT_ID`, `LOCALSCALE_GOOGLE_CLIENT_SECRET`, `LOCALSCALE_GOOGLE_REDIRECT_URI`, `LOCALSCALE_OIDC_ISSUER`, `LOCALSCALE_OIDC_SCOPES`). Quando qualquer rota de autenticação era chamada, `auth_provider()` retornava `None` e o backend respondia 503.
- **Solução Aplicada**:
  - Criado o serviço systemd de usuário em `/home/jemerson/.config/systemd/user/localscale-agent.service` executando o script `/home/jemerson/.local/opt/localscale-agent/start-agent-linux.py`.
  - Este script lê credenciais de `~/.config/localscale/oidc.json` e `~/.config/localscale/secrets/google-client.json`.
  - Serviço ativado e rodando (`systemctl --user enable --now localscale-agent.service`).
  - Testado via `curl` e autenticação retornou `302 Found` para o Google OAuth com sucesso.

### B. Ausência do Endereço Onion na Interface ("apareceu tudo, menos o onion")
- **Causa 1 (Backend Rust `src/lib.rs`)**: A função `service_status()` retornava `"onion_endpoint":null` hardcoded. E `devices_status()` retornava string vazia `""` se o peer não tivesse configurado um endpoint remoto.
- **Causa 2 (App Flutter `apps/desktop/lib/main.dart`)**: O campo `TextFormField` usava `initialValue: current?.onionEndpoint ?? ''`. Como `initialValue` só é lido na montagem inicial, quando o polling atualizava, a tela permanecia em branco. Além disso, a exibição do dispositivo avaliava `dev.onionEndpoint ?? "aguardando"`; com string vazia `""`, exibia `Onion: ` sem texto.
- **Soluções Aplicadas**:
  - Implementada a função `detect_local_onion_endpoint()` em `src/lib.rs` com descoberta em cascata de serviços ocultos Tor v3 locais.
  - `service_status()` e `devices_status()` agora retornam o endpoint detectado ou configurado.
  - Adicionado `TextEditingController _onionController` em `main.dart`, sincronizado no refresh, com botão de copiar para a área de transferência (`Clipboard`).
  - Tratamento aprimorado no `_buildDeviceTile` para strings vazias e botão de cópia.
  - Adicionado método `setPeerConfig` em `LocalAgentApi` para pareamento direto.
  - A sessão anterior relatou sucesso em Rust (`cargo test`) e Flutter (`flutter test`), mas isso é histórico: a execução atual deve revalidar os testes e registrar o comando/resultado antes de promover qualquer build.

---

## 4. O Que Pretendíamos Fazer e O Que Falta Fazer

### 1. Build e Execução da Versão Mais Recente no macOS
- Compilar o backend release:
  ```bash
  cargo build --release
  ```
- Compilar o app Flutter Desktop para macOS:
  ```bash
  cd apps/desktop
  /Users/jemerson.barros/develop/flutter/bin/flutter build macos --release
  ```
- Instalar e abrir:
  ```bash
  pkill -f localscale_desktop || true
  cp -R build/macos/Build/Products/Release/localscale_desktop.app /Users/jemerson.barros/Applications/LocalScale.app
  open -a /Users/jemerson.barros/Applications/LocalScale.app
  ```

### 2. Sincronização, Build e Instalação no Linux
- Sincronizar o repositório (`git push origin localscale` no Mac e `git pull origin localscale` no Linux, ou `rsync -avz --exclude 'target' --exclude 'build' . jemerson@192.168.15.102:~/localscale/`).
- No Linux:
  ```bash
  cd ~/localscale
  cargo build --release
  cp target/release/localscaled ~/.local/opt/localscale-agent/localscaled
  systemctl --user restart localscale-agent.service
  
  cd ~/localscale/apps/desktop
  /home/jemerson/development/flutter/bin/flutter build linux --release
  pkill -f localscale_desktop || true
  cp -r build/linux/x64/release/bundle/* ~/.local/opt/localscale-desktop/
  
  export WAYLAND_DISPLAY=wayland-0 DISPLAY=:1 XDG_RUNTIME_DIR=/run/user/1000
  nohup ~/.local/opt/localscale-desktop/localscale_desktop > /tmp/desktop.log 2>&1 &
  ```

### 3. Pareamento e teste funcional (Linux Host → macOS Cliente)

O aceite funcional deve ser executado **nos dois aplicativos**, com os controles
visíveis na tela. SSH, `curl`, `rsync`, `systemctl`, `nohup` e screenshots são
ferramentas de bootstrap/observabilidade, não evidência de que o fluxo de
pareamento funcionou. No Mac, Computer Use pode conduzir a interface quando
necessário.

1. Abra o app no Linux, selecione `Host`, aguarde o Onion aparecer e use
   **Gerar convite**. O convite é de uso único, gerado, com validade curta,
   fingerprint da chave pública e IP virtual `10.42.0.1`.
2. Transfira o convite pela ação **Copiar convite** ou **(QR é roadmap)**. Não copie
   arquivos de estado e não digite um segredo predefinido.
3. Abra o app no macOS, selecione `Cliente`, use **Colar convite** ou **Escanear
   QR**, confirme o fingerprint exibido e aceite o Linux como Host (`10.42.0.2`
   no overlay).
4. Aguarde no próprio app as transições `configured → dialing → handshaking →
   connected`. Execute a ação de sincronização/ping do app e confirme o evento
   nos dois lados.
5. Feche e reabra os apps e repita apenas a verificação de estado. O convite
   usado deve ser rejeitado se for importado novamente (replay), e a conexão
   persistida deve usar as chaves locais protegidas.

Para automação determinística, um fixture de convite pode ser selecionado no
perfil de desenvolvimento **somente pela UI**. Ele deve ser regenerado a cada
execução com token aleatório, expiração e identificador de teste; nunca deve
conter um `invitation_secret` estático ou ser gravado em Markdown, logs,
artefatos ou Git. Em produção, fixtures são desabilitados e o pareamento exige
convite manual/QR ou descoberta aprovada pela conta Google.

> **Critério de aceitação:** `approved` ou `peer_configured` em
> `/api/v1/devices` não comprova conectividade. Declare `connected` somente
> quando o estado do transporte indicar sessão ativa, handshake concluído,
> identidade/role validados e uma troca recente de dados. A validação deve
> combinar `peer_transport`, `peer_connected`, `last_handshake_at`/equivalente,
> evento de sync/ping na UI e evidência redigida do handshake Tor. Screenshot é
> evidência complementar.

### 3.1 Convites e segredo predefinido

O segredo predefinido legado que aparecia em exemplos antigos deve ser tratado
como **comprometido** e não pode ser usado. O registro persistido não
deve conter `invitation_secret` em texto puro. O envelope do convite contém
apenas versão, IDs, Onion, chave pública/fingerprint, IP virtual, nonce,
expiração e assinatura; a sessão é derivada das chaves dos dois dispositivos.
Revogue registros emitidos com o segredo antigo, gere novas chaves e confirme o
replay negativo antes de qualquer teste de produção.

---

## 5. Pareamento Fácil e Descoberta pela Conta Google

OAuth Google apenas autentica a identidade. Ele não oferece, por si só, um
canal para o Host publicar seu Onion nem para o Cliente descobri-lo. O desenho
recomendado separa o plano de controle do plano de dados:

- **Plano de dados:** continua estritamente P2P sobre Tor v3 Onion. Nenhuma porta
  LAN ou backend público participa do tráfego dos agentes.
- **Plano de controle sem backend próprio:** Google Drive `appDataFolder` (roadmap),
  acessível somente pelo aplicativo e pela mesma conta Google, armazena pequenos
  manifestos de descoberta gerados.

### Etapa A — Convite manual simples

1. O Host gera um convite de uso único com versão, `node_id`, Onion atual,
   chave pública, IP virtual proposto, validade e assinatura.
2. A interface oferece **Copiar convite** e **(QR é roadmap)**.
3. O Cliente usa **Colar convite** ou **(QR é roadmap)**.
4. O app valida assinatura/validade, configura e aprova o peer, reinicia ou
   recarrega o transporte e mostra progresso até o handshake real.
5. O segredo permanente não deve aparecer no QR nem ser salvo em texto puro;
   uma chave de sessão deve ser derivada a partir das chaves dos dispositivos.
   Convites predefinidos só podem existir como fixtures de desenvolvimento
   efêmeros, gerados dentro do app a cada execução e desabilitados em produção.

### Etapa B — Descoberta automática pela mesma conta

1. Adicionar consentimento incremental, explícito e opt-in para o escopo Google
   `https://www.googleapis.com/auth/drive.appdata`; o login base continua usando
   somente `openid email profile` quando Drive não foi habilitado.
2. O Host publica no `appDataFolder` um manifesto curto, gerado e com TTL,
   contendo apenas metadados de descoberta (Onion, `node_id`, chave pública e
   capacidades). Nunca publicar tokens OAuth ou o `invitation_secret` atual.
3. O Cliente autenticado na mesma conta consulta o manifesto, valida assinatura
   e validade e solicita confirmação no primeiro pareamento.
4. Após a descoberta, handshake, sincronização e tráfego seguem exclusivamente
   pelo Onion. O Drive não funciona como relay.
5. Implementar revogação, rotação de chaves, TTL/presença, proteção contra
   replay e tratamento de múltiplos Hosts da mesma conta.

### Etapa C — Confiabilidade do transporte

- Manter a sessão P2P aberta em vez de descartar o stream depois do handshake.
- Fazer retry com backoff e jitter quando Tor ainda estiver inicializando.
- Recarregar o transporte após `peer/config`, aprovação ou mudança de modo.
- Propagar o estado real do transporte para `/diagnostics`, `/peer/status` e a UI.
- Nunca apresentar `approved` como sinônimo de `connected`.

### Etapa D — Diagnóstico e promoção

O app deve separar estados de configuração, autorização e conectividade. Para
mostrar **connected**, a resposta precisa indicar, de forma consistente,
`peer_configured=true`, `approved=true`, `peer_transport=connected`,
`peer_connected=true`, handshake concluído/role validado e uma troca de dados
recente (por exemplo `last_handshake_at` dentro da janela de presença). Se um
desses sinais faltar, mostrar `configured`, `dialing`, `handshaking`, `stale` ou
`error` com a causa; nunca inferir conexão a partir de uma lista de dispositivos.

A promoção para produção é opt-in e exige: convite manual,
segredo/keys em armazenamento protegido, revogação e rotação testadas, escopo
OAuth revisado, logs redigidos, replay negativo, e evidência do teste
Linux-Host/macOS-Cliente obtida pelos dois apps. OAuth e Drive são plano de
controle; o tráfego de dados permanece P2P pelo Tor v3.

---

## 6. Páginas de Controle e Debug

Em cada computador, as interfaces locais ficam restritas ao loopback:

- macOS: `http://127.0.0.1:18765/` e `/config`
- Linux: `http://127.0.0.1:8765/` e `/config`
- Diagnóstico JSON: `/diagnostics` ou `/api/v1/diagnostics`
- Estado do peer: `/api/v1/peer/status`
- Dispositivos: `/api/v1/devices`

Todas as requisições mutáveis devem enviar `Origin` e/ou `Referer` com a mesma
authority do `Host` loopback. O app desktop deve iniciar o `localscaled`
empacotado quando o health check falhar, mas não deve duplicar um daemon já
gerenciado por launchd/systemd.
