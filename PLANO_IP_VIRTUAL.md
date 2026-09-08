# Plano: IP virtual editável de verdade

## Problema

Hoje, trocar o "IP Virtual Local" no painel, depois de já pareado, não funciona de
verdade — dois problemas independentes:

1. **A interface TUN é criada uma única vez por processo, com endereço fixo**
   (`ip addr add` só acontece na criação). Mudar o IP no painel apenas atualiza um
   valor anunciado no protocolo de heartbeat — nunca reconfigura a interface de
   rede real. Resultado: mudar de `.7` para `.6` na UI não muda nada na prática,
   o tráfego continua chegando em `.7`.

2. **O Host sempre mostra o IP fixo atribuído pelo registro na hora do convite**
   (`HostPeerEntry.virtual_ip`) na lista de dispositivos — nunca o valor ao vivo
   que o Cliente está de fato anunciando via heartbeat. Então mesmo que o Cliente
   mude seu IP e o heartbeat propague isso corretamente, o Host nunca reflete essa
   mudança na interface.

## Mudanças necessárias

1. **Reconfigurar a interface ao vivo** (`src/tun_linux.rs` / `src/tun_macos.rs`)
   Adicionar um `reconfigure_address(old_ip, new_ip)` que remove o endereço antigo
   (`ip addr del`) e adiciona o novo (`ip addr add`), em vez de só configurar na
   criação. No macOS, `utun` é point-to-point — trocar o IP local exige
   reconfigurar os dois lados do túnel (local + peer), mais delicado que no Linux.

2. **Thread de vigia do IP local**
   Hoje só existe a thread que reaplica a rota do peer a cada 2s
   (`ROUTE_THREAD_STARTED` em `src/main.rs`). É preciso uma equivalente para o IP
   local: detectar quando `status.local_virtual_ip()` muda e chamar
   `reconfigure_address`.

3. **Host: expor o IP ao vivo do Cliente, não o fixo do registro**
   Em `devices_status()` (`src/lib.rs`), trocar `entry.virtual_ip` (estático) por
   `live_status.remote_virtual_ip()` quando disponível, caindo para o valor do
   registro apenas enquanto nenhum heartbeat ainda chegou.

4. **Checagem de colisão**
   Antes de aceitar uma troca manual de IP (`set_virtual_ip_handler`), validar
   contra `HostPeerRegistry` (se for Cliente falando com Host) ou contra os
   outros peers conectados (se for Host) — hoje não existe nenhuma validação, um
   IP escolhido manualmente pode colidir com outro dispositivo já usando aquele
   endereço.

5. **Sincronizar `host_local_virtual_ip` também**
   `set_virtual_ip_handler` hoje só atualiza `state.peer`/`state.peer_transport_status`
   — não toca `state.host_local_virtual_ip`, que é a fonte usada para calcular o
   prefixo de rede e os IPs de novos convites. Precisa atualizar os dois juntos,
   ou a IP mostrada localmente diverge da usada internamente para novos convites.

## Risco

Mexe em 4 arquivos (`tun_linux.rs`, `tun_macos.rs`, `main.rs`, `lib.rs`) e no
caminho mais sensível do projeto — a ponte de rede real, que só ficou estável
recentemente (ver correções de identidade do Host e do bridge por-conexão na
mesma sessão que gerou este plano). Boa candidata a uma sessão dedicada, com
bastante teste ponta a ponta entre Mac e Linux antes de reinstalar em produção.

## Status atual (até este documento)

A troca de IP no painel funciona apenas como valor anunciado no protocolo —
não reconfigura a rede de fato. Nada foi implementado deste plano ainda.
