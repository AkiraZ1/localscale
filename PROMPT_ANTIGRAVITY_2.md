# Prompt Pronto para o Antigravity 2.0

> Copie o bloco abaixo para continuar a validação. O aceite deve usar os dois
> aplicativos; comandos remotos são apenas bootstrap/observabilidade.

```markdown
Olá Antigravity! Continue o projeto LocalScale conforme
`HANDOVER_ANTIGRAVITY_2.md` e `LINUX_SUBAGENT_GUIDE.md`.

## Cenário obrigatório desta execução

- **Linux = Host**: Debian/KDE em `192.168.15.102`, agente local em
  `http://127.0.0.1:8765`, IP virtual `10.42.0.1`.
- **macOS = Cliente**: Apple Silicon, agente local em
  `http://127.0.0.1:18765`, IP virtual `10.42.0.2`.
- O endpoint `.onion` do Host deve ser lido no app no início da execução. Não
  reutilize hostname antigo nem publique um Onion local do Cliente.

## Preparação

1. Use subagentes em paralelo para compilar/preparar Linux e macOS e, se
   necessário, observar logs e `/diagnostics` redigidos.
2. Abra os dois apps e deixe cada um mostrar sua página de controle local.
   Computer Use pode controlar a UI do macOS. Não use `curl`, POST manual,
   `ssh`, `nohup`, `systemctl` ou edição de `peer-record.json` como substituto
   das ações de pareamento.

## Teste de pareamento dentro do app

1. No Linux, selecione `Host`, aguarde o Onion ficar pronto e clique **Gerar
   convite**.
2. Transfira pelo botão **Copiar convite** ou **(QR é roadmap)**.
3. No macOS, selecione `Cliente`, clique **Colar convite** ou **(QR é roadmap)**,
   confira o fingerprint e aceite o Host Linux.
4. Aguarde as transições visíveis `configured → dialing → handshaking →
   connected`. Execute o ping/sync do app e confira o evento nos dois lados.
5. Importe o mesmo convite novamente: deve falhar por replay. Feche/reabra os
   apps e confirme que a sessão persistida continua usando apenas chaves locais.

Para automação determinística, use somente o fixture selecionável pela UI em
perfil de desenvolvimento. Gere um convite novo a cada execução com nonce,
expiração e token aleatórios. Nunca use ou documente
qualquer segredo predefinido legado, `invitation_secret` estático, token OAuth ou chave
privada. Desabilite fixtures no perfil de produção.

## Critérios de evidência

- `approved` e `peer_configured` significam apenas autorização/configuração.
- Só aceite `connected` se o app/diagnóstico indicar sessão de transporte ativa,
  `peer_connected=true`, handshake concluído, identidade/role validados e troca
  recente de dados (`last_handshake_at` ou equivalente).
- Colete evidência nos dois apps (sync/ping, horário e erro redigido). Health,
  `/api/v1/devices`, screenshot ou lista de peers, isoladamente, não provam
  conectividade.

## Descoberta opcional pela mesma conta Google

OAuth base usa somente `openid email profile`. Drive será opt-in (roadmap), com consentimento
incremental para `https://www.googleapis.com/auth/drive.appdata`; use o
`appDataFolder` para manifesto curto, gerado, com TTL e proteção contra
replay. Nunca publique tokens, refresh tokens, chaves privadas ou convite secreto
no Drive. Após descobrir, o tráfego continua exclusivamente pelo Tor v3; Drive
não é relay.

## Promoção

Não declare produção pronta sem revogação/rotação, replay negativo, logs
redigidos, escopos OAuth revisados e o teste Linux Host/macOS Cliente validado
pelos dois apps. Ao final, entregue um resumo com os critérios observados e
deixe o commit/push para o agente principal.
```
