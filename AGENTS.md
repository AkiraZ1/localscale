# LocalScale

## Objetivo

Perfil dedicado exclusivamente ao desenvolvimento e operação do LocalScale,
um transporte de rede local self-hosted que pode usar Tor/Onion como
intermediário e apresentar um endereço local para aplicações sem suporte nativo
à resolução `.onion`.

## Repositório

`/Users/jemerson.barros/Documents/ChatGPT/localscale`

## Regras

- Não alterar nem importar o produto Hermes Bridge, Android ou o app macOS.
- Não ler, copiar ou registrar tokens, senhas, chaves privadas, `.env`,
  `connections.json`, Keychain ou credenciais.
- Configurar servidores somente com opt-in explícito e validar toda mudança.
- Onion não é considerado disponível apenas porque Tor está instalado: exigir
  processo ativo, hostname publicado, autorização quando habilitada,
  alcançabilidade e health.
- O relay local deve escutar somente em loopback por padrão.
- Não inventar IPs, portas, endpoints ou modelos; descobrir do código e da
  configuração real.
- Toda entrega deve incluir teste executado e separar PASS de BLOCKED.
- Usar subagentes em tarefas complexas e auditar seus relatos com ferramentas.
- Relatórios em português brasileiro, objetivos e baseados em comandos reais.
