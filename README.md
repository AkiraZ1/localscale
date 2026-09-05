# LocalScale

Projeto independente para criar uma rede local privada entre máquinas, usando
um transporte intermediário Onion quando necessário e expondo um endpoint local
para clientes que não suportam `.onion` diretamente.

## Escopo

- relay local HTTP → SOCKS5/Tor;
- supervisão e configuração de Onion Service v3;
- callbacks/reverse para dispositivos pareados;
- documentação da topologia Mac ↔ Onion ↔ Linux;
- testes de conectividade, autenticação, queda e recuperação.

Este repositório **não contém** o Hermes Bridge, o cliente Android, o app
macOS, tokens, chaves privadas, `.env`, `connections.json` ou credenciais.

## Estado da separação

Extraído do repositório `hermes ponte celular` apenas o código de transporte
(relay/Tor/reverse) e a documentação de rede. O projeto original permanece
inalterado; os componentes Hermes Bridge continuam exclusivamente nele.

## Princípios

- nenhum segredo no código ou nos artefatos;
- Onion só é anunciado após publicação e health real;
- relay local deve escutar apenas em loopback e exigir autenticação quando
  encaminhar tráfego não confiável;
- testes de sandbox não substituem a validação ponta a ponta;
- mudanças devem ser verificadas com testes e diagnósticos reais.
