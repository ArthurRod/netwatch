# NetWatch

Widget de desktop para Ubuntu que mostra **o que está saindo do seu computador**: quanto cada processo está enviando, para onde, e quais processos merecem atenção. O objetivo é perceber um script malicioso enviando seus dados para fora sem você saber.

- Roda como usuário comum, **sem root**.
- **Nenhuma telemetria**: nada sai do computador por causa do NetWatch, exceto as consultas de DNS reverso, que podem ser desligadas.
- Histórico **local**, com retenção configurável e botão para apagar tudo.

<img width="329" height="469" alt="Screenshot From 2026-10-20 18-13-20" src="https://github.com/user-attachments/assets/ecac89cb-f52d-46ae-b7fc-59098a1f801f" />

## Sumário

- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Uso](#uso)
- [Configurações](#configurações)
- [Arquivos e privacidade](#arquivos-e-privacidade)
- [Desinstalação](#desinstalação)
- [Limitações](#limitações)
- [Desenvolvimento](#desenvolvimento)
- [Documentação técnica](#documentação-técnica)

## Requisitos

| Item | Versão testada | Observação |
|---|---|---|
| Ubuntu | 26.04 (GNOME) | Wayland ou X11 |
| Python | 3.12 ou superior (testado no 3.14) | `python3-venv` para criar o ambiente |
| `ss` (iproute2) | já vem no Ubuntu | bytes por conexão TCP |
| Bibliotecas xcb do Qt | — | só para "sempre visível" no Wayland, veja abaixo |
| `bpftrace` | 0.25 | só para o helper privilegiado opcional |

## Instalação

### 1. Baixar e instalar

```bash
git clone git@github.com:ArthurRod/netwatch.git
cd netwatch
scripts/install.sh
```

O script cria um ambiente isolado em `~/.local/share/netwatch-app/` e adiciona o **NetWatch** ao menu de aplicativos, para abrir sem terminal. Não pede `sudo`: se faltar algo do sistema, ele mostra o comando `apt` exato.

Para atualizar depois de um `git pull`, rode `scripts/install.sh` de novo.

### 2. "Sempre visível" no GNOME Wayland (recomendado)

O GNOME ignora o "sempre no topo" em apps Wayland nativos. Com estas bibliotecas, o NetWatch roda via XWayland, onde funciona:

```bash
sudo apt install libxcb-cursor0 libxcb-icccm4 libxcb-keysyms1
```

Sem elas, o NetWatch abre no Wayland nativo e registra um aviso no log.

### 3. Iniciar com o Ubuntu (opcional)

Em **Config.** → **Iniciar automaticamente ao entrar no Ubuntu**. Isso cria `~/.config/autostart/netwatch.desktop`.

### 4. Helper privilegiado (opcional)

Fecha os pontos cegos do modo sem privilégios: conexões rápidas, processos de root, bytes finais de cada conexão e o domínio real pedido via DNS.

```bash
sudo apt install bpftrace
sudo scripts/install-helper.sh
```

Veja [`docs/helper.md`](docs/helper.md) para o modelo de segurança antes de instalar.

## Uso

### Widget

| Elemento | O que mostra |
|---|---|
| **↑ taxa de envio** | Envio total das interfaces físicas (Docker, bridges e loopback ficam de fora para não contar em dobro). A entrada (↓) aparece pequena, para contexto. |
| **Enviado na sessão** | Total enviado desde que o NetWatch abriu |
| **Para onde está indo** | Os 4 processos que mais enviaram na sessão, com taxa atual, total, conexões e destinos. Um processo que já fechou as conexões continua aparecendo. |
| **● marcador** | Processo com sinal de suspeita; a cor indica a severidade. Passe o mouse para ver o motivo, o comando e quem iniciou o processo. |
| **⚠ N** | Quantos processos têm sinais. Clique para abrir os alertas. |
| **Sem atribuição** | Parte do envio que não pôde ser ligada a nenhuma conexão TCP (veja [Limitações](#limitações)) |
| **Novas conexões** | As 3 conexões de saída mais recentes |

- **Arrastar:** clique e arraste em qualquer área livre do widget.
- **─** esconde o widget na bandeja e **×** encerra o app.
- **Ícone da bandeja:** um clique mostra ou esconde o widget; o botão direito abre o menu.

### Janela de detalhes

| Aba | Para que serve |
|---|---|
| **Agora** | Todas as conexões no momento: processo, PID, destino, domínio, porta, bytes, estado. Busca por processo, IP, domínio, comando ou caminho. **Somente novas** mostra o que apareceu nos últimos 5 minutos (exceto o que já estava aberto quando o app iniciou). Selecione uma linha para ver o comando completo, o executável e a cadeia de processos pais. **Congelar** pausa a tabela enquanto você investiga. |
| **Alertas** | Processos com sinais de suspeita na sessão. **Confiar neste processo** para de destacá-lo e de notificar. |
| **Histórico** | Conexões gravadas, mesmo depois de fechar o app. A visão **Por processo** responde "quem mais enviou nas últimas 24 h". Tem filtros de período, protocolo e busca, **Exportar CSV** e **Apagar histórico**. |

### Sinais de suspeita

| Sinal | Severidade |
|---|---|
| Executável apagado do disco depois de iniciar | alta |
| Executável ou script em `/tmp`, `/var/tmp` ou `/dev/shm` | alta |
| Interpretador ou ferramenta de rede (`python`, `node`, `bash`, `curl`, `nc`…) enviando ≥ 1 MB | média |
| Processo fazendo conexões de saída pela primeira vez | baixa; média se enviou ≥ 100 KB |
| Envio ≥ 5 MB e mais de 4× o recebido | baixa |

Sinais médios e altos geram **uma notificação na bandeja** por processo. São heurísticas: indicam o que merece um olhar, não provam que algo é malicioso. O sinal de "primeira vez" só começa a valer 24 h depois do início do histórico.

### Domínios

| Exibição | Origem | Confiança |
|---|---|---|
| `discord.com` | **DNS observado** (com o helper): o nome que um programa pediu e cuja resposta foi este IP | alta |
| `discord.com?` | DNS observado, mas o IP respondeu por **mais de um nome** (CDN); os outros aparecem no tooltip | incerta |
| `…googleusercontent.com` | **Nome reverso (PTR) confirmado**: indica o dono da infraestrutura, não necessariamente o site | média |
| `nome?` | Nome reverso **não confirmado**: quem controla o IP escolhe esse nome, então ele pode ser falso | baixa |
| `—` | Sem nome. Comum para Google (IPv6), Cloudflare e Fastly sem o helper | — |

## Configurações

Botão **Config.** no widget:

| Opção | Padrão |
|---|---|
| Iniciar automaticamente ao entrar no Ubuntu | desligado |
| Opacidade | 92% |
| Intervalo de coleta | 1000 ms |
| Manter sobre outras janelas | ligado |
| Usar XWayland no Wayland (requer reiniciar) | ligado |
| Gravar histórico de conexões de saída | ligado |
| Manter histórico por | 30 dias |
| Resolver nomes dos destinos (DNS reverso) | ligado |

## Arquivos e privacidade

| Caminho | Conteúdo | Permissão |
|---|---|---|
| `~/.config/netwatch/config.json` | Preferências e processos confiáveis | `0600` |
| `~/.local/share/netwatch/history.db` | Histórico de conexões de saída | `0600` (pasta `0700`) |
| `~/.local/share/netwatch-app/` | Ambiente Python do app (criado pelo instalador) | padrão |
| `~/.config/autostart/netwatch.desktop` | Só se o início automático estiver ligado | padrão |
| `~/.local/state/netwatch/netwatch.log` | Log de diagnóstico (rotativo, 1 MB × 3) | padrão |

- Senhas e tokens na linha de comando (`--password X`, `--api-key=X`, `TOKEN=X`, `Bearer X`, `user:senha@` em URLs) são mascarados antes de aparecer na tela ou ir para o disco. A máscara é por padrão de nome e não garante pegar todo segredo.
- Nenhum conteúdo de pacote é capturado, e nada é descriptografado.
- **Apagar histórico** remove os dados do arquivo de verdade (`VACUUM`), não só do índice.

## Desinstalação

```bash
scripts/uninstall.sh            # remove o app; mantém preferências, histórico e logs
scripts/uninstall.sh --purge    # remove também preferências, histórico e logs
sudo scripts/uninstall-helper.sh   # se o helper foi instalado
```

As bibliotecas xcb, se não forem usadas por mais nada:

```bash
sudo apt remove libxcb-cursor0 libxcb-icccm4 libxcb-keysyms1
```

## Limitações

| Ponto cego | Sem o helper | Com o helper |
|---|---|---|
| Conexões TCP que abrem e fecham em menos de 1 s | não vistas; envio em "Sem atribuição" | ✅ vistas, com bytes |
| Bytes finais de cada conexão TCP | último trecho perdido (~5% num download medido) | ✅ lidos no fechamento |
| Processos de root e de outros usuários | "sem permissão" | ✅ identificados |
| Domínio pedido pelo programa | só nome reverso (raro em CDN) | ✅ DNS observado |
| Bytes de UDP, incluindo QUIC/HTTP3 | "Sem atribuição" | "Sem atribuição" |

Com a máquina ociosa, "Sem atribuição" fica em torno de 250 B/s. São cabeçalhos e ACKs do TCP, medidos e explicados em `docs/architecture.md`.

O NetWatch observa a máquina de dentro. Um malware com root pode se esconder de qualquer ferramenta local, inclusive desta; para esse nível de ameaça, a observação precisa vir de fora (roteador ou firewall da rede).

## Desenvolvimento

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
.venv/bin/netwatch
```

```
src/netwatch/
├── models/       dataclasses imutáveis (Connection, Snapshot, ProcessIdentity, Signal…)
├── monitoring/   coleta: psutil, ss, contadores das interfaces, sinais
├── services/     thread de monitoramento, histórico assíncrono, DNS reverso, CSV
├── storage/      SQLite (esquema versionado, gravação e consultas)
└── ui/           widget, janela de detalhes, abas, configurações
helper/           serviço privilegiado opcional (bpftrace + DNS do systemd-resolved)
scripts/          instalação e desinstalação do app e do helper
```

A interface só recebe dados normalizados (`Snapshot`) por sinal Qt. Coleta, gravação e DNS rodam fora da thread da interface.

## Documentação técnica

- [`docs/architecture.md`](docs/architecture.md): fluxo de dados, metodologia de medição por processo, histórico, sinais, DNS reverso, limitações medidas.
- [`docs/permissions.md`](docs/permissions.md): o que precisa ou não de privilégio, e o comportamento no Wayland e no X11.
- [`docs/helper.md`](docs/helper.md): helper privilegiado, modelo de segurança e protocolo.
- [`docs/validation.md`](docs/validation.md): critérios de aceitação do plano e o resultado de cada validação.
