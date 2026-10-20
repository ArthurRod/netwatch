# Arquitetura

```
ss -tinHn ─┐
psutil ────┤
helper ────┴► monitoring/ ──► SnapshotBuilder ──► MonitorService (QThread) ──signal──► ui/
           connections.py      collector.py      services/monitor_service.py       widget.py
           network_stats.py                                                         details_window.py
```

- **`models/connection.py`**: dataclasses imutáveis (`Connection`, `TrafficStats`, `ProcessOutbound`, `Snapshot`). A UI só consome `Snapshot`.
- **`monitoring/`**: acesso ao sistema. `ConnectionCollector` normaliza `psutil.net_connections("inet")` e resolve nomes de processo com cache por PID. `NetworkStatsTracker` calcula taxas a partir dos contadores das interfaces.
- **`monitoring/socket_stats.py`**: executa `ss -tinHn` e extrai `bytes_acked`/`bytes_received` de cada socket TCP.
- **`monitoring/process_traffic.py`**: transforma os contadores por socket em taxa e total da sessão por processo.
- **`monitoring/collector.py`**: monta o `Snapshot`: marca o primeiro instante em que cada conexão foi vista, mantém as 50 conexões de saída mais recentes e agrupa as conexões de saída por processo.
- **`services/monitor_service.py`**: um worker numa `QThread` com `QTimer`; nada de coleta na thread da interface. Pausar, mudar o intervalo e encerrar são feitos por sinais.
- **`ui/`**: widget flutuante, janela de detalhes, diálogo de configurações.

## Definições

- **Conexão de saída**: socket com endereço remoto que não é loopback, não especificado, nem um endereço da própria máquina (`net_if_addrs`), e que não está em `TIME_WAIT`. Conexões para outros hosts da rede local (ex.: roteador) contam como saída.
- **Taxa de envio/recebimento**: soma dos deltas de `net_io_counters(pernic=True)` **somente das interfaces físicas** (com `/sys/class/net/<if>/device`). Sem isso, o tráfego de Docker (`veth*`, `docker0`, `br-*`) e de bridges seria somado duas ou três vezes. Sem interface física (ex.: só VPN), soma todas exceto `lo`.
- **Primeira amostra** e **retomada após pausa/suspensão**: a taxa aparece como `—` (desconhecida), nunca como zero.
- Contador que diminui (interface reiniciada) é tratado como delta 0 para aquela interface; interface nova só entra no cálculo a partir da segunda leitura.

## Identidade do processo

Para cada PID (com cache enquanto o PID tiver conexões), `lookup_process` lê via psutil, sem root:

- **Comando**: linha de comando completa, **com segredos mascarados** antes de entrar no modelo (`--password X`, `--api-key=X`, `TOKEN=X`, `Bearer X`, `://user:senha@`). Assim eles não chegam à tela nem a um futuro histórico em disco. A máscara é por padrão de nome, não garante pegar todo segredo.
- **Executável** e se ele foi **apagado do disco** (`/proc/<pid>/exe` termina em ` (deleted)`). Falso positivo comum: processos que já rodavam durante um `apt upgrade` também aparecem assim.
- **Usuário** e **cadeia de pais** (até 4 níveis: `bash ← ptyxis ← systemd`), que mostra se algo veio do desktop, de um terminal, do cron ou do systemd.

**Agrupamento**: o tráfego é somado por `(executável, script)`. Para interpretadores (`python*`, `node`, `bash`, `sh`, `perl`, `ruby`, `php`, `deno`, `bun`, `lua`…), o "script" é o primeiro argumento que não é opção, `-m módulo` ou `-c`/`-e` (código inline). Dois scripts Python diferentes ficam em linhas separadas (`python3 app.py`, `python3 sync.py`); dois processos do mesmo script somam juntos.

## Bytes por processo: metodologia

1. A cada leitura, logo depois dos contadores da interface, o `ss -tinHn` lista todos os sockets TCP com o `tcp_info` do kernel (via netlink INET_DIAG). Não precisa de root para os sockets do próprio usuário (verificado). Sockets TCP de outros usuários (ex.: daemons root) ainda não foram verificados; se o kernel não expuser o `tcp_info` deles, esse tráfego cai em "sem atribuição".
2. **Enviado = `bytes_acked`**, os bytes que o destino confirmou ter recebido. Não usamos `bytes_sent` porque ele conta retransmissões mais de uma vez.
3. Cada socket é casado com a conexão do psutil por `(endereço local, endereço remoto)`, com IPs normalizados (sem colchetes nem `%interface`). O psutil fornece o PID e o nome do processo.
4. Delta por socket: `atual − anterior`. Socket que aparece depois da primeira leitura conta o contador inteiro, porque foi aberto desde a última leitura. Na primeira leitura, e depois de pausar ou suspender, os contadores servem só de base e nada é somado.
5. Os deltas são somados por **identidade do processo** (veja acima). Um socket compartilhado por dois processos (após `fork`) conta uma vez só, para o primeiro.
6. O total da sessão por processo **fica guardado depois que o processo fecha as conexões**, com os últimos 20 destinos. Um script que envia e termina continua visível no resumo.
7. **Sem atribuição** = taxa da interface física − soma atribuída (mínimo 0).

### O que fica sem atribuição

| Origem | Observação |
|---|---|
| Cabeçalhos TCP/IP e ACKs puros | Com a máquina ociosa, cerca de 250 B/s (≈ 4 pacotes/s de ~62 B, medido em `/proc/net/snmp`). Downloads grandes geram ACKs de saída proporcionais. |
| UDP: QUIC/HTTP3, DNS, mDNS | O kernel não expõe bytes por socket UDP pelo INET_DIAG |
| Conexões que abrem e fecham entre duas leituras | O socket some antes de ser lido |
| Bytes finais de uma conexão que fecha | Entre a última leitura e o fechamento |
| Containers e VMs | Sockets em outro namespace de rede |
| Desalinhamento de tempo | `bytes_acked` sobe quando chega o ACK (1 RTT depois do envio); a soma pode ficar alguns ms defasada da interface |

Validação (Ubuntu 26.04, 2026-10-20): 10 de 10 conexões TCP de saída casadas com o `ss`; num segundo com envio real, 20.992 B/s atribuídos de 22.201 B/s medidos na interface (95%; o resto são cabeçalhos).

## Histórico

- **Arquivo**: `~/.local/share/netwatch/history.db` (SQLite em modo WAL, esquema versionado por `PRAGMA user_version`; migrações em `BEGIN IMMEDIATE`, seguras com várias conexões abrindo ao mesmo tempo). Pasta `0700`; banco, `-wal` e `-shm` com `0600`.
- **Quem escreve**: `HistoryRecorder`, na mesma thread da coleta, numa transação por leitura. A interface consulta por `HistoryService` (pool com uma thread, uma conexão por consulta) e nunca toca no disco na thread da UI.
- **O que entra**: só conexões de saída (mesma definição do widget), com a identidade do processo (comando já mascarado), destino, estado e bytes TCP.
- **Ciclo de vida de uma linha**:
  - inserida quando a conexão aparece. Se ela já existia quando o app iniciou, recebe `seen_at_start = 1` e a UI mostra "antes de HH:MM";
  - atualizada só quando bytes ou estado mudam, ou a cada 60 s (`last_seen`). Isso evita reescrever dezenas de linhas por segundo;
  - fechada (`closed_at`) na primeira leitura em que a conexão não aparece mais, ou entra em `TIME_WAIT`. A precisão é o intervalo de coleta;
  - se o app fechar com a conexão aberta, `closed_at` fica vazio e a UI mostra "visto HH:MM".
- **Bytes no histórico** = último valor observado do contador do socket, desde a abertura da conexão. Para conexões já abertas no início, inclui o que foi enviado antes do monitoramento. Os bytes finais entre a última leitura e o fechamento se perdem.
- **Visão por processo** = soma por `(rótulo, executável)` dentro do período filtrado, ordenada por bytes enviados.
- **Retenção**: linhas com `last_seen` mais antigo que N dias (padrão 30, de 1 a 365) são apagadas na abertura e depois a cada hora.
- **Apagar histórico**: `DELETE`, depois `VACUUM` e `wal_checkpoint(TRUNCATE)`, para que os dados saiam do arquivo, não só do índice (coberto por teste).
- **Falha de disco ou banco**: o histórico é desligado, a bandeja avisa e o monitoramento continua.
- **CSV**: célula que começa com `= + - @` ganha um `'` na frente. A linha de comando de um script é controlada por quem o escreveu e não pode virar fórmula ao abrir o arquivo numa planilha.

## Sinais de suspeita

Calculados na thread de coleta (`monitoring/signals.py`) para cada processo do resumo, incluindo os que já fecharam as conexões. São **heurísticas**: apontam o que merece um olhar, não provam que algo é malicioso.

| Sinal | Severidade | Regra | Falso positivo conhecido |
|---|---|---|---|
| Executável apagado | alta | `/proc/<pid>/exe` termina em ` (deleted)` | processo que já rodava durante um `apt upgrade` |
| Pasta temporária | alta | executável ou script (caminho relativo resolvido pelo `cwd`) em `/tmp/`, `/var/tmp/` ou `/dev/shm/` | **excluído**: `/tmp/.mount_*` (AppImages) |
| Interpretador/ferramenta enviando | média | `python*`, `node`, `bash`, `sh`, `perl`, `ruby`, `php`, `deno`, `bun`, `lua`, `curl`, `wget`, `nc`, `ncat`, `netcat`, `socat` com ≥ 1 MiB enviado na sessão | scripts de desenvolvimento |
| Primeira vez | baixa; média com ≥ 100 KiB enviados | `(rótulo, executável)` sem nenhuma linha no histórico anterior a esta sessão | app recém-instalado (alerta uma vez; na sessão seguinte já é conhecido) |
| Muito mais envio que recebimento | baixa | ≥ 5 MiB enviados e > 4× o recebido | backup, upload, chamada de vídeo |

- **Aprendizado**: "primeira vez" só é avaliado 24 h depois da linha mais antiga do histórico. Antes disso, todo processo seria "novo". Com o histórico desligado, esse sinal não existe.
- **Confiar** num processo grava `executável\0script` em `trusted_processes` na configuração. Ele deixa de ter marcador no widget, de contar no "⚠ N" e de notificar, mas continua na aba Alertas.
- **Notificação** na bandeja quando um processo não confiável atinge severidade média ou alta, uma vez por processo e por nível na sessão.

### Texto controlado por terceiros

Nome do processo, linha de comando, caminhos e mensagens de sinal são controlados por quem escreveu o programa. O `QLabel` do Qt renderiza como HTML qualquer texto que pareça HTML. Num teste, `<span style="font-size:1px">python3 /tmp/x.py</span>` reduziu o rótulo de 106 px para 9 px, o suficiente para um processo se esconder no próprio widget. Por isso, todo rótulo dinâmico usa `PlainLabel` (texto puro) e os tooltips passam por `plain_tooltip` (HTML escapado). Células de tabela já são texto puro.

## Nomes dos destinos (DNS reverso)

`services/domain_resolver.py`, usado pela thread de coleta:

1. Para cada IP de saída novo, um pool de 4 threads faz `gethostbyaddr` (PTR) e depois resolve o nome de volta (`getaddrinfo`). Isso nunca roda na thread da interface nem na da coleta.
2. **Confirmado** = o nome resolve de volta para o mesmo IP. **Não confirmado** = não resolve, ou resolve para outros IPs; a interface mostra `nome?`.
3. Cache: 1 h para nomes encontrados, 10 min para "sem nome", no máximo 4096 IPs, no máximo 16 consultas novas por leitura. Uma consulta lenta não segura a coleta: o nome aparece numa leitura seguinte.
4. Gravado no histórico (`remote_name`, `remote_name_confirmed`, esquema v2), pesquisável e exportado no CSV.
5. Desligável em Configurações. Cada IP novo vira uma consulta ao seu servidor DNS.

**O que o nome reverso é e o que não é.** Ele é escolhido por quem controla o IP. Mesmo confirmado, indica o **dono da infraestrutura** (`…googleusercontent.com`, `…facebook.com`), não o site que o programa pediu. Um nome não confirmado pode ser falso: um servidor de ataque pode publicar `update.microsoft.com` como PTR.

**Cobertura medida** (2026-10-20, uso normal com navegador): 3 de 20 destinos tinham nome. Google (IPv6), Cloudflare e Fastly não publicam PTR, confirmado com `getent hosts`.

**Fonte melhor, que exige privilégio**: observar as respostas DNS reais ("o processo pediu `discord.com` e recebeu este IP"). O `systemd-resolved` tem isso (`io.systemd.Resolve.Monitor`), mas responde `InteractiveAuthenticationRequired` para usuário comum. Fica para o helper privilegiado.

## Helper privilegiado

Opcional. Quando o socket `/run/netwatch-helper/events.sock` existe, `services/helper_client.py` lê os eventos numa thread própria e `monitoring/helper_events.py` os converte para os modelos do app. Detalhes, segurança e protocolo em [`helper.md`](helper.md).

## Limitações conhecidas

- **Bytes por processo só cobrem TCP.** UDP (incluindo QUIC/HTTP3), ICMP e tráfego de containers entram em "sem atribuição".
- Conexões que abrem e fecham entre duas leituras (1 s por padrão) não são vistas.
- **UDP**: só aparece com destino quando o socket faz `connect()`; sockets UDP "soltos" não têm `raddr`.
- A identificação de "conexão nova" usa `(protocolo, local, remoto, pid)`. Reiniciar o app zera esse estado; o histórico persiste.
