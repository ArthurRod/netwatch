# Helper privilegiado (opcional)

O NetWatch funciona sem privilégios. O helper é um serviço do sistema, **opcional e separado da interface**, que fecha três pontos cegos:

| Ponto cego sem o helper | Com o helper |
|---|---|
| Conexões que abrem e fecham em menos de 1 s | Toda conexão TCP de saída é vista na abertura (`kprobe:tcp_connect`) |
| Bytes finais de cada conexão (entre a última leitura e o fechamento) | Bytes confirmados lidos no fechamento (`tcp_set_state → TCP_CLOSE`, `bytes_acked`) |
| Processos de root e de outros usuários ("sem permissão") | PID, executável, comando e processos pais lidos em `/proc` pelo helper |
| Domínio real pedido pelo programa | Respostas DNS observadas no `systemd-resolved` (nome pedido → IPs) |

**Ainda fora do helper:** bytes de fluxos UDP (inclui QUIC/HTTP3). Continuam em "Sem atribuição".

## Instalação

Requer `bpftrace` (`sudo apt install bpftrace`) e um kernel com BTF (`/sys/kernel/btf/vmlinux`; padrão no Ubuntu).

```bash
sudo scripts/install-helper.sh
```

O script:

1. copia `helper/netwatch_helper.py` e `helper/netwatch.bt` para `/usr/local/lib/netwatch-helper/` (dono root, `0644`);
2. grava `/etc/netwatch-helper.conf` com o seu UID (o de quem chamou o `sudo`) como único leitor permitido;
3. instala `/etc/systemd/system/netwatch-helper.service`;
4. roda o **autoteste** (`--self-test`): abre uma conexão TCP local e confere se os eventos de abertura e fechamento chegaram. Se falhar, o serviço **não** é ativado;
5. ativa e inicia o serviço.

O widget mostra **eBPF** no cabeçalho quando o helper está conectado: verde se as sondas estão ativas, vermelho se falharam. O tooltip mostra o estado das conexões TCP e do DNS.

## Desinstalação

```bash
sudo scripts/uninstall-helper.sh
```

Para o serviço e remove os arquivos instalados. O NetWatch volta ao modo sem privilégios automaticamente.

## Modelo de segurança

| Decisão | Motivo |
|---|---|
| Código do helper em `/usr/local/lib`, dono root | Código executado como root nunca fica num caminho que o usuário pode editar (como a venv). Se ficasse, qualquer processo do usuário viraria root. |
| Só biblioteca padrão do Python (`/usr/bin/python3 -I`) e o `bpftrace` do sistema | Nenhuma dependência de terceiros roda como root. O `-I` ignora variáveis de ambiente e o site-packages do usuário. |
| Socket `/run/netwatch-helper/events.sock` com `0666`, mas **UID verificado pelo kernel** (`SO_PEERCRED`) contra `/etc/netwatch-helper.conf` | Funciona sem precisar sair e entrar de novo na sessão (um grupo novo exigiria isso). Outros usuários são desconectados na hora. |
| Comunicação **só de saída**: o helper fecha a leitura do socket (`SHUT_RD`) e nunca interpreta o que o cliente envia | Não há comando nem parâmetro que um cliente possa usar para influenciar o processo root. |
| Cliente lento perde eventos em vez de travar o helper (fila de 20.000 por cliente) | Um cliente travado não segura o rastreamento. |
| Saída do bpftrace em JSON, com o nome do processo (`comm`) sempre no **último** campo | Um processo malicioso pode se chamar `a\tb\nC…`; o JSON impede quebra de linha e o último campo absorve tabulações, sem forjar outros campos. |
| Linha de comando sem máscara no socket; o NetWatch aplica a máscara de segredos ao receber | `/proc/<pid>/cmdline` já é legível por qualquer usuário no Ubuntu, então o socket não expõe nada novo. |
| Unidade systemd com `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp`, famílias de rede restritas e outras proteções | Limitam o que o processo root pode alterar no sistema. |
| `PrivateTmp=yes` | O bpftrace precisa criar arquivos temporários em `/tmp`; com `ProtectSystem=strict` sem `PrivateTmp`, `/tmp` fica somente leitura e as sondas não sobem (encontrado na primeira instalação real). |

**Endurecimento ainda não aplicado:** restringir capacidades (`CapabilityBoundingSet`) e tornar `/sys` somente leitura (`ProtectKernelTunables`). Ficaram de fora porque o bpftrace pode precisar delas para anexar as sondas, e isso só pode ser testado como root.

## Protocolo

Uma mensagem JSON por linha, do helper para o cliente:

```json
{"type":"hello","version":1}
{"type":"status","tcp":"running","dns":"running","ts":1760990000.0}
{"type":"tcp_connect","sock":123,"pid":4242,"uid":1000,"local":["192.168.0.2",50000],"remote":["6.6.6.6",443],"comm":"curl","process":{...},"ts":...}
{"type":"tcp_close","sock":123,"pid":4242,"uid":1000,"local":[...],"remote":[...],"bytes_sent":51234,"bytes_received":812,"comm":"curl","process":{...},"ts":...}
{"type":"dns","questions":["discord.com"],"answers":{"discord.com":["162.159.135.232"]},"ts":...}
```

`process` = `{"pid","name","exe","exe_deleted","cmdline":[...],"uid","cwd","ancestors":[[pid,name],...]}`, ou `null` se o processo já tinha terminado. Nesse caso o NetWatch usa o `comm` do kernel.

## Como o NetWatch usa os eventos

- **Conexão sem PID** (de root ou de outro usuário) visível no `ss`: recebe a identidade do evento `tcp_connect` do mesmo par local/remoto.
- **`tcp_close`:** os bytes finais entram no total do processo. Se o socket ainda aparece na leitura atual, conta só a diferença a partir dela; se não aparece, a diferença desde a leitura anterior; se nunca foi visto (conexão rápida), o total inteiro. Bytes enviados antes do NetWatch iniciar não entram na sessão.
- **Conexões rápidas** entram em "Novas conexões" e no histórico, com início e fim.
- **DNS:** o nome **pedido** pelo programa (a pergunta, não o CNAME final) é associado a cada IP da resposta por 1 h. Se o mesmo IP respondeu por mais de um nome no período (comum em CDN), a associação é marcada como **incerta** e a interface mostra `nome?` com os outros nomes no tooltip. O DNS observado tem prioridade sobre o nome reverso.

## Diagnóstico

```bash
systemctl status netwatch-helper
journalctl -u netwatch-helper -n 50
sudo /usr/bin/python3 -I /usr/local/lib/netwatch-helper/netwatch_helper.py --self-test
```
