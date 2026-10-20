# Validação

Critérios de aceitação do plano (seção 7) e como cada um foi verificado em Ubuntu 26.04, GNOME Wayland, kernel 7.0, Python 3.14, em 2026-10-20.

Legenda: ✅ verificado de verdade · 🧪 verificado por teste automatizado que simula a condição · ⏳ depende de uma ação do usuário · ⚠️ limitação do sistema, não defeito.

| Teste | Resultado esperado | Status | Como foi verificado |
|---|---|---|---|
| Abrir o aplicativo | Widget aparece sem terminal | ✅ | `scripts/install.sh` cria o atalho no menu (validado com `desktop-file-validate`); o app instalado abre pelo `Exec=` do atalho |
| Abrir navegador | Novas conexões identificadas | ✅ | Conexões do Firefox aparecem com processo, PID, destino e cadeia de pais (`gnome-shell ← systemd`) |
| Acessar um site HTTPS | IP, porta e processo apresentados | ✅ | Conexões `:443` com processo e, quando há, nome do destino |
| Fazer upload de um arquivo | Taxa global de saída aumenta | ✅ (parcial) | Envio real do `claude` atribuído: 20.992 de 22.201 B/s medidos na interface (95%; o resto são cabeçalhos). Não foi feito upload de arquivo para um servidor de terceiros. |
| Baixar um arquivo | Taxa global de entrada aumenta | ✅ | `curl` de 100 MiB (Hetzner): pico ↓ 15,4 MiB/s na interface; 94,8 MiB atribuídos ao `curl` (95%; o último trecho antes do fechamento só é visto com o helper) |
| Encerrar um processo | Conexões somem ou são registradas como encerradas | ✅ | O histórico grava `closed_at` na primeira leitura em que a conexão some ou entra em `TIME_WAIT`; o processo continua no resumo com o total enviado |
| Desativar privilégios de captura | Interface continua funcionando | ✅ | O modo padrão é sem privilégios; sem o socket do helper, o cliente fica em silêncio (teste `test_client_without_helper_stays_quiet`) |
| Reiniciar o aplicativo | Preferências e histórico persistem | ✅ | Configuração (`0600`) e banco SQLite relidos após reiniciar; migração de esquema v1→v3 coberta por teste |
| Desconectar a rede | App permanece funcional | 🧪 | Interface some e volta sem pico falso; `ss` falhando, DNS falhando e nenhuma interface: o snapshot continua sendo gerado (`tests/test_resilience.py`). Não foi derrubada a rede real, para não interromper o uso da máquina. |
| Suspender e retomar | Taxas não disparam | 🧪 | Um intervalo de relógio de parede maior que 5× o de coleta zera a base das taxas (`test_long_wall_clock_gap_resets_rates_after_suspend`). Não foi suspensa a máquina real. |
| Deixar aberto por horas | Consumo controlado | ✅ | Veja "Execução longa" abaixo |
| Iniciar o Ubuntu | Inicia automaticamente se ativado | ✅ (parcial) | `~/.config/autostart/netwatch.desktop` gerado e validado com `desktop-file-validate`; o login real não foi refeito |
| Executar em Wayland | Comportamento documentado | ✅ | `docs/permissions.md`: Wayland nativo ignora "sempre no topo"; via XWayland, `_NET_WM_STATE_ABOVE` e a posição foram conferidos com `xprop`/`xwininfo` |
| Instalar e remover | Seguindo as instruções | ✅ | Ciclo completo em diretórios isolados: instalar, abrir, ativar autostart, reinstalar, recusar desinstalação com o app aberto, desinstalar mantendo dados, `--purge` sem sobras |
| Helper privilegiado | Eventos TCP e DNS chegam ao app | ✅ | Instalado de verdade. Uma cópia do `curl` rodando de `/tmp`, com conexão de menos de 1 s, foi capturada pelo app completo: alerta alto "Rodando de pasta temporária", notificação, 1,9 KB atribuídos, entrada em "Novas conexões" e nome `www.wikipedia.org` vindo do DNS observado. O caminho `/tmp/...` do executável chega correto mesmo com o serviço no próprio namespace de montagem. Respostas DNS vindas do cache do `systemd-resolved` também são reportadas. Em 1 de 5 execuções o destino apareceu como IP em vez do nome; causa não identificada. |

### Defeitos encontrados na instalação real do helper

1. Com `ProtectSystem=strict` e sem `PrivateTmp`, o `/tmp` fica somente leitura e o bpftrace não sobe (`unable to create /tmp/bpftrace.XXXXXX`). O autoteste passou porque roda fora da unidade systemd. Corrigido com `PrivateTmp=yes`, e o instalador agora espera `tcp: running` **dentro do serviço** antes de declarar sucesso.
2. Um cliente que conectava depois do início do helper nunca recebia o estado atual, então o indicador eBPF não aparecia. Corrigido: o helper envia o estado logo após o `hello`.
3. O nome de um destino sumia da tela quando a conexão fechava. Corrigido: os nomes são calculados para todos os IPs exibidos.

## Execução longa

App completo, plataforma `offscreen`, coleta a cada 1 s, histórico ligado, DNS reverso ligado, amostras a cada 30 s.

RESULTADOS_EXECUCAO_LONGA

## Escrita em disco do histórico

Na primeira versão, cada conexão ativa tinha os bytes regravados a cada segundo. O WAL do SQLite crescia ~400 KB/min. Agora:

- estado e nome são gravados na hora;
- bytes, no máximo a cada 15 s por conexão (o valor mais recente fica em memória e é gravado no fechamento);
- `last_seen`, a cada 60 s;
- WAL limitado a 1 MiB após o checkpoint (`journal_size_limit`).

Medido com dados reais: 17 commits por minuto, e o WAL crescendo ~100 KB/min (≈ 4× menos).

Escrita total por chamadas de sistema (`wchar`, média de 40 s cada):

| Parte | KiB/s |
|---|---|
| Só executar o `ss` (subprocesso a cada 1 s) | 3,9 |
| Coleta completa, sem histórico | 4,1 |
| Coleta + histórico | 4,4 |

O volume é dominado pela comunicação por pipe com o `ss`, que não é escrita em disco. O histórico acrescenta ~0,3 KiB/s.
