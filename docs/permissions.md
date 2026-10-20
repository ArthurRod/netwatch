# Permissões e ambiente gráfico

## Sem root

O NetWatch roda inteiro como usuário comum.

| Recurso | Precisa de privilégio? | Comportamento sem privilégio |
|---|---|---|
| Lista de sockets (`/proc/net/*`) | Não | Todos os sockets do sistema aparecem |
| PID/processo do socket | Só para processos de **outros usuários** (ex.: daemons root como DHCP, systemd-resolved) | Mostrado como **"sem permissão"** e contado à parte no widget |
| Contadores das interfaces | Não | Completo |
| Sockets em `TIME_WAIT` | — | Não têm processo dono (o kernel os mantém após o fechamento); aparecem como **"encerrada"** e não contam como saída |

Para ver os processos de root seria preciso `CAP_SYS_PTRACE`/`CAP_DAC_READ_SEARCH` no interpretador, o que daria esses poderes a qualquer script Python. **Não recomendado.** Em vez disso, existe o helper privilegiado opcional: um serviço root separado, que só envia eventos e não aceita comandos. Veja [`helper.md`](helper.md).

## Com o helper

| Recurso | Como o helper obtém | Privilégio usado |
|---|---|---|
| Abertura e fechamento de conexões TCP | `bpftrace`: `kprobe:tcp_connect` e `kprobe:tcp_set_state` | root (eBPF; `kernel.unprivileged_bpf_disabled=2` no Ubuntu) |
| Identidade de processos de outros usuários | `/proc/<pid>/exe`, `cwd`, `cmdline`, `stat` | root |
| Consultas DNS | varlink `io.systemd.Resolve.Monitor` | root (o `systemd-resolved` responde `InteractiveAuthenticationRequired` para usuário comum) |

A interface continua sem privilégios: ela só lê o socket do helper, que aceita apenas o UID configurado na instalação.

## GNOME + Wayland

Ambiente de desenvolvimento: Ubuntu 26.04, GNOME, sessão Wayland. A coluna XWayland foi verificada com `xprop`/`xwininfo`: a janela recebe `_NET_WM_STATE_ABOVE`, abre na posição salva, e desligar/religar "sempre visível" remove/recoloca o estado sem perder a posição. Arrastar com o mouse e a bandeja nesse modo ainda não foram conferidos manualmente. A coluna Wayland nativo segue o protocolo xdg-shell, que não expõe "sempre no topo" nem posição absoluta para clientes.

| Recurso | Wayland nativo | XWayland (`QT_QPA_PLATFORM=xcb`) |
|---|---|---|
| Sempre visível | **Ignorado pelo GNOME** | Suportado |
| Restaurar posição salva | **Não** (o compositor decide) | Sim |
| Arrastar com o mouse | Sim (`startSystemMove`) | Sim |
| Transparência | Sim (fundo translúcido) | Sim |
| Bandeja | Sim, com a extensão AppIndicator (padrão do Ubuntu) | Sim |

Por padrão (`prefer_xwayland: true`), numa sessão Wayland o NetWatch usa XWayland **se** o plugin xcb do Qt carregar (bibliotecas abaixo); senão roda em Wayland nativo e registra um aviso no log. Para instalar:

```bash
sudo apt install libxcb-cursor0 libxcb-icccm4 libxcb-keysyms1
```

A variável `QT_QPA_PLATFORM`, se definida, sempre tem precedência.
