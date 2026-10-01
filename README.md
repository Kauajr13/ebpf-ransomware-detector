# Monitoramento de ransomware em nível de kernel com eBPF

Detector que identifica cifragem em massa de arquivos enquanto ela acontece. Um
programa eBPF observa as escritas dentro do kernel e o agente em espaço de
usuário mede a entropia de Shannon dos dados gravados. Não há assinaturas
envolvidas: a decisão vem do comportamento de escrita do processo, então o
detector não precisa conhecer o malware de antemão.

Trabalho de Conclusão de Curso em Bacharelado em Ciência da Computação, UNESP
Bauru. Título registrado: "Monitoramento de Ransomware em Nível de Kernel
Utilizando eBPF e Análise de Entropia".

## Como funciona

No kernel, em `src/bpf/ransomware_detect.bpf.c`:

1. Um kprobe em `vfs_write` intercepta cada escrita. Escritas menores que 64
   bytes são descartadas.
2. O programa copia uma amostra de 512 bytes do buffer do usuário com
   `bpf_probe_read_user`. O tamanho é fixo porque o verificador do BPF não
   aceita leitura de tamanho variável.
3. Para cada TGID, acumula um histograma de 256 posições com a frequência de
   cada valor de byte, o total de bytes escritos e a lista de inodes distintos
   que o processo tocou (até 32). Esse estado vive num hash map com capacidade
   para 1024 processos.
4. Quando um processo cruza os dois limiares ao mesmo tempo, 64 KiB escritos e
   10 arquivos distintos por padrão, o programa publica o histograma num ring
   buffer de 256 KiB e zera os contadores daquele processo, para o mesmo PID não
   inundar o canal.

No espaço de usuário, em `src/userspace/main.cpp`:

1. O agente carrega e anexa o programa pelo skeleton do libbpf, gravando os
   limiares em `rodata` antes do load.
2. Lê os alertas do ring buffer e calcula a entropia de Shannon do histograma em
   bits por byte, onde 8 é o máximo. O cálculo usa `log2(h) - log2(total)` em
   vez de `log2(p)`, porque a precisão do `double` sofre quando `p` fica muito
   pequeno.
3. Se a entropia alcança o limiar, 7,8 por padrão, imprime o alerta com PID,
   nome do processo, entropia, bytes e tempo decorrido. Com `--kill`, envia
   SIGKILL ao TGID, derrubando o processo inteiro e não apenas a thread que caiu
   no kprobe. Com `--csv`, grava cada evento em disco.

Dividir o trabalho assim mantém o laço quente no kernel enxuto: o histograma é
um incremento por byte amostrado, e o logaritmo, que é caro, só roda em espaço
de usuário quando um alerta já foi emitido.

## Requisitos

- Kernel Linux com BTF habilitado, ou seja, com `/sys/kernel/btf/vmlinux`
  presente
- clang-18 e llvm-18
- libbpf-dev 1.3
- bpftool 7.4
- Privilégio de root para carregar o programa eBPF
- Para os benchmarks: fio, auditd, inotify-tools e python3 com pandas e
  matplotlib

## Compilação

```sh
make vmlinux   # gera include/vmlinux.h a partir do BTF do kernel
make           # compila o programa eBPF, o skeleton e o agente
make tests     # compila os simuladores de carga
```

Rode `make vmlinux` uma vez, e de novo quando trocar de kernel. O alvo
`check-env` roda antes do build e aborta se faltar clang, bpftool ou BTF.

`make clean` remove os artefatos e preserva o `vmlinux.h`, que é caro de gerar.
`make distclean` apaga o `vmlinux.h` também.

## Uso

```sh
sudo ./ransomware_detect [opções]
```

| Opção | Efeito | Padrão |
| --- | --- | --- |
| `--threshold FLOAT` | Limiar de entropia para o alerta, em bits por byte | 7.8 |
| `--floor BYTES` | Bytes escritos antes de o processo ser avaliado | 65536 |
| `--files N` | Arquivos distintos mínimos, com teto de 32 | 10 |
| `--poll MS` | Intervalo de poll do ring buffer | 50 |
| `--kill` | Envia SIGKILL ao processo detectado | desligado |
| `--csv ARQUIVO` | Grava os eventos em CSV | desligado |
| `--verbose` | Mostra também os eventos abaixo do limiar | desligado |

O kernel guarda no máximo 32 inodes por processo, então `--files` acima disso
nunca seria alcançado. O agente detecta esse caso, avisa e limita o valor.

## Testes

`tests/sim_encrypt` imita a cifragem em massa: percorre um diretório e
sobrescreve cada arquivo com bytes de `/dev/urandom`, produzindo entropia alta.
Ele destrói os arquivos que encontra, então use apenas um diretório
descartável.

`tests/sim_benign` gera a carga de controle, arquivos de texto repetido e
entropia baixa, para medir falsos positivos.

## Benchmarks

`bench/run_bench.sh` mede o custo do detector com fio, comparando throughput,
IOPS e latência p99 de escrita sem o detector e com ele em modo monitor.

`bench/compare_detectors.sh` coloca o detector eBPF ao lado de auditd e inotify,
registrando quantos arquivos foram cifrados antes do bloqueio e quanto tempo a
cifragem levou. auditd e inotify entram como linha de base de observação, já que
nenhum dos dois bloqueia o processo por conta própria.

`scripts/setup_auditd.sh` prepara as regras do auditd. `scripts/plot_results.py`
gera os gráficos de overhead, de comparação e de distribuição de entropia. Os
dois scripts de benchmark precisam de root.

Os resultados versionados em `bench/results/ebpf_events.csv` trazem 8 alertas
disparados pelo `sim_encrypt`, com entropia entre 7,9235 e 7,9327 bits por byte
e 160 KiB acumulados por alerta. O histograma correspondente está em
`bench/plots/entropy_distribution.png`.

## Estrutura

```
src/bpf/ransomware_detect.bpf.c   programa eBPF, kprobe e histograma
src/userspace/main.cpp            agente, entropia, alertas e bloqueio
include/common.h                  structs e limiares compartilhados
tests/                            simuladores de cifragem e de carga benigna
bench/                            scripts de experimento e resultados
scripts/                          auditd e geração dos gráficos
docs/                             relatório, slides e cronograma
```

## Limitações conhecidas

- A entropia é calculada sobre a amostra de 512 bytes de cada escrita, não sobre
  todo o conteúdo gravado.
- O limiar de 7,8 veio do ShieldFS e ainda não foi calibrado com os dados dos
  experimentos.
- O estado cabe em 1024 processos e 32 inodes por processo. Além disso, eventos
  são perdidos.
- O kprobe em `vfs_write` depende de um símbolo interno do kernel, que não tem
  ABI estável entre versões.
- O bloqueio chega depois do alerta, então alguns arquivos já estão cifrados
  quando o SIGKILL é enviado. Quantificar essa janela é justamente o que
  `compare_detectors.sh` faz.
- A fase 3 de `run_bench.sh` conta os arquivos perdidos, mas ainda não cronometra
  o tempo até o kill.

## Documentos

`docs/` contém o relatório parcial, os slides da apresentação e o cronograma.

## Licença

Todos os direitos reservados. Leia o arquivo `LICENSE` antes de usar qualquer
parte deste repositório.

O arquivo `src/bpf/ransomware_detect.bpf.c` é a única exceção: ele carrega o
cabeçalho SPDX `GPL-2.0` e declara `GPL` ao kernel, o que o kernel exige de
qualquer programa BPF que use helpers restritos como `bpf_probe_read_user`.

## Autoria

Kauã Junior Silva Soares, RA 231024061.
Orientador: Prof. Dr. Kelton Augusto Pontara da Costa.
UNESP Bauru, Faculdade de Ciências, Departamento de Computação.
