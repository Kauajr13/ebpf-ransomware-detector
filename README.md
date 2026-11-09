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
   bytes são descartadas, e também tudo o que não é arquivo regular. Pipe,
   socket e terminal passam por `vfs_write` igual, e tráfego TLS ou SSH tem
   entropia perto de 8 espalhada por vários descritores.
2. O programa copia uma amostra do buffer do usuário com `bpf_probe_read_user`:
   512 bytes quando a escrita tem pelo menos isso, 64 bytes quando é menor. São
   dois tamanhos fixos porque o verificador não aceita leitura de tamanho
   variável, e ler 512 de uma escrita menor puxaria lixo da memória do processo.
3. Para cada TGID, acumula um histograma de 256 posições com a frequência de
   cada valor de byte, o total de bytes escritos e a lista de inodes distintos
   que o processo tocou (até 32). Esse estado vive num LRU hash map com
   capacidade para 1024 processos. Um tracepoint em `sched_process_exit` apaga
   a entrada quando o processo termina. Com um hash map comum, entrada de
   processo morto nunca saía, e depois de 1024 processos o detector ficava cego.
4. Os critérios valem dentro de uma janela de 10 segundos por padrão. Passado
   esse tempo o estado do processo é zerado. Sem a janela, um processo benigno
   juntava 64 KiB em 10 arquivos ao longo de horas e acabava alertando.
5. Quando um processo cruza os dois limiares dentro da janela, 64 KiB escritos e
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
3. Aplica a correção de Miller-Madow, somando `(k - 1) / (2 n ln 2)`, onde `k` é
   o número de valores de byte que apareceram. O estimador direto subestima a
   entropia quando há poucas amostras. Dado aleatório com 512 bytes amostrados
   dá 7,59 sem a correção, abaixo do limiar, e 7,90 com ela.
4. Calcula o qui-quadrado do histograma contra a distribuição uniforme. Dado
   cifrado fica perto de 255, que são os graus de liberdade. Saída de gzip ou
   JPG passa de 600 mesmo com entropia acima de 7,9. É o critério que separou
   arquivo comprimido de arquivo cifrado nos testes, coisa que a entropia
   sozinha não conseguiu.
5. Se a entropia corrigida alcança o limiar, 7,8 por padrão, e o qui-quadrado
   fica abaixo de 325, imprime o alerta com PID, nome do processo, entropia,
   qui-quadrado, bytes e arquivos. Com `--kill`, envia SIGKILL ao TGID,
   derrubando o processo inteiro e não apenas a thread que caiu no kprobe. Com
   `--csv`, grava em disco todo evento, inclusive os que ficaram abaixo do
   limiar, porque são eles que dão a taxa de falso positivo na calibração.

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
| `--threshold FLOAT` | Limiar da entropia corrigida para o alerta, em bits por byte | 7.8 |
| `--chi2 MAX` | Qui-quadrado máximo para considerar o dado cifrado, 0 desliga | 325 |
| `--floor BYTES` | Bytes escritos dentro da janela antes de o processo ser avaliado | 65536 |
| `--files N` | Arquivos distintos mínimos, com teto de 32 | 10 |
| `--window SEG` | Janela de tempo dos critérios, 0 desliga | 10 |
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

Tudo de uma vez, cerca de 25 minutos:

```sh
make && make tests                 # como usuário comum
sudo apt install fio               # única dependência que costuma faltar
sudo bash bench/run_all.sh
```

O `run_all.sh` testa primeiro se o verificador aceita o programa e mostra o log
se recusar. Depois roda os dois experimentos abaixo, devolve os arquivos ao seu
usuário e gera `bench/results/bench.md` e `bench/results/fp/calibracao.md`. A
fase de kill roda o detector com `--kill` no sistema todo, então feche programas
que gravam muito arquivo comprimido durante o teste.

`bench/run_bench.sh` tem duas fases:

1. Overhead com fio em quatro cargas: escrita sequencial de 64 KiB e de 4 KiB,
   escrita aleatória de 4 KiB e 200 arquivos pequenos. Cada carga roda sem e com
   o detector, 5 vezes, em ordem alternada. Mede vazão, latência p99, CPU de
   sistema do fio, CPU do agente e o custo por chamada do kprobe pelo
   `kernel.bpf_stats_enabled`. O fio usa `psync`: com `libaio`, que a versão
   anterior usava, o `io_submit` não passa por `vfs_write`, o detector não via a
   carga e o overhead saía zero por engano.
2. Tempo até o bloqueio com `sim_encrypt` e `--kill`, em arquivos de 16, 64 e
   256 KiB. O simulador imprime o instante de início no mesmo `CLOCK_MONOTONIC`
   do kernel, e o detector grava o instante do SIGKILL. Os arquivos perdidos são
   contados no disco depois do kill. Também roda um ransomware lento, com 500 ms
   e 1500 ms entre arquivos, para mostrar onde a janela de 10 s deixa passar.

`bench/falsos_positivos.sh` roda o detector em modo monitor enquanto executa
cargas benignas de entropia alta e controles positivos:

| Carga | Classe | O que faz |
| --- | --- | --- |
| `gzip_muitos` | benigna | 200 arquivos `.gz` num processo, como logrotate |
| `tar_gz`, `zip_r` | benigna | um arquivo compactado grande |
| `extrair_fotos` | benigna | `tar x` de 60 JPGs |
| `ffmpeg_jpg_ruido` | benigna | 60 JPGs gerados com ruído, o pior caso |
| `ffmpeg_hls` | benigna | vídeo transcodificado em segmentos de 2 s |
| `git_clone` | benigna | clone local com packfile |
| `sim_benign` | benigna | texto, entropia baixa |
| `nao_regular` | benigna | dado aleatório em 12 sockets |
| `cifragem_legitima` | positiva | AES-256-CTR com openssl, 40 arquivos num processo |
| `sim_encrypt_16k`, `_64k`, `_256k` | positiva | o simulador |
| `ocioso` | benigna | 60 s sem carga, só o que o sistema já faz |

`scripts/calibrar_limiar.py` lê esses eventos e compara três regras de decisão.

Sem root, `EMULAR=1 bash bench/falsos_positivos.sh` roda cada carga sob strace,
e `scripts/emular_detector.py` reproduz a lógica do kprobe sobre o trace. Com
`-xx -s 512 -y`, o strace mostra os primeiros 512 bytes de cada escrita e o tipo
do descritor, que é o que o kprobe vê.

`bench/compare_detectors.sh` coloca o detector eBPF ao lado de auditd e inotify.
Ainda não foi revisado. auditd e inotify só registram eventos e não decidem
nada, então a comparação de tempo de detecção precisa de um baseline que também
calcule entropia e mate o processo.

## Resultados preliminares, por emulação

`bench/results/fp_emulado/calibracao.md` traz 39 execuções, 3 por carga, emuladas
por strace:

| Regra | Execuções benignas com alarme falso | Detecção |
| --- | --- | --- |
| entropia comum ≥ 7,8, a regra anterior | 6 de 39, todas de `gzip_muitos` e `extrair_fotos` | 100% |
| Miller-Madow ≥ 7,8 | 9 de 39 | 100% |
| Miller-Madow sozinho, no melhor limiar, 7,99 | 0 | 100%, com margem de só 0,012 bit |
| **Miller-Madow ≥ 7,8 e qui-quadrado ≤ 325** | **0** | **100%** |

A entropia sozinha não separa gzip e JPG de cifragem: o `gzip_muitos` chega a
7,958 e o `extrair_fotos` a 7,986. O qui-quadrado separa com folga. Todo evento
de cifragem ficou entre 209 e 327, e todo evento benigno de entropia alta ficou
acima de 618. O corte de 325 é o quantil 0,999 da qui-quadrado com 255 graus de
liberdade, tirado da teoria e não ajustado nos dados. Com a regra combinada,
qualquer limiar de entropia entre 7,0 e 7,995 dá o mesmo resultado. O 7,8 foi
mantido por ser o mais próximo do original e o mais robusto para amostra
pequena.

Esses números ainda precisam ser confirmados pelo detector real com
`run_all.sh`.

`bench/results/legado/` guarda os 8 alertas da versão anterior. A entropia deles
saiu entre 7,92 e 7,93 e não perto de 8, porque o stdout do simulador ia para um
arquivo regular e as linhas de texto entravam no histograma.

## Estrutura

```
src/bpf/ransomware_detect.bpf.c   programa eBPF, kprobe e histograma
src/userspace/main.cpp            agente, entropia, alertas e bloqueio
include/common.h                  structs e limiares compartilhados
tests/                            simuladores de cifragem e de carga benigna
bench/                            scripts de experimento e resultados
scripts/                          auditd, emulação, calibração e gráficos
docs/                             relatório, slides e cronograma
```

## Limitações conhecidas

- A entropia é calculada sobre a amostra do começo de cada escrita, não sobre
  todo o conteúdo gravado.
- Só `write` e `pwrite64` passam por `vfs_write`. `writev`, `io_submit` do
  libaio, `io_uring` e `copy_file_range` usam outros caminhos no kernel, e um
  ransomware que escreva por eles não é visto.
- Cifragem intermitente, que cifra só parte de cada arquivo, deixa o
  histograma longe da uniforme e passa no corte do qui-quadrado.
- Um processo que intercala escritas de texto em arquivo regular, como uma nota
  de resgate, dilui a entropia do próprio histograma. Foi o que aconteceu sem
  querer com os 8 alertas antigos.
- Ransomware mais lento que 10 arquivos na janela de 10 s não é detectado. A
  fase 2 de `run_bench.sh` mede isso.
- O estado cabe em 1024 processos e 32 inodes por processo. No LRU, um ataque
  com muitos processos de vida curta pode despejar a entrada do processo que
  está cifrando.
- O histograma por processo é atualizado sem lock. Threads do mesmo processo em
  CPUs diferentes podem perder incrementos.
- O kprobe em `vfs_write` depende de um símbolo interno do kernel, que não tem
  ABI estável entre versões.
- O bloqueio chega depois do alerta e passa pelo espaço de usuário, então alguns
  arquivos já estão cifrados quando o SIGKILL é enviado. A fase 2 de
  `run_bench.sh` mede quantos.
- Os positivos de teste são o simulador, que usa `/dev/urandom`, e AES-CTR do
  openssl. Falta validar com amostras reais de ransomware.

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
