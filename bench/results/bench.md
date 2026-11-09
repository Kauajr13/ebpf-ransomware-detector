# Resultados do benchmark

## Overhead

Média ± desvio padrão entre repetições. CPU sys é do fio, que é onde o tempo do kprobe aparece, porque o programa eBPF roda no contexto de quem escreve. CPU do agente é o processo em espaço de usuário.

| carga | MB/s sem | MB/s com | perda de vazão | p99 µs sem | p99 µs com | CPU sys % sem | CPU sys % com | ns por kprobe | CPU do agente s | reps |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| seq_64k | 191.3 ± 32.6 | 225.4 ± 79.6 | -17.8% | 17104.9 ± 2023.7 | 12137.7 ± 7179.1 | 12.4 | 14.7 | 1784 | 0.014 | 5 |
| seq_4k | 140.6 ± 46.3 | 139.1 ± 13.4 | +1.1% | 16.5 ± 2.9 | 21.2 ± 1.2 | 10.4 | 13.6 | 1448 | 0.022 | 5 |
| rand_4k | 99.3 ± 5.9 | 88.4 ± 7.2 | +11.0% | 21.9 ± 1.3 | 30.0 ± 3.9 | 11.3 | 12.7 | 1566 | 0.018 | 5 |
| muitos_arquivos | 104.8 ± 54.9 | 92.6 ± 52.0 | +11.6% | 34.9 ± 4.1 | 44.7 ± 8.8 | 15.1 | 14.0 | 1852 | 0.418 | 5 |

![overhead](../plots/overhead.png)

## Tempo até o bloqueio

ms até o kill vai do primeiro instante do simulador até o SIGKILL, no mesmo CLOCK_MONOTONIC. Arquivos perdidos são contados no disco depois do kill, inclusive o que ficou truncado pela metade.

| cenário | arquivo KiB | atraso ms | bloqueado | arquivos perdidos | de | ms até o kill | kernel até agente µs |
| --- | --- | --- | --- | --- | --- | --- | --- |
| rapido | 16 | 0 | 5/5 | 10.0 ± 0.0 | 300 | 13.4 ± 0.5 | 51 ± 13 |
| rapido | 64 | 0 | 5/5 | 10.0 ± 0.0 | 300 | 17.6 ± 0.6 | 51 ± 19 |
| rapido | 256 | 0 | 5/5 | 10.0 ± 0.0 | 300 | 31.6 ± 1.1 | 55 ± 15 |
| lento | 64 | 500 | 3/3 | 10.0 ± 0.0 | 40 | 4565.4 ± 26.6 | 96 ± 6 |
| lento | 64 | 1500 | 0/3 | 40.0 ± 0.0 | 40 | - | - |

![arquivos perdidos](../plots/arquivos_perdidos.png)

