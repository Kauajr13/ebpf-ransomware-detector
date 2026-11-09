# Resultados do benchmark

## Overhead

Média ± desvio padrão entre repetições. CPU sys é do fio, que é onde o tempo do kprobe aparece, porque o programa eBPF roda no contexto de quem escreve. CPU do agente é o processo em espaço de usuário.

| carga | MB/s sem | MB/s com | perda de vazão | p99 µs sem | p99 µs com | CPU sys % sem | CPU sys % com | ns por kprobe | CPU do agente s | reps |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| seq_64k | 7965.0 ± 451.9 | 7294.2 ± 249.8 | +8.4% | 29.2 ± 4.4 | 29.6 ± 2.5 | 89.1 | 89.2 | 1212 | 0.016 | 5 |
| seq_4k | 3930.3 ± 228.3 | 2140.1 ± 180.2 | +45.5% | 2.6 ± 0.2 | 5.6 ± 0.6 | 64.0 | 74.3 | 1154 | 0.010 | 5 |
| rand_4k | 3612.0 ± 36.3 | 2147.0 ± 73.6 | +40.6% | 2.4 ± 0.1 | 5.1 ± 0.6 | 63.4 | 73.1 | 1027 | 0.010 | 5 |
| muitos_arquivos | 3380.0 ± 327.4 | 2814.6 ± 229.6 | +16.7% | 10.0 ± 4.7 | 14.1 ± 4.3 | 75.6 | 77.8 | 1401 | 0.016 | 5 |

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

