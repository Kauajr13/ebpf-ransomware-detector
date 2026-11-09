# Calibração do limiar, fp

40 execuções, 254 eventos, 66 vindos do processo que cifrou.

Taxas por execução. Uma execução benigna conta como alarme falso se qualquer evento dela passa na regra, porque com --kill isso já derruba o processo.

## Regras

| regra | detecção em 7.8 | execuções com falso em 7.8 | limiar recomendado | faixa empatada | detecção | execuções com falso |
| --- | --- | --- | --- | --- | --- | --- |
| entropia comum | 100% | 6/40 | 7.935 | 7.935 a 7.96 | 100% | 3/40 |
| miller-madow | 100% | 9/40 | 7.99 | 7.99 a 7.995 | 100% | 0/40 |
| miller-madow + qui2 | 100% | 0/40 | 7.8 | 7.0 a 7.995 | 100% | 0/40 |

qui2 limite = 325, quantil 0,999 da qui-quadrado com 255 graus de liberdade. Não é ajustado nos dados, vem da teoria.

## Por carga, regra miller-madow + qui2 em 7.8

| carga | classe | eventos | H_mm min | H_mm max | qui2 min | qui2 max | alarme H>=7.8 | alarme recomendado |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ocioso | negativo | 2 | 6.126 | 6.163 | 1366597 | 2469637 | 0/1 | 0/1 |
| gzip_muitos | negativo | 48 | 7.915 | 7.959 | 731 | 1198 | 3/3 | 0/3 |
| tar_gz | negativo | 0 | - | - | - | - | 0/3 | 0/3 |
| zip_r | negativo | 0 | - | - | - | - | 0/3 | 0/3 |
| extrair_fotos | negativo | 18 | 7.984 | 7.986 | 6228 | 7127 | 3/3 | 0/3 |
| ffmpeg_jpg_ruido | negativo | 18 | 7.782 | 7.810 | 9970 | 12260 | 0/3 | 0/3 |
| ffmpeg_hls | negativo | 6 | 7.470 | 7.473 | 99418 | 102165 | 0/3 | 0/3 |
| git_clone | negativo | 9 | 5.164 | 5.420 | 53588 | 118310 | 0/3 | 0/3 |
| sim_benign | negativo | 33 | 4.133 | 4.136 | 1134468 | 1265953 | 0/3 | 0/3 |
| nao_regular | negativo | 0 | - | - | - | - | 0/3 | 0/3 |
| cifragem_legitima | positivo | 12 | 7.987 | 8.003 | 235 | 361 | 3/3 | 3/3 |
| sim_encrypt_16k | positivo | 18 | 7.994 | 8.002 | 235 | 300 | 3/3 | 3/3 |
| sim_encrypt_64k | positivo | 18 | 7.991 | 8.007 | 206 | 309 | 3/3 | 3/3 |
| sim_encrypt_256k | positivo | 18 | 7.998 | 8.001 | 220 | 300 | 3/3 | 3/3 |

Margem pela entropia sozinha, menor máximo de execução positiva menos maior evento negativo, +0.012 bits por byte.

![calibracao_entropia_fp.png](../../plots/calibracao_entropia_fp.png)
![calibracao_qui2_fp.png](../../plots/calibracao_qui2_fp.png)
