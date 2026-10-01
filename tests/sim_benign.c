// gera carga benigna de escrita, texto de baixa entropia, pra rodar junto
// do detector e checar taxa de falsos positivos.
//
// uso ./sim_benign diretorio-saida, aceita --files N e --size-kb N opcionais

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define QTDE_PADRAO       100
#define TAMANHO_PADRAO_KB 64

const char *TEXTO_BASE =
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
    "Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. "
    "Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris. "
    "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum. "
    "Excepteur sint occaecat cupidatat non proident, sunt in culpa qui. ";

int main(int argc, char *argv[])
{
    if(argc < 2) {
        fprintf(stderr, "uso: %s <diretorio-saida> [--files N] [--size-kb N]\n", argv[0]);
        return 1;
    }

    const char *dirSaida = argv[1];
    int qtdeArquivos = QTDE_PADRAO;
    int tamanhoKb = TAMANHO_PADRAO_KB;

    for(int i = 2; i < argc; i++) {
        if(!strcmp(argv[i], "--files") && i + 1 < argc)
            qtdeArquivos = atoi(argv[++i]);
        else if(!strcmp(argv[i], "--size-kb") && i + 1 < argc)
            tamanhoKb = atoi(argv[++i]);
    }

    fprintf(stderr, "[*] carga benigna: %d arquivos de %d KB em %s\n",
            qtdeArquivos, tamanhoKb, dirSaida);

    size_t tamTexto = strlen(TEXTO_BASE);
    size_t alvo = (size_t)tamanhoKb * 1024;
    char caminho[4096];

    for(int i = 0; i < qtdeArquivos; i++) {
        snprintf(caminho, sizeof(caminho), "%s/benigno_%04d.txt", dirSaida, i);

        FILE *fp = fopen(caminho, "w");
        if(!fp) {
            perror(caminho);
            continue;
        }

        size_t escrito = 0;
        while(escrito < alvo) {
            size_t resto = alvo - escrito;
            size_t lote = resto < tamTexto ? resto : tamTexto;
            fwrite(TEXTO_BASE, 1, lote, fp);
            escrito += lote;
        }

        fflush(fp);
        fclose(fp);
    }

    fprintf(stderr, "[*] carga benigna concluida: %d arquivos\n", qtdeArquivos);
    return 0;
}
