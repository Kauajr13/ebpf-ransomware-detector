// simulador de ransomware pra testar deteccao, reescreve os arquivos de um
// diretorio com dados de /dev/urandom, entropia alta, imitando cifragem em massa.
// destrutivo, so roda em diretorio de teste descartavel.
//
// uso ./sim_encrypt diretorio, aceita --delay-ms N e --max-files N opcionais

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define TAM_BUFFER    (64 * 1024)
#define ATRASO_PADRAO 0
#define MAX_PADRAO    1000

int atrasoMs = ATRASO_PADRAO;
int maxArquivos = MAX_PADRAO;
int arquivosCifrados = 0;
int fdAleatorio = -1;
char bufferDados[TAM_BUFFER];

long msAgora(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

int cifrarArquivo(const char *caminho)
{
    struct stat info;
    if(stat(caminho, &info) < 0)
        return -1;
    if(!S_ISREG(info.st_mode) || info.st_size == 0)
        return 0;

    long tamanho = info.st_size;
    int fd = open(caminho, O_WRONLY | O_TRUNC);
    if(fd < 0) {
        perror(caminho);
        return -1;
    }

    long escrito = 0;
    while(escrito < tamanho) {
        long resto = tamanho - escrito;
        long lote = resto < TAM_BUFFER ? resto : TAM_BUFFER;

        ssize_t r = read(fdAleatorio, bufferDados, lote);
        if(r <= 0)
            break;

        ssize_t w = write(fd, bufferDados, r);
        if(w != r) {
            perror("write");
            close(fd);
            return -1;
        }
        escrito += w;
    }

    fsync(fd);
    close(fd);

    printf("[CIFRADO] %s (%ld bytes)\n", caminho, tamanho);
    return 0;
}

void processarDiretorio(const char *dirAlvo)
{
    if(arquivosCifrados >= maxArquivos)
        return;

    DIR *diretorio = opendir(dirAlvo);
    if(!diretorio) {
        perror(dirAlvo);
        return;
    }

    struct dirent *entrada;
    char caminho[4096];

    while((entrada = readdir(diretorio)) != NULL && arquivosCifrados < maxArquivos) {
        if(!strcmp(entrada->d_name, ".") || !strcmp(entrada->d_name, ".."))
            continue;

        snprintf(caminho, sizeof(caminho), "%s/%s", dirAlvo, entrada->d_name);

        struct stat info;
        if(stat(caminho, &info) < 0)
            continue;

        if(S_ISREG(info.st_mode)) {
            if(cifrarArquivo(caminho) == 0)
                arquivosCifrados++;
            if(atrasoMs > 0)
                usleep(atrasoMs * 1000);
        } else if(S_ISDIR(info.st_mode)) {
            processarDiretorio(caminho);
        }
    }

    closedir(diretorio);
}

int main(int argc, char *argv[])
{
    if(argc < 2) {
        fprintf(stderr, "uso: %s <diretorio> [--delay-ms N] [--max-files N]\n", argv[0]);
        fprintf(stderr, "aviso: sobrescreve arquivos com dados aleatorios!\n");
        return 1;
    }

    const char *dirAlvo = argv[1];

    int i = 2;
    while(i < argc) {
        if(!strcmp(argv[i], "--delay-ms") && i + 1 < argc)
            atrasoMs = atoi(argv[++i]);
        else if(!strcmp(argv[i], "--max-files") && i + 1 < argc)
            maxArquivos = atoi(argv[++i]);
        i++;
    }

    struct stat info;
    if(stat(dirAlvo, &info) < 0 || !S_ISDIR(info.st_mode)) {
        fprintf(stderr, "diretorio invalido: %s\n", dirAlvo);
        return 1;
    }

    fdAleatorio = open("/dev/urandom", O_RDONLY);
    if(fdAleatorio < 0) {
        perror("open /dev/urandom");
        return 1;
    }

    long tInicio = msAgora();
    fprintf(stderr, "[*] simulando cifragem em %s, max %d arquivos\n", dirAlvo, maxArquivos);

    processarDiretorio(dirAlvo);

    long tempo = msAgora() - tInicio;
    fprintf(stderr, "[*] concluido: %d arquivos em %ld ms (%.1f arq/s)\n",
            arquivosCifrados, tempo,
            tempo > 0 ? arquivosCifrados * 1000.0 / tempo : 0.0);

    close(fdAleatorio);
    return 0;
}
