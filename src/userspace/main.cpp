#include <cmath>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>

#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "ransomware_detect.skel.h"
#include "../../include/common.h"

using namespace std;

struct Configuracao {
    // TODO calibrar nos experimentos, 7.8 veio do ShieldFS
    double limiarEntropia = 7.8;
    uint64_t bytesMinimos = 65536;
    uint32_t limiarArquivos = 10;
    int intervaloMs = 50;
    bool matarAoDetectar = false;
    bool verboso = false;
    string arquivoCsv;
};

volatile bool rodando = true;
Configuracao config;
ofstream csvSaida;
struct timespec tsInicio;

double calcularEntropia(const uint32_t histograma[256], uint64_t total)
{
    if(total == 0)
        return 0.0;

    double entropia = 0.0;
    double log2Total = log2(static_cast<double>(total));

    for(int i = 0; i < 256; i++) {
        if(histograma[i] == 0)
            continue;
        double p = static_cast<double>(histograma[i]) / static_cast<double>(total);
        // log2(h) - log2(total) da o mesmo que log2(p), mas sem calcular o log
        // de um p minusculo, onde a precisao do double ja comeca a doer
        entropia -= p * (log2(static_cast<double>(histograma[i])) - log2Total);
    }
    return entropia;
}

void tratarSinal(int) { rodando = false; }

void imprimirUso(const char *prog)
{
    cerr << "uso: " << prog << " [opcoes]\n"
         << "  --threshold FLOAT   limiar de entropia para alerta (padrao: 7.8)\n"
         << "  --floor BYTES       bytes minimos antes de avaliar (padrao: 65536)\n"
         << "  --files N           arquivos distintos minimos (padrao: 10, teto: "
         << MAX_INODES << ")\n"
         << "  --poll MS           intervalo de poll em ms (padrao: 50)\n"
         << "  --kill              matar processo ao detectar\n"
         << "  --csv ARQUIVO       gravar eventos em csv\n"
         << "  --verbose           log de debug\n";
}

Configuracao parseArgs(int argc, char **argv)
{
    Configuracao cfg;

    for(int i = 1; i < argc; i++) {
        string arg = argv[i];

        if(arg == "--threshold" && i + 1 < argc)
            cfg.limiarEntropia = atof(argv[++i]);
        else if(arg == "--floor" && i + 1 < argc)
            cfg.bytesMinimos = stoull(argv[++i]);
        else if(arg == "--files" && i + 1 < argc)
            cfg.limiarArquivos = stoul(argv[++i]);
        else if(arg == "--poll" && i + 1 < argc)
            cfg.intervaloMs = stoi(argv[++i]);
        else if(arg == "--kill")
            cfg.matarAoDetectar = true;
        else if(arg == "--csv" && i + 1 < argc)
            cfg.arquivoCsv = argv[++i];
        else if(arg == "--verbose")
            cfg.verboso = true;
        else if(arg == "--help") {
            imprimirUso(argv[0]);
            exit(0);
        }
    }

    // o lado kernel so guarda MAX_INODES inodes por processo, entao um limiar
    // acima disso nunca seria alcancado e o alerta ficaria mudo pra sempre
    if(cfg.limiarArquivos > MAX_INODES) {
        cerr << "aviso: --files " << cfg.limiarArquivos << " passa do teto de "
             << MAX_INODES << ", limitando\n";
        cfg.limiarArquivos = MAX_INODES;
    }

    return cfg;
}

int tratarEvento(void *ctx, void *dados, size_t tamanho)
{
    (void)ctx; // a callback do ring_buffer exige a assinatura, nao uso o ctx
    if(tamanho < sizeof(evento_alerta))
        return 0;

    const auto *ev = static_cast<const evento_alerta *>(dados);

    uint64_t totalAmostrado = 0;
    for(int i = 0; i < 256; i++)
        totalAmostrado += ev->histograma[i];

    double h = calcularEntropia(ev->histograma, totalAmostrado);

    struct timespec agora;
    clock_gettime(CLOCK_MONOTONIC, &agora);
    double tempoMs = (agora.tv_sec - tsInicio.tv_sec) * 1000.0 +
                     (agora.tv_nsec - tsInicio.tv_nsec) / 1e6;

    if(h < config.limiarEntropia) {
        if(config.verboso)
            cerr << "[verbose] PID " << ev->tgid << " (" << ev->comm
                 << "): H=" << fixed << setprecision(4) << h << " bits, abaixo do limiar\n";
        return 0;
    }

    cout << "[ALERTA] PID=" << ev->tgid << " PROC=" << ev->comm
         << " H=" << fixed << setprecision(4) << h << " bits/byte"
         << " BYTES=" << ev->total_bytes
         << " TEMPO=" << setprecision(1) << tempoMs << " ms" << endl;

    if(csvSaida.is_open()) {
        csvSaida << ev->tgid << "," << ev->comm << ","
                 << fixed << setprecision(6) << h << ","
                 << ev->total_bytes << "," << setprecision(3) << tempoMs << "\n";
        csvSaida.flush();
    }

    if(config.matarAoDetectar) {
        cout << "[BLOQUEIO] enviando SIGKILL para PID " << ev->tgid << endl;
        // manda no tgid pra derrubar o processo inteiro, nao so a thread
        // que caiu no kprobe
        kill(static_cast<pid_t>(ev->tgid), SIGKILL);
    }

    return 0;
}

int imprimirLibbpf(enum libbpf_print_level nivel, const char *formato, va_list args)
{
    if(nivel == LIBBPF_DEBUG && !config.verboso)
        return 0;
    return vfprintf(stderr, formato, args);
}

void aumentarMemlock()
{
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    if(setrlimit(RLIMIT_MEMLOCK, &rl))
        perror("setrlimit(RLIMIT_MEMLOCK)");
}

int main(int argc, char **argv)
{
    config = parseArgs(argc, argv);

    if(!config.arquivoCsv.empty()) {
        csvSaida.open(config.arquivoCsv);
        if(!csvSaida.is_open()) {
            cerr << "erro ao abrir csv: " << config.arquivoCsv << "\n";
            return 1;
        }
        csvSaida << "pid,proc,entropia,total_bytes,tempo_ms\n";
    }

    aumentarMemlock();
    libbpf_set_print(imprimirLibbpf);

    ransomware_detect_bpf *skel = ransomware_detect_bpf__open();
    if(!skel) {
        cerr << "erro ao abrir skeleton eBPF\n";
        return 1;
    }

    skel->rodata->cfg_bytes_minimos = config.bytesMinimos;
    skel->rodata->cfg_limiar_arquivos = config.limiarArquivos;
    skel->rodata->cfg_emitir_alertas = 1;

    if(ransomware_detect_bpf__load(skel)) {
        cerr << "erro ao carregar programa eBPF\n";
        ransomware_detect_bpf__destroy(skel);
        return 1;
    }

    if(ransomware_detect_bpf__attach(skel)) {
        cerr << "erro ao anexar kprobe em vfs_write\n";
        ransomware_detect_bpf__destroy(skel);
        return 1;
    }

    ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.ring_alertas),
                                       tratarEvento, nullptr, nullptr);
    if(!rb) {
        cerr << "erro ao criar ring buffer\n";
        ransomware_detect_bpf__destroy(skel);
        return 1;
    }

    signal(SIGINT, tratarSinal);
    signal(SIGTERM, tratarSinal);

    clock_gettime(CLOCK_MONOTONIC, &tsInicio);

    cout << "[*] detector ativo, limiar=" << config.limiarEntropia
         << " bits/byte, minimo=" << config.bytesMinimos << " bytes"
         << (config.matarAoDetectar ? ", kill ativo" : ", modo monitor")
         << "\n[*] ctrl+c para encerrar\n";

    while(rodando) {
        int erro = ring_buffer__poll(rb, config.intervaloMs);
        if(erro < 0 && erro != -EINTR) {
            cerr << "erro no ring buffer poll: " << erro << "\n";
            break;
        }
    }

    cout << "\n[*] encerrando detector\n";

    ring_buffer__free(rb);
    ransomware_detect_bpf__destroy(skel);

    if(csvSaida.is_open())
        csvSaida.close();

    return 0;
}
