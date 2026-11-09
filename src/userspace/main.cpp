#include <cmath>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>

#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "ransomware_detect.skel.h"
#include "../../include/common.h"

using namespace std;

struct Configuracao {
    // 7.8 veio do ShieldFS e se manteve na calibracao, agora sobre a entropia
    // corrigida. scripts/calibrar_limiar.py refaz a conta com dados novos
    double limiarEntropia = 7.8;
    // quantil 0.999 da qui-quadrado com 255 graus de liberdade. separa
    // comprimido de cifrado, coisa que a entropia sozinha nao fez nos testes
    double maxQuiQuadrado = 325.0;
    uint64_t bytesMinimos = 65536;
    uint32_t limiarArquivos = 10;
    double janelaSeg = 10.0;
    int intervaloMs = 50;
    bool matarAoDetectar = false;
    bool verboso = false;
    string arquivoCsv;
};

volatile bool rodando = true;
Configuracao config;
ofstream csvSaida;
struct timespec tsInicio;

uint64_t monotonicoNs()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + ts.tv_nsec;
}

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

// o estimador direto subestima a entropia quando ha poucas amostras. dado
// aleatorio com 512 bytes amostrados da 7.59 e ficaria abaixo do limiar.
// a correcao de miller madow soma k-1 sobre 2n ln2, com k os valores de
// byte que apareceram, e deixa o limiar quase independente do volume
double corrigirMillerMadow(double entropia, const uint32_t histograma[256], uint64_t total)
{
    if(total == 0)
        return 0.0;

    int presentes = 0;
    for(int i = 0; i < 256; i++)
        if(histograma[i])
            presentes++;

    return entropia + (presentes - 1) / (2.0 * static_cast<double>(total) * log(2.0));
}

// distancia do histograma ate a uniforme. dado cifrado fica perto de 255, os
// graus de liberdade, e gzip ou jpg passam de 600 mesmo com entropia acima
// de 7.9, que e onde a entropia sozinha confunde os dois
double calcularQuiQuadrado(const uint32_t histograma[256], uint64_t total)
{
    if(total == 0)
        return 0.0;

    double esperado = static_cast<double>(total) / 256.0;
    double qui2 = 0.0;
    for(int i = 0; i < 256; i++) {
        double d = histograma[i] - esperado;
        qui2 += d * d / esperado;
    }
    return qui2;
}

void tratarSinal(int) { rodando = false; }

void imprimirUso(const char *prog)
{
    cerr << "uso: " << prog << " [opcoes]\n"
         << "  --threshold FLOAT   limiar de entropia corrigida para alerta (padrao: 7.8)\n"
         << "  --floor BYTES       bytes minimos dentro da janela (padrao: 65536)\n"
         << "  --files N           arquivos distintos minimos (padrao: 10, teto: "
         << MAX_INODES << ")\n"
         << "  --chi2 MAX          qui-quadrado maximo pra considerar cifrado, 0 desliga (padrao: 325)\n"
         << "  --window SEG        janela de tempo dos criterios, 0 desliga (padrao: 10)\n"
         << "  --poll MS           intervalo de poll em ms (padrao: 50)\n"
         << "  --kill              matar processo ao detectar\n"
         << "  --csv ARQUIVO       gravar todos os eventos em csv, inclusive abaixo do limiar\n"
         << "  --verbose           log de debug\n";
}

Configuracao parseArgs(int argc, char **argv)
{
    Configuracao cfg;

    try {
        for(int i = 1; i < argc; i++) {
            string arg = argv[i];
            bool temValor = i + 1 < argc;

            if(arg == "--threshold" && temValor)
                cfg.limiarEntropia = stod(argv[++i]);
            else if(arg == "--floor" && temValor)
                cfg.bytesMinimos = stoull(argv[++i]);
            else if(arg == "--files" && temValor)
                cfg.limiarArquivos = stoul(argv[++i]);
            else if(arg == "--chi2" && temValor)
                cfg.maxQuiQuadrado = stod(argv[++i]);
            else if(arg == "--window" && temValor)
                cfg.janelaSeg = stod(argv[++i]);
            else if(arg == "--poll" && temValor)
                cfg.intervaloMs = stoi(argv[++i]);
            else if(arg == "--kill")
                cfg.matarAoDetectar = true;
            else if(arg == "--csv" && temValor)
                cfg.arquivoCsv = argv[++i];
            else if(arg == "--verbose")
                cfg.verboso = true;
            else if(arg == "--help") {
                imprimirUso(argv[0]);
                exit(0);
            } else {
                // flag ignorada em silencio faria um experimento rodar com o
                // valor padrao sem ninguem perceber
                cerr << "opcao invalida ou sem valor: " << arg << "\n";
                imprimirUso(argv[0]);
                exit(2);
            }
        }
    } catch(const exception &) {
        cerr << "valor numerico invalido\n";
        imprimirUso(argv[0]);
        exit(2);
    }

    // o lado kernel so guarda MAX_INODES inodes por processo, entao um limiar
    // acima disso nunca seria alcancado e o alerta ficaria mudo pra sempre
    if(cfg.limiarArquivos > MAX_INODES) {
        cerr << "aviso: --files " << cfg.limiarArquivos << " passa do teto de "
             << MAX_INODES << ", limitando\n";
        cfg.limiarArquivos = MAX_INODES;
    }
    if(cfg.janelaSeg < 0)
        cfg.janelaSeg = 0;

    return cfg;
}

int tratarEvento(void *ctx, void *dados, size_t tamanho)
{
    (void)ctx; // a callback do ring_buffer exige a assinatura, nao uso o ctx
    if(tamanho < sizeof(evento_alerta))
        return 0;

    uint64_t tsUser = monotonicoNs();
    const auto *ev = static_cast<const evento_alerta *>(dados);

    uint64_t totalAmostrado = 0;
    for(int i = 0; i < 256; i++)
        totalAmostrado += ev->histograma[i];

    double h = calcularEntropia(ev->histograma, totalAmostrado);
    double hCorr = corrigirMillerMadow(h, ev->histograma, totalAmostrado);
    double qui2 = calcularQuiQuadrado(ev->histograma, totalAmostrado);
    bool acima = hCorr >= config.limiarEntropia &&
                 (config.maxQuiQuadrado <= 0 || qui2 <= config.maxQuiQuadrado);

    double tempoMs = (tsUser - (static_cast<uint64_t>(tsInicio.tv_sec) * 1000000000ULL +
                                tsInicio.tv_nsec)) / 1e6;

    uint64_t tsKill = 0;
    if(acima) {
        cout << "[ALERTA] PID=" << ev->tgid << " PROC=" << ev->comm
             << " H=" << fixed << setprecision(4) << hCorr << " bits/byte"
             << " QUI2=" << setprecision(1) << qui2 << setprecision(4)
             << " BYTES=" << ev->total_bytes
             << " ARQUIVOS=" << ev->n_arquivos
             << " TEMPO=" << setprecision(1) << tempoMs << " ms" << endl;

        if(config.matarAoDetectar) {
            // manda no tgid pra derrubar o processo inteiro, nao so a thread
            // que caiu no kprobe
            kill(static_cast<pid_t>(ev->tgid), SIGKILL);
            tsKill = monotonicoNs();
            cout << "[BLOQUEIO] SIGKILL enviado para PID " << ev->tgid << endl;
        }
    } else if(config.verboso) {
        cerr << "[verbose] PID " << ev->tgid << " (" << ev->comm
             << "): H=" << fixed << setprecision(4) << hCorr << " bits, QUI2="
             << setprecision(1) << qui2 << ", nao parece cifrado\n";
    }

    // evento abaixo do limiar tambem vai pro csv, porque e dele que sai a
    // taxa de falso positivo na hora de calibrar
    if(csvSaida.is_open()) {
        csvSaida << ev->tgid << "," << ev->comm << ","
                 << fixed << setprecision(6) << h << "," << hCorr << ","
                 << setprecision(2) << qui2 << "," << setprecision(6)
                 << (acima ? 1 : 0) << ","
                 << ev->total_bytes << "," << totalAmostrado << "," << ev->n_arquivos << ","
                 << ev->ts_inicio << "," << ev->ts_ns << "," << tsUser << "," << tsKill << ","
                 << setprecision(3) << tempoMs << "\n";
        csvSaida.flush();
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
        // ts em ns do CLOCK_MONOTONIC, mesmo relogio do bpf_ktime_get_ns, entao
        // da pra subtrair direto do instante em que o simulador comecou
        csvSaida << "pid,proc,entropia,entropia_mm,qui2,acima_limiar,total_bytes,amostras,"
                    "n_arquivos,ts_inicio_ns,ts_evento_ns,ts_user_ns,ts_kill_ns,tempo_ms\n";
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
    skel->rodata->cfg_janela_ns = static_cast<uint64_t>(config.janelaSeg * 1e9);

    if(ransomware_detect_bpf__load(skel)) {
        cerr << "erro ao carregar programa eBPF, rode com --verbose pro log do verificador\n";
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
         << " bits/byte, qui2 max=" << config.maxQuiQuadrado << ", minimo=" << config.bytesMinimos << " bytes, janela="
         << config.janelaSeg << " s"
         << (config.matarAoDetectar ? ", kill ativo" : ", modo monitor")
         << "\n[*] ctrl+c para encerrar" << endl;

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
