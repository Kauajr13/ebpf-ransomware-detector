// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../../include/common.h"

// fora da arvore do kernel essa anotacao sparse nao existe
#define __user

// macros de modo de arquivo nao vem no vmlinux.h, que so traz tipos
#ifndef S_IFMT
#define S_IFMT  00170000
#endif
#ifndef S_IFREG
#define S_IFREG 0100000
#endif

// lru em vez de hash comum porque entrada de processo morto nunca sairia
// sozinha e o mapa lotava, deixando o detector cego pra processo novo
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_PROCS);
    __type(key, __u32);
    __type(value, struct estat_proc);
} mapa_proc SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ring_alertas SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[TAM_AMOSTRA]);
} buf_amostra SEC(".maps");

// estat_proc passa de 512 bytes e nao cabe zerada na stack do bpf.
// mantem uma entrada sempre zerada aqui e copia pro hash map na criacao.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct estat_proc);
} mapa_zero SEC(".maps");

const volatile __u64 cfg_bytes_minimos = BYTES_MINIMOS;
const volatile __u32 cfg_limiar_arquivos = LIMIAR_ARQUIVOS;
const volatile __u32 cfg_emitir_alertas = 1;
const volatile __u64 cfg_janela_ns = JANELA_NS;

static __always_inline struct estat_proc *pegar_ou_criar(__u32 tgid, __u64 agora)
{
    struct estat_proc *st = bpf_map_lookup_elem(&mapa_proc, &tgid);
    if(st)
        return st;

    __u32 k0 = 0;
    struct estat_proc *tmpl = bpf_map_lookup_elem(&mapa_zero, &k0);
    if(!tmpl)
        return NULL;

    bpf_map_update_elem(&mapa_proc, &tgid, tmpl, BPF_NOEXIST);
    st = bpf_map_lookup_elem(&mapa_proc, &tgid);
    if(!st) // checagem dupla obrigatoria pro verificador
        return NULL;

    st->ts_inicio = agora;
    return st;
}

// laco sem unroll de proposito, chamado de dois lugares e desenrolado
// dobraria o tamanho do programa. kernel 5.3 em diante aceita laco limitado
static __always_inline void zerar_estat(struct estat_proc *st, __u64 agora)
{
    st->total_bytes = 0;
    st->n_arquivos = 0;
    st->ts_inicio = agora;

    #pragma clang loop unroll(disable)
    for(int i = 0; i < 256; i++)
        st->histograma[i] = 0;

    #pragma clang loop unroll(disable)
    for(int i = 0; i < MAX_INODES; i++)
        st->inodes[i] = 0;
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(kprobe_vfs_write, struct file *file, const char __user *buf,
               size_t count, loff_t *pos)
{
    if(count < AMOSTRA_MINIMA)
        return 0;

    // pipe, socket e tty tambem passam por vfs_write. trafego tls ou ssh tem
    // entropia perto de 8 e espalha por varios descritores, o que bateria os
    // tres criterios sem nenhum arquivo ser cifrado
    umode_t modo = BPF_CORE_READ(file, f_inode, i_mode);
    if((modo & S_IFMT) != S_IFREG)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    if(tgid == 0)
        return 0;

    __u32 zero = 0;
    char *amostra = bpf_map_lookup_elem(&buf_amostra, &zero);
    if(!amostra)
        return 0;

    // leitura segura do buffer de usuario, nunca deref direto. ler TAM_AMOSTRA
    // numa escrita menor puxaria lixo da memoria do processo pro histograma,
    // e tamanho variavel o verificador nao aceita, entao sao dois tamanhos fixos
    bool cheia = count >= TAM_AMOSTRA;
    long lido = cheia ? bpf_probe_read_user(amostra, TAM_AMOSTRA, buf)
                      : bpf_probe_read_user(amostra, AMOSTRA_MINIMA, buf);
    if(lido < 0)
        return 0;

    __u64 agora = bpf_ktime_get_ns();
    struct estat_proc *st = pegar_ou_criar(tgid, agora);
    if(!st)
        return 0;

    if(cfg_janela_ns && agora - st->ts_inicio > cfg_janela_ns)
        zerar_estat(st, agora);

    // acumula histograma, mascara garante ao verificador que o indice
    // fica entre 0 e 255. sem break dependente de count dentro do laco,
    // senao cada iteracao vira um caminho a mais pro verificador explorar
    if(cheia) {
        #pragma unroll
        for(int i = 0; i < TAM_AMOSTRA; i++) {
            __u8 idx = (__u8)amostra[i] & 0xff;
            st->histograma[idx]++;
        }
    } else {
        #pragma unroll
        for(int i = 0; i < AMOSTRA_MINIMA; i++) {
            __u8 idx = (__u8)amostra[i] & 0xff;
            st->histograma[idx]++;
        }
    }

    st->total_bytes += count;

    // inode 0 nao existe em arquivo real, entao serve de sentinela pra
    // marcar o fim da lista e cortar a busca cedo
    __u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
    bool visto = false;

    #pragma unroll
    for(int i = 0; i < MAX_INODES; i++) {
        __u64 v = st->inodes[i];
        if(v == 0)
            break;
        if(v == ino) {
            visto = true;
            break;
        }
    }

    if(!visto && st->n_arquivos < MAX_INODES) {
        st->inodes[st->n_arquivos] = ino;
        st->n_arquivos++;
    }

    if(!cfg_emitir_alertas)
        return 0;
    if(st->total_bytes < cfg_bytes_minimos || st->n_arquivos < cfg_limiar_arquivos)
        return 0;

    struct evento_alerta *ev = bpf_ringbuf_reserve(&ring_alertas, sizeof(*ev), 0);
    if(!ev)
        return 0;

    ev->pid = (__u32)pid_tgid;
    ev->tgid = tgid;
    ev->total_bytes = st->total_bytes;
    ev->ts_inicio = st->ts_inicio;
    ev->ts_ns = agora;
    ev->n_arquivos = st->n_arquivos;
    ev->_pad = 0;
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    #pragma unroll
    for(int i = 0; i < 256; i++)
        ev->histograma[i] = st->histograma[i];

    bpf_ringbuf_submit(ev, 0);

    // zera tudo pra nao inundar o ring buffer com o mesmo processo
    zerar_estat(st, agora);
    return 0;
}

// o lru ja impede o mapa de lotar, mas apagar na saida evita que processo
// vivo seja despejado por causa de entrada de processo que ja morreu
SEC("tracepoint/sched/sched_process_exit")
int limpar_saida(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;

    // so o lider do grupo, senao a saida de uma thread apagaria o estado
    // do processo que continua rodando
    if((__u32)pid_tgid != tgid)
        return 0;

    bpf_map_delete_elem(&mapa_proc, &tgid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
