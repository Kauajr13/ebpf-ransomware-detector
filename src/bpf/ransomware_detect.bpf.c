// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../../include/common.h"

// fora da arvore do kernel essa anotacao sparse nao existe
#define __user

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
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

static __always_inline struct estat_proc *pegar_ou_criar(__u32 tgid)
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

    st->ts_inicio = bpf_ktime_get_ns();
    return st;
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(kprobe_vfs_write, struct file *file, const char __user *buf,
               size_t count, loff_t *pos)
{
    if(count < 64)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    if(tgid == 0)
        return 0;

    __u32 zero = 0;
    char *amostra = bpf_map_lookup_elem(&buf_amostra, &zero);
    if(!amostra)
        return 0;

    // leitura segura do buffer de usuario, nunca deref direto
    if(bpf_probe_read_user(amostra, TAM_AMOSTRA, buf) < 0)
        return 0;

    struct estat_proc *st = pegar_ou_criar(tgid);
    if(!st)
        return 0;

    // acumula histograma, mascara garante ao verificador que o indice
    // fica entre 0 e 255
    #pragma unroll
    for(int i = 0; i < TAM_AMOSTRA; i++) {
        __u8 idx = (__u8)amostra[i] & 0xff;
        st->histograma[idx]++;
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
    ev->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    #pragma unroll
    for(int i = 0; i < 256; i++)
        ev->histograma[i] = st->histograma[i];

    bpf_ringbuf_submit(ev, 0);

    // zera tudo pra nao inundar o ring buffer com o mesmo processo
    st->total_bytes = 0;
    st->n_arquivos = 0;

    #pragma unroll
    for(int i = 0; i < 256; i++)
        st->histograma[i] = 0;

    #pragma unroll
    for(int i = 0; i < MAX_INODES; i++)
        st->inodes[i] = 0;

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
