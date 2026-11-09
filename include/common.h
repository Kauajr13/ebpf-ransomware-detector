#ifndef COMMON_H
#define COMMON_H

// vmlinux.h ja define esses tipos via BTF, entao so puxa linux/types.h
// quando ele nao foi incluido, caso do lado userspace
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define TAM_AMOSTRA     512   // bytes lidos por escrita, fixo por exigencia do verificador
#define AMOSTRA_MINIMA  64    // escrita menor que isso e ignorada, maior que isso e menor
                              // que TAM_AMOSTRA so tem esse tanto amostrado
#define MAX_PROCS       1024  // capacidade do mapa lru de pid pra estat_proc
#define BYTES_MINIMOS   (64ULL * 1024)
#define LIMIAR_ARQUIVOS 10
// teto de inodes guardados por processo. limita n_arquivos, entao --files
// nunca pode passar disso ou o alerta nao dispara nunca
#define MAX_INODES      32
// sem janela um processo benigno junta volume e arquivos ao longo de horas
// e acaba parecendo cifragem em massa
#define JANELA_NS       (10ULL * 1000000000ULL)

struct estat_proc {
    __u64 total_bytes;
    __u32 histograma[256];
    __u64 ts_inicio;
    __u32 n_arquivos;
    __u64 inodes[MAX_INODES];
    __u32 _pad;
};

// histograma fica no fim pra nao abrir buraco de alinhamento entre os campos
struct evento_alerta {
    __u32 pid;
    __u32 tgid;
    char comm[16];
    __u64 total_bytes;
    __u64 ts_inicio;
    __u64 ts_ns;
    __u32 n_arquivos;
    __u32 _pad;
    __u32 histograma[256];
};

#endif /* COMMON_H */
