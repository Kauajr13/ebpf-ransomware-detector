# requer clang-18, llvm-18, libbpf-dev 1.3, bpftool 7.4

CC       := clang-18
CXX      := clang++-18
BPFTOOL  := bpftool

# arquivos de origem
BPF_SRC   := src/bpf/ransomware_detect.bpf.c
BPF_OBJ   := src/bpf/ransomware_detect.bpf.o
SKEL_H    := src/bpf/ransomware_detect.skel.h
VMLINUX_H := include/vmlinux.h
MAIN_SRC  := src/userspace/main.cpp
TARGET    := ransomware_detect

# flags para o programa eBPF, compilação pro bytecode BPF
BPF_CFLAGS := \
    -g \
    -O2 \
    -fno-builtin \
    -target bpf \
    -D__TARGET_ARCH_x86 \
    -I./include \
    -I/usr/include/x86_64-linux-gnu

# flags para o userspace, C++17 e libbpf
CXX_FLAGS := \
    -std=c++17 \
    -O2 \
    -Wall \
    -Wextra \
    -I./include \
    -I./src/bpf

CXX_LDFLAGS := -lbpf -lelf -lz

.PHONY: all clean distclean vmlinux check-env tests bench

all: check-env $(TARGET)

# verifica dependências antes de qualquer build
check-env:
	@echo "[*] Verificando ambiente..."
	@$(CC) --version | head -1
	@$(BPFTOOL) version | head -1
	@ls /sys/kernel/btf/vmlinux > /dev/null 2>&1 || \
		(echo "ERRO: /sys/kernel/btf/vmlinux não encontrado. BTF não habilitado no kernel." && exit 1)
	@pkg-config --modversion libbpf 2>/dev/null || \
		(echo "AVISO: libbpf não encontrado via pkg-config. Continuando...")
	@echo "[*] Ambiente OK"

# gera vmlinux.h, roda uma vez ou quando o kernel for atualizado
vmlinux: $(VMLINUX_H)

$(VMLINUX_H):
	@echo "[*] Gerando $@..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@
	@echo "[*] vmlinux.h gerado ($(shell wc -l < $@) linhas)"

# compila o programa eBPF pra bytecode BPF
$(BPF_OBJ): $(BPF_SRC) $(VMLINUX_H) include/common.h
	@echo "[*] Compilando programa eBPF..."
	$(CC) $(BPF_CFLAGS) -c -o $@ $<
	@echo "[*] Verificando com llvm-objdump..."
	@llvm-objdump-18 -d $@ | head -5 || true

# gera o skeleton C a partir do objeto eBPF
$(SKEL_H): $(BPF_OBJ)
	@echo "[*] Gerando skeleton..."
	$(BPFTOOL) gen skeleton $< > $@
	@echo "[*] Skeleton gerado: $@"

# compila o loader userspace
$(TARGET): $(SKEL_H) $(MAIN_SRC) include/common.h
	@echo "[*] Compilando userspace..."
	$(CXX) $(CXX_FLAGS) -o $@ $(MAIN_SRC) $(CXX_LDFLAGS) -I./src/bpf
	@echo "[*] Build concluído: ./$(TARGET)"

# compila os simuladores de teste
tests: tests/sim_encrypt tests/sim_benign

tests/sim_encrypt: tests/sim_encrypt.c
	gcc -O2 -o $@ $<

tests/sim_benign: tests/sim_benign.c
	gcc -O2 -o $@ $<

# executa o benchmark
bench: $(TARGET) tests
	@echo "[*] Executando benchmark..."
	bash bench/run_bench.sh

# limpa artefatos de build, preserva vmlinux.h que é caro de gerar
clean:
	rm -f $(BPF_OBJ) $(SKEL_H) $(TARGET) tests/sim_encrypt tests/sim_benign
	@echo "[*] Build limpo (vmlinux.h preservado)"

# limpa tudo, incluindo vmlinux.h
distclean: clean
	rm -f $(VMLINUX_H)
