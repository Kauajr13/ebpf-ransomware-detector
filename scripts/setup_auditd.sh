#!/usr/bin/env bash
# setup_auditd.sh, Configura o auditd como baseline de comparação
# roda como root antes de compare_detectors.sh

set -euo pipefail

TARGET_DIR="${1:-/tmp/compare_target}"

echo "[*] Configurando auditd para monitorar $TARGET_DIR"

systemctl is-active auditd > /dev/null 2>&1 || {
    echo "ERRO: auditd não está ativo. Instale e inicie com:"
    echo "  apt install auditd && systemctl start auditd"
    exit 1
}

# limpa regras anteriores
auditctl -D

# regra pra auditar escritas no diretorio alvo
auditctl -w "$TARGET_DIR" -p w -k ransomware_baseline

# aumenta rate limit pra nao perder eventos sob carga alta
auditctl -r 10000

echo "[*] Regras configuradas:"
auditctl -l

echo "[*] Para verificar eventos: ausearch -k ransomware_baseline --raw"
