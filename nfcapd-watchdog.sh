#!/bin/bash
# nfcapd-watchdog.sh: reinicia o nfdump quando a coleta trava
# (processo vivo, mas arquivos vazios ou sem rotação).
#
# Cron (crontab -e, como root):
#   */5 * * * * /usr/local/sbin/nfcapd-watchdog.sh
#
# Histórico das intervenções:  grep nfcapd-watchdog /var/log/syslog
#                         ou:  journalctl -t nfcapd-watchdog

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

DIR=${DIR:-/var/cache/nfdump}   # diretório dos nfcapd.*
SVC=${SVC:-nfdump}              # unit do systemd
MIN_BYTES=1024                  # arquivo de 5 min menor que isso = vazio
MAX_AGE=900                     # 15 min sem arquivo novo = rotação parada
COOLDOWN=1800                   # no máximo 1 restart a cada 30 min
STAMP=${STAMP:-/var/run/nfcapd-watchdog.last}

log() { logger -t nfcapd-watchdog "$*"; }

# último arquivo fechado (ignora o nfcapd.current.*)
ultimo=$(ls -1t "$DIR"/nfcapd.2* 2>/dev/null | head -1)
agora=$(date +%s)
motivo=""

if [ -z "$ultimo" ]; then
    motivo="nenhum arquivo nfcapd em $DIR"
else
    idade=$(( agora - $(stat -c %Y "$ultimo") ))
    tam=$(stat -c %s "$ultimo")
    if [ "$idade" -gt "$MAX_AGE" ]; then
        motivo="nenhum arquivo novo há $(( idade / 60 )) min (último: $(basename "$ultimo"))"
    elif [ "$tam" -lt "$MIN_BYTES" ]; then
        motivo="último arquivo com $tam bytes ($(basename "$ultimo"))"
    fi
fi

[ -z "$motivo" ] && exit 0

# evita loop de restart se o problema persistir
if [ -f "$STAMP" ] && [ $(( agora - $(stat -c %Y "$STAMP") )) -lt "$COOLDOWN" ]; then
    log "FALHA persistente: $motivo. Restart recente, aguardando o cooldown."
    exit 1
fi

touch "$STAMP"
log "Coleta parada: $motivo. Reiniciando $SVC."
if systemctl restart "$SVC"; then
    log "$SVC reiniciado."
else
    log "ERRO ao reiniciar $SVC."
    exit 2
fi