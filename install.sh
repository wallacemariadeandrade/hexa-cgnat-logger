#!/bin/bash
chmod +x cgnat_bpa_lookup.py
chmod +x nfdump-watchdog.sh
apt install nfdump php tcpdump -y
cp nfdump-cgnat-logs.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now nfdump-cgnat-logs.service
CRON_JOB1="0 4 * * * find /var/cache/nfdump -name 'nfcapd.*' -type f -mtime +365 -delete"
CRON_JOB2="*/5 * * * * /var/opt/hexa-cgnat-logger/nfcapd-watchdog.sh"
(crontab -l 2>/dev/null | grep -Fv "$CRON_JOB1"; echo "$CRON_JOB1") | crontab -
(crontab -l 2>/dev/null | grep -Fv "$CRON_JOB2"; echo "$CRON_JOB2") | crontab -
systemctl is-active nfdump nfdump-cgnat-logs.service