#!/bin/sh
set -eu

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

RULE=/etc/mosdns/rule/tiktok_ip.txt
TMP=/tmp/tiktok_ip.txt.new
GEN=/usr/local/bin/gen_tiktok_capture.py

python3 "$GEN" --out "$TMP" >/dev/null 2>&1 || { echo "generator failed"; exit 1; }

if cmp -s "$TMP" "$RULE"; then
    echo "capture list unchanged, mosdns left running"
    rm -f "$TMP"
    exit 0
fi

cp "$TMP" "$RULE"
rm -f "$TMP"
mosdns service restart || { echo "mosdns restart failed"; exit 1; }
echo "capture list updated, mosdns restarted"
