#!/bin/sh
# Async wrapper: run python script in background
# Does NOT block DNS resolution, avoids context deadline exceeded
nohup python3 /config/mosdns/nat_map.py "$@" > /dev/null 2>&1 &
exit 0
