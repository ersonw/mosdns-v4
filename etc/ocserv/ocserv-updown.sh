#!/bin/sh
# ocserv up/down hook.
#
# Two jobs, in this order:
#   1. shape the tun device (VRF from the group name, then bring it up);
#   2. hand the session event to mosdns through its unix socket, in the
#      background, so a slow geo lookup or a stopped mosdns never delays the
#      VPN handshake.
#
# Nothing here talks to Telegram. The events are recorded by mosdns and can
# be read later with /vpn events or from event_log.

if [ "$REASON" = "connect" ]; then
    ip link set dev "${DEVICE}" down
    sleep 1

    VRF=${GROUPNAME%%V-g*}
    REALGROUP=${GROUPNAME##*V-g}

    if [ "${VRF}" = "" ]; then
        ip link set dev "${DEVICE}" nomaster
    else
        ip link set dev "${DEVICE}" master "${VRF}"
    fi

    ip link set dev "${DEVICE}" up
fi

# Backgrounded: ocserv must not wait for the recorder.
( python3 "$(dirname "$0")/ocserv_notify.py" ) >/dev/null 2>&1 &

exit 0
