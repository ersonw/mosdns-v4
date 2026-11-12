#!/usr/bin/env python3
"""Turn one ocserv up/down hook invocation into an event for mosdns.

Reads the environment ocserv exports, appends a human readable line to the
local audit log (fallback for a stopped mosdns), and sends one JSON object to
the ocserv_ctl unix socket. There is no Telegram push here on purpose: the
plugin records the event and the bot exposes it as /vpn events.
"""

import json
import os
import socket
import time
import urllib.request

# mosdns ocserv_ctl event_socket. Override with MOSDNS_EVENT_SOCKET.
EVENT_SOCKET = os.environ.get("MOSDNS_EVENT_SOCKET", "/run/mosdns/ocserv-updown.sock")
AUDIT_LOG = os.environ.get("OCSERV_AUDIT_LOG", "/config/ocserv-audit.log")
IP_API_TIMEOUT = 3
SOCKET_TIMEOUT = 2


def env(key, default=""):
    return os.environ.get(key, default) or default


def query_ip_info(ip):
    """Best effort geo/AS lookup; ip-api.com is free and needs no key."""
    if not ip:
        return None
    try:
        url = "http://ip-api.com/json/%s?lang=en" % ip
        with urllib.request.urlopen(url, timeout=IP_API_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if data.get("status") == "success":
            return data
    except Exception:
        pass
    return None


def int_env(key):
    try:
        return max(0, int(env(key, "0")))
    except (TypeError, ValueError):
        return 0


def write_audit(line):
    try:
        os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def send_event(payload):
    """One JSON line over the unix socket; the reply is read but not required."""
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(SOCKET_TIMEOUT)
        s.connect(EVENT_SOCKET)
        s.sendall((json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"))
        try:
            s.recv(4096)
        except Exception:
            pass
        s.close()
        return True
    except Exception:
        return False


def main():
    reason = env("REASON").lower()
    if reason not in ("connect", "disconnect"):
        return

    username = env("USERNAME")
    if not username:
        return

    real_ip = env("IP_REAL")
    vpn_ip = env("IP_REMOTE")
    vpn_ipv6 = env("IPV6_REMOTE")
    device = env("DEVICE")
    group = env("GROUPNAME")
    rx_bytes = int_env("STATS_BYTES_IN")
    tx_bytes = int_env("STATS_BYTES_OUT")
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    info = query_ip_info(real_ip)
    if info:
        geo = " / ".join(
            str(info.get(k, "")) for k in ("country", "regionName", "city") if info.get(k)
        )
        isp = str(info.get("isp", ""))
        as_info = str(info.get("as", ""))
        tags = []
        if info.get("proxy"):
            tags.append("Proxy")
        if info.get("hosting"):
            tags.append("IDC")
        ip_type = "/".join(tags) if tags else "residential"
    else:
        geo, isp, as_info, ip_type = "", "", "", ""

    if reason == "disconnect":
        audit = (
            '[%s] EVENT=disconnect USER=%s REAL_IP=%s GEO="%s" VPN_IP=%s '
            'RX_BYTES=%d TX_BYTES=%d'
            % (timestamp, username, real_ip, geo, vpn_ip, rx_bytes, tx_bytes)
        )
    else:
        audit = (
            '[%s] EVENT=connect USER=%s REAL_IP=%s GEO="%s" VPN_IP=%s VPN_IPV6=%s '
            "DEVICE=%s GROUP=%s"
            % (timestamp, username, real_ip, geo, vpn_ip, vpn_ipv6, device, group)
        )
    write_audit(audit)

    send_event(
        {
            "event": reason,
            "user": username,
            "real_ip": real_ip,
            "vpn_ip": vpn_ip,
            "vpn_ipv6": vpn_ipv6,
            "device": device,
            "group": group,
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
            "geo": geo,
            "isp": isp,
            "as": as_info,
            "ip_type": ip_type,
            "time": timestamp,
        }
    )


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # The hook must never fail the VPN handshake.
        pass
