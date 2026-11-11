#!/usr/bin/env python3
import os
import sys
import json
import subprocess
from datetime import datetime

# ========== Configuration ==========
# Persistent custom route config snippet, mounted via custom-config-file in VyOS
ROUTE_CONFIG_FILE = "/config/ocserv/custom-split-route.conf"
# Live runtime ocserv config file generated and used by the running service
RUNTIME_CONFIG_FILE = "/run/ocserv/dyize/ocserv.conf"
LOG_FILE = "/config/logs/ocserv-route-add.log"
AUTO_RELOAD = True  # Only reload ocserv when new routes are actually detected
# Occtl management socket path for target vhost
OCCTL_SOCKET = "/run/ocserv/occtl.socket"
# ===================================

def ensure_dir(file_path):
    """Auto-create parent directory for target file"""
    dir_path = os.path.dirname(file_path)
    if dir_path and not os.path.exists(dir_path):
        os.makedirs(dir_path, exist_ok=True)

def format_route_line(ip):
    """Format native ocserv route entry: route = ip/mask"""
    if ":" in ip:
        return f"route = {ip}/128"
    return f"route = {ip}/32"

def parse_routes_from_file(file_path):
    """
    Extract all 'route = CIDR' entries from any ocserv config file.
    Returns a set of route lines for fast deduplication and diff comparison.
    """
    routes = set()
    if not os.path.exists(file_path):
        return routes
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("route = "):
                    routes.add(line)
    except Exception:
        pass
    return routes

def is_route_exists(route_line):
    """Check if route entry already exists in the persistent custom config"""
    existing_routes = parse_routes_from_file(ROUTE_CONFIG_FILE)
    return route_line in existing_routes

def append_route(route_line):
    """Append new route entry to the persistent custom config file"""
    ensure_dir(ROUTE_CONFIG_FILE)
    with open(ROUTE_CONFIG_FILE, "a", encoding="utf-8") as f:
        f.write(route_line + "\n")

def sync_missing_routes_to_runtime():
    """
    Compare custom config with live runtime config.
    Append all missing routes to the runtime config file.
    Returns the total number of newly added routes.
    """
    runtime_routes = parse_routes_from_file(RUNTIME_CONFIG_FILE)
    custom_routes = parse_routes_from_file(ROUTE_CONFIG_FILE)
    missing_routes = custom_routes - runtime_routes

    if not missing_routes:
        return 0

    try:
        ensure_dir(RUNTIME_CONFIG_FILE)
        with open(RUNTIME_CONFIG_FILE, "a", encoding="utf-8") as f:
            for route in missing_routes:
                f.write(route + "\n")
    except Exception:
        pass

    return len(missing_routes)

def write_log(ip, domain, route_line, action, new_count=0):
    """Write audit log entry including actual new route count"""
    ensure_dir(LOG_FILE)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    count_suffix = f" NEW_COUNT={new_count}" if new_count > 0 else ""
    log_line = f"[{timestamp}] {action} IP={ip} DOMAIN={domain} ENTRY=\"{route_line}\"{count_suffix}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_line)

def reload_ocserv():
    """
    Gracefully reload ocserv configuration via native occtl tool.
    No impact on already connected clients; new routes take effect for new connections only.
    """
    try:
        subprocess.run(
            ["occtl", "-s", OCCTL_SOCKET, "reload"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10
        )
    except Exception:
        pass

def soft_reconnect_all():
    """
    Disconnect all online users to trigger auto-reconnect with updated routes.
    Causes ~1-3 seconds of connection interruption; most clients reconnect seamlessly.
    """
    try:
        result = subprocess.run(
            ["occtl", "-s", OCCTL_SOCKET, "-j", "show", "users"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            return

        users = json.loads(result.stdout)
        if not users:
            return

        for user in users:
            username = user.get("Username", "")
            if username:
                subprocess.run(
                    ["occtl", "-s", OCCTL_SOCKET, "disconnect", "user", username],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5
                )
    except Exception:
        pass

def main():
    # Arguments: <ip> [domain] [--soft-reconnect]
    if len(sys.argv) < 2:
        sys.exit(0)

    ip = sys.argv[1].strip()
    domain = sys.argv[2].strip() if len(sys.argv) >= 3 and not sys.argv[2].startswith("--") else ""
    enable_soft_reconnect = "--soft-reconnect" in sys.argv

    if not ip:
        sys.exit(0)

    try:
        route_line = format_route_line(ip)
        is_new = not is_route_exists(route_line)
        new_count = 0

        if is_new:
            # Step 1: Save to persistent custom config file
            append_route(route_line)

            # Step 2: Sync diff to runtime config and reload only if changes exist
            if AUTO_RELOAD:
                new_count = sync_missing_routes_to_runtime()
                if new_count >= 1:
                    reload_ocserv()

            # Step 3: Trigger soft reconnect if explicitly enabled
            if enable_soft_reconnect:
                soft_reconnect_all()
                write_log(ip, domain, route_line, "ADD_ROUTE_WITH_RECONNECT", new_count)
            else:
                write_log(ip, domain, route_line, "ADD_ROUTE", new_count)
        else:
            write_log(ip, domain, route_line, "DEDUP_SKIP", 0)

    except Exception:
        # Full fault tolerance: never break DNS main flow under any failure
        pass

if __name__ == "__main__":
    main()
