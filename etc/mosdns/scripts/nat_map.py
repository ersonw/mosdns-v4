#!/usr/bin/env python3
import os
import re
import sys
import socket
import sqlite3
import logging
import ipaddress
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# ========== Log Configuration ==========
ENABLE_LOG = False
LOG_FILE = "/config/mosdns/nat_map.log"
MAX_LOG_SIZE = 2 * 1024 * 1024
# =======================================

# ========== Route Configuration ==========
# Global switch for host route creation
ENABLE_HOST_ROUTE = True
# Default route table to write routes into (main = system main table)
DEFAULT_ROUTE_TABLE = "main"
# Enable strict CIDR route aggregation: merge adjacent /32 routes into larger subnets
# Strict mode: only merge perfectly aligned and contiguous networks, no over-expansion
ENABLE_ROUTE_AGGREGATION = True
# =======================================

def init_logging():
    if not ENABLE_LOG:
        logging.disable(logging.CRITICAL)
        return

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > MAX_LOG_SIZE:
        with open(LOG_FILE, "w") as f:
            f.truncate(0)

    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

def run_cmd(cmd, timeout=10, check=False):
    cmd_str = " ".join(cmd)
    logging.info(f"[CMD] Execute: {cmd_str}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check
        )
        logging.info(f"[CMD] Exit code: {result.returncode}")

        stdout = result.stdout.strip()
        if stdout:
            logging.info(f"[CMD] stdout:\n{stdout}")

        stderr = result.stderr.strip()
        if stderr:
            logging.info(f"[CMD] stderr:\n{stderr}")

        return result

    except subprocess.TimeoutExpired:
        logging.error(f"[CMD] Timeout after {timeout}s: {cmd_str}")
        if check:
            raise
        return subprocess.CompletedProcess(cmd, 1, "", "timeout")

    except Exception as e:
        logging.error(f"[CMD] Failed: {cmd_str} | Error: {str(e)}")
        if check:
            raise
        return subprocess.CompletedProcess(cmd, 1, "", str(e))

def get_names(prefix):
    sanitized = re.sub(r'[^a-zA-Z0-9_]', '_', prefix)
    db_table = f"{sanitized}_real_ips"
    nft_table = f"fakeip_{sanitized}"
    return db_table, nft_table

def get_system_default_route():
    logging.info("[STEP] Detect system default route as fallback")
    res = run_cmd(["ip", "route", "show", "default"])
    via, dev = "", ""
    if res.returncode == 0 and res.stdout.strip():
        parts = res.stdout.strip().splitlines()[0].split()
        if "via" in parts:
            idx = parts.index("via")
            if idx + 1 < len(parts):
                via = parts[idx + 1]
        if "dev" in parts:
            idx = parts.index("dev")
            if idx + 1 < len(parts):
                dev = parts[idx + 1]
    logging.info(f"[RESULT] Default route: via={via}, dev={dev}")
    return via, dev

def ensure_nft_table(table_name, cidr, out_dev=""):
    logging.info(f"[STEP] Check nftables table: {table_name}")
    res = run_cmd(["nft", "list", "table", "ip", table_name])
    if res.returncode != 0:
        logging.info(f"[INFO] Table not found, creating with egress interface: {out_dev}")
        cmds = [
            ["nft", "add", "table", "ip", table_name],
            ["nft", "add", "map", "ip", table_name, "dnat_map", "{ type ipv4_addr : ipv4_addr; }"],
            ["nft", "add", "chain", "ip", table_name, "prerouting", "{ type nat hook prerouting priority -100; policy accept; }"],
            ["nft", "add", "rule", "ip", table_name, "prerouting", "ip", "daddr", cidr, "dnat", "to", "ip", "daddr", "map", "@dnat_map"],
            ["nft", "add", "chain", "ip", table_name, "forward", "{ type filter hook forward priority -10; policy accept; }"],
            ["nft", "add", "rule", "ip", table_name, "forward", "ip", "daddr", cidr, "drop"],
            ["nft", "add", "chain", "ip", table_name, "postrouting", "{ type nat hook postrouting priority 100; policy accept; }"]
        ]
        if out_dev:
            cmds.append(["nft", "add", "rule", "ip", table_name, "postrouting", "oifname", out_dev, "masquerade"])
        for cmd in cmds:
            run_cmd(cmd)
    else:
        logging.info(f"[INFO] Table {table_name} already exists, keep original egress configuration")

def apply_host_route(real_ip, next_hop, next_hop_dev, route_table="main"):
    if not ENABLE_HOST_ROUTE:
        logging.info("[SKIP] Host route disabled by global config, skip")
        return

    if not next_hop and not next_hop_dev:
        logging.info("[SKIP] No next hop or device, skip host route")
        return

    cmd = ["ip", "route", "replace", f"{real_ip}/32"]
    if next_hop:
        cmd.extend(["via", next_hop])
    if next_hop_dev:
        cmd.extend(["dev", next_hop_dev])
    
    if route_table and route_table != "main":
        cmd.extend(["table", route_table])

    logging.info(f"[STEP] Add host route for {real_ip} (table: {route_table})")
    run_cmd(cmd, check=False)

def check_ip_reachable(ip, timeout=1.0):
    logging.info(f"[CHECK] Testing reachability: {ip}")
    for port in (443, 80):
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                logging.info(f"[RESULT] {ip}:{port} TCP connect success")
                return ip, True
        except Exception as e:
            logging.info(f"[RESULT] {ip}:{port} TCP connect failed: {str(e)}")
            continue

    logging.info(f"[CHECK] Fallback to ping test: {ip}")
    res = run_cmd(["ping", "-c", "1", "-W", "1", ip], timeout=3)
    if res.returncode == 0:
        logging.info(f"[RESULT] {ip} ping success")
        return ip, True

    logging.info(f"[RESULT] {ip} unreachable")
    return ip, False

def get_current_mapped_ip(table_name, fake_ip):
    logging.info(f"[STEP] Query current DNAT mapping for fake IP: {fake_ip}")
    res = run_cmd(["nft", "list", "map", "ip", table_name, "dnat_map"], check=False)
    
    if res.returncode != 0:
        logging.info("[RESULT] Map not found, no existing mapping")
        return None

    pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)\s*:\s*(\d+\.\d+\.\d+\.\d+)')
    for match in pattern.finditer(res.stdout):
        if match.group(1) == fake_ip:
            real_ip = match.group(2)
            logging.info(f"[RESULT] Current mapping: {fake_ip} -> {real_ip}")
            return real_ip
    
    logging.info("[RESULT] No existing mapping found")
    return None

def get_all_mapped_real_ips(table_name):
    """Extract all unique real IPs from dnat_map, return list of /32 IPv4Network objects"""
    logging.info("[STEP] Extract all real IPs from DNAT map for aggregation")
    res = run_cmd(["nft", "list", "map", "ip", table_name, "dnat_map"], check=False)
    
    if res.returncode != 0:
        logging.info("[SKIP] Map not found, skip aggregation")
        return []

    pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)\s*:\s*(\d+\.\d+\.\d+\.\d+)')
    real_ips = set()
    for match in pattern.finditer(res.stdout):
        real_ips.add(match.group(2))

    networks = []
    for ip in real_ips:
        try:
            net = ipaddress.IPv4Network(f"{ip}/32", strict=False)
            networks.append(net)
        except Exception:
            continue

    logging.info(f"[RESULT] Found {len(networks)} unique real IPs in map")
    return networks

def aggregate_strict(networks):
    """
    Strict CIDR aggregation using standard library.
    Only merges perfectly aligned, contiguous networks.
    Returns list of aggregated IPv4Network objects; unmergeable entries are kept as-is.
    """
    if not networks:
        return []
    collapsed = list(ipaddress.collapse_addresses(networks))
    return collapsed

def sync_aggregated_routes(next_hop, next_hop_dev, route_table, nft_table):
    """
    Full route aggregation sync:
    1. Read all /32 host routes from DNAT map
    2. Run strict CIDR aggregation
    3. Delete all old individual host routes from the target routing table
    4. Write aggregated CIDR routes to the target routing table
    """
    if not ENABLE_HOST_ROUTE:
        logging.info("[SKIP] Host route disabled, skip aggregation")
        return

    logging.info("[STEP] Run strict route aggregation")

    # Get all mapped real IPs as /32 networks
    old_networks = get_all_mapped_real_ips(nft_table)
    if not old_networks:
        logging.info("[SKIP] No mapped IPs, nothing to aggregate")
        return

    logging.info(f"[AGGREGATE] Before: {len(old_networks)} individual /32 routes")

    # Run strict aggregation
    aggregated = aggregate_strict(old_networks)
    logging.info(f"[AGGREGATE] After: {len(aggregated)} aggregated CIDR entries")

    # Step 1: Remove all old /32 host routes
    deleted = 0
    for net in old_networks:
        cmd = ["ip", "route", "delete", str(net)]
        if route_table and route_table != "main":
            cmd.extend(["table", route_table])
        res = run_cmd(cmd, check=False)
        if res.returncode == 0:
            deleted += 1

    logging.info(f"[AGGREGATE] Deleted {deleted} old host routes")

    # Step 2: Add new aggregated routes
    added = 0
    for net in aggregated:
        cmd = ["ip", "route", "replace", str(net)]
        if next_hop:
            cmd.extend(["via", next_hop])
        if next_hop_dev:
            cmd.extend(["dev", next_hop_dev])
        if route_table and route_table != "main":
            cmd.extend(["table", route_table])
        res = run_cmd(cmd, check=False)
        if res.returncode == 0:
            added += 1

    logging.info(f"[AGGREGATE] Added {added} aggregated CIDR routes")

def load_candidates_from_arg(arg_str):
    if not arg_str or not arg_str.strip():
        return []
    ips = [ip.strip() for ip in arg_str.split(",") if ip.strip()]
    valid_ips = []
    for ip in ips:
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
            valid_ips.append(ip)
    return valid_ips

def load_candidates_from_db(db_path, ip_table, domain):
    logging.info("[STEP] Load candidate IPs from SQLite database")
    conn = sqlite3.connect(db_path, timeout=5.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    try:
        rows = conn.execute(
            f"SELECT real_ip FROM {ip_table} WHERE domain = ? ORDER BY last_seen DESC LIMIT 15",
            (domain,)
        ).fetchall()
    finally:
        conn.close()
    return [r[0] for r in rows]

def main():
    init_logging()
    logging.info("=" * 70)
    logging.info("SCRIPT STARTED")
    logging.info(f"Full arguments ({len(sys.argv)} total):")
    for idx, arg in enumerate(sys.argv):
        logging.info(f"  argv[{idx}] = {arg}")

    if len(sys.argv) < 4:
        logging.error("Missing required arguments, exit")
        sys.exit(1)

    fake_ip = sys.argv[1]
    domain = sys.argv[2]
    db_path = sys.argv[3]
    raw_ip_list = sys.argv[4].strip() if len(sys.argv) >= 5 else ""
    cidr = sys.argv[5] if len(sys.argv) >= 6 and sys.argv[5] else "198.18.0.0/15"
    table_prefix = sys.argv[6] if len(sys.argv) >= 7 and sys.argv[6] else "default"
    next_hop = sys.argv[7].strip() if len(sys.argv) >= 8 else ""
    next_hop_dev = sys.argv[8].strip() if len(sys.argv) >= 9 else ""
    route_table = sys.argv[9].strip() if len(sys.argv) >= 10 and sys.argv[9] else DEFAULT_ROUTE_TABLE

    if not re.match(r'^[a-zA-Z0-9_]+$', table_prefix):
        logging.error("Invalid table_prefix, exit")
        sys.exit(1)

    if not next_hop and not next_hop_dev:
        next_hop, next_hop_dev = get_system_default_route()

    ip_table, nft_table = get_names(table_prefix)

    logging.info(f"[TABLE CONFIG]")
    logging.info(f"  Table prefix   = {table_prefix}")
    logging.info(f"  SQLite table   = {ip_table}")
    logging.info(f"  nftables table = {nft_table}")
    logging.info(f"  Match CIDR     = {cidr}")
    logging.info(f"  Route table    = {route_table}")
    logging.info(f"  Default next hop = {next_hop}")
    logging.info(f"  Default egress dev = {next_hop_dev}")

    ensure_nft_table(nft_table, cidr, next_hop_dev)

    # Fast path: reuse existing mapping if still reachable
    current_ip = get_current_mapped_ip(nft_table, fake_ip)
    if current_ip:
        logging.info("[STEP] Verify reachability of current mapped IP")
        apply_host_route(current_ip, next_hop, next_hop_dev, route_table)
        _, reachable = check_ip_reachable(current_ip, 1.0)
        if reachable:
            logging.info("[RESULT] Current IP still works, keep existing mapping, exit")
            logging.info("SCRIPT FINISHED (fast path)")
            logging.info("-" * 70)
            sys.exit(0)
        else:
            logging.info("[INFO] Current IP is unreachable, will select new one")

    # Priority 1: argument IP list; Priority 2: database
    candidate_ips = load_candidates_from_arg(raw_ip_list)
    if candidate_ips:
        logging.info(f"[SOURCE] Using {len(candidate_ips)} IPs from input argument")
    else:
        logging.info("[SOURCE] No IP list in arguments, fallback to database")
        candidate_ips = load_candidates_from_db(db_path, ip_table, domain)
        logging.info(f"[SOURCE] Found {len(candidate_ips)} IPs from database")

    logging.info(f"[RESULT] Total candidate IPs: {len(candidate_ips)}")
    if candidate_ips:
        logging.info(f"Candidates: {', '.join(candidate_ips)}")

    if not candidate_ips:
        logging.warning("No candidate IPs found, exit")
        logging.info("SCRIPT FINISHED (no candidates)")
        logging.info("-" * 70)
        sys.exit(0)

    # Pre-apply host routes for top 5 candidates
    logging.info("[STEP] Pre-apply host routes for top 5 candidates")
    for ip in candidate_ips[:5]:
        apply_host_route(ip, next_hop, next_hop_dev, route_table)

    # Concurrent reachability test
    logging.info("[STEP] Run concurrent reachability test")
    selected_ip = None
    with ThreadPoolExecutor(max_workers=min(10, len(candidate_ips))) as executor:
        futures = {executor.submit(check_ip_reachable, ip, 1.0): ip for ip in candidate_ips}
        for future in as_completed(futures):
            ip, ok = future.result()
            if ok and not selected_ip:
                selected_ip = ip
                logging.info(f"[RESULT] First reachable IP selected: {selected_ip}")

    if not selected_ip:
        selected_ip = candidate_ips[0]
        logging.warning(f"All IPs unreachable, fallback to first candidate: {selected_ip}")

    # Update DNAT mapping
    logging.info("[STEP] Update DNAT mapping")
    if current_ip:
        logging.info(f"Remove old mapping: {fake_ip} -> {current_ip}")
        run_cmd(["nft", "delete", "element", "ip", nft_table, "dnat_map", f"{{ {fake_ip} }}"], check=False)

    logging.info(f"Add new mapping: {fake_ip} -> {selected_ip}")
    run_cmd(["nft", "add", "element", "ip", nft_table, "dnat_map", f"{{ {fake_ip} : {selected_ip} }}"], check=True)

    apply_host_route(selected_ip, next_hop, next_hop_dev, route_table)

    # Run strict route aggregation after mapping update
    if ENABLE_ROUTE_AGGREGATION:
        sync_aggregated_routes(next_hop, next_hop_dev, route_table, nft_table)

    logging.info(f"[FINAL] Mapping updated successfully: {fake_ip} <-> {selected_ip}")
    logging.info(f"[FINAL] Route table: {route_table}, egress: via {next_hop} dev {next_hop_dev}")
    logging.info("SCRIPT FINISHED")
    logging.info("-" * 70)

if __name__ == "__main__":
    main()
