#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Compatible with Python3.4
import subprocess
import sys
import os
import argparse
import re
import time
from multiprocessing import Pool, cpu_count


def normalize_asn(asn_str):
    asn_str = asn_str.strip()
    if re.match(r'^AS\d+$', asn_str, re.IGNORECASE):
        return 'AS' + asn_str[2:]
    elif re.match(r'^\d+$', asn_str):
        return 'AS' + asn_str
    else:
        return ""


def run_bgpq3_single(asn, af_list=("4", "6")):
    """单个ASN获取指定地址族前缀，给多进程调用"""
    v4_set = set()
    v6_set = set()
    for af in af_list:
        cmd = [
            "bgpq3",
            "-%s" % af,
            "-l", "PL",
            asn
        ]
        try:
            out = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            print("\n[WARN] bgpq3 %s af%s failed: %s" % (asn, af, e.output), file=sys.stderr)
            continue

        for line in out.splitlines():
            line = line.strip()
            if af == "4":
                if line.startswith("ip prefix-list"):
                    parts = line.split()
                    if len(parts) >= 5:
                        pfx = parts[4].replace(",", "")
                        v4_set.add(pfx)
            else:
                if line.startswith("ipv6 prefix-list"):
                    parts = line.split()
                    if len(parts) >= 5:
                        pfx = parts[4].replace(",", "")
                        v6_set.add(pfx)
    return asn, v4_set, v6_set


def print_progress(current, total, bar_len=30):
    if not sys.stderr.isatty():
        return
    percent = float(current) / total
    filled = int(bar_len * percent)
    bar = u"█" * filled + u"-" * (bar_len - filled)
    msg = "\rProgress: |%s| %5.1f%% (%d/%d) " % (bar, percent*100, current, total)
    sys.stderr.write(msg)
    sys.stderr.flush()


def read_asn_list(src_path):
    asns = []
    if src_path is None:
        for line in sys.stdin:
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            norm = normalize_asn(raw)
            if norm:
                asns.append(norm)
    else:
        if not os.path.exists(src_path):
            print("[ERROR] File %s not found" % src_path, file=sys.stderr)
            sys.exit(1)
        with open(src_path, "r", encoding="utf-8") as f:
            for line in f:
                raw = line.strip()
                if not raw or raw.startswith("#"):
                    continue
                norm = normalize_asn(raw)
                if norm:
                    asns.append(norm)
    return asns


def worker_wrapper(args):
    """pool 包装：执行 + 延迟"""
    asn, delay, af_list = args
    res = run_bgpq3_single(asn, af_list)
    if delay > 0:
        time.sleep(delay)
    return res


def main():
    parser = argparse.ArgumentParser(description="Fetch prefix from ASN list via bgpq3 (multi-worker)")
    parser.add_argument("asn_file", nargs="?", default=None, help="Input ASN file, one ASN per line; omit for pipe stdin")
    parser.add_argument("out_file", nargs="?", default=None, help="Output file; omit for stdout (support > / >>)")
    parser.add_argument("--split", action="store_true", default=False,
                        help="Split output to ipv4 and ipv6 separate files, default off")
    parser.add_argument("-w", "--workers", type=int, default=4, help="concurrent workers, default 4")
    parser.add_argument("-d", "--delay", type=float, default=2.0, help="delay(seconds) after each ASN query, default 2.0")
    parser.add_argument("--ipv4-only", action="store_true", default=False,
                        help="Only fetch IPv4 prefixes")
    parser.add_argument("--ipv6-only", action="store_true", default=False,
                        help="Only fetch IPv6 prefixes")

    args = parser.parse_args()

    # 校验地址族参数互斥
    if args.ipv4_only and args.ipv6_only:
        print("[ERROR] --ipv4-only and --ipv6-only cannot be used together", file=sys.stderr)
        sys.exit(1)

    # 确定要查询的地址族
    af_list = ["4", "6"]
    if args.ipv4_only:
        af_list = ["4"]
    elif args.ipv6_only:
        af_list = ["6"]

    raw_asns = read_asn_list(args.asn_file)
    total_asn = len(raw_asns)
    if total_asn == 0:
        print("[ERROR] No valid ASN loaded", file=sys.stderr)
        sys.exit(1)

    v4_set = set()
    v6_set = set()
    done_cnt = 0

    task_list = [(asn, args.delay, af_list) for asn in raw_asns]
    pool_size = max(1, min(args.workers, cpu_count()))

    with Pool(processes=pool_size) as pool:
        for _, asn_v4, asn_v6 in pool.imap_unordered(worker_wrapper, task_list):
            v4_set.update(asn_v4)
            v6_set.update(asn_v6)
            done_cnt += 1
            print_progress(done_cnt, total_asn)

    if sys.stderr.isatty():
        sys.stderr.write("\n")

    v4_list = sorted(v4_set)
    v6_list = sorted(v6_set)

    if args.split:
        if args.out_file is None:
            print("[ERROR] --split requires out_file parameter", file=sys.stderr)
            sys.exit(1)
        base, ext = os.path.splitext(args.out_file)
        fv4 = "%s_v4%s" % (base, ext)
        fv6 = "%s_v6%s" % (base, ext)

        if not args.ipv6_only:
            with open(fv4, "w", encoding="utf-8") as fw:
                for p in v4_list:
                    fw.write(p + "\n")
            print("[DONE] IPv4 %d → %s" % (len(v4_list), fv4), file=sys.stderr)

        if not args.ipv4_only:
            with open(fv6, "w", encoding="utf-8") as fw:
                for p in v6_list:
                    fw.write(p + "\n")
            print("[DONE] IPv6 %d → %s" % (len(v6_list), fv6), file=sys.stderr)
    else:
        if args.ipv4_only:
            out_list = v4_list
        elif args.ipv6_only:
            out_list = v6_list
        else:
            out_list = sorted(v4_list + v6_list)

        if args.out_file is None:
            for p in out_list:
                print(p)
        else:
            with open(args.out_file, "w", encoding="utf-8") as fw:
                for p in out_list:
                    fw.write(p + "\n")
            print("[DONE] Total %d prefixes saved to %s" % (len(out_list), args.out_file), file=sys.stderr)


if __name__ == "__main__":
    main()
