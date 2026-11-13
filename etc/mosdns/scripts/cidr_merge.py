#!/usr/bin/env python3
import sys
import argparse
import ipaddress

GLOBAL_V4 = ipaddress.IPv4Network("0.0.0.0/0")
GLOBAL_V6 = ipaddress.IPv6Network("::/0")


def prune_subnets(networks):
    """Remove nested subnets only, do NOT merge adjacent networks, O(n log n)
    Input: list of ip_network objects
    Return: filtered list of network objects
    """
    if not networks:
        return []
    nets = sorted(networks)
    res = []
    for net in nets:
        keep = True
        for existing in res:
            if net.subnet_of(existing):
                keep = False
                break
        if keep:
            res.append(net)
    return res


def collapse_fallback_detail(nets: list):
    """
    Try collapse adjacent networks.
    If collapse yields global prefix:
        - MARK cannot aggregate on stderr
        - fallback to prune_subnets output detailed prefixes
    Else return collapsed result.
    """
    if not nets:
        return []

    collapsed = list(ipaddress.collapse_addresses(nets))
    has_global = any((n == GLOBAL_V4 or n == GLOBAL_V6) for n in collapsed)

    if has_global:
        fam = "IPv4" if isinstance(nets[0], ipaddress.IPv4Network) else "IPv6"
        print(f"MARK: Cannot safely aggregate {fam}, would generate global prefix", file=sys.stderr)
        return prune_subnets(nets)

    return collapsed


def drop_raw_global(net_list):
    """Drop single global prefix entries which already exist in raw input file"""
    out = []
    for n in net_list:
        if n == GLOBAL_V4 or n == GLOBAL_V6:
            print(f"[WARNING] Dropping raw global prefix from input: {n}", file=sys.stderr)
            continue
        out.append(n)
    return out


def main():
    parser = argparse.ArgumentParser(description="CIDR merge / deduplicate tool. Fallback to detail if merge would produce global prefix.")
    parser.add_argument("--no-merge", action="store_true", help="Do not merge adjacent networks, only remove nested subnets")
    parser.add_argument("--no-prune", action="store_true", help="Do not prune subnets, only remove exact duplicate entries")
    parser.add_argument("--ipv4-only", action="store_true", help="Only process and output IPv4 prefixes, IPv6 entries are discarded at read time")
    parser.add_argument("--ipv6-only", action="store_true", help="Only process and output IPv6 prefixes, IPv4 entries are discarded at read time")
    args = parser.parse_args()

    # 校验地址族参数互斥
    if args.ipv4_only and args.ipv6_only:
        print("[ERROR] --ipv4-only and --ipv6-only cannot be used together", file=sys.stderr)
        sys.exit(1)

    v4_nets = []
    v6_nets = []
    invalid = 0
    skipped_other_family = 0

    all_lines = [line.strip() for line in sys.stdin if line.strip()]
    total_raw = len(all_lines)
    if total_raw == 0:
        print("stdin empty!", file=sys.stderr)
        return

    show_progress = total_raw >= 20

    for idx, line in enumerate(all_lines):
        try:
            net = ipaddress.ip_network(line, strict=False)
            is_v4 = isinstance(net, ipaddress.IPv4Network)

            # 单地址族模式下，直接丢弃另一地址族，不存入内存
            if args.ipv4_only:
                if is_v4:
                    v4_nets.append(net)
                else:
                    skipped_other_family += 1
            elif args.ipv6_only:
                if not is_v4:
                    v6_nets.append(net)
                else:
                    skipped_other_family += 1
            else:
                if is_v4:
                    v4_nets.append(net)
                else:
                    v6_nets.append(net)
        except ValueError:
            invalid += 1

        if show_progress:
            pct = (idx + 1) / total_raw * 100
            bar_len = 30
            filled = int(bar_len * (idx + 1) / total_raw)
            bar = "#" * filled + "-" * (bar_len - filled)
            print(f"\r[Reading] |{bar}| {pct:5.1f}%  {idx+1}/{total_raw}", end="", file=sys.stderr)

    if show_progress:
        print(file=sys.stderr)
    print("Reading complete, start processing...", file=sys.stderr)

    # Deduplicate object
    v4_unique = list(dict.fromkeys(v4_nets))
    v6_unique = list(dict.fromkeys(v6_nets))

    # Step1: remove any global prefix that comes directly from input file
    v4_unique = drop_raw_global(v4_unique)
    v6_unique = drop_raw_global(v6_unique)

    if args.no_prune:
        v4_out = sorted(v4_unique)
        v6_out = sorted(v6_unique)
    elif args.no_merge:
        v4_out = sorted(prune_subnets(v4_unique))
        v6_out = sorted(prune_subnets(v6_unique))
    else:
        # Default: try merge; fallback to detail + mark when would generate global
        v4_out = sorted(collapse_fallback_detail(v4_unique)) if not args.ipv6_only else []
        v6_out = sorted(collapse_fallback_detail(v6_unique)) if not args.ipv4_only else []

    # Final safety guard
    v4_out = drop_raw_global(v4_out)
    v6_out = drop_raw_global(v6_out)

    # 按参数控制输出
    if args.ipv4_only:
        for net in v4_out:
            print(net)
    elif args.ipv6_only:
        for net in v6_out:
            print(net)
    else:
        for net in v4_out:
            print(net)
        for net in v6_out:
            print(net)

    # 统计信息
    print("\n==== Summary ====", file=sys.stderr)
    print(f"Total input lines: {total_raw}", file=sys.stderr)
    print(f"Invalid entries: {invalid}", file=sys.stderr)
    if skipped_other_family > 0:
        fam_name = "IPv6" if args.ipv4_only else "IPv4"
        print(f"Skipped {fam_name} entries: {skipped_other_family}", file=sys.stderr)

    if not args.ipv6_only:
        print(f"Original IPv4: {len(v4_nets)} → Output IPv4: {len(v4_out)}", file=sys.stderr)
    if not args.ipv4_only:
        print(f"Original IPv6: {len(v6_nets)} → Output IPv6: {len(v6_out)}", file=sys.stderr)


if __name__ == "__main__":
    main()
