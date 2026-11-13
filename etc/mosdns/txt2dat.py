#!/usr/bin/env python3
import ipaddress
import sys
import os

def encode_varint(value: int) -> bytes:
    """Encode integer to protobuf varint format"""
    buf = b''
    while value > 0x7F:
        buf += bytes([(value & 0x7F) | 0x80])
        value >>= 7
    buf += bytes([value & 0x7F])
    return buf

def make_length_prefixed(data: bytes) -> bytes:
    """Add varint length prefix for length-delimited fields"""
    return encode_varint(len(data)) + data

def make_domain_msg(domain_type: int, value: str) -> bytes:
    """
    Build a single Domain protobuf message:
    - field 1: type (varint enum)
    - field 2: value (string)
    Type 2 = suffix match (standard Domain rule)
    """
    # field 1: type (wire type 0)
    field_type = b'\x08' + encode_varint(domain_type)
    # field 2: value (wire type 2)
    value_bytes = value.encode('utf-8')
    field_value = b'\x12' + make_length_prefixed(value_bytes)
    return field_type + field_value

def make_site_msg(tag: str, domain_list: list) -> bytes:
    """
    Build a Site protobuf message:
    - field 1: country_code (string, tag name)
    - field 2: domain (repeated Domain messages)
    """
    # field 1: country_code
    tag_bytes = tag.encode('utf-8')
    field_tag = b'\x0a' + make_length_prefixed(tag_bytes)

    # field 2: repeated domain
    field_domains = b''
    for dtype, dom in domain_list:
        domain_msg = make_domain_msg(dtype, dom)
        field_domains += b'\x12' + make_length_prefixed(domain_msg)

    return field_tag + field_domains

def make_geosite_list(site_dict: dict) -> bytes:
    """
    Build top-level GeoSiteList protobuf message from dict:
    key = category name, value = list of (type, domain) tuples
    - field 1: entry (repeated Site messages)
    """
    payload = b''
    for tag, domains in site_dict.items():
        site_msg = make_site_msg(tag, domains)
        payload += b'\x0a' + make_length_prefixed(site_msg)
    return payload

def decode_varint(data: bytes, offset: int):
    """Decode varint from bytes, return (value, new_offset)"""
    value = 0
    shift = 0
    while offset < len(data):
        b = data[offset]
        offset += 1
        value |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    return value, offset

def decode_domain(data: bytes):
    """Decode single Domain protobuf message, return (type, value)"""
    domain_type = 0
    value = ""
    offset = 0
    while offset < len(data):
        tag_byte = data[offset]
        offset += 1
        field_number = tag_byte >> 3
        wire_type = tag_byte & 0x07

        if wire_type == 0:  # varint
            val, offset = decode_varint(data, offset)
            if field_number == 1:
                domain_type = val
        elif wire_type == 2:  # length-delimited
            length, offset = decode_varint(data, offset)
            field_data = data[offset:offset+length]
            offset += length
            if field_number == 2:
                value = field_data.decode('utf-8')
        else:
            # skip unknown wire types
            if wire_type == 1:
                offset += 8
            elif wire_type == 5:
                offset += 4
            else:
                break
    return domain_type, value

def decode_site(data: bytes):
    """Decode single Site protobuf message, return (tag, domain_list)"""
    tag = ""
    domains = []
    offset = 0
    while offset < len(data):
        tag_byte = data[offset]
        offset += 1
        field_number = tag_byte >> 3
        wire_type = tag_byte & 0x07

        if wire_type == 2:  # length-delimited
            length, offset = decode_varint(data, offset)
            field_data = data[offset:offset+length]
            offset += length
            if field_number == 1:
                tag = field_data.decode('utf-8')
            elif field_number == 2:
                dtype, val = decode_domain(field_data)
                domains.append((dtype, val))
        else:
            if wire_type == 0:
                _, offset = decode_varint(data, offset)
            elif wire_type == 1:
                offset += 8
            elif wire_type == 5:
                offset += 4
            else:
                break
    return tag, domains

def decode_geosite_file(file_path: str) -> dict:
    """Read and decode existing dat file, return dict {category: [(type, domain), ...]}"""
    if not os.path.exists(file_path):
        return {}
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    sites = {}
    offset = 0
    while offset < len(data):
        tag_byte = data[offset]
        offset += 1
        field_number = tag_byte >> 3
        wire_type = tag_byte & 0x07

        if field_number == 1 and wire_type == 2:
            length, offset = decode_varint(data, offset)
            site_data = data[offset:offset+length]
            offset += length
            tag, domains = decode_site(site_data)
            sites[tag] = domains
        else:
            # skip unknown fields
            if wire_type == 0:
                _, offset = decode_varint(data, offset)
            elif wire_type == 1:
                offset += 8
            elif wire_type == 2:
                length, offset = decode_varint(data, offset)
                offset += length
            elif wire_type == 5:
                offset += 4
            else:
                break
    return sites

def is_ip_rule(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def parse_rule_line(line: str):
    """Parse one provider rule line into (v2dat type, value).

    Type mapping follows v2data.Domain_Type:
      0 Plain -> keyword:, 1 Regex -> regexp:, 2 Domain -> suffix, 3 Full -> full:
    Bare domains and domain: both mean a suffix rule. Comments are preserved
    by domain_manage.py, so a normal rule may have a trailing " # comment";
    regexp rules are kept verbatim.
    """
    raw = line.strip()
    if not raw or raw.startswith('#'):
        return None

    lower = raw.lower()
    if lower.startswith('regexp:'):
        value = raw[len('regexp:'):].strip()
        if not value:
            raise ValueError("empty regexp rule")
        return 1, value

    if ' #' in raw:
        raw = raw.split(' #', 1)[0].strip()
    if not raw:
        return None

    lower = raw.lower()
    for prefix, dtype in (('full:', 3), ('keyword:', 0), ('domain:', 2)):
        if lower.startswith(prefix):
            value = raw[len(prefix):].strip()
            if not value:
                raise ValueError("empty %s rule" % prefix[:-1])
            if dtype in (2, 3) and is_ip_rule(value):
                raise ValueError("IP/CIDR rule %r cannot be stored in geosite" % value)
            if dtype == 2 and value.startswith('*.'):
                value = value[2:]
            return dtype, value

    if is_ip_rule(raw):
        raise ValueError("IP/CIDR rule %r cannot be stored in geosite" % raw)
    return 2, raw


def main():
    if len(sys.argv) < 4:
        print("Usage: python3 txt2dat.py <input_txt> <output_dat> <category_name> [--overwrite]")
        print("  Default: preserve existing categories, update the specified one")
        print("  --overwrite: clear all existing content, keep only the specified category")
        print("  Rule prefixes: domain: (suffix), full:, keyword:, regexp:; bare = suffix")
        sys.exit(1)

    input_txt = sys.argv[1]
    output_dat = sys.argv[2]
    category = sys.argv[3]
    overwrite = len(sys.argv) >= 5 and sys.argv[4] == "--overwrite"

    # Read rules from txt file. Type prefixes select the v2dat domain type.
    new_domains = []
    with open(input_txt, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                parsed = parse_rule_line(line)
            except ValueError as e:
                print("Error: %s" % e)
                sys.exit(1)
            if parsed is not None:
                new_domains.append(parsed)

    if not new_domains:
        print("Error: no valid domains found in input file")
        sys.exit(1)

    # Load existing sites or start fresh
    if overwrite or not os.path.exists(output_dat):
        all_sites = {}
    else:
        all_sites = decode_geosite_file(output_dat)

    # Update / add the target category
    all_sites[category] = new_domains

    # Build and write final dat file
    geosite_data = make_geosite_list(all_sites)
    with open(output_dat, 'wb') as f:
        f.write(geosite_data)

    print(f"Success: generated {output_dat}")
    print(f"  Category: {category} ({len(new_domains)} domains)")
    print(f"  Total categories in file: {len(all_sites)}")
    print(f"  Mode: {'overwrite (clean)' if overwrite else 'preserve existing'}")

if __name__ == '__main__':
    main()
