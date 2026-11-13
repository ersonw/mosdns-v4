#!/usr/bin/env python3
"""Add, delete or clean MosDNS domain/IP rules in a plain-text list.

Input is messy by nature: URLs, wildcards, ports, trailing notes and pasted
chat lines. Each rule is normalized to a MosDNS text-loader form: bare domain
(suffix), full:, domain:, keyword:, regexp:, or an IP/CIDR. In-place edits
preserve comments and blank lines and de-duplicate only real rule lines.

Without a file path the normalized list goes to stdout, so it can feed a
pipe; the summary goes to stderr. With a file path the list is edited in
place.

Examples:
  cat messy.txt | python3 domain_manage.py            # clean to stdout
  cat messy.txt | python3 domain_manage.py -o clean.txt  # clean to a new file
  python3 domain_manage.py 'https://foo.com/x'        # one domain to stdout
  python3 domain_manage.py /etc/mosdns/rule/oversea_domains.txt google.com
  python3 domain_manage.py del /etc/mosdns/rule/oversea_domains.txt foo.com
  python3 domain_manage.py clean /etc/mosdns/rule/oversea_domains.txt
"""

import ipaddress
import os
import re
import stat
import sys
import tempfile

# A DNS name candidate. The lookarounds keep it from matching a suffix of a
# longer broken token such as "foo_bar.com" or "foo..bar.com".
# IANA TLD list (tlds-alpha-by-domain.txt, version 2026111200). Checking the
# last label rejects file names such as "config.yaml"; -a/--any-tld disables
# the check for internal or invented suffixes.
_TLD_DATA = """
aaa aarp abb abbott abbvie abc able abogado abudhabi ac academy accenture accountant
accountants aco actor ad ads adult ae aeg aero aetna af afl africa ag agakhan agency ai
aig airbus airforce airtel akdn al alibaba alipay allfinanz allstate ally alsace alstom
am amazon americanexpress americanfamily amex amfam amica amsterdam analytics android
anquan anz ao aol apartments app apple aq aquarelle ar arab aramco archi army arpa art
arte as asda asia associates at athleta attorney au auction audi audible audio auspost
author auto autos aw aws ax axa az azure ba baby baidu banamex band bank bar barcelona
barclaycard barclays barefoot bargains baseball basketball bauhaus bayern bb bbc bbt
bbva bcg bcn bd be beats beauty beer berlin best bestbuy bet bf bg bh bharti bi bible
bid bike bing bingo bio biz bj black blackfriday blockbuster blog bloomberg blue bm bms
bmw bn bnpparibas bo boats boehringer bofa bom bond boo book booking bosch bostik boston
bot boutique box br bradesco bridgestone broadway broker brother brussels bs bt build
builders business buy buzz bv bw by bz bzh ca cab cafe cal call calvinklein cam camera
camp canon capetown capital capitalone car caravan cards care career careers cars casa
case cash casino cat catering catholic cba cbn cbre cc cd center ceo cern cf cfa cfd cg
ch chanel channel charity chase chat cheap chintai christmas chrome church ci cipriani
circle cisco citadel citi citic city ck cl claims cleaning click clinic clinique
clothing cloud club clubmed cm cn co coach codes coffee college cologne com commbank
community company compare computer comsec condos construction consulting contact
contractors cooking cool coop corsica country coupon coupons courses cpa cr credit
creditcard creditunion cricket crown crs cruise cruises cu cuisinella cv cw cx cy cymru
cyou cz dad dance data date dating datsun day dclk dds de deal dealer deals degree
delivery dell deloitte delta democrat dental dentist desi design dev dhl diamonds diet
digital direct directory discount discover dish diy dj dk dm dnp do docs doctor dog
domains dot download drive dtv dubai dupont durban dvag dvr dz earth eat ec eco edeka
edu education ee eg email emerck energy engineer engineering enterprises epson equipment
er ericsson erni es esq estate et eu eurovision eus events exchange expert exposed
express extraspace fage fail fairwinds faith family fan fans farm farmers fashion fast
fedex feedback ferrari ferrero fi fidelity fido film final finance financial fire
firestone firmdale fish fishing fit fitness fj fk flickr flights flir florist flowers
fly fm fo foo food football ford forex forsale forum foundation fox fr free fresenius
frl frogans frontier ftr fujitsu fun fund furniture futbol fyi ga gal gallery gallo
gallup game games gap garden gay gb gbiz gd gdn ge gea gent genting george gf gg ggee gh
gi gift gifts gives giving gl glass gle global globo gm gmail gmbh gmo gmx gn godaddy
gold goldpoint golf goodyear goog google gop got gov gp gq gr grainger graphics gratis
green gripe grocery group gs gt gu gucci guge guide guitars guru gw gy hair hamburg
hangout haus hbo hdfc hdfcbank health healthcare help here hermes hiphop hisamitsu
hitachi hiv hk hkt hm hn hockey holdings holiday homedepot homegoods homes homesense
honda horse hospital host hosting hot hotels hotmail house how hr hsbc ht hu hughes
hyatt hyundai ibm icbc ice icu id ie ieee ifm ikano il im imamat imdb immo immobilien in
inc industries infiniti info ing ink institute insurance insure int international intuit
investments io ipiranga iq ir irish is ismaili ist istanbul it itau itv jaguar java jcb
je jeep jetzt jewelry jio jll jm jmp jnj jo jobs joburg jot joy jp jpmorgan jprs juegos
kaufen kddi ke kerryhotels kerryproperties kfh kg kh ki kia kids kim kindle kitchen kiwi
km kn koeln komatsu kosher kp kpmg kpn kr krd kred kuokgroup kw ky kyoto kz la lacaixa
lamborghini lamer land landrover lanxess lasalle lat latino latrobe law lawyer lb lc lds
lease leclerc lefrak legal lego lexus lgbt li lidl life lifeinsurance lifestyle lighting
like lilly limited limo lincoln link live living lk llc llp loan loans locker locus lol
london lotte lotto love lpl lplfinancial lr ls lt ltd ltda lu lundbeck luxe luxury lv ly
ma madrid maif maison makeup man management mango map market marketing markets marriott
marshalls mattel mba mc mckinsey md me med media meet melbourne meme memorial men menu
merck merckmsd mg mh miami microsoft mil mini mint mit mitsubishi mk ml mlb mls mm mma
mn mo mobi mobile moda moe moi mom monash money monster mormon mortgage moscow moto
motorcycles mov movie mp mq mr ms msd mt mtn mtr mu museum music mv mw mx my mz na nab
nagoya name navy nba nc ne nec net netbank netflix network neustar new news next
nextdirect nexus nf nfl ng ngo nhk ni nico nike nikon ninja nissan nissay nl no nokia
norton now nowruz nowtv np nr nra nrw ntt nu nyc nz obi observer office okinawa olayan
olayangroup ollo om omega one ong onl online ooo open oracle orange org organic origins
osaka otsuka ott ovh pa page panasonic paris pars partners parts party pay pccw pe pet
pf pfizer pg ph pharmacy phd philips phone photo photography photos physio pics pictet
pictures pid pin ping pink pioneer pizza pk pl place play playstation plumbing plus pm
pn pnc pohl poker politie porn post pr praxi press prime pro prod productions prof
progressive promo properties property protection pru prudential ps pt pub pw pwc py qa
qpon quebec quest racing radio re read realestate realtor realty recipes red redumbrella
rehab reise reisen reit reliance ren rent rentals repair report republican rest
restaurant review reviews rexroth rich richardli ricoh ril rio rip ro rocks rodeo rogers
room rs rsvp ru rugby ruhr run rw rwe ryukyu sa saarland safe safety sakura sale salon
samsclub samsung sandvik sandvikcoromant sanofi sap sarl sas save saxo sb sbi sbs sc scb
schaeffler schmidt scholarships school schule schwarz science scot sd se search seat
secure security seek select sener services seven sew sex sexy sfr sg sh shangrila sharp
shell shia shiksha shoes shop shopping shouji show si silk sina singles site sj sk ski
skin sky skype sl sling sm smart smile sn sncf so soccer social softbank software sohu
solar solutions song sony soy spa space sport spot sr srl ss st stada staples star
statebank statefarm stc stcgroup stockholm storage store stream studio study style su
sucks supplies supply support surf surgery suzuki sv swatch swiss sx sy sydney systems
sz tab taipei talk taobao target tatamotors tatar tattoo tax taxi tc tci td tdk team
tech technology tel temasek tennis teva tf tg th thd theater theatre tiaa tickets tienda
tips tires tirol tj tjmaxx tjx tk tkmaxx tl tm tmall tn to today tokyo tools top toray
toshiba total tours town toyota toys tr trade trading training travel travelers
travelersinsurance trust trv tt tube tui tunes tushu tv tvs tw tz ua ubank ubs ug uk
unicom university uno uol ups us uy uz va vacations vana vanguard vc ve vegas ventures
verisign versicherung vet vg vi viajes video vig viking villas vin vip virgin visa
vision viva vivo vlaanderen vn vodka volvo vote voting voto voyage vu wales walmart
walter wang wanggou watch watches weather weatherchannel web webcam weber website wed
wedding weibo weir wf whoswho wien wiki williamhill win windows wine winners wme
woodside work works world wow ws wtc wtf xbox xerox xihuan xin xn--11b4c3d xn--1ck2e1b
xn--1qqw23a xn--2scrj9c xn--30rr7y xn--3bst00m xn--3ds443g xn--3e0b707e xn--3hcrj9c xn--
3pxu8k xn--42c2d9a xn--45br5cyl xn--45brj9c xn--45q11c xn--4dbrk0ce xn--4gbrim xn--
54b7fta0cc xn--55qw42g xn--55qx5d xn--5su34j936bgsg xn--5tzm5g xn--6frz82g xn--
6qq986b3xl xn--80adxhks xn--80ao21a xn--80aqecdr1a xn--80asehdb xn--80aswg xn--8y0a063a
xn--90a3ac xn--90ae xn--90ais xn--9dbq2a xn--9et52u xn--9krt00a xn--b4w605ferd xn--
bck1b9a5dre4c xn--c1avg xn--c2br7g xn--cck2b3b xn--cckwcxetd xn--cg4bki xn--
clchc0ea0b2g2a9gcd xn--czr694b xn--czrs0t xn--czru2d xn--d1acj3b xn--d1alf xn--e1a4c xn
--eckvdtc9d xn--efvy88h xn--fct429k xn--fhbei xn--fiq228c5hs xn--fiq64b xn--fiqs8s xn--
fiqz9s xn--fjq720a xn--flw351e xn--fpcrj9c3d xn--fzc2c9e2c xn--fzys8d69uvgm xn--g2xx48c
xn--gckr3f0f xn--gecrj9c xn--gk3at1e xn--h2breg3eve xn--h2brj9c xn--h2brj9c8c xn--
hxt814e xn--i1b6b1a6a2e xn--imr513n xn--io0a7i xn--j1aef xn--j1amh xn--j6w193g xn--
jlq480n2rg xn--jvr189m xn--kcrx77d1x4a xn--kprw13d xn--kpry57d xn--kput3i xn--l1acc xn--
lgbbat1ad8j xn--mgb9awbf xn--mgba3a3ejt xn--mgba3a4f16a xn--mgba7c0bbn0a xn--mgbaam7a8h
xn--mgbab2bd xn--mgbah1a3hjkrd xn--mgbai9azgqp6j xn--mgbayh7gpa xn--mgbbh1a xn--
mgbbh1a71e xn--mgbc0a9azcg xn--mgbca7dzdo xn--mgbcpq6gpa1a xn--mgberp4a5d4ar xn--
mgbgu82a xn--mgbi4ecexp xn--mgbpl2fh xn--mgbt3dhd xn--mgbtx2b xn--mgbx4cd0ab xn--mix891f
xn--mk1bu44c xn--mxtq1m xn--ngbc5azd xn--ngbe9e0a xn--ngbrx xn--node xn--nqv7f xn--
nqv7fs00ema xn--nyqy26a xn--o3cw4h xn--ogbpf8fl xn--otu796d xn--p1acf xn--p1ai xn--
pgbs0dh xn--pssy2u xn--q7ce6a xn--q9jyb4c xn--qcka1pmc xn--qxa6a xn--qxam xn--rhqv96g xn
--rovu88b xn--rvc1e0am3e xn--s9brj9c xn--ses554g xn--t60b56a xn--tckwe xn--tiq49xqyj xn
--unup4y xn--vermgensberater-ctb xn--vermgensberatung-pwb xn--vhquv xn--vuq861b xn--
w4r85el8fhu5dnra xn--w4rs40l xn--wgbh1c xn--wgbl6a xn--xhq521b xn--xkc2al3hye2a xn--
xkc2dl3a5ee0h xn--y9a3aq xn--yfro4i67o xn--ygbi2ammx xn--zfr164b xxx xyz yachts yahoo
yamaxun yandex ye yodobashi yoga yokohama you youtube yt yun za zappos zara zero zip zm
zone zuerich zw
"""
_TLDS = frozenset(_TLD_DATA.split())

_CHECK_TLD = True

_DOMAIN_RE = re.compile(
    r"(?<![a-z0-9_.-])"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?![a-z0-9_-])",
    re.IGNORECASE,
)

# MosDNS domain matcher directives. A bare domain uses the default "domain"
# suffix matcher; the explicit prefixes select full, keyword or regexp.
_RULE_RE = re.compile(
    r"^(keyword|full|domain|regexp):(.*)$", re.IGNORECASE | re.DOTALL
)

# A comment starts at whitespace followed by '#'. Requiring the whitespace
# avoids treating a URL fragment such as http://foo.com/#bar as a comment.
_INLINE_COMMENT_RE = re.compile(r"\s+#")


def normalize_domain(candidate):
    """Return a bare valid domain or None.

    Drops the trailing dot, lower-cases, rejects IP literals, single labels,
    empty labels, labels over 63 bytes and a numeric TLD. IDN input has to be
    punycode already, because the regex only accepts ASCII.
    """
    if not candidate:
        return None
    domain = candidate.strip().strip(".").lower()
    if not domain or len(domain) > 253:
        return None
    labels = domain.split(".")
    if len(labels) < 2:
        return None
    for label in labels:
        if not 1 <= len(label) <= 63:
            return None
        if label[0] == "-" or label[-1] == "-":
            return None
        if not re.fullmatch(r"[a-z0-9-]+", label):
            return None
    # A numeric TLD is never a domain, and this also rejects IPv4 literals.
    tld = labels[-1]
    if len(tld) < 2 or not tld[0].isalpha() or not any(ch.isalpha() for ch in tld):
        return None
    if _CHECK_TLD and tld not in _TLDS:
        return None
    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        pass
    return domain


def validate_regexp(value):
    """Check Python syntax and reject constructs Go's RE2 does not support."""
    try:
        re.compile(value)
    except re.error:
        return False
    # Go regexp/RE2 has no lookahead, lookbehind, conditional or backrefs.
    if re.search(r"\(\?[=!<]", value):
        return False
    if "(?P=" in value or "(?(" in value:
        return False
    if re.search(r"\\[1-9]", value):
        return False
    return True


def split_rule_line(raw_line):
    """Split a rule line from its trailing comment.

    regexp: lines are left intact because '#' can be part of the expression.
    """
    if raw_line.strip().lower().startswith("regexp:"):
        return raw_line, ""
    comment = _INLINE_COMMENT_RE.search(raw_line)
    if comment:
        return raw_line[: comment.start()], raw_line[comment.start() :]
    return raw_line, ""


def rule_key(rule):
    """Return a stable key for matching duplicate rules."""
    if rule["type"] == "ip":
        try:
            return ("ip", str(ipaddress.ip_network(rule["value"], strict=False)))
        except ValueError:
            return ("ip", rule["value"])
    return (rule["type"], rule["value"])


def format_rule(rule):
    """Render a rule in the form MosDNS' text loader understands."""
    if rule["type"] == "ip":
        return rule["value"]
    return rule["prefix"] + rule["value"]


def extract_rules(line):
    """Parse one raw line into MosDNS domain/IP rules.

    A bare domain is a suffix rule. Explicit full:/domain:/keyword:/regexp:
    prefixes are honored. URLs contribute their host, and a leading "*." is
    stripped because MosDNS does not treat it as a wildcard. A valid IP or
    CIDR is kept as an address-list rule.
    """
    text = line.strip().lstrip("\ufeff")
    if not text or text.startswith("#"):
        return []

    match = _RULE_RE.match(text)
    if match:
        kind = match.group(1).lower()
        value = match.group(2).strip()
        if kind == "keyword":
            if not value or re.search(r"\s", value):
                return []
            return [{"type": "keyword", "value": value.lower(),
                     "prefix": "keyword:"}]
        if kind == "regexp":
            if not value or not validate_regexp(value):
                return []
            return [{"type": "regexp", "value": value, "prefix": "regexp:"}]
        if kind == "domain":
            value = re.sub(r"^\*\.", "", value)
        domain = normalize_domain(value)
        if not domain:
            return []
        return [{"type": kind, "value": domain, "prefix": kind + ":"}]

    # An IP or CIDR line belongs to netlist (query_matcher client_ip/ecs,
    # response_matcher ip), not to the domain matcher.
    try:
        if "/" in text:
            value = str(ipaddress.ip_network(text, strict=False))
        else:
            value = str(ipaddress.ip_address(text))
        return [{"type": "ip", "value": value, "prefix": ""}]
    except ValueError:
        pass

    # A line containing a URL is a URL line: only its host counts, even when
    # the host is unusable (localhost, an IP literal). Otherwise a path such
    # as http://localhost/foo.com would leak foo.com into the list.
    url = re.search(r"(?:https?|ftp)://[^\s]+", text, re.IGNORECASE)
    if url:
        try:
            from urllib.parse import urlsplit

            host = urlsplit(url.group(0)).hostname
        except ValueError:
            host = None
        domain = normalize_domain(host) if host else None
        return [{"type": "domain", "value": domain, "prefix": ""}] if domain else []

    # Free-form line: pull every domain-like token. A leading "*." is not a
    # wildcard for MosDNS, so drop it and keep the suffix.
    text = re.sub(r"\*\.", "", text)
    found = []
    for match in _DOMAIN_RE.finditer(text):
        domain = normalize_domain(match.group(0))
        if domain:
            found.append({"type": "domain", "value": domain, "prefix": ""})
    return found


def load_file(path):
    """Read a rule file while keeping comments and blank lines.

    Returns (entries, rules, cleaned, dropped, raw). Each entry is a dict:
      {"kind": "blank"|"comment"} with "raw"
      {"kind": "rule", "rule": ..., "suffix": ...}

    Comments and blank lines are kept verbatim. Domain/IP rules are normalized
    and de-duplicated; an inline comment on a dropped duplicate is retained.
    """
    entries = []
    rules = set()
    cleaned = 0
    dropped = 0
    raw = 0
    if not os.path.exists(path):
        return entries, rules, cleaned, dropped, raw
    if os.path.isdir(path):
        raise SystemExit(f"Error: {path} is a directory")

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            raw_line = line.rstrip("\r\n")
            text = raw_line.strip()
            if not text:
                entries.append({"kind": "blank", "raw": raw_line})
                continue
            if text.startswith("#"):
                entries.append({"kind": "comment", "raw": raw_line})
                continue

            raw += 1
            code, suffix = split_rule_line(raw_line)
            found = extract_rules(code)
            if not found:
                dropped += 1
                cleaned += 1
                if suffix:
                    entries.append({"kind": "comment", "raw": suffix.lstrip()})
                continue

            canonical = format_rule(found[0]) if len(found) == 1 else None
            if canonical is None or code.strip() != canonical:
                cleaned += 1

            for i, rule in enumerate(found):
                key = rule_key(rule)
                if key in rules:
                    cleaned += 1
                    if i == 0 and suffix:
                        entries.append({"kind": "comment", "raw": suffix.lstrip()})
                    continue
                rules.add(key)
                line_suffix = suffix if i == 0 else ""
                entries.append(
                    {"kind": "rule", "rule": rule, "suffix": line_suffix}
                )
    return entries, rules, cleaned, dropped, raw


def insert_rules(entries, rules):
    """Insert new rules after the last existing rule, sorted by type/value."""
    if not rules:
        return
    pos = len(entries)
    for i in range(len(entries) - 1, -1, -1):
        if entries[i]["kind"] == "rule":
            pos = i + 1
            break
    for rule in sorted(rules, key=rule_key):
        entries.insert(pos, {"kind": "rule", "rule": rule, "suffix": ""})
        pos += 1


def save_entries(path, entries):
    """Write preserved comments and normalized rules atomically."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".domain_manage.", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for entry in entries:
                if entry["kind"] == "rule":
                    f.write(format_rule(entry["rule"]) + entry["suffix"] + "\n")
                else:
                    f.write(entry["raw"] + "\n")
        try:
            os.chmod(tmp, stat.S_IMODE(os.stat(path).st_mode))
        except FileNotFoundError:
            os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def save_rules(path, rules):
    """Write a sorted rule-only output file, keeping the original file mode."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".domain_manage.", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for rule in sorted(rules.values(), key=rule_key):
                f.write(format_rule(rule) + "\n")
        try:
            os.chmod(tmp, stat.S_IMODE(os.stat(path).st_mode))
        except FileNotFoundError:
            os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


USAGE = """Usage:
  python3 domain_manage.py [-o out_file] [file_path] rule1 [rule2 ...]
  python3 domain_manage.py add|del [file_path] rule1 [rule2 ...]
  python3 domain_manage.py clean [file_path]
  cat rule_list.txt | python3 domain_manage.py [-o out_file] [add|del]

Action defaults to add. Without file_path the sorted rules are printed to
stdout, or to -o out_file when given; -o never reads the output file, so it
is for "extract and save", not for merging. With file_path the file is edited
in place and comments/blank lines are preserved.

Supported rules:
  example.com             default MosDNS domain matcher (suffix)
  domain:example.com      explicit suffix matcher
  full:example.com        exact host only
  keyword:tiktok          substring match
  regexp:^ad\\.             Go/MosDNS regular expression
  1.2.3.4                 single IP for netlist
  1.2.3.0/24              IPv4 or IPv6 CIDR for netlist

The TLD is checked against the IANA list; -a/--any-tld accepts internal
suffixes such as .lan. URLs, "*." wildcards, ports and trailing notes are
reduced to bare domains. Inline "# comments" are preserved."""


def parse_args(argv):
    """Parse action / optional file / domains without argparse.

    argparse cannot accept an optional path before the domains, and the old
    script allowed exactly that ("script /path/file.txt domain").
    """
    args = list(argv)
    if args and args[0] in ("-h", "--help"):
        print(USAGE)
        raise SystemExit(0)

    # Pull -o/--output out before the positional interpretation: its value
    # may look like a path or a domain.
    output = None
    any_tld = False
    rest = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-a", "--any-tld"):
            any_tld = True
            i += 1
            continue
        if arg in ("-o", "--output"):
            if i + 1 >= len(args):
                print("Error: -o needs a file name", file=sys.stderr)
                raise SystemExit(1)
            output = args[i + 1]
            i += 2
            continue
        if arg.startswith("--output="):
            output = arg.split("=", 1)[1]
            i += 1
            continue
        rest.append(arg)
        i += 1
    args = rest

    action = "add"
    if args and args[0].lower() in ("add", "del", "clean"):
        action = args.pop(0).lower()

    path = None
    if args:
        first = args[0].strip()
        if first == "-":
            args.pop(0)
        elif not first.lower().startswith(("http://", "https://")) and (
            "/" in first or first.lower().endswith((".txt", ".conf", ".list"))
        ):
            path = args.pop(0)

    if output == "-":
        output = None
    if output is not None and path is not None:
        print("Error: -o and an in-place file path are mutually exclusive",
              file=sys.stderr)
        raise SystemExit(1)

    return action, path, args, output, any_tld


def main(argv=None):
    global _CHECK_TLD
    action, path, inputs, output, any_tld = parse_args(
        sys.argv[1:] if argv is None else argv
    )
    _CHECK_TLD = not any_tld

    # Pipe mode only when nothing was passed as positional domains. A file
    # clean never reads stdin; stream mode always does.
    read_stdin = not inputs and not sys.stdin.isatty()
    if read_stdin and (path is None or action != "clean"):
        raw_text = sys.stdin.read()
        inputs = raw_text.splitlines()

    valid = []
    skipped = 0
    for line in inputs:
        code, _suffix = split_rule_line(line)
        found = extract_rules(code)
        if not found:
            skipped += 1
            continue
        valid.extend(found)

    unique_input = {}
    for rule in valid:
        unique_input.setdefault(rule_key(rule), rule)
    duplicate_input = len(valid) - len(unique_input)

    # No file: write the normalized set to -o, or print it to stdout.
    if path is None:
        if action == "del":
            print("Error: del needs a file path", file=sys.stderr)
            return 1
        if not unique_input:
            print("Error: no valid rule found in input", file=sys.stderr)
            return 1
        if output is not None:
            save_rules(output, unique_input)
        else:
            for rule in sorted(unique_input.values(), key=rule_key):
                print(format_rule(rule))
        print(
            f"Input: {len(inputs)} lines, {len(unique_input)} valid, "
            f"{duplicate_input} duplicate, {skipped} skipped",
            file=sys.stderr,
        )
        return 0

    entries, existing, cleaned, dropped, raw = load_file(path)
    original = len(existing)

    if action != "clean" and not unique_input:
        print("Error: no valid rule found in input", file=sys.stderr)
        return 1

    changed = 0
    if action == "add":
        new_rules = [
            rule for key, rule in unique_input.items() if key not in existing
        ]
        insert_rules(entries, new_rules)
        for rule in new_rules:
            existing.add(rule_key(rule))
        changed = len(new_rules)
    elif action == "del":
        remove = set(unique_input) & existing
        if remove:
            new_entries = []
            for entry in entries:
                if (
                    entry["kind"] == "rule"
                    and rule_key(entry["rule"]) in remove
                ):
                    changed += 1
                    continue
                new_entries.append(entry)
            entries = new_entries
            existing.difference_update(remove)

    # clean rewrites even when only the existing entries needed fixing.
    if changed > 0 or (action == "clean" and cleaned > 0):
        save_entries(path, entries)

    print(f"File     : {path}")
    print(f"Action   : {action}")
    print(f"Input    : {len(inputs)} lines, {len(unique_input)} valid"
          f", {duplicate_input} duplicate, {skipped} skipped")
    print(f"Existing : {raw} lines, {original} rules, {cleaned} normalized/dropped"
          f" ({dropped} with no rule)")
    print(f"Changed  : {changed} entries")
    print(f"Total    : {len(existing)} rules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
