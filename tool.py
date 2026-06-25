#!/usr/bin/env python3
"""
asm.py — Attack Surface Mapper
A passive, public-data asset attribution tool.

Given a seed domain, it discovers internet-facing assets and assigns each one an
ATTRIBUTION CONFIDENCE level — the same judgment an Attribution Analyst makes:
moving from a broad scope of *probable* assets down to those *definitively* linked
to the organization.

It uses only PASSIVE, PUBLIC sources (no scanning, no unauthorized access):
  1. RDAP  — modern replacement for WHOIS: domain & IP registration records
  2. crt.sh — Certificate Transparency logs: subdomain enumeration via issued certs
  3. DNS   — A / AAAA / MX / NS / TXT / CNAME records
  4. RDAP/IP — maps resolved IPs to the org/ASN that owns the netblock

ETHICS / SCOPE NOTE:
  Everything here is open-source intelligence from public registries. Still, only
  run attribution against assets you own or are authorized to assess. The analyst's
  job is *attribution*, not intrusion — this tool never touches a target's systems.

Dependencies:  pip install requests dnspython
Usage:         python asm.py example.com --out ./report
"""

import argparse
import csv
import json
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("Missing dependency. Run: pip install requests dnspython")

try:
    import dns.resolver
    import dns.reversename
    _HAVE_DNS = True
except ImportError:
    _HAVE_DNS = False


# --------------------------------------------------------------------------- #
# Confidence model — the intellectual core of attribution work.
# An analyst rarely gets a binary yes/no. Most of the job is reasoning about
# *signals* and assigning a defensible confidence level, then flagging the
# ambiguous cases for human review.
# --------------------------------------------------------------------------- #
CONFIRMED = "CONFIRMED"  # The seed itself — given as ground truth.
HIGH      = "HIGH"       # Same registrable domain, or IP netblock owned by target org.
MEDIUM    = "MEDIUM"     # Shared infra signals (same NS/MX/registrant org) — likely, verify.
REVIEW    = "REVIEW"     # Hosted on shared cloud/CDN — cannot attribute from infra alone.
LOW       = "LOW"        # Weak/circumstantial signal.

# Known cloud / CDN / hosting providers. If an IP's netblock belongs to one of
# these, owning the IP does NOT prove the target owns the asset — it's shared
# infrastructure. This distinction is exactly what trips up naive attribution.
SHARED_INFRA_ORGS = [
    "amazon", "aws", "cloudflare", "google", "microsoft", "azure", "akamai",
    "fastly", "digitalocean", "linode", "ovh", "hetzner", "oracle cloud",
    "vultr", "godaddy", "squarespace", "wix", "shopify", "heroku", "netlify",
    "vercel", "github", "wpengine", "automattic", "incapsula", "imperva",
]

DEFAULT_HEADERS = {"User-Agent": "asm-attribution/1.0 (research; passive)"}


@dataclass
class Asset:
    """One discovered asset and the evidence trail behind its attribution."""
    asset_type: str                      # domain | subdomain | ip | netblock
    value: str
    confidence: str
    source: str                          # which technique surfaced it
    evidence: list = field(default_factory=list)
    owner_org: str = ""                  # registrant / netblock owner if known


# --------------------------------------------------------------------------- #
# Source 1 — RDAP (the modern WHOIS). HTTP/JSON, far cleaner than parsing
# free-text WHOIS. rdap.org bootstraps to the correct authoritative server.
# --------------------------------------------------------------------------- #
def rdap_domain(domain):
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}",
                         headers=DEFAULT_HEADERS, timeout=15)
        if r.status_code != 200:
            return None
        data = r.json()
        org = ""
        for ent in data.get("entities", []):
            roles = ent.get("roles", [])
            if "registrant" in roles or "registrar" in roles:
                org = _vcard_org(ent) or org
        nameservers = [ns.get("ldhName", "").lower()
                       for ns in data.get("nameservers", [])]
        return {"registrant_org": org, "nameservers": nameservers,
                "status": data.get("status", [])}
    except (requests.RequestException, ValueError):
        return None


def rdap_ip(ip):
    """Map an IP to the organization that owns its netblock."""
    try:
        r = requests.get(f"https://rdap.org/ip/{ip}",
                         headers=DEFAULT_HEADERS, timeout=15)
        if r.status_code != 200:
            return None
        data = r.json()
        org = data.get("name", "")
        for ent in data.get("entities", []):
            org = _vcard_org(ent) or org
        return {"netblock": data.get("handle", ""),
                "owner_org": org,
                "cidr": _extract_cidr(data)}
    except (requests.RequestException, ValueError):
        return None


def _vcard_org(entity):
    """Pull an org/full-name string out of an RDAP vCard entity."""
    vcard = entity.get("vcardArray")
    if not vcard or len(vcard) < 2:
        return ""
    for item in vcard[1]:
        if item and item[0] in ("org", "fn"):
            val = item[3]
            return val if isinstance(val, str) else " ".join(val)
    return ""


def _extract_cidr(data):
    start, end = data.get("startAddress"), data.get("endAddress")
    if start and end:
        return f"{start} - {end}"
    return data.get("handle", "")


# --------------------------------------------------------------------------- #
# Source 2 — Certificate Transparency (crt.sh). Every public TLS cert is logged,
# so CT is a goldmine for subdomains an org may have forgotten it exposed.
# --------------------------------------------------------------------------- #
def crtsh_subdomains(domain):
    subs = set()
    try:
        r = requests.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
                         headers=DEFAULT_HEADERS, timeout=30)
        if r.status_code != 200:
            return subs
        for row in r.json():
            for name in row.get("name_value", "").splitlines():
                name = name.strip().lower().lstrip("*.")
                if name.endswith(domain) and name != domain:
                    subs.add(name)
    except (requests.RequestException, ValueError):
        pass
    return subs


# --------------------------------------------------------------------------- #
# Source 3 — DNS resolution.
# --------------------------------------------------------------------------- #
def resolve_dns(name):
    out = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": []}
    if not _HAVE_DNS:
        return out
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    for rtype in out:
        try:
            for rdata in resolver.resolve(name, rtype):
                out[rtype].append(rdata.to_text().strip('"'))
        except Exception:
            continue
    return out


# --------------------------------------------------------------------------- #
# Attribution scoring.
# --------------------------------------------------------------------------- #
def classify_ip(ip, seed_org):
    info = rdap_ip(ip)
    if not info:
        return Asset("ip", ip, LOW, "dns-resolution",
                     ["No RDAP record for netblock"], "")
    owner = (info.get("owner_org") or "").strip()
    owner_l = owner.lower()
    evidence = [f"Netblock {info.get('cidr','?')} owned by '{owner or 'unknown'}'"]

    if any(p in owner_l for p in SHARED_INFRA_ORGS):
        evidence.append("Owner is a shared cloud/CDN provider — IP ownership does "
                        "NOT prove asset ownership. Confirm via other signals.")
        return Asset("ip", ip, REVIEW, "ip-rdap", evidence, owner)

    if seed_org and seed_org.lower() in owner_l:
        evidence.append(f"Netblock owner matches seed registrant org '{seed_org}'.")
        return Asset("ip", ip, HIGH, "ip-rdap", evidence, owner)

    return Asset("ip", ip, MEDIUM, "ip-rdap", evidence, owner)


def discover(seed, verbose=True):
    assets = []
    log = (lambda m: print(f"  {m}", file=sys.stderr)) if verbose else (lambda m: None)

    # 1. Seed domain registration — establishes the org "fingerprint".
    log(f"RDAP registration for {seed} ...")
    reg = rdap_domain(seed) or {}
    seed_org = reg.get("registrant_org", "")
    seed_ns = set(reg.get("nameservers", []))
    assets.append(Asset("domain", seed, CONFIRMED, "seed-input",
                        [f"Seed domain. Registrant org: '{seed_org or 'unknown'}'",
                         f"Nameservers: {', '.join(seed_ns) or 'unknown'}"], seed_org))

    # 2. Subdomain enumeration via Certificate Transparency.
    log("Enumerating subdomains via Certificate Transparency (crt.sh) ...")
    subs = crtsh_subdomains(seed)
    log(f"  found {len(subs)} candidate subdomains")
    for sub in sorted(subs):
        # Same registrable domain → high confidence it's the same org's asset.
        assets.append(Asset("subdomain", sub, HIGH, "cert-transparency",
                            ["Shares the seed's registrable domain"], seed_org))

    # 3. Resolve everything and attribute the IPs behind it.
    seen_ips = {}
    targets = [seed] + sorted(subs)
    for host in targets:
        recs = resolve_dns(host)
        for ip in recs["A"] + recs["AAAA"]:
            if ip in seen_ips:
                seen_ips[ip].append(host)
                continue
            seen_ips[ip] = [host]
            time.sleep(0.3)  # be polite to rdap.org
            ip_asset = classify_ip(ip, seed_org)
            ip_asset.evidence.insert(0, f"Resolved from: {host}")
            assets.append(ip_asset)

    # 4. Surface shared-NS / shared-MX signals as MEDIUM leads for related domains.
    seed_recs = resolve_dns(seed)
    for ns in seed_recs["NS"]:
        assets.append(Asset("signal", ns.rstrip("."), MEDIUM, "shared-nameserver",
                            ["Authoritative NS for seed. Other domains on the same "
                             "private NS are candidate related assets — pivot here."],
                            seed_org))
    return assets


# --------------------------------------------------------------------------- #
# Reporting.
# --------------------------------------------------------------------------- #
def write_reports(assets, outdir):
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    json_path = outdir / "attribution_report.json"
    json_path.write_text(json.dumps([asdict(a) for a in assets], indent=2))

    csv_path = outdir / "attribution_report.csv"
    with csv_path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["asset_type", "value", "confidence", "source",
                    "owner_org", "evidence"])
        for a in assets:
            w.writerow([a.asset_type, a.value, a.confidence, a.source,
                        a.owner_org, " | ".join(a.evidence)])
    return json_path, csv_path


def summarize(assets):
    order = [CONFIRMED, HIGH, MEDIUM, REVIEW, LOW]
    counts = {lvl: 0 for lvl in order}
    for a in assets:
        counts[a.confidence] = counts.get(a.confidence, 0) + 1
    print("\n=== Attribution summary ===")
    for lvl in order:
        print(f"  {lvl:<9} {counts[lvl]}")
    print(f"  {'TOTAL':<9} {len(assets)}")
    print("\nReview the REVIEW/MEDIUM rows by hand — that's the analyst's call.")


def main():
    ap = argparse.ArgumentParser(description="Passive attack surface attribution.")
    ap.add_argument("seed", help="seed domain, e.g. example.com")
    ap.add_argument("--out", default="./asm_report", help="output directory")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if not _HAVE_DNS:
        print("WARN: dnspython not installed — DNS/IP attribution skipped. "
              "Run: pip install dnspython\n", file=sys.stderr)

    print(f"Mapping attack surface for: {args.seed}\n", file=sys.stderr)
    assets = discover(args.seed, verbose=not args.quiet)
    jp, cp = write_reports(assets, args.out)
    summarize(assets)
    print(f"\nWrote:\n  {jp}\n  {cp}  (opens in Excel / Google Sheets)")


if __name__ == "__main__":
    main()