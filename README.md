# asm.py — Attack Surface Mapper

A passive, public-data asset attribution tool. Given a seed domain, it discovers
an organization's internet-facing assets and assigns each one an **attribution
confidence** level, moving from a broad set of *probable* assets to those
*definitively* linked to the organization.

It uses only **passive, public** sources. Nothing here interacts with a target's
systems. It reads public registries and records, similar to looking up a
property deed in a public database.

---

## Install & run

```bash
pip install requests dnspython
python asm.py example.com --out ./report
```

Outputs two files in `./report`:

* `attribution_report.json` — full structured results
* `attribution_report.csv` — same data, opens in Excel / Google Sheets

| flag      | meaning                                   |
| --------- | ----------------------------------------- |
| `seed`    | the domain to map, e.g. `example.com`     |
| `--out`   | output directory (default `./asm_report`) |
| `--quiet` | suppress progress logging                 |

---

## Overview

An **attack surface** is everything an organization exposes to the internet:
domains, subdomains, servers, mail systems, login portals, and related assets.

A common problem is incomplete asset inventory. Organizations may forget about
old marketing sites, test environments, or abandoned subdomains. Unmaintained
assets are more likely to contain security issues and are often where attackers
start looking.

**Attribution** is the process of determining whether an asset actually belongs
to a given organization. Finding possible assets is relatively easy. Establishing
ownership with confidence is harder.

The workflow is a funnel:

1. Gather candidate assets.
2. Collect supporting evidence.
3. Increase or decrease confidence based on that evidence.
4. Separate likely assets from confirmed ones.

False positives matter. Reporting an asset as belonging to a client when it
doesn't can lead to incorrect security conclusions and wasted effort.

---

## Data sources

All sources are passive and publicly available.

### 1. RDAP — domain registration records (`rdap_domain()`)

When a domain is registered, information about that registration is published
through RDAP. RDAP is the modern replacement for WHOIS, providing structured JSON
responses instead of free-form text.

The tool queries `rdap.org`, which routes requests to the appropriate registry.

RDAP can provide:

* Registrant organization
* Registrar information
* Registration dates
* Nameservers

These details create a fingerprint that can be used to identify related domains.

**Note:** Since GDPR and similar privacy regulations, registrant information is
often redacted, reducing the usefulness of this source compared to the past.

### 2. Certificate Transparency / crt.sh — subdomain discovery (`crtsh_subdomains()`)

Certificate Transparency (CT) logs are public, append-only records of issued TLS
certificates. Modern browsers require certificates to appear in CT logs.

Because certificates contain the hostnames they cover, CT logs provide a useful
historical source of subdomain information.

`crt.sh` is a searchable interface to those logs.

This often reveals subdomains that are not linked from public websites but still
required certificates at some point, such as:

* `vpn.example.com`
* `staging.example.com`
* `old-app.example.com`

A subdomain of a confirmed domain is generally considered **high confidence**
because it shares the same registrable domain.

### 3. DNS records — where hostnames point (`resolve_dns()`)

DNS maps names to infrastructure and exposes several useful record types:

* **A / AAAA** — IPv4 and IPv6 addresses
* **MX** — mail servers
* **NS** — authoritative nameservers
* **TXT** — verification tokens, SPF, DKIM, DMARC, and service metadata
* **CNAME** — aliases that often reveal SaaS providers

These records help identify hosting arrangements, third-party services, mail
providers, and relationships between domains.

The A and AAAA records also provide IP addresses that can be analyzed further.

### 4. RDAP on IPs — network ownership (`rdap_ip()` + `classify_ip()`)

IP address ranges are allocated to organizations through regional internet
registries. RDAP can be used to identify the organization responsible for a
particular IP block.

If an IP belongs to a network directly registered to the target organization,
that is strong evidence of ownership.

A common complication is cloud hosting. Many organizations host services on
platforms such as Amazon Web Services, Microsoft Azure, Google Cloud, or
Cloudflare.

In those cases, the IP owner is the cloud provider rather than the organization
being investigated. The same infrastructure may be shared by thousands of
unrelated customers, so IP ownership alone is not enough to establish
attribution.

---

## Attribution scoring

The tool assigns a confidence label to each asset:

| label         | meaning                                                                                   |
| ------------- | ----------------------------------------------------------------------------------------- |
| **CONFIRMED** | Seed domain; known ground truth                                                           |
| **HIGH**      | Subdomain of a confirmed domain, or IP within a netblock owned by the target organization |
| **MEDIUM**    | Shared attribution signals such as registrant organization or private nameservers         |
| **REVIEW**    | Asset hosted on shared cloud or CDN infrastructure; requires additional validation        |
| **LOW**       | Weak or circumstantial evidence                                                           |

`SHARED_INFRA_ORGS` contains known cloud and CDN providers.

When an IP owner matches one of these providers, the tool assigns **REVIEW**
rather than attributing ownership from infrastructure alone.

Examples:

* Incorrect conclusion: "The IP belongs to Amazon, therefore the asset belongs to Amazon."
* Correct conclusion: "The asset is hosted on Amazon infrastructure. Additional evidence is required to determine ownership."

The goal is not only to identify what can be concluded, but also to clearly mark
what cannot.

---

## Summary

The tool collects publicly available information about an organization's internet
presence and evaluates how strongly each piece of evidence supports ownership of
a given asset.

---

## Ethics & scope

All data comes from public registries and open sources.

Use the tool only on assets you own or are authorized to assess. Its purpose is
asset discovery and attribution, not interaction with target systems.
