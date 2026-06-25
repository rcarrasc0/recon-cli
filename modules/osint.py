#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  recon-cli · modules/osint.py  v1.1.6
#  Reconocimiento OSINT con separación explícita:
#    scope="endpoint"    → DNS del target, certificados, IPs
#    scope="root_domain" → WHOIS, ASN, SPF, DMARC
#  La sección OSINT del PDF mostrará solo datos del endpoint.
#  Los datos del dominio raíz van a la sección dedicada.
# ─────────────────────────────────────────────────────────────

import requests
import whois
import dns.resolver
import dns.zone
import dns.query
import dns.exception
from datetime import datetime
from ipwhois import IPWhois
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()
TIMEOUT = 10


def run_osint(target: str, target_info: dict, config: dict) -> dict:
    global console
    console = config.get("console") or console
    results = {
        "whois":        {},
        "dns_records":  {},
        "axfr":         {},
        "certificates": [],
        "asn":          {},
        "findings":     [],
    }

    timeout      = config.get("REQUEST_TIMEOUT", TIMEOUT)
    is_subdomain = target_info.get("is_subdomain", False)
    root_domain  = target_info.get("root_domain", target)

    # ── WHOIS → siempre root_domain scope ────────────────────
    console.print("[cyan]  [*][/cyan] WHOIS...")
    try:
        w          = whois.whois(target)
        raw_emails = w.emails or []
        if isinstance(raw_emails, str):
            raw_emails = [raw_emails]
        # Filtrar emails de abuso del registrador
        emails = [e.strip() for e in raw_emails if e and "@" in str(e) and not str(e).startswith("abuse@")]

        # Fix fechas: datetime puede venir como list o datetime object
        def fmt_date(val):
            if val is None:
                return "N/A"
            if isinstance(val, list):
                val = val[0] if val else None
            if isinstance(val, datetime):
                return val.strftime("%Y-%m-%d")
            return str(val)[:10] if val else "N/A"

        results["whois"] = {
            "registrar":       str(w.registrar or "N/A"),
            "creation_date":   fmt_date(w.creation_date),
            "expiration_date": fmt_date(w.expiration_date),
            "name_servers":    [str(ns).lower() for ns in (w.name_servers or [])],
            "emails":          emails,
            "org":             str(w.org or "N/A"),
            "country":         str(w.country or "N/A"),
        }
        console.print(f"  [green]✓[/green] Registrar: {results['whois']['registrar']}")
        # Emails WHOIS: se almacenan para el PDF pero NO generan finding

    except Exception as e:
        console.print(f"  [yellow]![/yellow] WHOIS falló: {e}")

    # ── DNS Records → endpoint scope ─────────────────────────
    if target_info["type"] == "domain":
        console.print("[cyan]  [*][/cyan] Consultas DNS...")
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"]
        resolver          = dns.resolver.Resolver()
        resolver.timeout  = timeout
        resolver.lifetime = timeout

        for rtype in record_types:
            try:
                answers = resolver.resolve(target, rtype)
                results["dns_records"][rtype] = [str(r) for r in answers]
                console.print(f"  [green]✓[/green] {rtype}: {len(answers)} registro(s)")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                pass
            except Exception:
                pass

        # SPF/DMARC → siempre root_domain, son configuraciones de correo
        # no de la aplicación web auditada, independientemente del target
        txt_records = " ".join(results["dns_records"].get("TXT", []))

        if "v=spf1" not in txt_records:
            results["findings"].append({
                "phase":       "OSINT",
                "title":       f"SPF no configurado en {root_domain}",
                "description": f"No hay registro SPF en {root_domain}. Permite email spoofing.",
                "severity":    "MEDIUM",
                "cvss":        5.3,
                "scope":       "root_domain",
                "remediation": f"Añadir TXT SPF en {root_domain}: v=spf1 include:... -all",
            })
        if "v=DMARC1" not in txt_records:
            results["findings"].append({
                "phase":       "OSINT",
                "title":       f"DMARC no configurado en {root_domain}",
                "description": f"No hay registro _dmarc en {root_domain}. Vulnerable a spoofing.",
                "severity":    "MEDIUM",
                "cvss":        5.3,
                "scope":       "root_domain",
                "remediation": f"Añadir: _dmarc.{root_domain} TXT v=DMARC1; p=reject; rua=mailto:...",
            })

        # ── AXFR → siempre endpoint ───────────────────────────
        console.print("[cyan]  [*][/cyan] Intentando AXFR...")
        ns_list      = results["dns_records"].get("NS", [])
        axfr_results = {}
        for ns in ns_list:
            ns = ns.rstrip(".")
            try:
                zone    = dns.zone.from_xfr(dns.query.xfr(ns, target, timeout=timeout))
                records = []
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            records.append(f"{name} {dns.rdatatype.to_text(rdataset.rdtype)} {rdata}")
                axfr_results[ns] = records
                console.print(f"  [bold red]⚠ AXFR exitoso en {ns}! {len(records)} registros[/bold red]")
                results["findings"].append({
                    "phase":       "OSINT",
                    "title":       f"Transferencia de zona AXFR permitida en {ns}",
                    "description": f"{ns} permite AXFR. {len(records)} registros expuestos.",
                    "severity":    "HIGH",
                    "cvss":        7.5,
                    "scope":       "endpoint",
                    "remediation": "Restringir AXFR a servidores secundarios autorizados.",
                })
            except Exception:
                axfr_results[ns] = []

        results["axfr"] = axfr_results
        if not any(axfr_results.values()):
            console.print("  [green]✓[/green] AXFR denegado (correcto)")

    # ── Certificados crt.sh → endpoint ───────────────────────
    if target_info["type"] == "domain":
        console.print("[cyan]  [*][/cyan] Consultando crt.sh...")
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%25.{target}&output=json",
                timeout=timeout
            )
            if resp.status_code == 200:
                certs = resp.json()
                seen  = set()
                for cert in certs:
                    for sub in cert.get("name_value", "").lower().strip().split("\n"):
                        sub = sub.strip()
                        if sub and sub not in seen:
                            seen.add(sub)
                            results["certificates"].append({
                                "name":       sub,
                                "issuer":     cert.get("issuer_name", "N/A"),
                                "not_before": cert.get("not_before", ""),
                                "not_after":  cert.get("not_after", ""),
                            })
                console.print(f"  [green]✓[/green] {len(seen)} nombres en crt.sh")
        except Exception as e:
            console.print(f"  [yellow]![/yellow] crt.sh falló: {e}")

    # ── ASN/BGP → root_domain scope ──────────────────────────
    console.print("[cyan]  [*][/cyan] Consulta ASN/BGP...")
    ips = target_info.get("ips", [target_info["value"]] if target_info["type"] == "ip" else [])
    for ip in ips[:3]:
        try:
            obj = IPWhois(ip)
            res = obj.lookup_rdap(depth=1)
            results["asn"][ip] = {
                "asn":         res.get("asn", "N/A"),
                "asn_cidr":    res.get("asn_cidr", "N/A"),
                "asn_country": res.get("asn_country_code", "N/A"),
                "asn_desc":    res.get("asn_description", "N/A"),
            }
            console.print(f"  [green]✓[/green] {ip} → ASN{res.get('asn')} ({res.get('asn_description','N/A')})")
        except Exception as e:
            console.print(f"  [yellow]![/yellow] ASN falló para {ip}: {e}")

    if results["dns_records"] and config.get("verbose"):
        _print_dns_table(target, results["dns_records"])

    ep = len([f for f in results["findings"] if f.get("scope") != "root_domain"])
    rd = len([f for f in results["findings"] if f.get("scope") == "root_domain"])
    console.print(f"  [green]✓[/green] OSINT — {ep} hallazgo(s) endpoint, {rd} dominio raíz")
    return results


def _print_dns_table(domain, records):
    table = Table(title=f"DNS — {domain}", box=box.SIMPLE, border_style="cyan")
    table.add_column("Tipo", style="bold cyan", width=8)
    table.add_column("Valor")
    for rtype, values in records.items():
        for i, val in enumerate(values):
            table.add_row(rtype if i == 0 else "", val[:120])
    console.print(table)
