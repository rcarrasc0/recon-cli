#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  recon-cli · modules/osint.py
#  WHOIS, DNS (A/AAAA/MX/TXT/NS/SOA), AXFR, crt.sh, ASN/BGP
# ─────────────────────────────────────────────────────────────

import requests
import whois
import dns.resolver
import dns.zone
import dns.query
import dns.exception
from ipwhois import IPWhois
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

TIMEOUT = 10


def run_osint(target: str, target_info: dict, config: dict) -> dict:
    results = {
        "whois": {},
        "dns_records": {},
        "axfr": {},
        "certificates": [],
        "asn": {},
        "findings": [],
    }

    timeout = config.get("REQUEST_TIMEOUT", TIMEOUT)

    # ── WHOIS ─────────────────────────────────────────────────
    console.print("[cyan]  [*][/cyan] WHOIS...")
    try:
        w = whois.whois(target)
        results["whois"] = {
            "registrar":      str(w.registrar or "N/A"),
            "creation_date":  str(w.creation_date or "N/A"),
            "expiration_date": str(w.expiration_date or "N/A"),
            "name_servers":   w.name_servers or [],
            "emails":         w.emails or [],
            "org":            str(w.org or "N/A"),
            "country":        str(w.country or "N/A"),
            "raw":            str(w.text or ""),
        }
        console.print(f"  [green]✓[/green] Registrar: {results['whois']['registrar']}")

        # Hallazgo: emails expuestos en WHOIS
        if results["whois"]["emails"]:
            for email in results["whois"]["emails"]:
                results["findings"].append({
                    "phase": "OSINT",
                    "title": "Email expuesto en WHOIS",
                    "description": f"Email {email} visible en registros WHOIS públicos.",
                    "severity": "INFO",
                    "cvss": 0.0,
                    "remediation": "Considerar privacidad WHOIS (WHOIS privacy protection) con el registrador.",
                })
    except Exception as e:
        console.print(f"  [yellow]![/yellow] WHOIS falló: {e}")

    # ── DNS Records ───────────────────────────────────────────
    if target_info["type"] == "domain":
        console.print("[cyan]  [*][/cyan] Consultas DNS...")
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"]
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
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

        # Hallazgo: SPF / DMARC / DKIM ausentes
        txt_records = " ".join(results["dns_records"].get("TXT", []))
        if "v=spf1" not in txt_records:
            results["findings"].append({
                "phase": "OSINT",
                "title": "SPF no configurado",
                "description": "No se encontró registro SPF en los TXT del dominio. Permite spoofing de email.",
                "severity": "MEDIUM",
                "cvss": 5.3,
                "remediation": "Añadir registro TXT SPF: v=spf1 include:... -all",
            })
        if "v=DMARC1" not in txt_records:
            results["findings"].append({
                "phase": "OSINT",
                "title": "DMARC no configurado",
                "description": "No se encontró registro _dmarc. Sin política DMARC el dominio es vulnerable a email spoofing.",
                "severity": "MEDIUM",
                "cvss": 5.3,
                "remediation": "Añadir registro TXT en _dmarc.<dominio>: v=DMARC1; p=reject; rua=mailto:...",
            })

        # ── AXFR ──────────────────────────────────────────────
        console.print("[cyan]  [*][/cyan] Intentando transferencia de zona (AXFR)...")
        ns_list = results["dns_records"].get("NS", [])
        axfr_results = {}

        for ns in ns_list:
            ns = ns.rstrip(".")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns, target, timeout=timeout))
                records = []
                for name, node in zone.nodes.items():
                    rdatasets = node.rdatasets
                    for rdataset in rdatasets:
                        for rdata in rdataset:
                            records.append(f"{name} {dns.rdatatype.to_text(rdataset.rdtype)} {rdata}")
                axfr_results[ns] = records
                console.print(f"  [bold red]⚠ AXFR exitoso en {ns}! {len(records)} registros expuestos[/bold red]")
                results["findings"].append({
                    "phase": "OSINT",
                    "title": f"Transferencia de zona AXFR permitida en {ns}",
                    "description": f"El servidor DNS {ns} permite transferencias de zona. {len(records)} registros expuestos.",
                    "severity": "HIGH",
                    "cvss": 7.5,
                    "remediation": "Restringir AXFR solo a servidores DNS secundarios autorizados (ACL en BIND/etc).",
                })
            except Exception:
                axfr_results[ns] = []

        results["axfr"] = axfr_results

        if not any(axfr_results.values()):
            console.print("  [green]✓[/green] AXFR denegado en todos los NS (correcto)")

    # ── Certificados (crt.sh) ─────────────────────────────────
    if target_info["type"] == "domain":
        console.print("[cyan]  [*][/cyan] Consultando crt.sh...")
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%25.{target}&output=json",
                timeout=timeout
            )
            if resp.status_code == 200:
                certs = resp.json()
                seen = set()
                for cert in certs:
                    name = cert.get("name_value", "").lower().strip()
                    for sub in name.split("\n"):
                        sub = sub.strip()
                        if sub and sub not in seen:
                            seen.add(sub)
                            results["certificates"].append({
                                "name": sub,
                                "issuer": cert.get("issuer_name", "N/A"),
                                "not_before": cert.get("not_before", ""),
                                "not_after": cert.get("not_after", ""),
                                "id": cert.get("id", ""),
                            })
                console.print(f"  [green]✓[/green] {len(seen)} nombres únicos encontrados en crt.sh")
        except Exception as e:
            console.print(f"  [yellow]![/yellow] crt.sh falló: {e}")

    # ── ASN / BGP / rDNS ──────────────────────────────────────
    console.print("[cyan]  [*][/cyan] Consulta ASN/BGP...")
    ips_to_check = target_info.get("ips", [])
    if target_info["type"] == "ip":
        ips_to_check = [target_info["value"]]

    asn_data = {}
    for ip in ips_to_check[:3]:  # máximo 3 IPs
        try:
            obj = IPWhois(ip)
            res = obj.lookup_rdap(depth=1)
            asn_data[ip] = {
                "asn":          res.get("asn", "N/A"),
                "asn_cidr":     res.get("asn_cidr", "N/A"),
                "asn_country":  res.get("asn_country_code", "N/A"),
                "asn_desc":     res.get("asn_description", "N/A"),
                "network_name": res.get("network", {}).get("name", "N/A"),
            }
            console.print(f"  [green]✓[/green] {ip} → ASN{res.get('asn')} ({res.get('asn_description', 'N/A')})")
        except Exception as e:
            console.print(f"  [yellow]![/yellow] ASN lookup falló para {ip}: {e}")

    results["asn"] = asn_data

    # ── Mostrar tabla resumen DNS ─────────────────────────────
    if results["dns_records"] and config.get("verbose"):
        _print_dns_table(target, results["dns_records"])

    console.print(f"  [green]✓[/green] OSINT completado — {len(results['findings'])} hallazgo(s)")
    return results


def _print_dns_table(domain: str, records: dict):
    table = Table(title=f"DNS Records — {domain}", box=box.SIMPLE, border_style="cyan")
    table.add_column("Tipo", style="bold cyan", width=8)
    table.add_column("Valor")
    for rtype, values in records.items():
        for i, val in enumerate(values):
            table.add_row(rtype if i == 0 else "", val[:120])
    console.print(table)
