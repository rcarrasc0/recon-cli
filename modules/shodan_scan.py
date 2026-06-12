#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  recon-cli · modules/shodan_scan.py
#  Consulta Shodan por IP/dominio: puertos, servicios, vulns
# ─────────────────────────────────────────────────────────────

import shodan
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()


def run_shodan(target: str, target_info: dict, config: dict) -> dict:
    results = {
        "hosts": [],
        "open_ports": [],
        "services": [],
        "vulns": [],
        "findings": [],
    }

    api = shodan.Shodan(config["SHODAN_API_KEY"])
    ips = target_info.get("ips", [])
    if target_info["type"] == "ip":
        ips = [target_info["value"]]

    for ip in ips[:5]:
        console.print(f"[cyan]  [*][/cyan] Shodan lookup: {ip}")
        try:
            host = api.host(ip)
            host_data = {
                "ip":           ip,
                "org":          host.get("org", "N/A"),
                "isp":          host.get("isp", "N/A"),
                "country":      host.get("country_name", "N/A"),
                "city":         host.get("city", "N/A"),
                "os":           host.get("os", "N/A"),
                "last_update":  host.get("last_update", "N/A"),
                "ports":        host.get("ports", []),
                "hostnames":    host.get("hostnames", []),
                "tags":         host.get("tags", []),
                "vulns":        list(host.get("vulns", {}).keys()),
            }
            results["hosts"].append(host_data)
            results["open_ports"].extend(host.get("ports", []))

            console.print(f"  [green]✓[/green] {ip} → {len(host_data['ports'])} puerto(s) | Org: {host_data['org']}")

            # Servicios detectados
            for item in host.get("data", []):
                svc = {
                    "ip":        ip,
                    "port":      item.get("port"),
                    "transport": item.get("transport", "tcp"),
                    "product":   item.get("product", ""),
                    "version":   item.get("version", ""),
                    "cpe":       item.get("cpe", []),
                    "banner":    (item.get("data", "") or "")[:300],
                    "module":    item.get("_shodan", {}).get("module", ""),
                }
                results["services"].append(svc)

            # Vulnerabilidades reportadas por Shodan
            for cve_id, cve_data in host.get("vulns", {}).items():
                vuln = {
                    "ip":      ip,
                    "cve":     cve_id,
                    "cvss":    cve_data.get("cvss", 0.0),
                    "summary": cve_data.get("summary", ""),
                    "verified": cve_data.get("verified", False),
                }
                results["vulns"].append(vuln)
                severity = _cvss_to_severity(vuln["cvss"])
                results["findings"].append({
                    "phase": "Shodan",
                    "title": f"Vulnerabilidad Shodan: {cve_id} en {ip}",
                    "description": vuln["summary"][:300],
                    "severity": severity,
                    "cvss": vuln["cvss"],
                    "remediation": f"Revisar y aplicar parche para {cve_id}. Verificar versión del servicio afectado.",
                })

            # Hallazgo: puertos sensibles expuestos
            sensitive_ports = {
                21: "FTP", 23: "Telnet", 25: "SMTP", 445: "SMB",
                3389: "RDP", 5900: "VNC", 6379: "Redis", 27017: "MongoDB",
                9200: "Elasticsearch", 11211: "Memcached",
            }
            for port in host_data["ports"]:
                if port in sensitive_ports:
                    results["findings"].append({
                        "phase": "Shodan",
                        "title": f"Puerto sensible expuesto: {port}/{sensitive_ports[port]} en {ip}",
                        "description": f"El puerto {port} ({sensitive_ports[port]}) está accesible desde Internet.",
                        "severity": "HIGH",
                        "cvss": 7.5,
                        "remediation": f"Restringir acceso al puerto {port} mediante firewall. Evaluar si el servicio debe estar expuesto públicamente.",
                    })

            # Tabla de servicios en modo verbose
            if config.get("verbose") and results["services"]:
                _print_services_table(ip, results["services"])

        except shodan.APIError as e:
            if "No information available" in str(e):
                console.print(f"  [yellow]![/yellow] {ip} no encontrado en Shodan")
            else:
                console.print(f"  [yellow]![/yellow] Error Shodan para {ip}: {e}")

    results["open_ports"] = sorted(list(set(results["open_ports"])))
    console.print(f"  [green]✓[/green] Shodan completado — {len(results['vulns'])} vuln(s), {len(results['open_ports'])} puerto(s)")
    return results


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:   return "CRITICAL"
    if score >= 7.0:   return "HIGH"
    if score >= 4.0:   return "MEDIUM"
    if score > 0:      return "LOW"
    return "INFO"


def _print_services_table(ip: str, services: list):
    table = Table(title=f"Servicios Shodan — {ip}", box=box.SIMPLE, border_style="cyan")
    table.add_column("Puerto", style="bold cyan", width=8)
    table.add_column("Proto", width=6)
    table.add_column("Producto")
    table.add_column("Versión")
    for svc in services:
        if svc["ip"] == ip:
            table.add_row(
                str(svc["port"]),
                svc["transport"],
                svc["product"] or "—",
                svc["version"] or "—",
            )
    console.print(table)
