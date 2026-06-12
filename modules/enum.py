#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  recon-cli · modules/enum.py
#  Enumeración de subdominios (crt.sh + fuerza bruta DNS)
#  y detección de tecnologías HTTP
# ─────────────────────────────────────────────────────────────

import socket
import concurrent.futures
import httpx
import dns.resolver
import dns.exception
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

console = Console()

# Wordlist básica de subdominios comunes
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "mx", "ns1", "ns2",
    "vpn", "remote", "gateway", "admin", "portal", "api", "app", "dev", "stage",
    "staging", "test", "demo", "beta", "cdn", "static", "media", "img", "images",
    "assets", "blog", "shop", "store", "help", "support", "docs", "wiki",
    "dashboard", "panel", "login", "auth", "sso", "id", "accounts", "my",
    "monitoring", "status", "health", "metrics", "grafana", "kibana", "elastic",
    "jenkins", "gitlab", "git", "repo", "jira", "confluence",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "backup", "files", "upload", "download", "filer",
    "intranet", "internal", "corp", "office", "extranet",
    "m", "mobile", "wap", "api2", "v1", "v2",
]

# Firmas de tecnologías (header/body patterns)
TECH_SIGNATURES = {
    "Nginx":        {"headers": {"Server": "nginx"}},
    "Apache":       {"headers": {"Server": "Apache"}},
    "IIS":          {"headers": {"Server": "Microsoft-IIS"}},
    "Cloudflare":   {"headers": {"Server": "cloudflare", "CF-RAY": ""}},
    "WordPress":    {"body": "wp-content", "headers": {"X-Powered-By": ""}},
    "Drupal":       {"body": "Drupal", "headers": {"X-Generator": "Drupal"}},
    "Joomla":       {"body": "/components/com_"},
    "Laravel":      {"headers": {"X-Powered-By": ""},"body": "laravel"},
    "Django":       {"headers": {"X-Frame-Options": ""}, "body": "csrfmiddlewaretoken"},
    "PHP":          {"headers": {"X-Powered-By": "PHP"}},
    "ASP.NET":      {"headers": {"X-Powered-By": "ASP.NET", "X-AspNet-Version": ""}},
    "Node.js":      {"headers": {"X-Powered-By": "Express"}},
    "jQuery":       {"body": "jquery"},
    "React":        {"body": "react"},
    "Vue.js":       {"body": "vue"},
    "Angular":      {"body": "ng-version"},
    "Bootstrap":    {"body": "bootstrap"},
}


def run_enumeration(target: str, target_info: dict, osint_data: dict, config: dict) -> dict:
    results = {
        "subdomains": [],
        "live_hosts": [],
        "technologies": {},
        "findings": [],
    }

    if target_info["type"] == "ip":
        console.print("  [yellow]![/yellow] Target es IP — omitiendo enumeración de subdominios")
        # Solo detección de tecnologías
        results["technologies"] = _detect_technologies(target_info["value"], config)
        return results

    domain = target_info["domain"]

    # ── Subdominios desde crt.sh ──────────────────────────────
    crt_names = set()
    for cert in osint_data.get("certificates", []):
        name = cert.get("name", "").strip().lstrip("*.")
        if name and domain in name:
            crt_names.add(name)
    console.print(f"[cyan]  [*][/cyan] {len(crt_names)} subdominios únicos desde crt.sh")

    # ── Fuerza bruta DNS ──────────────────────────────────────
    max_subs = config.get("MAX_SUBDOMAINS", 500)
    threads  = config.get("DNS_THREADS", 20)
    wordlist = COMMON_SUBDOMAINS[:max_subs]

    console.print(f"[cyan]  [*][/cyan] Fuerza bruta DNS ({len(wordlist)} palabras, {threads} hilos)...")

    brute_found = set()
    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), transient=True) as progress:
        progress.add_task("Resolviendo subdominios...", total=None)
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(_resolve_subdomain, f"{sub}.{domain}", config): sub
                for sub in wordlist
            }
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    brute_found.add(result["fqdn"])
                    results["subdomains"].append(result)

    all_names = crt_names | brute_found
    console.print(f"  [green]✓[/green] {len(results['subdomains'])} subdominios resueltos ({len(brute_found)} brute, {len(crt_names)} crt.sh)")

    # Añadir los de crt.sh que no se han resuelto aún
    resolved_fqdns = {s["fqdn"] for s in results["subdomains"]}
    for name in crt_names:
        if name not in resolved_fqdns:
            resolved = _resolve_subdomain(name, config)
            if resolved:
                results["subdomains"].append(resolved)

    # ── Live hosts (HTTP/HTTPS) ───────────────────────────────
    console.print(f"[cyan]  [*][/cyan] Comprobando hosts activos (HTTP/HTTPS)...")
    live = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(_check_http, sub["fqdn"], config): sub
            for sub in results["subdomains"]
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                live.append(result)

    results["live_hosts"] = live
    console.print(f"  [green]✓[/green] {len(live)} host(s) HTTP activo(s)")

    # ── Detección de tecnologías en host principal ────────────
    console.print(f"[cyan]  [*][/cyan] Detectando tecnologías en {domain}...")
    results["technologies"] = _detect_technologies(domain, config)

    # ── Hallazgos ─────────────────────────────────────────────
    if len(results["subdomains"]) > 20:
        results["findings"].append({
            "phase": "Enumeración",
            "title": f"Superficie de ataque amplia: {len(results['subdomains'])} subdominios",
            "description": f"Se encontraron {len(results['subdomains'])} subdominios activos. Mayor superficie de exposición.",
            "severity": "INFO",
            "cvss": 0.0,
            "remediation": "Revisar subdominios no necesarios y retirarlos. Implementar monitorización de subdominios.",
        })

    # Subdomain takeover potencial (resuelve pero no responde HTTP)
    for sub in results["subdomains"]:
        fqdn = sub["fqdn"]
        live_fqdns = {h["fqdn"] for h in live}
        if fqdn not in live_fqdns and sub.get("ips"):
            results["findings"].append({
                "phase": "Enumeración",
                "title": f"Posible subdominio huérfano: {fqdn}",
                "description": f"{fqdn} resuelve a {sub['ips']} pero no responde HTTP/HTTPS. Riesgo de subdomain takeover.",
                "severity": "LOW",
                "cvss": 3.1,
                "remediation": "Verificar si el subdominio sigue siendo necesario. Si no, eliminar el registro DNS.",
            })

    if config.get("verbose") and results["subdomains"]:
        _print_subdomains_table(results["subdomains"][:20])

    console.print(f"  [green]✓[/green] Enumeración completada — {len(results['findings'])} hallazgo(s)")
    return results


def _resolve_subdomain(fqdn: str, config: dict) -> dict | None:
    try:
        timeout = config.get("REQUEST_TIMEOUT", 5)
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(fqdn, "A")
        ips = [str(r) for r in answers]
        return {"fqdn": fqdn, "ips": ips, "type": "A"}
    except Exception:
        return None


def _check_http(fqdn: str, config: dict) -> dict | None:
    timeout = config.get("REQUEST_TIMEOUT", 5)
    for scheme in ["https", "http"]:
        try:
            url = f"{scheme}://{fqdn}"
            with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as client:
                resp = client.get(url)
                return {
                    "fqdn":        fqdn,
                    "url":         url,
                    "status_code": resp.status_code,
                    "title":       _extract_title(resp.text),
                    "server":      resp.headers.get("server", ""),
                    "redirect":    str(resp.url) if str(resp.url) != url else "",
                }
        except Exception:
            continue
    return None


def _extract_title(html: str) -> str:
    import re
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip()[:80] if match else ""


def _detect_technologies(host: str, config: dict) -> dict:
    timeout = config.get("REQUEST_TIMEOUT", 10)
    detected = {}

    for scheme in ["https", "http"]:
        try:
            url = f"{scheme}://{host}"
            with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as client:
                resp = client.get(url)

            headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
            body_lower    = resp.text.lower()

            for tech, sigs in TECH_SIGNATURES.items():
                matched = False
                version = ""

                if "headers" in sigs:
                    for h_key, h_val in sigs["headers"].items():
                        h_key_l = h_key.lower()
                        if h_key_l in headers_lower:
                            if not h_val or h_val.lower() in headers_lower[h_key_l]:
                                matched = True
                                # Intentar extraer versión
                                raw_val = resp.headers.get(h_key, "")
                                if "/" in raw_val:
                                    version = raw_val.split("/")[-1].split(" ")[0]

                if "body" in sigs and sigs["body"].lower() in body_lower:
                    matched = True

                if matched:
                    detected[tech] = version or "detectado"

            console.print(f"  [green]✓[/green] Tecnologías detectadas: {', '.join(detected.keys()) or 'ninguna identificada'}")
            break
        except Exception:
            continue

    return detected


def _print_subdomains_table(subdomains: list):
    table = Table(title="Subdominios resueltos (top 20)", box=box.SIMPLE, border_style="cyan")
    table.add_column("FQDN", style="cyan")
    table.add_column("IPs")
    for sub in subdomains:
        table.add_row(sub["fqdn"], ", ".join(sub.get("ips", [])))
    console.print(table)
