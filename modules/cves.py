#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  recon-cli · modules/cves.py
#  Búsqueda de CVEs en NVD/NIST API v2 a partir de productos
#  y versiones detectadas en fases anteriores.
# ─────────────────────────────────────────────────────────────

import time
import requests
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

NVD_API_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RATE_LIMIT_S = 0.6   # sin API key: 5 req/30s → ~0.6s entre llamadas
AUTH_LIMIT_S = 0.12  # con API key: 50 req/30s → ~0.12s entre llamadas


def run_cve_lookup(results: dict, config: dict) -> list:
    """
    Extrae productos/versiones de fases anteriores y consulta NVD.
    Devuelve lista de CVEs encontrados.
    """
    all_cves = []
    api_key  = config.get("NVD_API_KEY", "")
    delay    = AUTH_LIMIT_S if api_key else RATE_LIMIT_S
    timeout  = config.get("REQUEST_TIMEOUT", 15)

    # Recopilar productos a buscar
    products = _extract_products(results)

    if not products:
        console.print("  [yellow]![/yellow] No se detectaron productos/versiones para buscar CVEs")
        return all_cves

    console.print(f"[cyan]  [*][/cyan] Buscando CVEs para {len(products)} producto(s)...")

    for product in products:
        keyword = product["keyword"]
        version = product.get("version", "")
        source  = product.get("source", "")

        console.print(f"  [cyan]·[/cyan] {keyword} {version} ({source})")

        try:
            cves = _query_nvd(keyword, version, api_key, timeout)
            for cve in cves:
                cve["product"]  = keyword
                cve["version"]  = version
                all_cves.append(cve)

            if cves:
                console.print(f"    [red]⚠[/red] {len(cves)} CVE(s) encontrado(s) para {keyword} {version}")
            else:
                console.print(f"    [green]✓[/green] Sin CVEs conocidos para {keyword} {version}")

            time.sleep(delay)

        except Exception as e:
            console.print(f"    [yellow]![/yellow] Error consultando NVD para {keyword}: {e}")

    # Ordenar por CVSS descendente
    all_cves.sort(key=lambda c: c.get("cvss_score", 0), reverse=True)

    if all_cves and config.get("verbose"):
        _print_cves_table(all_cves[:20])

    console.print(f"  [green]✓[/green] CVEs completado — {len(all_cves)} CVE(s) encontrado(s)")
    return all_cves


def _extract_products(results: dict) -> list:
    """Extrae pares producto/versión de todos los resultados disponibles."""
    products = []
    seen     = set()

    def add(keyword: str, version: str = "", source: str = ""):
        key = f"{keyword.lower()}:{version.lower()}"
        if key not in seen and keyword.strip():
            seen.add(key)
            products.append({
                "keyword": keyword.strip(),
                "version": version.strip(),
                "source":  source,
            })

    # ── Desde Shodan (servicios detectados) ───────────────────
    for svc in results.get("shodan", {}).get("services", []):
        product = svc.get("product", "")
        version = svc.get("version", "")
        if product:
            add(product, version, "Shodan")

    # ── Desde enumeración (tecnologías HTTP) ──────────────────
    for tech, version in results.get("enumeration", {}).get("technologies", {}).items():
        v = version if version != "detectado" else ""
        add(tech, v, "HTTP Headers")

    # ── Desde cabeceras (Server, X-Powered-By) ────────────────
    for header, value in results.get("headers", {}).get("info_leaks", {}).items():
        if header in ("server", "x-powered-by"):
            # Intentar separar nombre y versión
            parts = value.split("/", 1)
            name  = parts[0].strip()
            ver   = parts[1].split(" ")[0].strip() if len(parts) > 1 else ""
            add(name, ver, f"Header:{header}")

    # ── Desde certificado (issuer como indicador de stack) ────
    issuer = results.get("ssl_tls", {}).get("certificate", {}).get("issuer_cn", "")
    if issuer and "let's encrypt" not in issuer.lower():
        add(issuer, "", "Certificado")

    return products


def _query_nvd(keyword: str, version: str, api_key: str, timeout: int) -> list:
    """Consulta NVD API v2 y devuelve lista de CVEs normalizados."""
    headers = {"apiKey": api_key} if api_key else {}
    params  = {
        "keywordSearch": f"{keyword} {version}".strip(),
        "resultsPerPage": 20,
        "startIndex":     0,
    }

    if version:
        params["versionEnd"]          = version
        params["versionEndType"]      = "including"

    resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=timeout)

    if resp.status_code == 403:
        raise Exception("NVD API: acceso denegado (rate limit o API key inválida)")
    if resp.status_code != 200:
        raise Exception(f"NVD API: HTTP {resp.status_code}")

    data         = resp.json()
    total        = data.get("totalResults", 0)
    vulnerabilities = data.get("vulnerabilities", [])

    cves = []
    for item in vulnerabilities:
        cve_obj = item.get("cve", {})
        cve_id  = cve_obj.get("id", "")

        # Descripción en inglés
        description = ""
        for desc in cve_obj.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # CVSS Score (v3.1 > v3.0 > v2)
        cvss_score = 0.0
        cvss_vector = ""
        severity    = "UNKNOWN"
        metrics     = cve_obj.get("metrics", {})

        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                m = metric_list[0].get("cvssData", {})
                cvss_score  = m.get("baseScore", 0.0)
                cvss_vector = m.get("vectorString", "")
                severity    = m.get("baseSeverity", _score_to_severity(cvss_score))
                break

        # Fecha publicación
        published = cve_obj.get("published", "")[:10]

        # Referencias
        refs = [r.get("url", "") for r in cve_obj.get("references", [])[:3]]

        # Remediation hint desde tags de referencias
        remediation = "Consultar el advisory oficial y aplicar el parche correspondiente."
        for ref in cve_obj.get("references", []):
            tags = ref.get("tags", [])
            if "Patch" in tags or "Vendor Advisory" in tags:
                remediation = f"Aplicar parche del fabricante: {ref.get('url', '')}"
                break

        cves.append({
            "id":           cve_id,
            "description":  description[:500],
            "cvss_score":   cvss_score,
            "cvss_vector":  cvss_vector,
            "severity":     severity.upper() if severity else _score_to_severity(cvss_score),
            "published":    published,
            "references":   refs,
            "remediation":  remediation,
        })

    return cves


def _score_to_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0:    return "LOW"
    return "NONE"


def _print_cves_table(cves: list):
    table = Table(title="CVEs encontrados", box=box.ROUNDED, border_style="red")
    table.add_column("CVE ID",     style="bold cyan", width=18)
    table.add_column("Producto",   width=18)
    table.add_column("CVSS",       justify="center", width=6)
    table.add_column("Severidad",  justify="center", width=10)
    table.add_column("Publicado",  width=12)

    severity_styles = {
        "CRITICAL": "bold red", "HIGH": "red",
        "MEDIUM":   "yellow",   "LOW":  "cyan", "NONE": "white",
    }

    for cve in cves:
        sev   = cve.get("severity", "NONE")
        style = severity_styles.get(sev, "white")
        table.add_row(
            cve.get("id", ""),
            cve.get("product", "")[:18],
            str(cve.get("cvss_score", "")),
            f"[{style}]{sev}[/{style}]",
            cve.get("published", ""),
        )

    console.print(table)
