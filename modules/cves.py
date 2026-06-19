#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  recon-cli · modules/cves.py  v1.2.0
#  Búsqueda de CVEs en NVD/NIST API v2.
#  Mejoras: timeout 30s, retries automáticos, warning
#  cuando NVD no está disponible, estado de disponibilidad
#  propagado al informe PDF.
# ─────────────────────────────────────────────────────────────

import time
import requests
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

NVD_API_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT  = 30     # segundos — subido de 10 a 30
RATE_LIMIT_S = 0.6    # sin API key: 5 req/30s
AUTH_LIMIT_S = 0.12   # con API key: 50 req/30s
MAX_RETRIES  = 3
RETRY_DELAY  = 5      # segundos entre reintentos


def run_cve_lookup(results: dict, config: dict) -> list:
    all_cves   = []
    nvd_errors = []
    api_key    = config.get("NVD_API_KEY", "")
    delay      = AUTH_LIMIT_S if api_key else RATE_LIMIT_S
    products   = _extract_products(results)

    if not products:
        console.print("  [yellow]![/yellow] No se detectaron productos/versiones para buscar CVEs")
        # Propagar estado al config para el PDF
        config["nvd_status"] = "no_products"
        return all_cves

    console.print(f"[cyan]  [*][/cyan] Buscando CVEs para {len(products)} producto(s) (timeout={NVD_TIMEOUT}s, retries={MAX_RETRIES})...")

    for product in products:
        keyword = product["keyword"]
        version = product.get("version", "")
        source  = product.get("source", "")

        console.print(f"  [cyan]·[/cyan] {keyword} {version} ({source})")

        try:
            cves = _query_nvd_with_retry(keyword, version, api_key)
            for cve in cves:
                cve["product"] = keyword
                cve["version"] = version
                all_cves.append(cve)

            if cves:
                console.print(f"    [red]⚠[/red] {len(cves)} CVE(s) para {keyword} {version}")
            else:
                console.print(f"    [green]✓[/green] Sin CVEs conocidos para {keyword} {version}")

        except Exception as e:
            err_msg = str(e)
            nvd_errors.append({"product": keyword, "error": err_msg})
            console.print(f"    [red]![/red] NVD falló para {keyword}: {err_msg}")

        time.sleep(delay)

    # ── Warning consolidado si hubo errores ───────────────────
    if nvd_errors:
        console.print(f"\n  [bold red]⚠ WARNING NVD:[/bold red] {len(nvd_errors)} consulta(s) fallaron")
        console.print("  [yellow]  Los resultados CVE pueden estar INCOMPLETOS[/yellow]")
        console.print("  [yellow]  Causa probable: NVD saturado, rate-limit o timeout[/yellow]")
        config["nvd_status"]  = "partial"
        config["nvd_errors"]  = nvd_errors
    else:
        config["nvd_status"] = "ok"

    all_cves.sort(key=lambda c: c.get("cvss_score", 0), reverse=True)

    if all_cves and config.get("verbose"):
        _print_cves_table(all_cves[:20])

    console.print(f"  [green]✓[/green] CVEs completado — {len(all_cves)} CVE(s) encontrado(s)")
    return all_cves


def _query_nvd_with_retry(keyword: str, version: str, api_key: str) -> list:
    """Consulta NVD con reintentos automáticos ante timeout o 503."""
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return _query_nvd(keyword, version, api_key)
        except requests.exceptions.Timeout:
            last_error = f"Timeout tras {NVD_TIMEOUT}s"
            if attempt < MAX_RETRIES:
                console.print(f"    [yellow]![/yellow] Timeout (intento {attempt}/{MAX_RETRIES}) — reintentando en {RETRY_DELAY}s...")
                time.sleep(RETRY_DELAY)
        except requests.exceptions.ConnectionError as e:
            last_error = f"Error de conexión: {e}"
            if attempt < MAX_RETRIES:
                console.print(f"    [yellow]![/yellow] Conexión fallida (intento {attempt}/{MAX_RETRIES}) — reintentando...")
                time.sleep(RETRY_DELAY)
        except Exception as e:
            # Errores no recuperables (403, 404, JSON inválido): no reintentar
            raise e

    raise Exception(last_error or "NVD no disponible tras reintentos")


def _query_nvd(keyword: str, version: str, api_key: str) -> list:
    headers = {"apiKey": api_key} if api_key else {}
    params  = {
        "keywordSearch":  f"{keyword} {version}".strip(),
        "resultsPerPage": 20,
        "startIndex":     0,
    }
    if version:
        params["versionEnd"]     = version
        params["versionEndType"] = "including"

    resp = requests.get(
        NVD_API_URL,
        params=params,
        headers=headers,
        timeout=NVD_TIMEOUT
    )

    if resp.status_code == 403:
        raise Exception("NVD API: acceso denegado (rate limit o API key inválida)")
    if resp.status_code == 503:
        raise requests.exceptions.ConnectionError("NVD API: servicio no disponible (503)")
    if resp.status_code != 200:
        raise Exception(f"NVD API: HTTP {resp.status_code}")

    data            = resp.json()
    vulnerabilities = data.get("vulnerabilities", [])
    cves            = []

    for item in vulnerabilities:
        cve_obj = item.get("cve", {})
        cve_id  = cve_obj.get("id", "")

        description = ""
        for desc in cve_obj.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        cvss_score  = 0.0
        cvss_vector = ""
        severity    = "UNKNOWN"
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            ml = cve_obj.get("metrics", {}).get(metric_key, [])
            if ml:
                m           = ml[0].get("cvssData", {})
                cvss_score  = m.get("baseScore", 0.0)
                cvss_vector = m.get("vectorString", "")
                severity    = m.get("baseSeverity", _score_to_severity(cvss_score))
                break

        published   = cve_obj.get("published", "")[:10]
        refs        = [r.get("url", "") for r in cve_obj.get("references", [])[:3]]
        remediation = "Consultar el advisory oficial y aplicar el parche correspondiente."
        for ref in cve_obj.get("references", []):
            if "Patch" in ref.get("tags", []) or "Vendor Advisory" in ref.get("tags", []):
                remediation = f"Aplicar parche del fabricante: {ref.get('url', '')}"
                break

        cves.append({
            "id":          cve_id,
            "description": description[:500],
            "cvss_score":  cvss_score,
            "cvss_vector": cvss_vector,
            "severity":    severity.upper() if severity else _score_to_severity(cvss_score),
            "published":   published,
            "references":  refs,
            "remediation": remediation,
        })

    return cves


# Productos que NVD no resuelve bien por keyword — excluir siempre
NVD_BLACKLIST = {
    "microsoft azure application gateway",
    "microsoft-azure-application-gateway",
    "azure application gateway",
    "azure front door",
    "cloudflare",
    "amazon cloudfront",
}

def _extract_products(results: dict) -> list:
    """
    Regla única: solo va a NVD si hay versión confirmada.
    Sin versión = sin CVE. Sin excepciones.

    Fuentes por confianza:
    - HIGH:   nmap -sV con versión | Shodan con versión
    - MEDIUM: header con versión (Server: nginx/1.24.0)
    - SKIP:   cualquier tecnología sin versión → omitida
    """
    products = []
    seen     = set()

    def add(keyword: str, version: str = "", source: str = "", confidence: str = "MEDIUM"):
        # Blacklist: productos que NVD no resuelve bien
        if keyword.lower().strip() in NVD_BLACKLIST:
            console.print(f"  [dim]  Omitiendo {keyword} (excluido de NVD — keyword no mapea bien)[/dim]")
            return
        # Regla principal: sin versión → no va a NVD
        if not version.strip():
            console.print(f"  [dim]  Omitiendo {keyword} (sin versión confirmada)[/dim]")
            return
        key = f"{keyword.lower()}:{version.lower()}"
        if key not in seen and keyword.strip():
            seen.add(key)
            products.append({
                "keyword":    keyword.strip(),
                "version":    version.strip(),
                "source":     source,
                "confidence": confidence,
            })

    # ── nmap -sV: máxima confianza ────────────────────────────
    for svc in results.get("enumeration", {}).get("nmap_services", []):
        if svc.get("product") and svc.get("version"):
            add(svc["product"], svc["version"], "nmap -sV", "HIGH")

    # ── Shodan: alta confianza ────────────────────────────────
    for svc in results.get("shodan", {}).get("services", []):
        if svc.get("product") and svc.get("version"):
            add(svc["product"], svc["version"], "Shodan", "HIGH")

    # ── Tecnologías detectadas (headers + body) ───────────────
    for tech, info in results.get("enumeration", {}).get("technologies", {}).items():
        if isinstance(info, dict):
            version    = info.get("version", "")
            confidence = info.get("confidence", "LOW")
        else:
            version    = info if info not in ("detectado", "") else ""
            confidence = "HIGH" if version else "LOW"
        # Sin versión → omitir (la función add lo gestiona)
        add(tech, version, "HTTP Tech", confidence)

    # ── Info leaks en headers (Server, X-Powered-By) ─────────
    for header, value in results.get("headers", {}).get("info_leaks", {}).items():
        if header in ("server", "x-powered-by"):
            parts = value.split("/", 1)
            name  = parts[0].strip()
            ver   = parts[1].split(" ")[0].strip() if len(parts) > 1 else ""
            # Sin versión en el header → no aporta nada a NVD
            add(name, ver, f"Header:{header}", "HIGH" if ver else "LOW")

    priority = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    products.sort(key=lambda p: priority.get(p["confidence"], 3))

    if products:
        console.print(f"  [cyan]  [*][/cyan] Productos con versión confirmada para NVD: "
                      f"[green]{sum(1 for p in products if p['confidence'] == 'HIGH')} HIGH[/green], "
                      f"[yellow]{sum(1 for p in products if p['confidence'] == 'MEDIUM')} MEDIUM[/yellow]")
    else:
        console.print("  [yellow]  ![/yellow] Ningún producto con versión confirmada — CVE omitido")

    return products


def _score_to_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0:    return "LOW"
    return "NONE"


def _print_cves_table(cves: list):
    table = Table(title="CVEs encontrados", box=box.ROUNDED, border_style="red")
    table.add_column("CVE ID",    style="bold cyan", width=18)
    table.add_column("Producto",  width=18)
    table.add_column("CVSS",      justify="center", width=6)
    table.add_column("Severidad", justify="center", width=10)
    table.add_column("Publicado", width=12)

    sev_styles = {"CRITICAL":"bold red","HIGH":"red","MEDIUM":"yellow","LOW":"cyan","NONE":"white"}
    for cve in cves:
        sev   = cve.get("severity", "NONE")
        style = sev_styles.get(sev, "white")
        table.add_row(
            cve.get("id",""),
            cve.get("product","")[:18],
            str(cve.get("cvss_score","")),
            f"[{style}]{sev}[/{style}]",
            cve.get("published",""),
        )
    console.print(table)
