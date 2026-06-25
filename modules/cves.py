#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  recon-cli · modules/cves.py  v1.1.6
#
#  Arquitectura de fuentes CVE:
#    Primaria:  NVD/NIST (keywordSearch)
#    Fallback:  vulnerability.circl.lu — Vulnerability-Lookup
#               API pública de CIRCL, gratuita, sin auth,
#               endpoint /api/search/{vendor}/{product}
#               documentada y activamente mantenida.
#
#  Por qué CIRCL y no MITRE CVE Services (cveawg.mitre.org):
#    La API de MITRE CVE Services está diseñada para CNAs
#    (gestión de registros), NO para búsqueda por producto.
#    Devuelve HTTP 400 ante consultas de búsqueda. No es apta
#    como fallback.
#
#  Por qué CIRCL y no CVE.org:
#    CVE.org no ofrece API de búsqueda por producto/versión.
#    Solo permite lookup por CVE-ID.
#
#  Regla: solo productos con versión confirmada van a CVE.
# ─────────────────────────────────────────────────────────────

import re
import time
import requests
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

NVD_API_URL    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# vulnerability.circl.lu reemplaza al antiguo cve.circl.lu
# API: GET /api/search/{vendor}/{product}
CIRCL_BASE_URL = "https://vulnerability.circl.lu"
NVD_TIMEOUT    = 30
CIRCL_TIMEOUT  = 15
RATE_LIMIT_S   = 0.6    # NVD sin key: 5 req/30s
AUTH_LIMIT_S   = 0.12   # NVD con key: 50 req/30s
MAX_RETRIES    = 3
RETRY_DELAY    = 5
NVD_FAIL_LIMIT = 3      # fallos consecutivos → activar fallback

NVD_BLACKLIST = {
    "microsoft azure application gateway",
    "microsoft-azure-application-gateway",
    "azure application gateway",
    "azure front door",
    "cloudflare",
    "amazon cloudfront",
}


def run_cve_lookup(results: dict, config: dict) -> list:
    global console
    console = config.get("console") or console
    all_cves        = []
    nvd_errors      = []
    nvd_consecutive = 0
    fallback_active = False
    api_key         = config.get("NVD_API_KEY", "")
    delay           = AUTH_LIMIT_S if api_key else RATE_LIMIT_S
    products        = _extract_products(results)

    if not products:
        console.print("  [yellow]![/yellow] Ningún producto con versión confirmada — CVE omitido")
        config["nvd_status"] = "no_products"
        config["cve_source"] = "none"
        config["cve_reason"] = "No se detectaron productos con versión confirmada"
        return all_cves

    console.print(
        f"[cyan]  [*][/cyan] Buscando CVEs para {len(products)} producto(s) "
        f"(timeout={NVD_TIMEOUT}s, retries={MAX_RETRIES})..."
    )

    for product in products:
        keyword = product["keyword"]
        version = product.get("version", "")
        source  = product.get("source", "")
        console.print(f"  [cyan]·[/cyan] {keyword} {version} ({source})")

        if fallback_active:
            _query_circl_and_append(keyword, version, all_cves)
            time.sleep(0.5)
            continue

        # ── NVD primario ──────────────────────────────────────
        try:
            cves = _query_nvd_with_retry(keyword, version, api_key)
            nvd_consecutive = 0
            for cve in cves:
                cve["product"] = keyword
                cve["version"] = version
                all_cves.append(cve)
            if cves:
                console.print(f"    [red]⚠[/red] {len(cves)} CVE(s) para {keyword} {version}")
            else:
                console.print(f"    [green]✓[/green] Sin CVEs conocidos para {keyword}")

        except Exception as e:
            nvd_errors.append({"product": keyword, "error": str(e)})
            nvd_consecutive += 1
            console.print(f"    [red]![/red] NVD falló ({nvd_consecutive}/{NVD_FAIL_LIMIT}): {e}")

            if nvd_consecutive >= NVD_FAIL_LIMIT:
                fallback_active = True
                config["nvd_fallback_reason"] = str(e)
                console.print(
                    f"\n  [bold yellow]⚡ NVD no disponible tras {NVD_FAIL_LIMIT} errores[/bold yellow]"
                )
                console.print("  [cyan]  [*][/cyan] Activando fallback → CIRCL Vulnerability-Lookup...")
                _query_circl_and_append(keyword, version, all_cves)

        time.sleep(delay if not fallback_active else 0.5)

    # ── Estado final ──────────────────────────────────────────
    if fallback_active:
        config["nvd_status"]    = "fallback"
        config["cve_source"]    = "CIRCL Vulnerability-Lookup (fallback)"
        config["cve_reason"]    = f"NVD no disponible: {config.get('nvd_fallback_reason','')}"
    elif nvd_errors:
        config["nvd_status"]    = "partial"
        config["cve_source"]    = "NVD/NIST (parcial)"
        config["cve_reason"]    = f"{len(nvd_errors)} consulta(s) fallaron"
    else:
        config["nvd_status"]    = "ok"
        config["cve_source"]    = "NVD/NIST"
        config["cve_reason"]    = ""

    config["nvd_errors"]        = nvd_errors
    config["nvd_fallback_used"] = fallback_active

    all_cves.sort(key=lambda c: c.get("cvss_score", 0), reverse=True)

    if all_cves and config.get("verbose"):
        _print_cves_table(all_cves[:20])

    console.print(
        f"  [green]✓[/green] CVEs — {len(all_cves)} encontrado(s) "
        f"[dim](fuente: {config['cve_source']})[/dim]"
    )
    return all_cves


# ── NVD ───────────────────────────────────────────────────────

def _query_nvd_with_retry(keyword: str, version: str, api_key: str) -> list:
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return _query_nvd(keyword, version, api_key)
        except requests.exceptions.Timeout:
            last_error = f"Timeout tras {NVD_TIMEOUT}s"
            if attempt < MAX_RETRIES:
                console.print(
                    f"    [yellow]![/yellow] Timeout ({attempt}/{MAX_RETRIES}) "
                    f"— reintentando en {RETRY_DELAY}s..."
                )
                time.sleep(RETRY_DELAY)
        except requests.exceptions.ConnectionError as e:
            last_error = f"Conexión: {e}"
            if attempt < MAX_RETRIES:
                console.print(f"    [yellow]![/yellow] Conexión fallida ({attempt}/{MAX_RETRIES})...")
                time.sleep(RETRY_DELAY)
        except Exception as e:
            raise e  # 403, 404 etc.: no reintentar
    raise Exception(last_error or "NVD no disponible")


def _query_nvd(keyword: str, version: str, api_key: str) -> list:
    """
    Normalización de queries NVD:
    - Usar solo el nombre del producto sin versión en keywordSearch
      (la versión en keywordSearch genera ruido o 404 en algunos casos)
    - Versión se pasa como versionEnd si está disponible
    - Para MariaDB, OpenSSH, WordPress: el problema era incluir
      la versión en el keyword; NVD los encuentra bien sin ella
    """
    headers = {"apiKey": api_key} if api_key else {}

    # Normalización: usar solo el nombre base del producto
    # ej: "OpenSSH 9.8" → keyword="OpenSSH", no "OpenSSH 9.8"
    clean_keyword = _clean_product_name(keyword)

    params = {
        "keywordSearch":  clean_keyword,
        "resultsPerPage": 20,
        "startIndex":     0,
    }
    # Solo añadir versionEnd si tenemos versión limpia
    if version:
        clean_version = _clean_version(version)
        if clean_version:
            params["versionEnd"]     = clean_version
            params["versionEndType"] = "including"

    resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=NVD_TIMEOUT)

    if resp.status_code == 403:
        raise Exception("NVD: rate limit o API key inválida (403)")
    if resp.status_code in (502, 503, 504):
        raise requests.exceptions.ConnectionError(f"NVD: no disponible ({resp.status_code})")
    if resp.status_code == 404:
        # 404 en NVD = producto no encontrado, no es error recuperable
        # pero tampoco debe activar el fallback — simplemente no hay CVEs
        return []
    if resp.status_code != 200:
        raise Exception(f"NVD: HTTP {resp.status_code}")

    cves = []
    for item in resp.json().get("vulnerabilities", []):
        cve_obj = item.get("cve", {})
        desc    = next(
            (d["value"] for d in cve_obj.get("descriptions", []) if d.get("lang") == "en"),
            ""
        )
        score, vector, sev = 0.0, "", "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            ml = cve_obj.get("metrics", {}).get(key, [])
            if ml:
                m      = ml[0].get("cvssData", {})
                score  = m.get("baseScore", 0.0)
                vector = m.get("vectorString", "")
                sev    = m.get("baseSeverity", _score_to_sev(score))
                break
        rem = "Consultar el advisory oficial y aplicar el parche correspondiente."
        for ref in cve_obj.get("references", []):
            if "Patch" in ref.get("tags", []) or "Vendor Advisory" in ref.get("tags", []):
                rem = f"Aplicar parche: {ref.get('url', '')}"
                break
        cves.append({
            "id":          cve_obj.get("id", ""),
            "description": desc[:500],
            "cvss_score":  score,
            "cvss_vector": vector,
            "severity":    sev.upper() if sev else _score_to_sev(score),
            "published":   cve_obj.get("published", "")[:10],
            "references":  [r.get("url", "") for r in cve_obj.get("references", [])[:3]],
            "remediation": rem,
            "source":      "NVD",
        })
    return cves


def _clean_product_name(name: str) -> str:
    """
    Limpia el nombre del producto para NVD keywordSearch.
    Elimina versiones embebidas y caracteres problemáticos.
    ej: "Apache/2.4.51" → "Apache"
        "OpenSSH_9.8"   → "OpenSSH"
        "PHP/8.2.1"     → "PHP"
    """
    # Quitar versión si viene concatenada con / o espacio
    clean = re.split(r'[/\s_]', name)[0]
    # Quitar caracteres no alfanuméricos (excepto guión)
    clean = re.sub(r'[^a-zA-Z0-9\-]', '', clean)
    return clean.strip() or name


def _clean_version(version: str) -> str:
    """
    Extrae versión semántica limpia.
    ej: "2.4.51 (Ubuntu)" → "2.4.51"
        "v1.2.3"          → "1.2.3"
    """
    match = re.search(r'(\d+\.\d+[\.\d]*)', version)
    return match.group(1) if match else ""


# ── CIRCL Vulnerability-Lookup fallback ──────────────────────

def _normalize_for_circl(keyword: str) -> tuple:
    """
    CIRCL API: GET /api/search/{vendor}/{product}
    Los nombres deben estar en minúsculas con guiones bajos.
    La estrategia es vendor=product para nombres de un solo token,
    o intentar separar vendor del product name.

    Casos reales:
      OpenSSH   → openssh/openssh
      MariaDB   → mariadb/mariadb
      WordPress → wordpress/wordpress
      Apache    → apache/apache_http_server (intentar ambos)
      nginx     → nginx/nginx
      PHP       → php/php
    """
    name_lower = keyword.lower().strip()
    # Limpiar caracteres no válidos para CPE/CIRCL
    name_clean = re.sub(r'[^a-z0-9_\-]', '_', name_lower).strip('_')
    name_clean = re.sub(r'_+', '_', name_clean)

    # Para la mayoría de productos opensource: vendor == product
    return (name_clean, name_clean)


def _query_circl_and_append(keyword: str, version: str, all_cves: list):
    """
    Consulta CIRCL Vulnerability-Lookup y añade resultados.
    Endpoint: GET /api/search/{vendor}/{product}
    Documentación: https://vulnerability.circl.lu/api
    """
    vendor, product = _normalize_for_circl(keyword)

    # Intentar con el nombre normalizado primero
    candidates = [
        f"{CIRCL_BASE_URL}/api/search/{vendor}/{product}",
    ]
    # Si el nombre tiene múltiples palabras, intentar también vendor=primera_palabra
    parts = vendor.split('_')
    if len(parts) > 1:
        candidates.append(f"{CIRCL_BASE_URL}/api/search/{parts[0]}/{vendor}")

    for url in candidates:
        try:
            resp = requests.get(url, timeout=CIRCL_TIMEOUT)

            if resp.status_code == 404:
                continue  # probar siguiente candidato
            if resp.status_code != 200:
                console.print(f"    [yellow]![/yellow] CIRCL: HTTP {resp.status_code} para {keyword}")
                return

            data  = resp.json()
            items = data if isinstance(data, list) else []

            if not items:
                console.print(f"    [dim]  Sin CVEs en CIRCL para {keyword}[/dim]")
                return

            count = 0
            for item in items[:20]:
                cve_id = item.get("id", "") or item.get("cve_id", "")
                if not cve_id:
                    continue
                desc  = item.get("summary", "") or item.get("description", "")
                score = 0.0
                for field in ("cvss3", "cvss", "cvssV3", "cvssV2"):
                    val = item.get(field)
                    if val:
                        try:
                            score = float(val)
                            break
                        except (ValueError, TypeError):
                            pass
                sev = _score_to_sev(score)
                all_cves.append({
                    "id":          cve_id,
                    "description": str(desc)[:500],
                    "cvss_score":  score,
                    "cvss_vector": "",
                    "severity":    sev,
                    "published":   str(item.get("Published", "") or "")[:10],
                    "references":  item.get("references", [])[:3],
                    "remediation": f"Ver detalles: https://vulnerability.circl.lu/vuln/{cve_id.lower()}",
                    "source":      "CIRCL",
                    "product":     keyword,
                    "version":     version,
                })
                count += 1

            if count:
                console.print(f"    [green]✓[/green] {count} CVE(s) desde CIRCL para {keyword}")
            return  # éxito: no probar más candidatos

        except requests.exceptions.Timeout:
            console.print(f"    [yellow]![/yellow] CIRCL timeout para {keyword}")
            return
        except Exception as e:
            console.print(f"    [yellow]![/yellow] CIRCL error para {keyword}: {e}")
            return

    console.print(f"    [dim]  Sin resultados en CIRCL para {keyword}[/dim]")


# ── Extracción de productos ───────────────────────────────────

def _extract_products(results: dict) -> list:
    products = []
    seen     = set()

    def add(keyword: str, version: str = "", source: str = "", confidence: str = "MEDIUM"):
        if keyword.lower().strip() in NVD_BLACKLIST:
            console.print(f"  [dim]  Omitiendo {keyword} (excluido de CVE lookup)[/dim]")
            return
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

    for svc in results.get("enumeration", {}).get("nmap_services", []):
        if svc.get("product") and svc.get("version"):
            add(svc["product"], svc["version"], "nmap -sV", "HIGH")

    for svc in results.get("shodan", {}).get("services", []):
        if svc.get("product") and svc.get("version"):
            add(svc["product"], svc["version"], "Shodan", "HIGH")

    for tech, info in results.get("enumeration", {}).get("technologies", {}).items():
        if isinstance(info, dict):
            version    = info.get("version", "")
            confidence = info.get("confidence", "LOW")
        else:
            version    = info if info not in ("detectado", "") else ""
            confidence = "HIGH" if version else "LOW"
        add(tech, version, "HTTP Tech", confidence)

    for header, value in results.get("headers", {}).get("info_leaks", {}).items():
        if header in ("server", "x-powered-by"):
            parts = value.split("/", 1)
            name  = parts[0].strip()
            ver   = parts[1].split(" ")[0].strip() if len(parts) > 1 else ""
            add(name, ver, f"Header:{header}", "HIGH" if ver else "LOW")

    products.sort(key=lambda p: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(p["confidence"], 3))

    if products:
        h = sum(1 for p in products if p["confidence"] == "HIGH")
        m = sum(1 for p in products if p["confidence"] == "MEDIUM")
        console.print(
            f"  [cyan]  [*][/cyan] Productos con versión: "
            f"[green]{h} HIGH[/green], [yellow]{m} MEDIUM[/yellow]"
        )
    return products


def _score_to_sev(score: float) -> str:
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
    table.add_column("Fuente",    width=8)
    sev_styles = {
        "CRITICAL": "bold red", "HIGH": "red",
        "MEDIUM":   "yellow",   "LOW":  "cyan", "NONE": "white"
    }
    for cve in cves:
        sev   = cve.get("severity", "NONE")
        style = sev_styles.get(sev, "white")
        table.add_row(
            cve.get("id", ""),
            cve.get("product", "")[:18],
            str(cve.get("cvss_score", "")),
            f"[{style}]{sev}[/{style}]",
            cve.get("source", ""),
        )
    console.print(table)
