#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  recon-cli · modules/waf_cdn.py  v1.1.0
#  Detección pasiva de WAF/CDN en entornos Cloudflare y AWS.
#  Estrategia 100% blackbox: cabeceras HTTP, rangos IP públicos,
#  patrones DNS, comportamiento de respuesta.
# ─────────────────────────────────────────────────────────────

import ipaddress
import json
import socket
import requests
import dns.resolver
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# ── Rangos IP públicos ────────────────────────────────────────
# Cloudflare: https://www.cloudflare.com/ips/
CLOUDFLARE_IPV4 = [
    "173.245.48.0/20","103.21.244.0/22","103.22.200.0/22",
    "103.31.4.0/22","141.101.64.0/18","108.162.192.0/18",
    "190.93.240.0/20","188.114.96.0/20","197.234.240.0/22",
    "198.41.128.0/17","162.158.0.0/15","104.16.0.0/13",
    "104.24.0.0/14","172.64.0.0/13","131.0.72.0/22",
]

# AWS CloudFront IPs se obtienen dinámicamente desde ip-ranges.amazonaws.com
# Este es el fallback estático con los rangos más comunes
AWS_CLOUDFRONT_IPV4 = [
    "13.32.0.0/15","13.35.0.0/16","52.46.0.0/18",
    "52.84.0.0/15","54.182.0.0/16","54.192.0.0/16",
    "54.230.0.0/16","54.239.128.0/18","64.252.64.0/18",
    "70.132.0.0/18","99.84.0.0/16","204.246.164.0/22",
    "204.246.168.0/22","205.251.192.0/19","216.137.32.0/19",
]

# Azure Front Door / CDN IPs (estáticos más comunes)
# Rangos dinámicos en: https://www.microsoft.com/en-us/download/details.aspx?id=56519
AZURE_FRONTDOOR_IPV4 = [
    "13.107.42.0/24", "13.107.43.0/24",
    "13.107.64.0/18", "13.107.128.0/22",
    "20.135.0.0/22",  "20.150.0.0/15",
    "20.190.0.0/16",  "40.82.0.0/22",
    "40.90.0.0/15",   "40.126.0.0/18",
    "51.105.0.0/19",  "52.108.0.0/14",
    "52.112.0.0/14",  "52.238.0.0/18",
    "104.146.0.0/15", "104.208.0.0/13",
]

# ── Firmas de cabeceras por proveedor ─────────────────────────
WAF_CDN_SIGNATURES = {
    "Cloudflare": {
        "headers_present": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "headers_value":   {"server": "cloudflare"},
        "confidence":      "HIGH",
        "type":            "CDN+WAF",
    },
    "AWS CloudFront": {
        "headers_present": ["x-amz-cf-id", "x-amz-cf-pop"],
        "headers_value":   {"via": "cloudfront", "server": "amazons3"},
        "confidence":      "HIGH",
        "type":            "CDN",
    },
    "AWS WAF": {
        "headers_present": ["x-amzn-requestid", "x-amzn-trace-id"],
        "headers_value":   {},
        "confidence":      "MEDIUM",
        "type":            "WAF",
    },
    "Akamai": {
        "headers_present": ["x-akamai-transformed", "x-akamai-request-id", "akamai-origin-hop"],
        "headers_value":   {"server": "akamaighost", "x-check-cacheable": ""},
        "confidence":      "HIGH",
        "type":            "CDN+WAF",
    },
    "Imperva (Incapsula)": {
        "headers_present": ["x-iinfo", "x-cdn"],
        "headers_value":   {"x-cdn": "incapsula"},
        "confidence":      "HIGH",
        "type":            "WAF",
    },
    "Fastly": {
        "headers_present": ["x-fastly-request-id", "fastly-restarts"],
        "headers_value":   {"via": "varnish", "x-served-by": ""},
        "confidence":      "MEDIUM",
        "type":            "CDN",
    },
    "Sucuri": {
        "headers_present": ["x-sucuri-id", "x-sucuri-cache"],
        "headers_value":   {"server": "sucuri/cloudproxy"},
        "confidence":      "HIGH",
        "type":            "WAF",
    },
    "Azure Front Door": {
        "headers_present": ["x-azure-ref", "x-fd-healthprobe", "x-msedge-ref"],
        "headers_value":   {"server": "ecs", "x-cache": ""},
        "confidence":      "HIGH",
        "type":            "CDN+WAF",
    },
    "Azure Application Gateway WAF": {
        "headers_present": ["x-appgw-trace-id"],
        "headers_value":   {},
        "confidence":      "HIGH",
        "type":            "WAF",
    },
    "Azure CDN": {
        "headers_present": ["x-ec-custom-error", "x-check-cacheable"],
        "headers_value":   {"x-cache": "tcp_hit"},
        "confidence":      "MEDIUM",
        "type":            "CDN",
    },
    "Cloudflare WAF Block": {
        "headers_present": ["cf-ray"],
        "status_codes":    [403, 429, 503],
        "body_patterns":   ["Cloudflare", "cf-ray", "error 1006", "error 1010", "error 1012"],
        "confidence":      "HIGH",
        "type":            "WAF_BLOCK",
    },
}

# ── Patrones en cuerpo de respuesta de bloqueo WAF ───────────
WAF_BLOCK_PATTERNS = {
    "Cloudflare":          ["attention required", "cloudflare ray id", "cf-ray"],
    "AWS WAF":             ["aws waf", "request blocked", "x-amzn-requestid"],
    "Imperva (Incapsula)": ["incapsula incident id", "powered by incapsula"],
    "Sucuri":              ["sucuri website firewall", "access denied - sucuri"],
    "Akamai":              ["akamai reference", "access denied. you don't have permission"],
    "Barracuda":           ["barracuda web application firewall"],
    "F5 BIG-IP":           ["the requested url was rejected", "f5 networks"],
    "Azure WAF":            ["azure web application firewall", "microsoft-azure-application-gateway"],
    "ModSecurity":         ["mod_security", "not acceptable"],
}


def run_waf_cdn(target: str, target_info: dict, config: dict) -> dict:
    results = {
        "detected":     [],
        "ip_provider":  {},
        "dns_hints":    {},
        "headers_raw":  {},
        "block_test":   {},
        "findings":     [],
    }

    host    = target_info.get("domain") or target_info.get("value")
    timeout = config.get("REQUEST_TIMEOUT", 10)

    console.print(f"[cyan]  [*][/cyan] Detección WAF/CDN para {host}...")

    # ── 1. Análisis de IPs contra rangos conocidos ────────────
    console.print("[cyan]  [*][/cyan] Comprobando rangos IP (Cloudflare / AWS)...")
    ip_results = _check_ip_ranges(target_info)
    results["ip_provider"] = ip_results

    if ip_results.get("provider"):
        provider = ip_results["provider"]
        console.print(f"  [red]⚑[/red] IP en rango de {provider}: {ip_results.get('matched_ip')} → {ip_results.get('matched_range')}")
        results["findings"].append({
            "phase":       "WAF/CDN",
            "title":       f"IP en rango de {provider}",
            "description": (
                f"La IP {ip_results.get('matched_ip')} pertenece al rango "
                f"{ip_results.get('matched_range')} de {provider}. "
                f"El tráfico pasa a través de su infraestructura."
            ),
            "severity":    "INFO",
            "cvss":        0.0,
            "remediation": (
                f"Verificar configuración de seguridad en {provider}. "
                f"Asegurarse de que las reglas WAF estén activas y actualizadas."
            ),
        })

    # ── 2. Pistas DNS (CNAME hacia CDN) ──────────────────────
    console.print("[cyan]  [*][/cyan] Analizando registros DNS para pistas CDN...")
    dns_hints = _check_dns_hints(host, config)
    results["dns_hints"] = dns_hints

    if dns_hints.get("cname_provider"):
        console.print(f"  [red]⚑[/red] CNAME apunta a {dns_hints['cname_provider']}: {dns_hints.get('cname_value')}")
        results["findings"].append({
            "phase":       "WAF/CDN",
            "title":       f"CNAME hacia {dns_hints['cname_provider']} detectado",
            "description": f"El registro CNAME de {host} apunta a {dns_hints.get('cname_value')}, infraestructura de {dns_hints['cname_provider']}.",
            "severity":    "INFO",
            "cvss":        0.0,
            "remediation": "Documentar la dependencia de CDN. Verificar configuración de seguridad en el proveedor.",
        })

    # ── 3. Fingerprinting por cabeceras HTTP ──────────────────
    console.print("[cyan]  [*][/cyan] Analizando cabeceras HTTP para fingerprinting WAF/CDN...")
    headers_detected = _check_headers(host, timeout)
    results["headers_raw"] = headers_detected.get("raw", {})

    for detection in headers_detected.get("detected", []):
        provider = detection["provider"]
        if provider not in [d["provider"] for d in results["detected"]]:
            results["detected"].append(detection)
            console.print(
                f"  [red]⚑[/red] {detection['type']} detectado: "
                f"[bold]{provider}[/bold] "
                f"(confianza: {detection['confidence']}) "
                f"via {', '.join(detection['matched_by'])}"
            )

    # ── 4. Rangos AWS CloudFront dinámicos ────────────────────
    console.print("[cyan]  [*][/cyan] Consultando rangos IP dinámicos de AWS...")
    aws_result = _check_aws_dynamic(target_info, timeout)
    if aws_result.get("matched"):
        console.print(f"  [red]⚑[/red] IP confirmada en rango CloudFront: {aws_result.get('range')}")
        if "AWS CloudFront" not in [d["provider"] for d in results["detected"]]:
            results["detected"].append({
                "provider":   "AWS CloudFront",
                "type":       "CDN",
                "confidence": "HIGH",
                "matched_by": [f"AWS ip-ranges.json: {aws_result.get('range')}"],
            })

    # ── 4b. Rangos Azure dinámicos ────────────────────────────
    console.print("[cyan]  [*][/cyan] Consultando rangos IP dinámicos de Azure...")
    azure_result = _check_azure_dynamic(target_info, timeout)
    if azure_result.get("matched"):
        console.print(f"  [red]⚑[/red] IP confirmada en rango Azure: {azure_result.get('range')}")
        if "Azure Front Door" not in [d["provider"] for d in results["detected"]]:
            results["detected"].append({
                "provider":   "Azure Front Door",
                "type":       "CDN+WAF",
                "confidence": "HIGH",
                "matched_by": [f"Azure ServiceTags: {azure_result.get('range')}"],
            })

    # ── 5. Test de respuesta a ruta inválida (WAF behavior) ──
    console.print("[cyan]  [*][/cyan] Comprobando comportamiento ante ruta inválida...")
    block_test = _test_waf_block_behavior(host, timeout)
    results["block_test"] = block_test

    if block_test.get("waf_detected"):
        provider = block_test.get("provider", "WAF genérico")
        console.print(f"  [red]⚑[/red] Comportamiento WAF detectado en respuesta: {provider}")
        if provider not in [d["provider"] for d in results["detected"]]:
            results["detected"].append({
                "provider":   provider,
                "type":       "WAF",
                "confidence": "MEDIUM",
                "matched_by": ["Patrón en cuerpo de respuesta a ruta inválida"],
            })

    # ── Hallazgos consolidados ────────────────────────────────
    if results["detected"]:
        providers_str = ", ".join(d["provider"] for d in results["detected"])
        results["findings"].append({
            "phase":       "WAF/CDN",
            "title":       f"WAF/CDN detectado: {providers_str}",
            "description": (
                f"Se ha identificado la presencia de {providers_str} "
                f"delante del servidor de origen. El tráfico está siendo "
                f"intermediado por esta infraestructura."
            ),
            "severity":    "INFO",
            "cvss":        0.0,
            "remediation": (
                "Verificar que las reglas WAF estén activas y correctamente configuradas. "
                "Asegurarse de que el servidor de origen no sea accesible directamente "
                "sin pasar por el WAF/CDN (posible bypass)."
            ),
        })

        # Hallazgo específico: origen potencialmente expuesto
        results["findings"].append({
            "phase":       "WAF/CDN",
            "title":       "Verificar exposición directa del servidor de origen",
            "description": (
                f"Con {providers_str} delante, existe riesgo de bypass si el servidor "
                f"de origen es accesible directamente por IP. Esto permitiría saltarse "
                f"las protecciones WAF."
            ),
            "severity":    "MEDIUM",
            "cvss":        5.3,
            "remediation": (
                "Restringir el acceso al servidor de origen solo desde los rangos IP "
                "del CDN/WAF. En Cloudflare: usar Cloudflare Tunnel o firewall de origen. "
                "En AWS: configurar security groups para permitir solo IPs de CloudFront."
            ),
        })
    else:
        console.print("  [green]✓[/green] No se detectó WAF/CDN conocido")

    # ── Tabla resumen ────────────────────────────────────────
    if results["detected"] and config.get("verbose"):
        _print_summary_table(results)

    console.print(f"  [green]✓[/green] WAF/CDN completado — {len(results['detected'])} proveedor(es) detectado(s)")
    return results


# ── Helpers ───────────────────────────────────────────────────

def _check_ip_ranges(target_info: dict) -> dict:
    result = {"provider": None, "matched_ip": None, "matched_range": None}
    ips = target_info.get("ips", [])
    if target_info.get("type") == "ip":
        ips = [target_info["value"]]

    for ip_str in ips:
        try:
            ip = ipaddress.ip_address(ip_str)
            for cidr in CLOUDFLARE_IPV4:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return {"provider": "Cloudflare", "matched_ip": ip_str, "matched_range": cidr}
            for cidr in AWS_CLOUDFRONT_IPV4:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return {"provider": "AWS CloudFront", "matched_ip": ip_str, "matched_range": cidr}
            for cidr in AZURE_FRONTDOOR_IPV4:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return {"provider": "Azure Front Door", "matched_ip": ip_str, "matched_range": cidr}
        except Exception:
            continue
    return result


def _check_dns_hints(host: str, config: dict) -> dict:
    result = {"cname_chain": [], "cname_provider": None, "cname_value": None}
    timeout = config.get("REQUEST_TIMEOUT", 5)

    cdn_cname_patterns = {
        "Cloudflare":    [".cdn.cloudflare.net", "cloudflare.net"],
        "AWS CloudFront":["cloudfront.net"],
        "Akamai":        ["akamaiedge.net", "akamaized.net", "edgekey.net", "edgesuite.net"],
        "Fastly":        ["fastly.net", "fastlylb.net"],
        "Sucuri":        ["sucuri.net"],
        "Azure Front Door": ["azurefd.net", "azureedge.net", "trafficmanager.net"],
    }

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout  = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(host, "CNAME")
        for rdata in answers:
            cname_val = str(rdata.target).rstrip(".")
            result["cname_chain"].append(cname_val)
            for provider, patterns in cdn_cname_patterns.items():
                if any(p in cname_val for p in patterns):
                    result["cname_provider"] = provider
                    result["cname_value"]    = cname_val
                    break
    except Exception:
        pass

    return result


def _check_headers(host: str, timeout: int) -> dict:
    result = {"detected": [], "raw": {}}

    for scheme in ["https", "http"]:
        try:
            resp = requests.get(
                f"{scheme}://{host}",
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (recon-cli/1.1.0)"},
                verify=False,
            )
            headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
            result["raw"]  = dict(resp.headers)

            for provider, sig in WAF_CDN_SIGNATURES.items():
                matched_by = []

                # Cabeceras presentes
                for h in sig.get("headers_present", []):
                    if h in headers_lower:
                        matched_by.append(f"header:{h}")

                # Valores de cabeceras
                for h, val in sig.get("headers_value", {}).items():
                    if h in headers_lower:
                        if not val or val in headers_lower[h]:
                            matched_by.append(f"header:{h}={headers_lower[h]}")

                if matched_by:
                    result["detected"].append({
                        "provider":   provider,
                        "type":       sig.get("type", "CDN"),
                        "confidence": sig.get("confidence", "MEDIUM"),
                        "matched_by": matched_by,
                    })

            break  # Con HTTPS es suficiente
        except Exception:
            continue

    return result


def _check_aws_dynamic(target_info: dict, timeout: int) -> dict:
    """Descarga ip-ranges.amazonaws.com y comprueba si la IP está en CloudFront."""
    result = {"matched": False, "range": None}
    ips = target_info.get("ips", [])
    if not ips:
        return result

    try:
        resp = requests.get(
            "https://ip-ranges.amazonaws.com/ip-ranges.json",
            timeout=timeout
        )
        if resp.status_code != 200:
            return result

        data = resp.json()
        cf_ranges = [
            p["ip_prefix"]
            for p in data.get("prefixes", [])
            if p.get("service") == "CLOUDFRONT"
        ]

        for ip_str in ips:
            try:
                ip = ipaddress.ip_address(ip_str)
                for cidr in cf_ranges:
                    if ip in ipaddress.ip_network(cidr, strict=False):
                        result["matched"] = True
                        result["range"]   = cidr
                        return result
            except Exception:
                continue
    except Exception:
        pass

    return result


def _test_waf_block_behavior(host: str, timeout: int) -> dict:
    """Solicita una ruta deliberadamente inválida y analiza la respuesta."""
    result = {"waf_detected": False, "provider": None, "status_code": None}

    test_paths = [
        "/.env", "/etc/passwd", "/wp-admin/",
        "/?q=<script>alert(1)</script>",
        "/?id=1 UNION SELECT 1,2,3--",
    ]

    for path in test_paths:
        try:
            resp = requests.get(
                f"https://{host}{path}",
                timeout=timeout,
                allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 (recon-cli/1.1.0)"},
                verify=False,
            )
            body_lower = resp.text.lower()
            result["status_code"] = resp.status_code

            for provider, patterns in WAF_BLOCK_PATTERNS.items():
                if any(p.lower() in body_lower for p in patterns):
                    result["waf_detected"] = True
                    result["provider"]     = provider
                    return result

            # Código de bloqueo típico de WAF sin firma conocida
            if resp.status_code in (403, 406, 429, 503) and len(resp.text) < 2000:
                result["waf_detected"] = True
                result["provider"]     = "WAF genérico"
                return result

        except Exception:
            continue

    return result


def _check_azure_dynamic(target_info: dict, timeout: int) -> dict:
    """Descarga ServiceTags de Azure y comprueba si la IP pertenece a AzureFrontDoor."""
    result = {"matched": False, "range": None}
    ips = target_info.get("ips", [])
    if not ips:
        return result

    # URL del JSON de ServiceTags de Azure (pública, sin auth)
    # Nota: la URL exacta cambia con cada release — usamos el endpoint de discovery
    service_tags_urls = [
        "https://raw.githubusercontent.com/tobilg/microsoft-azure-ip-ranges/main/data/ServiceTags_Public.json",
        "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20240115.json",
    ]

    for url in service_tags_urls:
        try:
            resp = requests.get(url, timeout=timeout)
            if resp.status_code != 200:
                continue

            data = resp.json()
            values = data.get("values", [])

            # Buscar rangos de AzureFrontDoor y AzureCDN
            azure_ranges = []
            for entry in values:
                name = entry.get("name", "")
                if any(k in name for k in ("AzureFrontDoor", "AzureCDN", "FrontDoor")):
                    for prefix in entry.get("properties", {}).get("addressPrefixes", []):
                        if "." in prefix:  # solo IPv4
                            azure_ranges.append(prefix)

            for ip_str in ips:
                try:
                    ip = ipaddress.ip_address(ip_str)
                    for cidr in azure_ranges:
                        if ip in ipaddress.ip_network(cidr, strict=False):
                            result["matched"] = True
                            result["range"]   = cidr
                            return result
                except Exception:
                    continue
            break  # Si descargó bien, no probar la siguiente URL

        except Exception:
            continue

    return result


def _print_summary_table(results: dict):
    table = Table(title="WAF/CDN Detectados", box=box.ROUNDED, border_style="red")
    table.add_column("Proveedor",   style="bold red")
    table.add_column("Tipo",        justify="center")
    table.add_column("Confianza",   justify="center")
    table.add_column("Detectado por")

    for d in results["detected"]:
        table.add_row(
            d["provider"],
            d["type"],
            d["confidence"],
            ", ".join(d["matched_by"])[:60],
        )
    console.print(table)
