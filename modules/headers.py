#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  recon-cli · modules/headers.py
#  Análisis de cabeceras HTTP de seguridad, CSP, cookies,
#  información expuesta en Server/X-Powered-By
# ─────────────────────────────────────────────────────────────

import httpx
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# Cabeceras de seguridad recomendadas
SECURITY_HEADERS = {
    "strict-transport-security":      {"severity": "MEDIUM", "cvss": 6.5,
        "remediation": "Añadir: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"},
    "content-security-policy":        {"severity": "MEDIUM", "cvss": 6.1,
        "remediation": "Implementar una CSP restrictiva. Ejemplo mínimo: default-src 'self'"},
    "x-content-type-options":         {"severity": "LOW",    "cvss": 4.3,
        "remediation": "Añadir: X-Content-Type-Options: nosniff"},
    "x-frame-options":                {"severity": "MEDIUM", "cvss": 6.1,
        "remediation": "Añadir: X-Frame-Options: DENY (o SAMEORIGIN si se necesitan iframes)"},
    "referrer-policy":                {"severity": "LOW",    "cvss": 3.1,
        "remediation": "Añadir: Referrer-Policy: strict-origin-when-cross-origin"},
    "permissions-policy":             {"severity": "LOW",    "cvss": 3.1,
        "remediation": "Añadir: Permissions-Policy: geolocation=(), microphone=(), camera=()"},
    "x-xss-protection":               {"severity": "LOW",    "cvss": 3.1,
        "remediation": "Añadir: X-XSS-Protection: 1; mode=block (legacy, pero útil en navegadores antiguos)"},
    "cross-origin-embedder-policy":   {"severity": "LOW",    "cvss": 3.1,
        "remediation": "Añadir: Cross-Origin-Embedder-Policy: require-corp"},
    "cross-origin-opener-policy":     {"severity": "LOW",    "cvss": 3.1,
        "remediation": "Añadir: Cross-Origin-Opener-Policy: same-origin"},
    "cross-origin-resource-policy":   {"severity": "LOW",    "cvss": 3.1,
        "remediation": "Añadir: Cross-Origin-Resource-Policy: same-origin"},
}

# Cabeceras que exponen información sensible
INFO_LEAK_HEADERS = [
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache", "x-runtime", "x-version",
    "via", "x-backend-server", "x-forwarded-server",
]

# Directivas CSP inseguras
UNSAFE_CSP_DIRECTIVES = ["unsafe-inline", "unsafe-eval", "unsafe-hashes", "*"]


def run_headers_analysis(target: str, target_info: dict, config: dict) -> dict:
    results = {
        "headers_present":  {},
        "headers_missing":  [],
        "info_leaks":       {},
        "csp_analysis":     {},
        "cookies":          [],
        "redirect_chain":   [],
        "raw_headers":      {},
        "findings":         [],
    }

    host = target_info.get("domain") or target_info.get("value")
    timeout = config.get("REQUEST_TIMEOUT", 10)

    for scheme in ["https", "http"]:
        url = f"{scheme}://{host}"
        try:
            with httpx.Client(
                timeout=timeout,
                verify=False,
                follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (recon-cli security scanner)"}
            ) as client:
                resp = client.get(url)

            # Guardar cabeceras en minúsculas
            headers = {k.lower(): v for k, v in resp.headers.items()}
            results["raw_headers"] = dict(resp.headers)
            results["final_url"]   = str(resp.url)
            results["status_code"] = resp.status_code

            console.print(f"[cyan]  [*][/cyan] Analizando cabeceras de {url} → HTTP {resp.status_code}")

            # ── Cabeceras de seguridad presentes/ausentes ──────
            for header, meta in SECURITY_HEADERS.items():
                if header in headers:
                    results["headers_present"][header] = headers[header]
                else:
                    # HSTS ya analizado en ssl_tls, evitar duplicar
                    if header != "strict-transport-security":
                        results["headers_missing"].append(header)
                        results["findings"].append({
                            "phase":       "Cabeceras HTTP",
                            "title":       f"Cabecera de seguridad ausente: {header}",
                            "description": f"La cabecera {header} no está presente en la respuesta HTTP.",
                            "severity":    meta["severity"],
                            "cvss":        meta["cvss"],
                            "remediation": meta["remediation"],
                        })

            # ── Fugas de información ───────────────────────────
            for h in INFO_LEAK_HEADERS:
                if h in headers:
                    val = headers[h]
                    results["info_leaks"][h] = val
                    results["findings"].append({
                        "phase":       "Cabeceras HTTP",
                        "title":       f"Información de servidor expuesta: {h}: {val}",
                        "description": f"La cabecera {h} revela información sobre el stack tecnológico: '{val}'.",
                        "severity":    "LOW",
                        "cvss":        3.1,
                        "remediation": f"Eliminar o generalizar la cabecera {h} en la configuración del servidor.",
                    })
                    if config.get("verbose"):
                        console.print(f"  [yellow]![/yellow] Info leak: {h}: {val}")

            # ── Análisis CSP ───────────────────────────────────
            csp_value = headers.get("content-security-policy", "")
            if csp_value:
                results["csp_analysis"] = _analyze_csp(csp_value)
                _check_csp_findings(results["csp_analysis"], results)

            # ── Análisis de cookies ────────────────────────────
            for cookie in resp.cookies.jar:
                cookie_data = {
                    "name":      cookie.name,
                    "secure":    bool(cookie.secure),
                    "httponly":  cookie.has_nonstandard_attr("HttpOnly") or
                                 "httponly" in str(cookie._rest).lower(),
                    "samesite":  cookie._rest.get("SameSite", ""),
                    "domain":    cookie.domain or "",
                    "path":      cookie.path or "/",
                }
                results["cookies"].append(cookie_data)
                _check_cookie_findings(cookie_data, scheme == "https", results)

            # ── HTTP → HTTPS redirect ──────────────────────────
            if scheme == "http":
                try:
                    with httpx.Client(
                        timeout=timeout, verify=False, follow_redirects=False
                    ) as client2:
                        r2 = client2.get(f"http://{host}")
                    if r2.status_code not in (301, 302, 307, 308):
                        results["findings"].append({
                            "phase":       "Cabeceras HTTP",
                            "title":       "No redirige HTTP a HTTPS",
                            "description": f"http://{host} devuelve {r2.status_code} sin redirección a HTTPS.",
                            "severity":    "MEDIUM",
                            "cvss":        6.5,
                            "remediation": "Configurar redirección 301 permanente de HTTP a HTTPS.",
                        })
                except Exception:
                    pass

            if config.get("verbose"):
                _print_headers_table(results)

            console.print(f"  [green]✓[/green] {len(results['headers_missing'])} cabecera(s) de seguridad ausente(s) | "
                          f"{len(results['info_leaks'])} fuga(s) de info | "
                          f"{len(results['cookies'])} cookie(s)")
            break  # Con HTTPS es suficiente

        except httpx.ConnectError:
            console.print(f"  [yellow]![/yellow] No se pudo conectar a {url}")
            continue
        except Exception as e:
            console.print(f"  [yellow]![/yellow] Error analizando {url}: {e}")
            continue

    console.print(f"  [green]✓[/green] Cabeceras completado — {len(results['findings'])} hallazgo(s)")
    return results


def _analyze_csp(csp: str) -> dict:
    directives = {}
    issues     = []

    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if not tokens:
            continue
        directive = tokens[0].lower()
        values    = tokens[1:] if len(tokens) > 1 else []
        directives[directive] = values

        for unsafe in UNSAFE_CSP_DIRECTIVES:
            if unsafe in [v.lower() for v in values]:
                issues.append({
                    "directive": directive,
                    "issue":     f"Valor inseguro '{unsafe}' en {directive}",
                })

    # Comprobar directivas importantes ausentes
    important = ["default-src", "script-src", "object-src", "base-uri"]
    for d in important:
        if d not in directives:
            issues.append({
                "directive": d,
                "issue":     f"Directiva {d} no definida en la CSP",
            })

    return {
        "raw":        csp,
        "directives": directives,
        "issues":     issues,
    }


def _check_csp_findings(csp_analysis: dict, results: dict):
    for issue in csp_analysis.get("issues", []):
        is_unsafe = any(u in issue["issue"] for u in ["unsafe-inline", "unsafe-eval", "*"])
        results["findings"].append({
            "phase":       "Cabeceras HTTP",
            "title":       f"CSP: {issue['issue']}",
            "description": f"La política CSP tiene un problema en '{issue['directive']}': {issue['issue']}.",
            "severity":    "MEDIUM" if is_unsafe else "LOW",
            "cvss":        6.1 if is_unsafe else 3.1,
            "remediation": "Revisar y endurecer la CSP. Evitar 'unsafe-inline' usando nonces o hashes. Definir todas las directivas críticas.",
        })


def _check_cookie_findings(cookie: dict, is_https: bool, results: dict):
    name = cookie["name"]

    if is_https and not cookie["secure"]:
        results["findings"].append({
            "phase":       "Cabeceras HTTP",
            "title":       f"Cookie sin flag Secure: {name}",
            "description": f"La cookie '{name}' no tiene el atributo Secure. Puede transmitirse en claro.",
            "severity":    "MEDIUM",
            "cvss":        5.9,
            "remediation": f"Añadir el atributo Secure a la cookie {name}.",
        })

    if not cookie["httponly"]:
        # Solo marcamos como hallazgo las cookies que parezcan de sesión
        if any(kw in name.lower() for kw in ["sess", "token", "auth", "jwt", "sid", "id"]):
            results["findings"].append({
                "phase":       "Cabeceras HTTP",
                "title":       f"Cookie de sesión sin flag HttpOnly: {name}",
                "description": f"La cookie '{name}' no tiene HttpOnly. Accessible via JavaScript (XSS).",
                "severity":    "MEDIUM",
                "cvss":        6.3,
                "remediation": f"Añadir el atributo HttpOnly a la cookie {name}.",
            })

    if not cookie["samesite"]:
        results["findings"].append({
            "phase":       "Cabeceras HTTP",
            "title":       f"Cookie sin atributo SameSite: {name}",
            "description": f"La cookie '{name}' no tiene SameSite. Riesgo de CSRF.",
            "severity":    "LOW",
            "cvss":        4.3,
            "remediation": f"Añadir SameSite=Strict o SameSite=Lax a la cookie {name}.",
        })


def _print_headers_table(results: dict):
    table = Table(title="Cabeceras de Seguridad", box=box.SIMPLE, border_style="cyan")
    table.add_column("Cabecera", style="bold")
    table.add_column("Estado", justify="center")
    table.add_column("Valor")

    for h in SECURITY_HEADERS:
        if h in results["headers_present"]:
            val = results["headers_present"][h]
            table.add_row(h, "[green]✓[/green]", val[:80])
        else:
            table.add_row(h, "[red]✗[/red]", "[red]AUSENTE[/red]")

    console.print(table)
