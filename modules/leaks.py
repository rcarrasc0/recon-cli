#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  recon-cli · modules/leaks.py
#  Consulta Leak-Lookup por dominio para detectar credenciales
#  y emails filtrados en brechas conocidas.
# ─────────────────────────────────────────────────────────────

import requests
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

LEAKLOOKUP_URL = "https://leak-lookup.com/api/search"


def run_leaklookup(target: str, target_info: dict, config: dict) -> dict:
    results = {
        "breaches": [],
        "emails_found": [],
        "total_records": 0,
        "findings": [],
    }

    api_key = config.get("LEAKLOOKUP_API_KEY", "")
    timeout = config.get("REQUEST_TIMEOUT", 10)

    # Solo tiene sentido contra dominios
    if target_info["type"] != "domain":
        console.print("  [yellow]![/yellow] Leak-Lookup: target es IP, omitiendo búsqueda de dominio")
        return results

    console.print(f"[cyan]  [*][/cyan] Consultando Leak-Lookup para @{target}...")

    try:
        payload = {
            "key":   api_key,
            "type":  "domain",
            "query": target,
        }
        resp = requests.post(LEAKLOOKUP_URL, data=payload, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()

        if data.get("error"):
            console.print(f"  [yellow]![/yellow] Leak-Lookup error: {data['error']}")
            return results

        # La respuesta es un dict: { "breach_name": [ {...registros...} ] }
        breach_map = data.get("message", {})
        if not isinstance(breach_map, dict):
            console.print("  [yellow]![/yellow] Respuesta inesperada de Leak-Lookup")
            return results

        total = 0
        emails_seen = set()

        for breach_name, records in breach_map.items():
            if not isinstance(records, list):
                continue

            breach_entry = {
                "name":    breach_name,
                "count":   len(records),
                "emails":  [],
                "sample":  [],
            }

            for rec in records[:10]:  # Máximo 10 registros por brecha
                email = rec.get("email") or rec.get("Email") or rec.get("username") or ""
                if email and "@" in email:
                    breach_entry["emails"].append(email)
                    emails_seen.add(email)
                breach_entry["sample"].append(rec)

            breach_entry["emails"] = list(set(breach_entry["emails"]))
            results["breaches"].append(breach_entry)
            total += len(records)

        results["total_records"] = total
        results["emails_found"]  = list(emails_seen)

        console.print(f"  [green]✓[/green] {len(results['breaches'])} brecha(s) encontrada(s) | {total} registro(s) totales")

        # ── Hallazgos ─────────────────────────────────────────
        if results["breaches"]:
            severity = "CRITICAL" if total > 100 else ("HIGH" if total > 10 else "MEDIUM")
            cvss     = 9.1 if total > 100 else (7.5 if total > 10 else 5.3)

            results["findings"].append({
                "phase":       "Leak-Lookup",
                "title":       f"Credenciales filtradas asociadas a {target}",
                "description": (
                    f"Se encontraron {total} registros en {len(results['breaches'])} brecha(s) de datos "
                    f"asociados al dominio {target}. "
                    f"Brechas: {', '.join(b['name'] for b in results['breaches'][:5])}."
                ),
                "severity":    severity,
                "cvss":        cvss,
                "remediation": (
                    "Notificar a usuarios afectados para reset de contraseñas. "
                    "Implementar MFA. Revisar reutilización de credenciales en sistemas internos. "
                    "Monitorizar accesos anómalos."
                ),
            })

            # Hallazgo adicional por cada brecha significativa
            for breach in results["breaches"]:
                if breach["count"] > 0:
                    results["findings"].append({
                        "phase":       "Leak-Lookup",
                        "title":       f"Brecha: {breach['name']}",
                        "description": f"{breach['count']} cuenta(s) de {target} comprometidas en {breach['name']}.",
                        "severity":    "INFO",
                        "cvss":        0.0,
                        "remediation": f"Verificar exposición en {breach['name']} y resetear credenciales afectadas.",
                    })

        else:
            console.print("  [green]✓[/green] No se encontraron brechas conocidas para este dominio")

        # ── Tabla resumen ─────────────────────────────────────
        if results["breaches"] and config.get("verbose"):
            _print_breaches_table(results["breaches"])

    except requests.exceptions.Timeout:
        console.print("  [yellow]![/yellow] Leak-Lookup: timeout de conexión")
    except requests.exceptions.RequestException as e:
        console.print(f"  [yellow]![/yellow] Leak-Lookup: error de conexión: {e}")
    except Exception as e:
        console.print(f"  [yellow]![/yellow] Leak-Lookup: error inesperado: {e}")

    return results


def _print_breaches_table(breaches: list):
    table = Table(title="Brechas encontradas — Leak-Lookup", box=box.SIMPLE, border_style="red")
    table.add_column("Brecha", style="bold red")
    table.add_column("Registros", justify="right")
    table.add_column("Emails muestra")
    for b in breaches:
        emails_str = ", ".join(b["emails"][:3])
        if len(b["emails"]) > 3:
            emails_str += f" (+{len(b['emails'])-3} más)"
        table.add_row(b["name"], str(b["count"]), emails_str or "—")
    console.print(table)
