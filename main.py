#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  recon-cli · main.py
#  Entry point principal. Orquesta todas las fases del análisis.
# ─────────────────────────────────────────────────────────────

import sys
import click
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.table import Table

from config import load_config, validate_target
from modules.osint import run_osint
from modules.shodan_scan import run_shodan
from modules.leaks import run_leaklookup
from modules.enum import run_enumeration
from modules.ssl_tls import run_ssl_analysis
from modules.headers import run_headers_analysis
from modules.cves import run_cve_lookup
from report.pdf_gen import generate_report

console = Console()

BANNER = """
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗      ██████╗██╗     ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║     ██╔════╝██║     ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║     ██║     ██║     ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║     ██║     ██║     ██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║     ╚██████╗███████╗██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝      ╚═════╝╚══════╝╚═╝
"""


@click.command()
@click.argument("target")
@click.option("--scope", default="blackbox", show_default=True,
              type=click.Choice(["blackbox", "greybox"]),
              help="Tipo de análisis")
@click.option("--skip-leaks", is_flag=True, default=False,
              help="Omitir consulta a Leak-Lookup")
@click.option("--skip-shodan", is_flag=True, default=False,
              help="Omitir consulta a Shodan")
@click.option("--skip-ssl", is_flag=True, default=False,
              help="Omitir análisis SSL/TLS")
@click.option("--skip-cves", is_flag=True, default=False,
              help="Omitir búsqueda de CVEs")
@click.option("--output", "-o", default=None,
              help="Ruta del PDF de salida (opcional)")
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Mostrar output detallado")
def cli(target, scope, skip_leaks, skip_shodan, skip_ssl, skip_cves, output, verbose):
    """
    recon-cli — Framework de reconocimiento y análisis de seguridad.

    TARGET puede ser un dominio (ejemplo.com) o una dirección IP (1.2.3.4).

    Ejemplos:\n
      python main.py ejemplo.com\n
      python main.py 1.2.3.4 --skip-leaks\n
      python main.py ejemplo.com --scope blackbox --output ./reports/resultado.pdf
    """

    start_time = datetime.now()

    # Banner
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    console.print(Panel.fit(
        f"[bold]Target:[/bold] [green]{target}[/green]  |  "
        f"[bold]Scope:[/bold] [yellow]{scope.upper()}[/yellow]  |  "
        f"[bold]Inicio:[/bold] {start_time.strftime('%Y-%m-%d %H:%M:%S')}",
        title="[bold white]recon-cli[/bold white]",
        border_style="cyan"
    ))

    # Cargar configuración
    config = load_config()
    config["verbose"] = verbose
    config["scope"] = scope
    config["start_time"] = start_time

    # Validar target
    target_info = validate_target(target)
    if not target_info:
        console.print(f"[bold red][✗][/bold red] Target inválido: {target}")
        sys.exit(1)

    console.print(f"\n[cyan][*][/cyan] Tipo de target: [bold]{target_info['type'].upper()}[/bold]")

    # ── Resultados acumulados ─────────────────────────────────
    results = {
        "target": target,
        "target_info": target_info,
        "scope": scope,
        "start_time": start_time,
        "osint": {},
        "shodan": {},
        "leaks": {},
        "enumeration": {},
        "ssl_tls": {},
        "headers": {},
        "cves": [],
        "findings": [],
    }

    # ── FASE 1: OSINT ─────────────────────────────────────────
    _phase_header("1", "OSINT & Reconocimiento")
    results["osint"] = run_osint(target, target_info, config)

    # ── FASE 2: Shodan ────────────────────────────────────────
    if not skip_shodan and config.get("SHODAN_API_KEY"):
        _phase_header("2", "Shodan")
        results["shodan"] = run_shodan(target, target_info, config)
    else:
        _skip_phase("2", "Shodan", skip_shodan, not config.get("SHODAN_API_KEY"))

    # ── FASE 3: Leak-Lookup ───────────────────────────────────
    if not skip_leaks and config.get("LEAKLOOKUP_API_KEY"):
        _phase_header("3", "Leak-Lookup")
        results["leaks"] = run_leaklookup(target, target_info, config)
    else:
        _skip_phase("3", "Leak-Lookup", skip_leaks, not config.get("LEAKLOOKUP_API_KEY"))

    # ── FASE 4: Enumeración ───────────────────────────────────
    _phase_header("4", "Enumeración & Descubrimiento")
    results["enumeration"] = run_enumeration(target, target_info, results["osint"], config)

    # ── FASE 5: SSL/TLS ───────────────────────────────────────
    if not skip_ssl:
        _phase_header("5", "Análisis SSL/TLS")
        results["ssl_tls"] = run_ssl_analysis(target, target_info, config)
    else:
        _skip_phase("5", "SSL/TLS", True, False)

    # ── FASE 6: Cabeceras HTTP ────────────────────────────────
    _phase_header("6", "Cabeceras HTTP & CSP")
    results["headers"] = run_headers_analysis(target, target_info, config)

    # ── FASE 7: CVEs ──────────────────────────────────────────
    if not skip_cves:
        _phase_header("7", "Búsqueda de CVEs")
        results["cves"] = run_cve_lookup(results, config)
    else:
        _skip_phase("7", "CVEs", True, False)

    # ── Consolidar hallazgos ──────────────────────────────────
    results["findings"] = _consolidate_findings(results)
    results["end_time"] = datetime.now()
    results["duration"] = results["end_time"] - start_time

    # ── Resumen en consola ────────────────────────────────────
    _print_summary(results)

    # ── FASE 8: Generar PDF ───────────────────────────────────
    _phase_header("8", "Generando Informe PDF")
    pdf_path = output or f"{config.get('REPORT_OUTPUT_DIR', './reports/')}{target.replace('.', '_')}_{start_time.strftime('%Y%m%d_%H%M%S')}.pdf"
    generate_report(results, pdf_path, config)
    console.print(f"\n[bold green][✓][/bold green] Informe generado: [underline]{pdf_path}[/underline]")
    console.print(f"[bold green][✓][/bold green] Análisis completado en {results['duration'].seconds}s\n")


# ── Helpers de UI ─────────────────────────────────────────────

def _phase_header(num: str, name: str):
    console.print(f"\n[bold cyan]━━━ Fase {num}: {name} [/bold cyan]")


def _skip_phase(num: str, name: str, flagged: bool, no_key: bool):
    reason = "flag --skip activo" if flagged else "API key no configurada"
    console.print(f"\n[bold cyan]━━━ Fase {num}: {name}[/bold cyan] [yellow](omitida · {reason})[/yellow]")


def _consolidate_findings(results: dict) -> list:
    """Agrega todos los hallazgos de todas las fases en una lista unificada."""
    findings = []
    for phase in ["osint", "shodan", "leaks", "enumeration", "ssl_tls", "headers"]:
        phase_findings = results.get(phase, {}).get("findings", [])
        findings.extend(phase_findings)
    for cve in results.get("cves", []):
        findings.append({
            "phase": "CVEs",
            "title": f"CVE: {cve.get('id', 'N/A')}",
            "description": cve.get("description", ""),
            "severity": cve.get("severity", "MEDIUM"),
            "cvss": cve.get("cvss_score", 0.0),
            "remediation": cve.get("remediation", "Actualizar a versión no vulnerable."),
        })
    return findings


def _print_summary(results: dict):
    console.print("\n")
    findings = results.get("findings", [])

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1

    table = Table(title="Resumen de Hallazgos", box=box.ROUNDED, border_style="cyan")
    table.add_column("Severidad", style="bold", justify="center")
    table.add_column("Cantidad", justify="center")

    severity_styles = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "INFO": "white",
    }
    for sev, count in counts.items():
        style = severity_styles.get(sev, "white")
        table.add_row(f"[{style}]{sev}[/{style}]", str(count))

    console.print(table)


if __name__ == "__main__":
    cli()
