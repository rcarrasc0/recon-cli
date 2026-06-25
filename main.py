#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  recon-cli · main.py
#  Entry point principal. Orquesta todas las fases del análisis.
# ─────────────────────────────────────────────────────────────

import sys
import uuid
import click
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich import box
from rich.table import Table

from version import __version__
from config import load_config, validate_target
from modules.osint import run_osint
from modules.shodan_scan import run_shodan
from modules.leaks import run_leaklookup
from modules.enum import run_enumeration
from modules.ssl_tls import run_ssl_analysis
from modules.headers import run_headers_analysis
from modules.waf_cdn import run_waf_cdn
from modules.cves import run_cve_lookup
from modules.mitre import enrich_findings_with_mitre, get_unique_techniques
from report.pdf_gen import generate_report

console = Console(record=True)

BANNER_TEMPLATE = """
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗      ██████╗██╗     ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║     ██╔════╝██║     ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║     ██║     ██║     ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║     ██║     ██║     ██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║     ╚██████╗███████╗██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝      ╚═════╝╚══════╝╚═╝
                                                            {__version__}
"""

BANNER = BANNER_TEMPLATE.format(__version__=__version__)


@click.command()
@click.argument("target")
@click.option("--scope", default="blackbox", show_default=True,
              type=click.Choice(["blackbox", "greybox"]),
              help="Tipo de análisis")
@click.option("--skip-leaks",  is_flag=True, default=False, help="Omitir Leak-Lookup")
@click.option("--skip-shodan", is_flag=True, default=False, help="Omitir Shodan")
@click.option("--skip-ssl",    is_flag=True, default=False, help="Omitir análisis SSL/TLS")
@click.option("--skip-waf",    is_flag=True, default=False, help="Omitir detección WAF/CDN")
@click.option("--skip-cves",   is_flag=True, default=False, help="Omitir búsqueda de CVEs")
@click.option("--output", "-o", default=None, help="Ruta del PDF de salida")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Output detallado")
def cli(target, scope, skip_leaks, skip_shodan, skip_ssl, skip_waf, skip_cves, output, verbose):
    """
    recon-cli — Framework de reconocimiento y análisis de seguridad.

    TARGET puede ser un dominio (ejemplo.com) o una dirección IP (1.2.3.4).

    Ejemplos:\n
      ./recon-exec.sh ejemplo.com\n
      ./recon-exec.sh 1.2.3.4 --skip-leaks --verbose\n
      ./recon-exec.sh ejemplo.com --scope blackbox --output ./reports/out.pdf
    """

    start_time = datetime.now()
    run_id     = f"{start_time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8].upper()}"
    command    = " ".join(sys.argv)

    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    console.print(Panel.fit(
        f"[bold]Target:[/bold] [green]{target}[/green]  |  "
        f"[bold]Scope:[/bold] [yellow]{scope.upper()}[/yellow]  |  "
        f"[bold]Inicio:[/bold] {start_time.strftime('%Y-%m-%d %H:%M:%S')}  |  "
        f"[bold]Run ID:[/bold] [magenta]{run_id}[/magenta]",
        title=f"[bold white]recon-cli {__version__}[/bold white]",
        border_style="cyan"
    ))

    config = load_config()
    config["verbose"]    = verbose
    config["scope"]      = scope
    config["start_time"] = start_time
    config["run_id"]     = run_id
    config["command"]    = command
    config["console"]    = console   # console compartido con record=True

    target_info = validate_target(target)
    if not target_info:
        console.print(f"[bold red][✗][/bold red] Target inválido: {target}")
        sys.exit(1)

    console.print(f"\n[cyan][*][/cyan] Tipo de target: [bold]{target_info['type'].upper()}[/bold]")

    results = {
        "target":               target,
        "target_info":          target_info,
        "scope":                scope,
        "start_time":           start_time,
        "run_id":               run_id,
        "command":              command,
        "osint":                {},
        "shodan":               {},
        "leaks":                {},
        "enumeration":          {},
        "ssl_tls":              {},
        "headers":              {},
        "waf_cdn":              {},
        "cves":                 [],
        "findings":             [],
        "root_domain_findings": [],
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

    # ── FASE 7: WAF/CDN ───────────────────────────────────────
    if not skip_waf:
        _phase_header("7", "Detección WAF/CDN")
        results["waf_cdn"] = run_waf_cdn(target, target_info, config)
    else:
        _skip_phase("7", "WAF/CDN", True, False)

    # ── FASE 8: CVEs ──────────────────────────────────────────
    if not skip_cves:
        _phase_header("8", "Búsqueda de CVEs")
        results["cves"] = run_cve_lookup(results, config)
    else:
        _skip_phase("8", "CVEs", True, False)

    # ── Propagar estado CVE al results para el PDF ───────────
    results["config_snapshot"] = {
        "nvd_status":        config.get("nvd_status", ""),
        "nvd_errors":        config.get("nvd_errors", []),
        "cve_source":        config.get("cve_source", "NVD/NIST"),
        "nvd_fallback_used": config.get("nvd_fallback_used", False),
        "nvd_fallback_reason": config.get("nvd_fallback_reason", ""),
    }

    # ── Consolidar hallazgos ──────────────────────────────────
    all_findings = _consolidate_findings(results)
    results["root_domain_findings"] = [f for f in all_findings if f.get("scope") == "root_domain"]
    results["findings"]             = [f for f in all_findings if f.get("scope") != "root_domain"]

    if results["root_domain_findings"]:
        root = target_info.get("root_domain", "")
        console.print(
            f"  [cyan][*][/cyan] {len(results['root_domain_findings'])} oportunidad(es) de mejora "
            f"del dominio raíz [bold]{root}[/bold] → sección separada en el informe"
        )

    results["end_time"] = datetime.now()
    results["duration"] = results["end_time"] - start_time

    _print_summary(results)

    # ── Correlación MITRE ATT&CK ──────────────────────────────
    _phase_header("9", "Correlación MITRE ATT&CK")
    results["findings"] = enrich_findings_with_mitre(results["findings"], config)
    results["mitre_techniques"] = get_unique_techniques(results["findings"])
    console.print(
        f"  [green]✓[/green] {len(results['mitre_techniques'])} técnica(s) únicas identificadas"
    )

    # ── FASE 10: PDF ──────────────────────────────────────────
    _phase_header("10", "Generando Informe PDF")
    pdf_path = output or (
        f"{config.get('REPORT_OUTPUT_DIR','./reports/')}"
        f"{target.replace('.','_')}_{start_time.strftime('%Y%m%d_%H%M%S')}.pdf"
    )
    generate_report(results, pdf_path, config)
    console.print(f"\n[bold green][✓][/bold green] Informe: [underline]{pdf_path}[/underline]")

    # ── Log TXT — salida completa de consola ──────────────────
    log_path = pdf_path.replace(".pdf", ".log")
    console.save_text(log_path, clear=False)
    console.print(f"[bold green][✓][/bold green] Log:     [underline]{log_path}[/underline]")

    console.print(f"[bold green][✓][/bold green] Completado en {results['duration'].seconds}s\n")


def _phase_header(num, name):
    console.print(f"\n[bold cyan]━━━ Fase {num}: {name}[/bold cyan]")

def _skip_phase(num, name, flagged, no_key):
    reason = "flag --skip activo" if flagged else "API key no configurada"
    console.print(f"\n[bold cyan]━━━ Fase {num}: {name}[/bold cyan] [yellow](omitida · {reason})[/yellow]")

def _consolidate_findings(results):
    findings = []
    for phase in ["osint","shodan","leaks","enumeration","ssl_tls","headers","waf_cdn"]:
        findings.extend(results.get(phase, {}).get("findings", []))
    for cve in results.get("cves", []):
        findings.append({
            "phase":       "CVEs",
            "title":       f"CVE: {cve.get('id','N/A')}",
            "description": cve.get("description",""),
            "severity":    cve.get("severity","MEDIUM"),
            "cvss":        cve.get("cvss_score", 0.0),
            "remediation": cve.get("remediation","Actualizar a versión no vulnerable."),
        })
    return findings

def _print_summary(results):
    counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
    for f in results.get("findings",[]):
        sev = f.get("severity","INFO").upper()
        counts[sev] = counts.get(sev,0) + 1

    table = Table(title="Resumen de Hallazgos", box=box.ROUNDED, border_style="cyan")
    table.add_column("Severidad", style="bold", justify="center")
    table.add_column("Cantidad",  justify="center")
    styles = {"CRITICAL":"bold red","HIGH":"red","MEDIUM":"yellow","LOW":"cyan","INFO":"white"}
    for sev, count in counts.items():
        table.add_row(f"[{styles[sev]}]{sev}[/{styles[sev]}]", str(count))
    console.print(table)

if __name__ == "__main__":
    cli()
