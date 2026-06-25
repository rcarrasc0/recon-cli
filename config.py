#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  recon-cli · config.py
#  Carga .env, valida configuración y clasifica el target.
#  v1.1.7: extracción de dominio raíz con tldextract para
#          separar hallazgos de endpoint vs dominio raíz.
# ─────────────────────────────────────────────────────────────

import os
import re
import socket
import tldextract
from dotenv import load_dotenv
from rich.console import Console

console = Console()

DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)
IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def load_config() -> dict:
    load_dotenv()

    config = {
        "SHODAN_API_KEY":         os.getenv("SHODAN_API_KEY", "").strip(),
        "LEAKLOOKUP_API_KEY":     os.getenv("LEAKLOOKUP_API_KEY", "").strip(),
        "VIRUSTOTAL_API_KEY":     os.getenv("VIRUSTOTAL_API_KEY", "").strip(),
        "SECURITYTRAILS_API_KEY": os.getenv("SECURITYTRAILS_API_KEY", "").strip(),
        "NVD_API_KEY":            os.getenv("NVD_API_KEY", "").strip(),
        "REQUEST_TIMEOUT":        int(os.getenv("REQUEST_TIMEOUT", "10")),
        "MAX_SUBDOMAINS":         int(os.getenv("MAX_SUBDOMAINS", "500")),
        "DNS_THREADS":            int(os.getenv("DNS_THREADS", "20")),
        "NMAP_PORTS":             os.getenv("NMAP_PORTS", "--top-ports 1000"),
        "LOG_LEVEL":              os.getenv("LOG_LEVEL", "INFO"),
        "REPORT_AUTHOR":          os.getenv("REPORT_AUTHOR", "recon-cli"),
        "REPORT_OUTPUT_DIR":      os.getenv("REPORT_OUTPUT_DIR", "./reports/"),
        "REPORT_LOGO_PATH":       os.getenv("REPORT_LOGO_PATH", "").strip(),
    }

    os.makedirs(config["REPORT_OUTPUT_DIR"], exist_ok=True)

    if not config["SHODAN_API_KEY"]:
        console.print("[yellow][!][/yellow] SHODAN_API_KEY no configurada — fase Shodan será omitida")
    if not config["LEAKLOOKUP_API_KEY"]:
        console.print("[yellow][!][/yellow] LEAKLOOKUP_API_KEY no configurada — fase Leak-Lookup será omitida")
    if not config["NVD_API_KEY"]:
        console.print("[yellow][!][/yellow] NVD_API_KEY no configurada — búsqueda CVE sin autenticación (rate limit reducido)")

    return config


def validate_target(target: str) -> dict | None:
    """
    Clasifica el target como dominio o IP.
    Extrae el dominio raíz (eTLD+1) para contextualizar hallazgos.
    """
    target = target.strip().lower().rstrip("/")

    # ── IPv4 ──────────────────────────────────────────────────
    if IPV4_RE.match(target):
        parts = target.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return {
                "type":        "ip",
                "value":       target,
                "ips":         [target],
                "domain":      None,
                "root_domain": None,
                "is_subdomain": False,
            }

    # ── Dominio ───────────────────────────────────────────────
    if DOMAIN_RE.match(target):
        ips = []
        try:
            info = socket.getaddrinfo(target, None)
            ips  = list({r[4][0] for r in info})
        except socket.gaierror:
            console.print(f"[yellow][!][/yellow] No se pudo resolver {target} — continuando sin IPs")

        # Extraer dominio raíz (eTLD+1)
        # Ej: studio.carteraidcat-pre.aoc.cat → aoc.cat
        #     example.com                     → example.com
        extracted   = tldextract.extract(target)
        root_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.domain and extracted.suffix else target
        is_subdomain = target != root_domain

        if is_subdomain:
            console.print(
                f"[cyan]  [*][/cyan] Dominio raíz detectado: [bold]{root_domain}[/bold] "
                f"— hallazgos de correo/DNS se tratarán como oportunidades de mejora"
            )

        return {
            "type":         "domain",
            "value":        target,
            "ips":          ips,
            "domain":       target,
            "root_domain":  root_domain,
            "is_subdomain": is_subdomain,
        }

    return None
