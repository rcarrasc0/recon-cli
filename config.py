#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  recon-cli · config.py
#  Carga .env, valida configuración y clasifica el target.
# ─────────────────────────────────────────────────────────────

import os
import re
import socket
from dotenv import load_dotenv
from rich.console import Console

console = Console()

# Regex básica para dominios
DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)

# Regex para IPv4
IPV4_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)


def load_config() -> dict:
    """Carga variables de entorno desde .env y devuelve un dict de configuración."""
    load_dotenv()

    config = {
        # APIs
        "SHODAN_API_KEY":       os.getenv("SHODAN_API_KEY", "").strip(),
        "LEAKLOOKUP_API_KEY":   os.getenv("LEAKLOOKUP_API_KEY", "").strip(),
        "VIRUSTOTAL_API_KEY":   os.getenv("VIRUSTOTAL_API_KEY", "").strip(),
        "SECURITYTRAILS_API_KEY": os.getenv("SECURITYTRAILS_API_KEY", "").strip(),
        "NVD_API_KEY":          os.getenv("NVD_API_KEY", "").strip(),

        # Comportamiento
        "REQUEST_TIMEOUT":      int(os.getenv("REQUEST_TIMEOUT", "10")),
        "MAX_SUBDOMAINS":       int(os.getenv("MAX_SUBDOMAINS", "500")),
        "DNS_THREADS":          int(os.getenv("DNS_THREADS", "20")),
        "NMAP_PORTS":           os.getenv("NMAP_PORTS", "--top-ports 1000"),
        "LOG_LEVEL":            os.getenv("LOG_LEVEL", "INFO"),

        # Informe
        "REPORT_AUTHOR":        os.getenv("REPORT_AUTHOR", "recon-cli"),
        "REPORT_OUTPUT_DIR":    os.getenv("REPORT_OUTPUT_DIR", "./reports/"),
        "REPORT_LOGO_PATH":     os.getenv("REPORT_LOGO_PATH", "").strip(),
    }

    # Crear directorio de reports si no existe
    os.makedirs(config["REPORT_OUTPUT_DIR"], exist_ok=True)

    # Avisos de APIs no configuradas
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
    Devuelve dict con type, value e IPs resueltas, o None si es inválido.
    """
    target = target.strip().lower().rstrip("/")

    # ── IPv4 ──────────────────────────────────────────────────
    if IPV4_RE.match(target):
        parts = target.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return {
                "type": "ip",
                "value": target,
                "ips": [target],
                "domain": None,
            }

    # ── Dominio ───────────────────────────────────────────────
    if DOMAIN_RE.match(target):
        ips = []
        try:
            info = socket.getaddrinfo(target, None)
            ips = list({r[4][0] for r in info})
        except socket.gaierror:
            console.print(f"[yellow][!][/yellow] No se pudo resolver {target} — continuando sin IPs")

        return {
            "type": "domain",
            "value": target,
            "ips": ips,
            "domain": target,
        }

    return None
