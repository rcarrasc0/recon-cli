#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  recon-cli · modules/ssl_tls.py
#  Análisis SSL/TLS: certificado, cifrados, protocolos,
#  HSTS, vulnerabilidades conocidas (BEAST, POODLE, etc.)
#  Usa sslyze (Python) + nmap ssl-enum-ciphers (subprocess)
# ─────────────────────────────────────────────────────────────

import ssl
import socket
import subprocess
import json
import shutil
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# Protocolos inseguros
INSECURE_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

# Cifrados débiles (patrones)
WEAK_CIPHER_PATTERNS = [
    "NULL", "EXPORT", "DES", "RC4", "MD5", "anon", "IDEA",
    "RC2", "3DES", "aDSS", "aNULL",
]

# Algoritmos de firma débiles
WEAK_SIGNATURE_ALGORITHMS = ["md5", "sha1"]

# Tamaños mínimos de clave por tipo de algoritmo
# RSA/DSA: mínimo 2048 bits
# ECDSA/EC: P-256 (256 bits) es seguro — mínimo recomendado 224 bits
KEY_MIN_BITS = {
    "rsa": 2048,
    "dsa": 2048,
    "ec":  224,   # P-256 (256 bits) es seguro según NIST
}


def run_ssl_analysis(target: str, target_info: dict, config: dict) -> dict:
    global console
    console = config.get("console") or console
    results = {
        "certificate":  {},
        "protocols":    {},
        "ciphers":      [],
        "vulnerabilities": [],
        "hsts":         False,
        "hsts_max_age": 0,
        "ocsp_stapling": False,
        "findings":     [],
    }

    host    = target_info.get("domain") or target_info.get("value")
    port    = 443
    timeout = config.get("REQUEST_TIMEOUT", 10)

    # Comprobar si hay puerto 443 abierto
    if not _port_open(host, port, timeout):
        console.print(f"  [yellow]![/yellow] Puerto 443 cerrado en {host} — omitiendo análisis SSL")
        return results

    # ── Análisis de certificado (cryptography) ────────────────
    console.print(f"[cyan]  [*][/cyan] Analizando certificado X.509...")
    cert_data = _get_certificate(host, port, timeout)
    if cert_data:
        results["certificate"] = cert_data
        _check_certificate_findings(cert_data, results)
        console.print(
            f"  [green]✓[/green] CN: {cert_data.get('subject_cn', 'N/A')} | "
            f"Expira: {cert_data.get('not_after', 'N/A')} | "
            f"Clave: {cert_data.get('key_type','?').upper()} {cert_data.get('key_size',0)} bits"
        )
    else:
        console.print("  [yellow]![/yellow] No se pudo obtener el certificado")

    # ── sslyze ────────────────────────────────────────────────
    console.print(f"[cyan]  [*][/cyan] Ejecutando sslyze...")
    sslyze_data = _run_sslyze(host, port)
    if sslyze_data:
        results["protocols"]     = sslyze_data.get("protocols", {})
        results["ciphers"]       = sslyze_data.get("ciphers", [])
        results["ocsp_stapling"] = sslyze_data.get("ocsp_stapling", False)
        _check_protocol_findings(sslyze_data, results)
        console.print(f"  [green]✓[/green] sslyze completado")
    else:
        console.print("  [yellow]![/yellow] sslyze no disponible o falló — usando análisis básico")
        results["protocols"] = _basic_protocol_check(host, port, timeout)
        _check_protocol_findings({"protocols": results["protocols"], "ciphers": []}, results)

    # ── nmap ssl-enum-ciphers ─────────────────────────────────
    if shutil.which("nmap"):
        console.print(f"[cyan]  [*][/cyan] Ejecutando nmap ssl-enum-ciphers...")
        nmap_data = _run_nmap_ssl(host, port)
        if nmap_data:
            results["nmap_ciphers"] = nmap_data
            _check_nmap_cipher_findings(nmap_data, results)
            console.print(f"  [green]✓[/green] nmap ssl-enum-ciphers completado")
    else:
        console.print("  [yellow]![/yellow] nmap no encontrado en PATH — omitiendo ssl-enum-ciphers")

    # ── HSTS ──────────────────────────────────────────────────
    console.print(f"[cyan]  [*][/cyan] Comprobando HSTS...")
    hsts_data = _check_hsts(host, port, timeout)
    results["hsts"]         = hsts_data["enabled"]
    results["hsts_max_age"] = hsts_data["max_age"]
    results["hsts_details"] = hsts_data

    if not hsts_data["enabled"]:
        results["findings"].append({
            "phase":       "SSL/TLS",
            "title":       "HSTS no configurado",
            "description": "El servidor no envía la cabecera Strict-Transport-Security. Permite ataques de downgrade.",
            "severity":    "MEDIUM",
            "cvss":        6.5,
            "remediation": "Añadir: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        })
    elif hsts_data["max_age"] < 31536000:
        results["findings"].append({
            "phase":       "SSL/TLS",
            "title":       f"HSTS max-age insuficiente ({hsts_data['max_age']}s)",
            "description": f"El max-age de HSTS es {hsts_data['max_age']}s. Se recomienda mínimo 1 año (31536000s).",
            "severity":    "LOW",
            "cvss":        3.1,
            "remediation": "Incrementar max-age a 31536000 y añadir includeSubDomains; preload.",
        })
    else:
        console.print(f"  [green]✓[/green] HSTS configurado (max-age={hsts_data['max_age']}s)")

    console.print(f"  [green]✓[/green] SSL/TLS completado — {len(results['findings'])} hallazgo(s)")
    return results


# ── Helpers ───────────────────────────────────────────────────

def _port_open(host: str, port: int, timeout: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _get_certificate(host: str, port: int, timeout: int) -> dict:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der  = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der, default_backend())

                # Subject
                subject_cn = ""
                try:
                    subject_cn = cert.subject.get_attributes_for_oid(
                        x509.NameOID.COMMON_NAME)[0].value
                except Exception:
                    pass

                issuer_cn = ""
                try:
                    issuer_cn = cert.issuer.get_attributes_for_oid(
                        x509.NameOID.COMMON_NAME)[0].value
                except Exception:
                    pass

                # SANs
                sans = []
                try:
                    san_ext = cert.extensions.get_extension_for_class(
                        x509.SubjectAlternativeName)
                    sans = [str(n.value) for n in san_ext.value]
                except Exception:
                    pass

                # Algoritmo de firma
                sig_algo = cert.signature_algorithm_oid.dotted_string
                try:
                    sig_algo = cert.signature_hash_algorithm.name
                except Exception:
                    pass

                # Tipo y tamaño de clave — distinguir RSA vs EC vs DSA
                pub_key  = cert.public_key()
                key_size = 0
                key_type = "unknown"
                try:
                    key_size = pub_key.key_size
                    if isinstance(pub_key, rsa.RSAPublicKey):
                        key_type = "rsa"
                    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                        key_type = "ec"
                        # Nombre de curva para info adicional
                        sig_algo = f"ecdsa ({pub_key.curve.name})"
                    elif isinstance(pub_key, dsa.DSAPublicKey):
                        key_type = "dsa"
                except Exception:
                    pass

                not_after  = (cert.not_valid_after_utc
                              if hasattr(cert, "not_valid_after_utc")
                              else cert.not_valid_after.replace(tzinfo=timezone.utc))
                not_before = (cert.not_valid_before_utc
                              if hasattr(cert, "not_valid_before_utc")
                              else cert.not_valid_before.replace(tzinfo=timezone.utc))
                days_left  = (not_after - datetime.now(timezone.utc)).days

                return {
                    "subject_cn":       subject_cn,
                    "issuer_cn":        issuer_cn,
                    "not_before":       not_before.strftime("%Y-%m-%d"),
                    "not_after":        not_after.strftime("%Y-%m-%d"),
                    "days_remaining":   days_left,
                    "serial":           str(cert.serial_number),
                    "signature_algo":   sig_algo,
                    "key_size":         key_size,
                    "key_type":         key_type,
                    "sans":             sans,
                    "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
                    "self_signed":      subject_cn == issuer_cn,
                    "expired":          days_left < 0,
                }

    except Exception as e:
        console.print(f"  [yellow]![/yellow] Error obteniendo certificado: {e}")
        return {}


def _check_certificate_findings(cert: dict, results: dict):
    # Expirado
    if cert.get("expired"):
        results["findings"].append({
            "phase":       "SSL/TLS",
            "title":       "Certificado SSL expirado",
            "description": f"El certificado expiró el {cert['not_after']}. Genera alertas en navegadores.",
            "severity":    "CRITICAL",
            "cvss":        9.1,
            "remediation": "Renovar el certificado inmediatamente.",
        })
    # Próximo a expirar
    elif 0 < cert.get("days_remaining", 999) < 30:
        results["findings"].append({
            "phase":       "SSL/TLS",
            "title":       f"Certificado SSL próximo a expirar ({cert['days_remaining']} días)",
            "description": f"El certificado expira el {cert['not_after']}.",
            "severity":    "HIGH",
            "cvss":        7.5,
            "remediation": "Planificar renovación del certificado antes de la fecha de expiración.",
        })

    # Autofirmado
    if cert.get("self_signed"):
        results["findings"].append({
            "phase":       "SSL/TLS",
            "title":       "Certificado autofirmado",
            "description": "El certificado está autofirmado. No es de confianza por los navegadores.",
            "severity":    "HIGH",
            "cvss":        7.5,
            "remediation": "Reemplazar por un certificado emitido por una CA pública (ej: Let's Encrypt).",
        })

    # Algoritmo de firma débil
    sig = cert.get("signature_algo", "").lower()
    if any(w in sig for w in WEAK_SIGNATURE_ALGORITHMS):
        results["findings"].append({
            "phase":       "SSL/TLS",
            "title":       f"Algoritmo de firma débil: {cert['signature_algo']}",
            "description": f"El certificado usa {cert['signature_algo']} que se considera inseguro.",
            "severity":    "HIGH",
            "cvss":        7.4,
            "remediation": "Reemitir el certificado con SHA-256 o superior.",
        })

    # ── Clave débil — lógica diferenciada por tipo de algoritmo ──
    key_type = cert.get("key_type", "unknown").lower()
    key_size = cert.get("key_size", 0)

    if key_size and key_type in KEY_MIN_BITS:
        min_bits = KEY_MIN_BITS[key_type]
        if key_size < min_bits:
            if key_type == "rsa":
                title = f"Clave RSA débil: {key_size} bits"
                desc  = (
                    f"La clave RSA del certificado es de {key_size} bits. "
                    f"El mínimo recomendado para RSA es {min_bits} bits."
                )
                rem   = f"Regenerar el certificado con clave RSA de {min_bits}+ bits o migrar a ECDSA P-256."
            elif key_type == "dsa":
                title = f"Clave DSA débil: {key_size} bits"
                desc  = (
                    f"La clave DSA del certificado es de {key_size} bits. "
                    f"El mínimo recomendado para DSA es {min_bits} bits."
                )
                rem   = f"Regenerar el certificado con clave DSA de {min_bits}+ bits o migrar a ECDSA P-256."
            else:  # ec — caso muy improbable con curvas estándar
                title = f"Clave EC débil: {key_size} bits"
                desc  = (
                    f"La clave EC del certificado es de {key_size} bits. "
                    f"El mínimo recomendado es {min_bits} bits (curva P-224 o superior)."
                )
                rem   = "Regenerar el certificado con ECDSA P-256 o superior."

            results["findings"].append({
                "phase":       "SSL/TLS",
                "title":       title,
                "description": desc,
                "severity":    "HIGH",
                "cvss":        7.4,
                "remediation": rem,
            })
        # ECDSA P-256 (256 bits) >= 224 → no genera hallazgo


def _run_sslyze(host: str, port: int) -> dict:
    try:
        from sslyze import Scanner, ServerNetworkLocation, ServerScanRequest
        from sslyze.plugins.scan_commands import ScanCommand

        location = ServerNetworkLocation(host, port)
        request  = ServerScanRequest(
            server_location=location,
            scan_commands={
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.HEARTBLEED,
                ScanCommand.ROBOT,
                ScanCommand.TLS_COMPRESSION,
                ScanCommand.TLS_FALLBACK_SCSV,
                ScanCommand.OPENSSL_CCS_INJECTION,
                ScanCommand.SESSION_RENEGOTIATION,
            }
        )

        scanner = Scanner()
        scanner.queue_scans([request])

        protocols = {}
        ciphers   = []
        vulns     = []

        for result in scanner.get_results():
            if result.scan_result is None:
                continue

            proto_map = {
                ScanCommand.SSL_2_0_CIPHER_SUITES: "SSLv2",
                ScanCommand.SSL_3_0_CIPHER_SUITES: "SSLv3",
                ScanCommand.TLS_1_0_CIPHER_SUITES: "TLSv1",
                ScanCommand.TLS_1_1_CIPHER_SUITES: "TLSv1.1",
                ScanCommand.TLS_1_2_CIPHER_SUITES: "TLSv1.2",
                ScanCommand.TLS_1_3_CIPHER_SUITES: "TLSv1.3",
            }

            for cmd, proto_name in proto_map.items():
                try:
                    scan_res = getattr(result.scan_result, cmd.value, None)
                    if scan_res and hasattr(scan_res, "accepted_cipher_suites"):
                        accepted = scan_res.accepted_cipher_suites
                        protocols[proto_name] = len(accepted) > 0
                        for suite in accepted:
                            ciphers.append({
                                "protocol": proto_name,
                                "name":     suite.cipher_suite.name,
                                "key_size": getattr(suite.cipher_suite, "key_size", 0),
                            })
                except Exception:
                    pass

            _extract_sslyze_vulns(result, vulns)

        return {"protocols": protocols, "ciphers": ciphers, "vulns": vulns, "ocsp_stapling": False}

    except ImportError:
        return {}
    except Exception as e:
        console.print(f"  [yellow]![/yellow] sslyze error: {e}")
        return {}


def _extract_sslyze_vulns(result, vulns: list):
    try:
        from sslyze.plugins.scan_commands import ScanCommand
        hb = getattr(result.scan_result, ScanCommand.HEARTBLEED.value, None)
        if hb and getattr(hb, "is_vulnerable_to_heartbleed", False):
            vulns.append("HEARTBLEED")
    except Exception:
        pass
    try:
        from sslyze.plugins.scan_commands import ScanCommand
        rb = getattr(result.scan_result, ScanCommand.ROBOT.value, None)
        if rb and "VULNERABLE" in str(getattr(rb, "robot_result", "")):
            vulns.append("ROBOT")
    except Exception:
        pass


def _check_protocol_findings(sslyze_data: dict, results: dict):
    protocols = sslyze_data.get("protocols", {})
    for proto in INSECURE_PROTOCOLS:
        if protocols.get(proto):
            results["findings"].append({
                "phase":       "SSL/TLS",
                "title":       f"Protocolo inseguro habilitado: {proto}",
                "description": f"{proto} está habilitado en el servidor. Vulnerable a múltiples ataques (POODLE, BEAST, etc.).",
                "severity":    "HIGH" if proto in ("SSLv2", "SSLv3") else "MEDIUM",
                "cvss":        7.4 if proto in ("SSLv2", "SSLv3") else 5.9,
                "remediation": f"Deshabilitar {proto} en la configuración del servidor. Usar TLSv1.2 y TLSv1.3.",
            })

    ciphers = sslyze_data.get("ciphers", [])
    for cipher in ciphers:
        name = cipher.get("name", "")
        if any(w.upper() in name.upper() for w in WEAK_CIPHER_PATTERNS):
            results["findings"].append({
                "phase":       "SSL/TLS",
                "title":       f"Cifrado débil: {name}",
                "description": f"El cifrado {name} ({cipher.get('protocol')}) está habilitado y se considera inseguro.",
                "severity":    "MEDIUM",
                "cvss":        5.9,
                "remediation": f"Deshabilitar {name} en la configuración SSL. Usar solo cifrados AEAD (AES-GCM, ChaCha20).",
            })

    for vuln in sslyze_data.get("vulns", []):
        vuln_map = {
            "HEARTBLEED": ("CRITICAL", 9.8, "Actualizar OpenSSL a versión no vulnerable a Heartbleed (>=1.0.1g)."),
            "ROBOT":      ("HIGH",     7.5, "Deshabilitar RSA como intercambio de claves. Usar ECDHE."),
        }
        sev, cvss, rem = vuln_map.get(vuln, ("HIGH", 7.0, "Investigar y mitigar la vulnerabilidad."))
        results["findings"].append({
            "phase":       "SSL/TLS",
            "title":       f"Vulnerabilidad SSL: {vuln}",
            "description": f"El servidor es vulnerable a {vuln}.",
            "severity":    sev,
            "cvss":        cvss,
            "remediation": rem,
        })


def _basic_protocol_check(host: str, port: int, timeout: int) -> dict:
    protocols = {}
    proto_map = {
        "TLSv1":   ssl.TLSVersion.TLSv1   if hasattr(ssl.TLSVersion, "TLSv1")   else None,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, "TLSv1_3") else None,
    }
    for name, version in proto_map.items():
        if version is None:
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname  = False
            ctx.verify_mode     = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    protocols[name] = True
        except Exception:
            protocols[name] = False
    return protocols


def _run_nmap_ssl(host: str, port: int) -> dict:
    try:
        cmd  = ["nmap", "--script", "ssl-enum-ciphers", "-p", str(port), host,
                "--script-timeout", "30", "-oN", "-"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = proc.stdout

        data         = {"raw": output, "ciphers": [], "grade": ""}
        current_proto = ""

        for line in output.splitlines():
            line = line.strip()
            if line.startswith("TLS") or line.startswith("SSL"):
                current_proto = line.rstrip(":")
            elif line.startswith("|") and "TLS_" in line or "cipher" in line.lower():
                data["ciphers"].append({"protocol": current_proto, "cipher": line.strip("| ")})
            elif "least strength" in line.lower() or "Grade:" in line:
                import re
                match = re.search(r"Grade:\s*([A-F])", line)
                if match:
                    data["grade"] = match.group(1)

        return data

    except subprocess.TimeoutExpired:
        console.print("  [yellow]![/yellow] nmap ssl-enum-ciphers: timeout")
        return {}
    except Exception as e:
        console.print(f"  [yellow]![/yellow] nmap ssl-enum-ciphers error: {e}")
        return {}


def _check_nmap_cipher_findings(nmap_data: dict, results: dict):
    grade = nmap_data.get("grade", "")
    if grade in ("C", "D", "E", "F"):
        results["findings"].append({
            "phase":       "SSL/TLS",
            "title":       f"Nota SSL/TLS baja según nmap: {grade}",
            "description": f"nmap ssl-enum-ciphers asigna grado {grade} a la configuración SSL/TLS.",
            "severity":    "HIGH" if grade in ("D", "E", "F") else "MEDIUM",
            "cvss":        7.4 if grade in ("D", "E", "F") else 5.9,
            "remediation": "Revisar y fortalecer la configuración SSL/TLS. Eliminar cifrados débiles y protocolos obsoletos.",
        })


def _check_hsts(host: str, port: int, timeout: int) -> dict:
    import httpx
    result = {"enabled": False, "max_age": 0, "include_subdomains": False, "preload": False, "raw": ""}
    try:
        with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
            resp = client.get(f"https://{host}")
            hsts = resp.headers.get("strict-transport-security", "")
            result["raw"] = hsts
            if hsts:
                result["enabled"] = True
                for part in hsts.split(";"):
                    part = part.strip().lower()
                    if part.startswith("max-age"):
                        try:
                            result["max_age"] = int(part.split("=")[1])
                        except Exception:
                            pass
                    elif part == "includesubdomains":
                        result["include_subdomains"] = True
                    elif part == "preload":
                        result["preload"] = True
    except Exception:
        pass
    return result
