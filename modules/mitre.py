#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  recon-cli · modules/mitre.py  v1.1.6
#  Correlación MITRE ATT&CK Enterprise — criterio conservador.
#  Solo mappings con correspondencia directa y justificable.
#  Sin API externa. Referencia: https://attack.mitre.org/
# ─────────────────────────────────────────────────────────────

from rich.console import Console

console = Console()

# Mappings conservadores: se asigna sub-técnica solo cuando
# la correspondencia es directa. En caso de duda → None.
MITRE_MAPPING = [

    # AXFR: exposición directa de zona DNS → Reconnaissance DNS
    {
        "keywords":        ("axfr", "transferencia de zona"),
        "tactic_id":       "TA0043",
        "tactic":          "Reconnaissance",
        "technique_id":    "T1590",
        "technique":       "Gather Victim Network Information",
        "subtechnique_id": "T1590.002",
        "subtechnique":    "DNS",
        "url":             "https://attack.mitre.org/techniques/T1590/002/",
    },

    # Subdominios expuestos → Reconnaissance IP/Network
    {
        "keywords":        ("subdominio", "subdomain"),
        "tactic_id":       "TA0043",
        "tactic":          "Reconnaissance",
        "technique_id":    "T1590",
        "technique":       "Gather Victim Network Information",
        "subtechnique_id": "T1590.001",
        "subtechnique":    "IP Addresses",
        "url":             "https://attack.mitre.org/techniques/T1590/001/",
    },

    # SPF/DMARC ausente → facilita phishing/spoofing de correo
    {
        "keywords":        ("spf", "dmarc"),
        "tactic_id":       "TA0043",
        "tactic":          "Reconnaissance",
        "technique_id":    "T1598",
        "technique":       "Phishing for Information",
        "subtechnique_id": "T1598.003",
        "subtechnique":    "Spearphishing Link",
        "url":             "https://attack.mitre.org/techniques/T1598/003/",
    },

    # Certificados digitales expuestos (crt.sh, SAN) → Reconnaissance
    {
        "keywords":        ("certificado", "crt.sh", "x.509"),
        "tactic_id":       "TA0043",
        "tactic":          "Reconnaissance",
        "technique_id":    "T1596",
        "technique":       "Search Open Technical Databases",
        "subtechnique_id": "T1596.003",
        "subtechnique":    "Digital Certificates",
        "url":             "https://attack.mitre.org/techniques/T1596/003/",
    },

    # Información de servidor expuesta (Server, X-Powered-By)
    {
        "keywords":        ("server:", "x-powered-by", "información de servidor", "fuga de información"),
        "tactic_id":       "TA0043",
        "tactic":          "Reconnaissance",
        "technique_id":    "T1592",
        "technique":       "Gather Victim Host Information",
        "subtechnique_id": "T1592.002",
        "subtechnique":    "Software",
        "url":             "https://attack.mitre.org/techniques/T1592/002/",
    },

    # Credenciales filtradas (Leak-Lookup)
    {
        "keywords":        ("credencial", "brecha", "leak", "filtrada"),
        "tactic_id":       "TA0006",
        "tactic":          "Credential Access",
        "technique_id":    "T1589",
        "technique":       "Gather Victim Identity Information",
        "subtechnique_id": "T1589.001",
        "subtechnique":    "Credentials",
        "url":             "https://attack.mitre.org/techniques/T1589/001/",
    },

    # SSL/TLS inseguro o HSTS ausente → Man-in-the-Middle
    {
        "keywords":        ("hsts", "protocolo inseguro", "sslv2", "sslv3", "tlsv1",
                            "cifrado débil", "downgrade"),
        "tactic_id":       "TA0009",
        "tactic":          "Collection",
        "technique_id":    "T1557",
        "technique":       "Adversary-in-the-Middle",
        "subtechnique_id": None,
        "subtechnique":    None,
        "url":             "https://attack.mitre.org/techniques/T1557/",
    },

    # X-Frame-Options ausente → Browser Session Hijacking (Clickjacking)
    {
        "keywords":        ("x-frame-options",),
        "tactic_id":       "TA0009",
        "tactic":          "Collection",
        "technique_id":    "T1185",
        "technique":       "Browser Session Hijacking",
        "subtechnique_id": None,
        "subtechnique":    None,
        "url":             "https://attack.mitre.org/techniques/T1185/",
    },

    # CSP ausente / X-Content-Type → Execution client-side
    {
        "keywords":        ("content-security-policy", "csp", "x-content-type-options"),
        "tactic_id":       "TA0002",
        "tactic":          "Execution",
        "technique_id":    "T1203",
        "technique":       "Exploitation for Client Execution",
        "subtechnique_id": None,
        "subtechnique":    None,
        "url":             "https://attack.mitre.org/techniques/T1203/",
    },

    # CVE / vulnerabilidad conocida → Exploit Public-Facing Application
    {
        "keywords":        ("cve-", "vulnerabilidad", "heartbleed"),
        "tactic_id":       "TA0001",
        "tactic":          "Initial Access",
        "technique_id":    "T1190",
        "technique":       "Exploit Public-Facing Application",
        "subtechnique_id": None,
        "subtechnique":    None,
        "url":             "https://attack.mitre.org/techniques/T1190/",
    },

    # ── Greybox API ───────────────────────────────────────────

    # IDOR / BOLA → acceso no autorizado a datos de otro usuario/tenant
    # explotando un fallo de autorización expuesto en la propia API pública.
    # (No es Privilege Escalation: no hay elevación de privilegio, es acceso
    # a datos del mismo nivel de privilegio que no debería ser visible.)
    {
        "keywords":        ("idor", "bola", "broken object", "acceso no autorizado a recursos"),
        "tactic_id":       "TA0001",
        "tactic":          "Initial Access",
        "technique_id":    "T1190",
        "technique":       "Exploit Public-Facing Application",
        "subtechnique_id": None,
        "subtechnique":    None,
        "url":             "https://attack.mitre.org/techniques/T1190/",
    },

    # Mass Assignment → aquí SÍ hay elevación de privilegio real cuando el
    # valor inyectado (p.ej. role=admin) queda persistido/reflejado.
    {
        "keywords":        ("mass assignment",),
        "tactic_id":       "TA0004",
        "tactic":          "Privilege Escalation",
        "technique_id":    "T1548",
        "technique":       "Abuse Elevation Control Mechanism",
        "subtechnique_id": None,
        "subtechnique":    None,
        "url":             "https://attack.mitre.org/techniques/T1548/",
    },

    # Identificadores secuenciales enumerables en endpoint público —
    # no es un fallo de acceso, es reconnaissance de volumen/cardinalidad
    # de negocio. Misma técnica que el descubrimiento de shadow APIs.
    {
        "keywords":        ("identificadores secuenciales", "enumerables"),
        "tactic_id":       "TA0043",
        "tactic":          "Reconnaissance",
        "technique_id":    "T1595",
        "technique":       "Active Scanning",
        "subtechnique_id": "T1595.003",
        "subtechnique":    "Wordlist Scanning",
        "url":             "https://attack.mitre.org/techniques/T1595/003/",
    },

    # Endpoint sin autenticación → Valid Accounts (acceso con credenciales nulas)
    {
        "keywords":        ("sin autenticación", "no requiere autenticación", "endpoint abierto",
                            "sin token"),
        "tactic_id":       "TA0001",
        "tactic":          "Initial Access",
        "technique_id":    "T1078",
        "technique":       "Valid Accounts",
        "subtechnique_id": "T1078.004",
        "subtechnique":    "Cloud Accounts",
        "url":             "https://attack.mitre.org/techniques/T1078/004/",
    },

    # Rate limiting ausente → Resource Exhaustion / DoS
    {
        "keywords":        ("rate limiting", "ratelimit", "sin límite"),
        "tactic_id":       "TA0040",
        "tactic":          "Impact",
        "technique_id":    "T1499",
        "technique":       "Endpoint Denial of Service",
        "subtechnique_id": "T1499.004",
        "subtechnique":    "Application or System Exploitation",
        "url":             "https://attack.mitre.org/techniques/T1499/004/",
    },

    # Endpoint no documentado / shadow API → Reconnaissance superficie
    {
        "keywords":        ("endpoint no documentado", "shadow api", "no aparece en la documentación"),
        "tactic_id":       "TA0043",
        "tactic":          "Reconnaissance",
        "technique_id":    "T1595",
        "technique":       "Active Scanning",
        "subtechnique_id": "T1595.003",
        "subtechnique":    "Wordlist Scanning",
        "url":             "https://attack.mitre.org/techniques/T1595/003/",
    },

    # Token inválido/expirado aceptado → Broken Authentication
    # Nota: se elimina "acepta.*token" — mitre.py matchea por substring
    # literal (operador `in`), no por regex, así que ese patrón con
    # comodines nunca podía matchear nada; era código muerto.
    {
        "keywords":        ("token inválido", "token expirado", "ya está expirado"),
        "tactic_id":       "TA0006",
        "tactic":          "Credential Access",
        "technique_id":    "T1550",
        "technique":       "Use Alternate Authentication Material",
        "subtechnique_id": "T1550.001",
        "subtechnique":    "Application Access Token",
        "url":             "https://attack.mitre.org/techniques/T1550/001/",
    },

    # Exposición de datos sensibles en respuesta API
    # (keywords ampliadas: el finding real de api_audit.py dice literalmente
    # "campos potencialmente sensibles" y "excessive data exposure", no
    # "datos sensibles" — con el set anterior este finding nunca mapeaba).
    {
        "keywords":        ("expuesto en respuesta", "stack trace", "datos sensibles",
                            "excessive data exposure", "campos potencialmente sensibles"),
        "tactic_id":       "TA0009",
        "tactic":          "Collection",
        "technique_id":    "T1213",
        "technique":       "Data from Information Repositories",
        "subtechnique_id": None,
        "subtechnique":    None,
        "url":             "https://attack.mitre.org/techniques/T1213/",
    },

    # OAuth2: endpoint accesible por HTTP sin TLS → intercepción de tokens en tránsito
    {
        "keywords":        ("accesible por http", "sin tls", "transmitirse en claro"),
        "tactic_id":       "TA0009",
        "tactic":          "Collection",
        "technique_id":    "T1557",
        "technique":       "Adversary-in-the-Middle",
        "subtechnique_id": None,
        "subtechnique":    None,
        "url":             "https://attack.mitre.org/techniques/T1557/",
    },

    # OAuth2: open redirect en redirect_uri → robo de authorization_code
    {
        "keywords":        ("open redirect",),
        "tactic_id":       "TA0006",
        "tactic":          "Credential Access",
        "technique_id":    "T1528",
        "technique":       "Steal Application Access Token",
        "subtechnique_id": None,
        "subtechnique":    None,
        "url":             "https://attack.mitre.org/techniques/T1528/",
    },
]


def enrich_findings_with_mitre(findings: list, config: dict = None) -> list:
    enriched    = 0
    not_matched = []

    for finding in findings:
        text  = f"{finding.get('title','').lower()} {finding.get('description','').lower()}"
        match = None

        for mapping in MITRE_MAPPING:
            if any(kw.lower() in text for kw in mapping["keywords"]):
                match = {
                    "tactic_id":       mapping["tactic_id"],
                    "tactic":          mapping["tactic"],
                    "technique_id":    mapping["technique_id"],
                    "technique":       mapping["technique"],
                    "subtechnique_id": mapping.get("subtechnique_id"),
                    "subtechnique":    mapping.get("subtechnique"),
                    "url":             mapping["url"],
                }
                break

        finding["mitre"] = match
        if match:
            enriched += 1
        else:
            not_matched.append(finding.get("title", ""))

    console.print(
        f"  [green]✓[/green] MITRE ATT&CK: {enriched}/{len(findings)} hallazgo(s) correlacionados"
    )
    return findings


def get_unique_techniques(findings: list) -> list:
    seen       = set()
    techniques = []

    for finding in findings:
        mitre = finding.get("mitre")
        if not mitre:
            continue
        key = mitre.get("subtechnique_id") or mitre.get("technique_id")
        if key and key not in seen:
            seen.add(key)
            techniques.append({
                **mitre,
                "findings": [
                    f.get("title","") for f in findings
                    if f.get("mitre") and (
                        (f["mitre"].get("subtechnique_id") or f["mitre"].get("technique_id")) == key
                    )
                ],
            })

    techniques.sort(key=lambda t: (t["tactic_id"], t["technique_id"]))
    return techniques
