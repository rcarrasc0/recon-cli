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
]


def enrich_findings_with_mitre(findings: list, config: dict = None) -> list:
    global console
    if config:
        console = config.get("console") or console
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
