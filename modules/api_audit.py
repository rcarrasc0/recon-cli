#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  recon-cli · modules/api_audit.py  v1.2.0
#  Auditoría de seguridad sobre endpoints descubiertos.
#  Checks: auth, métodos, IDOR, info exposure, rate limiting,
#          SOAP/WSDL, GraphQL introspection, tokens.
# ─────────────────────────────────────────────────────────────

import re
import httpx
from rich.console import Console

console = Console()

# Patrones de datos sensibles en respuestas
SENSITIVE_PATTERNS = [
    (re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*\S+'),         "Contraseña expuesta en respuesta"),
    (re.compile(r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?\w{16,}'),"API key expuesta en respuesta"),
    (re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),     "JWT token expuesto en respuesta"),
    (re.compile(r'(?i)stack\s*trace|traceback|at\s+\w+\.\w+\('),    "Stack trace expuesto"),
    (re.compile(r'(?i)(secret|token)\s*[=:]\s*["\']?\w{16,}'),      "Secret/token expuesto en respuesta"),
    (re.compile(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'),       "Posible número de tarjeta expuesto"),
    (re.compile(r'\b[0-9]{8}[A-Za-z]\b'),                            "Posible NIF expuesto"),
]

# Cabeceras de seguridad específicas de APIs
API_SECURITY_HEADERS = {
    "x-content-type-options":   "Previene MIME sniffing",
    "x-request-id":             "Trazabilidad de requests",
    "x-ratelimit-limit":        "Rate limiting configurado",
    "x-ratelimit-remaining":    "Rate limiting configurado",
}

# GraphQL introspection query
GRAPHQL_INTROSPECTION = '{"query": "{ __schema { types { name } } }"}'


# ── Matriz de cobertura de pruebas ─────────────────────────────
# Registra qué se comprobó y con qué resultado, aunque no haya hallazgos —
# un informe que solo lista hallazgos no distingue "no lo hemos mirado" de
# "lo hemos mirado y está bien". Se agrega por TIPO de check (no por
# endpoint individual, o la tabla sería ilegible con muchos endpoints).
COVERAGE_DEFS_API = {
    "headers":         ("Cabeceras de seguridad de la API",              "Sin sesión"),
    "graphql":         ("GraphQL introspection",                          "Ambas"),
    "wsdl":            ("WSDL expuesto públicamente",                     "Sin sesión"),
    "swagger":         ("Swagger/OpenAPI accesible sin autenticación",    "Sin sesión"),
    "auth":            ("Autenticación (endpoint abierto / token inválido)", "Ambas"),
    "methods":         ("Métodos HTTP no documentados",                  "Con sesión"),
    "info_exposure":   ("Exposición de información (patrones)",         "Con sesión"),
    "idor":            ("IDOR (ID adyacente)",                           "Con sesión"),
    "sequential_id":   ("Identificadores secuenciales (endpoint público)","Sin sesión"),
    "bola":            ("BOLA (cross-tenant)",                          "Con sesión"),
    "undocumented":    ("Endpoint no documentado (shadow API)",          "Sin sesión"),
    "mass_assignment": ("Mass Assignment",                               "Con sesión"),
    "excessive_data":  ("Excessive Data Exposure",                       "Con sesión"),
    "rate_limiting":   ("Rate limiting",                                 "Con sesión"),
    "bfla":            ("BFLA (función de nivel superior accesible)",   "Con sesión"),
}


def _cov_init_api(results: dict):
    results["coverage"] = {
        key: {"label": label, "session": session, "tested": 0, "findings": 0, "detail": ""}
        for key, (label, session) in COVERAGE_DEFS_API.items()
    }


def _cov_run(results: dict, key: str, before_count: int):
    """Registra una ejecución de check y cuántos findings nuevos generó."""
    cov = results.setdefault("coverage", {})
    if key not in cov:
        return
    cov[key]["tested"] += 1
    after_count = len(results["findings"])
    if after_count > before_count:
        cov[key]["findings"] += after_count - before_count


# Endpoints de PROTOCOLO OAuth2/OIDC (token, authorize, revoke, logout,
# userinfo, discovery metadata) — no son recursos de negocio. Los checks
# genéricos de este módulo (sin auth, IDOR, BOLA, Mass Assignment...) parten
# de la base de que un endpoint autenticado usa Bearer y expone datos de
# negocio; un token endpoint, por diseño (RFC 6749 §3.2), se autentica con
# client_id/secret o un código en el BODY, no con un Bearer previo — así que
# "responde igual con y sin Authorization header" no es una vulnerabilidad
# ahí, es el comportamiento correcto. Ya están cubiertos por los checks
# dedicados de oauth_audit.py (submodo SSO), que sí conocen ese protocolo.
_OAUTH_PROTOCOL_LAST_SEGMENTS = (
    "token", "authorize", "auth", "revoke", "logout", "userinfo", "introspect",
)
_OAUTH_PROTOCOL_HINTS = ("oauth2", "oauth", "connect", "openid")


def _is_oauth_protocol_endpoint(path: str) -> bool:
    p = path.lower().rstrip("/")
    if p in ("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"):
        return True
    last_segment = p.split("/")[-1]
    if last_segment in _OAUTH_PROTOCOL_LAST_SEGMENTS and any(hint in p for hint in _OAUTH_PROTOCOL_HINTS):
        return True
    return False


def run_audit(discovery: dict, config: dict) -> dict:
    """
    Ejecuta todos los checks de seguridad sobre los endpoints descubiertos.
    Devuelve dict con findings y estadísticas.
    """
    global console
    console = config.get("console") or console

    token    = config.get("greybox_api_token", "")
    timeout  = config.get("REQUEST_TIMEOUT", 10)
    base_url = discovery.get("base_url", "")
    endpoints = discovery.get("endpoints", [])

    # ── Perfil de agresividad ─────────────────────────────────
    profile         = config.get("greybox_api_profile", "normal")
    rate_limit_reqs = {"normal": 15, "aggressive": 30}.get(profile, 15)
    console.print(f"  [dim]Perfil de auditoría: {profile}[/dim]")

    results = {
        "findings":          [],
        "endpoints_audited": 0,
        "endpoints_open":    0,
        "endpoints_runtime_generated": 0,
        "endpoints_oauth_protocol": 0,
        "profile":           profile,
        "checks": {
            "auth":         0,
            "methods":      0,
            "idor":         0,
            "info_exposure":0,
            "rate_limit":   0,
            "special":      0,
        },
    }
    _cov_init_api(results)

    if not endpoints:
        console.print("  [yellow]![/yellow] Sin endpoints que auditar")
        return results

    headers_with_token    = _auth_headers(token)
    headers_without_token = {"User-Agent": "recon-cli/1.2 security-scanner"}

    # Conjuntos para hallazgo "no documentado"
    documented_paths = {
        ep.get("path")
        for ep in endpoints
        if any(s in ep.get("sources", [ep.get("source", "")])
               for s in ("postman", "openapi"))
    }
    spider_only_paths = {
        ep.get("path")
        for ep in endpoints
        if all(s == "spider" or s == "spider_html"
               for s in ep.get("sources", [ep.get("source", "spider")]))
    }

    console.print(f"  [dim]Auditando {len(endpoints)} endpoint(s)...[/dim]")

    with httpx.Client(timeout=timeout, verify=False, follow_redirects=False) as client:

        # ── Check global: cabeceras de seguridad API ─────────────
        before = len(results["findings"])
        _check_api_headers(client, base_url, headers_with_token, results)
        _cov_run(results, "headers", before)

        # ── Check global: GraphQL introspection ──────────────────
        if discovery.get("graphql_found"):
            before = len(results["findings"])
            _check_graphql(client, base_url, headers_with_token,
                           headers_without_token, results)
            _cov_run(results, "graphql", before)
            results["checks"]["special"] += 1

        # ── Check global: WSDL expuesto ──────────────────────────
        if discovery.get("wsdl_found"):
            before = len(results["findings"])
            _add_finding(results, {
                "phase":       "Greybox API",
                "title":       "WSDL expuesto públicamente",
                "description": (
                    f"El WSDL del servicio SOAP es accesible sin autenticación. "
                    f"Operaciones detectadas: "
                    f"{', '.join(discovery.get('wsdl_operations', [])[:5]) or 'N/A'}."
                ),
                "severity":    "LOW",
                "cvss":        3.7,
                "remediation": "Restringir acceso al WSDL. Solo exponer a clientes autorizados.",
            })
            _cov_run(results, "wsdl", before)
            results["checks"]["special"] += 1

        # ── Swagger/ReDoc sin auth ───────────────────────────────
        if discovery.get("swagger_found"):
            before = len(results["findings"])
            _add_finding(results, {
                "phase":       "Greybox API",
                "title":       "Swagger UI / OpenAPI accesible sin autenticación",
                "description": (
                    "La documentación OpenAPI/Swagger es accesible públicamente. "
                    "Expone la superficie completa de la API a cualquier usuario."
                ),
                "severity":    "LOW",
                "cvss":        3.7,
                "remediation": "Proteger /swagger-ui, /docs y /openapi.json con autenticación en producción.",
            })
            _cov_run(results, "swagger", before)
            results["checks"]["special"] += 1

        # ── Por endpoint ─────────────────────────────────────────
        for ep in endpoints:
            path     = ep.get("path", "")
            method   = ep.get("method", "GET")
            full_url = ep.get("full_url", f"{base_url}{path}")
            sources  = ep.get("sources", [ep.get("source", "unknown")])

            # Variables Postman generadas en runtime (pm.environment.set()),
            # no resolubles estáticamente — el path es un placeholder literal
            # como "/{{credential_offer_uri}}", no una URL real. Auditarlo
            # solo produciría peticiones fallidas en silencio y, peor, un
            # falso "endpoint no documentado" si además vino solo del spider.
            if ep.get("runtime_generated"):
                results["endpoints_runtime_generated"] += 1
                continue

            if _is_oauth_protocol_endpoint(path):
                results["endpoints_oauth_protocol"] += 1
                console.print(
                    f"  [dim]Endpoint de protocolo OAuth2/OIDC (no de negocio): {method} {path} "
                    f"— excluido de checks genéricos, cubierto por el submodo SSO[/dim]"
                )
                continue

            results["endpoints_audited"] += 1

            # Check 1 — Sin autenticación
            if ep.get("intentionally_public"):
                console.print(f"  [dim]Endpoint público (noauth): {method} {path}[/dim]")
                results["checks"]["auth"] += 1
                results["coverage"]["auth"]["tested"] += 1
                results["coverage"]["auth"]["detail"] = "Incluye endpoints públicos por diseño (no se auditan como fallo)"
            else:
                before = len(results["findings"])
                open_finding = _check_no_auth(
                    client, method, full_url, path,
                    headers_with_token, headers_without_token, results
                )
                results["checks"]["auth"] += 1
                _cov_run(results, "auth", before)
                if open_finding:
                    results["endpoints_open"] += 1

            # Check 2 — Métodos HTTP no documentados
            before = len(results["findings"])
            _check_extra_methods(client, full_url, path, method, headers_with_token, results)
            results["checks"]["methods"] += 1
            _cov_run(results, "methods", before)

            # Check 3 — Info exposure en respuesta
            before = len(results["findings"])
            _check_info_exposure(client, method, full_url, path, headers_with_token,
                                 results, ep.get("intentionally_public", False))
            results["checks"]["info_exposure"] += 1
            _cov_run(results, "info_exposure", before)

            # Check 4 — IDOR básico (solo si el path contiene un ID numérico)
            # IDOR es por definición un fallo de CONTROL DE ACCESO. Si el endpoint
            # es público por diseño (intentionally_public), no hay control de acceso
            # que romper — cualquiera puede pedir cualquier ID intencionadamente.
            # Por eso ya no se degrada a MEDIUM: se omite el check de IDOR y, en su
            # lugar, se reporta un hallazgo de naturaleza distinta (Check 4b).
            idor_found = False
            if re.search(r'/\d+', path) and not ep.get("intentionally_public"):
                before = len(results["findings"])
                idor_found = _check_idor(client, method, full_url, path, headers_with_token,
                            results, ep.get("intentionally_public", False))
                results["checks"]["idor"] += 1
                _cov_run(results, "idor", before)

            # Check 4b — Enumeración de IDs secuenciales en endpoint público
            # No es un fallo de acceso, pero permite inferir volumen/cardinalidad
            # de negocio (p.ej. nº de credenciales emitidas) por incremento simple.
            if re.search(r'/\d+', path) and ep.get("intentionally_public"):
                before = len(results["findings"])
                _check_sequential_id_enumeration(client, method, full_url, path,
                                                 headers_with_token, results)
                _cov_run(results, "sequential_id", before)

            # Check 5 — BOLA / Cross-tenant (IDs no secuenciales: 0, 99, 9999)
            # Se omite si el Check 4 (IDOR) ya reportó el mismo endpoint: ambos
            # detectan la misma causa raíz (falta de validación de ownership) y
            # generar los dos findings solo duplica ruido en el informe.
            # También se omite en endpoints públicos — ver comentario del Check 4.
            if re.search(r'/\d+', path) and not ep.get("intentionally_public") and not idor_found:
                before = len(results["findings"])
                _check_bola(client, method, full_url, path, headers_with_token, results)
                _cov_run(results, "bola", before)

            # Check 6 — Endpoint no documentado (solo spider)
            if path in spider_only_paths and documented_paths:
                before = len(results["findings"])
                _add_finding(results, {
                    "phase":       "Greybox API",
                    "title":       f"Endpoint no documentado descubierto: {method} {path}",
                    "description": (
                        f"El endpoint {method} {full_url} fue descubierto por el spider "
                        f"pero no aparece en la documentación aportada (Postman/OpenAPI). "
                        f"Puede indicar shadow API, endpoint olvidado o falta de documentación."
                    ),
                    "severity":    "INFO",
                    "cvss":        0.0,
                    "remediation": (
                        "Revisar si el endpoint es intencionado y documentarlo. "
                        "Si no es necesario, considerar eliminarlo o restringir el acceso."
                    ),
                })
                _cov_run(results, "undocumented", before)

            # Check 7 — Mass Assignment (solo POST/PUT autenticados)
            if method in ("POST", "PUT") and not ep.get("intentionally_public"):
                before = len(results["findings"])
                _check_mass_assignment(client, method, full_url, path,
                                       headers_with_token, results)
                _cov_run(results, "mass_assignment", before)

            # Check 8 — Excessive Data Exposure en respuestas autenticadas
            if not ep.get("intentionally_public") and method == "GET":
                before = len(results["findings"])
                _check_excessive_data(client, full_url, path,
                                      headers_with_token, results)
                _cov_run(results, "excessive_data", before)

            # Check 9 — BFLA heurístico (función de nivel superior accesible)
            before = len(results["findings"])
            _check_bfla(client, method, full_url, path, headers_with_token,
                       results, ep.get("intentionally_public", False))
            _cov_run(results, "bfla", before)

        # ── Check global: rate limiting ──────────────────────────
        if endpoints:
            test_url = endpoints[0].get("full_url", base_url)
            before = len(results["findings"])
            _check_rate_limiting(client, test_url, headers_with_token,
                                 results, rate_limit_reqs)
            results["checks"]["rate_limit"] += 1
            _cov_run(results, "rate_limiting", before)

    console.print(
        f"  [green]✓[/green] Auditoría completada — "
        f"{results['endpoints_audited']} endpoint(s) analizados, "
        f"{results['endpoints_open']} sin autenticación, "
        f"{len(results['findings'])} hallazgo(s)"
    )
    return results


# ── Checks individuales ───────────────────────────────────────

def _check_no_auth(client, method, url, path, h_auth, h_noauth, results) -> bool:
    """Verifica si el endpoint responde sin token de autenticación."""
    try:
        r_auth   = _request(client, method, url, h_auth)
        r_noauth = _request(client, method, url, h_noauth)

        if r_auth is None or r_noauth is None:
            return False

        # Si responde igual sin token que con token → sin auth
        if r_noauth.status_code in (200, 201, 202) and r_auth.status_code in (200, 201, 202):
            _add_finding(results, {
                "phase":       "Greybox API",
                "title":       f"Endpoint sin autenticación: {method} {path}",
                "description": (
                    f"{method} {url} devuelve HTTP {r_noauth.status_code} sin token. "
                    f"El endpoint no requiere autenticación."
                ),
                "severity":    "HIGH",
                "cvss":        7.5,
                "remediation": f"Implementar autenticación Bearer en {method} {path}.",
                "confidence":  "HIGH",
            })
            return True

        # Token inválido aceptado
        r_invalid = _request(client, method, url,
                             {**h_noauth, "Authorization": "Bearer invalid_token_test_recon"})
        if r_invalid and r_invalid.status_code in (200, 201, 202):
            _add_finding(results, {
                "phase":       "Greybox API",
                "title":       f"Token inválido aceptado: {method} {path}",
                "description": (
                    f"{method} {url} acepta un Bearer token inválido (HTTP {r_invalid.status_code}). "
                    f"La validación de tokens no funciona correctamente."
                ),
                "severity":    "HIGH",
                "cvss":        8.1,
                "remediation": "Verificar la firma y validez del JWT en cada request.",
                "confidence":  "HIGH",
            })
            return True

    except Exception:
        pass
    return False


def _check_extra_methods(client, url, path, documented_method, headers, results):
    """Comprueba si el endpoint acepta métodos HTTP no documentados."""
    for method in ["PUT", "DELETE", "PATCH"]:
        if method == documented_method:
            continue
        try:
            r = _request(client, method, url, headers)
            if r and r.status_code in (200, 201, 202):
                _add_finding(results, {
                    "phase":       "Greybox API",
                    "title":       f"Método no documentado activo: {method} {path}",
                    "description": (
                        f"{method} {url} devuelve HTTP {r.status_code}. "
                        f"Este método no estaba documentado para este endpoint."
                    ),
                    "severity":    "MEDIUM",
                    "cvss":        5.3,
                    "remediation": f"Restringir {method} en {path} si no es un método previsto.",
                    "confidence":  "MEDIUM",
                })
        except Exception:
            pass


def _check_info_exposure(client, method, url, path, headers, results,
                          intentionally_public=False):
    """Detecta información sensible en el body de la respuesta."""
    try:
        r = _request(client, method, url, headers)
        if r is None or r.status_code not in (200, 201, 500):
            return
        body = r.text[:5000]

        for pattern, description in SENSITIVE_PATTERNS:
            # JWT en endpoint público: es contenido legítimo (status_list, OIDC config...)
            # no reportar como fuga — el JWT ES la respuesta esperada
            if "JWT token" in description and intentionally_public:
                continue

            if pattern.search(body):
                _add_finding(results, {
                    "phase":       "Greybox API",
                    "title":       f"{description}: {method} {path}",
                    "description": (
                        f"{method} {url} expone información sensible en la respuesta: "
                        f"{description}."
                    ),
                    "severity":    "HIGH" if "token" in description.lower() or
                                             "contraseña" in description.lower() else "MEDIUM",
                    "cvss":        7.5 if "token" in description.lower() else 5.3,
                    "remediation": "Revisar y limpiar la respuesta. No exponer credenciales ni tokens.",
                    "confidence":  "MEDIUM",
                })
                break

        # Stack trace en 500
        if r.status_code == 500:
            if any(kw in body.lower() for kw in ["traceback", "stack trace", "exception", "at line"]):
                _add_finding(results, {
                    "phase":       "Greybox API",
                    "title":       f"Stack trace expuesto en error 500: {path}",
                    "description": (
                        f"{method} {url} devuelve HTTP 500 con stack trace visible. "
                        f"Revela información interna de la aplicación."
                    ),
                    "severity":    "MEDIUM",
                    "cvss":        5.3,
                    "remediation": "Implementar gestión de errores. No exponer stack traces en producción.",
                    "confidence":  "HIGH",
                })

    except Exception:
        pass


def _check_idor(client, method, url, path, headers, results,
                intentionally_public=False) -> bool:
    """
    Posible IDOR: si el path contiene /123, probar /124 y comparar respuestas.
    Incluye evidencia completa: IDs, status codes y tamaños de respuesta.
    En endpoints públicos la severidad es MEDIUM — el impacto real es menor
    porque no hay datos de usuario autenticado en juego.
    Devuelve True si se generó un finding (usado para evitar que el check de
    BOLA duplique el mismo hallazgo).
    """
    try:
        match = re.search(r'/(\d+)', path)
        if not match:
            return False

        original_id = int(match.group(1))
        test_id     = original_id + 1 if original_id < 9999 else original_id - 1

        # Sustitución precisa: se reemplaza el ID dentro del path (donde se
        # localizó con el regex) y luego se aplica ese mismo path a la URL
        # completa. Sustituir directamente sobre `url` con re.sub podría
        # acertar sobre otro segmento numérico previo (puerto, /v2/, etc.)
        # si el ID real no es el primer /\d+ de la URL completa.
        path_test = re.sub(r'/\d+', f'/{test_id}', path, count=1)
        url_test  = url.replace(path, path_test, 1)

        r_orig = _request(client, method, url, headers)
        r_test = _request(client, method, url_test, headers)

        if (r_orig and r_test and
                r_orig.status_code == 200 and r_test.status_code == 200 and
                len(r_test.text) > 50 and r_test.text != r_orig.text):

            # Severidad reducida en endpoints públicos — no hay sesión de usuario en juego
            severity = "MEDIUM" if intentionally_public else "HIGH"
            cvss     = 5.3     if intentionally_public else 7.5
            pub_note = (
                " El endpoint es público, por lo que el impacto real puede ser limitado,"
                " pero se recomienda verificación manual."
            ) if intentionally_public else ""

            _add_finding(results, {
                "phase":       "Greybox API",
                "title":       f"Posible IDOR: {method} {path}",
                "description": (
                    f"Al modificar el ID en {method} {url} se obtiene una respuesta diferente, "
                    f"lo que podría indicar acceso no autorizado a recursos de otros usuarios.\n"
                    f"Evidencia: ID original={original_id} (HTTP {r_orig.status_code}, "
                    f"{len(r_orig.text)} bytes) → "
                    f"ID probado={test_id} (HTTP {r_test.status_code}, "
                    f"{len(r_test.text)} bytes). "
                    f"Se requiere verificación manual para confirmar el impacto real.{pub_note}"
                ),
                "severity":    severity,
                "cvss":        cvss,
                "remediation": (
                    f"Verificar que {path} valida que el recurso pertenece al usuario autenticado. "
                    "Usar UUIDs en lugar de IDs secuenciales para dificultar la enumeración."
                ),
                "confidence": "MEDIUM",
                "escalation": "horizontal",
                "evidence": {
                    "id_original":       original_id,
                    "id_probado":        test_id,
                    "url_original":    url,
                    "url_probada":     url_test,
                    "status_original": r_orig.status_code,
                    "status_probado":  r_test.status_code,
                    "bytes_original":  len(r_orig.text),
                    "bytes_probado":   len(r_test.text),
                },
            })
            return True
    except Exception:
        pass
    return False


def _check_sequential_id_enumeration(client, method, url, path, headers, results):
    """
    Endpoint PÚBLICO (intentionally_public) con un ID numérico secuencial
    en el path. No es un fallo de control de acceso — el endpoint es público
    por diseño, cualquiera puede pedir cualquier ID intencionadamente — pero
    sí permite inferir volumen/cardinalidad de negocio (p.ej. cuántas
    credenciales se han emitido) por simple incremento del ID.
    Severidad INFO: es una nota de higiene, no una vulnerabilidad de acceso.
    """
    try:
        match = re.search(r'/(\d+)', path)
        if not match:
            return

        r = _request(client, method, url, headers)
        if not r or r.status_code not in (200, 201):
            return

        _add_finding(results, {
            "phase":       "Greybox API",
            "title":       f"Identificadores secuenciales enumerables en endpoint público: {method} {path}",
            "description": (
                f"{method} {url} es un endpoint público (sin autenticación requerida) "
                f"que usa un identificador numérico secuencial en el path. No hay "
                f"control de acceso que romper — es público por diseño — pero el "
                f"carácter secuencial del ID permite inferir volumen o cardinalidad "
                f"de negocio (p.ej. número de recursos emitidos) mediante incremento simple."
            ),
            "severity":    "INFO",
            "cvss":        0.0,
            "remediation": (
                "Usar identificadores no secuenciales (UUID) incluso en endpoints "
                "públicos, para evitar fuga de volumen/cardinalidad del negocio."
            ),
            "confidence": "HIGH",
        })
    except Exception:
        pass


def _check_rate_limiting(client, url, headers, results, num_requests: int = 15):
    """Comprueba ausencia de rate limiting enviando 15 requests rápidos."""
    try:
        status_codes = []
        for _ in range(num_requests):
            r = _request(client, "GET", url, headers)
            if r:
                status_codes.append(r.status_code)

        # Si ninguno devuelve 429 → sin rate limiting
        if 429 not in status_codes and all(s in (200, 201, 401, 403) for s in status_codes):
            # Verificar también ausencia de cabeceras X-RateLimit-*
            last_r = _request(client, "GET", url, headers)
            if last_r:
                has_rl_header = any(
                    h.lower().startswith("x-ratelimit") or h.lower() == "retry-after"
                    for h in last_r.headers.keys()
                )
                if not has_rl_header:
                    _add_finding(results, {
                        "phase":       "Greybox API",
                        "title":       "Rate limiting no detectado",
                        "description": (
                            f"15 requests consecutivos a {url} no generaron HTTP 429 "
                            f"ni cabeceras X-RateLimit-*. La API no parece tener rate limiting."
                        ),
                        "severity":    "LOW",
                        "cvss":        3.7,
                        "remediation": (
                            "Implementar rate limiting. Añadir cabeceras X-RateLimit-Limit, "
                            "X-RateLimit-Remaining y Retry-After."
                        ),
                        "confidence": "LOW",
                    })
    except Exception:
        pass


def _check_api_headers(client, base_url, headers, results):
    """Verifica cabeceras de seguridad específicas de APIs."""
    try:
        r = _request(client, "GET", base_url, headers)
        if r is None:
            return
        resp_headers = {k.lower(): v for k, v in r.headers.items()}
        missing = []
        for h, desc in API_SECURITY_HEADERS.items():
            if h not in resp_headers and h.startswith("x-ratelimit"):
                # X-RateLimit se comprueba por separado en rate limiting
                continue
            if h not in resp_headers and not h.startswith("x-ratelimit"):
                missing.append(h)

        if "x-content-type-options" not in resp_headers:
            _add_finding(results, {
                "phase":       "Greybox API",
                "title":       "Cabecera X-Content-Type-Options ausente en API",
                "description": "La API no envía X-Content-Type-Options: nosniff.",
                "severity":    "LOW",
                "cvss":        3.1,
                "remediation": "Añadir X-Content-Type-Options: nosniff en las respuestas de la API.",
            })
    except Exception:
        pass


def _check_graphql(client, base_url, h_auth, h_noauth, results):
    """Comprueba si GraphQL permite introspection sin autenticación."""
    graphql_url = f"{base_url.rstrip('/')}/graphql"
    try:
        # Con token
        r_auth = client.post(
            graphql_url,
            content=GRAPHQL_INTROSPECTION,
            headers={**h_auth, "Content-Type": "application/json"}
        )
        # Sin token
        r_noauth = client.post(
            graphql_url,
            content=GRAPHQL_INTROSPECTION,
            headers={**h_noauth, "Content-Type": "application/json"}
        )

        if r_noauth.status_code == 200 and "__schema" in r_noauth.text:
            _add_finding(results, {
                "phase":       "Greybox API",
                "title":       "GraphQL introspection habilitada sin autenticación",
                "description": (
                    "El endpoint GraphQL permite introspection sin token. "
                    "Expone el esquema completo de la API a usuarios no autenticados."
                ),
                "severity":    "MEDIUM",
                "cvss":        5.3,
                "remediation": "Deshabilitar introspection en producción o requerir autenticación.",
            })
        elif r_auth.status_code == 200 and "__schema" in r_auth.text:
            # Solo INFO — introspection disponible con auth (aceptable en algunos casos)
            _add_finding(results, {
                "phase":       "Greybox API",
                "title":       "GraphQL introspection habilitada (con autenticación)",
                "description": (
                    "El endpoint GraphQL permite introspection con token válido. "
                    "Considerar deshabilitar en producción."
                ),
                "severity":    "INFO",
                "cvss":        0.0,
                "remediation": "Evaluar si la introspection GraphQL es necesaria en producción.",
            })
    except Exception:
        pass


def _check_bola(client, method, url, path, headers, results):
    """
    BOLA / Broken Object Level Authorization (OWASP API #1).
    Prueba IDs de otros tenants: 0, 2, 99, 9999.
    Si responde con datos DISTINTOS a los del ID original → posible acceso cross-tenant.

    Importante: exige que el cuerpo de respuesta sea distinto al del ID original.
    Sin esta comparación, cualquier endpoint que devuelva 200 con >50 bytes para
    cualquier ID (p.ej. un catch-all que ignora el parámetro, o una colección
    genérica) dispararía el check aunque no exista fuga real de datos de otro
    tenant — ese fue el principal falso positivo detectado en la revisión.
    """
    try:
        match = re.search(r'/(\d+)', path)
        if not match:
            return

        original_id = int(match.group(1))
        # Probar IDs que claramente pertenecen a otros tenants
        test_ids = [i for i in [0, 2, 99, 9999] if i != original_id]

        r_orig = _request(client, method, url, headers)
        if not r_orig or r_orig.status_code not in (200, 201):
            return

        for test_id in test_ids:
            path_test = re.sub(r'/\d+', f'/{test_id}', path, count=1)
            url_test  = url.replace(path, path_test, 1)
            r_test   = _request(client, method, url_test, headers)
            if not r_test:
                continue

            if (r_test.status_code in (200, 201) and len(r_test.text) > 50
                    and r_test.text != r_orig.text):
                # Responde con datos DISTINTOS para un ID de otro tenant → BOLA
                _add_finding(results, {
                    "phase":       "Greybox API",
                    "title":       f"Posible BOLA (acceso cross-tenant): {method} {path}",
                    "description": (
                        f"El endpoint {method} {url} responde con datos distintos a los "
                        f"del recurso original al sustituir el ID {original_id} por "
                        f"{test_id} (otro tenant potencial). "
                        f"HTTP {r_orig.status_code} ({len(r_orig.text)} bytes) → "
                        f"HTTP {r_test.status_code} ({len(r_test.text)} bytes). "
                        f"Requiere verificación manual para confirmar acceso no autorizado "
                        f"a recursos de otros tenants."
                    ),
                    "severity":    "HIGH",
                    "cvss":        8.1,
                    "remediation": (
                        f"Verificar que {path} valida que el ID solicitado pertenece "
                        f"al tenant autenticado. Implementar validación de ownership "
                        f"en cada operación sobre recursos."
                    ),
                    "confidence": "MEDIUM",
                    "escalation": "horizontal",
                    "evidence": {
                        "id_original": original_id,
                        "id_probado":  test_id,
                        "url_original": url,
                        "url_probada":  url_test,
                        "status_original": r_orig.status_code,
                        "status_probado":  r_test.status_code,
                        "bytes_original":  len(r_orig.text),
                        "bytes_probado":   len(r_test.text),
                    },
                })
                break  # Un finding por endpoint es suficiente
    except Exception:
        pass


def _check_mass_assignment(client, method, url, path, headers, results):
    """
    Mass Assignment: envía campos extra privilegiados en el body JSON.
    Si la respuesta REFLEJA LOS VALORES inyectados (no solo el nombre del
    campo) → posible vulnerabilidad.

    Importante: se comprueba el par campo=valor inyectado (p.ej. "role":"admin",
    "tenant_id":9999), no la mera presencia del nombre del campo en el body.
    Buscar solo el nombre ("role", "admin", "verified"...) genera falsos
    positivos casi garantizados, porque cualquier API que gestione roles,
    tenants o verificación de cuentas devuelve esos mismos nombres de campo
    en su comportamiento normal y correcto (p.ej. "role":"user",
    "verified":false) — eso no es mass assignment, es la respuesta esperada.
    """
    try:
        # Payload con campos que no deberían aceptarse.
        # Los valores se eligen para ser inequívocos si aparecen reflejados:
        # tenant_id=9999999 y role="reconcli_masstest" son marcadores muy
        # improbables en una respuesta legítima no relacionada con el test.
        marker_tenant = 9999999
        marker_role   = "reconcli_masstest"
        evil_payload = {
            "admin":     True,
            "role":      marker_role,
            "tenant_id": marker_tenant,
            "is_active": True,
            "verified":  True,
        }

        r_evil = client.request(
            method, url,
            json=evil_payload,
            headers={**headers, "Content-Type": "application/json"}
        )

        if r_evil.status_code not in (200, 201):
            return

        body = r_evil.text[:2000]

        # Patrones que comprueban el VALOR inyectado, no solo el nombre del campo.
        # Cubren variantes con/sin espacio tras los dos puntos y comillas simples/dobles.
        reflected_patterns = [
            (re.compile(r'"role"\s*:\s*"' + re.escape(marker_role) + r'"'),
             f"role={marker_role}"),
            (re.compile(r'"tenant_id"\s*:\s*"?' + str(marker_tenant) + r'"?'),
             f"tenant_id={marker_tenant}"),
            (re.compile(r'"admin"\s*:\s*true'),
             "admin=true"),
        ]

        reflected = [label for pattern, label in reflected_patterns if pattern.search(body)]

        if reflected:
            # role/admin reflejado = elevas TU propio privilegio (vertical).
            # Solo tenant_id reflejado, sin role/admin = te mueves a OTRO
            # tenant al mismo nivel de privilegio (horizontal), no una
            # elevación de rol en sí.
            is_vertical = any(r.startswith("role=") or r == "admin=true" for r in reflected)
            escalation = "vertical" if is_vertical else "horizontal"

            _add_finding(results, {
                "phase":       "Greybox API",
                "title":       f"Posible Mass Assignment: {method} {path}",
                "description": (
                    f"{method} {url} reflejó en la respuesta los valores privilegiados "
                    f"inyectados en el body ({', '.join(reflected)}), lo que indica que "
                    f"el servidor aceptó campos que un cliente no debería poder controlar. "
                    f"HTTP {r_evil.status_code}. Requiere verificación manual para confirmar "
                    f"que el valor quedó realmente persistido (y no solo reflejado en el eco "
                    f"de la respuesta)."
                ),
                "severity":    "HIGH",
                "cvss":        7.5,
                "remediation": (
                    "Implementar allowlist de campos aceptados en cada endpoint. "
                    "Ignorar o rechazar campos no esperados en el body de la petición."
                ),
                "confidence": "HIGH",
                "escalation": escalation,
            })
    except Exception:
        pass


# Palabras clave de path que sugieren una función de nivel superior
# (administración, gestión interna) — no es una lista exhaustiva, es una
# heurística de nomenclatura habitual en APIs reales.
ADMIN_PATH_KEYWORDS = (
    "/admin", "/administrator", "/internal", "/management", "/manage",
    "/staff", "/backoffice", "/back-office", "/superuser", "/root",
    "/ops", "/moderat", "/console", "/debug", "/system", "/_internal",
)


def _check_bfla(client, method, url, path, headers, results, intentionally_public=False):
    """
    BFLA (Broken Function Level Authorization) heurístico — comprueba si un
    endpoint cuyo path sugiere una función de nivel superior (admin,
    interno, gestión...) responde con éxito al token de prueba aportado.

    Limitación real, y por eso confidence Baja: no hay comparación entre un
    token normal y uno con privilegios elevados — solo disponemos del token
    que se aportó a la ejecución. Esto es un indicio por convención de
    nomenclatura del path, no una confirmación de escalada de privilegios
    real. Requiere verificación manual sabiendo qué rol tiene ese token.

    Si el endpoint es además público (intentionally_public), el hallazgo es
    más serio — ni siquiera hace falta un token para llegar a una función
    que suena a administrativa — y se marca con severidad mayor.
    """
    path_lower = path.lower()
    if not any(kw in path_lower for kw in ADMIN_PATH_KEYWORDS):
        return
    try:
        r = _request(client, method, url, headers)
        if not r or r.status_code not in (200, 201):
            return

        if intentionally_public:
            severity, cvss = "HIGH", 7.1
            access_note = (
                "El endpoint es además público (no requiere token) — cualquiera puede "
                "acceder a una función que por su nombre sugiere ser administrativa."
            )
        else:
            severity, cvss = "MEDIUM", 6.5
            access_note = (
                "Requiere verificación manual: confirma qué rol tiene el token empleado "
                "en esta auditoría — si es un usuario SIN privilegios elevados, esto "
                "sería una escalada de privilegios vertical real (BFLA)."
            )

        _add_finding(results, {
            "phase":       "Greybox API",
            "title":       f"Posible BFLA: función de nivel superior accesible: {method} {path}",
            "description": (
                f"{method} {url} responde HTTP {r.status_code}. El path sugiere una "
                f"función de administración/gestión interna (coincide con: "
                f"{', '.join(kw for kw in ADMIN_PATH_KEYWORDS if kw in path_lower)}). "
                f"{access_note}"
            ),
            "severity":    severity,
            "cvss":        cvss,
            "remediation": (
                "Verificar que este endpoint aplica control de autorización a nivel "
                "de función (Broken Function Level Authorization — OWASP API Security "
                "Top 10), no solo autenticación, restringido al rol correspondiente."
            ),
            "confidence":  "LOW",
            "escalation":  "vertical",
        })
    except Exception:
        pass


def _check_excessive_data(client, url, path, headers, results):
    """
    Excessive Data Exposure: la respuesta devuelve más datos de los necesarios.
    Busca campos sensibles que no deberían exponerse en APIs públicas.

    Se distinguen dos niveles:
    - CRITICAL_FIELDS: secretos reales (contraseñas, tokens, claves, datos de
      pago/identidad). Su presencia es un problema en casi cualquier contexto.
    - INFORMATIONAL_FIELDS: campos de rol/permisos (admin, is_staff...) que en
      muchas APIs son datos legítimos y esperados en la respuesta de un
      usuario autenticado sobre su propio perfil (p.ej. GET /me devolviendo
      "is_staff": false). Marcarlos igual que un password expuesto generaba
      MEDIUM en prácticamente cualquier API con roles, sin relación con un
      problema real. Se reportan aparte, en INFO, como nota a revisar.
    """
    CRITICAL_FIELDS = [
        "password", "passwd", "secret", "private_key", "access_token",
        "refresh_token", "ssn", "tax_id", "credit_card", "cvv",
    ]
    INFORMATIONAL_FIELDS = [
        "internal_id", "admin", "superuser", "is_staff",
    ]
    try:
        r = _request(client, "GET", url, headers)
        if not r or r.status_code not in (200, 201):
            return

        body_lower = r.text[:3000].lower()

        def _present(fields):
            return [f for f in fields
                    if f'"{f}"' in body_lower or f"'{f}'" in body_lower]

        found_critical = _present(CRITICAL_FIELDS)
        found_info     = _present(INFORMATIONAL_FIELDS)

        if found_critical:
            _add_finding(results, {
                "phase":       "Greybox API",
                "title":       f"Posible Excessive Data Exposure: GET {path}",
                "description": (
                    f"La respuesta de GET {url} contiene campos potencialmente "
                    f"sensibles: {', '.join(found_critical[:5])}. "
                    f"La API puede estar devolviendo más datos de los necesarios."
                ),
                "severity":    "MEDIUM",
                "cvss":        5.3,
                "remediation": (
                    "Revisar los campos devueltos por el endpoint y eliminar "
                    "los que no sean necesarios para el cliente. "
                    "Implementar proyección de campos (field filtering)."
                ),
                "confidence": "MEDIUM",
            })
        elif found_info:
            # Severidad informativa: son campos de rol/permiso que suelen ser
            # legítimos (el propio usuario viendo su nivel de acceso), pero se
            # documentan para que el equipo confirme que es intencionado.
            _add_finding(results, {
                "phase":       "Greybox API",
                "title":       f"Campos de rol/permisos en la respuesta: GET {path}",
                "description": (
                    f"La respuesta de GET {url} incluye campos de rol o "
                    f"permisos ({', '.join(found_info[:5])}). Es un patrón "
                    f"habitual y legítimo cuando el usuario consulta su propio "
                    f"perfil; se documenta para confirmar que ningún endpoint "
                    f"los expone sobre recursos de OTROS usuarios."
                ),
                "severity":    "INFO",
                "cvss":        0.0,
                "remediation": (
                    "Confirmar que estos campos solo se devuelven cuando el "
                    "recurso consultado pertenece al usuario autenticado."
                ),
                "confidence": "LOW",
            })
    except Exception:
        pass


# ── Utilidades ────────────────────────────────────────────────

def _request(client: httpx.Client, method: str, url: str, headers: dict):
    """Ejecuta un request HTTP con manejo de errores."""
    try:
        return client.request(method, url, headers=headers)
    except Exception:
        return None


def _auth_headers(token: str) -> dict:
    headers = {"User-Agent": "recon-cli/1.2 security-scanner"}
    if token:
        if not token.startswith("Bearer "):
            token = f"Bearer {token}"
        headers["Authorization"] = token
    return headers


def _add_finding(results: dict, finding: dict):
    """Añade un finding evitando duplicados por título."""
    existing_titles = {f["title"] for f in results["findings"]}
    if finding["title"] not in existing_titles:
        results["findings"].append(finding)
