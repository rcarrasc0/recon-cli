#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  recon-cli · modules/oauth_audit.py  v1.2.0
#
#  Auditoría de flujos OAuth2 / OpenID Connect (submodo SSO / OAuth2).
#  Extraído de greybox.py — mismo criterio que api_audit.py /
#  api_discovery.py: greybox.py solo orquesta menú, credenciales y
#  presentación; la lógica de auditoría real vive en su propio módulo.
#
#  Checks:
#    - Endpoint OAuth2 accesible por HTTP sin TLS
#    - Token endpoint acepta refresh_token inválido
#    - Token expirado (aviso operativo — ver nota en _check_expired_token)
#    - Logout / Revocación (informativos, best-effort)
#    - Open redirect en redirect_uri
#
#  Revisión v1.2.0 — 4 correcciones respecto a la versión original
#  (vivía dentro de greybox.py):
#    1. _check_http_token_endpoint: la condición de disparo no filtraba
#       nada — cualquier respuesta HTTP (incluido un redirect 301/302 a
#       HTTPS, comportamiento CORRECTO) generaba HIGH. Ahora se exige
#       que no redirija a https:// y que el cuerpo parezca realmente
#       un endpoint OAuth2/OIDC.
#    2. _check_expired_token: generaba un finding contra EL SERVIDOR
#       decodificando el token que el propio operador proporcionó — si
#       ese token ya estaba caducado (p.ej. copiado de una sesión
#       anterior), el hallazgo era falso. Ahora es un aviso operativo,
#       no un finding.
#    3. _check_revocation: usaba GET con el token en query string.
#       RFC 7009 especifica POST con el token en el body — con GET,
#       un servidor bien implementado puede devolver 404/405 y el
#       check no lo interpreta correctamente. Cambiado a POST. Se
#       retira el finding LOW basado en HTTP 400, evidencia
#       insuficiente para atribuir un fallo real.
#    4. _check_open_redirect: usaba client_id="test" inventado — un
#       servidor bien implementado rechaza client_id desconocidos
#       antes de validar redirect_uri, dando pruebas poco concluyentes.
#       Ahora reutiliza el client_id real de greybox si está disponible.
# ─────────────────────────────────────────────────────────────

from __future__ import annotations

import re
import httpx
from rich.console import Console

console = Console()


def _bearer_headers(token: str) -> dict:
    headers = {"User-Agent": "recon-cli/1.2 security-scanner"}
    if token:
        headers["Authorization"] = token if token.startswith("Bearer ") else f"Bearer {token}"
    return headers


def _verify_sso_token(client: httpx.Client, userinfo_endpoint: str, token: str) -> dict:
    """
    Verifica si el token SSO es válido llamando al userinfo_endpoint
    (OIDC Core 1.0 §5.3) — mismo criterio y misma forma de resultado que
    verify_token() en api_discovery.py para el submodo API, pero aquí
    usando el endpoint estándar pensado exactamente para esto, en vez de
    heurísticas sobre rutas genéricas (/health, /api...).

    HTTP 200            → token válido, aceptado por el servidor.
    HTTP 401 / 403       → token rechazado (inválido, caducado o revocado).
    Cualquier otra cosa  → no concluyente (p.ej. WAF, timeout, endpoint
                           que no responde como se espera).
    """
    if not token or not userinfo_endpoint:
        return {"valid": None, "reason": "sin_token_o_endpoint"}

    try:
        r = client.get(userinfo_endpoint, headers=_bearer_headers(token))
        if r.status_code == 200:
            return {"valid": True, "reason": "200_userinfo", "url": userinfo_endpoint,
                     "code": r.status_code}
        if r.status_code in (401, 403):
            return {"valid": False, "reason": "rechazado", "url": userinfo_endpoint,
                     "code": r.status_code}
        return {"valid": None, "reason": "no_concluyente", "url": userinfo_endpoint,
                 "code": r.status_code}
    except Exception as e:
        return {"valid": None, "reason": "error", "message": str(e)}

# Paths OAuth2/OIDC estándar — única fuente de verdad, usada tanto para
# el discovery de este módulo (GET) como para el autodiscovery del token
# endpoint en greybox.py (POST). Antes eran dos listas mantenidas por
# separado con solapamiento parcial.
OAUTH_ENDPOINT_PATHS = [
    "/o/oauth2/token", "/o/oauth2/auth",
    "/oauth/token", "/oauth2/token",
    "/oauth/authorize", "/oauth2/authorize",
    "/.well-known/openid-configuration",
    "/auth/token", "/auth/realms",
    "/api/token", "/connect/token",
    "/realms/master/protocol/openid-connect/token",
]


# ── Matriz de cobertura de pruebas ─────────────────────────────
# Registra qué se comprobó y con qué resultado, aunque no haya hallazgos —
# un informe que solo lista hallazgos no distingue "no lo hemos mirado" de
# "lo hemos mirado y está bien".
COVERAGE_DEFS_SSO = {
    "http_exposure":       ("Endpoint accesible por HTTP (sin TLS)",        "Sin sesión"),
    "invalid_token":       ("Token endpoint acepta refresh_token inválido", "Con sesión"),
    "token_validation":    ("Validación activa del token contra el servidor (userinfo)", "Con sesión"),
    "expired_token":       ("Verificación de expiración de token (local, informativo)", "Con sesión"),
    "logout":              ("Detección de endpoint de logout",             "Con sesión"),
    "revocation":          ("Detección de endpoint de revocación",         "Con sesión"),
    "open_redirect":       ("Open redirect en redirect_uri",               "Sin sesión"),
    "bot_protection":      ("Protección anti-automatización (CAPTCHA)",    "Sin sesión"),
    "token_invalidation":  ("Invalidación de token tras logout/revocación","Con sesión"),
}


def _cov_init_sso(results: dict):
    results["coverage"] = {
        key: {"label": label, "session": session, "tested": 0, "findings": 0, "detail": ""}
        for key, (label, session) in COVERAGE_DEFS_SSO.items()
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


def run_sso_audit(target: str, config: dict) -> dict:
    """
    Punto de entrada del audit SSO/OAuth2 — mismo patrón que
    run_audit(discovery, config) en api_audit.py.
    """
    global console
    console = config.get("console") or console

    console.print("\n[bold magenta]━━━ Greybox SSO — Auditoría OAuth2/OIDC[/bold magenta]")

    token     = config.get("greybox_sso_token", "")
    client_id = config.get("greybox_sso_client_id", "")
    timeout   = config.get("REQUEST_TIMEOUT", 10)
    base_url  = f"https://{target}"

    results = {"findings": []}
    _cov_init_sso(results)

    # ── Discovery de metadata OAuth2/OIDC (primero de todo) ─────
    # FIX (v1.2.1): antes la "Verificación de token" corría aquí mismo,
    # antes del discovery, pero solo hacía un decode local del JWT
    # (_check_expired_token) — nunca comprobaba contra el servidor si el
    # token era realmente válido. Para poder validarlo de verdad hace
    # falta primero conocer el userinfo_endpoint, así que el discovery de
    # metadata pasa a ir primero. Sigue siendo "antes de lanzar ningún
    # check de seguridad" — solo se adelanta el propio descubrimiento.
    # Decode local del JWT — no depende de la red ni del discovery, así
    # que corre siempre que haya token, incluso si el discovery de abajo
    # no encuentra nada (antes quedaba huérfano detrás de un return
    # temprano en ese caso).
    if token:
        results["coverage"]["expired_token"]["tested"] += 1
        _check_expired_token(token, results)

    discovery = _discover_oauth_endpoints(base_url, timeout)

    if not discovery["all"]:
        console.print(
            f"  [yellow]![/yellow] No se detectaron endpoints OAuth2 en {base_url}\n"
            "  [dim]Asegúrate de que el target es el servidor de autenticación[/dim]"
        )
        return results

    source_label = {
        "metadata": "metadata estándar (OIDC discovery / RFC 8414)",
        "wordlist": "rutas conocidas",
        "crawl":    "rastreo de pistas léxicas (sin metadata ni rutas convencionales)",
    }.get(discovery["source"], "desconocida")

    console.print(
        f"  [green]✓[/green] {len(discovery['all'])} endpoint(s) OAuth2 detectados "
        f"— fuente: {source_label}"
    )
    if discovery["source"] == "crawl":
        console.print(
            "  [yellow]![/yellow] Entorno sin metadata de discovery ni rutas convencionales — "
            "cobertura de este submodo puede ser parcial. Revisa manualmente."
        )

    # ── Verificación de token (antes de lanzar los checks) ──────
    # Mismo criterio que el submodo API (verify_token() en
    # api_discovery.py, previo al Security Audit): confirmar visiblemente
    # si el token funciona ANTES de gastar peticiones asumiendo que sí.
    #
    # NUEVO — validación activa contra userinfo_endpoint (OIDC Core §5.3):
    # es el endpoint estándar hecho exactamente para esto. Si el servidor
    # no publica userinfo_endpoint, se avisa explícitamente de que no hay
    # validación activa posible y solo queda el decode local de arriba.
    token_verified_sso = None
    if token:
        console.print("\n[bold magenta]━━━ Greybox SSO — Verificación de token[/bold magenta]")

        userinfo_endpoint = discovery.get("userinfo_endpoint")
        results["coverage"]["token_validation"]["tested"] += 1
        if userinfo_endpoint:
            with httpx.Client(timeout=timeout, verify=False, follow_redirects=False) as _vclient:
                vresult = _verify_sso_token(_vclient, userinfo_endpoint, token)
            if vresult["valid"] is True:
                token_verified_sso = True
                console.print(
                    f"  [green]✓[/green] Token SSO válido "
                    f"[dim](HTTP {vresult.get('code')} en {vresult.get('url')})[/dim]"
                )
                results["coverage"]["token_validation"]["detail"] = (
                    f"✓ Token válido — HTTP {vresult.get('code')} en userinfo_endpoint"
                )
            elif vresult["valid"] is False:
                token_verified_sso = False
                console.print(
                    f"  [bold red]✗ Token SSO rechazado por el servidor[/bold red] "
                    f"[dim](HTTP {vresult.get('code')} en {vresult.get('url')})[/dim] — "
                    f"revisa las credenciales antes de interpretar el resto de resultados."
                )
                results["coverage"]["token_validation"]["detail"] = (
                    f"✗ Token rechazado — HTTP {vresult.get('code')} en userinfo_endpoint"
                )
            else:
                console.print(
                    f"  [yellow]![/yellow] No se pudo confirmar la validez del token "
                    f"({vresult.get('reason', '?')}) — se continúa, pero interpreta los "
                    f"resultados con cautela."
                )
                results["coverage"]["token_validation"]["detail"] = (
                    f"No concluyente ({vresult.get('reason', '?')})"
                )
        else:
            console.print(
                "  [yellow]![/yellow] El servidor no publica userinfo_endpoint — "
                "no es posible validar el token activamente contra el servidor. "
                "Solo se dispone del decode local del JWT (arriba)."
            )
            results["coverage"]["token_validation"]["detail"] = (
                "No ejecutado — el servidor no publica userinfo_endpoint"
            )

    with httpx.Client(timeout=timeout, verify=False, follow_redirects=False) as client:

        for ep in discovery["all"]:
            # Check 1 — Accesible por HTTP (sin TLS)
            before = len(results["findings"])
            _check_http_token_endpoint(client, ep, timeout, results)
            _cov_run(results, "http_exposure", before)

            # Check 2 — Token inválido aceptado en token endpoint
            before = len(results["findings"])
            _check_invalid_token_acceptance(client, ep, results)
            _cov_run(results, "invalid_token", before)

        # Check 3 — Token expirado: ya verificado al principio de la función
        # (antes de gastar peticiones contra un token potencialmente caducado)

        # Verificación de invalidación de token tras logout/revocación. Sin
        # un endpoint de datos real, los checks 4/5 de abajo solo confirman
        # que logout/revocación EXISTEN, no que invalidan el token de
        # verdad — que es lo que importa ante un token robado/filtrado.
        # FIX (v1.2.1): antes solo había endpoint de datos disponible en
        # submodo 3 (Ambos), vía el candidato del API audit. Con
        # userinfo_endpoint ya descubierto arriba, se usa como endpoint de
        # datos por defecto cuando no hay uno del API audit — esto activa
        # el check también en submodo 2 (SSO solo).
        data_endpoint = config.get("_greybox_data_endpoint") or discovery.get("userinfo_endpoint")
        data_endpoint_source = (
            "api_audit" if config.get("_greybox_data_endpoint")
            else ("userinfo" if discovery.get("userinfo_endpoint") else None)
        )

        token_worked_before = False
        r_before_status = None
        if token and data_endpoint:
            if data_endpoint_source == "userinfo":
                # Reutiliza el resultado de la verificación activa de
                # arriba en vez de repetir la misma petición — solo es
                # fiable si esa verificación efectivamente concluyó válido.
                token_worked_before = bool(token_verified_sso)
                r_before_status = 200 if token_verified_sso else None
            else:
                try:
                    r_before = client.get(data_endpoint, headers=_bearer_headers(token))
                    r_before_status = r_before.status_code
                    token_worked_before = r_before.status_code in (200, 201)
                except Exception:
                    pass

        # Check 4 — Logout programático (informativo)
        if token:
            results["coverage"]["logout"]["tested"] += 1
            detected = _check_logout(client, base_url, token, results)
            results["coverage"]["logout"]["detail"] = (
                "Endpoint detectado" if detected else "No detectado"
            )

        # Check 5 — Revocación (informativo, prueba GET y POST)
        if token:
            results["coverage"]["revocation"]["tested"] += 1
            detected = _check_revocation(client, base_url, token, results)
            results["coverage"]["revocation"]["detail"] = (
                "Endpoint detectado" if detected else "No detectado"
            )

        # Check — Invalidación real de token tras logout/revocación
        source_note = {
            "api_audit": " (endpoint descubierto durante el API audit)",
        }.get(data_endpoint_source, "")

        if not (token and data_endpoint):
            results["coverage"]["token_invalidation"]["detail"] = (
                "No ejecutado — requiere submodo 3 (Ambos) con un endpoint de "
                "datos descubierto durante el API audit"
            )
        elif not token_worked_before:
            results["coverage"]["token_invalidation"]["detail"] = (
                f"No ejecutado — el token no funcionaba contra {data_endpoint}{source_note} "
                f"antes de logout/revocación, no se puede concluir nada con certeza"
            )
        else:
            results["coverage"]["token_invalidation"]["tested"] += 1
            try:
                r_after = client.get(data_endpoint, headers=_bearer_headers(token))
                if r_after.status_code in (200, 201):
                    _add_finding(results, {
                        "phase":       "Greybox SSO",
                        "title":       f"El token sigue siendo válido tras logout/revocación: {data_endpoint}",
                        "description": (
                            f"El token usado en esta auditoría funcionaba contra "
                            f"{data_endpoint}{source_note} (HTTP {r_before_status}) antes de "
                            f"ejecutar logout/revocación, y sigue funcionando (HTTP "
                            f"{r_after.status_code}) después. Un token robado o filtrado "
                            f"seguiría siendo utilizable aunque el usuario cierre sesión "
                            f"o el token se revoque explícitamente."
                        ),
                        "severity":    "HIGH",
                        "cvss":        7.5,
                        "remediation": (
                            "Verificar que el logout/revocación invalida realmente el "
                            "token en el servidor (lista de revocación, blacklist de JTI, "
                            "o tokens de corta duración con refresh controlado), no solo "
                            "que el endpoint de logout/revoke responde 200."
                        ),
                        "confidence": "MEDIUM",
                    })
                    results["coverage"]["token_invalidation"]["findings"] += 1
                else:
                    results["coverage"]["token_invalidation"]["detail"] = (
                        f"Token correctamente invalidado (HTTP {r_after.status_code} "
                        f"tras logout/revocación)"
                    )
            except Exception:
                pass

        # Check 6 — Open redirect en OAuth (redirect_uri manipulation).
        # Si el discovery de nivel 1/3 identificó una authorization_endpoint
        # real (no adivinada por wordlist), se prueba también explícitamente
        # — cubre entornos con rutas no convencionales que sí exponen su
        # propia authorization_endpoint por metadata o por pista de crawl.
        before = len(results["findings"])
        _check_open_redirect(client, base_url, client_id, results,
                             extra_path=discovery.get("authorization_endpoint"))
        _cov_run(results, "open_redirect", before)

        # Check 7 — Protección anti-automatización (CAPTCHA) en el login.
        # No es un check de vulnerabilidad en sí — documenta si el control
        # sigue activo. Útil porque estas protecciones a veces se desactivan
        # temporalmente para pruebas de carga/rendimiento y pueden quedar
        # así por descuido.
        #
        # FIX: el fallback anterior comprobaba "auth" in u.lower() — pero
        # "oauth2" CONTIENE "auth" como substring (o-AUTH-2), así que
        # cualquier URL con "oauth2" en el path (incluido el propio token
        # endpoint) se colaba como si fuera la pantalla de login. Enviar
        # este check contra un token endpoint (que devuelve JSON, no HTML)
        # daría un "no se detectó CAPTCHA" sin sentido — no porque falte
        # protección, sino porque se miró la URL equivocada. Ahora se exige
        # "/auth" como segmento de path real (con la barra delante) y se
        # excluyen explícitamente rutas que claramente no son de login.
        def _looks_like_login_url(u: str) -> bool:
            u = u.lower()
            if any(seg in u for seg in ("/token", "/revoke", "/logout", "/introspect")):
                return False
            return "/auth" in u  # cubre /auth, /authorize, /oauth2/auth...

        auth_ep = discovery.get("authorization_endpoint") or next(
            (u for u in discovery["all"] if _looks_like_login_url(u)), None
        )
        if auth_ep:
            before = len(results["findings"])
            _check_bot_protection(client, auth_ep, client_id, results)
            _cov_run(results, "bot_protection", before)
        else:
            results["coverage"]["bot_protection"]["detail"] = (
                "No ejecutado — sin URL de login fiable en el discovery"
            )

    console.print(
        f"  [green]✓[/green] SSO audit completado — "
        f"{len(results['findings'])} hallazgo(s)"
    )
    return results


def _fetch_discovery_metadata(client: httpx.Client, base_url: str) -> dict | None:
    """
    Nivel 1 de discovery — el más fiable. Prueba los dos formatos estándar
    de metadata de configuración: OIDC Discovery y RFC 8414 (OAuth 2.0
    Authorization Server Metadata). Si el servidor la publica, da los
    endpoints EXACTOS que él mismo declara — funciona incluso si usa rutas
    completamente no convencionales, siempre que siga el estándar de
    publicar su propia configuración.
    """
    for path in ("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"):
        url = f"{base_url.rstrip('/')}{path}"
        try:
            r = client.get(url)
            if r.status_code != 200:
                continue
            data = r.json()
            if "token_endpoint" in data or "authorization_endpoint" in data:
                return data
        except Exception:
            continue
    return None


def _crawl_for_oauth_hints(client: httpx.Client, base_url: str,
                            max_depth: int = 2, max_pages: int = 20) -> list:
    """
    Nivel 3 de discovery — último recurso, para entornos sin metadata
    estándar ni rutas convencionales. Rastrea varios niveles de
    profundidad a partir de la home (no solo la propia home), buscando
    en cada página enlaces y formularios (href/action/src) con pistas
    léxicas de OAuth2/OIDC — típico en portales donde el acceso vive
    detrás de un enlace "Acceder" / "Iniciar sesión" en una página
    intermedia, no en la home directamente.

    Límites deliberados (esto sigue sin ser el spider completo de
    api_discovery.py, es una red de seguridad, no un reemplazo):
      - max_depth: cuántos saltos desde la home (por defecto 2)
      - max_pages: techo total de páginas descargadas (por defecto 20)
      - Solo sigue enlaces del MISMO dominio — nunca sale a terceros
      - Ignora esquemas no HTTP (mailto:, javascript:, tel:, etc.)

    Los resultados son heurísticos: pueden incluir falsos positivos
    (p.ej. un enlace a un artículo que mencione "oauth" en la URL) —
    se avisa en consola para revisar a mano.
    """
    from urllib.parse import urljoin, urlparse, urlunparse

    keywords = ("oauth", "authorize", "openid", "/sso", "connect/token",
                "login", "signin", "iniciar-sesion", "acceso")

    base_domain = urlparse(base_url).netloc
    visited     = set()
    to_visit    = [(base_url, 0)]
    hints       = set()
    pages_done  = 0

    while to_visit and pages_done < max_pages:
        url, depth = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            r = client.get(url)
            pages_done += 1
            if r.status_code != 200:
                continue

            for m in re.findall(r'(?:href|action|src)=["\']([^"\']+)["\']', r.text):
                full = urljoin(url, m)
                parsed = urlparse(full)

                if parsed.scheme not in ("http", "https") or parsed.netloc != base_domain:
                    continue  # fuera de dominio o esquema no navegable (mailto:, javascript:...)

                full_clean = urlunparse(parsed._replace(fragment=""))

                if any(kw in full_clean.lower() for kw in keywords):
                    hints.add(full_clean)

                if depth < max_depth and full_clean not in visited:
                    to_visit.append((full_clean, depth + 1))

        except Exception:
            continue

    return list(hints)


def _discover_oauth_endpoints(base_url: str, timeout: int) -> dict:
    """
    Descubre endpoints OAuth2/OIDC en tres niveles de fiabilidad decreciente:

      1. Metadata estándar (OIDC discovery / RFC 8414) — endpoints EXACTOS
         declarados por el propio servidor. Cubre servidores con rutas no
         convencionales que sí sigan el estándar de publicar su config.
      2. Wordlist de rutas conocidas (OAUTH_ENDPOINT_PATHS) — para
         servidores que no publican metadata pero usan convenciones
         habituales (Keycloak, Auth0, Okta...).
      3. Crawl ligero de pistas léxicas en la home — última red de
         seguridad para entornos que no siguen ni estándares de discovery
         ni convenciones de rutas.

    Se detiene en el primer nivel que dé resultado — no se combinan (un
    servidor que publica metadata estándar no necesita que además le
    adivinemos rutas).
    """
    result = {
        "all":                     [],
        "token_endpoint":          None,
        "authorization_endpoint":  None,
        "userinfo_endpoint":       None,
        "source":                  None,
    }
    headers = {"User-Agent": "recon-cli/1.2 security-scanner"}

    try:
        with httpx.Client(timeout=timeout, verify=False, follow_redirects=False, headers=headers) as client:

            # Nivel 1 — metadata estándar
            metadata = _fetch_discovery_metadata(client, base_url)
            if metadata:
                result["token_endpoint"]         = metadata.get("token_endpoint")
                result["authorization_endpoint"] = metadata.get("authorization_endpoint")
                # userinfo_endpoint (estándar OIDC Core 1.0 §5.3) — único
                # endpoint pensado exactamente para esto: dado un access
                # token, confirmar si el servidor lo considera válido.
                # Se guarda aparte de "all" (que son endpoints a auditar,
                # no a autenticar) para usarlo en _verify_sso_token.
                result["userinfo_endpoint"]      = metadata.get("userinfo_endpoint")
                result["all"] = [u for u in (
                    metadata.get("token_endpoint"),
                    metadata.get("authorization_endpoint"),
                    metadata.get("revocation_endpoint"),
                    metadata.get("end_session_endpoint"),
                    metadata.get("introspection_endpoint"),
                ) if u]
                if result["all"]:
                    result["source"] = "metadata"
                    return result

            # Nivel 2 — wordlist de rutas conocidas
            found = []
            for path in OAUTH_ENDPOINT_PATHS:
                url = f"{base_url.rstrip('/')}{path}"
                try:
                    r = client.get(url)
                    if r.status_code in (200, 400, 401, 405):
                        found.append(url)
                except Exception:
                    continue
            if found:
                result["all"] = found
                result["source"] = "wordlist"
                return result

            # Nivel 3 — crawl ligero de pistas léxicas
            hints = _crawl_for_oauth_hints(client, base_url)
            if hints:
                result["all"] = hints
                result["source"] = "crawl"
            return result

    except Exception:
        return result


def _check_http_token_endpoint(client: httpx.Client, endpoint: str, timeout: int, results: dict):
    """
    Comprueba si el token endpoint es accesible por HTTP sin TLS.

    FIX: la versión anterior disparaba con cualquier respuesta HTTP,
    incluido un redirect 301/302 a HTTPS — que es precisamente el
    comportamiento CORRECTO. Ahora exige:
      1. Que la respuesta NO sea un redirect hacia https://
      2. Que el cuerpo contenga alguna señal real de ser un endpoint
         OAuth2/OIDC (no una página de error genérica del servidor).
    """
    http_url = endpoint.replace("https://", "http://")
    if http_url == endpoint:
        return  # ya era HTTP

    try:
        r = client.get(http_url)

        location = r.headers.get("location", "")
        if location.startswith("https://"):
            # El servidor SÍ fuerza HTTPS — comportamiento correcto, no es hallazgo.
            return

        body = r.text[:500].lower()
        looks_like_oauth = any(
            marker in body for marker in (
                "access_token", "token_type", "invalid_client", "invalid_grant",
                "invalid_request", "unauthorized_client", "oauth", "openid",
            )
        )

        if r.status_code in (200, 400, 401) and looks_like_oauth:
            _add_finding(results, {
                "phase":       "Greybox SSO",
                "title":       f"Endpoint OAuth2 accesible por HTTP: {http_url}",
                "description": (
                    f"El endpoint de autenticación {http_url} responde por HTTP sin TLS "
                    f"(HTTP {r.status_code}) sin redirigir a HTTPS, y el contenido de la "
                    f"respuesta corresponde a un endpoint OAuth2/OIDC real. "
                    f"Los tokens pueden transmitirse en claro."
                ),
                "severity":    "HIGH",
                "cvss":        7.4,
                "remediation": "Forzar HTTPS en todos los endpoints OAuth2. Rechazar conexiones HTTP.",
                "confidence":  "MEDIUM",
            })
    except Exception:
        pass


def _check_invalid_token_acceptance(client: httpx.Client, endpoint: str, results: dict):
    """
    Envía un refresh_token inválido al token endpoint y verifica la respuesta.

    FIX: la versión anterior disparaba CRITICAL con solo ver HTTP 200,
    sin comprobar el cuerpo de la respuesta. Esto genera un falso positivo
    real contra servidores (frecuentes detrás de API gateways tipo Azure
    Application Gateway) que devuelven SIEMPRE HTTP 200 y comunican el
    error dentro del JSON (`{"error": "invalid_grant"}`) en vez de usar
    400/401 como especifica RFC 6749 — el servidor rechaza el token
    perfectamente bien, solo que con un código de estado poco ortodoxo.

    Ahora se distinguen tres casos:
      1. HTTP 200 + access_token real en el body → vulnerable de verdad (CRITICAL)
      2. HTTP 200 + campo de error en el body → rechazó bien, pero no usa
         códigos HTTP estándar (nota de estilo, LOW — no es una vulnerabilidad)
      3. HTTP 200 + cuerpo ambiguo (ni token ni error reconocible) → no se
         puede concluir con certeza, se marca para revisión manual (MEDIUM,
         confidence Baja)
    """
    try:
        r = client.post(
            endpoint,
            data={
                "grant_type":    "refresh_token",
                "refresh_token": "invalid_token_recon_test",
                "client_id":     "test",
                "client_secret": "test",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        if r.status_code != 200:
            return  # comportamiento correcto esperado (400/401/etc.)

        try:
            body = r.json()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}

        access_token = body.get("access_token")
        has_real_token = isinstance(access_token, str) and len(access_token) > 20
        has_error_field = any(k in body for k in ("error", "error_description"))

        if has_real_token:
            _add_finding(results, {
                "phase":       "Greybox SSO",
                "title":       f"Token endpoint acepta refresh_token inválido: {endpoint}",
                "description": (
                    f"{endpoint} devuelve HTTP 200 con un access_token real en el cuerpo, "
                    f"a partir de un refresh_token claramente inválido. "
                    f"La validación de tokens puede estar deshabilitada."
                ),
                "severity":    "CRITICAL",
                "cvss":        9.1,
                "remediation": "Verificar la validación de tokens en el servidor OAuth2.",
                "confidence":  "HIGH",
            })
        elif has_error_field:
            _add_finding(results, {
                "phase":       "Greybox SSO",
                "title":       f"Token endpoint usa HTTP 200 para respuestas de error: {endpoint}",
                "description": (
                    f"{endpoint} rechaza correctamente el refresh_token inválido (el cuerpo "
                    f"contiene un campo de error: {', '.join(k for k in ('error','error_description') if k in body)}), "
                    f"pero devuelve HTTP 200 en vez de 400/401 como especifica RFC 6749. "
                    f"No es una vulnerabilidad — es una desviación del estándar que puede "
                    f"confundir a clientes que solo miran el código de estado."
                ),
                "severity":    "LOW",
                "cvss":        3.1,
                "remediation": (
                    "Devolver HTTP 400 (invalid_grant) o 401 en vez de 200 para errores "
                    "de token, conforme a RFC 6749 §5.2."
                ),
                "confidence":  "MEDIUM",
            })
        else:
            _add_finding(results, {
                "phase":       "Greybox SSO",
                "title":       f"Token endpoint responde 200 sin access_token ni error reconocible: {endpoint}",
                "description": (
                    f"{endpoint} devuelve HTTP 200 ante un refresh_token inválido, pero el "
                    f"cuerpo de la respuesta no contiene ni un access_token reconocible ni "
                    f"un campo de error estándar. No se puede concluir automáticamente si "
                    f"el token fue aceptado o rechazado — requiere inspección manual del "
                    f"cuerpo completo de la respuesta."
                ),
                "severity":    "MEDIUM",
                "cvss":        5.3,
                "remediation": "Inspeccionar manualmente el cuerpo de la respuesta para confirmar el comportamiento real.",
                "confidence":  "LOW",
            })
    except Exception:
        pass


def _check_expired_token(token: str, results: dict) -> bool:
    """
    FIX: la versión anterior generaba un finding HIGH contra EL SERVIDOR
    a partir de decodificar el token que el propio operador proporcionó.
    Si ese token ya estaba caducado por cualquier motivo ajeno al servidor
    (copiado de una sesión anterior, TTL corto entre obtención y ejecución
    del escaneo), el hallazgo era falso: no demuestra que el servidor
    ACEPTE tokens expirados, solo que el token que le disteis ya lo estaba.

    No podemos generar un token expirado real sin control del servidor
    (docstring original, sigue siendo cierto) — así que esto se queda
    como aviso operativo al operador, nunca como finding contra el target.

    Feedback simétrico: avisa tanto si está caducado (con cuánto tiempo)
    como si es válido (con cuánto le queda) — antes solo avisaba en el
    caso malo, y en el bueno quedaba en silencio sin confirmar nada.

    Devuelve True si el token está caducado (para poder avisar también
    con un panel destacado al principio de la ejecución).
    """
    try:
        import base64, json as _json, time

        raw = token[7:] if token.startswith("Bearer ") else token
        parts = raw.split(".")
        if len(parts) != 3:
            console.print(
                "  [dim]Token no es un JWT decodificable — no se puede verificar "
                "caducidad localmente (puede ser un token opaco, válido igualmente).[/dim]"
            )
            return False

        payload = parts[1]
        payload += "=" * (4 - len(payload) % 4)
        decoded = _json.loads(base64.b64decode(payload))
        exp = decoded.get("exp")

        if not exp:
            console.print(
                "  [dim]El token no incluye campo 'exp' — no se puede verificar caducidad.[/dim]"
            )
            return False

        remaining = exp - time.time()
        if remaining < 0:
            mins_ago = abs(remaining) // 60
            console.print(
                f"  [bold red]⚠ El token proporcionado ya está expirado[/bold red] "
                f"(caducó hace ~{int(mins_ago)} min) — los checks que dependen de un "
                f"token válido pueden dar resultados poco fiables. Considera obtener "
                f"un token fresco antes de continuar."
            )
            return True
        else:
            mins_left = remaining // 60
            console.print(
                f"  [green]✓[/green] Token válido — caduca en ~{int(mins_left)} min"
            )
            return False
    except Exception:
        console.print("  [dim]No se pudo verificar la caducidad del token.[/dim]")
        return False


def _check_logout(client: httpx.Client, base_url: str, token: str, results: dict) -> bool:
    """
    Detecta el endpoint de logout, si existe.
    Informativo: verificar que el token deja de funcionar tras logout
    requeriría un endpoint de datos autenticado — no disponible aquí sin
    acoplar este módulo al discovery de api_discovery.py. Queda pendiente
    para v1.2.x si se decide integrar ambos submodos.
    Devuelve True si se detectó el endpoint (para la matriz de cobertura).
    """
    logout_paths = ["/o/oauth2/logout", "/oauth/logout", "/auth/logout", "/logout"]
    for path in logout_paths:
        url = f"{base_url.rstrip('/')}{path}"
        try:
            r = client.get(f"{url}?token={token}")
            if r.status_code in (200, 302):
                console.print(f"  [dim]Logout endpoint detectado: {url} (HTTP {r.status_code})[/dim]")
                return True
        except Exception:
            continue
    return False


def _check_revocation(client: httpx.Client, base_url: str, token: str, results: dict) -> bool:
    """
    Verifica la existencia del endpoint de revocación.

    Prueba dos formatos, porque en la práctica coexisten ambos en servidores
    reales:
      1. GET con el token en query string (?token=...) — formato que usan
         de facto algunos IdP reales en producción (revocación vía GET),
         aunque no sea estrictamente RFC 7009.
      2. POST con el token en el body — formato que sí especifica RFC 7009.

    Antes este check solo probaba POST (por seguir RFC 7009 a rajatabla),
    lo que hacía que fallara en silencio contra servidores que usan GET —
    no porque el servidor esté mal, sino porque el check no hablaba su
    protocolo real.

    No se genera un finding por el simple hecho de que el endpoint responda
    con 400: no es evidencia suficiente de un fallo real (puede ser
    simplemente una petición mal formada por nuestra parte, p.ej. sin
    client_id). Queda como comprobación informativa de existencia.
    """
    revoke_paths = ["/o/oauth2/revoke", "/oauth/revoke", "/oauth2/revoke"]
    for path in revoke_paths:
        url = f"{base_url.rstrip('/')}{path}"

        try:
            r = client.get(url, params={"token": token})
            if r.status_code in (200, 400, 401):
                console.print(f"  [dim]Endpoint de revocación detectado (GET): {url} (HTTP {r.status_code})[/dim]")
                return True
        except Exception:
            pass

        try:
            r = client.post(
                url,
                data={"token": token},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if r.status_code in (200, 400, 401):
                console.print(f"  [dim]Endpoint de revocación detectado (POST): {url} (HTTP {r.status_code})[/dim]")
                return True
        except Exception:
            continue
    return False


def _check_open_redirect(client: httpx.Client, base_url: str, client_id: str, results: dict,
                         extra_path: str | None = None):
    """
    Comprueba open redirect en el parámetro redirect_uri del flujo OAuth2.
    Un servidor correcto rechaza redirect_uri no registradas.

    FIX: la versión anterior usaba client_id="test" inventado. Un servidor
    bien implementado rechaza client_id desconocidos ANTES de validar
    redirect_uri, así que la prueba casi nunca era concluyente (ni en
    positivo ni en negativo). Ahora reutiliza el client_id real configurado
    en greybox (GREYBOX_CLIENT_ID), si está disponible, para que el
    servidor sí llegue a evaluar el redirect_uri.

    extra_path: URL completa de authorization_endpoint si el discovery la
    identificó por metadata estándar o crawl — cubre entornos con rutas no
    convencionales que no están en la wordlist fija de abajo.
    """
    auth_paths = ["/o/oauth2/auth", "/oauth/authorize", "/oauth2/authorize", "/auth"]
    targets = [f"{base_url.rstrip('/')}{p}" for p in auth_paths]
    if extra_path and extra_path not in targets:
        targets.insert(0, extra_path)  # la fuente más fiable, se prueba primero

    evil_redirect = "https://evil.example.com/callback"
    test_client_id = client_id or "test"

    for target_url in targets:
        sep = "&" if "?" in target_url else "?"
        url = (
            f"{target_url}{sep}response_type=code&client_id={test_client_id}"
            f"&redirect_uri={evil_redirect}&scope=openid&state=test"
        )
        try:
            r = client.get(url)
            location = r.headers.get("location", "")
            if "evil.example.com" in location:
                _add_finding(results, {
                    "phase":       "Greybox SSO",
                    "title":       f"Open redirect en OAuth2 redirect_uri: {target_url}",
                    "description": (
                        f"El endpoint {target_url} redirige a redirect_uri no registrada "
                        f"({evil_redirect}) usando "
                        f"{'el client_id real configurado' if client_id else 'un client_id de prueba'}. "
                        f"Facilita ataques de robo de authorization_code."
                    ),
                    "severity":    "HIGH",
                    "cvss":        7.4,
                    "remediation": (
                        "Validar redirect_uri contra la lista de URIs registradas para cada client_id. "
                        "Rechazar cualquier redirect_uri no registrada."
                    ),
                    "confidence": "HIGH",
                })
                break
        except Exception:
            continue


def _check_bot_protection(client: httpx.Client, authorization_url: str, client_id: str, results: dict):
    """
    Comprueba si la pantalla de login (accesible vía la authorization_endpoint)
    expone marcadores de una protección anti-automatización activa
    (reCAPTCHA / reCAPTCHA Enterprise / hCaptcha / Cloudflare Turnstile).

    No es un check de vulnerabilidad per se — documenta el ESTADO del
    control. Motivación real: estas protecciones a veces se desactivan
    temporalmente para pruebas de carga/rendimiento/búsqueda de punto de
    ruptura, y pueden quedar así por descuido. Si está presente, se reporta
    como INFO (nota positiva). Si no se detecta, se reporta como aviso a
    verificar manualmente — la ausencia en el HTML no es prueba concluyente
    de que el control no exista (podríamos no estar viendo el formulario
    real, o el sitio puede depender de controles no visibles como rate
    limiting de servidor) — de ahí la confidence baja en ese caso.
    """
    MARKERS = {
        "reCAPTCHA":            ("g-recaptcha", "grecaptcha", "recaptcha/api.js", "data-sitekey"),
        "reCAPTCHA Enterprise": ("recaptcha/enterprise.js",),
        "hCaptcha":             ("hcaptcha.com", "h-captcha"),
        "Cloudflare Turnstile": ("challenges.cloudflare.com/turnstile", "cf-turnstile"),
    }
    try:
        params = {
            "response_type": "code",
            "scope":         "openid",
            "state":         "recon-cli-check",
        }
        if client_id:
            params["client_id"] = client_id

        r = client.get(authorization_url, params=params)
        if r.status_code != 200:
            return
        body = r.text

        detected = [name for name, markers in MARKERS.items() if any(m in body for m in markers)]

        if detected:
            _add_finding(results, {
                "phase":       "Greybox SSO",
                "title":       f"Protección anti-automatización detectada en login: {', '.join(detected)}",
                "description": (
                    f"El formulario de login en {authorization_url} expone marcadores de "
                    f"{', '.join(detected)}. Es un control positivo: dificulta el scripting "
                    f"de logins masivos o ataques de fuerza bruta contra el mecanismo de "
                    f"autenticación."
                ),
                "severity":    "INFO",
                "cvss":        0.0,
                "remediation": (
                    "Ninguna acción requerida. Se recomienda verificar periódicamente que "
                    "la protección sigue activa — especialmente después de pruebas de carga, "
                    "rendimiento o búsqueda de punto de ruptura, donde a veces se desactiva "
                    "temporalmente y puede quedar así por descuido."
                ),
                "confidence": "HIGH",
            })
        else:
            _add_finding(results, {
                "phase":       "Greybox SSO",
                "title":       "No se detectó protección anti-automatización (CAPTCHA) en el login",
                "description": (
                    f"No se encontraron marcadores conocidos de reCAPTCHA/hCaptcha/Turnstile "
                    f"en la respuesta de {authorization_url}. Puede deberse a: (a) que la "
                    f"protección esté desactivada temporalmente (p.ej. tras una prueba de "
                    f"carga/rendimiento) y haya quedado así por descuido, (b) que esta "
                    f"petición concreta no esté mostrando el formulario real de login "
                    f"(faltan parámetros o cookies de sesión), o (c) que el servicio "
                    f"dependa de otros controles no visibles en el HTML (rate limiting de "
                    f"servidor, WAF). No se puede distinguir automáticamente entre estos "
                    f"casos — requiere verificación manual en el navegador."
                ),
                "severity":    "MEDIUM",
                "cvss":        5.3,
                "remediation": (
                    "Verificar manualmente en el navegador si el formulario de login muestra "
                    "CAPTCHA. Si no lo muestra y se esperaba que lo hiciera, confirmar que no "
                    "quedó desactivado tras una prueba de carga/rendimiento anterior."
                ),
                "confidence": "LOW",
            })
    except Exception:
        pass


def _add_finding(results: dict, finding: dict):
    """Añade un finding evitando duplicados por título."""
    existing_titles = {f["title"] for f in results["findings"]}
    if finding["title"] not in existing_titles:
        results["findings"].append(finding)
