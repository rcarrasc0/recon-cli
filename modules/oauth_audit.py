#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  recon-cli · modules/oauth_audit.py  v1.2.0
#
#  Auditoría de flujos OAuth2 / OpenID Connect (submodo SSO / VALid2).
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

import httpx
from rich.console import Console

console = Console()

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


def run_sso_audit(target: str, config: dict) -> dict:
    """
    Punto de entrada del audit SSO/OAuth2 — mismo patrón que
    run_audit(discovery, config) en api_audit.py.
    """
    global console
    console = config.get("console") or console

    console.print("\n[bold magenta]━━━ Greybox SSO — Auditoría OAuth2/VALid2[/bold magenta]")

    token     = config.get("greybox_token", "")
    client_id = config.get("greybox_client_id", "")
    timeout   = config.get("REQUEST_TIMEOUT", 10)
    base_url  = f"https://{target}"

    results = {"findings": []}

    oauth_endpoints = _discover_oauth_endpoints(base_url, token, timeout)

    if not oauth_endpoints:
        console.print(
            f"  [yellow]![/yellow] No se detectaron endpoints OAuth2 en {base_url}\n"
            "  [dim]Asegúrate de que el target es el servidor de autenticación[/dim]"
        )
        return results

    console.print(f"  [green]✓[/green] {len(oauth_endpoints)} endpoint(s) OAuth2 detectados")

    with httpx.Client(timeout=timeout, verify=False, follow_redirects=False) as client:

        for ep in oauth_endpoints:
            # Check 1 — Accesible por HTTP (sin TLS)
            _check_http_token_endpoint(client, ep, timeout, results)

            # Check 2 — Token inválido aceptado en token endpoint
            _check_invalid_token_acceptance(client, ep, results)

        # Check 3 — Token expirado: aviso operativo, no finding (ver docstring)
        if token:
            _check_expired_token(token, results)

        # Check 4 — Logout programático (informativo)
        if token:
            _check_logout(client, base_url, token, results)

        # Check 5 — Revocación (informativo, RFC 7009 vía POST)
        if token:
            _check_revocation(client, base_url, token, results)

        # Check 6 — Open redirect en OAuth (redirect_uri manipulation)
        _check_open_redirect(client, base_url, client_id, results)

    console.print(
        f"  [green]✓[/green] SSO audit completado — "
        f"{len(results['findings'])} hallazgo(s)"
    )
    return results


def _discover_oauth_endpoints(base_url: str, token: str, timeout: int) -> list:
    """Detecta endpoints OAuth2 estándar en el target (prueba GET)."""
    headers = {"User-Agent": "recon-cli/1.2 security-scanner"}
    found = []
    try:
        with httpx.Client(timeout=timeout, verify=False, follow_redirects=False) as client:
            for path in OAUTH_ENDPOINT_PATHS:
                url = f"{base_url.rstrip('/')}{path}"
                try:
                    r = client.get(url, headers=headers)
                    if r.status_code in (200, 400, 401, 405):
                        found.append(url)
                except Exception:
                    continue
    except Exception:
        pass
    return found


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
    """Envía un refresh_token inválido al token endpoint y verifica la respuesta."""
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
        # Un servidor correcto devuelve 400/401, no 200
        if r.status_code == 200:
            _add_finding(results, {
                "phase":       "Greybox SSO",
                "title":       f"Token endpoint acepta refresh_token inválido: {endpoint}",
                "description": (
                    f"{endpoint} devuelve HTTP 200 con un refresh_token claramente inválido. "
                    "La validación de tokens puede estar deshabilitada."
                ),
                "severity":    "CRITICAL",
                "cvss":        9.1,
                "remediation": "Verificar la validación de tokens en el servidor OAuth2.",
                "confidence":  "HIGH",
            })
    except Exception:
        pass


def _check_expired_token(token: str, results: dict):
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
    """
    try:
        import base64, json as _json, time

        raw = token[7:] if token.startswith("Bearer ") else token
        parts = raw.split(".")
        if len(parts) != 3:
            return

        payload = parts[1]
        payload += "=" * (4 - len(payload) % 4)
        decoded = _json.loads(base64.b64decode(payload))
        exp = decoded.get("exp")

        if exp and exp < time.time():
            console.print(
                "  [yellow]![/yellow] El token proporcionado ya está expirado "
                "(exp en el pasado) — los checks que dependen de un token válido "
                "pueden dar resultados poco fiables. Considera obtener un token fresco."
            )
    except Exception:
        pass


def _check_logout(client: httpx.Client, base_url: str, token: str, results: dict):
    """
    Detecta el endpoint de logout, si existe.
    Informativo: verificar que el token deja de funcionar tras logout
    requeriría un endpoint de datos autenticado — no disponible aquí sin
    acoplar este módulo al discovery de api_discovery.py. Queda pendiente
    para v1.2.x si se decide integrar ambos submodos.
    """
    logout_paths = ["/o/oauth2/logout", "/oauth/logout", "/auth/logout", "/logout"]
    for path in logout_paths:
        url = f"{base_url.rstrip('/')}{path}"
        try:
            r = client.get(f"{url}?token={token}")
            if r.status_code in (200, 302):
                console.print(f"  [dim]Logout endpoint detectado: {url} (HTTP {r.status_code})[/dim]")
                break
        except Exception:
            continue


def _check_revocation(client: httpx.Client, base_url: str, token: str, results: dict):
    """
    Verifica la existencia del endpoint de revocación.

    FIX: la versión anterior usaba GET con el token en query string
    (además de la fuga potencial vía logs/referrer, no es el formato
    que especifica RFC 7009 — POST con el token en el body). Un servidor
    bien implementado devolvía 404/405 con GET, no porque estuviera mal,
    sino porque el check no hablaba el protocolo correcto.
    Se retira también el finding LOW anterior basado en HTTP 400: no es
    evidencia suficiente de un fallo real (puede ser simplemente una
    petición mal formada por nuestra parte, p.ej. sin client_id).
    Queda como comprobación informativa de existencia del endpoint.
    """
    revoke_paths = ["/o/oauth2/revoke", "/oauth/revoke", "/oauth2/revoke"]
    for path in revoke_paths:
        url = f"{base_url.rstrip('/')}{path}"
        try:
            r = client.post(
                url,
                data={"token": token},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if r.status_code in (200, 400, 401):
                console.print(f"  [dim]Endpoint de revocación detectado: {url} (HTTP {r.status_code})[/dim]")
                break
        except Exception:
            continue


def _check_open_redirect(client: httpx.Client, base_url: str, client_id: str, results: dict):
    """
    Comprueba open redirect en el parámetro redirect_uri del flujo OAuth2.
    Un servidor correcto rechaza redirect_uri no registradas.

    FIX: la versión anterior usaba client_id="test" inventado. Un servidor
    bien implementado rechaza client_id desconocidos ANTES de validar
    redirect_uri, así que la prueba casi nunca era concluyente (ni en
    positivo ni en negativo). Ahora reutiliza el client_id real configurado
    en greybox (GREYBOX_CLIENT_ID), si está disponible, para que el
    servidor sí llegue a evaluar el redirect_uri.
    """
    auth_paths = ["/o/oauth2/auth", "/oauth/authorize", "/oauth2/authorize", "/auth"]
    evil_redirect = "https://evil.example.com/callback"
    test_client_id = client_id or "test"

    for path in auth_paths:
        url = (
            f"{base_url.rstrip('/')}{path}"
            f"?response_type=code&client_id={test_client_id}"
            f"&redirect_uri={evil_redirect}&scope=openid&state=test"
        )
        try:
            r = client.get(url)
            location = r.headers.get("location", "")
            if "evil.example.com" in location:
                _add_finding(results, {
                    "phase":       "Greybox SSO",
                    "title":       f"Open redirect en OAuth2 redirect_uri: {path}",
                    "description": (
                        f"El endpoint {path} redirige a redirect_uri no registrada "
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


def _add_finding(results: dict, finding: dict):
    """Añade un finding evitando duplicados por título."""
    existing_titles = {f["title"] for f in results["findings"]}
    if finding["title"] not in existing_titles:
        results["findings"].append(finding)
