#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  recon-cli · modules/api_discovery.py  v1.2.0
#  Descubrimiento de endpoints API desde tres fuentes:
#    Fuente A — Colección Postman (.json)
#    Fuente B — OpenAPI / Swagger (.json / .yaml)
#    Fuente C — Spider activo (crawl HTML/JS + wordlist)
#  Devuelve lista normalizada de endpoints para api_audit.py
# ─────────────────────────────────────────────────────────────

import json
import re
import yaml
import httpx
from bs4 import BeautifulSoup
from rich.console import Console
from urllib.parse import urljoin, urlparse

console = Console()

# Paths comunes a probar en el spider (wordlist conservadora)
API_WORDLIST = [
    # ── Estructura genérica de APIs ───────────────────────────
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/v1/docs", "/api/v2/docs",
    "/v1", "/v2", "/v3",

    # ── Documentación OpenAPI / Swagger ───────────────────────
    "/swagger", "/swagger.json", "/swagger.yaml",
    "/swagger-ui", "/swagger-ui.html",
    "/openapi.json", "/openapi.yaml",
    "/api/swagger.json", "/api/openapi.json",
    "/docs", "/redoc",

    # ── GraphQL ───────────────────────────────────────────────
    "/graphql", "/graphql/v1",

    # ── Health / Status ───────────────────────────────────────
    "/health", "/healthz", "/status", "/ping", "/ready",
    "/api/health", "/api/v1/health", "/api/v2/health",

    # ── Métricas ──────────────────────────────────────────────
    "/metrics", "/actuator", "/actuator/health",

    # ── SOAP / WSDL ───────────────────────────────────────────
    "/wsdl", "/?wsdl", "/?WSDL",
    "/ws", "/soap", "/services",

    # ── Auth / OAuth2 / OIDC ──────────────────────────────────
    "/auth", "/login", "/logout",
    "/oauth/token", "/oauth2/token", "/o/oauth2/token",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",

    # ── SSI / Verifiable Credentials / Wallets ────────────────
    # Issuance — vocabulario OIDC4VCI estándar
    "/issuance", "/issuance/api", "/issuance/api/v1", "/issuance/api/v2",
    "/issuance/api/v1/init", "/issuance/api/v2/init",
    "/credential", "/credential/issue", "/credential/offer",
    "/credential-offer", "/credentials",
    "/api/v1/credential", "/api/v2/credential",

    # Issuance con service_id (plataformas multi-tenant: Namirial, etc.)
    "/issuance/api/v1/1/init", "/issuance/api/v1/2/init",
    "/issuance/api/v1/1/status", "/issuance/api/v1/1/credentials",
    "/issuance/api/v2/1/init", "/issuance/api/v2/2/init",

    # Revocación
    "/issuance/api/v1/credential/revoke_by_did",
    "/issuance/api/v1/1/credential/revoke_by_did",
    "/credential/revoke", "/credential/status",
    "/api/v1/credential/revoke",

    # Status list (BitString Status List / Token Status List)
    "/issuance/api/v2/status_list",
    "/issuance/api/v2/1/status_list", "/issuance/api/v2/2/status_list",
    "/status_list", "/statuslist",
    "/api/v1/status_list", "/api/v2/status_list",

    # Verification — vocabulario OIDC4VP estándar
    "/verification", "/verification/api", "/verification/api/v1",
    "/verification/api/v1/init",
    "/verification/api/v1/1/init", "/verification/api/v1/2/init",
    "/verification/api/v1/1/status",
    "/presentation", "/presentation/request",
    "/api/v1/presentation", "/api/v2/presentation",
    "/vp-request", "/vp_request",

    # Wallet / DID
    "/wallet", "/wallet/api", "/wallet/api/v1",
    "/did", "/did/resolve",
    "/.well-known/did.json",
    "/.well-known/did-configuration.json",
    "/api/v1/did", "/api/v2/did",

    # Trust Registry / Schema
    "/trust", "/trust-registry", "/registry",
    "/schema", "/schemas", "/api/v1/schema",
    "/api/v1/trust",

    # Tenant / Admin (típico en plataformas multi-tenant como Namirial)
    "/tenant", "/tenants", "/api/v1/tenant",
    "/admin", "/admin/api", "/api/admin",
    "/api/v1/admin",

    # eIDAS / identidad digital europea
    "/eidas", "/pid", "/mdoc",
    "/api/v1/pid", "/api/v1/eidas",
]

# Métodos HTTP a probar en cada endpoint
HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]


def verify_token(base_url: str, token: str, timeout: int) -> dict:
    """
    Verifica si el token es válido haciendo una llamada de prueba.
    Devuelve dict con status, http_code y mensaje.
    """
    if not token:
        return {"valid": False, "reason": "sin_token"}

    headers = _auth_headers(token)
    test_urls = [
        base_url,
        f"{base_url.rstrip('/')}/health",
        f"{base_url.rstrip('/')}/api",
        f"{base_url.rstrip('/')}/issuance/api/v1",
        f"{base_url.rstrip('/')}/issuance/api/v2/1/status_list",
    ]

    try:
        with httpx.Client(timeout=timeout, verify=False,
                          follow_redirects=False) as client:
            for url in test_urls:
                try:
                    # Sin token
                    r_noauth = client.get(url)
                    # Con token
                    r_auth   = client.get(url, headers=headers)

                    # Si con token obtenemos respuesta diferente → token reconocido
                    if r_auth.status_code != r_noauth.status_code:
                        return {
                            "valid":     True,
                            "reason":    "diferencia_con_sin_token",
                            "url":       url,
                            "code_auth": r_auth.status_code,
                            "code_none": r_noauth.status_code,
                        }

                    # Si con token obtenemos 200/201 → válido
                    if r_auth.status_code in (200, 201):
                        return {
                            "valid":     True,
                            "reason":    "200_con_token",
                            "url":       url,
                            "code_auth": r_auth.status_code,
                        }

                    # Si sin token 401/403 y con token también → token inválido o insuficiente
                    if (r_noauth.status_code in (401, 403) and
                            r_auth.status_code in (401, 403)):
                        # Continuar probando otras URLs antes de concluir
                        continue

                except Exception:
                    continue

        # Si todas las URLs devuelven lo mismo con/sin token
        return {
            "valid":   False,
            "reason":  "sin_diferencia",
            "message": "El token no produce diferencia en las respuestas — puede ser inválido o el servidor bloquea todo el tráfico (WAF)",
        }

    except Exception as e:
        return {"valid": False, "reason": "error", "message": str(e)}


def run_discovery(target: str, target_info: dict, config: dict) -> dict:
    """
    Orquesta el discovery desde todas las fuentes disponibles.
    Devuelve dict con endpoints normalizados y metadata de origen.
    """
    global console
    console = config.get("console") or console

    base_url = _build_base_url(target, target_info)
    timeout  = config.get("REQUEST_TIMEOUT", 10)
    token    = config.get("greybox_token", "")
    api_docs = config.get("greybox_api_docs", [])   # lista — puede ser vacía
    env_file = config.get("greybox_env_file", "")

    # Retrocompatibilidad con clave singular
    if not api_docs and config.get("greybox_api_doc"):
        api_docs = [config["greybox_api_doc"]]

    # Cargar variables del entorno Postman si se ha proporcionado
    postman_vars = _load_postman_env(env_file) if env_file else {}
    if postman_vars.get("base_url"):
        base_url = postman_vars["base_url"]

    results = {
        "base_url":  base_url,
        "endpoints": [],
        "sources":   {"postman": 0, "openapi": 0, "spider": 0},
        "swagger_found": False,
        "graphql_found": False,
        "wsdl_found":    False,
        "wsdl_operations": [],
    }

    # ── Fuentes A y B: ficheros aportados ────────────────────
    for api_doc in api_docs:
        if api_doc.endswith(".json"):
            console.print(f"[cyan]  [*][/cyan] Cargando colección Postman: {api_doc!r}")
            eps = _parse_postman(api_doc, base_url, postman_vars)
            results["endpoints"].extend(eps)
            results["sources"]["postman"] += len(eps)
            console.print(f"  [green]✓[/green] Postman: {len(eps)} endpoint(s) cargados")
        elif api_doc.endswith((".yaml", ".yml")):
            console.print(f"[cyan]  [*][/cyan] Cargando especificación OpenAPI: ", end=""); console.print(api_doc, highlight=False)
            eps = _parse_openapi_file(api_doc, base_url)
            results["endpoints"].extend(eps)
            results["sources"]["openapi"] += len(eps)
            console.print(f"  [green]✓[/green] OpenAPI: {len(eps)} endpoint(s) cargados")

    # ── Fuente C: Spider activo ───────────────────────────────
    waf_detected = config.get("waf_detected", False)
    console.print(f"[cyan]  [*][/cyan] Spider activo en {base_url}...")
    spider_eps, meta = _spider(base_url, token, timeout, waf_detected)

    results["swagger_found"]    = meta.get("swagger_found", False)
    results["graphql_found"]    = meta.get("graphql_found", False)
    results["wsdl_found"]       = meta.get("wsdl_found", False)
    results["wsdl_operations"]  = meta.get("wsdl_operations", [])

    # Si el spider encontró OpenAPI/Swagger, parsear también
    if meta.get("openapi_url"):
        console.print(f"  [yellow]![/yellow] Swagger/OpenAPI detectado: {meta['openapi_url']}")
        remote_eps = _parse_openapi_url(meta["openapi_url"], base_url, token, timeout)
        spider_eps.extend(remote_eps)
        results["sources"]["openapi"] += len(remote_eps)

    results["endpoints"].extend(spider_eps)
    results["sources"]["spider"] = len(spider_eps)

    # Deduplicar por (method, path) — merge de sources si coinciden
    seen     = {}
    deduped  = []
    for ep in results["endpoints"]:
        key = (ep.get("method", "GET"), ep.get("path", ""))
        if key not in seen:
            ep["sources"] = [ep.get("source", "unknown")]
            seen[key]     = ep
            deduped.append(ep)
        else:
            # Endpoint ya visto — añadir source si es nuevo
            existing_src = seen[key]["sources"]
            new_src      = ep.get("source", "unknown")
            if new_src not in existing_src:
                existing_src.append(new_src)
    results["endpoints"] = deduped

    total = len(results["endpoints"])
    runtime_generated = sum(1 for ep in results["endpoints"] if ep.get("runtime_generated"))
    results["runtime_generated_count"] = runtime_generated

    console.print(
        f"  [green]✓[/green] Discovery completado — "
        f"[bold]{total}[/bold] endpoint(s) únicos "
        f"(Postman: {results['sources']['postman']}, "
        f"OpenAPI: {results['sources']['openapi']}, "
        f"Spider: {results['sources']['spider']})"
    )
    if runtime_generated:
        console.print(
            f"  [yellow]![/yellow] {runtime_generated} endpoint(s) con variables Postman "
            f"generadas en runtime (p.ej. {{{{credential_offer_uri}}}}) — no resolubles "
            f"estáticamente, se excluyen de la auditoría"
        )
    if results["swagger_found"]:
        console.print("  [yellow]![/yellow] Swagger UI accesible sin autenticación")
    if results["graphql_found"]:
        console.print("  [yellow]![/yellow] Endpoint GraphQL detectado")
    if results["wsdl_found"]:
        console.print(f"  [yellow]![/yellow] WSDL detectado — {len(results['wsdl_operations'])} operación(es)")

    return results


# ── Fuente A: Parser de colección Postman ────────────────────

def _load_postman_env(path: str) -> dict:
    """Carga variables desde un fichero de entorno Postman (.json)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {
            v["key"]: v.get("value", "")
            for v in data.get("values", [])
            if v.get("enabled", True) and v.get("value", "")
        }
    except Exception as e:
        console.print(f"  [yellow]![/yellow] Error leyendo entorno Postman: {e}")
        return {}


def _resolve_vars(text: str, vars: dict) -> str:
    """Resuelve variables Postman {{variable}} con los valores del entorno."""
    if not text:
        return text
    for key, value in vars.items():
        text = text.replace(f"{{{{{key}}}}}", str(value))
    return text


def _parse_postman(path: str, base_url: str, postman_vars: dict = None) -> list:
    """Extrae endpoints de una colección Postman v2.0 / v2.1."""
    endpoints = []
    vars = postman_vars or {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Añadir variables de colección (prioridad menor que las de entorno)
        for v in data.get("variable", []):
            key = v.get("key", "")
            val = v.get("value", "")
            if key and key not in vars:
                vars[key] = val

        # Añadir base_url si no viene del entorno
        if "base_url" not in vars:
            vars["base_url"] = base_url.rstrip("/")

        # Auth a nivel de colección
        collection_auth = data.get("auth", {})

        items = data.get("item", [])
        _extract_postman_items(items, base_url, vars, collection_auth, endpoints)

    except Exception as e:
        console.print(f"  [yellow]![/yellow] Error leyendo Postman: {e}")
    return endpoints


def _extract_postman_items(items: list, base_url: str, vars: dict,
                           parent_auth: dict, endpoints: list):
    """Recursivo — Postman permite carpetas anidadas."""
    for item in items:
        # Auth heredada o propia de la carpeta
        item_auth = item.get("auth", parent_auth)

        if "item" in item:
            # Es una carpeta — recurrir
            _extract_postman_items(item["item"], base_url, vars, item_auth, endpoints)
        elif "request" in item:
            req    = item["request"]
            method = req.get("method", "GET").upper()

            # Auth del request (máxima prioridad) o heredada
            req_auth = req.get("auth", item_auth)
            is_noauth = (
                isinstance(req_auth, dict) and
                req_auth.get("type") == "noauth"
            )

            url = req.get("url", {})
            if isinstance(url, str):
                raw = _resolve_vars(url, vars)
            else:
                raw = _resolve_vars(url.get("raw", ""), vars)

            # Variables {{...}} que NO estaban en el entorno/colección — típicamente
            # generadas en tiempo de ejecución dentro de Postman vía
            # pm.environment.set() (credential_offer_uri, token_endpoint, etc.).
            # Sin resolver, quedan literalmente como "/{{variable}}" en el path,
            # lo que produce un endpoint fantasma: se cuenta como "descubierto"
            # pero cualquier petición real contra él va a fallar en silencio.
            unresolved = re.findall(r'\{\{([^}]+)\}\}', raw)

            path = _extract_path(raw, base_url)
            if path:
                endpoints.append({
                    "method":               method,
                    "path":                 path,
                    "full_url":             raw,
                    "source":               "postman",
                    "name":                 item.get("name", ""),
                    "intentionally_public": is_noauth,
                    "auth_needed":          not is_noauth and _postman_has_auth(req_auth),
                    "runtime_generated":    bool(unresolved),
                    "unresolved_vars":      unresolved,
                })


def _postman_has_auth(auth: dict) -> bool:
    return bool(auth and isinstance(auth, dict) and auth.get("type") not in (None, "noauth"))


# ── Fuente B: Parser OpenAPI / Swagger ───────────────────────

def _parse_openapi_file(path: str, base_url: str) -> list:
    """Parsea fichero OpenAPI local (.json o .yaml)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            if path.endswith(".json"):
                spec = json.load(f)
            else:
                spec = yaml.safe_load(f)
        return _extract_openapi_endpoints(spec, base_url)
    except Exception as e:
        console.print(f"  [yellow]![/yellow] Error leyendo OpenAPI: {e}")
        return []


def _parse_openapi_url(url: str, base_url: str, token: str, timeout: int) -> list:
    """Descarga y parsea especificación OpenAPI remota."""
    try:
        headers = _auth_headers(token)
        resp = httpx.get(url, headers=headers, timeout=timeout, verify=False)
        if resp.status_code != 200:
            return []
        if url.endswith(".yaml") or url.endswith(".yml"):
            spec = yaml.safe_load(resp.text)
        else:
            spec = resp.json()
        return _extract_openapi_endpoints(spec, base_url)
    except Exception:
        return []


def _extract_openapi_endpoints(spec: dict, base_url: str) -> list:
    """Extrae endpoints de spec OpenAPI 2.x (Swagger) o 3.x."""
    endpoints = []
    paths = spec.get("paths", {})

    # Base path (Swagger 2.x)
    api_base = spec.get("basePath", "")

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if method.upper() not in HTTP_METHODS:
                continue
            if not isinstance(op, dict):
                continue
            full_path = f"{api_base}{path}".replace("//", "/")
            endpoints.append({
                "method":      method.upper(),
                "path":        full_path,
                "full_url":    f"{base_url}{full_path}",
                "source":      "openapi",
                "name":        op.get("operationId", f"{method.upper()} {path}"),
                "summary":     op.get("summary", ""),
                "auth_needed": bool(op.get("security")),
            })
    return endpoints


# ── Fuente C: Spider activo ───────────────────────────────────

def _spider(base_url: str, token: str, timeout: int, waf_detected: bool = False) -> tuple:
    """
    Spider activo en dos pasos:
    1. Crawl del HTML/JS de la página principal buscando rutas API
    2. Wordlist de paths comunes

    Si hay WAF detectado, usa timeout reducido para el probe de wordlist
    — los paths bloqueados por WAF responden rápido con 403/404,
    no tiene sentido esperar el timeout completo.
    """
    # Timeout diferenciado: WAF → 3s (responde rápido), sin WAF → timeout completo
    probe_timeout = 3 if waf_detected else timeout
    if waf_detected:
        console.print(f"  [dim]WAF detectado — timeout de probe reducido a {probe_timeout}s[/dim]")
    endpoints = []
    meta = {
        "swagger_found": False,
        "graphql_found": False,
        "wsdl_found":    False,
        "wsdl_operations": [],
        "openapi_url":   None,
    }
    headers = _auth_headers(token)

    # Paso 1 — Crawl HTML/JS
    console.print(f"  [dim]Spider: crawl HTML/JS...[/dim]")
    try:
        resp = httpx.get(base_url, headers=headers, timeout=timeout,
                         verify=False, follow_redirects=True)
        if resp.status_code == 200:
            html_eps = _extract_from_html(resp.text, base_url)
            endpoints.extend(html_eps)
            if html_eps:
                console.print(f"  [dim]Spider: {len(html_eps)} ruta(s) en HTML/JS[/dim]")
    except Exception:
        pass

    # Paso 2 — Wordlist
    console.print(f"  [dim]Spider: wordlist ({len(API_WORDLIST)} paths)...[/dim]")
    found_paths = []

    # Paths que típicamente solo aceptan POST — probar directamente con POST
    POST_HINTS = ("/init", "/revoke", "/revoke_by_did", "/issue", "/verify",
                  "/token", "/introspect", "/register", "/callback")

    with httpx.Client(headers=headers, timeout=probe_timeout, verify=False,
                      follow_redirects=False) as client:
        for path in API_WORDLIST:
            url = f"{base_url.rstrip('/')}{path}"
            try:
                # Determinar método inicial
                initial_method = "POST" if path.endswith(POST_HINTS) else "GET"
                r = client.request(initial_method, url)

                if r.status_code in (200, 201, 401, 403, 405, 422):
                    # 405 con GET → probar POST (y viceversa)
                    actual_method = initial_method
                    if r.status_code == 405:
                        alt = "POST" if initial_method == "GET" else "GET"
                        r2 = client.request(alt, url)
                        if r2.status_code in (200, 201, 401, 403, 422):
                            r            = r2
                            actual_method = alt
                        elif r2.status_code != 405:
                            # El original devuelve 405 y el alternativo tampoco — saltar
                            continue

                    found_paths.append(path)

                    # Determinar si el endpoint es público intencionalmente:
                    # responde 200 tanto con token como sin token → público por diseño
                    intentionally_public = False
                    if r.status_code in (200, 201) and token:
                        try:
                            r_noauth = client.request(
                                actual_method, url,
                                headers={"User-Agent": "recon-cli/1.2 security-scanner"}
                            )
                            if r_noauth.status_code in (200, 201):
                                intentionally_public = True
                        except Exception:
                            pass

                    endpoints.append({
                        "method":               actual_method,
                        "path":                 path,
                        "full_url":             url,
                        "source":               "spider",
                        "name":                 path,
                        "status_code":          r.status_code,
                        "auth_needed":          r.status_code in (401, 403),
                        "intentionally_public": intentionally_public,
                    })

                    # Detectar tipos especiales
                    ct = r.headers.get("content-type", "").lower()
                    body = r.text[:500].lower()

                    if path in ("/swagger.json", "/openapi.json", "/api/swagger.json",
                                "/api/openapi.json") and r.status_code == 200:
                        meta["openapi_url"] = url
                        meta["swagger_found"] = True

                    if "swagger" in body or "swagger-ui" in body:
                        meta["swagger_found"] = True

                    if path == "/graphql" or "graphql" in ct:
                        meta["graphql_found"] = True

                    if path in ("/wsdl", "/?wsdl", "/?WSDL") and r.status_code == 200:
                        meta["wsdl_found"] = True
                        meta["wsdl_operations"] = _parse_wsdl_operations(r.text)

            except Exception:
                continue

    if found_paths:
        console.print(f"  [dim]Spider: {len(found_paths)} path(s) activos de {len(API_WORDLIST)} probados[/dim]")

    return endpoints, meta


def _extract_from_html(html: str, base_url: str) -> list:
    """Extrae referencias a rutas API desde HTML y bloques JS."""
    endpoints = []
    seen      = set()

    # Patrones JS comunes: fetch('/api/...'), axios.get('/api/...')
    patterns = [
        re.compile(r'''(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['"`](/[^'"`\s]+)'''),
        re.compile(r'''(?:url|endpoint|path|route)\s*[:=]\s*['"`](/api/[^'"`\s]+)''', re.IGNORECASE),
        re.compile(r'''['"`](/(?:api|v\d|graphql|oauth|auth)[^'"`\s]*)['"`]'''),
    ]

    try:
        soup = BeautifulSoup(html, "html.parser")
        # Buscar en scripts inline
        for script in soup.find_all("script"):
            text = script.string or ""
            for pat in patterns:
                for m in pat.finditer(text):
                    path = m.group(1)
                    if path not in seen and len(path) < 200:
                        seen.add(path)
                        endpoints.append({
                            "method":   "GET",
                            "path":     path,
                            "full_url": urljoin(base_url, path),
                            "source":   "spider_html",
                            "name":     path,
                        })
    except Exception:
        pass

    return endpoints


def _parse_wsdl_operations(wsdl_text: str) -> list:
    """Extrae nombres de operaciones de un WSDL."""
    operations = re.findall(r'<(?:wsdl:)?operation\s+name=["\']([^"\']+)["\']', wsdl_text)
    return list(set(operations))


# ── Utilidades ────────────────────────────────────────────────

def _build_base_url(target: str, target_info: dict) -> str:
    if target_info.get("type") == "ip":
        return f"https://{target}"
    return f"https://{target}"


def _extract_path(raw_url: str, base_url: str) -> str:
    """Extrae el path de una URL, relativizándolo si es posible."""
    try:
        parsed = urlparse(raw_url)
        if parsed.scheme:
            return parsed.path or "/"
        if raw_url.startswith("/"):
            return raw_url
        return f"/{raw_url}"
    except Exception:
        return ""


def _auth_headers(token: str) -> dict:
    headers = {"User-Agent": "recon-cli/1.2 security-scanner"}
    if token:
        if not token.startswith("Bearer "):
            token = f"Bearer {token}"
        headers["Authorization"] = token
    return headers
