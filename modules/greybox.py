#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  recon-cli · modules/greybox.py  v1.2.0
#  Orquestador del modo greybox.
#  Submodos:
#    [1] API audit  — Bearer token + discovery + audit
#    [2] SSO audit  — OAuth2/OIDC Bearer + checks de sesión
#    [3] Ambos
#  Credenciales por prioridad:
#    1. config (CLI flags --token / --api-doc)
#    2. .env   (GREYBOX_TOKEN / GREYBOX_API_DOC)
#    3. Interactivo (pregunta al usuario)
# ─────────────────────────────────────────────────────────────

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt

from modules.api_discovery import run_discovery
from modules.api_audit import run_audit

console = Console()


def run_greybox(target: str, target_info: dict, config: dict) -> dict:
    """
    Punto de entrada del modo greybox.
    Presenta el menú guiado, recoge credenciales y ejecuta el submodo elegido.
    """
    global console
    console = config.get("console") or console

    results = {
        "submode":   None,
        "api_token": None,
        "sso_token": None,
        "api_doc":   None,
        "discovery": {},
        "audit":     {},
        "sso_audit": {},
        "findings":  [],
    }

    # ── Paso 1: Presentación y selección de submodo ───────────
    # Si GREYBOX_SUBMODE está configurado (.env o CLI), se salta el menú
    # entero — útil para pruebas repetidas contra el mismo target/submodo
    # (p.ej. validar SSO varias veces sin tener que re-elegir cada vez).
    preset = str(config.get("greybox_submode", "")).strip().lower()
    SUBMODE_ALIASES = {
        "1": 1, "api": 1, "api_audit": 1, "api-audit": 1,
        "2": 2, "sso": 2, "sso_audit": 2, "sso-audit": 2, "oauth2": 2, "oidc": 2,
        "3": 3, "both": 3, "ambos": 3, "all": 3,
    }
    submode = SUBMODE_ALIASES.get(preset)

    if submode:
        console.print(
            f"\n[bold magenta]━━━ Greybox — {target}[/bold magenta]\n"
            f"  [dim]Submodo preconfigurado (GREYBOX_SUBMODE={preset}) — menú omitido[/dim]"
        )
    else:
        if preset:
            console.print(
                f"  [yellow]![/yellow] GREYBOX_SUBMODE=\"{preset}\" no reconocido "
                f"(usa 1/2/3 o api/sso/both) — se muestra el menú interactivo"
            )
        console.print(Panel.fit(
            "[bold magenta]MODO GREYBOX[/bold magenta] — Auditoría con credenciales\n\n"
            "Selecciona qué quieres auditar:\n\n"
            "  [bold cyan][1][/bold cyan] [bold]API audit[/bold]\n"
            "      Auditoría de APIs REST o SOAP con token de autenticación.\n"
            "      Descubre endpoints automáticamente y verifica autenticación,\n"
            "      métodos, IDOR, exposición de datos y rate limiting.\n\n"
            "  [bold cyan][2][/bold cyan] [bold]SSO audit[/bold]\n"
            "      Auditoría de flujos OAuth2 / OpenID Connect.\n"
            "      Verifica validación de tokens, logout, revocación\n"
            "      y open redirect en redirect_uri.\n\n"
            "  [bold cyan][3][/bold cyan] [bold]Ambos[/bold]\n"
            "      API audit + SSO audit en un único informe.\n"
            "      Máxima cobertura con una sola ejecución.",
            title=f"[bold white]recon-cli · Greybox — {target}[/bold white]",
            border_style="magenta"
        ))

        while True:
            try:
                submode = IntPrompt.ask(
                    "\n[magenta]  Selecciona submodo[/magenta] [dim][1/2/3][/dim]",
                    choices=["1", "2", "3"],
                    default=1
                )
                break
            except Exception:
                console.print("[yellow]  Introduce 1, 2 o 3[/yellow]")

    results["submode"] = submode
    console.print(
        f"\n  [green]✓[/green] Submodo: [bold magenta]{_submode_name(submode)}[/bold magenta]"
    )

    base_url = f"https://{target}"
    step = 1
    api_token = None
    sso_token = None
    api_docs  = []
    env_file  = ""

    # ── Bloque API: credenciales + documentación ──────────────
    if submode in (1, 3):
        step += 1
        console.print(Panel.fit(
            f"[bold]Paso {step} — Credenciales de API[/bold]\n\n"
            "Introduce el Bearer token para autenticar las peticiones de API.\n\n"
            "  [dim]Ejemplos:[/dim]\n"
            "  [dim]· JWT:      eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...[/dim]\n"
            "  [dim]· API key:  a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2[/dim]\n\n"
            "  [dim]Si no tienes token, pulsa Enter para continuar sin él.[/dim]\n"
            "  [dim]El spider seguirá descubriendo endpoints públicos.[/dim]",
            border_style="dim",
        ))

        env_api_token          = config.get("greybox_api_token", "")
        env_api_client_id      = config.get("greybox_api_client_id", "")
        env_api_client_secret  = config.get("greybox_api_client_secret", "")
        env_api_token_endpoint = config.get("greybox_api_token_endpoint", "")

        if env_api_token:
            api_token = env_api_token
        elif env_api_client_id and env_api_client_secret:
            console.print("  [dim]Credenciales de API detectadas en .env — obteniendo token automáticamente...[/dim]")
            api_token = _client_credentials_flow(
                base_url=base_url,
                client_id=env_api_client_id,
                client_secret=env_api_client_secret,
                token_endpoint=env_api_token_endpoint,
            )
        else:
            api_token = _ask_token(base_url,
                                   hint_client_id=env_api_client_id,
                                   hint_client_secret=env_api_client_secret,
                                   hint_token_endpoint=env_api_token_endpoint,
                                   label="API")

        if not api_token:
            console.print(
                "  [yellow][!][/yellow] Sin token de API — "
                "se auditarán endpoints públicos y se verificará qué requiere auth."
            )
        else:
            config["greybox_api_token"] = api_token
            results["api_token"] = "***"
            console.print("  [green]✓[/green] Token de API configurado")

        # ── Documentación de la API ─────────────────────────────
        step += 1
        console.print(Panel.fit(
            f"[bold]Paso {step} — Documentación de la API[/bold] [dim](opcional)[/dim]\n\n"
            "Si tienes documentación de la API, la herramienta la usará para\n"
            "descubrir todos los endpoints con precisión.\n"
            "Sin documentación, el spider intentará descubrirlos automáticamente.\n\n"
            "  [bold cyan][1][/bold cyan] Colección Postman  [dim](.json)[/dim]\n"
            "      [dim]El fichero exportado desde Postman con los endpoints definidos.[/dim]\n\n"
            "  [bold cyan][2][/bold cyan] OpenAPI / Swagger  [dim](.yaml o .json)[/dim]\n"
            "      [dim]Especificación técnica estándar de la API.[/dim]\n\n"
            "  [bold cyan][3][/bold cyan] Ambos\n"
            "      [dim]Colección Postman + especificación OpenAPI.[/dim]\n\n"
            "  [bold cyan][4][/bold cyan] No tengo documentación — usar solo el spider",
            border_style="dim",
        ))

        api_docs = list(config.get("greybox_api_docs", []))
        env_file = config.get("greybox_api_env_file", "")

        if not api_docs:
            try:
                doc_choice = Prompt.ask(
                    "  [magenta]Tipo de documentación[/magenta]",
                    choices=["1", "2", "3", "4"], default="4"
                )
            except Exception:
                doc_choice = "4"

            if doc_choice in ("1", "3"):
                console.print(
                    "\n  [dim]Introduce la ruta completa al fichero de la colección Postman:[/dim]\n"
                    "  [dim]Ejemplo: /home/usuario/mis-apis/mi-api.postman_collection.json[/dim]"
                )
                try:
                    postman_path = Prompt.ask("  [magenta]Colección Postman[/magenta]", default="")
                    if postman_path.strip():
                        api_docs.append(postman_path.strip())
                        console.print("  [green]✓[/green] Colección Postman cargada")

                        # Preguntar entorno solo después de la colección Postman
                        if not env_file:
                            console.print(
                                "\n  [dim]La colección puede usar variables como {{base_url}} o {{service_id}}.[/dim]\n"
                                "  [dim]Si tienes el fichero de entorno Postman introduce la ruta aquí.[/dim]\n"
                                "  [dim]Si no lo tienes o no sabes qué es, pulsa Enter para omitir.[/dim]\n"
                                "  [dim]Ejemplo: /home/usuario/mis-apis/mi-entorno.postman_environment.json[/dim]"
                            )
                            try:
                                env_path = Prompt.ask(
                                    "  [magenta]Entorno Postman[/magenta] [dim](opcional, Enter para omitir)[/dim]",
                                    default=""
                                )
                                if env_path.strip():
                                    env_file = env_path.strip()
                                    console.print("  [green]✓[/green] Entorno Postman cargado")
                            except Exception:
                                pass
                except Exception:
                    pass

            if doc_choice in ("2", "3"):
                console.print(
                    "\n  [dim]Introduce la ruta completa al fichero OpenAPI/Swagger:[/dim]\n"
                    "  [dim]Ejemplo: /home/usuario/mis-apis/mi-api.yaml[/dim]"
                )
                try:
                    openapi_path = Prompt.ask("  [magenta]OpenAPI / Swagger[/magenta]", default="")
                    if openapi_path.strip():
                        api_docs.append(openapi_path.strip())
                        console.print("  [green]✓[/green] OpenAPI/Swagger cargado")
                except Exception:
                    pass

            if doc_choice == "4" or not api_docs:
                console.print(
                    "  [dim]Sin documentación — se usará el spider para descubrir endpoints.[/dim]"
                )

        if api_docs:
            config["greybox_api_docs"] = api_docs
            results["api_doc"] = api_docs
        if env_file:
            config["greybox_api_env_file"] = env_file

    # ── Bloque SSO: credenciales ───────────────────────────────
    if submode in (2, 3):
        step += 1
        console.print(Panel.fit(
            f"[bold]Paso {step} — Credenciales de SSO / OAuth2[/bold]\n\n"
            "Introduce el Bearer token para autenticar las peticiones de SSO.\n\n"
            "  [dim]Ejemplos:[/dim]\n"
            "  [dim]· JWT:      eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...[/dim]\n"
            "  [dim]· API key:  a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2[/dim]\n\n"
            "  [dim]Si no tienes token, pulsa Enter para continuar sin él.[/dim]\n"
            "  [dim]El spider seguirá descubriendo endpoints públicos.[/dim]",
            border_style="dim",
        ))

        env_sso_token          = config.get("greybox_sso_token", "")
        env_sso_client_id      = config.get("greybox_sso_client_id", "")
        env_sso_client_secret  = config.get("greybox_sso_client_secret", "")
        env_sso_token_endpoint = config.get("greybox_sso_token_endpoint", "")

        if env_sso_token:
            sso_token = env_sso_token
        elif env_sso_client_id and env_sso_client_secret:
            console.print("  [dim]Credenciales de SSO detectadas en .env — obteniendo token automáticamente...[/dim]")
            sso_token = _client_credentials_flow(
                base_url=base_url,
                client_id=env_sso_client_id,
                client_secret=env_sso_client_secret,
                token_endpoint=env_sso_token_endpoint,
            )
        else:
            sso_token = _ask_token(base_url,
                                   hint_client_id=env_sso_client_id,
                                   hint_client_secret=env_sso_client_secret,
                                   hint_token_endpoint=env_sso_token_endpoint,
                                   label="SSO")

        if not sso_token:
            console.print(
                "  [yellow][!][/yellow] Sin token de SSO — "
                "se auditarán endpoints públicos y se verificará qué requiere auth."
            )
        else:
            config["greybox_sso_token"] = sso_token
            results["sso_token"] = "***"
            console.print("  [green]✓[/green] Token de SSO configurado")

    # ── Resumen antes de ejecutar ─────────────────────────────
    api_docs_cfg = config.get("greybox_api_docs", [])
    env_cfg      = config.get("greybox_api_env_file", "")

    # Construir líneas de documentación — una ruta por línea
    doc_lines = ""
    if submode in (1, 3):
        if api_docs_cfg:
            for doc in api_docs_cfg:
                doc_lines += f"\n  Colección:     [cyan]{doc}[/cyan]"
        else:
            doc_lines = "\n  Colección:     [dim]ninguna — spider automático[/dim]"

    token_lines = ""
    if submode in (1, 3):
        token_lines += (
            f"\n  Token API:     "
            f"{'[green]configurado[/green]' if api_token else '[yellow]no configurado[/yellow]'}"
        )
    if submode in (2, 3):
        token_lines += (
            f"\n  Token SSO:     "
            f"{'[green]configurado[/green]' if sso_token else '[yellow]no configurado[/yellow]'}"
        )

    console.print(Panel.fit(
        f"[bold]Resumen de configuración greybox[/bold]\n\n"
        f"  Target:        [green]{target}[/green]\n"
        f"  Submodo:       [magenta]{_submode_name(submode)}[/magenta]"
        + token_lines
        + doc_lines +
        (f"\n  Entorno:       [cyan]{env_cfg}[/cyan]" if env_cfg else "") +
        "\n\n  [dim]Iniciando análisis...[/dim]",
        border_style="magenta"
    ))

    # ── Ejecutar submodos ──────────────────────────────────────
    if submode in (1, 3):
        _run_api_audit(target, target_info, config, results)

    if submode in (2, 3):
        _run_sso_audit(target, target_info, config, results)

    # ── Consolidar hallazgos ──────────────────────────────────
    results["findings"].extend(results["audit"].get("findings", []))
    results["findings"].extend(results["sso_audit"].get("findings", []))

    # ── Export JSON — discovery y audit ──────────────────────
    _export_json(results, config)

    console.print(
        f"\n  [green]✓[/green] Greybox completado — "
        f"[bold]{len(results['findings'])}[/bold] hallazgo(s)"
    )
    return results


# ── API audit ─────────────────────────────────────────────────

def _run_api_audit(target: str, target_info: dict, config: dict, results: dict):
    """Ejecuta discovery + audit sobre APIs REST/SOAP."""
    from modules.api_discovery import run_discovery, verify_token

    token   = config.get("greybox_api_token", "")
    timeout = config.get("REQUEST_TIMEOUT", 10)
    base_url = f"https://{target}"

    # ── Verificación de token ─────────────────────────────────
    if token:
        console.print("\n[bold magenta]━━━ Greybox API — Verificación de token[/bold magenta]")
        vresult = verify_token(base_url, token, timeout)
        if vresult["valid"]:
            code_auth = vresult.get('code_auth', '?')
            code_none = vresult.get('code_none')
            url_check = vresult.get('url', '')
            auth_info = (
                f"HTTP {code_auth} con token vs {code_none} sin token"
                if code_none
                else f"HTTP {code_auth} con token — sin acceso sin token"
            )
            console.print(
                f"  [green]✓[/green] Token válido [dim]({auth_info} en {url_check})[/dim]"
            )
            config["token_verified"] = True
        else:
            console.print(
                f"  [yellow]![/yellow] No se pudo verificar el token: "
                f"{vresult.get('message', vresult.get('reason',''))}"
            )
            config["token_verified"] = False

    # ── Discovery ─────────────────────────────────────────────
    console.print("\n[bold magenta]━━━ Greybox API — Discovery[/bold magenta]")
    discovery = run_discovery(target, target_info, config)
    results["discovery"] = discovery

    # ── Fallback: spider sin resultados + token válido ────────
    endpoints_found = len(discovery.get("endpoints", []))
    if endpoints_found == 0 and config.get("token_verified"):
        console.print(Panel.fit(
            "[bold yellow]⚠ Discovery sin resultados con token válido[/bold yellow]\n\n"
            "El token es válido pero el spider no encontró endpoints.\n"
            "Esto suele ocurrir cuando el servidor bloquea el tráfico de\n"
            "descubrimiento (WAF, paths no estándar, API privada).\n\n"
            "Puedes aportar documentación para continuar con la auditoría:\n\n"
            "  [dim]· Colección Postman:   /ruta/coleccion.postman_collection.json[/dim]\n"
            "  [dim]· OpenAPI / Swagger:   /ruta/especificacion.yaml[/dim]\n\n"
            "  [dim]Pulsa Enter para omitir y generar el informe sin auditoría API.[/dim]",
            border_style="yellow",
        ))

        fallback_docs = _ask_api_docs()
        if fallback_docs:
            config["greybox_api_docs"] = fallback_docs
            has_postman = any(d.endswith(".json") for d in fallback_docs)
            if has_postman and not config.get("greybox_api_env_file"):
                console.print(Panel.fit(
                    "[bold]Entorno Postman[/bold] [dim](opcional)[/dim]\n\n"
                    "Si la colección usa variables como {{base_url}} o {{service_id}},\n"
                    "introduce el fichero de entorno para resolverlas.\n\n"
                    "  [dim]Ejemplo: /ruta/entorno.postman_environment.json[/dim]",
                    border_style="dim",
                ))
                env_file = _ask_env_file()
                if env_file:
                    config["greybox_api_env_file"] = env_file

            # Re-ejecutar discovery con la documentación aportada
            console.print("\n[bold magenta]━━━ Greybox API — Discovery (con documentación)[/bold magenta]")
            discovery = run_discovery(target, target_info, config)
            results["discovery"] = discovery

    # ── Audit ─────────────────────────────────────────────────
    console.print("\n[bold magenta]━━━ Greybox API — Security Audit[/bold magenta]")
    audit = run_audit(discovery, config)
    results["audit"] = audit

    # Candidato de "endpoint de datos conocido" para el submodo 3 (Ambos):
    # permite al SSO audit verificar que el token deja de funcionar tras
    # logout/revocación, no solo que esos endpoints existen. Se elige el
    # primer endpoint autenticado (no público, no runtime_generated) —
    # no hace falta que ya haya funcionado con el token, el propio check
    # de invalidación comprueba esto antes de sacar ninguna conclusión.
    candidate = next(
        (ep for ep in discovery.get("endpoints", [])
         if not ep.get("intentionally_public") and not ep.get("runtime_generated")),
        None
    )
    if candidate:
        config["_greybox_data_endpoint"] = candidate.get("full_url")


# ── SSO / OAuth2 audit ─────────────────────────────────────────

def _run_sso_audit(target: str, target_info: dict, config: dict, results: dict):
    """Delega la auditoría OAuth2/OIDC en modules/oauth_audit.py."""
    from modules.oauth_audit import run_sso_audit

    results["sso_audit"] = run_sso_audit(target, config)



# ── Helpers ───────────────────────────────────────────────────

def _export_json(results: dict, config: dict):
    """Exporta discovery y audit como JSON con nombre base_name + run_id."""
    import json, os
    base_name  = config.get("base_name", "greybox")
    report_dir = config.get("report_dir", "./reports/")
    os.makedirs(report_dir, exist_ok=True)

    discovery = results.get("discovery", {})
    audit     = results.get("audit", {})

    # api_discovery.json — endpoints con sources
    discovery_export = {
        "run_id":    config.get("run_id", ""),
        "target":    config.get("command", "").split()[1] if config.get("command") else "",
        "sources":   discovery.get("sources", {}),
        "endpoints": [
            {
                "method":               ep.get("method"),
                "path":                 ep.get("path"),
                "full_url":             ep.get("full_url"),
                "sources":              ep.get("sources", [ep.get("source", "unknown")]),
                "intentionally_public": ep.get("intentionally_public", False),
                "auth_needed":          ep.get("auth_needed", True),
                "name":                 ep.get("name", ""),
            }
            for ep in discovery.get("endpoints", [])
        ],
        "swagger_found": discovery.get("swagger_found", False),
        "graphql_found": discovery.get("graphql_found", False),
        "wsdl_found":    discovery.get("wsdl_found", False),
    }

    # api_audit.json — hallazgos con evidencia
    audit_export = {
        "run_id":             config.get("run_id", ""),
        "profile":            audit.get("profile", "normal"),
        "endpoints_audited":  audit.get("endpoints_audited", 0),
        "endpoints_open":     audit.get("endpoints_open", 0),
        "findings":           audit.get("findings", []),
        "sso_findings":       results.get("sso_audit", {}).get("findings", []),
    }

    disc_path  = f"{report_dir}{base_name}_api_discovery.json"
    audit_path = f"{report_dir}{base_name}_api_audit.json"

    try:
        with open(disc_path, "w", encoding="utf-8") as f:
            json.dump(discovery_export, f, indent=2, ensure_ascii=False, default=str)
        console.print(f"  [green]✓[/green] Discovery JSON: [underline]{disc_path}[/underline]")
    except Exception as e:
        console.print(f"  [yellow]![/yellow] Error exportando discovery JSON: {e}")

    try:
        with open(audit_path, "w", encoding="utf-8") as f:
            json.dump(audit_export, f, indent=2, ensure_ascii=False, default=str)
        console.print(f"  [green]✓[/green] Audit JSON:     [underline]{audit_path}[/underline]")
    except Exception as e:
        console.print(f"  [yellow]![/yellow] Error exportando audit JSON: {e}")


def _submode_name(submode: int) -> str:
    return {1: "API audit", 2: "SSO / OAuth2 audit", 3: "API + SSO"}.get(submode, "?")


def _ask_token(base_url: str = "", hint_client_id: str = "",
               hint_client_secret: str = "", hint_token_endpoint: str = "",
               label: str = "") -> str:
    """
    Pregunta credenciales de autenticación — soporta cuatro opciones:
    1. Bearer token directo (JWT o API key)
    2. Client Credentials (client_id + client_secret → intercambio automático)
    3. Sin autenticación
    4. Ayuda guiada — para quien no tiene token y no sabe cómo conseguirlo
       (p.ej. servidores OAuth2 que no soportan Client Credentials porque
       validan personas reales — solo authorization_code, que requiere
       login real de un usuario). Muestra los pasos y vuelve a preguntar
       el método.
    Los hints pre-rellenan campos si ya vienen del .env.
    label: contexto a mostrar ("API" / "SSO") para no confundir cuál de
    los dos bloques de credenciales se está pidiendo en cada momento.
    """
    prefix = f" ({label})" if label else ""
    while True:
        console.print(f"\n[dim]¿Cómo quieres autenticarte{prefix}?[/dim]")
        console.print("  [bold cyan][1][/bold cyan] Bearer token directo  [dim](JWT o API key)[/dim]")
        console.print("  [bold cyan][2][/bold cyan] Client ID + Secret    [dim](intercambio automático → Bearer)[/dim]")
        if hint_client_id or hint_client_secret:
            console.print(
                f"  [dim]       → parcialmente configurado en .env: "
                f"{'client_id ✓' if hint_client_id else 'client_id ✗'}  "
                f"{'client_secret ✓' if hint_client_secret else 'client_secret ✗'}[/dim]"
            )
        console.print("  [bold cyan][3][/bold cyan] Sin autenticación     [dim](solo endpoints públicos)[/dim]")
        console.print("  [bold cyan][4][/bold cyan] No tengo token y no sé cómo conseguirlo  [dim](ver ayuda)[/dim]")

        try:
            choice = Prompt.ask("  [magenta]Método[/magenta]", choices=["1", "2", "3", "4"], default="3")
        except Exception:
            return ""

        if choice == "1":
            try:
                token = Prompt.ask("  [magenta]Token[/magenta]", password=True, default="")
                return token.strip()
            except Exception:
                return ""

        elif choice == "2":
            return _client_credentials_flow(
                base_url=base_url,
                client_id=hint_client_id,
                client_secret=hint_client_secret,
                token_endpoint=hint_token_endpoint,
            )

        elif choice == "4":
            _show_token_help(base_url)
            continue  # vuelve a preguntar el método, ahora con el token ya en mano

        return ""


def _show_token_help(base_url: str = ""):
    """
    Guía paso a paso para conseguir un access_token manualmente vía el
    flujo authorization_code — necesaria para IdPs que no soportan Client
    Credentials porque validan la identidad de una persona real (no tiene
    sentido un flujo máquina-a-máquina sin usuario en ese caso).
    Genérica: sirve para cualquier servidor OAuth2/OIDC.
    """
    target_hint = base_url or "https://tu-servidor-oauth2.ejemplo"
    console.print(Panel.fit(
        "[bold]Cómo conseguir un token manualmente (flujo authorization_code)[/bold]\n\n"
        "Necesitas: un [bold]client_id[/bold] registrado (y su [bold]client_secret[/bold] "
        "si el servidor lo requiere) y una [bold]redirect_uri[/bold] registrada junto a él.\n\n"
        "[bold cyan]1.[/bold cyan] Abre en el navegador (sustituye TU_CLIENT_ID y TU_REDIRECT):\n"
        f"   [dim]{target_hint}/o/oauth2/auth?response_type=code&client_id=TU_CLIENT_ID"
        "&redirect_uri=TU_REDIRECT&scope=openid&state=test123[/dim]\n"
        "   [dim](si no conoces la ruta exacta de tu servidor, prueba /oauth2/authorize "
        "o consulta su documentación)[/dim]\n\n"
        "[bold cyan]2.[/bold cyan] Completa el login normal (usuario/contraseña, SMS, "
        "certificado... lo que pida ese servidor)\n\n"
        "[bold cyan]3.[/bold cyan] El navegador te redirige a tu redirect_uri con "
        "[dim]?code=XXXX&state=test123[/dim] en la URL — cópialo de la barra de "
        "direcciones aunque no haya nada escuchando en esa redirect_uri\n\n"
        "[bold cyan]4.[/bold cyan] Cambia ese código por un token, con curl:\n"
        "   [dim]curl -X POST " + target_hint + "/o/oauth2/token \\\n"
        "     -d grant_type=authorization_code \\\n"
        "     -d code=XXXX \\\n"
        "     -d client_id=TU_CLIENT_ID \\\n"
        "     -d client_secret=TU_CLIENT_SECRET \\\n"
        "     -d redirect_uri=TU_REDIRECT[/dim]\n\n"
        "[bold cyan]5.[/bold cyan] La respuesta trae el [bold]access_token[/bold] — "
        "ese es el que introduces en la opción [1] Bearer token directo",
        border_style="yellow",
        title="[yellow]Ayuda — obtener token[/yellow]",
    ))


def _client_credentials_flow(base_url: str = "", client_id: str = "",
                              client_secret: str = "", token_endpoint: str = "") -> str:
    """
    Flujo OAuth2 Client Credentials.
    Puede llamarse con parámetros directos (desde .env/config)
    o de forma interactiva (desde el prompt).
    """
    interactive = not (client_id and client_secret)

    if interactive:
        try:
            # Si ya viene client_id de config, no preguntar
            if not client_id:
                client_id = Prompt.ask("  [magenta]Client ID[/magenta]", default="")
            else:
                console.print(f"  [dim]Client ID: {client_id} (desde .env)[/dim]")
            if not client_id.strip():
                return ""

            # Si ya viene client_secret de config, no preguntar
            if not client_secret:
                client_secret = Prompt.ask("  [magenta]Client Secret[/magenta]", password=True, default="")
            else:
                console.print("  [dim]Client Secret: configurado en .env[/dim]")
            if not client_secret.strip():
                return ""

            # Token endpoint — solo preguntar si no viene de config
            if not token_endpoint:
                console.print(
                    "\n  [dim]Token endpoint — deja en blanco para autodescubrir[/dim]\n"
                    "  [dim]Ejemplos:[/dim]\n"
                    "  [dim]· /oauth/token[/dim]\n"
                    "  [dim]· /o/oauth2/token[/dim]\n"
                    "  [dim]· /auth/realms/myrealm/protocol/openid-connect/token[/dim]"
                )
                token_endpoint = Prompt.ask("  [magenta]Token endpoint[/magenta]", default="")
        except Exception:
            return ""

    console.print("  [dim]Solicitando token...[/dim]")

    import httpx as _httpx

    # Si no informó endpoint, intentar autodescubrir
    if not token_endpoint.strip():
        token_endpoint = _autodiscover_token_endpoint(base_url)
        if token_endpoint:
            console.print(f"  [dim]Endpoint detectado: {token_endpoint}[/dim]")
        else:
            console.print("  [yellow]![/yellow] No se pudo autodescubrir el token endpoint.")
            console.print("  [dim]Introduce el endpoint manualmente con --token o vuelve a ejecutar.[/dim]")
            return ""

    try:
        resp = _httpx.post(
            token_endpoint.strip(),
            data={
                "grant_type":    "client_credentials",
                "client_id":     client_id.strip(),
                "client_secret": client_secret.strip(),
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=15,
            verify=False,
            follow_redirects=True,
        )

        if resp.status_code == 200:
            data = resp.json()
            token = data.get("access_token") or data.get("token") or data.get("id_token")
            if token:
                token_type = data.get("token_type", "Bearer")
                expires_in = data.get("expires_in", "?")
                console.print(
                    f"  [green]✓[/green] Token obtenido "
                    f"[dim](tipo: {token_type}, expira en: {expires_in}s)[/dim]"
                )
                return token
            else:
                console.print(f"  [yellow]![/yellow] Respuesta 200 pero sin access_token. Campos: {list(data.keys())}")
                return ""
        else:
            console.print(
                f"  [yellow]![/yellow] Error al obtener token: HTTP {resp.status_code}\n"
                f"  [dim]{resp.text[:200]}[/dim]"
            )
            return ""

    except Exception as e:
        console.print(f"  [yellow]![/yellow] Error en el intercambio de credenciales: {e}")
        return ""


def _autodiscover_token_endpoint(base_url: str) -> str:
    """
    Intenta autodescubrir el token endpoint:
    1. Consulta /.well-known/openid-configuration
    2. Prueba paths comunes
    """
    import httpx as _httpx

    if not base_url:
        return ""

    base = base_url.rstrip("/")

    # Paso 1 — OpenID Connect discovery
    try:
        resp = _httpx.get(
            f"{base}/.well-known/openid-configuration",
            timeout=8, verify=False, follow_redirects=True
        )
        if resp.status_code == 200:
            data = resp.json()
            endpoint = data.get("token_endpoint")
            if endpoint:
                return endpoint
    except Exception:
        pass

    # Paso 2 — Paths comunes
    # Lista compartida con modules/oauth_audit.py — antes había dos listas
    # de paths OAuth2 mantenidas por separado con solapamiento parcial.
    from modules.oauth_audit import OAUTH_ENDPOINT_PATHS
    common_paths = OAUTH_ENDPOINT_PATHS

    for path in common_paths:
        try:
            resp = _httpx.post(
                f"{base}{path}",
                data={"grant_type": "client_credentials"},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=5, verify=False
            )
            # 400/401 indica que el endpoint existe pero falta auth
            if resp.status_code in (400, 401):
                return f"{base}{path}"
        except Exception:
            continue

    return ""


def _ask_env_file() -> str:
    """Pregunta la ruta al fichero de entorno Postman."""
    try:
        path = Prompt.ask("  [magenta]Entorno Postman[/magenta]", default="")
        return path.strip()
    except Exception:
        return ""


def _ask_api_docs() -> list:
    """Pregunta rutas a ficheros de documentación API — acepta múltiples."""
    docs = []
    i = 1
    while True:
        try:
            path = Prompt.ask(
                f"  [magenta]Fichero {i}[/magenta]",
                default=""
            )
            path = path.strip()
            if not path:
                break
            docs.append(path)
            i += 1
        except Exception:
            break
    return docs


def _add_finding(results: dict, finding: dict):
    """Añade finding evitando duplicados por título."""
    existing = {f["title"] for f in results["findings"]}
    if finding["title"] not in existing:
        results["findings"].append(finding)
