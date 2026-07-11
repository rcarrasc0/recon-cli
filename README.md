[![GitHub release](https://img.shields.io/github/v/release/rcarrasc0/recon-cli)](https://github.com/rcarrasc0/recon-cli/releases)

```text
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗      ██████╗██╗     ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║     ██╔════╝██║     ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║     ██║     ██║     ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║     ██║     ██║     ██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║     ╚██████╗███████╗██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝      ╚═════╝╚══════╝╚═╝

   recon-cli · External Attack Surface Recon + API/OAuth2 Audit
```

Herramienta CLI de reconocimiento y auditoría de seguridad, con dos modalidades:
**BLACKBOX** (sin credenciales, superficie de ataque externa — EASM) y
**GREYBOX** (con credenciales, auditoría de APIs REST/SOAP y flujos OAuth2/OIDC).
Automatiza OSINT, enumeración, análisis de seguridad y auditoría de APIs autenticadas,
generando informes técnicos en PDF con correlación CVE/CVSS y MITRE ATT&CK.

------------------------------------------------------------

Casos de uso

- Auditorías externas sin credenciales (BLACKBOX)
- Auditoría de APIs REST/SOAP con token o credenciales OAuth2 (GREYBOX)
- Revisión de flujos OAuth2/OIDC — validación de tokens, open redirect (GREYBOX)
- Validación de exposición de activos
- Preparación de pentests
- Monitorización básica de superficie externa
- Informes alineados con MITRE ATT&CK para analistas y CISO

------------------------------------------------------------

Concepto y propósito

El proyecto nace con el objetivo de automatizar tareas recurrentes de pentesting en fase de reconocimiento (recon), centralizando múltiples técnicas y herramientas en un único flujo controlado. El modo Greybox amplía esto con auditoría autenticada de APIs, extendiendo el alcance de reconocimiento pasivo a verificación activa de controles de autorización.

El objetivo no es la explotación, sino:

- Mapear superficie de ataque externa
- Identificar exposición de activos
- Analizar configuraciones públicas
- Detectar WAF/CDN y su configuración (Cloudflare, AWS, Azure)
- Detectar versiones de servicios expuestos (nmap -sV)
- Priorizar riesgos mediante CVE/CVSS
- **(Greybox)** Descubrir y auditar endpoints de API — autenticación, IDOR/BOLA, exposición de datos
- **(Greybox)** Verificar la robustez de flujos OAuth2/OIDC, incluida la validez real del token aportado
- Generar informes estructurados, con la misma historia contada en consola, JSON y PDF

------------------------------------------------------------

Filosofía de diseño

- Modularidad — cada fase es un módulo independiente
- Scope awareness — separación estricta endpoint vs dominio raíz
- Trazabilidad — Run ID, log completo y metadatos por ejecución
- Resiliencia — fallback automático NVD → CIRCL Vulnerability-Lookup
- Criterio conservador en MITRE — precisión antes que cobertura
- Sin dependencias de APIs externas innecesarias
- Enfoque práctico orientado a pentesting real
- **Confianza explícita** — los hallazgos heurísticos (Greybox) declaran su nivel de confianza (Alta/Media/Baja) en vez de mezclarlo con la severidad
- **Orquestación separada de la auditoría** — cada dominio de auditoría vive en su propio módulo (`api_audit.py`, `oauth_audit.py`); los orquestadores (`greybox.py`) solo coordinan menú, credenciales y ejecución
- **Correlación después de generación** — MITRE ATT&CK correlaciona hallazgos, no los genera; se ejecuta siempre después de todas las fases que sí generan hallazgos (incluida Greybox), nunca antes

------------------------------------------------------------

Arquitectura

El flujo sigue un modelo en pipeline, con una rama adicional para el modo greybox que se reincorpora antes de la correlación final:

```
OSINT → Enumeración → SSL/TLS → Cabeceras → WAF/CDN → CVEs
                                                          │
                                    (--scope greybox) → Greybox
                                                          │      (API Discovery + API Audit
                                                          │       y/o OAuth2/OIDC Audit,
                                                          │       según submodo elegido)
                                                          ▼
                                                  MITRE ATT&CK
                                          (correlaciona TODOS los hallazgos
                                           generados hasta este punto)
                                                          │
                                                          ▼
                                        Resumen consolidado de hallazgos
                                                          │
                                                          ▼
                                                    Informe PDF
```

Cada fase es independiente pero encadenada, permitiendo: modularidad, extensibilidad y mantenimiento sencillo. MITRE ATT&CK se ejecuta siempre en última posición entre las fases de análisis porque correlaciona hallazgos ya existentes — incluye por tanto los de Greybox cuando aplica, en una sola pasada.

------------------------------------------------------------

Características

- **OSINT** — WHOIS, DNS, AXFR, ASN/BGP, crt.sh con separación automática endpoint/dominio raíz
- **Shodan** (opcional vía API key)
- **Leak-Lookup** (opcional vía API key)
- **Enumeración** — subdominios, hosts activos, fingerprinting con extracción de versión confirmada
- **nmap -sV** — detección de versiones de servicios expuestos con contador diferenciado
- **SSL/TLS** — análisis nativo + nmap ssl-enum-ciphers, diferenciación RSA/ECDSA/DSA
- **Cabeceras HTTP, CSP y HSTS**
- **WAF/CDN** — Cloudflare, AWS WAF/CloudFront, Azure Front Door/WAF, Akamai, Fastly, Sucuri, Imperva
- **CVEs** — NVD/NIST con fallback automático a CIRCL Vulnerability-Lookup, solo versión confirmada
- **MITRE ATT&CK** — táctica + técnica + sub-técnica, mappings conservadores, sin API externa, ejecutado tras Greybox para cubrir todos los hallazgos
- **Separación endpoint / dominio raíz** — SPF, DMARC y WHOIS nunca afectan el scoring principal
- **Trazabilidad completa** — Run ID, log detallado, metadatos de ejecución en PDF con hora real de generación
- **Informe PDF** — paginación consistente (cada sección arranca en página nueva, subsecciones nunca se parten de su tabla), riesgo global real, sección metadatos al final
- **Resumen consolidado en consola** — se imprime una sola vez, al final del análisis (tras Greybox y MITRE), con los mismos contadores que el PDF y el JSON
- **API Discovery** — Postman, OpenAPI/Swagger, spider activo (119 paths, vocabulario SSI/VC/Wallet incluido)
- **API Audit** — autenticación, IDOR, BOLA, BFLA, Mass Assignment, Excessive Data Exposure, rate limiting, métodos no documentados
- **Propagación de endpoints públicos** — un endpoint confirmado público (documentado, o verificado con token) propaga esa condición a otras instancias del mismo patrón de path descubiertas solo por spider, evitando falsos positivos sobre variantes no documentadas de un recurso ya conocido
- **OAuth2/OIDC Audit** — discovery en 3 niveles, validación activa del token contra el servidor (`userinfo_endpoint`), invalidación tras logout/revocación, open redirect, protección anti-automatización
- **Nivel de confianza e impacto por hallazgo** — checks heurísticos declaran Alta/Media/Baja (independiente del CVSS) y, cuando aplica, escalada horizontal/vertical
- **Cobertura de pruebas y glosario** — el informe documenta todos los checks ejecutados (API y SSO, con o sin hallazgo) y define en lenguaje llano los términos técnicos usados
- **Detalle de hallazgos por submodo** — tanto la auditoría API como la OAuth2/OIDC tienen su propia tabla-índice de hallazgos (severidad, confianza) dentro de la sección Greybox del PDF

------------------------------------------------------------

Estructura del proyecto

```text
recon-cli/
├── main.py                Entry point CLI
├── config.py               Carga de entorno y configuración
├── version.py               Fuente única de verdad para el versionado
├── modules/
│   ├── osint.py             WHOIS, DNS, AXFR, crt.sh, ASN
│   ├── leaks.py             Leak-Lookup
│   ├── shodan_scan.py       Shodan
│   ├── enum.py               Subdominios, tecnologías y nmap -sV
│   ├── ssl_tls.py           SSL/TLS (análisis nativo + nmap)
│   ├── headers.py           Cabeceras HTTP, CSP, HSTS
│   ├── waf_cdn.py           Detección WAF/CDN (Cloudflare, AWS, Azure...)
│   ├── cves.py               CVEs (NVD/NIST) con retry y warning
│   ├── mitre.py               Correlación MITRE ATT&CK (mappings conservadores)
│   ├── greybox.py            Orquestador greybox — menú, credenciales, submodos
│   ├── api_discovery.py      Discovery de endpoints (Postman/OpenAPI/Spider)
│   ├── api_audit.py          Auditoría de API — IDOR, BOLA, Mass Assignment, etc.
│   └── oauth_audit.py        Auditoría OAuth2/OIDC (submodo OAuth2/OIDC Audit)
├── report/
│   └── pdf_gen.py            Generación de informe PDF
├── reports/                  Directorio de salida (no versionado)
├── recon-exec.sh             Launcher CLI con validación de parámetros
├── .env.example               Plantilla de variables de entorno
├── requirements.txt           Dependencias Python
└── setup.sh                   Script de instalación completo
```
Los scripts `setup.sh` y `recon-exec.sh` automatizan completamente la instalación y ejecución, reduciendo la interacción manual del usuario.

Cada módulo es independiente y puede ampliarse sin afectar al pipeline.


### Gestión de versiones

La versión de recon-cli se define en un único fichero (`version.py`).

Esta información es utilizada automáticamente por:

- Banner de terminal
- Portada del informe PDF
- Pie de página del informe PDF (con la hora real de generación del informe)
- Componentes internos de la aplicación

Este enfoque evita inconsistencias entre versiones, elimina valores hardcodeados y simplifica el mantenimiento de futuras releases.

------------------------------------------------------------

Descarga

Última versión estable:

https://github.com/rcarrasc0/recon-cli/releases/latest

También puedes clonar el repositorio o descargar el código desde GitHub.

------------------------------------------------------------

Requisitos

- Python 3.11 recomendado
- nmap instalado
- testssl.sh disponible
- entorno Linux (Kali recomendado, probado en Kali Linux 2026)

------------------------------------------------------------

Instalación

```bash
git clone https://github.com/rcarrasc0/recon-cli.git
cd recon-cli
chmod +x setup.sh
./setup.sh
```

El script:

- detecta el OS
- instala dependencias del sistema
- crea el entorno virtual Python
- instala dependencias Python
- valida herramientas
- y empaqueta un ZIP de distribución.

------------------------------------------------------------

Configuración

Editar el fichero .env:

```env
SHODAN_API_KEY=
LEAKLOOKUP_API_KEY=
NVD_API_KEY=

REPORT_AUTHOR=
REPORT_CLASSIFICATION=

# ── Greybox — modo --scope greybox ────────────────────────
# GREYBOX_API_* → submodo [1] API audit. GREYBOX_SSO_* → submodo [2] SSO.
# Todas son opcionales: lo que falte se pedirá de forma interactiva.
GREYBOX_SUBMODE=

GREYBOX_API_TOKEN=
GREYBOX_API_CLIENT_ID=
GREYBOX_API_CLIENT_SECRET=
GREYBOX_API_TOKEN_ENDPOINT=
GREYBOX_API_DOC=
GREYBOX_API_ENV_FILE=
GREYBOX_API_PROFILE=normal

GREYBOX_SSO_TOKEN=
GREYBOX_SSO_CLIENT_ID=
GREYBOX_SSO_CLIENT_SECRET=
GREYBOX_SSO_TOKEN_ENDPOINT=
```

Detalle de cada campo y ejemplos de configuración según tu escenario: ver "Configuración Greybox — ejemplos prácticos" justo debajo.

------------------------------------------------------------

Configuración Greybox — ejemplos prácticos

Cuatro escenarios mínimos — copia el que se ajuste a tus credenciales y rellena solo esos campos, dejando el resto vacío.

**Escenario A — API con Client Credentials** (la API te ha dado un `client_id`/`client_secret` para que la herramienta obtenga el token ella sola)

```env
GREYBOX_API_CLIENT_ID=tu-client-id
GREYBOX_API_CLIENT_SECRET=tu-client-secret
```

**Escenario B — API con Bearer token directo** (ya tienes un token/API key fijo)

```env
GREYBOX_API_TOKEN=tu-token-o-api-key
```

**Escenario C — SSO/OAuth2 con Authorization Code** (el caso más común: el IdP valida personas reales, no soporta Client Credentials — obtienes el token manualmente vía login + curl, ver más abajo)

```env
GREYBOX_SSO_TOKEN=el-access-token-que-te-devuelve-el-idp
GREYBOX_SSO_CLIENT_ID=tu-client-id
```

*(`GREYBOX_SSO_CLIENT_ID` sin secret es seguro — no dispara ningún intercambio automático, solo lo reutiliza el check de open redirect para ser más realista. **No** añadas `GREYBOX_SSO_CLIENT_SECRET` aquí si tu IdP no soporta Client Credentials — dispararía un intento automático destinado a fallar.)*

**Escenario D — SSO/OAuth2 con Client Credentials** (solo si tu IdP sí lo soporta — no habitual en brokers de identidad de personas)

```env
GREYBOX_SSO_CLIENT_ID=tu-client-id
GREYBOX_SSO_CLIENT_SECRET=tu-client-secret
GREYBOX_SSO_TOKEN_ENDPOINT=
```

`GREYBOX_SSO_TOKEN_ENDPOINT` puede dejarse vacío para autodescubrir — solo rellénalo si el servidor no expone `/.well-known/openid-configuration` ni rutas OAuth2 estándar.

------------------------------------------------------------

Uso

```bash
./recon-exec.sh <dominio|IP> [opciones]
```

El launcher `recon-exec.sh`:

- valida el formato del target
- avisa de IPs privadas
- activa el entorno virtual
- y ejecuta el pipeline completo.

Opciones disponibles:

| Opción | Descripción |
|---|---|
| `--scope [blackbox\|greybox]` | Modalidad de análisis (default: blackbox) |
| `--api-token <token>` | (Greybox) Bearer token para la auditoría de API — alternativa a `GREYBOX_API_TOKEN` |
| `--api-doc <ruta>` | (Greybox) Colección Postman (`.json`) u OpenAPI/Swagger (`.yaml`/`.json`). Repetible para combinar varias fuentes |
| `--env-file <ruta>` | (Greybox) Entorno Postman (`.postman_environment.json`) para resolver variables `{{...}}` |
| `--api-profile [normal\|aggressive]` | (Greybox) Perfil de auditoría de API — controla la intensidad del check de rate limiting |
| `--skip-leaks` | Omitir Leak-Lookup |
| `--skip-shodan` | Omitir Shodan |
| `--skip-ssl` | Omitir SSL/TLS |
| `--skip-waf` | Omitir detección WAF/CDN |
| `--skip-cves` | Omitir CVEs |
| `--output <ruta.pdf>` | Ruta del informe PDF |
| `--verbose / -v` | Output detallado |

> El submodo SSO (`GREYBOX_SSO_*`) se configura solo vía `.env` por ahora — no tiene flags CLI equivalentes a `--api-token`/`--api-doc`.

> **`--scope greybox`** activa un menú guiado que pregunta el submodo (API audit / SSO audit / Ambos), el método de autenticación (Bearer token directo, Client Credentials OAuth2, o sin autenticación) y la documentación de API disponible. Cualquier credencial no aportada por flag o `.env` se pide de forma interactiva.
>
> *Nota de nomenclatura: el menú interactivo del CLI muestra la opción como "SSO audit" — esta documentación usa también "OAuth2/OIDC Audit" para describir el mismo submodo, porque refleja mejor su alcance real (validación de tokens y open redirect, no gestión completa de sesión SSO).*

Ejemplos de ejecución:

```bash
# Análisis completo (blackbox)
./recon-exec.sh example.com

# Con output detallado
./recon-exec.sh example.com --verbose

# Omitir Leak-Lookup y Shodan (sin API keys)
./recon-exec.sh example.com --skip-leaks --skip-shodan

# Sin API keys y con verbose
./recon-exec.sh example.com --skip-leaks --skip-shodan --verbose

# Omitir detección WAF/CDN
./recon-exec.sh example.com --skip-waf

# Omitir CVEs (útil si NVD está caído)
./recon-exec.sh example.com --skip-cves

# Ruta de salida personalizada
./recon-exec.sh example.com --output /tmp/informe.pdf

# Sobre una IP
./recon-exec.sh 1.2.3.4 --skip-leaks

# Greybox — API audit con colección Postman + entorno
./recon-exec.sh api.example.com --scope greybox \
  --api-doc ./mi-api.postman_collection.json \
  --env-file ./mi-entorno.postman_environment.json

# Greybox — API con token directo por CLI, sin documentación (spider)
./recon-exec.sh api.example.com --scope greybox --api-token "eyJhbGci..."

# Greybox — sin documentación, solo spider + token interactivo
./recon-exec.sh api.example.com --scope greybox
```

Tiempo estimado: 1–3 minutos dependiendo del target (blackbox); el modo greybox depende del número de endpoints descubiertos y puede tardar bastante más si el spider prueba su wordlist completa contra un target lento o con WAF.

------------------------------------------------------------

Fases del análisis

| # | Fase | Descripción |
|---|---|---|
| 1 | **OSINT & Reconocimiento** | WHOIS, DNS, AXFR, crt.sh, ASN/BGP |
| 2 | **Shodan** | Servicios expuestos, puertos, banners, CVEs indexados |
| 3 | **Leak-Lookup** | Credenciales y emails filtrados en brechas conocidas |
| 4 | **Enumeración & Descubrimiento** | Subdominios, hosts activos, fingerprinting, nmap -sV |
| 5 | **Análisis SSL/TLS** | Protocolos, cifrados, certificado, HSTS, vulnerabilidades |
| 6 | **Cabeceras HTTP & CSP** | Security headers, CSP, cookies, fugas de información |
| 7 | **Detección WAF/CDN** | Cloudflare, AWS WAF/CloudFront, Azure Front Door/WAF, Akamai... |
| 8 | **CVEs** | Búsqueda en NVD/NIST por productos y versiones detectadas |
| 9 *(solo `--scope greybox`)* | **Greybox** | Discovery (Postman/OpenAPI/Spider) + API Audit y/o OAuth2/OIDC Audit, según el submodo elegido |
| 9 (blackbox) / 10 (greybox) | **MITRE ATT&CK** | Correlación táctica + técnica + sub-técnica sobre **todos** los hallazgos generados hasta este punto, incluidos los de Greybox |
| 10 (blackbox) / 11 (greybox) | **Informe PDF** | Informe estructurado con hallazgos, CVSS, confianza y mitigaciones |

MITRE ATT&CK se numera después de Greybox porque correlaciona hallazgos ya existentes — no los genera. El resumen consolidado de hallazgos que ve el operador en consola se imprime justo después de esta fase, con el mismo recuento final que reflejan el JSON y el PDF.

WAF/CDN — vectores de detección pasiva

- Rangos IP estáticos (Cloudflare, AWS CloudFront, Azure Front Door)
- Rangos IP dinámicos en tiempo real (`ip-ranges.amazonaws.com`, ServiceTags de Microsoft)
- Fingerprinting de cabeceras HTTP (`CF-RAY`, `X-Amz-Cf-Id`, `X-Azure-Ref`, `X-AppGw-Trace-Id`...)
- Análisis de CNAME hacia dominios CDN (`cloudflare.net`, `cloudfront.net`, `azurefd.net`...)
- Comportamiento ante rutas inválidas (páginas de bloqueo WAF)

Proveedores: Cloudflare, AWS WAF, AWS CloudFront, Azure Front Door, Azure Application Gateway WAF, Azure CDN, Akamai, Fastly, Sucuri, Imperva, Barracuda, F5 BIG-IP, ModSecurity.

------------------------------------------------------------

Modo Greybox — API & OAuth2 Audit

Auditoría con credenciales que complementa el reconocimiento externo. Se activa con `--scope greybox` y ofrece tres submodos:

| Submodo | Qué hace |
|---|---|
| **[1] API audit** | Discovery + auditoría de endpoints REST/SOAP |
| **[2] OAuth2/OIDC Audit** *(el menú CLI aún la etiqueta como "SSO audit")* | Discovery de metadata OAuth2/OIDC, validación activa del token, y checks de robustez del flujo |
| **[3] Ambos** | API audit + OAuth2/OIDC Audit en una sola ejecución, con cobertura combinada en el mismo informe |

**Discovery de endpoints — tres fuentes combinables**

- **Postman** — parsea colecciones `.postman_collection.json` (v2.0/v2.1), resuelve variables `{{...}}` desde el entorno aportado y detecta `auth.type = noauth` para marcar endpoints públicos por diseño
- **OpenAPI / Swagger** — `.yaml` o `.json`, local o autodescubierto por el spider
- **Spider activo** — wordlist de 119 paths (incluye vocabulario SSI/VC/Wallet: issuance, verification, status_list, DID, trust registry) + crawl de HTML/JS

Los endpoints se deduplican por (método, path) fusionando las fuentes que los detectaron.

**Propagación de endpoints públicos por patrón de path**

Cuando un endpoint ya está confirmado como público por diseño (documentado con `auth.type = noauth`, o verificado por comportamiento durante el spider), y el spider descubre **otra instancia del mismo patrón de path** — mismo método, mismo path salvo un segmento numérico (típico en APIs con `service_id`/`tenant_id`/ID de recurso en la ruta) — esa segunda instancia hereda la condición de pública. Esto evita que variantes no documentadas de un recurso ya conocido (p.ej. una segunda entrada de un endpoint tipo `status_list`, pensado por especificación para ser público) se traten como un fallo de control de acceso solo por no estar listadas explícitamente en la documentación aportada.

**Variables Postman generadas en runtime**

Las colecciones OIDC4VCI/OAuth2 suelen generar variables dinámicamente durante la ejecución en Postman (`pm.environment.set()`) — `credential_offer_uri`, `token_endpoint`, etc. — que no existen en el fichero de entorno estático. recon-cli las detecta y marca como `runtime_generated`, excluyéndolas de la auditoría (evita peticiones fallidas en silencio y falsos "endpoint no documentado") y contándolas aparte en el informe.

**Checks de auditoría de API**

| Check | Qué detecta |
|---|---|
| Autenticación | Endpoint accesible sin token / token inválido aceptado |
| Métodos no documentados | PUT/DELETE/PATCH activos sobre un endpoint no documentado para ese método |
| IDOR | Respuesta distinta al probar el ID adyacente — **omitido/degradado en endpoints públicos** (ver más abajo) |
| BOLA | Respuesta distinta al probar IDs de otros tenants (0, 99, 9999) |
| BFLA | Función de nivel superior (`/admin`, `/internal`, `/management`...) accesible con el token de prueba aportado |
| Identificadores secuenciales enumerables | Endpoint público con ID secuencial — no es un fallo de acceso, pero permite inferir volumen de negocio |
| Mass Assignment | El servidor refleja valores privilegiados inyectados (`role`, `tenant_id`, `admin`) en el body |
| Excessive Data Exposure | Campos sensibles (contraseñas, tokens, claves) en la respuesta de endpoints GET autenticados y no públicos |
| Rate limiting | Ausencia de HTTP 429 / cabeceras `X-RateLimit-*` |
| Endpoint no documentado | Descubierto por el spider pero ausente de Postman/OpenAPI |
| GraphQL introspection | Introspection habilitada sin autenticación |
| WSDL / Swagger expuestos | Documentación técnica accesible sin autenticación |

**Endpoints de protocolo OAuth2/OIDC quedan excluidos de estos checks** — si el discovery de API encuentra un endpoint de protocolo (`/token`, `/authorize`, `/revoke`, `/logout`, `/userinfo`, `/.well-known/...`, generalmente vía spider), no se le aplican los checks de arriba. Un token endpoint, por diseño (RFC 6749 §3.2), se autentica con `client_id`/`client_secret` o un código en el body, no con un Bearer previo — probarlo con la lógica de "endpoint de negocio sin auth" genera un falso positivo. Estos endpoints ya están cubiertos, correctamente, por los checks dedicados del submodo OAuth2/OIDC.

**Impacto: escalada horizontal vs. vertical**

Los hallazgos de IDOR, BOLA y Mass Assignment incluyen un campo de impacto en lenguaje llano, además de la nomenclatura técnica: **horizontal** (acceso a datos de otro usuario/tenant con el mismo nivel de privilegio) o **vertical** (elevación a un rol de mayor privilegio). Mass Assignment se clasifica dinámicamente según qué valor se reflejó — `role`/`admin` inyectado = vertical; solo `tenant_id` sin tocar el rol = horizontal.

**IDOR en endpoints públicos e `intentionally_public`**

IDOR es por definición un fallo de *control de acceso*. Si el endpoint es público por diseño, no hay control de acceso que romper — cualquiera puede pedir cualquier ID intencionadamente. recon-cli distingue este caso: en vez de un IDOR de severidad alta, genera un hallazgo **INFO** separado ("Identificadores secuenciales enumerables"), reconociendo que el riesgo real es de otra naturaleza — inferencia de volumen/cardinalidad de negocio, no acceso indebido. El resto de checks que no dependen de control de acceso (exposición de datos, mass assignment, etc.) siguen aplicando igual, sea o no público el endpoint.

Esta distinción se apoya en el flag `intentionally_public`, que marca cualquier endpoint público — por Postman (`auth.type = noauth`), por comportamiento durante el spider (misma respuesta con y sin token), o por herencia de patrón de path desde otro endpoint ya confirmado como público (ver más arriba).

**Verificación de token — API**

Antes de lanzar el discovery, se verifica el token contra varias URLs de prueba genéricas (`/health`, `/api`, `/status`...) comparando la respuesta con y sin él. El resultado (válido / no concluyente) se muestra de forma visible en consola antes de continuar. Si no se puede verificar, se ofrece completar credenciales de forma interactiva sin perder lo ya configurado por `.env`.

**Checks de auditoría OAuth2/OIDC**

| Check | Qué detecta |
|---|---|
| Validación activa del token | Llamada real a `userinfo_endpoint` (OIDC Core §5.3) con el token aportado — confirma de forma visible si el servidor lo acepta antes de lanzar el resto de checks. Si el servidor no publica `userinfo_endpoint`, se informa explícitamente de que no hay validación activa posible |
| Verificación de expiración (local) | Decodifica el JWT aportado y avisa si ya está caducado — informativo, no depende de red |
| Endpoint accesible por HTTP | Token endpoint sin forzar HTTPS (excluye redirects correctos a HTTPS) |
| Token inválido aceptado | El token endpoint devuelve 200 con un `refresh_token` claramente inválido |
| Open redirect | `redirect_uri` no registrada aceptada — reutiliza el `client_id` real si está configurado |
| Logout / Revocación | Detección de los endpoints correspondientes (informativo) |
| Invalidación de token tras logout/revocación | Verifica que el token deja de funcionar de verdad tras logout/revocación (no solo que el endpoint existe) — usa como endpoint de datos el `userinfo_endpoint` si el servidor lo publica, o el endpoint descubierto durante el API audit en submodo 3 (Ambos) si no |
| Protección anti-automatización en login | Presencia de reCAPTCHA / reCAPTCHA Enterprise / hCaptcha / Cloudflare Turnstile en el formulario de login. No es un check de vulnerabilidad — documenta si el control sigue activo |

**Discovery en 3 niveles** — no depende solo de rutas conocidas

1. **Metadata estándar** (`/.well-known/openid-configuration`, RFC 8414) — si el servidor la publica, usa los endpoints exactos que declara (incluido `userinfo_endpoint`, usado para la validación activa del token), sean cuales sean sus rutas reales
2. **Wordlist conocida** — rutas habituales (Keycloak, Auth0, Okta...)
3. **Crawl léxico multi-nivel** — hasta 2 saltos desde la home, solo mismo dominio, buscando enlaces con pistas (`oauth`, `authorize`, `login`...) — última red de seguridad para entornos sin metadata ni convenciones de rutas

**Obtención manual de token — para IdPs sin Client Credentials**

Algunos proveedores de identidad (p.ej. brokers que validan personas reales, no aplicaciones máquina-a-máquina) no soportan el grant `client_credentials`. En esos casos hace falta un `access_token` obtenido una vez, a mano, vía el flujo `authorization_code` completo en el navegador. El menú interactivo de recon-cli (opción **[4] No tengo token y no sé cómo conseguirlo**, en el paso de autenticación) muestra los pasos exactos — genérico, no específico de ningún proveedor.

Nota de seguridad: si el formulario de login está protegido con CAPTCHA (ver check de arriba), este paso **no es automatizable** — es intencionado, es el control haciendo su trabajo. El login manual de 30 segundos en el navegador sigue siendo necesario; todo lo posterior (validación activa del token, exposición HTTP, open redirect, revocación) sí es 100% automático una vez se tiene el token.

**Nivel de confianza por hallazgo**

Los checks heurísticos (comportamiento, no hechos deterministas) incluyen un campo `confidence` (Alta / Media / Baja), visible como badge junto al CVSS en el PDF. Es una dimensión independiente de la severidad: indica cuánta verificación manual adicional requiere el hallazgo antes de priorizar su remediación. El Resumen Ejecutivo avisa automáticamente si hay hallazgos de confianza baja.

**Timeout adaptativo ante WAF**

Si se detecta un WAF delante del target, el spider reduce su timeout a 3 segundos (los paths bloqueados responden rápido) en vez de esperar el timeout general — evita que una auditoría con WAF tarde minutos en lugar de segundos.

**Cobertura de pruebas realizadas**

Un informe que solo lista hallazgos no distingue "no lo hemos comprobado" de "lo hemos comprobado y está bien". La sección Greybox del PDF incluye una tabla con **todos** los checks ejecutados — API y OAuth2/OIDC, combinados cuando el submodo es Ambos — tengan o no hallazgo, indicando si requieren sesión (token) o no, y el resultado concreto de cada uno, incluidos los que salen limpios.

**Detalle de hallazgos por submodo**

Además del recuento y la cobertura, tanto la auditoría API como la OAuth2/OIDC tienen su propia tabla-índice de hallazgos dentro de la sección Greybox del PDF (título, severidad, confianza), para localizarlos rápido sin tener que recorrer manualmente toda la sección de Hallazgos de Seguridad.

**Glosario de términos técnicos**

Al final de la sección Greybox del PDF, un glosario en lenguaje llano de IDOR, BOLA, BFLA, Mass Assignment, Excessive Data Exposure, Confianza e Impacto horizontal/vertical — para que cualquier lector del informe entienda los hallazgos sin necesitar documentación externa.

**Artefactos generados (modo greybox)**

Además del PDF y el `.log`, cada ejecución greybox genera:

- `[target]_[run_id]_api_discovery.json` — endpoints descubiertos, fuentes, metadatos
- `[target]_[run_id]_api_audit.json` — hallazgos de auditoría API y OAuth2/OIDC con evidencias

------------------------------------------------------------

Separación endpoint vs dominio raíz

recon-cli detecta automáticamente el dominio raíz mediante `tldextract` y separa los hallazgos en dos categorías:

- **Hallazgos de seguridad** — relativos al endpoint, contribuyen al scoring CVSS y al riesgo global
- **Sección "Análisis del Dominio Raíz"** — SPF, DMARC, WHOIS/ASN en sección separada, sin afectar el scoring

Esta separación es **siempre activa**, independientemente de si el target es un subdominio o el dominio raíz directamente. SPF y DMARC son configuraciones de correo, no de la aplicación web auditada, y nunca deben inflar el riesgo global de un análisis de superficie web.

Ejemplo:

```
Target: portal.miempresa.com
  → Hallazgos endpoint: SSL/TLS, cabeceras, WAF, CVEs
  → Dominio raíz: SPF/DMARC de miempresa.com (sección separada)

Target: miempresa.com
  → Hallazgos endpoint: SSL/TLS, cabeceras, WAF, CVEs
  → Dominio raíz: SPF/DMARC de miempresa.com (sección separada)
```

------------------------------------------------------------

Output

- **Informe PDF** en `reports/` con versión de herramienta en portada, y pie de página con la hora real de generación
- **Salida en consola** con progreso por fases
- **Resumen consolidado de hallazgos** por severidad (CRITICAL / HIGH / MEDIUM / LOW / INFO) — se imprime una única vez, al final del análisis (tras Greybox y MITRE), con el mismo recuento que el PDF y el JSON
- **Scoring CVSS** consolidado
- **Nivel de confianza** por hallazgo heurístico (Greybox)
- **Propuestas de mitigación** priorizadas
- **(Greybox)** JSON de discovery y de auditoría con evidencias completas

------------------------------------------------------------

Trazabilidad de ejecuciones

Cada ejecución genera un **Run ID** único con formato `YYYYMMDD-HHMMSS-XXXXXXXX` visible en:

- El panel de inicio en consola
- La portada del PDF
- La sección final "Metadatos de Ejecución" del PDF
- El fichero `.log` asociado
- **(Greybox)** Los ficheros `_api_discovery.json` y `_api_audit.json`

El `.log` contiene la salida completa y detallada de todas las fases — equivalente exacto a lo que el usuario ve en pantalla durante la ejecución — incluyendo tecnologías detectadas, consultas CVE, Greybox, correlación MITRE y el resumen consolidado final. Consola, `.log`, JSON y PDF están sincronizados: mismos contadores, misma duración, misma numeración de fases.

------------------------------------------------------------

Alcance y modelo de análisis

**BLACKBOX** — reconocimiento pasivo o de bajo impacto, sin credenciales.

**Incluye:** información pública (DNS, WHOIS, certificados), consultas a fuentes abiertas (NVD, Shodan, crt.sh), análisis de configuraciones accesibles.

**GREYBOX** — auditoría activa con credenciales legítimas aportadas por el operador (Bearer token o Client Credentials OAuth2). Incluye peticiones de escritura controladas (p.ej. Mass Assignment envía un POST/PUT con campos privilegiados para verificar si el servidor los acepta).

**Ninguno de los dos modos incluye:** exploits, payloads maliciosos, fuerza bruta, acceso no autorizado, movimiento lateral ni escalada de privilegios real.

> Uso únicamente sobre activos propios o con autorización explícita. El modo greybox realiza peticiones de escritura con las credenciales aportadas — asegúrate de que el entorno auditado (idealmente PRE/staging) tolera estas pruebas.

------------------------------------------------------------

Resiliencia CVEs — Fallback NVD → CIRCL

Cuando NVD/NIST falla repetidamente (timeout, HTTP 503), recon-cli activa automáticamente un fallback a **CIRCL Vulnerability-Lookup** (`vulnerability.circl.lu`):

```
NVD/NIST
↓ 3 errores consecutivos (timeout / 5xx)
CIRCL Vulnerability-Lookup — gratuito, sin autenticación
↓
continuar análisis sin interrupción
```

Solo se envían a correlación CVE los productos con **versión confirmada**. Tecnologías detectadas sin versión (jQuery sin versión, Bootstrap sin versión) quedan excluidas para evitar falsos positivos.

**Por qué CIRCL y no otras alternativas:**

| Fuente | Búsqueda por producto | Sin auth | Fiabilidad | Decisión |
|---|---|---|---|---|
| NVD/NIST | ✓ keywordSearch | ✓ (con key opcional) | Media (timeouts frecuentes) | Primaria |
| CIRCL Vulnerability-Lookup | ✓ /api/search/{vendor}/{product} | ✓ | Alta | Fallback |
| MITRE CVE Services | ✗ No soporta búsqueda por producto | ✓ | — | Descartada (devuelve HTTP 400) |
| CVE.org | ✗ Solo lookup por CVE-ID | ✓ | Alta | No apta para búsqueda |

------------------------------------------------------------

Correlación MITRE ATT&CK

Mapeo automático de hallazgos con criterio conservador — se prefieren pocos mappings sólidos antes que muchos discutibles. Se asigna sub-técnica solo cuando la correspondencia es directa y justificable. Se ejecuta tras Greybox, correlacionando en una sola pasada todos los hallazgos de la ejecución (blackbox + greybox cuando aplica).

| Hallazgo | Táctica · Técnica |
|---|---|
| Endpoint sin autenticación | Initial Access · T1190 (Exploit Public-Facing Application) |
| IDOR / BOLA | Collection · T1213 (Data from Information Repositories) |
| BFLA | Privilege Escalation · T1548 (Abuse Elevation Control Mechanism) |
| Mass Assignment | Privilege Escalation · T1548 (Abuse Elevation Control Mechanism) |
| Identificadores secuenciales enumerables | Reconnaissance · T1595.003 (Wordlist Scanning) |
| Endpoint no documentado / shadow API | Reconnaissance · T1595.003 (Wordlist Scanning) |
| Excessive Data Exposure | Collection · T1213 (Data from Information Repositories) |
| OAuth2 accesible por HTTP | Collection · T1557 (Adversary-in-the-Middle) |
| Open redirect OAuth2 | Credential Access · T1528 (Steal Application Access Token) |
| Token inválido/expirado aceptado | Credential Access · T1550.001 (Application Access Token) |

*Nota de transparencia*: los mappings de Mass Assignment/BFLA (T1548) y de identificadores secuenciales (T1595.003, compartido con shadow APIs) son las mejores aproximaciones disponibles en ATT&CK Enterprise, no ajustes perfectos — no existe una técnica dedicada a "abuso de parámetros de API" en el framework. Se documentan así a propósito en vez de forzar una sub-técnica más específica que no aplicaría de verdad. Algunos mappings de hallazgos heurísticos de desviación de estándar (p.ej. respuestas de error con código HTTP no convencional) están pendientes de revisión metodológica en una futura versión.

El informe incluye resumen en el ejecutivo, badge por hallazgo y sección dedicada al final.

------------------------------------------------------------

Estructura del informe PDF

| # | Sección | Siempre presente |
|---|---|---|
| 1 | Resumen Ejecutivo | ✓ |
| 2 | Alcance y Metodología | ✓ |
| 3 | Hallazgos de Seguridad | ✓ |
| 4 | Análisis SSL/TLS | ✓ |
| 5 | Cabeceras HTTP | ✓ |
| 6 | Detección WAF/CDN | ✓ |
| 7 | OSINT & Reconocimiento | ✓ |
| 8 | Análisis del Dominio Raíz | Solo si hay hallazgos de dominio raíz |
| 9 | Análisis Greybox | Solo con `--scope greybox` |
| 10 | CVEs Identificados | ✓ (placeholder si no hay resultados) |
| 11 | Tabla CVSS Consolidada | Solo si hay hallazgos con CVSS |
| 12 | Correlación MITRE ATT&CK | Solo si hay correlaciones |
| 13 | Propuestas de Mitigación | ✓ |
| 14 | Metadatos de Ejecución | ✓ |

Las secciones 8-14 se numeran dinámicamente según qué condicionales aplican en cada ejecución — un informe blackbox sin greybox ni dominio raíz, por ejemplo, tendría CVEs en la sección 8, no en la 10. El orden de construcción (dominio raíz → greybox → CVEs → CVSS → MITRE → mitigación → metadatos) es siempre el mismo; solo cambia la numeración según qué secciones existan.

La sección "2.2 Metodología" describe las fases realmente ejecutadas, en el mismo orden y con la misma numeración que usa la consola — incluida la posición de Greybox justo antes de MITRE ATT&CK.

La sección "Análisis Greybox" incluye, según el submodo, resumen y detalle de hallazgos de API, resumen y detalle de hallazgos OAuth2/OIDC, matriz de cobertura combinada y glosario técnico común.

Cada sección principal arranca siempre en página nueva, sin excepciones (incluida Metadatos de Ejecución); las subsecciones nunca se separan de su tabla o contenido asociado. El pie de página final indica la hora real en la que se generó el informe.

------------------------------------------------------------

Cálculo de riesgo global

El riesgo global es la **severidad más alta encontrada entre los hallazgos del endpoint**, sin ponderaciones. SPF, DMARC y hallazgos de dominio raíz no participan en este cálculo.

| Severidad más alta | Riesgo global |
|---|---|
| CRITICAL | CRÍTICO |
| HIGH | ALTO |
| MEDIUM | MEDIO |
| LOW | BAJO |
| Solo INFO | INFORMATIVO |

------------------------------------------------------------

Limitaciones

- La correlación CVE solo se realiza cuando existe una versión suficientemente fiable de la tecnología detectada.
- Las tecnologías sin versión confirmada se omiten de NVD para reducir falsos positivos.
- Dependencia de APIs externas (Shodan, NVD, crt.sh, Leak-Lookup)
- NVD puede estar saturado — usar `--skip-cves` si no es prioritario
- No valida explotación real
- Resultados orientativos, no definitivos
- **(Greybox)** El discovery vía OpenAPI/Swagger solo se ha probado con ficheros locales, no validado combinando varios `--api-doc` en la misma ejecución
- **(Greybox)** El check de rate limiting testea un único endpoint (el primero del discovery), no es representativo de toda la API — confidence Baja por diseño
- **(Greybox)** El menú interactivo del CLI sigue mostrando "SSO audit" en vez de "OAuth2/OIDC Audit" — solo nomenclatura, sin impacto funcional (ver nota en la sección Uso)
- **(Greybox)** La validación activa del token OAuth2/OIDC depende de que el servidor publique `userinfo_endpoint`. Si no lo publica, no hay forma estándar de validar el token contra el servidor antes de lanzar el resto de checks — solo queda disponible el decode local del JWT (informativo, no depende de red)
- **(Greybox)** El check de invalidación de token tras logout/revocación necesita un endpoint de datos contra el que probar — se obtiene de `userinfo_endpoint` si el servidor lo publica, o del API audit en submodo 3 (Ambos) si no. Sin ninguno de los dos, el check no se ejecuta

------------------------------------------------------------

Validación de campo — submodo OAuth2/OIDC

El submodo OAuth2/OIDC Audit se ha validado en campo, en varias ejecuciones reales contra un proveedor OAuth2/OIDC de producción-pre: flujo `authorization_code` completo (login real de usuario, intercambio del código por token), discovery de endpoints, validación activa del token contra el servidor, logout, revocación, open redirect, y verificación de invalidación de token tras logout/revocación. Estas ejecuciones reales sirvieron para detectar y corregir varios falsos positivos genuinos — no solo revisión de código sin ejecución real.

Recomendación general (aplica a cualquier submodo, no solo OAuth2/OIDC): revisa los hallazgos antes de incluirlos en un informe a cliente, como con cualquier herramienta de escaneo automatizado.

------------------------------------------------------------

## Troubleshooting

- **Pillow error (Python 3.13)**

Error:
Failed to build Pillow

Solución:
```
pip install "Pillow>=11.2.1"
```

- **pydantic-core / Rust error**

Error:
Failed building wheel for pydantic-core

Solución:
```
Usar Python 3.11 o: pip install pydantic==1.10.14
```

- **Dependency conflicts (ResolutionImpossible)**

Causa:
Versiones fijadas incompatibles

Solución:
Eliminar versiones fijas en requirements.txt

- **RequestsDependencyWarning**

Solución:
```
pip install --upgrade requests urllib3 charset_normalizer
pip check
```

- **crt.sh timeout**

Causa:
Servicio externo inestable

Solución:
Ignorar o reintentar

- **ReportLab Invalid color**

Error:
Invalid color value

Solución:
Cambiar:
```c.hexval()[1:]```
por:
```c.hexval()[2:]```

- **Python 3.13 incompatibilidades**

Algunas librerías aún no están totalmente adaptadas.

Recomendación:
usar Python 3.11

- **CVEs siempre a 0**

Solución:
```
NVD saturado o con timeouts — reintentar más tarde o añadir NVD_API_KEY en .env
```

- **(Greybox) Discovery sin resultados con token válido**

Causa:
El servidor bloquea el tráfico de descubrimiento (WAF, paths no estándar, API privada)

Solución:
Aportar documentación (`--api-doc`) para continuar la auditoría sin depender del spider

- **(Greybox) Endpoints con "variables runtime (no auditados)" en el informe**

Causa:
La colección Postman genera variables dinámicamente (`pm.environment.set()`) que no existen en el fichero de entorno estático

Solución:
Es un comportamiento esperado, no un error — esos endpoints se excluyen de la auditoría automáticamente. Revisar `_api_discovery.json` para ver qué variables quedaron sin resolver

- **(Greybox) "Validación activa del token" aparece como No ejecutado en la matriz de cobertura**

Causa:
El servidor OAuth2/OIDC no publica `userinfo_endpoint` en su metadata

Solución:
Es un comportamiento esperado — sin `userinfo_endpoint` no hay endpoint estándar contra el que validar el token activamente. Sigue disponible el decode local del JWT (aviso de caducidad, no depende de red)

------------------------------------------------------------

## Evolución del proyecto

- **v1.0.0** — Release inicial
- **v1.1.0** — WAF/CDN (Cloudflare, AWS) y `recon-exec.sh` con validación
- **v1.1.2** — nmap -sV, Azure WAF/CDN, resiliencia NVD
- **v1.1.3** — CVEs basados en versión confirmada
- **v1.1.4** — `version.py` como fuente única de versionado
- **v1.1.5** — Portada limpia, KPIs en Resumen Ejecutivo
- **v1.1.6** — MITRE ATT&CK, Run ID, trazabilidad completa, paginación PDF estabilizada
- **v1.2.0** — Modo Greybox: API Discovery, API Audit, OAuth2/OIDC Audit y Confidence Scoring
- **v1.2.1** — Greybox se ejecuta antes de la correlación MITRE ATT&CK (metodología alineada con el orden real de generación de hallazgos); validación activa del token OAuth2/OIDC contra `userinfo_endpoint`; propagación de endpoints públicos por patrón de path; resumen consolidado único al final de la ejecución; detalle de hallazgos y cobertura combinada API+SSO en el PDF; hora real de generación en metadatos y pie de página; discovery OAuth2 en 3 niveles, BFLA, invalidación de token tras logout/revocación, protección anti-automatización, glosario técnico en PDF

Detalle completo de cada versión en [Historial de versiones](#historial-de-versiones).

------------------------------------------------------------

## Roadmap

Solo cambios pendientes — lo ya implementado está en [Evolución del proyecto](#evolución-del-proyecto) y [Historial de versiones](#historial-de-versiones).

**v1.2.x**

- [ ] Validar OpenAPI YAML como fuente de discovery
- [ ] Validar combinación de múltiples `--api-doc` en la misma ejecución
- [ ] Validar `--api-profile aggressive`
- [ ] Rate limiting por endpoint (no solo el primero del discovery)
- [ ] Sincronizar la etiqueta "SSO audit" del menú CLI con "OAuth2/OIDC Audit"
- [ ] Revisar el mapping MITRE ATT&CK de hallazgos de desviación de estándar (p.ej. códigos de respuesta HTTP no convencionales en flujos OAuth2) frente a hallazgos de explotación real

**v1.3.x**

- [ ] Integración con nuclei
- [ ] Export STIX
- [ ] Export SARIF
- [ ] Export JSON consolidado
- [ ] Integración SIEM
- [ ] Inventario diferencial entre ejecuciones
- [ ] Comparativa de resultados por Run ID
- [ ] Validación activa de token OAuth2/OIDC vía `introspection_endpoint` (RFC 7662) cuando el servidor no publica `userinfo_endpoint` pero sí soporta introspección con credenciales de cliente
- [ ] Mitigar los timeouts recurrentes de crt.sh — causas conocidas: sobrecarga del frontend (502/504), límite de 2 min en la consulta PostgreSQL subyacente, y dominios con muchos subdominios (consulta pesada). Vías a evaluar:
  - Usar `&output=json` en vez de scrapear el HTML, y `&exclude=expired` para acotar el histórico consultado
  - Respetar rate limit (máx. 1 petición/5s) para no arriesgar bloqueo temporal de IP
  - Fallback a consulta directa por `psql -h crt.sh -p 5432 -U guest certwatch` si la web falla
  - Evaluar Amass/Subfinder como fuente alternativa/adicional de CT logs (no dependen solo de crt.sh)

------------------------------------------------------------

## Historial de versiones

| Versión | Cambios principales |
|---|---|
| v1.2.1 | Greybox se ejecuta antes de la correlación MITRE ATT&CK; validación activa del token OAuth2/OIDC contra `userinfo_endpoint` (más decode local de expiración); propagación de `intentionally_public` por patrón de path; resumen consolidado único de hallazgos al final del análisis; tabla de detalle de hallazgos y matriz de cobertura combinada API+SSO en el PDF; metadatos y pie de página del PDF con la hora real de generación; discovery OAuth2 en 3 niveles (metadata/wordlist/crawl), BFLA, invalidación real de token tras logout/revocación, protección anti-automatización (CAPTCHA), glosario técnico en PDF, exclusión de endpoints de protocolo OAuth2 de los checks de negocio, `GREYBOX_API_*`/`GREYBOX_SSO_*` separados en `.env`, validación de campo del submodo OAuth2/OIDC contra proveedor real |
| v1.2.0 | Modo Greybox — API discovery/audit y OAuth2/OIDC audit, nivel de confianza por hallazgo, IDOR público separado de enumeración de IDs, mappings MITRE de API/OAuth2, módulos `api_audit.py`/`oauth_audit.py` independientes, paginación PDF consistente |
| v1.1.6 | Trazabilidad (Run ID, log, metadatos PDF), fix ECDSA, separación estricta dominio raíz, fix versiones WordPress, paginación inteligente, MITRE ATT&CK |
| v1.1.5 | Portada limpia, KPIs en ejecutivo, cabeceras de tabla legibles |
| v1.1.4 | version.py fuente única, fix portada |
| v1.1.3 | CVEs con versión confirmada, fix WHOIS, fix hexval |
| v1.1.2 | nmap -sV, Azure WAF/CDN, resiliencia NVD, correlación CVE basada en versiones confirmadas |
| v1.1.0 | Módulo WAF/CDN (Cloudflare + AWS), recon-exec.sh con validación |
| v1.0.0 | Release inicial |

------------------------------------------------------------

Disclaimer

Herramienta destinada a fines educativos y auditorías autorizadas.
El modo greybox realiza peticiones de escritura controladas (Mass Assignment) contra el target — usar únicamente sobre activos propios o con autorización explícita, idealmente en entornos de pre-producción.
El uso indebido puede ser ilegal.

------------------------------------------------------------

Autor

Rafael Carrasco
