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

## 🚀 Novedades principales v1.2.0

- ✅ Nuevo modo Greybox para auditoría autenticada
- ✅ Discovery de APIs desde Postman, OpenAPI/Swagger y Spider activo
- ✅ Auditoría de APIs REST y SOAP
- ✅ Soporte de Bearer Token y OAuth2 Client Credentials
- ✅ Detección de IDOR, BOLA, Mass Assignment y Excessive Data Exposure
- ✅ Auditoría OAuth2/OIDC — validación de tokens, open redirect
- ✅ Correlación MITRE ATT&CK para hallazgos de API y OAuth2
- ✅ Artefactos JSON independientes de Discovery y Audit
- ✅ Run ID único propagado a PDF, LOG y JSON
- ✅ Nivel de confianza (Alta / Media / Baja) para hallazgos heurísticos

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

El proyecto nace con el objetivo de automatizar tareas recurrentes de pentesting en fase de reconocimiento (recon), centralizando múltiples técnicas y herramientas en un único flujo controlado. Desde v1.2.0 incorpora también auditoría autenticada de APIs, ampliando el alcance de reconocimiento pasivo a verificación activa de controles de autorización.

El objetivo no es la explotación, sino:

- Mapear superficie de ataque externa
- Identificar exposición de activos
- Analizar configuraciones públicas
- Detectar WAF/CDN y su configuración (Cloudflare, AWS, Azure)
- Detectar versiones de servicios expuestos (nmap -sV)
- Priorizar riesgos mediante CVE/CVSS
- **(Greybox)** Descubrir y auditar endpoints de API — autenticación, IDOR/BOLA, exposición de datos
- **(Greybox)** Verificar la robustez de flujos OAuth2/OIDC
- Generar informes estructurados

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

------------------------------------------------------------

Arquitectura

El flujo sigue un modelo en pipeline, con una rama adicional para el modo greybox:

```
Input → Reconocimiento → Enumeración → Análisis → WAF/CDN → CVEs → MITRE → Reporte
                                          │
                                          └─ (--scope greybox) → API Discovery → API Audit
                                                                → OAuth2/OIDC Audit
```

Cada fase es independiente pero encadenada, permitiendo: modularidad, extensibilidad y mantenimiento sencillo.

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
- **MITRE ATT&CK** — táctica + técnica + sub-técnica, mappings conservadores, sin API externa
- **Separación endpoint / dominio raíz** — SPF, DMARC y WHOIS nunca afectan el scoring principal
- **Trazabilidad completa** — Run ID, log detallado, metadatos de ejecución en PDF
- **Informe PDF** — paginación consistente (cada sección arranca en página nueva, subsecciones nunca se parten de su tabla), riesgo global real, sección metadatos al final
- **(Nuevo v1.2.0) API Discovery** — Postman, OpenAPI/Swagger, spider activo (119 paths, vocabulario SSI/VC/Wallet incluido)
- **(Nuevo v1.2.0) API Audit** — autenticación, IDOR, BOLA, Mass Assignment, Excessive Data Exposure, rate limiting, métodos no documentados
- **(Nuevo v1.2.0) OAuth2/OIDC Audit** — validación de tokens, open redirect en `redirect_uri`
- **(Nuevo v1.2.0) Nivel de confianza por hallazgo** — checks heurísticos declaran Alta/Media/Baja, independiente del CVSS

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
- Pie de página del informe PDF
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

# ── Greybox (v1.2.0) ──────────────────────────────────────
# Credenciales para el modo --scope greybox. Todas son opcionales:
# lo que falte se pedirá de forma interactiva al ejecutar.
GREYBOX_TOKEN=
GREYBOX_CLIENT_ID=
GREYBOX_CLIENT_SECRET=
GREYBOX_TOKEN_ENDPOINT=
GREYBOX_API_DOC=
GREYBOX_ENV_FILE=
GREYBOX_PROFILE=
```

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
| `--api-doc <ruta>` | (Greybox) Colección Postman (`.json`) u OpenAPI/Swagger (`.yaml`/`.json`). Repetible para combinar varias fuentes |
| `--env-file <ruta>` | (Greybox) Entorno Postman (`.postman_environment.json`) para resolver variables `{{...}}` |
| `--skip-leaks` | Omitir Leak-Lookup |
| `--skip-shodan` | Omitir Shodan |
| `--skip-ssl` | Omitir SSL/TLS |
| `--skip-waf` | Omitir detección WAF/CDN |
| `--skip-cves` | Omitir CVEs |
| `--output <ruta.pdf>` | Ruta del informe PDF |
| `--verbose / -v` | Output detallado |

> **Nota sobre `--scope greybox`:** a partir de v1.2.0 el parámetro es **funcional** — activa un menú guiado que pregunta el submodo (API audit / OAuth2/OIDC Audit / Ambos), el método de autenticación (Bearer token directo, Client Credentials OAuth2, o sin autenticación) y la documentación de API disponible. Cualquier credencial no aportada por flag o `.env` se pide de forma interactiva. En versiones anteriores a v1.2.0 este flag era solo informativo.
>
> *Nota de nomenclatura: el menú interactivo del CLI todavía muestra la opción como "SSO audit" — esta documentación usa "OAuth2/OIDC Audit" porque describe mejor el alcance real del submodo (validación de tokens y open redirect, no gestión completa de sesión SSO). Pendiente de sincronizar la etiqueta del menú en el propio código.*

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

# Greybox — sin documentación, solo spider + token interactivo
./recon-exec.sh api.example.com --scope greybox
```

Tiempo estimado: 1–3 minutos dependiendo del target (blackbox); el modo greybox depende del número de endpoints descubiertos.

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
| 9 | **MITRE ATT&CK** | Correlación táctica + técnica + sub-técnica |
| 10 | **Greybox — API Discovery** *(solo `--scope greybox`)* | Postman / OpenAPI / Spider activo (119 paths) |
| 11 | **Greybox — API Audit** *(solo `--scope greybox`)* | Auth, IDOR, BOLA, Mass Assignment, Excessive Data, rate limiting |
| 12 | **Greybox — OAuth2/OIDC Audit** *(solo `--scope greybox`, submodo 2 o 3)* | Validación de tokens, open redirect |
| 13 | **Informe PDF** | Informe estructurado con hallazgos, CVSS, confianza y mitigaciones |

WAF/CDN — vectores de detección pasiva

- Rangos IP estáticos (Cloudflare, AWS CloudFront, Azure Front Door)
- Rangos IP dinámicos en tiempo real (`ip-ranges.amazonaws.com`, ServiceTags de Microsoft)
- Fingerprinting de cabeceras HTTP (`CF-RAY`, `X-Amz-Cf-Id`, `X-Azure-Ref`, `X-AppGw-Trace-Id`...)
- Análisis de CNAME hacia dominios CDN (`cloudflare.net`, `cloudfront.net`, `azurefd.net`...)
- Comportamiento ante rutas inválidas (páginas de bloqueo WAF)

Proveedores: Cloudflare, AWS WAF, AWS CloudFront, Azure Front Door, Azure Application Gateway WAF, Azure CDN, Akamai, Fastly, Sucuri, Imperva, Barracuda, F5 BIG-IP, ModSecurity.

------------------------------------------------------------

Modo Greybox — API & OAuth2 Audit (v1.2.0)

Auditoría con credenciales que complementa el reconocimiento externo. Se activa con `--scope greybox` y ofrece tres submodos:

| Submodo | Qué hace |
|---|---|
| **[1] API audit** | Discovery + auditoría de endpoints REST/SOAP |
| **[2] OAuth2/OIDC Audit** *(el menú CLI aún la etiqueta como "SSO audit")* | Validación de tokens, open redirect en flujos OAuth2/OIDC |
| **[3] Ambos** | API audit + OAuth2/OIDC Audit en una sola ejecución |

**Discovery de endpoints — tres fuentes combinables**

- **Postman** — parsea colecciones `.postman_collection.json` (v2.0/v2.1), resuelve variables `{{...}}` desde el entorno aportado y detecta `auth.type = noauth` para marcar endpoints públicos por diseño
- **OpenAPI / Swagger** — `.yaml` o `.json`, local o autodescubierto por el spider
- **Spider activo** — wordlist de 119 paths (incluye vocabulario SSI/VC/Wallet: issuance, verification, status_list, DID, trust registry) + crawl de HTML/JS

Los endpoints se deduplican por (método, path) fusionando las fuentes que los detectaron.

**Variables Postman generadas en runtime**

Las colecciones OIDC4VCI/OAuth2 suelen generar variables dinámicamente durante la ejecución en Postman (`pm.environment.set()`) — `credential_offer_uri`, `token_endpoint`, etc. — que no existen en el fichero de entorno estático. recon-cli las detecta y marca como `runtime_generated`, excluyéndolas de la auditoría (evita peticiones fallidas en silencio y falsos "endpoint no documentado") y contándolas aparte en el informe.

**Checks de auditoría de API**

| Check | Qué detecta |
|---|---|
| Autenticación | Endpoint accesible sin token / token inválido aceptado |
| Métodos no documentados | PUT/DELETE/PATCH activos sobre un endpoint no documentado para ese método |
| IDOR | Respuesta distinta al probar el ID adyacente — **omitido en endpoints públicos** (ver más abajo) |
| BOLA | Respuesta distinta al probar IDs de otros tenants (0, 99, 9999) |
| Identificadores secuenciales enumerables | Endpoint público con ID secuencial — no es un fallo de acceso, pero permite inferir volumen de negocio |
| Mass Assignment | El servidor refleja valores privilegiados inyectados (`role`, `tenant_id`, `admin`) en el body |
| Excessive Data Exposure | Campos sensibles (contraseñas, tokens, claves) en la respuesta |
| Rate limiting | Ausencia de HTTP 429 / cabeceras `X-RateLimit-*` |
| Endpoint no documentado | Descubierto por el spider pero ausente de Postman/OpenAPI |
| GraphQL introspection | Introspection habilitada sin autenticación |
| WSDL / Swagger expuestos | Documentación técnica accesible sin autenticación |

**IDOR en endpoints públicos e `intentionally_public`**

IDOR es por definición un fallo de *control de acceso*. Si el endpoint es público por diseño, no hay control de acceso que romper — cualquiera puede pedir cualquier ID intencionadamente. recon-cli ya no degrada estos casos a un IDOR de severidad menor: los excluye del check de IDOR y genera en su lugar un hallazgo **INFO** distinto ("Identificadores secuenciales enumerables"), reconociendo que el riesgo real es de otra naturaleza — inferencia de volumen/cardinalidad de negocio, no acceso indebido.

Esta distinción se apoya en el flag `intentionally_public`, que marca cualquier endpoint público — por Postman (`auth.type = noauth`), o porque responde igual con y sin token durante el spider. El flag atenúa o excluye los checks que asumen control de acceso (IDOR, BOLA) sin perder cobertura sobre el resto (exposición de datos, mass assignment, etc., que siguen aplicando igual independientemente de si el endpoint es público).

**Checks de auditoría OAuth2/OIDC**

| Check | Qué detecta |
|---|---|
| Endpoint accesible por HTTP | Token endpoint sin forzar HTTPS (excluye redirects correctos a HTTPS) |
| Token inválido aceptado | El token endpoint devuelve 200 con un `refresh_token` claramente inválido |
| Open redirect | `redirect_uri` no registrada aceptada — reutiliza el `client_id` real si está configurado |
| Logout / Revocación | Detección de los endpoints correspondientes (informativo) |

**Nivel de confianza por hallazgo**

Los checks heurísticos (comportamiento, no hechos deterministas) incluyen un campo `confidence` (Alta / Media / Baja), visible como badge junto al CVSS en el PDF. Es una dimensión independiente de la severidad: indica cuánta verificación manual adicional requiere el hallazgo antes de priorizar su remediación. El Resumen Ejecutivo avisa automáticamente si hay hallazgos de confianza baja.

**Timeout adaptativo ante WAF**

Si se detecta un WAF delante del target, el spider reduce su timeout a 3 segundos (los paths bloqueados responden rápido) en vez de esperar el timeout general — evita que una auditoría con WAF tarde minutos en lugar de segundos.

**Verificación de token**

Antes de lanzar el spider, se verifica el token contra varias URLs de prueba comparando la respuesta con y sin él. Si no se puede verificar, se ofrece completar credenciales de forma interactiva sin perder lo ya configurado por `.env`.

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

- **Informe PDF** en `reports/` con versión de herramienta en portada y pie de página
- **Salida en consola** con progreso por fases
- **Resumen de hallazgos** por severidad (CRITICAL / HIGH / MEDIUM / LOW / INFO)
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

El `.log` contiene la salida completa y detallada de todas las fases — equivalente exacto a lo que el usuario ve en pantalla durante la ejecución — incluyendo tecnologías detectadas, consultas CVE, correlación MITRE y resumen final.

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

Mapeo automático de hallazgos con criterio conservador — se prefieren pocos mappings sólidos antes que muchos discutibles. Se asigna sub-técnica solo cuando la correspondencia es directa y justificable.

Desde v1.2.0 incluye mappings dedicados a hallazgos de API y OAuth2:

| Hallazgo | Táctica · Técnica |
|---|---|
| IDOR / BOLA | Initial Access · T1190 (Exploit Public-Facing Application) |
| Mass Assignment | Privilege Escalation · T1548 (Abuse Elevation Control Mechanism) |
| Identificadores secuenciales enumerables | Reconnaissance · T1595.003 (Wordlist Scanning) |
| Excessive Data Exposure | Collection · T1213 (Data from Information Repositories) |
| OAuth2 accesible por HTTP | Collection · T1557 (Adversary-in-the-Middle) |
| Open redirect OAuth2 | Credential Access · T1528 (Steal Application Access Token) |
| Token inválido/expirado aceptado | Credential Access · T1550.001 (Application Access Token) |

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
| 8 | CVEs Identificados | ✓ (placeholder si no hay resultados) |
| 9 | Tabla CVSS Consolidada | Solo si hay hallazgos con CVSS |
| 10 | Análisis del Dominio Raíz | Solo si hay hallazgos de dominio raíz |
| 11 | Análisis Greybox | Solo con `--scope greybox` |
| 12 | Correlación MITRE ATT&CK | Solo si hay correlaciones |
| 13 | Propuestas de Mitigación | ✓ |
| 14 | Metadatos de Ejecución | ✓ |

Cada sección principal arranca siempre en página nueva; las subsecciones nunca se separan de su tabla o contenido asociado.

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
- **(Greybox)** El submodo OAuth2/OIDC Audit no ha sido validado contra un entorno OAuth2 real — ver aviso más abajo
- **(Greybox)** El check de rate limiting testea un único endpoint (el primero del discovery), no es representativo de toda la API — confidence Baja por diseño

------------------------------------------------------------

⚠ Aviso — Submodo OAuth2/OIDC sin validar en campo

El submodo OAuth2/OIDC Audit (`--scope greybox`, opciones 2 y 3 del menú — mostradas actualmente como "SSO audit" en el CLI) está **implementado y ha pasado revisión de código** — se corrigieron varios falsos positivos detectados por inspección manual antes de cualquier ejecución real (ver Historial de versiones, v1.2.0) — pero **no se ha ejecutado todavía contra un servidor de autorización OAuth2/OIDC real**. A diferencia del submodo API audit (validado contra un target real en producción-pre), este submodo debe tratarse como **beta** hasta su primera validación de campo, prevista para v1.2.1.

Recomendación: si vas a usar el submodo OAuth2/OIDC en un entorno real, revisa manualmente los hallazgos antes de incluirlos en un informe a cliente.

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

Detalle completo de cada versión en [Historial de versiones](#historial-de-versiones).

------------------------------------------------------------

## Roadmap

Solo cambios pendientes — lo ya implementado está en [Evolución del proyecto](#evolución-del-proyecto) y [Historial de versiones](#historial-de-versiones).

**v1.2.x**

- [ ] Validar OAuth2/OIDC Audit contra servidores reales (VALid2 u otros IdP)
- [ ] Validar OpenAPI YAML como fuente de discovery
- [ ] Validar combinación de múltiples `--api-doc` en la misma ejecución
- [ ] Validar `--greybox-profile aggressive`
- [ ] Rate limiting por endpoint (no solo el primero del discovery)
- [ ] Ajustar mappings MITRE de OAuth2 según casos reales

**v1.3.x**

- [ ] Integración con nuclei
- [ ] Export STIX
- [ ] Export SARIF
- [ ] Export JSON consolidado
- [ ] Integración SIEM
- [ ] Inventario diferencial entre ejecuciones
- [ ] Comparativa de resultados por Run ID

------------------------------------------------------------

## Historial de versiones

| Versión | Cambios principales |
|---|---|
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
