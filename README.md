[![GitHub release](https://img.shields.io/github/v/release/rcarrasc0/recon-cli)](https://github.com/rcarrasc0/recon-cli/releases)

```text
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗      ██████╗██╗     ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║     ██╔════╝██║     ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║     ██║     ██║     ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║     ██║     ██║     ██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║     ╚██████╗███████╗██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝      ╚═════╝╚══════╝╚═╝

   recon-cli · External Attack Surface Recon
```

Herramienta CLI de reconocimiento automatizado orientada a auditorías BLACKBOX de 
superficie de ataque externa (EASM), que automatiza OSINT, enumeración y análisis de 
seguridad, generando informes técnicos en PDF con correlación CVE/CVSS.

------------------------------------------------------------

Casos de uso

- Auditorías externas sin credenciales (BLACKBOX)
- Validación de exposición de activos
- Preparación de pentests
- Monitorización básica de superficie externa
- Informes alineados con MITRE ATT&CK para analistas y CISO

------------------------------------------------------------

Concepto y propósito

El proyecto nace con el objetivo de automatizar tareas recurrentes de pentesting en fase de reconocimiento (recon), centralizando múltiples técnicas y herramientas en un único flujo controlado.

El objetivo no es la explotación, sino:

- Mapear superficie de ataque externa
- Identificar exposición de activos
- Analizar configuraciones públicas
- Detectar WAF/CDN y su configuración (Cloudflare, AWS, Azure)
- Detectar versiones de servicios expuestos (nmap -sV)
- Priorizar riesgos mediante CVE/CVSS
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

------------------------------------------------------------

Arquitectura

El flujo sigue un modelo en pipeline:

```
Input → Reconocimiento → Enumeración → Análisis → WAF/CDN → CVEs → MITRE → Reporte
```

Cada fase es independiente pero encadenada, permitiendo: modularidad, extensibilidad y mantenimiento sencillo

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
- **Informe PDF** — paginación inteligente, wrap correcto, riesgo global real, sección metadatos al final

------------------------------------------------------------

Estructura del proyecto

```text
recon-cli/
├── main.py              Entry point CLI
├── config.py            Carga de entorno y configuración
├── version.py           Fuente única de verdad para el versionado
├── modules/
│   ├── osint.py         WHOIS, DNS, AXFR, crt.sh, ASN
│   ├── leaks.py         Leak-Lookup
│   ├── shodan_scan.py   Shodan
│   ├── enum.py          Subdominios, tecnologías y nmap -sV
│   ├── ssl_tls.py       SSL/TLS (análisis nativo + nmap)
│   ├── headers.py       Cabeceras HTTP, CSP, HSTS
│   ├── waf_cdn.py       Detección WAF/CDN (Cloudflare, AWS, Azure...)
│   └── cves.py          CVEs (NVD/NIST) con retry y warning
│   └── mitre.py         Correlación MITRE ATT&CK (mappings conservadores)
├── report/
│   └── pdf_gen.py       Generación de informe PDF
├── reports/             Directorio de salida (no versionado)
├── recon-exec.sh        Launcher CLI con validación de parámetros
├── .env.example         Plantilla de variables de entorno
├── requirements.txt     Dependencias Python
└── setup.sh             Script de instalación completo
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
| `--scope [blackbox\|greybox]` | Tipo de análisis en el informe (informativo, default: blackbox) |
| `--skip-leaks` | Omitir Leak-Lookup |
| `--skip-shodan` | Omitir Shodan |
| `--skip-ssl` | Omitir SSL/TLS |
| `--skip-waf` | Omitir detección WAF/CDN |
| `--skip-cves` | Omitir CVEs |
| `--output <ruta.pdf>` | Ruta del informe PDF |
| `--verbose / -v` | Output detallado |

> **Nota sobre `--scope`:** actualmente el parámetro es **informativo** — aparece en el banner del terminal y en la portada del informe PDF, pero no activa ni desactiva ningún módulo ni cambia la lógica de análisis. La diferenciación funcional entre blackbox y greybox se implementará en la próxima versión con el módulo de análisis de APIs, donde greybox habilitará el uso de credenciales y tokens.


Ejemplos de ejecución:

```bash
# Análisis completo
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
```

Tiempo estimado: 1–3 minutos dependiendo del target

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
| 9 | **Informe PDF** | Informe estructurado con hallazgos, CVSS y mitigaciones |

WAF/CDN — vectores de detección pasiva

- Rangos IP estáticos (Cloudflare, AWS CloudFront, Azure Front Door)
- Rangos IP dinámicos en tiempo real (`ip-ranges.amazonaws.com`, ServiceTags de Microsoft)
- Fingerprinting de cabeceras HTTP (`CF-RAY`, `X-Amz-Cf-Id`, `X-Azure-Ref`, `X-AppGw-Trace-Id`...)
- Análisis de CNAME hacia dominios CDN (`cloudflare.net`, `cloudfront.net`, `azurefd.net`...)
- Comportamiento ante rutas inválidas (páginas de bloqueo WAF)

Proveedores: Cloudflare, AWS WAF, AWS CloudFront, Azure Front Door, Azure Application Gateway WAF, Azure CDN, Akamai, Fastly, Sucuri, Imperva, Barracuda, F5 BIG-IP, ModSecurity.

------------------------------------------------------------

Separación endpoint vs dominio raíz

recon-cli detecta automáticamente el dominio raíz mediante `tldextract` y separa los hallazgos en dos categorías:

- **Hallazgos de seguridad** — relativos al endpoint, contribuyen al scoring CVSS y al riesgo global
- **Sección "Análisis del Dominio Raíz"** — SPF, DMARC, WHOIS/ASN en sección separada, sin afectar el scoring

Esta separación es **siempre activa**, independientemente de si el target es un subdominio o el dominio raíz directamente. SPF y DMARC son configuraciones de correo, no de la aplicación web auditada, y nunca deben inflar el riesgo global de un análisis de superficie web.

Ejemplo:

```
Target: studio.empresa.cat
  → Hallazgos endpoint: SSL/TLS, cabeceras, WAF, CVEs
  → Dominio raíz: SPF/DMARC de empresa.cat (sección separada)

Target: empresa.cat
  → Hallazgos endpoint: SSL/TLS, cabeceras, WAF, CVEs
  → Dominio raíz: SPF/DMARC de empresa.cat (sección separada)
```

------------------------------------------------------------

Output

- **Informe PDF** en `reports/` con versión de herramienta en portada y pie de página
- **Salida en consola** con progreso por fases
- **Resumen de hallazgos** por severidad (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- **Scoring CVSS** consolidado
- **Propuestas de mitigación** priorizadas

------------------------------------------------------------

Trazabilidad de ejecuciones

Cada ejecución genera un **Run ID** único con formato `YYYYMMDD-HHMMSS-XXXXXXXX` visible en:

- El panel de inicio en consola
- La portada del PDF
- La sección final "Metadatos de Ejecución" del PDF
- El fichero `.log` asociado

El `.log` contiene la salida completa y detallada de todas las fases — equivalente exacto a lo que el usuario ve en pantalla durante la ejecución — incluyendo tecnologías detectadas, consultas CVE, correlación MITRE y resumen final.

------------------------------------------------------------

Alcance y modelo de análisis

Enfoque **BLACKBOX** basado en reconocimiento pasivo o de bajo impacto.

**Incluye:** información pública (DNS, WHOIS, certificados), consultas a fuentes abiertas (NVD, Shodan, crt.sh), análisis de configuraciones accesibles.

**No incluye:** exploits, payloads maliciosos, fuerza bruta, acceso no autorizado, movimiento lateral ni escalada de privilegios.

> Uso únicamente sobre activos propios o con autorización explícita.

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
| 11 | Correlación MITRE ATT&CK | Solo si hay correlaciones |
| 12 | Propuestas de Mitigación | ✓ |
| 13 | Metadatos de Ejecución | ✓ |

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

------------------------------------------------------------

Roadmap

- [x] OSINT, Shodan, Leak-Lookup, Enumeración, SSL/TLS, Cabeceras HTTP
- [x] WAF/CDN — Cloudflare, AWS, Azure ← v1.1.0
- [x] nmap -sV para detección de versiones ← v1.1.0
- [x] CVEs solo con versión confirmada ← v1.1.3
- [x] Versión dinámica en PDF ← v1.1.4
- [x] Portada limpia, KPIs en Resumen Ejecutivo ← v1.1.5
- [x] MITRE ATT&CK con mappings conservadores ← v1.1.6
- [x] Separación estricta endpoint vs dominio raíz ← v1.1.6
- [x] SPF/DMARC siempre fuera del scoring principal ← v1.1.6
- [x] Eliminados hallazgos de emails WHOIS ← v1.1.6
- [x] Fallback CVE: NVD → CIRCL Vulnerability-Lookup ← v1.1.6
- [x] Riesgo global = severidad más alta del endpoint ← v1.1.6
- [x] Corrección falso positivo ECDSA P-256 ← v1.1.6
- [x] Diferenciación RSA / ECDSA / DSA en SSL/TLS ← v1.1.6
- [x] Fix versiones heredadas desde ?ver= de WordPress ← v1.1.6
- [x] Contador nmap diferenciado (abiertos / con versión / sin versión) ← v1.1.6
- [x] Run ID único por ejecución ← v1.1.6
- [x] Log completo de ejecución (console compartido) ← v1.1.6
- [x] Sección "Metadatos de Ejecución" al final del PDF ← v1.1.6
- [x] Paginación inteligente y wrap correcto en tablas ← v1.1.6
- [x] Numeración y estructura PDF estabilizadas ← v1.1.6
- [ ] API discovery greybox (Swagger/OpenAPI, GraphQL, tokens)
- [ ] Diferenciación funcional blackbox vs greybox
- [ ] Integración con nuclei
- [ ] Export JSON / STIX
- [ ] Integración SIEM

------------------------------------------------------------

## Historial de versiones

| Versión | Cambios principales |
|---|---|
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
El uso indebido puede ser ilegal.

------------------------------------------------------------

Autor

Rafael Carrasco
