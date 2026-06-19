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

- Modularidad
- Pipeline por fases
- Dependencias desacopladas
- Uso de herramientas estándar (nmap, testssl.sh)
- Enfoque práctico orientado a pentesting real

------------------------------------------------------------

Arquitectura

El flujo sigue un modelo en pipeline:

```
Input → Reconocimiento → Enumeración → Análisis → WAF/CDN → Scoring → Reporte
```

Cada fase es independiente pero encadenada, permitiendo: modularidad, extensibilidad y mantenimiento sencillo

------------------------------------------------------------

Características

- **OSINT:** WHOIS, DNS, AXFR, ASN/BGP, crt.sh
- **Integración Shodan** (opcional vía API key)
- **Integración Leak-Lookup** (opcional vía API key)
- **Enumeración de subdominios** y hosts activos HTTP/HTTPS
- **Fingerprinting de tecnologías**
- **Detección de versiones** con nmap -sV ← nuevo en v1.1.2
- **Análisis SSL/TLS:** sslyze + nmap ssl-enum-ciphers
- **Cabeceras HTTP y CSP**
- **HSTS**
- **Detección WAF/CDN:** Cloudflare, AWS WAF/CloudFront, Azure Front Door/WAF, Akamai, Fastly, Sucuri, Imperva
- **Correlación CVEs** (NVD/NIST) basada en versiones confirmadas con retry automático y warning de disponibilidad
- **Scoring por CVSS**
- **Generación de informe PDF** con versión de herramienta en portada y pie

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
| `--scope [blackbox\|greybox]` | Tipo de análisis (default: blackbox) |
| `--skip-leaks` | Omitir consulta a Leak-Lookup |
| `--skip-shodan` | Omitir consulta a Shodan |
| `--skip-ssl` | Omitir análisis SSL/TLS |
| `--skip-waf` | Omitir detección WAF/CDN |
| `--skip-cves` | Omitir búsqueda de CVEs |
| `--output <ruta.pdf>` | Ruta del informe PDF de salida |
| `--verbose / -v` | Output detallado por fase |

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

Output

- **Informe PDF** en `reports/` con versión de herramienta en portada y pie de página
- **Salida en consola** con progreso por fases
- **Resumen de hallazgos** por severidad (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- **Scoring CVSS** consolidado
- **Propuestas de mitigación** priorizadas

------------------------------------------------------------

Alcance y modelo de análisis

Enfoque **BLACKBOX** basado en reconocimiento pasivo o de bajo impacto.

**Incluye:** información pública (DNS, WHOIS, certificados), consultas a fuentes abiertas (NVD, Shodan, crt.sh), análisis de configuraciones accesibles.

**No incluye:** exploits, payloads maliciosos, fuerza bruta, acceso no autorizado, movimiento lateral ni escalada de privilegios.

> Uso únicamente sobre activos propios o con autorización explícita.

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

- [x] OSINT & Reconocimiento
- [x] Integración Shodan
- [x] Integración Leak-Lookup
- [x] Enumeración de subdominios
- [x] Análisis SSL/TLS
- [x] Cabeceras HTTP & CSP
- [x] Detección WAF/CDN — Cloudflare + AWS ← v1.1.0
- [x] Detección WAF/CDN — Azure Front Door + Azure WAF
- [x] Detección de versiones con nmap -sV
- [x] Resiliencia NVD — timeout, retries, warning en PDF
- [x] Versión de herramienta en informe PDF
- [ ] API discovery greybox (endpoints, Swagger/OpenAPI, GraphQL, tokens)
- [ ] Diferenciación funcional blackbox vs greybox
- [ ] Integración con nuclei
- [ ] Mejora de correlación CVE (version-aware)
- [ ] Correlación con MITRE ATT&CK
- [ ] Export JSON
- [ ] Integración SIEM

------------------------------------------------------------

## Historial de versiones

| Versión | Cambios principales |
|---|---|
| v1.1.2 | nmap -sV, Azure WAF/CDN, resiliencia NVD, correlación CVE basada en versiones confirmadas |
| v1.1.0 | Módulo WAF/CDN (Cloudflare + AWS), recon-exec.sh con validación |
| v1.0.7 | Estabilización, fix sslyze Python 3.13, fix urllib3 |
| v1.0.0 | Release inicial |

------------------------------------------------------------

Disclaimer

Herramienta destinada a fines educativos y auditorías autorizadas.
El uso indebido puede ser ilegal.

------------------------------------------------------------

Autor

Rafael Carrasco
