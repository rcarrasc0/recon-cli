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
- Priorizar riesgos mediante CVE/CVSS
- Generar informes estructurados

------------------------------------------------------------

Filosofía de diseño

- Modularidad
- Pipeline por fases
- Dependencias desacopladas
- Uso de herramientas estándar (nmap, sslyze)
- Enfoque práctico orientado a pentesting real

------------------------------------------------------------

Arquitectura

El flujo sigue un modelo en pipeline:

```
Input → Reconocimiento → Enumeración → Análisis → WAF/CDN → Scoring → Reporte
```

Cada fase es independiente pero encadenada, permitiendo:

- modularidad
- extensibilidad
- mantenimiento sencillo

------------------------------------------------------------

Características

- **OSINT:** WHOIS, DNS, AXFR, ASN/BGP, crt.sh
- **Integración Shodan** (opcional)
- **Integración Leak-Lookup** (opcional)
- **Enumeración de subdominios** y hosts activos HTTP/HTTPS
- **Fingerprinting de tecnologías**
- **Análisis SSL/TLS:** sslyze + nmap ssl-enum-ciphers
- **Cabeceras HTTP y CSP**
- **HSTS**
- **Detección WAF/CDN:** Cloudflare, AWS WAF/CloudFront, Akamai, Fastly, Sucuri, Imperva
- **Correlación con CVEs** (NVD/NIST)
- **Scoring por CVSS**
- **Generación de informe PDF** estructurado

------------------------------------------------------------

Estructura del proyecto

```text
recon-cli/
├── main.py              Entry point CLI
├── config.py            Carga de entorno y configuración
├── modules/
│   ├── osint.py         WHOIS, DNS, AXFR, crt.sh, ASN
│   ├── leaks.py         Leak-Lookup
│   ├── shodan_scan.py   Shodan
│   ├── enum.py          Subdominios y tecnologías
│   ├── ssl_tls.py       SSL/TLS (sslyze + nmap)
│   ├── headers.py       Cabeceras HTTP, CSP, HSTS
│   ├── waf_cdn.py       Detección WAF/CDN (Cloudflare, AWS, Akamai...)
│   └── cves.py          CVEs (NVD/NIST)
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
- instala dependencias del sistema
- crea entorno virtual
- instala dependencias Python
- valida herramientas (nmap, testssl.sh)
- genera estructura del proyecto

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

- activa automáticamente el entorno virtual
- ejecuta el pipeline completo
- carga configuración del entorno

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

# Guardar informe en ruta específica
./recon-exec.sh example.com --output /tmp/informe.pdf
```

Salida esperada:

- Resolución DNS
- Enumeración
- Análisis SSL/TLS
- Cabeceras HTTP
- CVEs asociados
- Informe generado en reports/

Tiempo estimado: 1–3 minutos dependiendo del target

------------------------------------------------------------

Fases del análisis

| # | Fase | Descripción |
|---|---|---|
| 1 | **OSINT & Reconocimiento** | WHOIS, DNS, AXFR, crt.sh, ASN/BGP |
| 2 | **Shodan** | Servicios expuestos, puertos, banners, CVEs indexados |
| 3 | **Leak-Lookup** | Credenciales y emails filtrados en brechas conocidas |
| 4 | **Enumeración & Descubrimiento** | Subdominios, hosts activos, fingerprinting de tecnologías |
| 5 | **Análisis SSL/TLS** | Protocolos, cifrados, certificado, HSTS, vulnerabilidades |
| 6 | **Cabeceras HTTP & CSP** | Security headers, CSP, cookies, fugas de información |
| 7 | **Detección WAF/CDN** | Cloudflare, AWS WAF/CloudFront, Akamai, Fastly, Sucuri, Imperva |
| 8 | **CVEs** | Búsqueda en NVD/NIST por productos y versiones detectadas |
| 9 | **Informe PDF** | Generación de informe estructurado con hallazgos y scoring CVSS |

Detección WAF/CDN (v1.1.0)

La fase 7 detecta WAF y CDN de forma **100% pasiva** mediante:

- **Rangos IP estáticos** de Cloudflare y AWS CloudFront
- **Rangos IP dinámicos** descargados en tiempo real desde `ip-ranges.amazonaws.com`
- **Fingerprinting de cabeceras HTTP** (`CF-RAY`, `X-Amz-Cf-Id`, `X-Amzn-Trace-Id`...)
- **Análisis de registros CNAME** hacia dominios de CDN conocidos
- **Análisis de comportamiento** ante rutas inválidas (páginas de bloqueo WAF)

Proveedores soportados: Cloudflare, AWS WAF, AWS CloudFront, Akamai, Fastly, Sucuri, Imperva (Incapsula), Barracuda, F5 BIG-IP, ModSecurity.

------------------------------------------------------------

Output

- **Informe PDF** generado en `reports/`
- **Salida estructurada en consola** con progreso por fases
- **Resumen de hallazgos** clasificados por severidad (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- **Scoring CVSS** consolidado
- **Propuestas de mitigación** priorizadas

------------------------------------------------------------

Alcance y modelo de análisis

Enfoque **BLACKBOX** basado en reconocimiento pasivo o de bajo impacto.

**Incluye:**
- Información pública (DNS, WHOIS, certificados)
- Consultas a fuentes abiertas (NVD, Shodan, crt.sh, ip-ranges.amazonaws.com)
- Análisis de configuraciones accesibles públicamente

**No incluye:**
- Ejecución de exploits
- Envío de payloads maliciosos
- Fuerza bruta de credenciales
- Acceso no autorizado
- Movimiento lateral o escalada de privilegios

> Uso únicamente sobre activos propios o con autorización explícita.

------------------------------------------------------------

Limitaciones

- Correlación de CVEs basada en fingerprinting (puede generar falsos positivos)
- Falta de versionado preciso en muchas tecnologías detectadas
- Dependencia de APIs externas (Shodan, NVD, crt.sh, Leak-Lookup)
- No valida explotación real
- Posibles falsos negativos en subdominios o detección WAF/CDN
- Resultados orientativos, no definitivos

------------------------------------------------------------

Troubleshooting

Pillow error (Python 3.13)

Error:
Failed to build Pillow

Solución:
pip install "Pillow>=11.2.1"

------------------------------------------------------------

pydantic-core / Rust error

Error:
Failed building wheel for pydantic-core

Solución:
Actualiza dependencias o usa Python 3.11

------------------------------------------------------------

Dependency conflicts (ResolutionImpossible)

Causa:
Versiones fijadas incompatibles

Solución:
Eliminar versiones fijas en requirements.txt

------------------------------------------------------------

RequestsDependencyWarning

Solución:
pip install --upgrade requests urllib3 charset_normalizer
pip check

------------------------------------------------------------

crt.sh timeout

Causa:
Servicio externo inestable

Solución:
Ignorar o reintentar

------------------------------------------------------------

ReportLab Invalid color

Error:
Invalid color value

Solución:
Cambiar:
c.hexval()[1:]
por:
c.hexval()[2:]

------------------------------------------------------------

Python 3.13 incompatibilidades

Algunas librerías aún no están totalmente adaptadas.

Recomendación:
usar Python 3.11

------------------------------------------------------------

Caso real (Python 3.13):

- error en Pillow
- error en pydantic-core (Rust)
- conflictos pip

Solución recomendada:

- usar Python 3.11
- evitar versiones fijadas
- recrear entorno virtual

------------------------------------------------------------

Roadmap

- [x] OSINT & Reconocimiento
- [x] Integración Shodan
- [x] Integración Leak-Lookup
- [x] Enumeración de subdominios
- [x] Análisis SSL/TLS
- [x] Cabeceras HTTP & CSP
- [x] Detección WAF/CDN (Cloudflare + AWS) ← **v1.1.0**
- [ ] Detección WAF/CDN Azure
- [ ] API discovery (endpoints, Swagger/OpenAPI, GraphQL)
- [ ] Fingerprinting avanzado de APIs
- [ ] Integración con nuclei
- [ ] Integración con JIRA para el inicio del Plan de Tratamiento
- [ ] Mejora de correlación CVE (version-aware)
- [ ] Correlación con MITRE ATT&CK
- [ ] Export JSON
- [ ] Integración SIEM

------------------------------------------------------------

Disclaimer

Herramienta destinada a fines educativos y auditorías autorizadas.
El uso indebido puede ser ilegal.

------------------------------------------------------------

Autor

Rafael Carrasco
