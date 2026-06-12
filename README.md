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

Input → Reconocimiento → Enumeración → Análisis → Scoring → Reporte

Cada fase es independiente pero encadenada, permitiendo:

- modularidad
- extensibilidad
- mantenimiento sencillo

------------------------------------------------------------

Características

- OSINT:
  WHOIS, DNS, AXFR, ASN/BGP, crt.sh
- Integración Shodan (opcional)
- Integración Leak-Lookup (opcional)
- Enumeración de subdominios
- Descubrimiento de hosts activos HTTP/HTTPS
- Fingerprinting de tecnologías
- Análisis SSL/TLS:
  - sslyze
  - nmap ssl-enum-ciphers
- Cabeceras HTTP y CSP
- HSTS
- Correlación con CVEs (NVD)
- Scoring por CVSS
- Generación de informe PDF

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
│   └── cves.py          CVEs (NVD)
├── report/
│   └── pdf_gen.py       Generación de informe PDF
├── reports/              Directorio de salida para informes generados (no versionado)
├── recon-exec.sh         Launcher CLI: activa el entorno y ejecuta el pipeline completo
├── .env.example          Plantilla de variables de entorno (configuración opcional)
├── requirements.txt      Dependencias Python del proyecto
└── setup.sh              Script de instalación (entorno virtual + dependencias)
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

git clone <repo>
cd recon-cli
chmod +x setup.sh
./setup.sh

El script:
- instala dependencias del sistema
- crea entorno virtual
- instala dependencias Python
- valida herramientas (nmap, testssl.sh)
- genera estructura del proyecto

------------------------------------------------------------

Configuración

Editar el fichero .env:

SHODAN_API_KEY=
LEAKLOOKUP_API_KEY=
NVD_API_KEY=

REPORT_AUTHOR=
REPORT_CLASSIFICATION=

------------------------------------------------------------

Uso

./recon-exec.sh dominio.com

El launcher:

- activa automáticamente el entorno virtual
- ejecuta el pipeline completo
- carga configuración del entorno

Ejemplo:

./recon-exec.sh example.com

Salida esperada:

- Resolución DNS
- Enumeración
- Análisis SSL/TLS
- Cabeceras HTTP
- CVEs asociados
- Informe generado en reports/

Tiempo estimado: 1–3 minutos dependiendo del target

------------------------------------------------------------

Flujo interno simplificado:

1. Recopilación OSINT
2. Generación de lista de targets
3. Resolución y filtrado de activos
4. Análisis HTTP/SSL
5. Enriquecimiento con CVEs
6. Generación de informe

------------------------------------------------------------

Fases del análisis

1. OSINT & Reconocimiento
   - WHOIS
   - DNS
   - AXFR
   - crt.sh
   - ASN/BGP

2. Enumeración & Descubrimiento
   - Subdominios
   - Resolución DNS
   - Hosts activos
   - Tecnologías

3. Análisis de Seguridad
   - SSL/TLS (sslyze + nmap)
   - Cabeceras HTTP
   - CSP, HSTS

4. CVEs & Scoring
   - Correlación con NVD
   - Clasificación CVSS

5. Reporte
   - Informe PDF
   - Resumen de hallazgos
   - Clasificación por severidad
   - Recomendaciones

------------------------------------------------------------

Output

- Informe PDF generado en reports/
- Salida estructurada en consola (análisis por fases)
- Datos agregados del pipeline para correlación y scoring

------------------------------------------------------------

Alcance y modelo de análisis

Este proyecto está orientado a un enfoque BLACKBOX basado en reconocimiento pasivo o de bajo impacto.

Incluye:

- información pública (DNS, WHOIS, certificados)
- consultas a fuentes abiertas (NVD, Shodan, crt.sh)
- análisis de configuraciones accesibles

No incluye:

- ejecución de exploits
- envío de payloads
- fuerza bruta
- acceso no autorizado
- movimiento lateral
- escalada de privilegios

El comportamiento replica la fase inicial de reconocimiento de un atacante.

Uso únicamente sobre activos propios o con autorización.

------------------------------------------------------------

Limitations

- Correlación de CVEs basada en fingerprinting (puede generar falsos positivos)
- Falta de versionado preciso en muchas tecnologías detectadas
  - Muchos hallazgos deben considerarse potenciales
  - No implican vulnerabilidades confirmadas
- Dependencia de APIs externas (Shodan, NVD, crt.sh)
- No valida explotación real
- Fingerprinting heurístico
- Posibles falsos negativos (subdominios no detectados, WAF/CDN)
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

- Detección WAF/CDN
- API discovery (endpoints, versiones, Swagger/OpenAPI, GraphQL)
- Fingerprinting avanzado (incluyendo tipo de API)
- Integración con nuclei
- Mejora de correlación CVE (version-aware)
- Correlación con MITRE ATT&CK
- Export JSON
- Integración SIEM

Futuro:

- Generación de contexto para explotación asistida
- Exportación de contexto técnico (Metasploit / tooling)
- Identificación de vectores potenciales
- Generación de apuntes para fase post-recon

------------------------------------------------------------

Disclaimer

Herramienta destinada a fines educativos y auditorías autorizadas.
El uso indebido puede ser ilegal.

------------------------------------------------------------

Autor

Rafael Carrasco
