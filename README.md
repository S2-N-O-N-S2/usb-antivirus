# USB Antivirus

Antivirus portátil para Windows 10 y Windows 11.  
Motor: ClamAV 1.5.4 · Python 3 · Tkinter · SQLite  
**Funciona completamente sin conexión a Internet.**

> Los binarios de ClamAV y las firmas antivirus **no están incluidos** en este repositorio por su tamaño (~240 MB). Descárgalos siguiendo las instrucciones de instalación.

---

## Características

- Análisis de archivos, carpetas, unidades USB y discos completos
- Múltiples workers en paralelo con detección automática de SSD/HDD
- Priority scanning — analiza primero las carpetas de mayor riesgo
- Soporte de archivos comprimidos: ZIP, RAR, PDF, Office, HTML, correo
- Soporte de reglas YARA personalizadas
- Indicador de confianza por detección (falso positivo vs amenaza real)
- Sistema de cuarentena local con restauración
- Reportes en JSON, TXT y CSV
- Historial de análisis en SQLite local
- Lista blanca por SHA-256
- **Panel de métricas históricas** con estadísticas acumuladas y gráficas
- 100% offline — no transmite datos al exterior
- Sin instalación — corre directamente desde USB

---

## Estructura del proyecto

```
USB_Antivirus/
├── main.py                    Punto de entrada
├── construir_exe.bat          Genera el ejecutable con PyInstaller
├── update_signatures.bat      Descarga firmas (requiere Internet, una sola vez)
│
├── config/
│   └── settings.py            Gestión de configuración portable
│
├── core/
│   ├── scanner.py             Motor multi-worker con ClamAV
│   ├── quarantine.py          Sistema de cuarentena local
│   ├── report.py              Generación de reportes
│   └── database.py            Historial SQLite
│
├── ui/
│   ├── main_window.py         Ventana principal
│   ├── scan_panel.py          Panel lateral con progreso
│   ├── detections_table.py    Tabla de amenazas detectadas
│   ├── finish_panel.py        Panel de resumen al terminar (con métricas de velocidad y tasa)
│   ├── errors_panel.py        Panel de archivos con errores
│   ├── quarantine_window.py   Gestión de cuarentena
│   ├── report_window.py       Historial de análisis
│   ├── dashboard_window.py    Panel de métricas históricas
│   └── settings_window.py     Configuración
│
├── utils/
│   ├── theme.py               Paleta de colores y widgets
│   ├── file_utils.py          Utilidades + detección SSD/HDD
│   ├── threat_classifier.py   Clasificador de amenazas
│   └── whitelist.py           Lista blanca por SHA-256
│
├── clamav/                    ← DESCARGAR APARTE (ver instalación)
├── database/                  ← DESCARGAR APARTE (firmas antivirus)
├── quarantine/                Archivos aislados (vacía al inicio)
├── reports/                   Reportes generados
└── logs/                      Registros de errores
```

---

## Requisitos

- Windows 10 o Windows 11 (64-bit)
- Python 3.10 o superior
- ClamAV 1.5.4 para Windows (descarga aparte)
- Firmas antivirus descargadas con `freshclam`

---

## Instalación

### 1. Clonar el repositorio

```powershell
git clone https://github.com/S2-N-O-N-S2/usb-antivirus.git
cd usb-antivirus
```

### 2. Descargar ClamAV para Windows

Descarga el paquete ZIP de ClamAV 1.5.4 desde:  
https://www.clamav.net/downloads

Extrae todos los archivos `.exe` y `.dll` en la carpeta `clamav\`.

### 3. Descargar las firmas antivirus

Ejecuta **en una computadora con Internet**:

```
update_signatures.bat
```

Esto descarga `main.cvd`, `daily.cvd` y `bytecode.cvd` en `database\` (~107 MB).

### 4. Instalar PyInstaller (opcional, solo para generar .exe)

```powershell
pip install pyinstaller
```

---

## Ejecutar desde Python

```powershell
python main.py
```

---

## Generar ejecutable portátil (.exe)

```
construir_exe.bat
```

El resultado queda en `LISTO_PARA_USB\` listo para copiar a una USB.  
El `.exe` incluye Python internamente — no requiere instalación en la PC destino.

---

## Uso desde USB

1. Copia la carpeta `LISTO_PARA_USB\` completa a tu USB
2. En cualquier PC con Windows 10/11: doble clic en `USB_Antivirus.exe`
3. No instala nada, no modifica el registro, no requiere Internet

---

## Prueba con EICAR

Para verificar que el motor funciona sin usar malware real:

1. Descarga el archivo de prueba de https://www.eicar.org/download-anti-malware-testfile/
2. Usa "Analizar archivo" y selecciona el archivo descargado
3. Debe detectar: `Win.Test.EICAR_HDB-1` (categoría: Archivo de prueba)

---

## Actualizar firmas

Las firmas se actualizan varias veces al día. Para actualizar:

1. Conecta la USB a una PC con Internet
2. Ejecuta `update_signatures.bat`
3. La app muestra un aviso cuando las firmas tienen más de 7 días

---

## Reglas YARA (opcional)

Coloca archivos `.yar` o `.yara` en `clamav\yara\` para ampliar la detección.  
Fuentes gratuitas: [Yara-Rules](https://github.com/Yara-Rules/rules), [Neo23x0](https://github.com/Neo23x0/signature-base)

---

## Panel de métricas

Accede desde **Archivo → 📊 Métricas** o desde el botón de la cabecera principal.

El panel muestra estadísticas acumuladas de todos los análisis realizados con esa USB:

### Resumen global
| Métrica | Descripción |
|---|---|
| Análisis realizados | Total de análisis completados o cancelados |
| Archivos examinados | Suma de todos los archivos procesados |
| Amenazas detectadas | Total histórico de detecciones |
| Tasa de detección | `amenazas / archivos × 100` — indica qué tan infectados han estado los dispositivos analizados |
| Análisis sin amenazas | Conteo y porcentaje de análisis completamente limpios |
| En cuarentena | Archivos aislados actualmente |
| Tiempo total acumulado | Suma de todas las duraciones de análisis |
| Duración media | Tiempo promedio por análisis |
| Errores acumulados | Archivos que no pudieron analizarse por permisos o bloqueo del SO |

### Tendencia (últimos 20 análisis)
- Tres sparklines: archivos escaneados, amenazas detectadas y duración en segundos
- Tabla compacta con los 10 análisis más recientes (tipo, fecha, archivos, amenazas, tiempo, estado)

### Distribución de amenazas
- Gráfica de barras horizontales por **categoría** (Ransomware, Troyano, Gusano…)
- Gráfica de barras horizontales por **nivel de riesgo** (Crítico → Prueba)

### Desglose adicional
- Extensiones de archivo más frecuentes en detecciones (`.exe`, `.dll`, `.bat`…)
- Conteo de análisis por tipo con porcentaje (Rápido, USB, Carpeta, Completo…)

> Las gráficas están implementadas con Canvas puro de Tkinter. No requieren `matplotlib` ni ninguna dependencia adicional.

### Métricas en el resumen por análisis

Al finalizar cada análisis, el panel de resultados ahora muestra 9 tarjetas en lugar de 6:

| Nueva métrica | Descripción |
|---|---|
| ⚡ Velocidad | Archivos por segundo durante el análisis |
| 🎯 Tasa de detección | Porcentaje de archivos que resultaron infectados |
| ⏭ Archivos omitidos | Archivos que no pudieron analizarse |

---

## Limitaciones

- Solo detecta amenazas conocidas hasta la fecha de las firmas
- Archivos en uso o con permisos restringidos no pueden analizarse
- No incluye protección en tiempo real (solo análisis bajo demanda)
- ClamAV puede generar falsos positivos en algunos instaladores legítimos

---

## Licencia

MIT — libre para uso personal y comercial.  
ClamAV tiene su propia licencia GPL v2 (ver `clamav\COPYING\`).

---

*USB Antivirus no reemplaza a un antivirus instalado en el sistema.  
Sirve como herramienta de análisis portátil y complementaria.*
