"""
Clasificador de amenazas y evaluador de confianza.
No inventa categorías — si no hay información suficiente usa 'No determinada'.
"""

from dataclasses import dataclass

# ──────────────────────────────────────────────────────────────────────────────
# Patrones de clasificación
# ──────────────────────────────────────────────────────────────────────────────

_PATTERNS: list[tuple[list[str], str, int, str]] = [
    # keywords, categoría, riesgo(0-5), descripción detallada
    (["Ransomware", "Ransom", "Cryptor", "Locker", "FileCrypt"],
     "Ransomware", 5,
     "Cifra tus archivos y exige pago para recuperarlos. "
     "Puede dejar inutilizable el equipo en minutos. "
     "Acción recomendada: aislar de inmediato y desconectar del dispositivo."),

    (["Trojan", "Troj", "Backdoor", "RAT", "RemoteAccess"],
     "Troyano", 5,
     "Se disfraza de programa legítimo para dar acceso remoto al atacante. "
     "Puede robar contraseñas, activar la cámara o instalar más malware. "
     "Acción recomendada: aislar y no usar el equipo hasta limpiar."),

    (["Rootkit"],
     "Rootkit", 5,
     "Se oculta en el sistema operativo con privilegios de administrador. "
     "Muy difícil de detectar y eliminar. Puede sobrevivir al formateo. "
     "Acción recomendada: formateo completo del sistema operativo."),

    (["Stealer", "InfoStealer", "PWS", "PasswordStealer", "Credential"],
     "Ladrón de información", 5,
     "Roba contraseñas, cookies de sesión, datos bancarios y credenciales. "
     "Puede comprometer cuentas bancarias, correos y redes sociales. "
     "Acción recomendada: aislar, cambiar todas las contraseñas desde otro equipo."),

    (["Banker", "BankTrojan", "Phishing", "Fraud"],
     "Troyano bancario", 5,
     "Diseñado para robar credenciales bancarias en línea. "
     "Puede interceptar transacciones y redirigir transferencias. "
     "Acción recomendada: aislar, contactar al banco y cambiar contraseñas."),

    (["Worm", "Gusano", "AutoRun", "Autorun"],
     "Gusano", 4,
     "Se replica automáticamente por redes, USB y carpetas compartidas. "
     "Puede saturar la red y propagar malware a otros equipos. "
     "Acción recomendada: aislar el archivo y revisar otros dispositivos conectados."),

    (["Virus", "Infector", "Prepend", "Append", "Overwrite", "Companion"],
     "Virus", 4,
     "Se inserta en archivos ejecutables para propagarse al abrirlos. "
     "Puede dañar o corromper archivos del sistema. "
     "Acción recomendada: aislar y escanear todos los archivos ejecutables."),

    (["Spyware", "Spy", "Keylogger", "Monitor"],
     "Spyware / Keylogger", 4,
     "Registra todo lo que escribes, incluyendo contraseñas. "
     "Puede enviar capturas de pantalla y registros al atacante. "
     "Acción recomendada: aislar, revisar el equipo completo."),

    (["Exploit", "CVE-", "Shellcode", "HeapSpray", "StackOverflow"],
     "Exploit", 4,
     "Aprovecha vulnerabilidades del sistema para ejecutar código malicioso. "
     "Puede comprometer el sistema sin que el usuario haga nada. "
     "Acción recomendada: aislar y mantener el sistema actualizado."),

    (["Botnet", "Bot", "Zombie", "DDoS"],
     "Botnet", 4,
     "Convierte el equipo en parte de una red de ataques controlada remotamente. "
     "Puede usarse para ataques DDoS, envío de spam o minería. "
     "Acción recomendada: aislar y limpiar el sistema."),

    (["Miner", "CoinMiner", "CryptoMiner", "XMR", "Monero"],
     "Minero de criptomonedas", 3,
     "Usa la CPU/GPU del equipo para minar criptomonedas sin permiso. "
     "Ralentiza el equipo y aumenta el consumo eléctrico. "
     "Acción recomendada: eliminar, generalmente no roba datos."),

    (["Macro", "VBA", "Word.Macro", "Excel.Macro", "Office.Macro"],
     "Macro maliciosa", 3,
     "Código malicioso embebido en documentos de Office (Word, Excel). "
     "Se activa al abrir el documento y puede descargar más malware. "
     "Acción recomendada: no abrir el documento, aislar el archivo."),

    (["Script", "JS.", "VBS.", "PS1.", "BAT.", "CMD.", "PowerShell", "HTA"],
     "Script malicioso", 3,
     "Script diseñado para ejecutar acciones maliciosas en el sistema. "
     "Puede descargar malware, modificar el registro o crear usuarios. "
     "Acción recomendada: aislar, no ejecutar."),

    (["Adware", "Downloader", "Dropper", "Installer"],
     "Adware / Dropper", 3,
     "Muestra publicidad no deseada o instala otro software sin permiso. "
     "Droppers pueden descargar malware más peligroso. "
     "Acción recomendada: eliminar, revisar otros programas instalados."),

    (["PUA", "PUP", "Potentially", "Riskware", "RiskTool", "Unwanted", "Unwanted"],
     "Aplicación potencialmente no deseada (PUA)", 2,
     "Programa no necesariamente malicioso pero indeseable: toolbars, "
     "optimizadores falsos, adware leve. "
     "Acción recomendada: evaluar si lo instalaste intencionalmente."),

    (["Joke", "Hoax", "Prank"],
     "Broma / Probable falso positivo", 1,
     "Programa inofensivo diseñado como broma. "
     "No causa daño real al sistema. "
     "Acción recomendada: eliminar si no lo instalaste tú."),

    (["Test", "EICAR"],
     "Archivo de prueba (EICAR)", 0,
     "Archivo estándar de prueba de la industria antivirus. "
     "No es malware real, solo sirve para verificar que el antivirus funciona. "
     "Acción recomendada: ninguna, es completamente inofensivo."),
]

_RISK_LABELS = {
    0: "Prueba",
    1: "Muy bajo",
    2: "Bajo",
    3: "Medio",
    4: "Alto",
    5: "Crítico",
}

_RISK_COLORS = {
    0: "#3a86ff",
    1: "#8ecae6",
    2: "#90e0ef",
    3: "#ffd166",
    4: "#ef8c2f",
    5: "#e63946",
}

# Acciones recomendadas por nivel (fallback)
_RISK_ACTIONS = {
    0: "Ninguna — archivo de prueba inofensivo.",
    1: "Evaluar origen. Generalmente seguro eliminar.",
    2: "Revisar si lo instalaste intencionalmente. Eliminar si no.",
    3: "Aislar el archivo. No ejecutar. Revisar el equipo.",
    4: "Aislar inmediatamente. Cambiar contraseñas. Revisar el equipo completo.",
    5: "URGENTE: Aislar, desconectar de redes, cambiar todas las contraseñas desde otro equipo.",
}


@dataclass
class ThreatInfo:
    detection_name: str
    category:       str
    risk_level:     int
    risk_label:     str
    risk_color:     str
    description:    str   # ← descripción detallada del tipo de amenaza
    action:         str   # ← acción recomendada


def classify(detection_name: str) -> ThreatInfo:
    if not detection_name or not detection_name.strip():
        return ThreatInfo(
            detection_name=detection_name,
            category="No determinada",
            risk_level=3,
            risk_label=_RISK_LABELS[3],
            risk_color=_RISK_COLORS[3],
            description="No se pudo determinar el tipo de amenaza con la información disponible.",
            action=_RISK_ACTIONS[3],
        )

    name_upper = detection_name.upper()

    for keywords, category, risk, description in _PATTERNS:
        for kw in keywords:
            if kw.upper() in name_upper:
                return ThreatInfo(
                    detection_name=detection_name,
                    category=category,
                    risk_level=risk,
                    risk_label=_RISK_LABELS[risk],
                    risk_color=_RISK_COLORS[risk],
                    description=description,
                    action=_RISK_ACTIONS[risk],
                )

    return ThreatInfo(
        detection_name=detection_name,
        category="No determinada",
        risk_level=3,
        risk_label=_RISK_LABELS[3],
        risk_color=_RISK_COLORS[3],
        description="Detección sin categoría conocida. Puede ser una variante nueva o un falso positivo.",
        action=_RISK_ACTIONS[3],
    )


def risk_color(risk_level: int) -> str:
    return _RISK_COLORS.get(risk_level, "#ffd166")


# ──────────────────────────────────────────────────────────────────────────────
# Indicador de confianza
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ConfidenceResult:
    label:       str
    color:       str
    icon:        str
    explanation: str


_FP_PATH_HINTS = [
    "program files", "program files (x86)",
    "windows", "system32", "syswow64",
    "microsoft", "sql server", "office",
    "installer", "setup", "install",
]

_FP_EXTENSIONS = {
    ".rtf", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".txt", ".log", ".ini", ".cfg", ".xml", ".json",
}

_FP_DETECTION_PREFIXES = ["PUA.", "Heuristics.Encrypted", "Heuristics.OLE2"]

_REAL_THREAT_KEYWORDS = [
    "Trojan", "Backdoor", "RAT", "Ransomware", "Rootkit",
    "Stealer", "Banker", "Keylogger", "Worm", "Dropper",
    "Miner", "CoinMiner", "Botnet", "Exploit.Win",
]

_RISKY_PATH_HINTS = [
    "\\temp\\", "\\tmp\\", "appdata\\local\\temp",
    "\\startup\\", "\\start menu\\programs\\startup",
    "recycle.bin",
]


def assess_confidence(file_path: str, detection_name: str,
                      file_ext: str) -> ConfidenceResult:
    path_lower = file_path.lower().replace("/", "\\")
    det_upper  = detection_name.upper()
    ext_lower  = (file_ext or "").lower()

    real_signals = 0
    fp_signals   = 0

    for kw in _REAL_THREAT_KEYWORDS:
        if kw.upper() in det_upper:
            real_signals += 2

    for hint in _RISKY_PATH_HINTS:
        if hint in path_lower:
            real_signals += 1

    if ext_lower in {".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".cmd"}:
        real_signals += 1

    for prefix in _FP_DETECTION_PREFIXES:
        if detection_name.startswith(prefix):
            fp_signals += 2

    for hint in _FP_PATH_HINTS:
        if hint in path_lower:
            fp_signals += 1

    if ext_lower in _FP_EXTENSIONS:
        fp_signals += 1

    score = real_signals - fp_signals

    if score >= 3:
        return ConfidenceResult(
            label="Confirmar amenaza",
            color="#ef4444", icon="🔴",
            explanation="Múltiples señales apuntan a malware real. Aislar inmediatamente.",
        )
    if score >= 1:
        return ConfidenceResult(
            label="Sospechoso",
            color="#f97316", icon="🟠",
            explanation="Señales mixtas. Verificar manualmente antes de actuar.",
        )
    if score == 0:
        return ConfidenceResult(
            label="Revisar",
            color="#f59e0b", icon="🟡",
            explanation="Sin señales claras. Verifica el origen del archivo.",
        )
    return ConfidenceResult(
        label="Probable falso positivo",
        color="#22c55e", icon="🟢",
        explanation="Ubicación y tipo sugieren que es seguro. Confirma si no lo reconoces.",
    )
