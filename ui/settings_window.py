"""
Ventana de configuración de la aplicación.
"""

import tkinter as tk
from tkinter import filedialog, messagebox

from config.settings import settings
from utils.theme import ACCENT, BG_DARK, BG_PANEL, BG_CARD, BG_INPUT, BORDER, TEXT_PRI, TEXT_SEC, MUTED, OK, WARN, DANGER

# Alias locales para compatibilidad con el código existente
COLOR_BG    = BG_DARK
COLOR_BG2   = BG_PANEL
COLOR_TEXT  = TEXT_PRI
COLOR_ACCENT= ACCENT
COLOR_BTN   = BG_CARD
COLOR_ENTRY = BG_INPUT
COLOR_GREEN = OK


class SettingsWindow(tk.Toplevel):

    def __init__(self, parent, on_save=None):
        super().__init__(parent)
        self.title("Configuración — USB Antivirus")
        self.configure(bg=COLOR_BG)
        self.geometry("660x580")
        self.resizable(False, False)
        self.grab_set()
        self._on_save = on_save
        self._vars: dict[str, tk.StringVar] = {}
        self._build()
        self._load_values()

    def _build(self):
        tk.Label(self, text="⚙  Configuración",
                 font=("Segoe UI", 14, "bold"),
                 fg=COLOR_ACCENT, bg=COLOR_BG).pack(anchor="w", padx=20, pady=(16, 8))

        # ── Rutas ─────────────────────────────────────────────────────────────
        form = tk.LabelFrame(self, text="  Rutas  ",
                             font=("Segoe UI", 9, "bold"),
                             fg=COLOR_ACCENT, bg=COLOR_BG2,
                             padx=12, pady=8, relief="flat")
        form.pack(fill="x", padx=16, pady=(0, 4))

        for key, label in [
            ("clamav_dir",    "Carpeta ClamAV"),
            ("database_dir",  "Firmas (.cvd / .cld)"),
            ("quarantine_dir","Cuarentena"),
            ("reports_dir",   "Reportes"),
            ("logs_dir",      "Logs"),
        ]:
            self._path_row(form, key, label)

        # ── Opciones de análisis ──────────────────────────────────────────────
        opts = tk.LabelFrame(self, text="  Análisis  ",
                             font=("Segoe UI", 9, "bold"),
                             fg=COLOR_ACCENT, bg=COLOR_BG2,
                             padx=12, pady=8, relief="flat")
        opts.pack(fill="x", padx=16, pady=4)

        row = 0

        # Workers: automático o manual
        tk.Label(opts, text="Workers paralelos:",
                 fg=COLOR_TEXT, bg=COLOR_BG2,
                 font=("Segoe UI", 9)).grid(row=row, column=0, sticky="w")

        self._vars["num_workers"] = tk.StringVar(value="auto")
        workers_frame = tk.Frame(opts, bg=COLOR_BG2)
        workers_frame.grid(row=row, column=1, columnspan=2, sticky="w", padx=8)

        # Opción automática (recomendada)
        tk.Radiobutton(workers_frame, text="Automático (recomendado)",
                       variable=self._vars["num_workers"], value="auto",
                       bg=COLOR_BG2, fg="#4ade80", selectcolor=COLOR_BG,
                       activebackground=COLOR_BG2,
                       font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 8))

        # Opciones manuales
        for n, lbl in [("1", "1"), ("2", "2"), ("3", "3"), ("4", "4")]:
            tk.Radiobutton(workers_frame, text=lbl,
                           variable=self._vars["num_workers"], value=n,
                           bg=COLOR_BG2, fg=COLOR_TEXT, selectcolor=COLOR_BG,
                           activebackground=COLOR_BG2,
                           font=("Segoe UI", 9)).pack(side="left", padx=2)

        row += 1
        tk.Label(opts,
                 text="En modo automático detecta si el disco es SSD o HDD y elige el número óptimo.",
                 fg="#8ecae6", bg=COLOR_BG2, font=("Segoe UI", 8),
                 wraplength=420, anchor="w").grid(
                     row=row, column=0, columnspan=3, sticky="w", pady=(0, 6))

        # Tamaño máximo
        row += 1
        tk.Label(opts, text="Tamaño máximo de archivo (MB):",
                 fg=COLOR_TEXT, bg=COLOR_BG2,
                 font=("Segoe UI", 9)).grid(row=row, column=0, sticky="w")
        self._vars["max_file_size_mb"] = tk.StringVar()
        tk.Entry(opts, textvariable=self._vars["max_file_size_mb"],
                 bg=COLOR_ENTRY, fg=COLOR_TEXT, insertbackground=COLOR_TEXT,
                 relief="flat", width=8).grid(row=row, column=1, sticky="w", padx=8)

        # Formato de reporte
        row += 1
        tk.Label(opts, text="Formato de reporte:",
                 fg=COLOR_TEXT, bg=COLOR_BG2,
                 font=("Segoe UI", 9)).grid(row=row, column=0, sticky="w", pady=(6, 0))
        self._vars["report_format"] = tk.StringVar()
        fmt_frame = tk.Frame(opts, bg=COLOR_BG2)
        fmt_frame.grid(row=row, column=1, columnspan=2, sticky="w", padx=8, pady=(6, 0))
        for fmt in ("json", "txt", "csv", "all"):
            tk.Radiobutton(fmt_frame, text=fmt.upper(),
                           variable=self._vars["report_format"], value=fmt,
                           bg=COLOR_BG2, fg=COLOR_TEXT, selectcolor=COLOR_BG,
                           activebackground=COLOR_BG2,
                           font=("Segoe UI", 9)).pack(side="left", padx=4)

        # ── Botón de test de disco ────────────────────────────────────────────
        test_frame = tk.Frame(self, bg=COLOR_BG)
        test_frame.pack(fill="x", padx=16, pady=(4, 0))

        self._btn(test_frame, "🔍 Detectar disco ahora",
                  COLOR_BTN, self._detect_disk).pack(side="left")
        self._lbl_disk_result = tk.Label(
            test_frame, text="",
            font=("Segoe UI", 9), fg="#4ade80", bg=COLOR_BG)
        self._lbl_disk_result.pack(side="left", padx=10)

        # ── Botones ───────────────────────────────────────────────────────────
        btn_frame = tk.Frame(self, bg=COLOR_BG)
        btn_frame.pack(fill="x", padx=16, pady=12)

        self._btn(btn_frame, "💾 Guardar", COLOR_ACCENT, self._save).pack(side="left", padx=(0, 8))
        self._btn(btn_frame, "Cancelar",   COLOR_BTN,    self.destroy).pack(side="left")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _path_row(self, parent, key: str, label: str):
        row = tk.Frame(parent, bg=COLOR_BG2)
        row.pack(fill="x", pady=3)
        tk.Label(row, text=label, width=24, anchor="w",
                 fg=COLOR_TEXT, bg=COLOR_BG2,
                 font=("Segoe UI", 9)).pack(side="left")
        var = tk.StringVar()
        self._vars[key] = var
        tk.Entry(row, textvariable=var, bg=COLOR_ENTRY, fg=COLOR_TEXT,
                 insertbackground=COLOR_TEXT, relief="flat",
                 width=32).pack(side="left", padx=6)
        tk.Button(row, text="…", command=lambda k=key: self._browse(k),
                  bg=COLOR_BTN, fg=COLOR_TEXT, relief="flat",
                  font=("Segoe UI", 9), padx=6).pack(side="left")

    def _browse(self, key: str):
        current = self._vars[key].get()
        chosen = filedialog.askdirectory(
            title=f"Seleccionar: {key}",
            initialdir=current if current else "/",
            parent=self,
        )
        if chosen:
            self._vars[key].set(chosen)

    def _btn(self, parent, text, color, command):
        return tk.Button(parent, text=text, command=command,
                         bg=color,
                         fg="#1a1a2e" if color == COLOR_ACCENT else COLOR_TEXT,
                         relief="flat", font=("Segoe UI", 10, "bold"),
                         padx=14, pady=6, cursor="hand2")

    def _detect_disk(self):
        """Ejecuta la detección inmediata y muestra el resultado."""
        import threading
        from utils.file_utils import auto_detect_workers, detect_disk_type
        import os

        self._lbl_disk_result.config(text="Detectando...", fg="#8ecae6")

        def _run():
            home = os.environ.get("USERPROFILE", "C:\\")
            disk  = detect_disk_type(home)
            n, desc = auto_detect_workers(home)
            # CORRECCIÓN: self.after(ms, func, **kwargs) no acepta dict.
            # Usar lambda para pasar kwargs correctamente.
            result_text = f"  {disk} → {n} worker(s)  |  {desc}"
            self.after(0, lambda: self._lbl_disk_result.config(
                text=result_text, fg="#4ade80"))

        threading.Thread(target=_run, daemon=True).start()

    def _load_values(self):
        for key, var in self._vars.items():
            val = settings.get(key, "")
            if val is None:
                val = ""
            var.set(str(val))

    def _save(self):
        for key, var in self._vars.items():
            val = var.get().strip()
            if key == "max_file_size_mb":
                try:
                    val = int(val)
                except ValueError:
                    messagebox.showerror(
                        "Error", "El tamaño máximo debe ser un número entero.", parent=self)
                    return
            settings.set(key, val)
        messagebox.showinfo("Configuración", "Guardado correctamente.", parent=self)
        if self._on_save:
            self._on_save()
        self.destroy()
