@echo off
:: ============================================================
:: build_exe.bat — Empaqueta USB Antivirus con PyInstaller
:: Ejecuta este script desde la carpeta USB_Antivirus
:: Requiere: pip install pyinstaller
:: ============================================================

echo.
echo === USB Antivirus — Generando ejecutable ===
echo.

:: Verificar que pyinstaller está disponible
pyinstaller --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: PyInstaller no encontrado.
    echo Instálalo con: pip install pyinstaller
    pause
    exit /b 1
)

:: Limpiar compilaciones anteriores
if exist build  rmdir /s /q build
if exist dist   rmdir /s /q dist

:: Compilar
pyinstaller ^
    --onefile ^
    --windowed ^
    --name "USB_Antivirus" ^
    --icon "assets\icon.ico" ^
    --add-data "config;config" ^
    --add-data "ui;ui" ^
    --add-data "core;core" ^
    --add-data "utils;utils" ^
    --hidden-import "tkinter" ^
    --hidden-import "tkinter.ttk" ^
    --hidden-import "tkinter.filedialog" ^
    --hidden-import "tkinter.messagebox" ^
    --hidden-import "sqlite3" ^
    --hidden-import "ctypes" ^
    main.py

if errorlevel 1 (
    echo.
    echo ERROR: La compilacion fallo. Revisa los mensajes anteriores.
    pause
    exit /b 1
)

echo.
echo === Ejecutable generado en: dist\USB_Antivirus.exe ===
echo.
echo Ahora copia el contenido de USB_Antivirus\ a tu memoria USB:
echo   - dist\USB_Antivirus.exe
echo   - clamav\
echo   - database\
echo   - quarantine\  (vacia)
echo   - reports\     (vacia)
echo   - config\
echo   - logs\        (vacia)
echo.
pause
