@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

:: ============================================================
::  USB ANTIVIRUS — Constructor de ejecutable portátil
::
::  Genera la carpeta LISTO_PARA_USB\ con todo incluido:
::    USB_Antivirus.exe  (Python embebido, sin instalación)
::    clamav\            (motor antivirus)
::    database\          (firmas)
::    quarantine\, reports\, logs\, config\
::
::  Ejecuta UNA VEZ en tu PC con Internet.
::  Luego copia LISTO_PARA_USB\ a tu memoria USB.
:: ============================================================

echo.
echo  =====================================================
echo   USB ANTIVIRUS ^| Generador de ejecutable portatil
echo  =====================================================
echo.

set "BASE=%~dp0"
if "%BASE:~-1%"=="\" set "BASE=%BASE:~0,-1%"
set "DIST=%BASE%\LISTO_PARA_USB"

:: ── PASO 1: Verificar Python ──────────────────────────────
echo [1/5] Verificando Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo  ERROR: Python no encontrado.
    echo  Descarga desde: https://www.python.org/downloads/
    echo  Marca "Add Python to PATH" al instalar.
    pause & exit /b 1
)
for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo  OK - %%v

:: ── PASO 2: Verificar/instalar PyInstaller ────────────────
echo.
echo [2/5] Verificando PyInstaller...
python -c "import PyInstaller" >nul 2>&1
if errorlevel 1 (
    echo  Instalando PyInstaller...
    python -m pip install pyinstaller --quiet
    if errorlevel 1 (
        echo  ERROR instalando PyInstaller.
        pause & exit /b 1
    )
)
for /f "tokens=*" %%v in ('python -c "import PyInstaller; print(PyInstaller.__version__)"') do echo  OK - PyInstaller %%v

:: ── PASO 3: Limpiar y compilar ────────────────────────────
echo.
echo [3/5] Compilando ejecutable (2-5 minutos)...
echo.

if exist "%BASE%\build_temp" rmdir /s /q "%BASE%\build_temp"
if exist "%BASE%\dist_temp"  rmdir /s /q "%BASE%\dist_temp"

python -m PyInstaller ^
    --onefile ^
    --windowed ^
    --name "USB_Antivirus" ^
    --distpath "%BASE%\dist_temp" ^
    --workpath "%BASE%\build_temp" ^
    "--add-data=%BASE%\config;config" ^
    "--add-data=%BASE%\ui;ui" ^
    "--add-data=%BASE%\core;core" ^
    "--add-data=%BASE%\utils;utils" ^
    --hidden-import tkinter ^
    --hidden-import tkinter.ttk ^
    --hidden-import tkinter.filedialog ^
    --hidden-import tkinter.messagebox ^
    --hidden-import tkinter.simpledialog ^
    --hidden-import sqlite3 ^
    --hidden-import ctypes ^
    --hidden-import json ^
    --hidden-import hashlib ^
    --hidden-import threading ^
    --hidden-import subprocess ^
    --hidden-import logging ^
    --hidden-import pathlib ^
    --hidden-import csv ^
    --hidden-import re ^
    --noconfirm ^
    "%BASE%\main.py"

if errorlevel 1 (
    echo.
    echo  ERROR: Compilacion fallida. Revisa los mensajes anteriores.
    pause & exit /b 1
)
echo.
echo  OK - Ejecutable generado.

:: ── PASO 4: Armar carpeta LISTO_PARA_USB ─────────────────
echo.
echo [4/5] Armando carpeta LISTO_PARA_USB\...

if exist "%DIST%" rmdir /s /q "%DIST%"
mkdir "%DIST%"

copy "%BASE%\dist_temp\USB_Antivirus.exe" "%DIST%\USB_Antivirus.exe" >nul
echo  + USB_Antivirus.exe

xcopy "%BASE%\clamav"    "%DIST%\clamav\"    /E /I /Q >nul
echo  + clamav\

if exist "%BASE%\database" (
    xcopy "%BASE%\database" "%DIST%\database\" /E /I /Q >nul
    echo  + database\  (firmas incluidas)
) else (
    mkdir "%DIST%\database"
    echo  AVISO: database\ vacia. Ejecuta update_signatures.bat antes de copiar a USB.
)

mkdir "%DIST%\quarantine"
mkdir "%DIST%\reports"
mkdir "%DIST%\logs"
mkdir "%DIST%\config"
echo  + quarantine\, reports\, logs\, config\

copy "%BASE%\update_signatures.bat" "%DIST%\update_signatures.bat" >nul
copy "%BASE%\README.md"             "%DIST%\README.md" >nul
echo  + update_signatures.bat, README.md

echo CUARENTENA - No abrir ni ejecutar archivos manualmente. > "%DIST%\quarantine\NO_EJECUTAR.txt"

:: Limpiar temporales
rmdir /s /q "%BASE%\build_temp" >nul 2>&1
rmdir /s /q "%BASE%\dist_temp"  >nul 2>&1
if exist "%BASE%\USB_Antivirus.spec" del /q "%BASE%\USB_Antivirus.spec"

:: ── PASO 5: Resultado ─────────────────────────────────────
echo.
echo [5/5] Calculando tamano final...

powershell -NoProfile -Command "$s=(Get-ChildItem '%DIST%' -Recurse -File | Measure-Object -Property Length -Sum).Sum; $n=(Get-ChildItem '%DIST%' -Recurse -File).Count; Write-Host ('  Archivos: ' + $n + '  |  Tamano: ' + [math]::Round($s/1MB,1) + ' MB')"

echo.
echo  =====================================================
echo   LISTO
echo  =====================================================
echo.
echo  Carpeta generada: %DIST%
echo.
echo  PROXIMOS PASOS:
echo  1. Copia la carpeta LISTO_PARA_USB\ a tu memoria USB
echo  2. En cualquier PC Windows 10/11, ejecuta:
echo        USB_Antivirus.exe
echo  3. No requiere Python, Internet ni instalacion
echo.
echo  NOTA: Si database\ esta vacia, ejecuta primero:
echo        update_signatures.bat  (requiere Internet)
echo.
pause
