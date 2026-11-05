@echo off
:: ============================================================
:: update_signatures.bat
:: Descarga/actualiza las firmas antivirus usando freshclam.
:: Ejecuta SOLO en una computadora CON conexión a Internet.
:: Solo necesitas hacerlo una vez antes de copiar a la USB.
:: ============================================================

echo.
echo === USB Antivirus -- Actualizacion de firmas ===
echo IMPORTANTE: Este proceso requiere conexion a Internet.
echo.

:: Rutas relativas al directorio donde está este .bat
set BASE_DIR=%~dp0
set CLAMAV_DIR=%BASE_DIR%clamav
set DB_DIR=%BASE_DIR%database
set LOG_DIR=%BASE_DIR%logs
set CERTS_DIR=%CLAMAV_DIR%\certs
set FRESHCLAM=%CLAMAV_DIR%\freshclam.exe
set CONF=%CLAMAV_DIR%\freshclam.conf

:: Verificar freshclam.exe
if not exist "%FRESHCLAM%" (
    echo ERROR: No se encontro freshclam.exe en: %CLAMAV_DIR%
    echo Asegurate de haber copiado los archivos de ClamAV a la carpeta clamav\
    pause
    exit /b 1
)

:: Crear carpetas si no existen
if not exist "%DB_DIR%"  mkdir "%DB_DIR%"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

echo Destino de firmas : %DB_DIR%
echo Log               : %LOG_DIR%\freshclam.log
echo.

:: Ejecutar freshclam pasando TODAS las rutas por argumento
:: Esto evita que busque rutas absolutas hardcodeadas en el .conf
"%FRESHCLAM%" ^
    --config-file="%CONF%" ^
    --datadir="%DB_DIR%" ^
    --cvdcertsdir="%CERTS_DIR%" ^
    --log="%LOG_DIR%\freshclam.log" ^
    --no-dns

set EXIT_CODE=%ERRORLEVEL%

echo.
if %EXIT_CODE% EQU 0 (
    echo Firmas actualizadas correctamente.
    echo Archivos en database\:
    dir /b "%DB_DIR%\*.cvd" "%DB_DIR%\*.cld" 2>nul
) else if %EXIT_CODE% EQU 1 (
    echo Las firmas ya estan actualizadas. No fue necesario descargar nada.
) else (
    echo ADVERTENCIA: freshclam termino con codigo %EXIT_CODE%
    echo Revisa %LOG_DIR%\freshclam.log para mas informacion.
)

echo.
pause
