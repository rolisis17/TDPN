@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "PS1=%SCRIPT_DIR%desktop_release_bundle.ps1"

if not exist "%PS1%" (
  echo Missing PowerShell script: "%PS1%"
  endlocal & exit /b 1
)

if not "%~1"=="" (
  set "FORWARD_ARGS=%*"
  echo(%FORWARD_ARGS%| findstr /r "[&|<>^]" >nul
  if not errorlevel 1 (
    echo Unsupported cmd metacharacters in arguments. Use "%PS1%" directly.
    exit /b 2
  )
)
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
set "EXIT_CODE=%ERRORLEVEL%"

if not "%EXIT_CODE%"=="0" (
  echo.
  echo Desktop release bundle scaffold failed with exit code %EXIT_CODE%.
)

endlocal & exit /b %EXIT_CODE%
