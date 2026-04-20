@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
set "PS1=%SCRIPT_DIR%local_api_session.ps1"
if not exist "%PS1%" (
  echo missing script: %PS1%
  exit /b 1
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
set "RC=%ERRORLEVEL%"
exit /b %RC%
