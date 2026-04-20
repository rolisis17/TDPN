@echo off
setlocal

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0desktop_installer.ps1" %*
set "RC=%ERRORLEVEL%"

endlocal & exit /b %RC%
