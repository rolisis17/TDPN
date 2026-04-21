@echo off
setlocal DisableDelayedExpansion
set "SCRIPT_DIR=%~dp0"
set "PS1=%SCRIPT_DIR%desktop_one_click.ps1"
if not exist "%PS1%" (
  echo missing script: %PS1%
  exit /b 1
)

set "PS_EXEC_POLICY_ARG="
if /I "%GPM_DESKTOP_ENABLE_POLICY_BYPASS%"=="1" set "PS_EXEC_POLICY_ARG=-ExecutionPolicy Bypass"
if /I "%TDPN_DESKTOP_ENABLE_POLICY_BYPASS%"=="1" set "PS_EXEC_POLICY_ARG=-ExecutionPolicy Bypass"

if not "%~1"=="" (
  set "FORWARD_ARGS=%*"
  powershell.exe -NoLogo -NoProfile -Command "$argsLine = $env:FORWARD_ARGS; if ($argsLine -match '[&|<>^%%!]') { exit 2 }; if ($argsLine -match '(^|\s)-EnablePolicyBypass(\s|$|:\$?(true|1)(\s|$))') { exit 42 }"
  if errorlevel 42 (
    set "PS_EXEC_POLICY_ARG=-ExecutionPolicy Bypass"
  ) else if errorlevel 2 (
    echo Unsupported cmd metacharacters in arguments. Use "%PS1%" directly.
    exit /b 2
  )
)
powershell.exe -NoLogo -NoProfile %PS_EXEC_POLICY_ARG% -File "%PS1%" %*
set "RC=%ERRORLEVEL%"
exit /b %RC%
