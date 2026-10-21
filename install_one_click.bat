@echo off
setlocal DisableDelayedExpansion
rem Run beside this checkout, even when launched by double-click or from elsewhere.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\install_one_click.ps1" %*
exit /b %errorlevel%
