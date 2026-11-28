@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "PREFIX=%~dp0"

rem Do not interpolate user values into any command line here. Delegate to the
rem Node wrapper, which validates the URL/selector and spawns the CLI with
rem shell=false and separate argv tokens.

if "%~2"=="" (
  echo {"ok":false,"reason":"url is required"}
  exit /b 0
)

node "%PREFIX%chrome-mcp-wrapper.js" %*
exit /b %ERRORLEVEL%
