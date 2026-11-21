@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "ACTION=%~1"
set "URL=%~2"
set "SELECTOR=%~3"
set "OUTPUT=%~4"
set "PREFIX=%~dp0"

if "%URL%"=="" (
  echo {"ok":false,"reason":"url is required"}
  exit /b 0
)

if /I "%ACTION%"=="navigate" (
  npx --prefix "%PREFIX%" chrome-devtools navigate_page 1 --url "%URL%" --output-format md 2>nul
  if errorlevel 1 (
    echo {"ok":false,"reason":"chrome mcp navigate failed"}
    exit /b 0
  )
  npx --prefix "%PREFIX%" chrome-devtools take_snapshot 1 --output-format md 2>nul
  exit /b 0
)

if /I "%ACTION%"=="screenshot" (
  if "%OUTPUT%"=="" set "OUTPUT=screenshot.png"
  npx --prefix "%PREFIX%" chrome-devtools navigate_page 1 --url "%URL%" --output-format md >nul 2>&1
  npx --prefix "%PREFIX%" chrome-devtools take_screenshot 1 --filePath "%OUTPUT%" --output-format md 2>nul
  echo {"ok":true,"action":"screenshot","url":"%URL%","screenshot":"%OUTPUT%","backend":"chrome-devtools-mcp"}
  exit /b 0
)

if /I "%ACTION%"=="click" (
  if "%SELECTOR%"=="" (
    echo {"ok":false,"reason":"selector is required for click"}
    exit /b 0
  )
  echo %SELECTOR% | findstr /C:"'" >nul
  if not errorlevel 1 (
    echo {"ok":false,"reason":"selector contains a quote; refused"}
    exit /b 0
  )
  npx --prefix "%PREFIX%" chrome-devtools navigate_page 1 --url "%URL%" --output-format md >nul 2>&1
  npx --prefix "%PREFIX%" chrome-devtools evaluate_script "document.querySelector('%SELECTOR%').click(); return 'clicked';" --output-format md 2>nul
  exit /b 0
)

echo {"ok":false,"reason":"unsupported action"}
exit /b 0
