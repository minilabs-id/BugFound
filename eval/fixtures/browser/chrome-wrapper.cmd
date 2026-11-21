@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "ACTION=%~1"
set "URL=%~2"
set "SELECTOR=%~3"
set "OUTPUT=%~4"
set "CHROME=C:\Program Files\Google\Chrome\Application\chrome.exe"

if not exist "%CHROME%" set "CHROME=C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
if not exist "%CHROME%" (
  echo {"ok":false,"reason":"no system chromium browser found"}
  exit /b 0
)

if "%URL%"=="" (
  echo {"ok":false,"reason":"url is required"}
  exit /b 0
)

if /I "%ACTION%"=="screenshot" (
  if "%OUTPUT%"=="" set "OUTPUT=screenshot.png"
  "%CHROME%" --headless=new --disable-gpu --no-first-run --no-default-browser-check --hide-scrollbars --window-size=1280,900 --screenshot="%OUTPUT%" "%URL%" >nul 2>&1
  echo {"ok":true,"action":"screenshot","url":"%URL%","screenshot":"%OUTPUT%","backend":"chrome-cli"}
  exit /b 0
)

if /I "%ACTION%"=="click" (
  echo {"ok":false,"reason":"click requires the playwright backend; chrome-cli supports navigate and screenshot only"}
  exit /b 0
)

"%CHROME%" --headless=new --disable-gpu --no-first-run --no-default-browser-check --virtual-time-budget=3000 --dump-dom "%URL%" 2>nul
exit /b 0
