@echo off
setlocal
cd /d "%~dp0"
if not exist "target\release\bugfound-desktop.exe" (
  echo Building BugFound Desktop...
  cargo build --release -p bugfound-desktop
  if errorlevel 1 exit /b 1
)
start "" "target\release\bugfound-desktop.exe"
endlocal
