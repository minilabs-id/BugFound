@echo off
setlocal
cd /d "%~dp0"
if not exist "target\release\agentbug-desktop.exe" (
  echo Building AgentBug Desktop...
  cargo build --release -p agentbug-desktop
  if errorlevel 1 exit /b 1
)
start "" "target\release\agentbug-desktop.exe"
endlocal
