@echo off
setlocal
cd /d "%~dp0"
if not exist "target\release\minibug-desktop.exe" (
  echo Building MiniBug Desktop...
  cargo build --release -p minibug-desktop
  if errorlevel 1 exit /b 1
)
start "" "target\release\minibug-desktop.exe"
endlocal
