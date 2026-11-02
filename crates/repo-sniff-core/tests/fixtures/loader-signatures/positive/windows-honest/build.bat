@echo off
rem SYNTHETIC TEST FIXTURE — not functional
powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1
certutil -hashfile app.exe SHA256
bitsadmin /list
regsvr32 /s mylib.dll
rundll32 user32.dll,LockWorkStation
