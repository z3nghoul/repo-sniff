# SYNTHETIC TEST FIXTURE — not functional
$cmd = "Get-Date"
Invoke-Expression $cmd
Invoke-WebRequest -Uri 'https://downloads.example.invalid/tool.zip' -OutFile tool.zip
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
