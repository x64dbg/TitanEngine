@echo off
IF EXIST TitanScriptRelease rmdir TitanScriptRelease /s /q
mkdir TitanScriptRelease
mkdir .\TitanScriptRelease\x86
mkdir .\TitanScriptRelease\x64

copy .\Release\x32\TitanScriptGui.exe .\TitanScriptRelease\x86\TitanScriptGuix86.exe
copy .\Release\x32\TitanScriptGui.map .\TitanScriptRelease\x86\TitanScriptGuix86.map
copy .\Release\x32\TitanEngine.dll .\TitanScriptRelease\x86\TitanEngine.dll

copy .\Release\x64\TitanScriptGui.exe .\TitanScriptRelease\x64\TitanScriptGuix64.exe
copy .\Release\x64\TitanScriptGui.map .\TitanScriptRelease\x64\TitanScriptGuix64.map
copy .\Release\x64\TitanEngine.dll .\TitanScriptRelease\x64\TitanEngine.dll

exit

