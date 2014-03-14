@echo off
IF EXIST TitanScriptRelease rmdir TitanScriptRelease /s /q
mkdir TitanScriptRelease
mkdir .\TitanScriptRelease\x86
mkdir .\TitanScriptRelease\x64


copy .\Release\x32\TitanScriptGui.exe .\TitanScriptRelease\x86\TitanScriptGuix86.exe
copy .\Release\x32\TitanScriptGui.map .\TitanScriptRelease\x86\TitanScriptGuix86.map
copy .\Release\x32\TitanEngine.dll .\TitanScriptRelease\x86\TitanEngine.dll
copy .\Release\x32\TitanEngine.map .\TitanScriptRelease\x86\TitanEngine.map

copy .\Release\x64\TitanScriptGui.exe .\TitanScriptRelease\x64\TitanScriptGuix64.exe
copy .\Release\x64\TitanScriptGui.map .\TitanScriptRelease\x64\TitanScriptGuix64.map
copy .\Release\x64\TitanEngine.dll .\TitanScriptRelease\x64\TitanEngine.dll
copy .\Release\x64\TitanEngine.map .\TitanScriptRelease\x64\TitanEngine.map

mkdir .\TitanScriptRelease\x86\plugins
mkdir .\TitanScriptRelease\x86\plugins\x86
mkdir .\TitanScriptRelease\x64\plugins
mkdir .\TitanScriptRelease\x64\plugins\x64

copy ..\titanscript-update\Release\Win32\TitanScript.dll .\TitanScriptRelease\x86\plugins\x86\TitanScript.dll
copy ..\titanscript-update\Release\Win32\TitanScript.map .\TitanScriptRelease\x86\plugins\x86\TitanScript.map
copy ..\titanscript-update\Release\x64\TitanScript.dll .\TitanScriptRelease\x64\plugins\x64\TitanScript.dll
copy ..\titanscript-update\Release\x64\TitanScript.map .\TitanScriptRelease\x64\plugins\x64\TitanScript.map

pause

