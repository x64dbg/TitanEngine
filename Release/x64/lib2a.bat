@echo off
set PATH=c:\MinGW64\bin
gendef TitanEngine.dll
dlltool --as-flags=--64 -m i386:x86-64 -k --output-lib TitanEngine_x64.a --input-def TitanEngine.def
del TitanEngine.def