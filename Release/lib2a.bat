@echo off
set PATH=c:\MinGW64\bin
gendef TitanEngine.dll
dlltool --as-flags=--32 -m i386 -k --output-lib TitanEngine_x86.a --input-def TitanEngine.def
del TitanEngine.def