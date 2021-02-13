:: Visual Studio Build (x86_64)
::   Make sure you have VS environment variables by running 'vcvarsall.bat'

@echo off

if not exist ".\bin\" (
	mkdir "bin"
)

if not exist ".\bin\Win64" (
	mkdir ".\bin\Win64"
)

if not exist ".\bin\Win64\obj" (
	mkdir ".\bin\Win64\obj"
)

del /f /q /s ".\bin\Win64"
cl.exe /Z7 /LD /MD "..\libmem\libmem.c" /Fo".\bin\Win64\obj\libmem.o" /link /DLL /IMPLIB:".\bin\Win64\libmem.lib" /OUT:".\bin\Win64\libmem.dll"
