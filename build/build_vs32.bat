:: Visual Studio Build (x86_32)
::   Make sure you have 32 bit VS environment variables by running 'vsvars32.bat'

@echo off

if not exist ".\bin\" (
	mkdir "bin"
)

if not exist ".\bin\Win32\" (
	mkdir ".\bin\Win32"
)

if not exist ".\bin\Win32\obj\" (
	mkdir ".\bin\Win32\obj"
)

del /f /q /s ".\bin\Win32"
cl.exe /Z7 /LD /MD "..\libmem\libmem.c" /Fo".\bin\Win32\obj\libmem.o" /link /OUT:".\bin\Win32\libmem.dll"
