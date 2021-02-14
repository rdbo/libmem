:: Visual Studio Build

cl.exe example.c ..\libmem\libmem.c /link /OUT:example.exe
del /f /q *.obj
