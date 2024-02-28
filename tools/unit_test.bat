start /b build\tests\target.exe

:search
tasklist|find "target"
IF %ERRORLEVEL% == 0 GOTO :found
TIMEOUT /T 1
GOTO :search

:found
.\build\tests\unit.exe
