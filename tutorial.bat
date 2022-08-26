
:start
@ECHO OFF
title TUTORIAL [START]
echo TUTORIAL
echo.
echo.
echo EXIT - EX
echo HELP - INF
echo.
echo.
SET /P OPCSTART=Wybierz opcje: 
IF '%OPCSTART%'=='EX' goto exit
IF '%OPCSTART%'=='INF' goto info
IF '%OPCSTART%'=='MOT' goto motive


:info
@ECHO OFF
title TUTORIAL [INFO]
cls
echo aplikacja TUTORIAL zostala stworzona w celach edukacyjnych
echo przez Himo Code na potrzeby odcinka
echo.
echo Aby wrocic kilkij przycisk na klawiaturze
pause
goto start
:exit
@ECHO OFF
title TUTORIAL [EXIT]
cls
echo Aby zamknac kilkij przycisk na klawiaturze
echo.
echo.
pause>nul

:motive
@ECHO OFF
cls
echo GREEN - GREEN MOTIVE
echo.
echo BLUE - BLUE MOTIVE
echo.
echo RED - RED MOTIVE

SET /P OPCMOTIVE=Wybierz opcje: 
IF '%OPCMOTIVE%'=='RED' goto motivered
IF '%OPCMOTIVE%'=='GREEN' goto motivegreen
IF '%OPCMOTIVE%'=='BLUE' goto motiveblue


:motivered
cls
color C
goto start
:motivegreen
cls
COLOR A
goto start
:motiveblue
cls
color B
goto start