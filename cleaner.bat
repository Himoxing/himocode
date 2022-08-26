@ECHO OFF
title Cleaner [START]
Color A
:menu
cls
echo===================
echo    LOGI     L
echo===================
echo.
echo===================
echo    TEMP     T
echo===================
echo.
echo===================
echo  WU Cached  C
echo===================
SET /P OPCMENU=Wybierz Typ Plikow: 
if %OPCMENU%=='L' goto LOG
if %OPCMENU%=='C' goto CACH
if %OPCMENU%=='T' goto TEMP

:TEMP
cls
echo Usuwanie plikow temporalnych
RD /S /Q %temp%
MKDIR %temp%
@echo
takeown /f "%temp%" /r /d y
@echo
takeown /f "C:\Windows\Temp" /r /d y
@echo
RD /S /Q C:\Windows\Temp
MKDIR C:\Windows\Temp
@echo
takeown /f "C:\Windows\Temp" /r /d y
takeown /f %temp% /r /d y
pause
goto menu
:CACH
cls
echo Usuwanie plikow WU Cached 
net stop wuauserv
net stop UsoSvc
net stop bits
net stop dosvc
@echo
echo Usuwanie plikow aktualizacji
rd /s /q C:\Windows\SoftwareDistribution
md / C:\Windows\SoftwareDistribution 
pause
goto menu
:TEMP
cls
echo Usuwanie logow
cd
@echo
del *.log /a /s /q /f
pause
goto menu