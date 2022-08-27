@ECHO OFF
Title PC Optimizer [Start]
Color A

:menu
cls
echo=====================
echo   START       F
echo=====================
echo.  HELP        H
echo=====================
echo   EXIT        E
echo=====================
echo.
echo.
set /p opcstart=Wybierz opcje z powyzszych: 
if %opcstart%=='F' goto (start)
if %opcstart%=='H' goto help
if %opcstart%=='E' goto exit

:start
echo Czy wyrazasz zgode na wylaczenie nie potrzebnych
echo uslug/opcji systemu, ktore opciazaja twoj procesor?
set /p start= Wybierz opcje: (Tak/Nie) 
if %start%=='Tak' goto start2
if %start%=='Nie' goto menu

:start2
echo Rozpoczeto procesz wylaczania nie potrzebnych funkcji

PowerShell -Command "Get-Service DiagTrack | Set-Service -StartupType Disabled" >nul
PowerShell -Command "Get-Service dmwappushservice | Set-Service -StartupType Disabled" >nul
PowerShell -Command "Get-Service diagnosticshub.standardcollector.service | Set-Service -StartupType Disabled" >nul
PowerShell -Command "Get-Service DPS | Set-Service -StartupType Disabled" >nul
PowerShell -Command "Get-Service RemoteRegistry | Set-Service -StartupType Disabled" >nul
PowerShell -Command "Get-Service TrkWks | Set-Service -StartupType Disabled" >nul
PowerShell -Command "Get-Service WMPNetworkSvc | Set-Service -StartupType Disabled" >nul
PowerShell -Command "Get-Service WSearch | Set-Service -StartupType Disabled" >nul
PowerShell -Command "Get-Service SysMain | Set-Service -StartupType Disabled" >nul
SC config "DiagTrack" start= disabled >nul
SC config "dmwappushservice" start= disabled >nul
SC config "diagnosticshub.standardcollector.service" start= disabled >nul
SC config "DPS " start= disabled >nul
SC config "RemoteRegistry" start= disabled >nul
SC config "TrkWks" start= disabled >nul
SC config "WMPNetworkSvc" start= disabled >nul
SC config "WSearch" start= disabled >nul
SC config "SysMain" start= disabled >nul
NET STOP DiagTrack >nul
NET STOP diagnosticshub.standardcollector.service >nul
NET STOP dmwappushservice >nul
NET STOP DPS >nul
NET STOP RemoteRegistry >nul
NET STOP TrkWks >nul
NET STOP WMPNetworkSvc >nul
NET STOP WSearch >nul
NET STOP SysMain >nul
SC delete DiagTrack >nul
SC delete "diagnosticshub.standardcollector.service" >nul
SC delete "dmwappushservice" >nul
SC delete "DPS" >nul
SC delete "RemoteRegistry" >nul
SC delete "TrkWks" >nul
SC delete "WMPNetworkSvc" >nul
SC delete "WSearch" >nul
SC delete "SysMain" >nul

SC config "CscService" start= disabled              >nul
SC config "MapsBroker" start= disabled              >nul
SC config "CertPropSvc" start= disabled             >nul
SC config "wscsvc" start= demand                    >nul
SC config "SystemEventsBroker" start= demand        >nul
SC config "tiledatamodelsvc" start= demand          >nul
SC config "WerSvc" start= demand                    >nul    

echo.
echo.
echo.

echo Wylaczono podstawowe funkcje....
echo.

echo Wylaczono podstawowe funkcje....
echo.

echo Wylaczono podstawowe funkcje....
echo.

echo Wylaczono podstawowe funkcje....

echo Wylaczono podstawowe funkcje....
echo.

echo Wylaczono podstawowe funkcje....
echo.

echo Wylaczono podstawowe funkcje....
echo.

echo Wylaczono podstawowe funkcje....
echo.

echo Wylaczono podstawowe funkcje....
echo.

echo Wylaczono podstawowe funkcje....
echo.

echo Wylaczono podstawowe funkcje....
echo.

echo Wylaczono podstawowe funkcje....
echo.

echo Wylaczono podstawowe funkcje....
echo.

echo Wylaczono podstawowe funkcje....
echo.

echo Wylaczono podstawowe funkcje....
echo.

echo Wylaczono podstawowe funkcje....
echo.
echo Wylaczono podstawowe funkcje....

pause
goto start 3

:start 3

echo Kontynuuj wylaczanie opcji podstawowych

sc config xbgm start=disabled                          >nul
sc config XboxGipSvc start=disabled                    >nul
sc config WaaSMedicSvc start=disabled                  >nul
sc config wuauserv start=disabled                      >nul
sc config W32Time start=disabled                       >nul
sc config spectrum start=disabled                      >nul
sc config wcncsvc start=disabled                       >nul
sc config WebClient start=disabled                     >nul
sc config SysMain start=disabled                       >nul
sc config NcaSvc start=disabled                        >nul
sc config wlidsvc start=disabled                       >nul
sc config SCardSvr start=disabled                      >nul
sc config NgcCtnrSvc start=disabled                    >nul
sc config diagsvc start=disabled                       >nul
sc config UserDataSvc_3228d start=disabled             >nul
sc config stisvc start=disabled                        >nul
sc config AdobeFlashPlayerUpdateSvc start=disabled     >nul
sc config TrkWks start=disabled                        >nul
sc config dmwappushservice start=disabled              >nul
sc config PimIndexMaintenanceSvc_3228d start=disabled  >nul
sc config DiagTrack start=disabled                     >nul
sc config VaultSvc start=disabled                      >nul
sc config GoogleChromeElevationService start=disabled  >nul
sc config OneSyncSvc_3228d start=disabled              >nul
sc config ibtsiva start=disabled                       >nul
sc config SNMPTRAP start=disabled                      >nul
sc config pla start=disabled                           >nul
sc config ssh-agent start=disabled                     >nul
sc config sshd start=disabled                          >nul
sc config DoSvc start=disabled                         >nul
sc config tzautoupdate start=disabled                  >nul
sc config CertPropSvc start=disabled                   >nul
sc config RemoteRegistry start=disabled                >nul
sc config RemoteAccess start=disabled                  >nul
sc config TimeBrokerSvc start=disabled                 >nul
sc config WbioSrvc start=disabled                      >nul
sc config PcaSvc start=disabled                        >nul
sc config NetTcpPortSharing start=disabled             >nul
sc config WerSvc start=disabled                        >nul
sc config gupdate start=disabled                       >nul
sc config gupdatem start=disabled                      >nul
sc config MSiSCSI start=disabled                       >nul
sc config WMPNetworkSvc start=disabled                 >nul
sc config CDPUserSvc_3228d start=disabled              >nul
sc config WpnUserService_3228d start=disabled          >nul
sc config shpamsvc start=disabled                      >nul
sc config LanmanWorkstation start=disabled             >nul
sc config UnistoreSvc_3228d start=disabled             >nul
sc config MapsBroker start=disabled                    >nul
sc config debugregsvc start=disabled                   >nul
sc config Schedule start=disabled                      >nul



echo rozpocznij wylaczanie zaawansowanych opcji systemu windows
pause
goto start4
:start4
cls
echo rozpoczeto wylaczanie zaawansowanych opcji systemu windows

SCHTASKS /Change /TN "\Microsoft\Windows\WS\WSTask" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\WOF\WIM-Hash-Validation" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\WOF\WIM-Hash-Management" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\WindowsUpdate\sih" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\WDI\ResolutionHost" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\Sysmain\WsSwapAssessmentTask" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\Sysmain\ResPriStaticDbSync" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskLogon" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\Shell\IndexerAutomaticMaintenance" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\SettingSync\NetworkStateChangeTask" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\SettingSync\BackgroundUploadTask" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\PI\Sqm-Tasks" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\Maintenance\WinSAT" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\FileHistory\File History (maintenance mode)" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\File Classification Infrastructure\Property Definition Sync" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\File Classification Infrastructure\Property Definition Sync" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\Feedback\Siuf\DmClient" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\CertificateServicesClient\UserTask-Roam" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\Autochk\Proxy" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\AppxDeploymentClient\Pre-staged app cleanup" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\Application Experience\StartupAppTask" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Windows\AppID\SmartScreenSpecific" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Office\OfficeTelemetryAgentLogOn" /DISABLE >nul
SCHTASKS /Change /TN "\Microsoft\Office\OfficeTelemetryAgentFallBack" /DISABLE >nul
echo.
echo.
echo Ukonczono usuwanie nie potrzebnych opcji windows
echo.
echo.
echo.
echo Rozpocznij wylaczanie nie potrzebnych uslug Microsoftu
pause
goto start5

:start5
echo rozpoczeto wylaczanie uslug
PowerShell -Command Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName "Internet-Explorer-Optional-amd64" >nul
PowerShell -Command Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName "MediaPlayback" >nul
PowerShell -Command Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName "WindowsMediaPlayer" >nul
PowerShell -Command Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName "WorkFolders-Client" >nul
PowerShell -Command "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq Microsoft.3DBuilder | Remove-AppxProvisionedPackage -Online" >nul
PowerShell -Command "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq Microsoft.BingFinance | Remove-AppxProvisionedPackage -Online" >nul
PowerShell -Command "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq Microsoft.BingNews | Remove-AppxProvisionedPackage -Online" >nul
PowerShell -Command "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq Microsoft.Getstarted | Remove-AppxProvisionedPackage -Online" >nul
PowerShell -Command "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq Microsoft.MicrosoftOfficeHub | Remove-AppxProvisionedPackage -Online" >nul
PowerShell -Command "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq Microsoft.MicrosoftSolitaireCollection | Remove-AppxProvisionedPackage -Online" >nul
PowerShell -Command "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq Microsoft.Office.OneNote | Remove-AppxProvisionedPackage -Online" >nul
PowerShell -Command "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq Microsoft.SkypeApp | Remove-AppxProvisionedPackage -Online" >nul
PowerShell -Command "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq Microsoft.WindowsPhone | Remove-AppxProvisionedPackage -Online" >nul
PowerShell -Command "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq Microsoft.XboxApp | Remove-AppxProvisionedPackage -Online" >nul
PowerShell -Command "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq Microsoft.ZuneMusic | Remove-AppxProvisionedPackage -Online" >nul
PowerShell -Command "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq Microsoft.ZuneVideo | Remove-AppxProvisionedPackage -Online" >nul
PowerShell -Command "Get-AppxPackage *Microsoft* | Remove-AppxPackage" >nul
PowerShell -Command "Get-AppXProvisionedPackage -online | Remove-AppxProvisionedPackage -online" >nul
PowerShell -Command "Get-AppXPackage | Remove-AppxPackage" >nul
PowerShell -Command "Get-AppXPackage -User  | Remove-AppxPackage" >nul
PowerShell -Command "Get-AppxPackage -AllUsers | Remove-AppxPackage" >nul


REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /v "enablefileobfuscation" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /v "enablelogging" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /v "enableupload" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /v "qmenable" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /v "sendcustomerdata" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /v "updatereliabilitydata" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /v "enabled" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /v "includescreenshot" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\internet" /v "useonlinecontent" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\ptwatson" /v "ptwoptin" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /v "enablefileobfuscation" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /v "enablelogging" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /v "enableupload" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "accesssolution" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "olksolution" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "onenotesolution" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "pptsolution" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "projectsolution" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "publishersolution" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "visiosolution" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "wdsolution" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "xlsolution" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /v "agave" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /v "appaddins" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /v "comaddins" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /v "documentfiles" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /v "templatefiles" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "level" /t REG_DWORD /d 2 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 0 /f  >nul

REG ADD "HKCU\SOFTWARE\Microsoft\Tracing\WPPMediaPerApp\Skype\ETW" /v "TraceLevelThreshold" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Microsoft\Tracing\WPPMediaPerApp\Skype" /v "EnableTracing" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Microsoft\Tracing\WPPMediaPerApp\Skype\ETW" /v "EnableTracing" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Microsoft\Tracing\WPPMediaPerApp\Skype" /v "WPPFilePath" /t REG_SZ /d "%%SYSTEMDRIVE%%\TEMP\Tracing\WPPMedia" /f >nul
REG ADD "HKCU\SOFTWARE\Microsoft\Tracing\WPPMediaPerApp\Skype\ETW" /v "WPPFilePath" /t REG_SZ /d "%%SYSTEMDRIVE%%\TEMP\WPPMedia" /f >nul



::REG Delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >nul
::REG Delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >nul
::REG Delete "HKCU\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f /reg:32 >nul
::REG Delete "HKCU\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f /reg:64 >nul
::REG Delete "HKLM\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f /reg:32 >nul
::REG Delete "HKLM\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f /reg:64 >nul
::REG Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{A52BBA46-E9E1-435f-B3D9-28DAA648C0F6}" /f >nul
::REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /f >nul
::REG Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{339719B5-8C47-4894-94C2-D8F77ADD44A6}" /f >nul
::REG Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{767E6811-49CB-4273-87C2-20F355E1085B}" /f >nul
::REG Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{C3F2459E-80D6-45DC-BFEF-1F769F2BE730}" /f >nul
::REG Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{24D89E24-2F19-4534-9DDE-6A6671FBB8FE}" /f >nul


reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ndu" /v "Start" /d "00000002" /t REG_DWORD /f >nul
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc" /v "Start" /d "00000002" /t REG_DWORD /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f                                                                                                                                                >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f                                                                                                                                                >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableBoottrace" /t REG_DWORD /d "0" /f                                                                                                                                                 >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f                                                                                                               >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f                                                                                                               >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f                                                                                                                   >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f                                                                                                                   >nul
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f                                                                                                                   >nul
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f                                                                                                                   >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f                                                                                                                                                                                               >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f                                                                                                                                                                               >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c" /v "ValueMax" /t REG_DWORD /d "100" /f                                                                                                             >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ValueMax" /t REG_DWORD /d "100" /f                                               >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "VsyncIdleTimeout" /t REG_DWORD /d "0" /f                                                                                                                                                                           >nul
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f                                                                                                                                                                                                                >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f                                                                                                                                                                                   >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f                                                                                                                                                                                   >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /d "0" /f                                                                                                                                                                                              >nul
Reg.exe add "HKLM\SOFTWARE\Intel\GMM" /v "DedicatedSegmentSize" /t REG_DWORD /d "1298" /f                                                                                                                                                                                                            >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f                                                                                                                                                                             >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f                                                                                                                                                                                         >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d "2" /f                                                                                                                                                                                        >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f                                                                                                                                                                                 >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f                                                                                                                                                                                             >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d "2" /f                                                                                                                                                                                            >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f                                                                                                                                                >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f                                                                                                                                                >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableBoottrace" /t REG_DWORD /d "0" /f                                                                                                                                                 >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f                                                                                                                                                                      >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f                                                                                                                                                                 >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f                                                                                                                                                                           >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f                                                                                                                                                                            >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f                                                                                                                                                                        >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMftZoneReservation" /t REG_DWORD /d "1" /f                                                                                                                                                                                    >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisable8dot3NameCreation" /t REG_DWORD /d "1" /f                                                                                                                                                                              >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "DontVerifyRandomDrivers" /t REG_DWORD /d "1" /f                                                                                                                                                                                   >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisableLastAccessUpdate" /t REG_DWORD /d "1" /f                                                                                                                                                                               >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "ContigFileAllocSize" /t REG_DWORD /d "64" /f                                                                                                                                                                                      >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f                                                                                                                                                                                                                       >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f                                                                                                                                                                                                                      >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "5000" /f                                                                                                                                                                                                            >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1000" /f                                                                                                                                                                                                        >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "4000" /f                                                                                                                                                                                                                  >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f                                                                                                                                                                                                            >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_SZ /d "150000" /f                                                                                                                                                                                                         >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "FpsAll" /t REG_DWORD /d "1" /f                                                                                                                                                                                                                       >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "GameFluidity" /t REG_DWORD /d "1" /f                                                                                                                                                                                                                 >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "FpsStatusGames" /t REG_DWORD /d "16" /f                                                                                                                                                                                                              >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "FpsStatusGamesAll" /t REG_DWORD /d "4" /f                                                                                                                                                                                                            >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f                                                                                                                                                            >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f                                                                                                                                                    >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f                                                                                                                                                      >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f                                                                                                                                                        >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "2" /f                                                                                                                                                            >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f                                                                                                                                                 >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f                                                                                                                                                       >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f                                                                                                                                                   >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Affinity" /t REG_DWORD /d "0" /f                                                                                                                                                      >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Background Only" /t REG_SZ /d "False" /f                                                                                                                                              >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Clock Rate" /t REG_DWORD /d "10000" /f                                                                                                                                                >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "GPU Priority" /t REG_DWORD /d "8" /f                                                                                                                                                  >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Priority" /t REG_DWORD /d "2" /f                                                                                                                                                      >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Scheduling Category" /t REG_SZ /d "High" /f                                                                                                                                           >nul


Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /d "0" /f                                                                                                                                                                                              >nul
Reg.exe add "HKLM\SOFTWARE\Intel\GMM" /v "DedicatedSegmentSize" /t REG_DWORD /d "1298" /f                                                                                                                                                                                                            >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f                                                                                                                                                                             >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f                                                                                                                                                                                         >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d "2" /f                                                                                                                                                                                        >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f                                                                                                                                                                                 >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f                                                                                                                                                                                             >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d "2" /f                                                                                                                                                                                            >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f                                                                                                                                                >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f                                                                                                                                                >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableBoottrace" /t REG_DWORD /d "0" /f                                                                                                                                                 >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f                                                                                                                                                                      >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f                                                                                                                                                                 >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f                                                                                                                                                                           >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f                                                                                                                                                                            >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f                                                                                                                                                                        >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMftZoneReservation" /t REG_DWORD /d "1" /f                                                                                                                                                                                    >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisable8dot3NameCreation" /t REG_DWORD /d "1" /f                                                                                                                                                                              >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "DontVerifyRandomDrivers" /t REG_DWORD /d "1" /f                                                                                                                                                                                   >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisableLastAccessUpdate" /t REG_DWORD /d "1" /f                                                                                                                                                                               >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "ContigFileAllocSize" /t REG_DWORD /d "64" /f                                                                                                                                                                                      >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f                                                                                                                                                                                                                       >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f                                                                                                                                                                                                                      >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "5000" /f                                                                                                                                                                                                            >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1000" /f                                                                                                                                                                                                        >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "4000" /f                                                                                                                                                                                                                  >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f                                                                                                                                                                                                            >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_SZ /d "150000" /f                                                                                                                                                                                                         >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "FpsAll" /t REG_DWORD /d "1" /f                                                                                                                                                                                                                       >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "GameFluidity" /t REG_DWORD /d "1" /f                                                                                                                                                                                                                 >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "FpsStatusGames" /t REG_DWORD /d "16" /f                                                                                                                                                                                                              >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "FpsStatusGamesAll" /t REG_DWORD /d "4" /f                                                                                                                                                                                                            >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f                                                                                                                                                            >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f                                                                                                                                                    >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f                                                                                                                                                      >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f                                                                                                                                                        >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "2" /f                                                                                                                                                            >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f                                                                                                                                                 >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f                                                                                                                                                       >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f                                                                                                                                                   >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Affinity" /t REG_DWORD /d "0" /f                                                                                                                                                      >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Background Only" /t REG_SZ /d "False" /f                                                                                                                                              >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Clock Rate" /t REG_DWORD /d "10000" /f                                                                                                                                                >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "GPU Priority" /t REG_DWORD /d "8" /f                                                                                                                                                  >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Priority" /t REG_DWORD /d "2" /f                                                                                                                                                      >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Scheduling Category" /t REG_SZ /d "High" /f                                                                                                                                           >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "SFIO Priority" /t REG_SZ /d "High" /f                                                                                                                                                 >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Latency Sensitive" /t REG_SZ /d "True" /f                                                                                                                                             >nul
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "CPUPriority" /t REG_DWORD /d "1" /f                                                                                                                                                                                                >nul
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "FastDRAM" /t REG_DWORD /d "1" /f                                                                                                                                                                                                   >nul
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "PCIConcur" /t REG_DWORD /d "1" /f                                                                                                                                                                                                  >nul
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "AGPConcur" /t REG_DWORD /d "1" /f                                                                                                                                                                                                  >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "Max Cached Icons" /t REG_SZ /d "2000" /f                                                                                                                                                                                   >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "AlwaysUnloadDLL" /t REG_DWORD /d "1" /f                                                                                                                                                                                    >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AlwaysUnloadDLL" /v "Default" /t REG_DWORD /d "1" /f                                                                                                                                                                            >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableBalloonTips" /t REG_DWORD /d "0" /f                                                                                                                                                                         >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f                                                                                                                                                                                                         >nul                                                                                                                                                                                                                  >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f                                                                                                               >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f                                                                                                               >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f                                                                                                                   >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f                                                                                                                   >nul
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f                                                                                                                   >nul
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f                                                                                                                   >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f                                                                                                                                                                                               >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f                                                                                                                                                                               >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c" /v "ValueMax" /t REG_DWORD /d "100" /f                                                                                                             >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ValueMax" /t REG_DWORD /d "100" /f                                               >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "VsyncIdleTimeout" /t REG_DWORD /d "0" /f                                                                                                                                                                           >nul
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f                                                                                                                                                                                                                >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /v "enablefileobfuscation" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /v "enablelogging" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /v "enableupload" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /v "qmenable" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /v "sendcustomerdata" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /v "updatereliabilitydata" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /v "enabled" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /v "includescreenshot" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\internet" /v "useonlinecontent" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\ptwatson" /v "ptwoptin" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /v "enablefileobfuscation" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /v "enablelogging" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /v "enableupload" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "accesssolution" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "olksolution" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "onenotesolution" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "pptsolution" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "projectsolution" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "publishersolution" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "visiosolution" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "wdsolution" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "xlsolution" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /v "agave" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /v "appaddins" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /v "comaddins" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /v "documentfiles" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /v "templatefiles" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "level" /t REG_DWORD /d 2 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 0 /f  >nul

REG ADD "HKCU\SOFTWARE\Microsoft\Tracing\WPPMediaPerApp\Skype\ETW" /v "TraceLevelThreshold" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Microsoft\Tracing\WPPMediaPerApp\Skype" /v "EnableTracing" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Microsoft\Tracing\WPPMediaPerApp\Skype\ETW" /v "EnableTracing" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Microsoft\Tracing\WPPMediaPerApp\Skype" /v "WPPFilePath" /t REG_SZ /d "%%SYSTEMDRIVE%%\TEMP\Tracing\WPPMedia" /f >nul
REG ADD "HKCU\SOFTWARE\Microsoft\Tracing\WPPMediaPerApp\Skype\ETW" /v "WPPFilePath" /t REG_SZ /d "%%SYSTEMDRIVE%%\TEMP\WPPMedia" /f >nul


Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f                                                                                                                                                                                   >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /d "0" /f                                                                                                                                                                                              >nul
Reg.exe add "HKLM\SOFTWARE\Intel\GMM" /v "DedicatedSegmentSize" /t REG_DWORD /d "1298" /f                                                                                                                                                                                                            >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f                                                                                                                                                                             >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f                                                                                                                                                                                         >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d "2" /f                                                                                                                                                                                        >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f                                                                                                                                                                                 >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f                                                                                                                                                                                             >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d "2" /f                                                                                                                                                                                            >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f                                                                                                                                                >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f                                                                                                                                                >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableBoottrace" /t REG_DWORD /d "0" /f                                                                                                                                                 >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f                                                                                                                                                                      >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f                                                                                                                                                                 >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f                                                                                                                                                                           >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f                                                                                                                                                                            >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f                                                                                                                                                                        >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMftZoneReservation" /t REG_DWORD /d "1" /f                                                                                                                                                                                    >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisable8dot3NameCreation" /t REG_DWORD /d "1" /f                                                                                                                                                                              >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "DontVerifyRandomDrivers" /t REG_DWORD /d "1" /f                                                                                                                                                                                   >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisableLastAccessUpdate" /t REG_DWORD /d "1" /f                                                                                                                                                                               >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "ContigFileAllocSize" /t REG_DWORD /d "64" /f                                                                                                                                                                                      >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f                                                                                                                                                                                                                       >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f                                                                                                                                                                                                                      >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "5000" /f                                                                                                                                                                                                            >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1000" /f                                                                                                                                                                                                        >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "4000" /f                                                                                                                                                                                                                  >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f                                                                                                                                                                                                            >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_SZ /d "150000" /f                                                                                                                                                                                                         >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "FpsAll" /t REG_DWORD /d "1" /f                                                                                                                                                                                                                       >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "GameFluidity" /t REG_DWORD /d "1" /f                                                                                                                                                                                                                 >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "FpsStatusGames" /t REG_DWORD /d "16" /f                                                                                                                                                                                                              >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "FpsStatusGamesAll" /t REG_DWORD /d "4" /f                                                                                                                                                                                                            >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f                                                                                                                                                            >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f                                                                                                                                                    >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f                                                                                                                                                      >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f                                                                                                                                                        >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "2" /f                                                                                                                                                            >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f                                                                                                                                                 >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f                                                                                                                                                       >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f                                                                                                                                                   >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Affinity" /t REG_DWORD /d "0" /f                                                                                                                                                      >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Background Only" /t REG_SZ /d "False" /f                                                                                                                                              >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Clock Rate" /t REG_DWORD /d "10000" /f                                                                                                                                                >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "GPU Priority" /t REG_DWORD /d "8" /f                                                                                                                                                  >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Priority" /t REG_DWORD /d "2" /f                                                                                                                                                      >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Scheduling Category" /t REG_SZ /d "High" /f                                                                                                                                           >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "SFIO Priority" /t REG_SZ /d "High" /f                                                                                                                                                 >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Latency Sensitive" /t REG_SZ /d "True" /f                                                                                                                                             >nul
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "CPUPriority" /t REG_DWORD /d "1" /f                                                                                                                                                                                                >nul
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "FastDRAM" /t REG_DWORD /d "1" /f                                                                                                                                                                                                   >nul
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "PCIConcur" /t REG_DWORD /d "1" /f                                                                                                                                                                                                  >nul
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "AGPConcur" /t REG_DWORD /d "1" /f                                                                                                                                                                                                  >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "Max Cached Icons" /t REG_SZ /d "2000" /f                                                                                                                                                                                   >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "AlwaysUnloadDLL" /t REG_DWORD /d "1" /f                                                                                                                                                                                    >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AlwaysUnloadDLL" /v "Default" /t REG_DWORD /d "1" /f                                                                                                                                                                            >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableBalloonTips" /t REG_DWORD /d "0" /f                                                                                                                                                                         >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f     



echo ukonczono optymalizacje twojego komputera!
echo.
echo.
echo.
echo Rozpocznij wylaczanie opcji niskiego poziomu wbudowanych w windows
pause



 

:help
echo.
echo============================
echo  Aplikacja Desktopowa
echo Przyspieszajaca Internet
echo============================
pause
goto menu

:exit
echo.
echo============================
echo  Aby zamknac aplikacje
echo Klinij dowolny przycisk
echo============================
pause>nul