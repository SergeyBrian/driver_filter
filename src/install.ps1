echo "Removing old version"

fltmc unload DriverFilter
sc.exe delete DriverFilter
del C:\Windows\System32\drivers\DriverFilter.sys

echo "Installing new version"

Start-Process DriverFilter.inf -Verb Install
Start-Sleep -Seconds 1

sc.exe start DriverFilter
echo "Done."
sc.exe query DriverFilter

echo "Removing old service"

sc.exe stop DriverFilterService
Start-Sleep -Seconds 1
sc.exe delete DriverFilterService

echo "Installing new service"

cp Z:\DriverFilterService.exe C:\DriverFilterService.exe
sc.exe create DriverFilterService binPath= "C:\DriverFilterService.exe" start= auto
sc.exe sidtype DriverFilterService unrestricted
sc.exe start DriverFilterService

echo "Done."
