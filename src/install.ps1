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
