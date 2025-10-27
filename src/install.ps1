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

Start-Sleep -Seconds 1


$acl = New-Object System.Security.AccessControl.FileSecurity

$acl.SetAccessRuleProtection($true, $false)

$rights        = [System.Security.AccessControl.FileSystemRights]::FullControl
$inheritFlags  = [System.Security.AccessControl.InheritanceFlags]::None
$propFlags     = [System.Security.AccessControl.PropagationFlags]::None
$allow         = [System.Security.AccessControl.AccessControlType]::Allow

$ruleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SYSTEM", $rights, $inheritFlags, $propFlags, $allow
)
$acl.AddAccessRule($ruleSystem)

$ruleSvc = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "NT SERVICE\DriverFilterService", $rights, $inheritFlags, $propFlags, $allow
)
$acl.AddAccessRule($ruleSvc)

Set-Acl -Path C:\ProgramData\DriverFilterSvc\db\config.db -AclObject $acl

echo "Done."
