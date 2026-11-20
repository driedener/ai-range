# Install cloudbase-init and configure it for Proxmox ConfigDrive (configdrive2).
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$url = $env:CBI_MSI_URL
$msi = 'C:\Windows\Temp\CloudbaseInitSetup_x64.msi'
$src = 'C:\Windows\Temp\packer-cbi'
$cbi = 'C:\Program Files\Cloudbase Solutions\Cloudbase-Init'

Write-Host "Downloading $url"
Invoke-WebRequest -Uri $url -OutFile $msi -UseBasicParsing

# Service as LocalSystem (no extra "cloudbase-init" user)
$msiArgs = "/i `"$msi`" /qn /norestart /l*v C:\Windows\Temp\cloudbase-init-msi.log RUN_SERVICE_AS_LOCAL_SYSTEM=1"
$p = Start-Process -FilePath msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
if ($p.ExitCode -notin 0, 3010) { throw "cloudbase-init MSI failed ($($p.ExitCode))" }

Copy-Item "$src\cloudbase-init.conf"          "$cbi\conf\cloudbase-init.conf" -Force
Copy-Item "$src\cloudbase-init-unattend.conf" "$cbi\conf\cloudbase-init-unattend.conf" -Force
Copy-Item "$src\Unattend.xml"                 "$cbi\conf\Unattend.xml" -Force
New-Item -ItemType Directory -Path "$cbi\LocalScripts" -Force | Out-Null
Copy-Item "$src\set-hostname-network.ps1"     "$cbi\LocalScripts\set-hostname-network.ps1" -Force

# Do not run during the build (no ConfigDrive present);
# sysprep.ps1 sets it back to Automatic.
Stop-Service -Name cloudbase-init -ErrorAction SilentlyContinue
Set-Service  -Name cloudbase-init -StartupType Manual

Remove-Item $msi -Force
Remove-Item $src -Recurse -Force
Write-Host 'cloudbase-init installed.'
