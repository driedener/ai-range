# Runs as FirstLogonCommand (autologon Administrator) from the UNATTEND CD.
# Order: basic settings -> virtio-win-guest-tools (incl. qemu-guest-agent)
#        -> WinRM (only at the very end, so that Packer connects only afterwards).
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
Start-Transcript -Path 'C:\Windows\Temp\packer-bootstrap.log' -Append

function Set-PrivateNetwork {
    Get-NetConnectionProfile -ErrorAction SilentlyContinue |
        Where-Object { $_.NetworkCategory -ne 'DomainAuthenticated' } |
        Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue
}

# --- Basic settings ---------------------------------------------------------
Set-PrivateNetwork
# Otherwise Win11 (vTPM + Secure Boot) starts automatic device encryption,
# and Sysprep fails on ValidateBitLockerState (0x80310039).
# Not New-Item -Force (it would try to recreate the existing, protected key)
# and never let the bootstrap abort - sysprep.ps1 decrypts if necessary.
try {
    & reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Control\BitLocker' /v PreventDeviceEncryption /t REG_DWORD /d 1 /f | Out-Null
} catch {
    Write-Warning "PreventDeviceEncryption not set: $_"
}
# No "network discovery?" popup for new networks
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff' -Force | Out-Null
# Power: no standby/hibernate
powercfg /change standby-timeout-ac 0
powercfg /change monitor-timeout-ac 0
powercfg /hibernate off
# Do not start Server Manager automatically
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\ServerManager') {
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\ServerManager' -Name DoNotOpenServerManagerAtLogon -Value 1 -Type DWord
}
# Win11: Store auto-updates off (prevents Appx packages that block Sysprep)
$os = Get-CimInstance Win32_OperatingSystem
if ($os.ProductType -eq 1) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -Name AutoDownload -Value 2 -Type DWord
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name DisableWindowsConsumerFeatures -Value 1 -Type DWord
}

# --- virtio-win-guest-tools --------------------------------------------------
$virtio = Get-Volume |
    Where-Object { $_.DriveType -eq 'CD-ROM' -and $_.DriveLetter -and (Test-Path "$($_.DriveLetter):\virtio-win-guest-tools.exe") } |
    Select-Object -First 1
if (-not $virtio) { throw 'virtio-win ISO (virtio-win-guest-tools.exe) not found' }
$vd = "$($virtio.DriveLetter):"

# Trust the Red Hat publisher so the driver install shows no dialog
Get-ChildItem -Path "$vd\Balloon" -Recurse -Filter '*.cat' -ErrorAction SilentlyContinue |
    Select-Object -First 3 | ForEach-Object {
        $cert = (Get-AuthenticodeSignature $_.FullName).SignerCertificate
        if ($cert) {
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('TrustedPublisher', 'LocalMachine')
            $store.Open('ReadWrite'); $store.Add($cert); $store.Close()
        }
    }

Write-Host "Installing virtio-win-guest-tools from $vd"
$p = Start-Process -FilePath "$vd\virtio-win-guest-tools.exe" -ArgumentList '/install', '/quiet', '/norestart' -Wait -PassThru
Write-Host "virtio-win-guest-tools ExitCode: $($p.ExitCode)"
if ($p.ExitCode -notin 0, 3010) { throw "virtio-win-guest-tools failed ($($p.ExitCode))" }

Set-Service -Name QEMU-GA -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name QEMU-GA -ErrorAction SilentlyContinue

# NetKVM may have been reinstalled -> wait for the network, set the profile again
Start-Sleep -Seconds 15
Set-PrivateNetwork

# --- WinRM (HTTP 5985) for Packer and Ansible -------------------------------
# Remote UAC filter off (relevant for local admins other than the built-in Administrator)
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy -Value 1 -Type DWord

Enable-PSRemoting -SkipNetworkProfileCheck -Force
Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true
Set-Item -Path WSMan:\localhost\Shell\MaxMemoryPerShellMB -Value 2048
Set-Item -Path WSMan:\localhost\MaxTimeoutms -Value 1800000

New-NetFirewallRule -Name 'ai-range-WinRM-HTTP' -DisplayName 'WinRM HTTP 5985 (ai-range)' `
    -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow -Profile Any -RemoteAddress Any | Out-Null

Set-Service -Name WinRM -StartupType Automatic
Restart-Service -Name WinRM

Write-Host 'Bootstrap done.'
Stop-Transcript
