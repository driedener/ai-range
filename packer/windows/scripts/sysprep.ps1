# Cleanup + Sysprep generalize with the cloudbase-init unattend file.
# /quit instead of /shutdown: Packer then shuts the VM down itself (API / guest agent)
# and converts it to a template.
$ErrorActionPreference = 'Stop'
$cbi      = 'C:\Program Files\Cloudbase Solutions\Cloudbase-Init'
$unattend = "$cbi\conf\Unattend.xml"

if ($env:IS_CLIENT -eq 'true') {
    # Per-user installed, non-provisioned Store Appx packages make Sysprep abort
    $prov = (Get-AppxProvisionedPackage -Online).PackageName
    Get-AppxPackage -AllUsers | Where-Object {
        -not $_.IsFramework -and -not $_.NonRemovable -and $_.SignatureKind -eq 'Store' -and ($prov -notcontains $_.PackageFullName)
    } | ForEach-Object {
        Write-Host "Removing Appx $($_.PackageFullName)"
        Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction SilentlyContinue
    }
}

# Cleanup
& Dism.exe /Online /Cleanup-Image /StartComponentCleanup | Out-Null
Optimize-Volume -DriveLetter C -ReTrim -ErrorAction SilentlyContinue

# Remove the autologon from the installation
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty -Path $wl -Name AutoAdminLogon -Value '0'
Remove-ItemProperty -Path $wl -Name DefaultPassword -ErrorAction SilentlyContinue

Set-Service -Name cloudbase-init -StartupType Automatic

# BitLocker/device encryption must be off, otherwise Sysprep aborts with
# ValidateBitLockerState (0x80310039) (Win11 with vTPM encrypts automatically)
$bl = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction SilentlyContinue
if ($bl -and $bl.VolumeStatus -ne 'FullyDecrypted') {
    Write-Host "BitLocker on C: is $($bl.VolumeStatus) - decrypting ..."
    Disable-BitLocker -MountPoint 'C:' | Out-Null
    while ((Get-BitLockerVolume -MountPoint 'C:').VolumeStatus -ne 'FullyDecrypted') { Start-Sleep -Seconds 10 }
    Write-Host 'BitLocker off.'
}

# Sysprep splits /unattend:"C:\Program Files\..." at the space despite the quotes
# ("Malformed command line") -> copy to a path without spaces
$unattendNoSpace = "$env:SystemRoot\Panther\cbi-unattend.xml"
Copy-Item -Path $unattend -Destination $unattendNoSpace -Force

Write-Host 'Starting Sysprep ...'
$p = Start-Process -FilePath "$env:SystemRoot\System32\Sysprep\sysprep.exe" `
    -ArgumentList "/generalize /oobe /mode:vm /quit /unattend:$unattendNoSpace" -Wait -PassThru

$state = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State').ImageState
Write-Host "Sysprep ExitCode=$($p.ExitCode) ImageState=$state"
if ($state -ne 'IMAGE_STATE_GENERALIZE_RESEAL_TO_OOBE') {
    Get-Content "$env:SystemRoot\System32\Sysprep\Panther\setuperr.log" -ErrorAction SilentlyContinue | Write-Host
    throw 'Sysprep failed'
}

# Windows has cached the file to C:\Windows\Panther -> delete the original with the plaintext password
Remove-Item -Path $unattend -Force
Write-Host 'Sysprep ok - VM is being shut down by Packer.'
