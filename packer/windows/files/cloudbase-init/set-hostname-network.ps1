# cloudbase-init LocalScript (service phase, after NetworkConfigPlugin).
# 1) Network profile to Private (until the domain join).
# 2) Hostname fallback: with configdrive2, Proxmox writes the hostname only to
#    user_data ("#cloud-config ... hostname: X"), not to meta_data.json -> the
#    SetHostNamePlugin does not apply then. Read it from user_data here and set it.
# Exit code 1001 = cloudbase-init reboots, the script does not run again afterwards.
$ErrorActionPreference = 'Continue'

Get-NetConnectionProfile -ErrorAction SilentlyContinue |
    Where-Object { $_.NetworkCategory -eq 'Public' } |
    Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue

# WinRM for Ansible: Win11 sets the service to Manual after Sysprep, and the
# default firewall rule only allows the local subnet on Public (the controller is in
# 192.168.51.0/24). Hence: service automatic, remoting on, own rule for all profiles.
Set-Service -Name WinRM -StartupType Automatic -ErrorAction SilentlyContinue
Enable-PSRemoting -SkipNetworkProfileCheck -Force -ErrorAction SilentlyContinue | Out-Null
if (-not (Get-NetFirewallRule -DisplayName 'ai-range WinRM HTTP' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName 'ai-range WinRM HTTP' -Direction Inbound -Protocol TCP `
        -LocalPort 5985 -Profile Any -Action Allow -ErrorAction SilentlyContinue | Out-Null
}

$vol = Get-Volume -ErrorAction SilentlyContinue |
    Where-Object { $_.FileSystemLabel -eq 'config-2' -and $_.DriveLetter } |
    Select-Object -First 1
if (-not $vol) { exit 0 }

$ud = "$($vol.DriveLetter):\openstack\latest\user_data"
if (-not (Test-Path $ud)) { exit 0 }

$m = Select-String -Path $ud -Pattern '^\s*hostname:\s*["'']?([A-Za-z0-9\-\.]+)' | Select-Object -First 1
if (-not $m) { exit 0 }

$name = $m.Matches[0].Groups[1].Value.Split('.')[0]
if ($name.Length -gt 15) { $name = $name.Substring(0, 15) }

if ($env:COMPUTERNAME -ieq $name) { exit 0 }

Rename-Computer -NewName $name -Force -ErrorAction Stop
exit 1001
