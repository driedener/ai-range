#Requires -RunAsAdministrator
# Firewall rules on a Windows controller for ai-range (idempotent). Run as Administrator.
# Networks from docker/range.env (scripts/configure.py from range.yaml): RANGE_CIDR, RANGE_ADMIN_NETWORKS.
$envFile = Join-Path $PSScriptRoot '..\..\docker\range.env'
if (-not (Test-Path $envFile)) { throw "docker/range.env missing - run scripts/configure.py first (see docs/configuration.md)" }
$cfg = @{}
Get-Content $envFile | Where-Object { $_ -match '^\s*([A-Z_]+)=(.*)$' } | ForEach-Object { $cfg[$Matches[1]] = $Matches[2].Trim() }
$range = $cfg['RANGE_CIDR']
$admin = @($cfg['RANGE_ADMIN_NETWORKS'] -split ',' | Where-Object { $_ })
if (-not $range) { throw "RANGE_CIDR missing in $envFile" }

$rules = @(
  @{ Name = 'ai-range Elastic/Fleet';  Ports = '9200','8220';  Remote = @($range) },
  @{ Name = 'ai-range Kibana';         Ports = '5601';         Remote = @($range) + $admin },
  @{ Name = 'ai-range Packer HTTP';    Ports = '8100-8110';    Remote = @($range) }
)
foreach ($r in $rules) {
  Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  New-NetFirewallRule -DisplayName $r.Name -Direction Inbound -Action Allow -Protocol TCP `
    -LocalPort $r.Ports -RemoteAddress ($r.Remote | Select-Object -Unique) -Profile Any | Out-Null
  Write-Host "OK: $($r.Name) -> $($r.Ports -join ',') from $(($r.Remote | Select-Object -Unique) -join ',')"
}
