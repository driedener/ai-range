# Optional Windows updates via the WU COM API (no extra plugin).
# Packer runs the script "elevated" (scheduled task), since the API does not work over WinRM.
$ErrorActionPreference = 'Stop'
if ($env:INSTALL_UPDATES -ne 'true') { Write-Host 'install_updates=false -> skipped'; exit 0 }

$session  = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
Write-Host 'Searching for updates ...'
$result = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
if ($result.Updates.Count -eq 0) { Write-Host 'No updates.'; exit 0 }

$coll = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($u in $result.Updates) {
    if (-not $u.EulaAccepted) { $u.AcceptEula() }
    Write-Host " - $($u.Title)"
    [void]$coll.Add($u)
}

$dl = $session.CreateUpdateDownloader()
$dl.Updates = $coll
Write-Host 'Download ...'
[void]$dl.Download()

$inst = $session.CreateUpdateInstaller()
$inst.Updates = $coll
Write-Host 'Installation ...'
$res = $inst.Install()
Write-Host "ResultCode=$($res.ResultCode) RebootRequired=$($res.RebootRequired)"
exit 0
