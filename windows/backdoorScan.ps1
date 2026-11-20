$procs = @{}
Get-CimInstance Win32_Process | ForEach-Object { procs[[int]_.ProcessId] = $_ }

$allowedParents = @("services", "wininit", "System Idle Process")
$esc = [char]27
red="esc[31m"
reset="esc[0m"

Get-NetTCPConnection -State Listen | ForEach-Object {
  $procObj = procs[[int]_.OwningProcess]
  ppid=[int]procObj.ParentProcessId
  parentName=(procs[$ppid].Name -replace '\.exe$','')
  if ([string]::IsNullOrWhiteSpace($parentName) -and $ppid -eq 0) {
    $parentName = "System Idle Process"
  }

  procName=(procObj.Name -replace '\.exe$','')
  cmdLine=(procObj.CommandLine -replace '\r?\n', ' ')
  $line = "{0,-15} {1,-6} {2,-9} PID:{3,-6} {4,-20} PPID:{5,-6} Parent:{6,-20} | {7}" -f $_.LocalAddress, $_.LocalPort, $_.State, $_.OwningProcess, $procName, $ppid, $parentName, $cmdLine

  shouldHighlight=([string]::IsNullOrWhiteSpace(parentName) -or ($parentName -notin allowedParents))-and(procName -ne "wininit")
  if ($shouldHighlight) {
    Write-Output "redline$reset"
  }
  else {
    Write-Output $line
  }
}
