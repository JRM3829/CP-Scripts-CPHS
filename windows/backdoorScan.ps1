$procs = @{}
Get-CimInstance Win32_Process | ForEach-Object {
    $procs[[int]$_.ProcessId] = $_
}

$allowedParents = @("services", "wininit", "System Idle Process")
$esc = [char]27
$red = "$esc[31m"
$reset = "$esc[0m"

Get-NetTCPConnection -State Listen | ForEach-Object {
    $owningPid = [int]$_.OwningProcess
    $procObj = $procs[$owningPid]

    if ($null -ne $procObj) {
        $ppid = [int]$procObj.ParentProcessId
        $parentObj = $procs[$ppid]
        $parentName = if ($null -ne $parentObj) {
            $parentObj.Name -replace '\.exe$', ''
        } else {
            ""
        }
        $procName = $procObj.Name -replace '\.exe$', ''
        $cmdLine = $procObj.CommandLine -replace '\r?\n', ' '
    } else {
        $ppid = 0
        $parentName = ""
        $procName = ""
        $cmdLine = ""
    }

    if ([string]::IsNullOrWhiteSpace($parentName) -and $ppid -eq 0) {
        $parentName = "System Idle Process"
    }

    $line = "{0,-15} {1,-6} {2,-9} PID:{3,-6} {4,-20} PPID:{5,-6} Parent:{6,-20} | {7}" -f `
        $_.LocalAddress, $_.LocalPort, $_.State, $owningPid, $procName, $ppid, $parentName, $cmdLine

    $shouldHighlight = (
        [string]::IsNullOrWhiteSpace($parentName) -or ($parentName -notin $allowedParents)
    ) -and ($procName -ne "wininit")

    if ($shouldHighlight) {
        Write-Output "${red}${line}${reset}"
    } else {
        Write-Output $line
    }
}
