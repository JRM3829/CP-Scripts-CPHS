# Use -> Set-ExecutionPolicy RemoteSigned
# This will allow you to use scripts in power shell.
# Make sure to open Power Shell in admin mode.

# Define input file path
if (-not (Test-Path -Path "$([Environment]::GetFolderPath('Desktop'))\ReadMe.html" -PathType Leaf)) { Write-Error "ReadMe.html not found on desktop. Aborting script."; exit 1 }
$htmlFilePath = "$HOME\Desktop\ReadMe.html"

# Define the output file path
$outputPath = "$HOME\Desktop\UserAndGroupReport.txt"


