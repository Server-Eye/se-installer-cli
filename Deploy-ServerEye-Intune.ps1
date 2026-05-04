<#
    .SYNOPSIS
    Deploy servereye via Microsoft Intune

    .DESCRIPTION
    This script is designed to be deployed via Microsoft Intune to install servereye on target machines.
    It checks for 64-bit architecture and then downloads and executes the ServerEye deployment script with the necessary parameters.
#>

# --- Intune 64-bit Enforcement ---
if ($env:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
    & "$env:WINDIR\SysNative\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass -File $PSCommandPath
    exit $LASTEXITCODE
}

# --- Download servereye deploy script ---
$InstallerUrl = "https://raw.githubusercontent.com/Server-Eye/se-installer-cli/master/Deploy-ServerEye.ps1"
$InstallerPath = Join-Path -Path $env:SystemDrive -ChildPath "Deploy-ServerEye.ps1"

Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerPath -UseBasicParsing

# --- Execute servereye deploy script with parameters ---
# Replace the parameter values with actual values before deploying the script via Intune.
# If additional parameters are needed, uncomment the relevant lines and provide the necessary values.
powershell.exe -ExecutionPolicy Bypass -File $InstallerPath `
    -Deploy "OCC-Connector" `
    -CustomerID "CustomerID" `
    -ApiKey "ApiKey" `
#    -ParentGuid "ParentGuid" `
#    -TemplateID "TemplateID" `
#    -TagIDs "TagIDs" `
#    -Cleanup `
#    -ConnectorPort "ConnectorPort" `
#    -LogPath "$env:windir\Temp" `
#    -RemoteLogPath "RemoteLogPath" `
#    -DeployPath $env:SystemDrive `
#    -SkipInstalledCheck `
#    -ProxyUrl "ProxyUrl" `
#    -ProxyPort "ProxyPort" `
#    -ProxyDomain "ProxyDomain" `
#    -ProxyUser "ProxyUser" `
#    -ProxyPassword "ProxyPassword" `
    -Silent

exit 0