# --- Intune 64-bit Enforcement ---
if ($env:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
    & "$env:WINDIR\SysNative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
    exit $LASTEXITCODE
}

#region User Configuration
# =================================================================
# START OF CONFIGURATION - Edit the values below before deploying
# =================================================================

# -- Required --
$Deploy         = ""         # "OCC-Connector" or "Sensorhub"
$CustomerID     = ""         # The long customerId, e.g. "15e86bf3-f9ff-4fdc-7fb4-449f86ba78d7"
$ApiKey         = ""         # API key for authentication

# -- Optional --
$ParentGuid         = ""     # OCC-Connector GUID for Sensorhub assignment (Sensorhub only)
$TemplateId         = ""     # Template ID to apply to the Sensorhub
$TagIDs             = ""     # Comma-separated Tag IDs to assign to the Sensorhub, e.g. "id1,id2"
$ConnectorPort      = ""     # Custom port for the OCC-Connector (OCC-Connector only)
$DeployPath         = ""     # Folder where the installer is saved during deployment; leave empty for default (system drive)
$LogPath            = ""     # Folder where log files are saved; leave empty for default (%windir%\Temp)
$RemoteLogPath      = ""     # Folder on a remote share where a copy of the log is saved, e.g. "\\server\share\logs"
$Cleanup            = ""     # Set to "true" to clean up servereye remnants before installing
$SkipInstalledCheck = ""     # Set to "true" to skip check for an existing servereye installation

# -- Proxy (leave empty if no proxy is needed) --
$ProxyUrl      = ""          # e.g. "http://10.50.2.30:8080"
$ProxyPort     = ""          # e.g. "8080"
$ProxyUser     = ""
$ProxyPassword = ""
$ProxyDomain   = ""

# =================================================================
# END OF CONFIGURATION - Do not edit anything below this line
# =================================================================
#endregion





#region Variables
$ProgressPreference = 'SilentlyContinue'
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

$DownloadUrl    = "https://occ.server-eye.de/download/se/Deploy-ServerEye.ps1"
$DownloadTarget = "$env:windir\Temp\Deploy-ServerEye.ps1"

$ResolvedLogPath = if ($LogPath -ne "") { $LogPath } else { "$env:windir\Temp" }
$TranscriptPath  = Join-Path $ResolvedLogPath "Deploy-ServerEye-Intune.log"
#endregion

#region Transcript
if (Test-Path $TranscriptPath) { Remove-Item $TranscriptPath -Force -ErrorAction SilentlyContinue }
if ($RemoteLogPath -ne "") {
    $RemoteTranscriptPath = Join-Path $RemoteLogPath "$env:COMPUTERNAME-Intune.log"
    if (Test-Path $RemoteTranscriptPath) { Remove-Item $RemoteTranscriptPath -Force -ErrorAction SilentlyContinue }
}
Start-Transcript -Path $TranscriptPath -Force
#endregion

#region Download
$WebClient = New-Object System.Net.WebClient
if ($ProxyUrl -ne "") {
    $WebProxy  = New-Object System.Net.WebProxy($ProxyUrl, $true)
    if ($ProxyUser) {
        $WebProxy.Credentials = New-Object System.Net.NetworkCredential($ProxyUser, $ProxyPassword, $ProxyDomain)
    }
    $WebClient.Proxy = $WebProxy
}

try {
    $WebClient.DownloadFile($DownloadUrl, $DownloadTarget)
} catch {
    Write-Error "Failed to download Deploy-ServerEye.ps1: $($_.Exception.Message)"
    $DownloadFailed = $true
}
#endregion

#region Execution
if ($DownloadFailed) {
    Stop-Transcript
    if ($RemoteLogPath -ne "") {
        Copy-Item -Path $TranscriptPath -Destination $RemoteTranscriptPath -Force -ErrorAction SilentlyContinue
    }
    exit 1
}

$DeployParams = @{
    Deploy     = $Deploy
    CustomerID = $CustomerID
    ApiKey     = $ApiKey
    Silent     = $true
}

if ($ParentGuid -ne "")         { $DeployParams.ParentGuid           = $ParentGuid }
if ($TemplateId -ne "")         { $DeployParams.TemplateId           = $TemplateId; $DeployParams.ApplyTemplate = $true }
if ($TagIDs -ne "")             { $DeployParams.TagIDs               = $TagIDs -split "," }
if ($ConnectorPort -ne "")      { $DeployParams.ConnectorPort        = $ConnectorPort }
if ($DeployPath -ne "")         { $DeployParams.DeployPath           = $DeployPath }
if ($LogPath -ne "")            { $DeployParams.LogPath              = $LogPath }
if ($RemoteLogPath -ne "")      { $DeployParams.RemoteLogPath        = $RemoteLogPath }
if ($Cleanup -ne "")            { $DeployParams.Cleanup              = $true }
if ($SkipInstalledCheck -ne "") { $DeployParams.SkipInstalledCheck   = $true }
if ($ProxyUrl -ne "")           { $DeployParams.ProxyUrl             = $ProxyUrl; $DeployParams.proxy = $WebProxy }
if ($ProxyPort -ne "")          { $DeployParams.ProxyPort            = $ProxyPort }
if ($ProxyDomain -ne "")        { $DeployParams.ProxyDomain          = $ProxyDomain }
if ($ProxyUser -ne "")          { $DeployParams.ProxyUser            = $ProxyUser }
if ($ProxyPassword -ne "")      { $DeployParams.ProxyPassword        = $ProxyPassword }

& $DownloadTarget @DeployParams
$DeployExitCode = $LASTEXITCODE
#endregion

#region Cleanup
Stop-Transcript
if ($RemoteLogPath -ne "") {
    Copy-Item -Path $TranscriptPath -Destination $RemoteTranscriptPath -Force -ErrorAction SilentlyContinue
}
#endregion

exit $DeployExitCode