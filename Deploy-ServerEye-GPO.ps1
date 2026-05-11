#Requires -RunAsAdministrator
#Requires -Version 2

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
	exit 1
}
#endregion

#region Execution
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
if ($Cleanup -ne "")            { $DeployParams.Cleanup              = $true }
if ($SkipInstalledCheck -ne "") { $DeployParams.SkipInstalledCheck   = $true }
if ($ProxyUrl -ne "")           { $DeployParams.ProxyUrl             = $ProxyUrl; $DeployParams.proxy = $WebProxy }
if ($ProxyPort -ne "")          { $DeployParams.ProxyPort            = $ProxyPort }
if ($ProxyDomain -ne "")        { $DeployParams.ProxyDomain          = $ProxyDomain }
if ($ProxyUser -ne "")          { $DeployParams.ProxyUser            = $ProxyUser }
if ($ProxyPassword -ne "")      { $DeployParams.ProxyPassword        = $ProxyPassword }

& $DownloadTarget @DeployParams
#endregion
