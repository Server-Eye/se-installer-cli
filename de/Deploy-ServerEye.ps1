#Requires -RunAsAdministrator
<#
	.SYNOPSIS
	Silent installer and deployment script for servereye.

	.DESCRIPTION
	This script automates the download, installation, and configuration of servereye (OCC-Connector or Sensorhub) on Windows systems.
	It is designed for unattended or semi-automated deployments, including environments without a full UI.
	The script supports proxy configuration, parameter validation, and logging.
	It can be used to:
	- Download the latest servereye installer
	- Install and configure an OCC-Connector or Sensorhub
	- Assign the installation to a customer
	- Apply a template to the Sensorhub (optional)
	- Apply tags to the Sensorhub (optional)
	- Log all actions to a file and to the screen if executed interactively

	.PARAMETER Deploy
	Specify the installation type: "OCC-Connector" or "Sensorhub". Required.

	.PARAMETER CustomerID
	The customer ID to which the system will be assigned. Required.

	.PARAMETER ParentGuid
	(Sensorhub only) The GUID of the parent OCC-Connector.

	.PARAMETER ConnectorPort
	The port to use for the OCC-Connector. Optional.

	.PARAMETER TemplateId
	The ID of the template to apply to the Sensorhub. Optional.

	.PARAMETER ApiKey
	The API key for authentication. Required.

	.PARAMETER Cleanup
	Switch. If set, cleans up temporary files after installation. Optional.

	.PARAMETER proxyUrl
	The proxy server URL to use for downloads and API calls. Optional.

	.PARAMETER proxyPort
	The proxy server port. Optional.

	.PARAMETER proxyDomain
	The proxy domain for authentication. Optional.

	.PARAMETER proxyUser
	The proxy username for authentication. Optional.

	.PARAMETER proxyPassword
	The proxy password for authentication. Optional.

	.PARAMETER Silent
	Switch. Suppresses all interactive prompts and verbose output. Required for unattended installs.

	.PARAMETER DeployPath
	The directory where runtime and installer files are stored. Defaults to the script directory. Optional.

	.PARAMETER SkipInstalledCheck
	Switch. Skips the check for an existing servereye installation. Optional.

	.PARAMETER LogFile
	Path to a log file. All log messages will also be written to this file. Optional.

	.PARAMETER NoExit
	Switch. Prevents the script from calling 'exit', allowing it to be used in larger automation workflows. Optional.

	.EXAMPLE
	PS C:\> .\Deploy-ServerEye.ps1 -Deploy Sensorhub -CustomerID 12345 -ParentGuid 67890 -ApiKey ABCDEFG -Silent
	Installs a Sensorhub for customer 12345, assigns it to the OCC-Connector 67890, using the provided API key, in silent mode.

	.EXAMPLE
	PS C:\> .\Deploy-ServerEye.ps1 -Deploy OCC-Connector -CustomerID 12345 -ApiKey ABCDEFG -proxyUrl "http://proxy" -proxyPort 8080
	Installs an OCC-Connector for customer 12345 and configures it to use the specified proxy server.

	.NOTES
	Author  : servereye
	Version : 2.0

	.LINK
	https://github.com/Server-Eye/se-installer-cli
#>
#Requires -Version 2

[CmdletBinding(DefaultParameterSetName ='None')]
param(
	[Parameter(Mandatory=$true)]
	[ValidateSet("OCC-Connector", "Sensorhub")]
	[string]
	$Deploy,
	
	[Parameter(Mandatory=$true)]
	[string]
	$CustomerID,
	
	[Parameter(Mandatory=$false)]
	[string]
	$ParentGuid,
	
	[Parameter(Mandatory=$false)]
	[string]
	$TemplateID,

	[Parameter(Mandatory=$false)]
	[string[]]
	$TagIDs,

	[Parameter(Mandatory=$false)]
	[string]
	$LogPath = "$env:windir\Temp",

	[Parameter(Mandatory=$true)]
	[string]
	$RemoteLogPath,
	
	[Parameter(Mandatory=$true)]
	[string]
	$ApiKey,

	[Parameter(Mandatory=$false)]
	[switch]
	$Cleanup,
	
	[Parameter(Mandatory=$false)]
	[string]
	$DeployPath,
	
	[Parameter(Mandatory=$false)]
	[switch]
    $SkipInstalledCheck,

	[Parameter(Mandatory=$false)]
	[string]
	$ConnectorPort,

	[Parameter(Mandatory=$false)]
	[string]
	$ProxyUrl,

	[Parameter(Mandatory=$false)]
	[string]
	$ProxyPort,

	[Parameter(Mandatory=$false)]
	[string]
	$ProxyDomain,

	[Parameter(Mandatory=$false)]
	[string]
	$ProxyUser,

	[Parameter(Mandatory=$false)]
	[string]
	$ProxyPassword
)

#region Utility functions
function Log {
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]
        $LogMessage,

        [Parameter(Mandatory=$false)]
        [string]
        $LogPath = $LogPath,

        [Parameter(Mandatory=$false)]
        [switch]
        $ToScreen = $false,

        [Parameter(Mandatory=$false)]
        [switch]
        $ToFile = $false,

        [Parameter(Mandatory=$false)]
        [ValidateSet(
            "Black", "DarkBlue", "DarkGreen", "DarkCyan", "DarkRed", "DarkMagenta",
            "DarkYellow", "Gray", "DarkGray", "Blue", "Green", "Cyan", "Red",
            "Magenta", "Yellow", "White"
        )]
        [string]
        $ForegroundColor = "Gray",

        [Parameter(Mandatory=$false)]
        [ValidateSet(
            "Black", "DarkBlue", "DarkGreen", "DarkCyan", "DarkRed", "DarkMagenta",
            "DarkYellow", "Gray", "DarkGray", "Blue", "Green", "Cyan", "Red",
            "Magenta", "Yellow", "White"
        )]
        [string]
        $BackgroundColor = "Black"
    )

    $Stamp = (Get-Date).toString("dd/MM/yyyy HH:mm:ss")
    $LogMessage = "[$Stamp] $LogMessage"

    if ($ToScreen) {
        Write-Host -Object $LogMessage -ForegroundColor $ForegroundColor -BackgroundColor $BackgroundColor
    }
    if ($ToFile) {
        Add-Content -Path $LogPath -Value $LogMessage
    }
}


function Get-ProgramFilesDirectory {	
	if (([IntPtr]::Size -eq 8) -eq $true) {
		Get-Item ${Env:ProgramFiles(x86)} | Select-Object -ExpandProperty FullName
	} else {
		Get-Item $env:ProgramFiles | Select-Object -ExpandProperty FullName
	}
}

function Write-SEHeader {
	$AsciiArt_servereye = @"
 ___  ___ _ ____   _____ _ __ ___ _   _  ___ 	
/ __|/ _ \ '__\ \ / / _ \ '__/ _ \ | | |/ _ \
\__ \  __/ |   \ V /  __/ | |  __/ |_| |  __/
|___/\___|_|    \_/ \___|_|  \___|\__, |\___|
                                   __/ |     
                                  |___/      
"@
	Log $AsciiArt_servereye -ForegroundColor DarkYellow -ToScreen
	Log "                            Version 4.0.$SE_version`n" -ForegroundColor Gray -ToScreen
	Log "Welcome to the silent servereye installer`n" -ForegroundColor Gray -ToScreen
}
#endregion

#region Main functions
function Check-SEInvalidParameterization {

	try {
		$null = Invoke-WebRequest -Method Post -Uri "https://api.server-eye.de/3/auth/login" -Headers @{ "x-api-key" = $ApiKey } -ErrorAction Stop
	} catch {
		$StatusCode = $_.Exception.Response.StatusCode.value__
		switch ($StatusCode) {
			401 {
				Log "Invalid Parameters: The provided API-Key is invalid. Please provide a valid API-Key via '-ApiKey'." -ToScreen -ToFile
				exit
			}
			500 {
				Log $Error500Msg -ForegroundColor Red -ToScreen -ToFile
				exit
			}
			default {
				Log $UnexpectedErrorMsg -ForegroundColor Red -ToScreen -ToFile
				exit
			}
		}
	}

	if ($Deploy -eq "Sensorhub" -and (-not $ParentGuid)) {
		Log "Invalid Parameters: Please provide the ParentGuid of an OCC-Connector when installing a Sensorhub via '-ParentGuid'" -ToScreen -ToFile
		$StopExecution = $true
	}

	if ($Deploy -eq "Sensorhub" -and ($ConnectorPort)) {
		Log "Invalid Parameters: A ConnectorPort can only be specified when installing an OCC-Connector. Don't use -ConnectorPort when installing a Sensorhub." -ToScreen -ToFile
		$StopExecution = $true
	}

	try {
		$null = Invoke-WebRequest -Method Get -Uri "https://api.server-eye.de/3/customer/$CustomerID" -Headers @{ "x-api-key" = $ApiKey } -ErrorAction Stop
	} catch {
		$StatusCode = $_.Exception.Response.StatusCode.value__
		switch ($StatusCode) {
			403 {
				Log "Invalid Parameters: A customer with this ID doesn't exist or you don't have access to it. Please check if the provided CustomerID is correct." -ToScreen -ToFile
			}
			500 {
				Log $Error500Msg -ForegroundColor Red -ToScreen -ToFile
				exit
			}
			default {
				Log $UnexpectedErrorMsg -ForegroundColor Red -ToScreen -ToFile
				exit
			}
		}
		$StopExecution = $true
	}

	try {
		$null = Invoke-WebRequest -Method Get -Uri "https://api.server-eye.de/3/container/$ParentGuid" -Headers @{ "x-api-key" = $ApiKey } -ErrorAction Stop
	} catch {
		$StatusCode = $_.Exception.Response.StatusCode.value__
		switch ($StatusCode) {
			404 {
				Log "Invalid Parameters: An OCC-Connector with this ID doesn't exist or you don't have access to it. Please check if the provided ParentGuid is correct." -ToScreen -ToFile
			}
			500 {
				Log $Error500Msg -ForegroundColor Red -ToScreen -ToFile
				exit
			}
			default {
				Log $UnexpectedErrorMsg -ForegroundColor Red -ToScreen -ToFile
				exit
			}
		}
		$StopExecution = $true
	}

	try {
		Invoke-WebRequest -Method Get -Uri "https://api.server-eye.de/3/customer/template/$TemplateId/agent" -Headers @{ "x-api-key" = $ApiKey } -ErrorAction Stop | Out-Null
	} catch {
		$StatusCode = $_.Exception.Response.StatusCode.value__
		switch ($StatusCode) {
			404 {
				Log "Invalid Parameters: A Template with this ID doesn't exist or you don't have access to it. Please check if the provided TemplateID is correct." -ToScreen -ToFile
			}
			500 {
				Log $Error500Msg -ToScreen -ToFile
				exit
			}
			default {
				Log $UnexpectedErrorMsg -ToScreen -ToFile
				exit
			}
		}
		$StopExecution = $true
	}

	if ($StopExecution) {
		Log "Exiting script due to invalid parameters!" -ToScreen -ToFile
		exit
	}
}

function Check-SESupportedOSVersion {
	if ([environment]::OSVersion.Version.Major -lt 6) {
		if (-not $script:_SilentOverride) {
			Log "Your operating system is not officially supported.`nThe install will most likely work but we can no longer provide support for servereye on this system." -ToScreen -ToFile
			
			$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes, continue without support", "The install will continue, but we cannot help you if something doesn't work."
			$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No, cancel the install", "End the install now."
			$choices = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
			$caption = ""
			$message = "Do you still want to install servereye on this computer?"
			$result = $Host.UI.PromptForChoice($caption, $message, $choices, 1)
			if ($result -eq 1) {
				Log "Execution interrupted by user" -ToScreen -ToFile
				exit
			   } else { Log "Execution continued by user" -ToScreen -ToFile }
		} else {
			Log "Non-Supported OS detected, interrupting installation." -ToScreen -ToFile
			exit
		}
	}
}

function Check-SEPreExistingInstallation {
	$progdir = Get-ProgramFilesDirectory
	$confDir = "$progdir\Server-Eye\config"
	$confFileMAC = "$confDir\se3_mac.conf"
	$confFileCC = "$confDir\se3_cc.conf"
	$seDataDir = "$env:ProgramData\ServerEye3"

	if ((-not $SkipInstalledCheck) -and (($PSBoundParameters.ContainsKey('Deploy')) -and ((Test-Path $confFileMAC) -or (Test-Path $confFileCC) -or (Test-Path $seDataDir)))) {
		Log "Stopping Execution: A previous installation was detected." -ToScreen -ToFile
		exit
	}
}

function Check-SEDeployPath {
	if (-not (Test-Path $DeployPath)) {
		try {
			$folder = New-Item -Path $DeployPath -ItemType 'Directory' -Force -Confirm:$false
			if ((-not $folder.Exists) -or (-not $folder.PSIsContainer)) {
				Log "Stopping Execution: Deployment Path: $DeployPath could not be created." -ForegroundColor Red -ToScreen -ToFile
				exit
			} else { $DeployPath = $folder.FullName }
		}
		catch {
			Log "Stopping Execution: Deployment Path: $DeployPath could not be created: $($_.Exception.Message)" -ForegroundColor Red -ToScreen -ToFile
			exit
		}
	} else {
		$DeployPath = Get-Item -Path $DeployPath | Select-Object -ExpandProperty FullName -First 1
	}
}

function Download-SEInstallationFiles {
	Log "Current servereye version is: $SE_version" -ToScreen -ToFile
	Log "Starting download of ServerEyeSetup.exe... " -ToScreen -ToFile
	try {
		$null = Invoke-WebRequest -Uri "$SE_baseDownloadUrl/$SE_cloudIdentifier/ServerEyeSetup.exe" -OutFile "$DeployPath\ServerEyeSetup.exe" -ErrorAction Stop
	}
	catch {
		Log "Download failed:`n$($_.Exception.Message)`nStopping execution." -ToScreen -ToFile
		exit
	}
}

function Start-SEInstallation {
	Write-SEHeader
	
	if ($Deploy -eq "OCC-Connector") {
		Log "Make sure user is sure he wants to install an OCC-Connector..." -ToFile
		$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes, I want to install an OCC-Connector", "This will continue to set up the OCC-Connector."
		$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No.", "This will cancel everything and end this installer."
		$choices = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
		$caption = ""
		$message = "Are you sure you want to install an OCC-Connector? In most cases, only one is needed per network/subnet."
		$result = $Host.UI.PromptForChoice($caption, $message, $choices, 1)
		
		if ($result -eq 0) {
			Log "Great, let's continue." -ToScreen -ToFile
		} else {
			Log "Then we better stop here. Use the parameter '-Deploy Sensorhub' instead. Exiting." -ToScreen -ToFile
			exit
		}
	}

	Log "Starting installation process..." -ToScreen -ToFile

	Log "Starting download routine..." -ToScreen -ToFile
	Download-SEInstallationFiles
	Log "Download routine finished." -ToScreen -ToFile

	$parameterString = ""

	# These are specific to the installation type
	if ($Deploy -eq "OCC-Connector") {
		Log "Starting servereye OCC-Connector installation..." -ToScreen -ToFile
		$parameterString += "newConnector"
	} elseif ($Deploy -eq "Sensorhub") {
		Log "Starting servereye Sensorhub configuration..." -ToScreen -ToFile
		$parameterString += "install"
		$parameterString += " --cID=$ParentGuid"
	}

	# These are common to all installations
	if ($ApiKey) { $parameterString += " --apiKey=$ApiKey" }
	if ($CustomerID) { $parameterString += " --customerID=$CustomerID" }
	if ($TemplateId) { $parameterString += " --templateID=$TemplateId" }
	if ($ConnectorPort) { $parameterString += " --port=$ConnectorPort" }
	if ($ProxyUrl) { $parameterString += " --proxyUrl=$ProxyUrl" }
	if ($ProxyPort) { $parameterString += " --proxyPort=$ProxyPort" }
	if ($ProxyDomain) { $parameterString += " --proxyDomain=$ProxyDomain" }
	if ($ProxyUser) { $parameterString += " --proxyUser=$ProxyUser" }
	if ($ProxyPassword) { $parameterString += " --proxyPassword=$ProxyPassword" }
	if ($Cleanup) { $parameterString += " --cleanup=true" }

	# This always needs to be set
	$parameterString += " --silent=true"
	
	# Execute ServerEyeSetup.exe with the constructed parameter string
	$setupPath = Join-Path -Path $DeployPath -ChildPath "ServerEyeSetup.exe"
	Start-Process -FilePath $setupPath -ArgumentList "ARGUMENTS=`"$parameterString`" /quiet" -Wait -NoNewWindow
	
	# Read the content of the installer log file
	$installerLogPath = "$env:ProgramData\ServerEye3\logs\installer.log"
	if (Test-Path $installerLogPath) {
		$installerLogContent = Get-Content -Path $installerLogPath -Raw
		if ($installerLogContent -like "*Successfully installed*") {
			Log "Installation finished successfully!" -ForegroundColor Green -ToScreen -ToFile
			Log "Please visit https://occ.server-eye.de to add Sensors.`nHave fun!" -ToScreen
			exit
		} else {
			Log "The installation has failed. Please report this to the servereye Helpdesk and include the following file in your Ticket:`n'$installerLogPath'" -ForegroundColor Red -ToScreen -ToFile
		}
	} else {
		Log "The installation was probably successful, but the installer.log file could not be found at '$installerLogPath'.`nPlease report this to the servereye Helpdesk." -ForegroundColor Yellow -ToScreen -ToFile
	}
}

function Add-SETags {
	Log "Starting to add Tags since -TagIDs was passed..." -ToScreen -ToFile

	Log "Waiting for CCService to generate a GUID for the Sensorhub..."
    for ($i = 1; $i -le 120; $i++) {
        try {
            Log "Attempt $($i): Getting new Sensorhub GUID..." -ToScreen -ToFile
            Start-Sleep -Seconds 10
            $SensorhubId = (Get-Content $CCConfigPath -ErrorAction Stop | Select-String -Pattern "^guid=").ToString().Split("=")[1].Trim()
            if (-not $SensorhubId) {
                if ($i -eq 120) {
                    Log "Failed to get Sensorhub GUID after 20 minutes, tags can't be added." -ForegroundColor Red -ToScreen -ToFile
                }
                continue
            }
            Log "New Sensorhub GUID which the tags will be added to: '$SensorhubId'" -ToScreen -ToFile
            break
        }
        catch {
            Log "Failed to retrieve new Sensorhub GUID. No Tags were added. Error: `n$_" -ForegroundColor Red -ToScreen -ToFile
        }
    }

	foreach ($TagID in $TagIDs) {
		try {
			$null = Invoke-WebRequest -Method Put -Uri "https://api.server-eye.de/3/container/$SensorhubId/tag/$TagID" -Headers @{ "x-api-key" = $ApiKey } -ErrorAction Stop
			Log "Successfully added Tag with ID '$($TagID)' to the Sensorhub." -ToScreen -ToFile
		} catch {
			$StatusCode = $_.Exception.Response.StatusCode.value__
			switch ($StatusCode) {
				403 {
					Log "Failed to add Tag with ID '$($TagID)': You don't have access to this Tag." -ToScreen -ToFile
				}
				404 {
					Log "Failed to add Tag with ID '$($TagID)': A Tag with this ID doesn't exist." -ToScreen -ToFile
				}
				500 {
					Log $Error500Msg -ForegroundColor Red -ToScreen -ToFile
					exit
				}
				default {
					Log $UnexpectedErrorMsg -ForegroundColor Red -ToScreen -ToFile
					exit
				}
			}
		}
	}
}
#endregion

#region Variables
$LogPath = $LogPath | Join-Path -ChildPath "Deploy-ServerEye.log"

$Error500Msg = "Server Error: An internal server error occurred. Please check status.server-eye.de for a potential outage.`nIf theres no current outage, please contact the servereye Helpdesk."
$UnexpectedErrorMsg = "Unexpected Error: An unexpected error occurred with status code $($_.Exception.Response.StatusCode.value__). Please report this to the servereye Helpdesk."

$SE_occServer = "occ.server-eye.de"
$SE_baseDownloadUrl = "https://$SE_occServer/download"
$SE_cloudIdentifier = "se"
$SE_Version = Invoke-RestMethod -Uri "$SE_baseDownloadUrl/se/currentVersion"
$ProgramFiles = Get-ProgramFilesDirectory
$CCConfigPath = "$ProgramFiles\Server-Eye\config\se3_cc.conf"

if ($DeployPath -eq "") { $DeployPath = (Resolve-Path .\).Path }
#endregion

#region Main execution
Check-SEInvalidParameterization
Check-SESupportedOSVersion
Check-SEPreExistingInstallation
Check-SEDeployPath
Start-SEInstallation
if ($TagIDs) { Add-SETags }
if ($RemoteLog) {
	Copy-Item -Path $LogPath -Destination "$RemoteLog\$env:computername.log" -Force
}
Log "Deploy-ServerEye.ps1 finished!" -ToFile -ToScreen
#endregion