#Requires -RunAsAdministrator
<#
	TODO: Change the argument descriptions to match the new parameters

	.SYNOPSIS
    This is the silent servereye installer.
	
	.DESCRIPTION
    This script will help to install servereye on systems without a full UI or when a full interactive setup is not needed.
    The script can be used to:
    - Download the current version of the client
    - Install the client
    - Setup an OCC-Connector or Sensorhub
    - Create a new customer
    - Apply a template during installation
	
	.PARAMETER Install
    Installs servereye using the Setup .exe in the same folder as the script
	
	.PARAMETER Download
    Downloads the servereye Setup files for servereye matching the version number of the script.
	
	.PARAMETER Offline
    Skips all online checks. Use this only if the computer does not have an Internet connection.
    This should really only be used if all else fails. 
	
	.PARAMETER Deploy
    Assigns the connector to a specific customer.
	
	.PARAMETER CustomerID
    The customer ID to which the computer is added.
	
	.PARAMETER Secret
    The secret to authenticate the connection.
	
	.PARAMETER NodeName
    Optionally, a nodename can be prespecified.
	
	.PARAMETER ParentGuid
    Optionally, this node can be assigned to a specific parent node.
	
	.PARAMETER ConnectorPort
    The port on the connector to connect to.
    Comes preconfigured with the servereye defaults. Don't change it unless you know what you do.

	.PARAMETER Silent
    Suppresses all verbosity and all interactive menus.
    Required for unattended installs.

	.PARAMETER SilentOCCConfirmed
    Confirms that the OCC Connector should be installed in silent (unattended) mode.

	.PARAMETER DeployPath
    The folder runtime files (especially downloaded installer files) are stored in.
    By default, the folder the script was called from. Since this location is not always reliable and sometimes other rules (e.g. Software Restriction Policy) must be honored, this can be configured.
    If the path is not present, the script will try to create it. If this fails, the script will terminate.

	.PARAMETER ApplyTemplate
    No longer in use, only exists for compatibility reasons

	.PARAMETER TemplateId
    The GUID of the template you want to apply to the SensorHub.

	.PARAMETER ApiKey
    No longer in use, only exists for compatibility reasons

	.PARAMETER LogFile
    Path including filename. Logs messages also to that file.

	.PARAMETER NoExit
    Using this, the script is no longer terminated with "exit", allowing it to be used as part of a greater script.
	
	.PARAMETER InstallDotNet
    No longer in use, only exists for compatibility reasons
	
	.EXAMPLE
    PS C:\> .\Deploy-ServerEye.ps1 -Download
    
    This just downloads the current version of the client setup.
	
	.EXAMPLE
    PS C:\> .\Deploy-ServerEye.ps1 -Download -Install
    
    This will download the current version of ServerEye and install it on this computer.
	
	.EXAMPLE
    PS C:\> .\Deploy-ServerEye.ps1 -Download -Install -Deploy All -Customer XXXXXX -Secret YYYYYY
    
    This will download the current version of ServerEye and install it on this computer.
    This will also set up an OCC-Connector and a Sensorhub on this computer for the given customer.
    The parameters Customer and Secret are required for this.
	
	.EXAMPLE
    PS C:\> .\Deploy-ServerEye.ps1 -Download -Install -Deploy SenorhubOnly -Customer XXXXXX -Secret YYYYYY -ParentGuid ZZZZZZ
    
    This will download the current version of ServerEye and install it on this computer.
    This will also set up a Sensorhub on this computer for the given customer.
    The parameters Customer, Secret and ParentGuid are required for this.
	
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
	$ConnectorPort,
	
	[Parameter(Mandatory=$false)]
	[string]
	$TemplateId,
	
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
	$LogFile,
	
	[Parameter(Mandatory=$false)]
	[switch]
	$NoExit
)

#region Utility functions
function Log {
	Param (
		[Parameter(Mandatory=$true, Position=0)]
		[string]
		$LogMessage,

		[Parameter(Mandatory=$false)]
		[switch]
		$LogPath = $LogPath,

		[Parameter(Mandatory=$false)]
		[switch]
		$ToScreen = $false,

		[Parameter(Mandatory=$false)]
		[switch]
		$ToFile = $false,

		[Parameter(Mandatory=$false)]
		[string]
		$ForegroundColor = "Grey",

		[Parameter(Mandatory=$false)]
		[string]
		$BackgroundColor = "Black"
	)

    $Stamp = (Get-Date).toString("dd/MM/yyyy HH:mm:ss")
    $LogMessage = "[$Stamp] $LogString"
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

	$Error500Msg = "Server Error: An internal server error occurred. Please check status.server-eye.de for a potential outage.`nIf theres no current outage, please contact the servereye Helpdesk."
	$UnexpectedErrorMsg = "Unexpected Error: An unexpected error occurred with status code $StatusCode. Please report this to the servereye Helpdesk."

	try {
		$Result = Invoke-WebRequest -Method Post -Uri "https://api.server-eye.de/3/auth/login" -Headers @{ "x-api-key" = $ApiKey } -ErrorAction Stop
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
		$Response = Invoke-WebRequest -Method Get -Uri "https://api.server-eye.de/3/customer/$CustomerID" -Headers @{ "x-api-key" = $ApiKey } -ErrorAction Stop
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
		$Response = Invoke-WebRequest -Method Get -Uri "https://api.server-eye.de/3/container/$ParentGuid" -Headers @{ "x-api-key" = $ApiKey } -ErrorAction Stop
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
		$Result = Invoke-WebRequest -Uri "$SE_baseDownloadUrl/$SE_cloudIdentifier/ServerEyeSetup.exe" -OutFile "$DeployPath\ServerEyeSetup.exe" -ErrorAction Stop
	}
	catch {
		Log "Download failed: `n$($_.Exception.Message)`nStopping execution." -ToScreen -ToFile
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
	Download-SEInstallationFiles -BaseDownloadUrl $BaseDownloadUrl -Path $Path -proxy $WebProxy
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
	if ($proxyUrl) { $parameterString += " --proxyUrl=$proxyUrl" }
	if ($proxyPort) { $parameterString += " --proxyPort=$proxyPort" }
	if ($proxyDomain) { $parameterString += " --proxyDomain=$proxyDomain" }
	if ($proxyUser) { $parameterString += " --proxyUser=$proxyUser" }
	if ($Cleanup) { $parameterString += " --cleanup=true" }

	# This always needs to be set
	$parameterString += " --silent=true"
	
	# Execute ServerEyeSetup.exe with the constructed parameter string
	$setupPath = Join-Path -Path $DeployPath -ChildPath "ServerEyeSetup.exe"
	Start-Process -FilePath $setupPath -ArgumentList "ARGUMENTS=`"$parameterString`" /quiet" -Wait -NoNewWindow
	
	# Read the content of the installer log file
	$installerLogPath = "C:\ProgramData\ServerEye3\logs\installer.log"
	if (Test-Path $installerLogPath) {
		$installerLogContent = Get-Content -Path $installerLogPath -Raw
		if ($installerLogContent -like "*Successfully installed*") {
			Log "Installation finished successfully!" -ForegroundColor Green -ToScreen -ToFile
			Log "`nPlease visit https://occ.server-eye.de to add Sensors.`nHave fun!" -ToScreen
			exit
		} else {
			Log "The installation failed. Please report this to the servereye Helpdesk and include the following file in your Ticket:`n$installerLogPath" -ForegroundColor Red -ToScreen -ToFile
		}
	} else {
		Write-Log -Message "Installer log file not found at $installerLogPath" -EventID 666 -EntryType Error
		Write-Host "The installation was probably successfull, but the ínstaller.log file could not be found at $installerLogPath.`nPlease report this to the servereye Helpdesk." -ForegroundColor Yellow -ToScreen -ToFile
	}
}
#endregion

#region Variables

$SE_occServer = "occ.server-eye.de"
$SE_baseDownloadUrl = "https://$SE_occServer/download"
$SE_cloudIdentifier = "se"
$SE_Version = Invoke-RestMethod -Uri "https://occ.server-eye.de/download/se/currentVersion"

if ($DeployPath -eq "") { $DeployPath = (Resolve-Path .\).Path }

$LogPath = "$env:windir\Temp\Deploy-ServerEye.log"
#endregion

#region Main execution
Check-SEInvalidParameterization
Check-SESupportedOSVersion
Check-SEPreExistingInstallation
Check-SEDeployPath
Start-SEInstallation
#endregion