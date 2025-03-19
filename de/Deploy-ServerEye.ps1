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

	.PARAMETER Proxy
    Proxy seetings if needed
	
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
	$proxyUrl,

	[Parameter(Mandatory=$false)]
	[string]
	$proxyPort,

	[Parameter(Mandatory=$false)]
	[string]
	$proxyDomain,

	[Parameter(Mandatory=$false)]
	[string]
	$proxyUser,

	[Parameter(Mandatory=$false)]
	[string]
	$proxyPassword,
	
	[Parameter(Mandatory=$false)]
	[switch]
	$Silent,
	
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
function Write-Log {
	<#
		.SYNOPSIS
			A swift logging function.
		
		.DESCRIPTION
			A simple way to produce logs in various formats.
			Log-Types:
			- Eventlog (Application --> ServerEyeDeployment)
			- LogFile (Includes timestamp, EntryType, EventID and Message)
			- Screen (Includes only the message)
		
		.PARAMETER Message
			The message to log.
		
		.PARAMETER Silent
			Whether anything should be written to host. Is controlled by the closest scoped $_SilentOverride variable, unless specified.
		
		.PARAMETER ForegroundColor
			In what color messages should be written to the host.
			Ignored if silent is set to true.
		
		.PARAMETER NoNewLine
			Prevents output to host to move on to the next line.
			Ignored if silent is set to true.
		
		.PARAMETER EventID
			ID of the event as logged to both the eventlog as well as the logfile.
			Defaults to 1000
		
		.PARAMETER EntryType
			The type of event that is written.
			By default an information event is written.
		
		.PARAMETER LogFilePath
			The path to the file (including filename) that is written to.
			Is controlled by the closest scoped $_LogFilePath variable, unless specified.
		
		.EXAMPLE
			PS C:\> Write-Log 'Test Message'
	
			Writes the string 'Test Message' with EventID 1000 as an information event into the application eventlog, into the logfile and to the screen.
		
		.NOTES
			Supported Interfaces:
			------------------------
			
			Author:       Friedrich Weinmann
			Company:      die netzwerker Computernetze GmbH
			Created:      12.05.2016
			LastChanged:  12.05.2016
			Version:      1.0
	
			EventIDs:
			1000 : All is well
			4*   : Some kind of Error
			666  : Terminal Error
	
			10   : Started Download
			11   : Finished Download
			12   : Started Installation
			13   : Finished Installation
			14   : Started Configuring Sensorhub
			15   : Finished Configuriong Sensorhub
			16   : Started Configuring OCC Connector
			17   : Finished Configuring Sensorhub
			
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Position = 0)]
		[string]
		$Message,
		
		[bool]
		$Silent = $_SilentOverride,
		
		[System.ConsoleColor]
		$ForegroundColor,
		
		[switch]
		$NoNewLine,
		
		[Parameter(Position = 1)]
		[int]
		$EventID = 1000,
		
		[Parameter(Position = 2)]
		[System.Diagnostics.EventLogEntryType]
		$EntryType = ([System.Diagnostics.EventLogEntryType]::Information),
		
		[string]
		$LogFilePath = $_LogFilePath
	)
	
	# Log to Eventlog
	try { Write-EventLog -Message $message -LogName 'Application' -Source 'ServerEyeDeployment' -Category 0 -EventId $EventID -EntryType $EntryType -ErrorAction Stop }
	catch { }
	
	# Log to File
	try { "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss");$EntryType;$EventID;$Message" | Out-File -FilePath $LogFilePath -Append -Encoding UTF8 -ErrorAction Stop }
	catch { }
	
	# Write to screen
	if (-not $Silent)
	{
		$splat = @{ }
		$splat['Object'] = $Message
		if ($PSBoundParameters.ContainsKey('ForegroundColor')) { $splat['ForegroundColor'] = $ForegroundColor }
		if ($PSBoundParameters.ContainsKey('NoNewLine')) { $splat['NoNewLine'] = $NoNewLine }
		
		Write-Host @splat
	}
}

function Get-SELatestVersion {
    $wc = New-Object System.Net.WebClient
    if (!$Proxy){
        $WebProxy = New-Object System.Net.WebProxy($proxy, $true)
        $wc.Proxy = $WebProxy
    } elseif (($Proxy.gettype()).Name -eq "WebProxy") {
        $wc.Proxy = $WebProxy
    } else {
        $WebProxy = New-Object System.Net.WebProxy($proxy, $true)
        $wc.Proxy = $WebProxy
    }

    return $wc.DownloadString("https://occ.server-eye.de/download/se/currentVersion")
}

function Download-SEFile {
	[CmdletBinding()]
	Param (
		[string]
		$Url,
		
		[string]
		$TargetFile,

		$Proxy
	)

	if ([System.IO.File]::Exists($TargetFile)) {
		Write-Log "Using local file" -ForegroundColor Green
	} else {	
		try {
			$uri = New-Object "System.Uri" "$url"
			$request = [System.Net.HttpWebRequest]::Create($uri)
			if (!$Proxy) {
				$WebProxy = New-Object System.Net.WebProxy($proxy, $true)
				$request.Proxy = $WebProxy
			} elseif (($Proxy.gettype()).Name -eq "WebProxy") {
				$request.Proxy = $WebProxy
			} else {
				$WebProxy = New-Object System.Net.WebProxy($proxy, $true)
				$request.Proxy = $WebProxy
			}
			$request.set_Timeout(15000) # 15 second timeout
			$response = $request.GetResponse()
			$totalLength = [System.Math]::Floor($response.get_ContentLength()/1024)
			$responseStream = $response.GetResponseStream()
			$targetStream = New-Object -TypeName System.IO.FileStream -ArgumentList $targetFile, Create
			$buffer = New-Object byte[] 10KB
			$count = $responseStream.Read($buffer, 0, $buffer.length)
			$downloadedBytes = $count
			
			while ($count -gt 0) {
				$targetStream.Write($buffer, 0, $count)
				$count = $responseStream.Read($buffer, 0, $buffer.length)
				$downloadedBytes = $downloadedBytes + $count
				Write-Progress -activity "Downloading file '$($url.split('/') | Select-Object -Last 1)'" -status "Downloaded ($([System.Math]::Floor($downloadedBytes/1024))K of $($totalLength)K): " -PercentComplete ((([System.Math]::Floor($downloadedBytes/1024)) / $totalLength) * 100)
			}
			
			Write-Progress -activity "Finished downloading file '$($url.split('/') | Select-Object -Last 1)'" -Status "Done" -Completed
			
			$targetStream.Flush()
			$targetStream.Close()
			$targetStream.Dispose()
			$responseStream.Dispose()

			Write-Log "done" -ForegroundColor Green
			
		} catch {
			Write-Log -Message "Error downloading: $Url - Interrupting execution - $($_.Exception.Message)" -EventID 666 -EntryType Error
			Stop-Execution
		}
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
	# Suppress all text-output in silent mode
	if ($script:_SilentOverride) { return }

	$AsciiArt_servereye = @"
 ___  ___ _ ____   _____ _ __ ___ _   _  ___ 	
/ __|/ _ \ '__\ \ / / _ \ '__/ _ \ | | |/ _ \
\__ \  __/ |   \ V /  __/ | |  __/ |_| |  __/
|___/\___|_|    \_/ \___|_|  \___|\__, |\___|
                                   __/ |     
                                  |___/      
"@
	Write-Host $AsciiArt_servereye -ForegroundColor DarkYellow
	Write-Host "                            Version 4.0.$SE_version`n" -ForegroundColor DarkGray
	Write-Host "Welcome to the silent servereye installer`n"
}

function Stop-Execution {
	[CmdletBinding()]
	Param (
		[Parameter(Position = 1)]
		[int]
		$Number = 1
	)
	
	if ($script:_NoExit) { break main }
	else { exit $Number }
}

function Check-ForSuccessfulInstallation {

	switch ($x) {
		condition {  }
		Default {}
	}
	
}
#endregion

#region Main functions
function Check-SEInvalidParameterization {

	$Error500Msg = "Server Error: An internal server error occurred. Please check status.server-eye.de for a potential outage.`n If theres no current outage, please contact the servereye Helpdesk."
	$UnexpectedErrorMsg = "Unexpected Error: An unexpected error occurred with status code $StatusCode. Please report this to the servereye Helpdesk."

	try {
		Invoke-WebRequest -Method Post -Uri "https://api.server-eye.de/3/auth/login" -Headers @{ "x-api-key" = $ApiKey } -ErrorAction Stop | Out-Null
	} catch {
		$StatusCode = $_.Exception.Response.StatusCode.value__
		switch ($StatusCode) {
			401 {
				Write-Log "Invalid Parameters: The provided API-Key is invalid. Please provide a valid API-Key via '-ApiKey'." -EventID 666 -EntryType Error -ForegroundColor Red
				Stop-Execution
			}
			500 {
				Write-Log $Error500Msg -EventID 666 -EntryType Error -ForegroundColor Red
				Stop-Execution
			}
			default {
				Write-Log $UnexpectedErrorMsg -EventID 666 -EntryType Error -ForegroundColor Red
				Stop-Execution
			}
		}
	}

	if ($Deploy -eq "Sensorhub" -and (-not $ParentGuid)) {
		Write-Log -Message "Invalid Parameters: Please provide the ParentGuid of an OCC-Connector when installing a Sensorhub via '-ParentGuid'" -EventID 666 -EntryType Error
		$StopExecution = $true
	}

	if ($proxyUrl -and (-not $proxyPort)) {
		Write-Log -Message "Invalid Parameters: Proxy URL is set but no port is provided. Please provide a port via '-ProxyPort'." -EventID 666 -EntryType Error
		$StopExecution = $true
	}

	if ($Deploy -eq "Sensorhub" -and ($ConnectorPort)) {
		Write-Log -Message "Invalid Parameters: A ConnectorPort can only be specified when installing an OCC-Connector. Don't use -ConnectorPort when installing a Sensorhub." -EventID 666 -EntryType Error
		$StopExecution = $true
	}

	try {
		Invoke-WebRequest -Method Get -Uri "https://api.server-eye.de/3/customer/$CustomerID" -Headers @{ "x-api-key" = $ApiKey } -ErrorAction Stop | Out-Null
	} catch {
		$StatusCode = $_.Exception.Response.StatusCode.value__
		switch ($StatusCode) {
			403 {
				Write-Log "Invalid Parameters: A customer with this ID doesn't exist or you don't have access to it. Please check if the provided CustomerID is correct." -EventID 666 -EntryType Error -ForegroundColor Red
			}
			500 {
				Write-Log $Error500Msg -EventID 666 -EntryType Error -ForegroundColor Red
				Stop-Execution
			}
			default {
				Write-Log $UnexpectedErrorMsg -EventID 666 -EntryType Error -ForegroundColor Red
				Stop-Execution
			}
		}
		$StopExecution = $true
	}

	try {
		Invoke-WebRequest -Method Get -Uri "https://api.server-eye.de/3/container/$ParentGuid" -Headers @{ "x-api-key" = $ApiKey } -ErrorAction Stop | Out-Null
	} catch {
		$StatusCode = $_.Exception.Response.StatusCode.value__
		switch ($StatusCode) {
			404 {
				Write-Log "Invalid Parameters: An OCC-Connector with this ID doesn't exist or you don't have access to it. Please check if the provided ParentGuid is correct." -EventID 666 -EntryType Error -ForegroundColor Red
			}
			500 {
				Write-Log $Error500Msg -EventID 666 -EntryType Error -ForegroundColor Red
				Stop-Execution
			}
			default {
				Write-Log $UnexpectedErrorMsg -EventID 666 -EntryType Error -ForegroundColor Red
				Stop-Execution
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
				Write-Log "Invalid Parameters: A Template with this ID doesn't exist or you don't have access to it. Please check if the provided TemplateID is correct." -EventID 666 -EntryType Error -ForegroundColor Red
			}
			500 {
				Write-Log $Error500Msg -EventID 666 -EntryType Error -ForegroundColor Red
				Stop-Execution
			}
			default {
				Write-Log $UnexpectedErrorMsg -EventID 666 -EntryType Error -ForegroundColor Red
				Stop-Execution
			}
		}
		$StopExecution = $true
	}

	if ($StopExecution) {
		Write-Log -Message "Exiting script due to invalid parameters!" -EventID 666 -EntryType Error -ForegroundColor Red
		Stop-Execution
	}
}

function Check-SESupportedOSVersion {
	if ([environment]::OSVersion.Version.Major -lt 6) {
		if (-not $script:_SilentOverride) {
			Write-Log -Message "Your operating system is not officially supported.`nThe install will most likely work but we can no longer provide support for servereye on this system." -EntryType Warning -EventID 400
			
			$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes, continue without support", "The install will continue, but we cannot help you if something doesn't work."
			$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No, cancel the install", "End the install now."
			$choices = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
			$caption = ""
			$message = "Do you still want to install servereye on this computer?"
			$result = $Host.UI.PromptForChoice($caption, $message, $choices, 1)
			if ($result -eq 1) {
				Write-Log -Message "Execution interrupted by user" -EventID 666 -EntryType Warning -Silent $true
				Stop-Execution
			} else { Write-Log -Message "Execution continued by user" -EventID 499 -EntryType Warning -Silent $true }
		} else {
			Write-Log -Message "Non-Supported OS detected, interrupting installation" -EventID 666 -EntryType Error
			Stop-Execution
		}
	}
}

function Check-PreExistingInstallation {
	$progdir = Get-ProgramFilesDirectory
	$confDir = "$progdir\Server-Eye\config"
	$confFileMAC = "$confDir\se3_mac.conf"
	$confFileCC = "$confDir\se3_cc.conf"
	$seDataDir = "$env:ProgramData\ServerEye3"
	
	if ((-not $SkipInstalledCheck) -and (($PSBoundParameters.ContainsKey('Deploy')) -and ((Test-Path $confFileMAC) -or (Test-Path $confFileCC) -or (Test-Path $seDataDir)))) {		
		Stop-Execution
	}
}

function Check-SEDeployPath {
	if (-not (Test-Path $DeployPath))
	{
		try
		{
			$folder = New-Item -Path $DeployPath -ItemType 'Directory' -Force -Confirm:$false
			if ((-not $folder.Exists) -or (-not $folder.PSIsContainer))
			{
				Write-Log "Stopping Execution: Deployment Path: $DeployPath could not be created."
				Stop-Execution
			}
			else { $DeployPath = $folder.FullName }
		}
		catch
		{
			Write-Log "Stopping Execution: Deployment Path: $DeployPath could not be created: $($_.Exception.Message)"
			Stop-Execution
		}
	}
	else
	{
		$DeployPath = Get-Item -Path $DeployPath | Select-Object -ExpandProperty FullName -First 1
	}
}

function Download-SEInstallationFiles {	
	Write-Log "Getting current servereye version... "
	Write-Log "Current servereye version is: $SE_version"
	Write-Log "Downloading ServerEye.Setup... "
	Download-SEFile -Url "$SE_baseDownloadUrl/$SE_cloudIdentifier/ServerEyeSetup.exe" -TargetFile "$DeployPath\ServerEyeSetup.exe" -Proxy $Proxy
}

function Start-ServerEyeInstallation {
	if (-not $Silent) { Write-SEHeader }
	
	if ((-not $Silent) -and ($Deploy -eq "OCC-Connector")) {
		Write-Log -Message "Ensuring user is sure setting up an OCC-Connector is the correct choice" -Silent $true
		$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes, I want to install an OCC-Connector", "This will continue to set up the OCC-Connector."
		$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No.", "This will cancel everything and end this installer."
		$choices = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
		$caption = ""
		$message = "Are you sure you want to install an OCC-Connector? In most cases, only one is needed per network/subnet."
		$result = $Host.UI.PromptForChoice($caption, $message, $choices, 1)
		
		if ($result -eq 0) {
			Write-Host "Great, let's continue."
			Write-Log "User-Choice: Is sure. Continuing OCC-Connector installation" -Silent $true
		} else {
			Write-Host "Then we better stop here. Use the switch '-Deploy SensorhubOnly' instead."
			Write-Log "User-Choice: Is sure of wrong choice. Interrupting OCC-Connector installation" -Silent $true -EventID 1001
			Stop-Execution
		}
	}

	Write-Log "Starting installation process..."

	Write-Log "Starting download routine..." -EventID 10
	Download-SEInstallationFiles -BaseDownloadUrl $BaseDownloadUrl -Path $Path -proxy $WebProxy
	Write-Log "Download routine finished" -EventID 11

	# Build the parameter string for ServerEyeSetup.exe
	$parameterString = ""

	# These are specific to the installation type
	if ($Deploy -eq "OCC-Connector") {
		Write-Log "Starting servereye OCC-Connector installation" -EventID 16
		$parameterString += "newConnector"
	} elseif ($Deploy -eq "Sensorhub") {
		Write-Log "Starting servereye Sensorhub configuration" -EventID 14
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
			Write-Log "Installation finished successfully!" -EventID 1 -Silent $true
			Write-Host "Installation finished successfully!" -ForegroundColor Green
			Write-Host "`nPlease visit https://occ.server-eye.de to add Sensors.`nHave fun!"
			Stop-Execution -Number 0
		} else {
			Write-Log -Message "Installation failed!" -EventID 666 -EntryType Error -Silent $true
			Write-Host "The installation failed. Please report this to the servereye Helpdesk and include the following file in your Ticket:`n$installerLogPath" -ForegroundColor Red
		}
	} else {
		Write-Log -Message "Installer log file not found at $installerLogPath" -EventID 666 -EntryType Error
		Write-Host "The installation was probably successfull, but the ínstaller.log file could not be found at $installerLogPath.`nPlease report this to the servereye Helpdesk." -ForegroundColor Yellow
	}
}
#endregion

#region Variables
# Set the global verbosity level
$script:_SilentOverride = $Silent.ToBool()

# Set global exit preference
$script:_NoExit = $NoExit.ToBool()

$SE_occServer = "occ.server-eye.de"
$SE_baseDownloadUrl = "https://$SE_occServer/download"
$SE_cloudIdentifier = "se"
$SE_Version = Get-SELatestVersion

# Construct the proxy for use in the script from the parameters provided by the user
if ($proxyUrl -and $proxyPort) {
	$Proxy = New-Object System.Net.WebProxy($proxyUrl, $proxyPort)
	if ($proxyDomain -and $proxyUser -and $proxyPassword) {
		$Proxy.Credentials = New-Object System.Net.NetworkCredential($proxyUser, $proxyPassword, $proxyDomain)
	}
} else {
	$Proxy = $null
}

if ($DeployPath -eq "") { $DeployPath = (Resolve-Path .\).Path }

if ($LogFile -eq "") {
	$script:_LogFilePath = "$env:ProgramData\ServerEye3\logs\Deploy-ServerEye.log"
} else {
	$script:_LogFilePath = $LogFile
}
#endregion

#region Main execution
Check-SEInvalidParameterization
Check-SESupportedOSVersion
Check-PreExistingInstallation
Check-SEDeployPath
Start-ServerEyeInstallation
#endregion