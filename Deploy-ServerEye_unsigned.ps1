<#
	.SYNOPSIS
		This is the (mostly) silent Server-Eye installer.
	
	.DESCRIPTION
		This script will help to install Server-Eye on systems without a full UI or when a full interactive setup is not needed.
		Right now this script can download the current version of the client, install the client, setup an OCC-Connector and setup a Sensorhub.
	
	.PARAMETER Install
		Installs Server-Eye using the .msi files in the current directory.
	
	.PARAMETER Download
		Downloads the newest .msi files for Server-Eye.
	
	.PARAMETER Offline
		Skips all online checks. Use this only if the computer does not have an Internet connection.
	
	.PARAMETER Deploy
		Assigns the connector to a specific customer.
	
	.PARAMETER Customer
		The customer ID to which the computer is added.
	
	.PARAMETER Secret
		The secret to authenticate the connection.
	
	.PARAMETER NodeName
		Optionally, a nodename can be prespecified.
	
	.PARAMETER ParentGuid
		Optionally, this node can be assigned to a specific parent node.
	
	.PARAMETER HubPort
		The port on the sensorhub to connect to.
		Comes preconfigured with the server-eye defaults. Don't change it unless you know what you do.
	
	.PARAMETER ConnectorPort
		The port on the connector to connect to.
		Comes preconfigured with the server-eye defaults. Don't change it unless you know what you do.

	.PARAMETER Silent
		Suppresses all verbosity and all interactive menus.
		Required for unattended installs.

	.PARAMETER SilentOCCConfirmed
		Confirms that the OCC Connector should be installed in silent (unattended) mode.

	.PARAMETER DeployPath
		The folder runtime files (especially downloaded installer files) are stored in.
		By default, the folder the script is in is used. Since this location is not always reliable and sometimes other rules (e.g. Software Restriction Policy) must be honored, this can be configured.
		If the path is not present, the script will try to create it. If this fails, the script will terminate.
	
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
		Creating customers with this is not yet supported.
	
	.LINK
		https://github.com/Server-Eye/se-installer-cli
#>

[CmdletBinding(DefaultParameterSetName = 'None')]
param (
	[switch] $Install,
	[switch] $Download,
	[switch] $Offline,
	[Parameter(ParameterSetName = 'DeployData', Mandatory = $true)]	[ValidateSet("All", "SensorHubOnly")] [string] $Deploy,
	[Parameter(ParameterSetName = 'DeployData', Mandatory = $true)] [string] $Customer,
	[Parameter(ParameterSetName = 'DeployData', Mandatory = $true)] [string] $Secret,
	[Parameter(ParameterSetName = 'DeployData', Mandatory = $false)] [string] $NodeName,
	[Parameter(ParameterSetName = 'DeployData', Mandatory = $false)] [string] $ParentGuid,
	[Parameter(ParameterSetName = 'DeployData', Mandatory = $false)] [string] $HubPort = "11010",
	[Parameter(ParameterSetName = 'DeployData', Mandatory = $false)] [string] $ConnectorPort = "11002",
	[switch] $Silent,
	[switch] $SilentOCCConfirmed,
	[string] $DeployPath = ($MyInvocation.MyCommand.Path)
)

#region Preconfigure some static settings
# Note: Changes in the infrastructure may require reconfiguring these and break scripts deployed without these changes
$SE_version = 402
$SE_occServer = "occ.server-eye.de"
$SE_apiServer = "api.server-eye.de"
$SE_configServer = "config.server-eye.de"
$SE_pushServer = "push.server-eye.de"
$SE_queueServer = "queue.server-eye.de"
$SE_baseDownloadUrl = "https://$SE_occServer/download"
$SE_cloudIdentifier = "se"
$SE_vendor = "Vendor.ServerEye"

# Create OCC Configuration Object
$OCCConfig = New-Object System.Management.Automation.PSObject -Property @{
	ConfFileMAC = ""
	Customer = $Customer
	Secret = $Secret
	NodeName = $NodeName
	ConnectorPort = $ConnectorPort
	ConfigServer = $SE_configServer
	PushServer = $SE_pushServer
	QueueServer = $SE_queueServer
}

# Create Sensorhub Configuration Object
$HubConfig = New-Object System.Management.Automation.PSObject -Property @{
	ConfFileCC = ""
	Customer = $Customer
	Secret = $Secret
	NodeName = $NodeName
	HubPort = $HubPort
	ParentGuid = $ParentGuid
}

# Set the global verbosity level
$script:_SilentOverride = $Silent.ToBool()

# Set the logfile path
$script:_LogFilePath = $env:TEMP + "\ServerEyeInstall.log"
#endregion Preconfigure some static settings

#region Register Eventlog Source
try { New-EventLog -Source 'ServerEyeDeployment' -LogName 'Application' -ErrorAction Stop | Out-Null }
catch { }
#endregion Register Eventlog Source

#region Utility Functions
function Test-64Bit {
	[CmdletBinding()]
	Param (
	
	)
	return ([IntPtr]::Size -eq 8)
}

function Get-ProgramFilesDirectory {
	[CmdletBinding()]
	Param (
	
	)
	
	if ((Test-64Bit) -eq $true)
	{
		Get-Item ${Env:ProgramFiles(x86)} | Select-Object -ExpandProperty FullName
	}
	else
	{
		Get-Item $env:ProgramFiles | Select-Object -ExpandProperty FullName
	}
}

function Write-Header {
	[CmdletBinding()]
	Param (
	
	)
	
	# Suppress all text-output in silent mode
	if ($script:_SilentOverride) { return }
	
	$AsciiArt_ServerEye = @"
  ___                          ___         
 / __| ___ _ ___ _____ _ _ ___| __|  _ ___ 
 \__ \/ -_) '_\ V / -_) '_|___| _| || / -_)
 |___/\___|_|  \_/\___|_|     |___\_, \___|
                                  |__/     
"@
	Write-Host $AsciiArt_ServerEye -ForegroundColor DarkYellow
	Write-Host "                            Version 3.5.$SE_version`n" -ForegroundColor DarkGray
	Write-Host "Welcome to the (mostly) silent Server-Eye installer`n"
}

function Write-SEDeployHelp {
	[CmdletBinding()]
	Param (
	
	)
	
	# Suppress all text-output in silent mode
	if ($script:_SilentOverride) { return }
	
	$me = ".\Deploy-ServerEye.ps1"
	Write-Header
	
    Write-host "This script needs at least one of the following parameters.`n" -ForegroundColor red

    Write-Host "$me -Download"
    Write-Host "Downloads the current version of Server-Eye.`n"

    Write-Host "$me -Install"
    Write-Host "Installs Server-Eye on this computer using the .msi files in this folder.`n"

    Write-Host "$me -Deploy [All|SensorHubOnly] -Customer XXXX -Secret YYYY"
    Write-Host "Sets up Server-Eye on this computer using the given customer and secret key.`n"

    Write-Host "$me -Download -Install -Deploy [All|SensorHubOnly] -Customer XXXX -Secret YYYY"
    Write-Host "Does all of the above.`n"

}

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

function Stop-Execution
{
	[CmdletBinding()]
	Param (
	    [Parameter(Position = 1)] [int]	$Number = 1
	)
	
	exit $Number
}
#endregion Utility Functions

#region Main Functions
function Start-ServerEyeInstallation
{
	[CmdletBinding()]
	Param (
		[bool]
		$Silent = $_SilentOverride,
		
		[string]
		$Deploy,
		
		[bool]
		$Download,
		
		[bool]
		$Install,
		
		[string]
		$OCCServer,
		
		[string]
		$BaseDownloadUrl,
		
		[string]
		$Vendor,
		
		[string]
		$Version,
		
		[string]
		$Path,
		
		$OCCConfig,
	
		$HubConfig
	)
	
	if (-not $Silent) { Write-Header }
	
	#region Really install OCC Connector?
	if ((-not $Silent) -and ($Deploy -eq "All"))
	{
		Write-Log -Message "Ensuring user is sure setting up an OCC Connector is the proper parameterization" -Silent $true
		$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes, this will be the only OCC-Connector.", "This will continue to set up the OCC-Connector."
		$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No, another OCC-Connector is already running.  ", "This will cancel everything and end this installer."
		$unkown = New-Object System.Management.Automation.Host.ChoiceDescription "I &don't know. ", "Pick this if you are unsure."
		$choices = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no, $unkown)
		$caption = ""
		$message = "Only one OCC-Connector should be installed in a network.`nIs this the only OCC-Connector?"
		$result = $Host.UI.PromptForChoice($caption, $message, $choices, 2)
		
		switch ($result)
		{
			0
			{
				Write-Host "Great, let's continue."
				Write-Log "User-Choice: Is sure. Continueing OCC Connector installation" -Silent $true
			}
			1
			{
				Write-Host "Then we better stop here. Use the switch '-Deploy SensorhubOnly' instead."
				Write-Log "User-Choice: Is sure that wrong choice. Interrupting OCC Connector installation" -Silent $true -EventID 1001
				Stop-Execution
			}
			2
			{
				Write-Host "Then we better stop here. Please make sure this is the only OCC-Connector."
				Write-Log "User-Choice: Is unsure that no other OCC Connector is present. Interrupting OCC Connector installation" -Silent $true -EventID 1002
				Stop-Execution
			}
		}
	}
	#endregion Really install OCC Connector?
	
	Write-Log "Starting installation process"
	
	if ($Download)
	{
		Write-Log "Starting Download Routine" -EventID 10
		Download-SEInstallationFiles -BaseDownloadUrl $BaseDownloadUrl -Path $Path -Vendor $Vendor -Version $Version
		Write-Log "Download Routine finished" -EventID 11
	}
	
	if ($Install)
	{
		Write-Log "Starting Installation Routine" -EventID 12
		Install-SEConnector -Path $Path -Vendor $Vendor
		Write-Log "Installation Routine finished" -EventID 13
	}
	
	if ($Deploy -eq "All")
	{
		Write-Log "Starting OCC Connector Configuration" -EventID 16
		$HubConfig.ParentGuid = New-SEOccConnectorConfig -OCCConfig $OCCConfig
		Write-Log "OCC Connector Configuration finished" -EventID 17
		Start-Sleep 5
		Write-Log "Starting Server-Eye Sensorhub Configuration" -EventID 14
		New-SESensorHubConfig -HubConfig $HubConfig
		Write-Log "Server-Eye Sensorhub Configuration finished" -EventID 15
	}
	
	if ($Deploy -eq "SensorhubOnly")
	{
		Write-Log "Starting Server-Eye Sensorhub Configuration" -EventID 14
		New-SESensorHubConfig -HubConfig $HubConfig
		Write-Log "Server-Eye Sensorhub Configuration finished" -EventID 15
	}
	
	Write-Host "Finished!" -ForegroundColor Green
	
	Write-Host "`nPlease visit https://$OCCServer to add Sensors`nHave fun!"
	Write-Log "Installation successfully finished!" -EventID 1 -Silent $true
	Stop-Execution -Number 0
}

function Download-SEInstallationFiles
{
	[CmdletBinding()]
	Param (
		[string]
		$BaseDownloadUrl,
		
		[string]
		$Vendor,
		
		[string]
		$Version,
		
		[string]
		$Path
	)
	
	Write-Log "  downloading ServerEye.Vendor... " -NoNewline
	Download-SEFile "$BaseDownloadUrl/vendor/$Vendor/Vendor.msi" "$Path\Vendor.msi"
	Write-Log "done" -ForegroundColor Green
	
	Write-Log "  downloading ServerEye.Core... " -NoNewline
	Download-SEFile "$BaseDownloadUrl/$Version/ServerEye.msi" "$Path\ServerEye.msi"
	Write-Log "done" -ForegroundColor Green
	
}

function Install-SEConnector
{
	[CmdletBinding()]
	Param (
		[string]
		$Path,
		
		[string]
		$Vendor
	)
	
	Write-Host "  installing $($Vendor)...  " -NoNewline
	if (-not (Test-Path "$Path\Vendor.msi"))
	{
		Write-Host "failed" -ForegroundColor Red
		Write-Host "  The file Vendor.msi is missing." -ForegroundColor Red
		Write-Log -Message "Installation failed, file not found: $Path\Vendor.msi" -EventID 666 -EntryType Error -Silent $true
		Stop-Execution
	}
	
	Start-Process "$Path\Vendor.msi" /passive -Wait
	Write-Host "done" -ForegroundColor Green
	
	Write-Host "  installing ServerEye.Core...  " -NoNewline
	if (-not (Test-Path "$Path\ServerEye.msi"))
	{
		Write-Host "failed" -ForegroundColor Red
		Write-Host "  The file ServerEye.msi is missing." -ForegroundColor Red
		Write-Log -Message "Installation failed, file not found: $Path\ServerEye.msi" -EventID 666 -EntryType Error -Silent $true
		Stop-Execution
	}
	
	Start-Process "$Path\ServerEye.msi" /passive -Wait
	Write-Host "done" -ForegroundColor Green
}

function New-SEOccConnectorConfig
{
	[CmdletBinding()]
	Param (
		$OCCConfig
	)
	try
	{
		Write-Log "  creating OCC-Connector configuration... " -NoNewline
		
		Set-Content -Path $OCCConfig.ConfFileMAC -ErrorAction Stop -Value @"
customer=$($OCCConfig.Customer)
secretKey=$($OCCConfig.Secret)
name=$($OCCConfig.NodeName)
description=
port=$($OCCConfig.ConnectorPort)
	
servletUrl=https://$($OCCConfig.ConfigServer)/
statUrl=https://$($OCCConfig.PushServer)/0.1/
pushUrl=https://$($OCCConfig.PushServer)/
queueUrl=https://$($OCCConfig.QueueServer)/

proxyType=EdS2vHJFGTNVHy4Uq570OQ==|===
proxyUrl=L8aGFOF4VKZiWLRQEb72lA==|===
proxyPort=lo/VY9yIpiJ46BYKnAtljQ==|===
proxyDomain=lo/VY9yIpiJ46BYKnAtljQ==|===
proxyUser=lo/VY9yIpiJ46BYKnAtljQ==|===
proxyPass=lo/VY9yIpiJ46BYKnAtljQ==|===
"@
		Write-Log "done" -ForegroundColor Green
		
		Write-Log "  starting OCC-Connector... " -NoNewline
		
		Set-Service MACService -StartupType Automatic
		Start-Service MACService
		
		Write-Log "done" -ForegroundColor Green
		
		Write-Log "  waiting for OCC-Connector to register with Server-Eye... " -NoNewline
		
		$guid = ""
		$maxWait = 300
		$wait = 0
		while (($guid -eq "") -and ($wait -lt $maxWait))
		{
			$x = Get-Content $confFileMAC | Select-String "guid"
			if ($x.Line.Length -gt 1)
			{
				$splitX = $x.Line.ToString().Split("=")
				$guid = $splitX[1]
			}
			Start-Sleep 1
			$wait++
		}
		
		if ($guid -eq "")
		{
			Write-Log "failed" -ForegroundColor Red
			Write-Log "GUID was not generated in time." -ForegroundColor Red
			Write-Log "Stopping Execution: OCC Connector Configuration failed" -EventID 666 -EntryType Error
			Stop-Execution
		}
		
		Write-Log "done" -ForegroundColor Green
		return $guid
	}
	catch
	{
		Write-Log "Stopping Execution: An error occured during OCC Connector Configuration: $($_.Exception.Message)" -EventID 666 -EntryType Error
		Stop-Execution
	}
}

function New-SESensorHubConfig
{
	[CmdletBinding()]
	Param (
		$HubConfig
	)
	
	try
	{
		Write-Log "  creating Sensorhub configuration... " -NoNewline
		
		Set-Content -Path $HubConfig.ConfFileCC -ErrorAction Stop -Value @"
customer=$($HubConfig.Customer)
secretKey=$($HubConfig.Secret)
name=$($HubConfig.NodeName)
description=
port=$($HubConfig.HubPort)
"@
		if ($HubConfig.ParentGuid)
		{
			"parentGuid=$($HubConfig.ParentGuid)" | Add-Content $confFileCC -ErrorAction Stop
		}
		
		Write-Log "done" -ForegroundColor Green
		
		Write-Log "  starting Sensorhub... " -NoNewline
		
		Set-Service CCService -StartupType Automatic
		Start-Service CCService
		
		Start-Service SE3Recovery
		
		Write-Log "done" -ForegroundColor Green
	}
	catch
	{
		Write-Log "Stopping Execution: An error occured during Sensorhub Configuration: $($_.Exception.Message)" -EventID 666 -EntryType Error
		Stop-Execution
	}
}

function Download-SEFile
{
	[CmdletBinding()]
	Param (
		[string]
		$Url,
		
		[string]
		$TargetFile
	)
	
	try
	{
		$uri = New-Object "System.Uri" "$url"
		$request = [System.Net.HttpWebRequest]::Create($uri)
		$request.set_Timeout(15000) #15 second timeout
		$response = $request.GetResponse()
		$totalLength = [System.Math]::Floor($response.get_ContentLength()/1024)
		$responseStream = $response.GetResponseStream()
		$targetStream = New-Object -TypeName System.IO.FileStream -ArgumentList $targetFile, Create
		$buffer = new-object byte[] 10KB
		$count = $responseStream.Read($buffer, 0, $buffer.length)
		$downloadedBytes = $count
		
		while ($count -gt 0)
		{
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
	}
	catch
	{
		Write-Log -Message "Error downloading: $Url - Interrupting execution" -EventID 666 -EntryType Error
		Stop-Execution
	}
}
#endregion Main Functions

#region Validation
#region Elevation Check
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
	Write-Log -Message "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!" -EntryType Error -EventID 666 -ForegroundColor Red
	Stop-Execution
}
#endregion Elevation Check

#region Invalid parameterization Check
if ($Offline -and $Download)
{
	Write-Log -Message "Invalid Parameter combination: Cannot use offline mode and download at the same time." -EventID 666 -EntryType Error
	Stop-Execution
}

if ((-not $Install) -and (-not $Download) -and (-not $PSBoundParameters.ContainsKey('Deploy')))
{
	# Give guidance
	if (-not $_SilentOverride) { Write-SEDeployHelp }
	Write-Log -Message "Invalid Parameter combination: Must specify at least one of the following parameters: '-Download', '-Install' or '-Deploy'." -EventID 666 -EntryType Error
	Stop-Execution
}

if (($Silent) -and (-not $SilentOCCConfirmed) -and ($Deploy -eq "All"))
{
	Write-Log -Message "Invalid Parameters: Cannot silently install OCC Connector without confirming this with the Parameter '-SilentOCCConfirmed'" -EventID 666 -EntryType Error
	Stop-Execution
}
#endregion Invalid parameterization Check

#region OSVersion Check
If ([environment]::OSVersion.Version.Major -lt 6)
{
	if (-not $script:_SilentOverride)
	{
		Write-Log -Message "Your operating system is not officially supported.`nThe install will most likely work but we can no longer provide support for Server-Eye on this system." -EntryType Warning -EventID 400
		
		$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes, continue without support", "The install will continue, but we cannot help you if something doesn't work."
		$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No, cancel the install", "End the install right now."
		$choices = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
		$caption = ""
		$message = "Do you still want to install Server-Eye on this computer?"
		$result = $Host.UI.PromptForChoice($caption, $message, $choices, 1)
		if ($result -eq 1)
		{
			Write-Log -Message "Execution interrupted by user" -EventID 666 -EntryType Warning -Silent $true
			Stop-Execution
		}
		else { Write-Log -Message "Execution continued by user" -EventID 499 -EntryType Warning -Silent $true }
	}
	else
	{
		Write-Log -Message "Non-Supported OS detected, interrupting Installation" -EventID 666 -EntryType Error
		Stop-Execution
	}
}
#endregion OSVersion Check

#region validate already installed
$progdir = Get-ProgramFilesDirectory
$confDir = "$progdir\Server-Eye\config"
$confFileMAC = "$confDir\se3_mac.conf"
$OCCConfig.ConfFileMAC = $confFileMAC
$confFileCC = "$confDir\se3_cc.conf"
$HubConfig.ConfFileCC = $confFileCC

if ($PSBoundParameters.ContainsKey('Deploy') -and ((Test-Path $confFileMAC) -or (Test-Path $confFileCC)))
{
	Write-Log -Message "Server-Eye is already installed on this system. This script works only on system without a previous Server-Eye installation" -EventID 666 -EntryType Error -ForegroundColor Red
	Stop-Execution
}
#endregion validate already installed

#region validate script version
if (-not $Offline)
{
	try
	{
		Write-Log -Message "Checking for new script verion"
		$r = [System.Net.WebRequest]::Create("$SE_baseDownloadUrl/$SE_cloudIdentifier/currentVersionCli")
		$resp = $r.GetResponse()
		$reqstream = $resp.GetResponseStream()
		$sr = new-object System.IO.StreamReader $reqstream
		$result = $sr.ReadToEnd()
		if ($SE_version -lt $result)
		{
			Write-Log -Message @"
This version of the Server-Eye deployment script is no longer supported.
Please update to the newest version with this command:
Invoke-WebRequest "$($SE_baseDownloadUrl)/$($SE_cloudIdentifier)/Deploy-ServerEye.ps1" -OutFile Deploy-ServerEye.ps1
"@ -EventID 666 -EntryType Error
			Stop-Execution
		}
	}
	# Failing the update-check is not necessarily a game-over. Failure to download the actual packages will terminate script
	catch
	{
		Write-Log -Message "Failed to access version information: $($_.Exception.Message)" -EventID 404 -EntryType Warning
	}
}
#endregion validate script version

#region Validate DeployPath
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
#region Validate DeployPath
#endregion Validation

# Finally launch into the main execution
Start-ServerEyeInstallation -Deploy $Deploy -Download $Download -Install $Install -OCCServer $SE_occServer -BaseDownloadUrl $SE_baseDownloadUrl -Vendor $SE_vendor -Version $SE_version -Path $DeployPath -OCCConfig $OCCConfig -HubConfig $HubConfig
