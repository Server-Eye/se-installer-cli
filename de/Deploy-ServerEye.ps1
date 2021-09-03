<#
	.SYNOPSIS
		This is the (mostly) silent Server-Eye installer.
	
	.DESCRIPTION
		This script will help to install Server-Eye on systems without a full UI or when a full interactive setup is not needed.
		Right now this script can download the current version of the client, install the client, setup an OCC-Connector and setup a Sensorhub.
	
	.PARAMETER Install
		Installs Server-Eye using the .msi files in the current directory.
	
	.PARAMETER Download
		Downloads the .msi files for Server-Eye matching the version number of the script.
	
	.PARAMETER Offline
		Skips all online checks. Use this only if the computer does not have an Internet connection.
		This should really only be used if all else fails. 
	
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
		By default, the folder the script was called from. Since this location is not always reliable and sometimes other rules (e.g. Software Restriction Policy) must be honored, this can be configured.
		If the path is not present, the script will try to create it. If this fails, the script will terminate.

	.PARAMETER ApplyTemplate
		Applies a template after the deploy stage.

	.PARAMETER TemplateId
		The GUID of the template you want to apply to the SensorHub.

	.PARAMETER ApiKey
		Operations such as 'ApplyTemplate' require an API key. 

	.PARAMETER LogFile
		Path including filename. Logs messages also to that file.

	.PARAMETER NoExit
		Using this, the script is no longer terminated with "exit", allowing it to be used as part of a greater script.

	.PARAMETER Proxy
		Proxy seetings if needed
	
	.PARAMETER InstallDotNet
		No longer in Use
	
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
#Requires -Version 2


[CmdletBinding(DefaultParameterSetName ='None')]
param(
	[switch]
	$Install,
	
	[switch]
	$Download,
	
	[switch]
	$Offline,
	
	[ValidateSet("All", "SensorHubOnly")]
	[string]
	$Deploy,
	
	[string]
	$Customer,
	
	[string]
	$Secret,
	
	[string]
	$NodeName,
	
	[string]
	$ParentGuid,
	
	[string]
	$HubPort = "11010",
	
	[string]
	$ConnectorPort = "11002",
	
	[string]
	$TemplateId,
	
	[switch]
	$ApplyTemplate,
	
	[string]
	$ApiKey,
	
	[switch]
	$Silent,
	
	[switch]
	$SilentOCCConfirmed,
	
	[string]
	$DeployPath,
	
	[switch]
    $SkipInstalledCheck,
    
    [switch]
    $SkipLogInstalledCheck,
	
	[string]
	$LogFile,
	
	[switch]
	$NoExit,

	$proxy=$Null,

	[switch]
	$InstallDotNet
)

#region Preconfigure some static settings
# Note: Changes in the infrastructure may require reconfiguring these and break scripts deployed without these changes

$SE_occServer = "occ.server-eye.de"
$SE_apiServer = "api.server-eye.de"
$SE_configServer = "config.server-eye.de"
$SE_pushServer = "push.server-eye.de"
$SE_queueServer = "queue.server-eye.de"
$SE_baseDownloadUrl = "https://$SE_occServer/download"
$SE_cloudIdentifier = "se"
$SE_vendor = "Vendor.ServerEye"
$wc= new-object system.net.webclient
if (!$Proxy){
	$WebProxy = New-Object System.Net.WebProxy($proxy,$true)
	$wc.Proxy = $WebProxy
}elseif (($Proxy.gettype()).Name -eq "WebProxy") {
	$wc.Proxy = $WebProxy
}else {
	$WebProxy = New-Object System.Net.WebProxy($proxy,$true)
	$wc.Proxy = $WebProxy
}

$SE_Version = $wc.DownloadString("$SE_baseDownloadUrl/$SE_cloudIdentifier/currentVersion")

if ($DeployPath -eq "")
{
	$DeployPath = (Resolve-Path .\).Path
}

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

# Create Template Configuration Object
$TemplateConfig = New-Object System.Management.Automation.PSObject -Property @{
	ApplyTemplate = $ApplyTemplate.ToBool()
	TemplateID = $TemplateId
	ApiKey = $ApiKey
}

# Set the global verbosity level
$script:_SilentOverride = $Silent.ToBool()

# Set global exit preference
$script:_NoExit = $NoExit.ToBool()

# Set the logfile path
if ($LogFile -eq "")
{
	$script:_LogFilePath = $env:TEMP + "\ServerEyeInstall.log"
}
else
{
	$script:_LogFilePath = $LogFile
}

#endregion Preconfigure some static settings

#region Register Eventlog Source
try { New-EventLog -Source 'ServerEyeDeployment' -LogName 'Application' -ErrorAction Stop | Out-Null }
catch { }
#endregion Register Eventlog Source

#region Utility Functions
function Test-64Bit
{
	[CmdletBinding()]
	Param (
		
	)
	return ([IntPtr]::Size -eq 8)
}

function Get-ProgramFilesDirectory
{
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

function Write-Header
{
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

function Write-SEDeployHelp
{
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

function Write-Log
{
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
		[Parameter(Position = 1)]
		[int]
		$Number = 1
	)
	
	if ($script:_NoExit) { break main }
	else { exit $Number }
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
		$Version,
		
		[string]
		$Path,
		
		$OCCConfig,
		
		$HubConfig,
		
		$TemplateConfig,

		$proxy,

		$wc
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
		Download-SEInstallationFiles -BaseDownloadUrl $BaseDownloadUrl -Path $Path -Version $Version -proxy $WebProxy
		Write-Log "Download Routine finished" -EventID 11
	}
	
	if ($Install)
	{
		Write-Log "Starting Installation Routine" -EventID 12
		Install-SEConnector -Path $Path
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
	
	if ($TemplateConfig.ApplyTemplate -and $TemplateConfig.TemplateId -ne $NULL)
	{
		Write-Log "Starting to apply template to the SensorHub" -EventID 16
		$guid = Get-SensorHubId -ConfigFileCC $HubConfig.ConfFileCC
		Apply-Template -Guid $guid -ApiKey $TemplateConfig.ApiKey -templateId $TemplateConfig.TemplateId
		Write-Log "Finished to apply template to the SensorHub" -EventID 17
	}
	
	Write-Host "Finished!" -ForegroundColor Green
	
	Write-Host "`nPlease visit https://$OCCServer to add Sensors`nHave fun!"
	Write-Log "Installation successfully finished!" -EventID 1 -Silent $true
	Stop-Execution -Number 0
}

function Apply-Template
{
	[CmdletBinding()]
	Param (
		[string]
		$Guid,
		
		[string]
		$ApiKey,
		
		[string]
		$TemplateId
	)
	$url = "https://api.server-eye.de/2/container/$guid/template/$templateId"
	#$url = "https://api.server-eye.de/2/me"
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("x-api-key", $apiKey)
	
	try
	{
		$WebRequest = [System.Net.WebRequest]::Create($url)
		if (!$Proxy){
			$WebProxy = New-Object System.Net.WebProxy($proxy,$true)
			$WebRequest.Proxy = $WebProxy
		}elseif (($Proxy.gettype()).Name -eq "WebProxy") {
			$WebRequest.Proxy = $WebProxy
		}else {
			$WebProxy = New-Object System.Net.WebProxy($proxy,$true)
			$WebRequest.Proxy = $WebProxy
		}
		$WebRequest.Method = "POST"
		$WebRequest.Headers.Add("x-api-key", $apiKey)
		$WebRequest.ContentType = "application/json"
		$Response = $WebRequest.GetResponse()
		$ResponseStream = $Response.GetResponseStream()
		$ReadStream = New-Object System.IO.StreamReader $ResponseStream
		$Data = $ReadStream.ReadToEnd()
		
	}
	catch
	{
		#$result = $_.Exception.Response.GetResponseStream()
		
		Write-Log "Could not apply template. Error message: $($_.Exception) " -EventID 105 -ForegroundColor Red
		Stop-Execution -Number 1
	}
	
	Write-Log "Template applied" -EventID 106
}

function Get-SensorHubId
{
	[CmdletBinding()]
	Param (
		$ConfigFileCC
	)
	
	$pattern = '\bguid=\b'
	
	$i = 1200
	Write-Log "Waiting for SensorHub GUID (max wait $i seconds)" -EventID 102 -Silent $Silent
	
	while ((-not ($guidFound = Select-String -Quiet -Path $ConfigFileCC -Pattern $pattern)) -and ($i -gt 0))
	{
		Start-Sleep -Seconds 1
		$i--
	}
	
	if ($guidFound)
	{
		$guid = Get-Content $ConfigFileCC | Select-String -Pattern $pattern
		$guid = $guid -replace "guid=", ''
		Write-Log "Found SensorHub with GUID $guid" -EventID 103 -Silent $Silent
		
	}
	else
	{
		Write-Log "Could not get GUID" -ForegroundColor Red -EventID 104 -Silent $Silent
		Stop-Execution -Number 1
	}
	
	
	$guid
}

function Download-SEInstallationFiles
{
	[CmdletBinding()]
	Param (
		[string]
		$BaseDownloadUrl,
		
		[string]
		$Version,
		
		[string]
		$Path,

		$proxy
	)
	
	Write-Log "  getting current Server-Eye version... " -NoNewLine
	Write-Log "  Version is:$version" -NoNewLine
	Write-Log "done" -ForegroundColor Green

	Write-Log "  downloading ServerEye.Setup... " -NoNewline
	Download-SEFile "$BaseDownloadUrl/$SE_cloudIdentifier/ServerEyeSetup.exe" "$Path\ServerEyeSetup.exe" -proxy $proxy
	Write-Log "done" -ForegroundColor Green
	
	Write-Log "  downloading ServerEye.Vendor... " -NoNewline
	Download-SEFile "$BaseDownloadUrl/vendor/$SE_vendor/Vendor.msi" "$Path\Vendor.msi" -proxy $proxy
	Write-Log "done" -ForegroundColor Green
	
	Write-Log "  downloading ServerEye.Core... " -NoNewline
	Download-SEFile "$BaseDownloadUrl/setup/ServerEye.msi" "$Path\ServerEye.msi" -proxy $proxy
	Write-Log "done" -ForegroundColor Green

	
}

function Install-SEConnector
{
	[CmdletBinding()]
	Param (
		[string]
		$Path
	)
	
	Write-Host "  installing Server-eye in Version:$SE_version...  " -NoNewline
	if (-not (Test-Path "$Path\Vendor.msi"))
	{
		Write-Host "failed" -ForegroundColor Red
		Write-Host "  The file Vendor.msi is missing." -ForegroundColor Red
		Write-Log -Message "Installation failed, file not found: $Path\Vendor.msi" -EventID 666 -EntryType Error -Silent $true
		Stop-Execution
	}

	if (-not (Test-Path "$Path\ServerEye.msi"))
	{
		Write-Host "failed" -ForegroundColor Red
		Write-Host "  The file ServerEye.msi is missing." -ForegroundColor Red
		Write-Log -Message "Installation failed, file not found: $Path\ServerEye.msi" -EventID 666 -EntryType Error -Silent $true
		Stop-Execution
	}
	if (-not (Test-Path "$Path\ServerEyeSetup.exe"))
	{
		Write-Host "failed" -ForegroundColor Red
		Write-Host "  The file ServerEyeSetup.exe is missing." -ForegroundColor Red
		Write-Log -Message "Installation failed, file not found: $Path\ServerEyeSetup.exe" -EventID 666 -EntryType Error -Silent $true
		Stop-Execution
	}
	
	Start-Process -Wait -FilePath "$Path\ServerEyeSetup.exe" -ArgumentList "/install /passive /quiet /l C:\kits\se\log.txt"
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
			$x = Get-Content $OCCConfig.ConfFileMAC | Select-String "guid"
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
			"parentGuid=$($HubConfig.ParentGuid)" | Add-Content $HubConfig.ConfFileCC  -ErrorAction Stop
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
		$TargetFile,

		$proxy
	)
	
	try
	{
		
		$uri = New-Object "System.Uri" "$url"
		$request = [System.Net.HttpWebRequest]::Create($uri)
		if (!$Proxy){
			$WebProxy = New-Object System.Net.WebProxy($proxy,$true)
			$request.Proxy = $WebProxy
		}elseif (($Proxy.gettype()).Name -eq "WebProxy") {
			$request.Proxy = $WebProxy
		}else {
			$WebProxy = New-Object System.Net.WebProxy($proxy,$true)
			$request.Proxy = $WebProxy
		}
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
		
		#Write-Log -Message "Error downloading: $Url - Interrupting execution - $($_.Exception.Message)" -EventID 666 -EntryType Error
		Stop-Execution
	}
}
#endregion Main Functions

:main do
{
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
	
	if ((-not $Install) -and (-not $Download) -and (-not $ApplyTemplate) -and (-not $PSBoundParameters.ContainsKey('Deploy')))
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
	$seDataDir = "$env:ProgramData\ServerEye3"
	
	
	if ((-not $SkipInstalledCheck) -and (($Install -or $PSBoundParameters.ContainsKey('Deploy')) -and ((Test-Path $confFileMAC) -or (Test-Path $confFileCC) -or (Test-Path $seDataDir))))
	{   
        if(-not $SkipLogInstalledCheck){
            Write-Log -Message "Server-Eye is or was installed on this system. This script works only on system without a previous Server-Eye installation" -EventID 666 -EntryType Error -ForegroundColor Red    
        }
		
		Stop-Execution
	}
	#endregion validate already installed
	
	#region validate script version
	if (-not $Offline)
	{
		try
		{
			Write-Log -Message "Checking for new script version"
			$result = $wc.DownloadString("$SE_baseDownloadUrl/$SE_cloudIdentifier/currentVersionCli")
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
	#endregion Validate DeployPath
	#endregion Validation
	
	# Finally launch into the main execution
	$params = @{
		Deploy = $Deploy
		Download = $Download
		Install = $Install
		OCCServer = $SE_occServer
		BaseDownloadUrl = $SE_baseDownloadUrl
		Version = $SE_version
		Path = $DeployPath
		OCCConfig = $OCCConfig
		HubConfig = $HubConfig
		TemplateConfig = $TemplateConfig
		proxy = $WebProxy
	}
	Start-ServerEyeInstallation @params
}
while ($false)
# SIG # Begin signature block
# MIIlMgYJKoZIhvcNAQcCoIIlIzCCJR8CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUSlrLdqkow2MBG7noTxV2MZQv
# Xaqggh8aMIIFQDCCBCigAwIBAgIQPoouYh6JSKCXNBstwZR1fDANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVy
# MRAwDgYDVQQHEwdTYWxmb3JkMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxJDAi
# BgNVBAMTG1NlY3RpZ28gUlNBIENvZGUgU2lnbmluZyBDQTAeFw0yMTAzMTUwMDAw
# MDBaFw0yMzAzMTUyMzU5NTlaMIGnMQswCQYDVQQGEwJERTEOMAwGA1UEEQwFNjY1
# NzExETAPBgNVBAgMCFNhYXJsYW5kMRIwEAYDVQQHDAlFcHBlbGJvcm4xGTAXBgNV
# BAkMEEtvc3NtYW5zdHJhc3NlIDcxIjAgBgNVBAoMGUtyw6RtZXIgSVQgU29sdXRp
# b25zIEdtYkgxIjAgBgNVBAMMGUtyw6RtZXIgSVQgU29sdXRpb25zIEdtYkgwggEi
# MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD2ffa5PXcN75tpZewrLUVUmNWe
# GUKMJu49HDdY2hbChjEf3557YCC8Ch6z+JwH1Qw+X52mUFvVOxgiQXXSzVjT4kSf
# zBkW0id0tVhwSWGys8fral5roP5P2MGDYxusC1fsCwjjBWsWtsJBT3IHSI0RfZhO
# QU/NUIAdIqd9gB90wPQ2Bl/xJUosNN6kKTc95NZsL7br/qXK+rz+HP2b9FDJSnCo
# YXmlZQznNabuJmHKkgylu/QsGy5UeDLRH5HIESeb4TYVz2FK8dkNdTANY0LaKazP
# X5APMcevI8TL76CSVtzr3G5zVP6G7zCigjXsf+r0J+cq3X1nV+SBc9N0DTQhAgMB
# AAGjggGQMIIBjDAfBgNVHSMEGDAWgBQO4TqoUzox1Yq+wbutZxoDha00DjAdBgNV
# HQ4EFgQUv6NoXcU4+16wIL34u0CFr2BkBXswDgYDVR0PAQH/BAQDAgeAMAwGA1Ud
# EwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEQYJYIZIAYb4QgEBBAQDAgQQ
# MEoGA1UdIARDMEEwNQYMKwYBBAGyMQECAQMCMCUwIwYIKwYBBQUHAgEWF2h0dHBz
# Oi8vc2VjdGlnby5jb20vQ1BTMAgGBmeBDAEEATBDBgNVHR8EPDA6MDigNqA0hjJo
# dHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29SU0FDb2RlU2lnbmluZ0NBLmNy
# bDBzBggrBgEFBQcBAQRnMGUwPgYIKwYBBQUHMAKGMmh0dHA6Ly9jcnQuc2VjdGln
# by5jb20vU2VjdGlnb1JTQUNvZGVTaWduaW5nQ0EuY3J0MCMGCCsGAQUFBzABhhdo
# dHRwOi8vb2NzcC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAKiH0uKG9
# MA1QtQkFdKpaP5pzussbm2FbgmwZiMeimTPKRNjmXm1XFYdbfNp6mHZrpRR7PO/B
# d+YgotlZbPHkzYa6bTSxqfiUwA+W4VdcfaGww9Nk7KoEsrJjKKmr9LD/LyCXbB7k
# f9dsM8vRw7fIp77x1owXiGvGKu263qEnqZwD5/fZbdKtkGAlhxnn+7o96UUjMg/h
# 3n9MxEUXArjkWSafpiQ3LUkcDEPDM1pTaYNaBjOKkKp7SFRA0XbnoBjuSBdZ9w7c
# f5UqIdlli/tTzvGjbJq70CuF8OktlRFmbwIqbvTHQrp8rNOcB0ZBtkAkoAmOEv2d
# o7MC2wPQExjMSTCCBd4wggPGoAMCAQICEAH9bTD8o8pRqBu8ZA41Ay0wDQYJKoZI
# hvcNAQEMBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5MRQw
# EgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBOZXR3
# b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgUlNBIENlcnRpZmljYXRpb24gQXV0aG9y
# aXR5MB4XDTEwMDIwMTAwMDAwMFoXDTM4MDExODIzNTk1OVowgYgxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEe
# MBwGA1UEChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1
# c3QgUlNBIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAgBJlFzYOw9sIs9CsVw127c0n00ytUINh4qogTQktZAnc
# zomfzD2p7PbPwdzx07HWezcoEStH2jnGvDoZtF+mvX2do2NCtnbyqTsrkfjib9Ds
# FiCQCT7i6HTJGLSR1GJk23+jBvGIGGqQIjy8/hPwhxR79uQfjtTkUcYRZ0YIUcuG
# FFQ/vDP+fmyc/xadGL1RjjWmp2bIcmfbIWax1Jt4A8BQOujM8Ny8nkz+rwWWNR9X
# Wrf/zvk9tyy29lTdyOcSOk2uTIq3XJq0tyA9yn8iNK5+O2hmAUTnAU5GU5szYPeU
# vlM3kHND8zLDU+/bqv50TmnHa4xgk97Exwzf4TKuzJM7UXiVZ4vuPVb+DNBpDxsP
# 8yUmazNt925H+nND5X4OpWaxKXwyhGNVicQNwZNUMBkTrNN9N6frXTpsNVzbQdcS
# 2qlJC9/YgIoJk2KOtWbPJYjNhLixP6Q5D9kCnusSTJV882sFqV4Wg8y4Z+LoE53M
# W4LTTLPtW//e5XOsIzstAL81VXQJSdhJWBp/kjbmUZIO8yZ9HE0XvMnsQybQv0Ff
# QKlERPSZ51eHnlAfV1SoPv10Yy+xUGUJ5lhCLkMaTLTwJUdZ+gQek9QmRkpQgbLe
# vni3/GcV4clXhB4PY9bpYrrWX1Uu6lzGKAgEJTm4Diup8kyXHAc/DVL17e8vgg8C
# AwEAAaNCMEAwHQYDVR0OBBYEFFN5v1qqK0rPVIDh2JvAnfKyA2bLMA4GA1UdDwEB
# /wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDAUAA4ICAQBc1HwN
# z/cBfUGZZQxzxVKfy/jPmQZ/G9pDFZ+eAlVXlhTxUjwnh5Qo7R86ATeidvxTUMCE
# m8ZrTrqMIU+ijlVikfNpFdi8iOPEqgv976jpS1UqBiBtVXgpGe5fMFxLJBFV/ySa
# bl4qK+4LTZ9/9wE4lBSVQwcJ+2Cp7hyrEoygml6nmGpZbYs/CPvI0UWvGBVkkBIP
# cyguxeIkTvxY7PD0Rf4is+svjtLZRWEFwZdvqHZyj4uMNq+/DQXOcY3mpm8fbKZx
# YsXY0INyDPFnEYkMnBNMcjTfvNVx36px3eG5bIw8El1l2r1XErZDa//l3k1mEVHP
# ma7sF7bocZGM3kn+3TVxohUnlBzPYeMmu2+jZyUhXebdHQsuaBs7gq/sg2eF1JhR
# dLG5mYCJ/394GVx5SmAukkCuTDcqLMnHYsgOXfc2W8rgJSUBtN0aB5x3AD/Q3NXs
# PdT6uz/MhdZvf6kt37kC9/WXmrU12sNnsIdKqSieI47/XCdr4bBP8wfuAC7UWYfL
# UkGV6vRH1+5kQVV8jVkCld1incK57loodISlm7eQxwwH3/WJNnQy1ijBsLAL4JxM
# wxzW/ONptUdGgS+igqvTY0RwxI3/LTO6rY97tXCIrj4Zz0Ao2PzIkLtdmSL1UuZY
# xR+IMUPuiB3Xxo48Q2odpxjefT0W8WL5ypCo/TCCBfUwggPdoAMCAQICEB2iSDBv
# myYY0ILgln0z02owDQYJKoZIhvcNAQEMBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpOZXcgSmVyc2V5MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UEChMV
# VGhlIFVTRVJUUlVTVCBOZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgUlNBIENl
# cnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTE4MTEwMjAwMDAwMFoXDTMwMTIzMTIz
# NTk1OVowfDELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3Rl
# cjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSQw
# IgYDVQQDExtTZWN0aWdvIFJTQSBDb2RlIFNpZ25pbmcgQ0EwggEiMA0GCSqGSIb3
# DQEBAQUAA4IBDwAwggEKAoIBAQCGIo0yhXoYn0nwli9jCB4t3HyfFM/jJrYlZilA
# hlRGdDFixRDtsocnppnLlTDAVvWkdcapDlBipVGREGrgS2Ku/fD4GKyn/+4uMyD6
# DBmJqGx7rQDDYaHcaWVtH24nlteXUYam9CflfGqLlR5bYNV+1xaSnAAvaPeX7Wpy
# vjg7Y96Pv25MQV0SIAhZ6DnNj9LWzwa0VwW2TqE+V2sfmLzEYtYbC43HZhtKn52B
# xHJAteJf7wtF/6POF6YtVbC3sLxUap28jVZTxvC6eVBJLPcDuf4vZTXyIuosB69G
# 2flGHNyMfHEo8/6nxhTdVZFuihEN3wYklX0Pp6F8OtqGNWHTAgMBAAGjggFkMIIB
# YDAfBgNVHSMEGDAWgBRTeb9aqitKz1SA4dibwJ3ysgNmyzAdBgNVHQ4EFgQUDuE6
# qFM6MdWKvsG7rWcaA4WtNA4wDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwHQYDVR0lBBYwFAYIKwYBBQUHAwMGCCsGAQUFBwMIMBEGA1UdIAQKMAgw
# BgYEVR0gADBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLnVzZXJ0cnVzdC5j
# b20vVVNFUlRydXN0UlNBQ2VydGlmaWNhdGlvbkF1dGhvcml0eS5jcmwwdgYIKwYB
# BQUHAQEEajBoMD8GCCsGAQUFBzAChjNodHRwOi8vY3J0LnVzZXJ0cnVzdC5jb20v
# VVNFUlRydXN0UlNBQWRkVHJ1c3RDQS5jcnQwJQYIKwYBBQUHMAGGGWh0dHA6Ly9v
# Y3NwLnVzZXJ0cnVzdC5jb20wDQYJKoZIhvcNAQEMBQADggIBAE1jUO1HNEphpNve
# aiqMm/EAAB4dYns61zLC9rPgY7P7YQCImhttEAcET7646ol4IusPRuzzRl5ARokS
# 9At3WpwqQTr81vTr5/cVlTPDoYMot94v5JT3hTODLUpASL+awk9KsY8k9LOBN9O3
# ZLCmI2pZaFJCX/8E6+F0ZXkI9amT3mtxQJmWunjxucjiwwgWsatjWsgVgG10Xkp1
# fqW4w2y1z99KeYdcx0BNYzX2MNPPtQoOCwR/oEuuu6Ol0IQAkz5TXTSlADVpbL6f
# ICUQDRn7UJBhvjmPeo5N9p8OHv4HURJmgyYZSJXOSsnBf/M6BZv5b9+If8AjntIe
# Q3pFMcGcTanwWbJZGehqjSkEAnd8S0vNcL46slVaeD68u28DECV3FTSK+TbMQ5Lk
# uk/xYpMoJVcp+1EZx6ElQGqEV8aynbG8HArafGd+fS7pKEwYfsR7MUFxmksp7As9
# V1DSyt39ngVR5UR43QHesXWYDVQk/fBO4+L4g71yuss9Ou7wXheSaG3IYfmm8SoK
# C6W59J7umDIFhZ7r+YMp08Ysfb06dy6LN0KgaoLtO0qqlBCk4Q34F8W2WnkzGJLj
# tXX4oemOCiUe5B7xn1qHI/+fpFGe+zmAEc3btcSnqIBv5VPU4OOiwtJbGvoyJi1q
# V3AcPKRYLqPzW0sH3DJZ84enGm1YMIIG7DCCBNSgAwIBAgIQMA9vrN1mmHR8qUY2
# p3gtuTANBgkqhkiG9w0BAQwFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5l
# dyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNF
# UlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNh
# dGlvbiBBdXRob3JpdHkwHhcNMTkwNTAyMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjB9
# MQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYD
# VQQHEwdTYWxmb3JkMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxJTAjBgNVBAMT
# HFNlY3RpZ28gUlNBIFRpbWUgU3RhbXBpbmcgQ0EwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQDIGwGv2Sx+iJl9AZg/IJC9nIAhVJO5z6A+U++zWsB21hoE
# pc5Hg7XrxMxJNMvzRWW5+adkFiYJ+9UyUnkuyWPCE5u2hj8BBZJmbyGr1XEQeYf0
# RirNxFrJ29ddSU1yVg/cyeNTmDoqHvzOWEnTv/M5u7mkI0Ks0BXDf56iXNc48Ray
# cNOjxN+zxXKsLgp3/A2UUrf8H5VzJD0BKLwPDU+zkQGObp0ndVXRFzs0IXuXAZSv
# f4DP0REKV4TJf1bgvUacgr6Unb+0ILBgfrhN9Q0/29DqhYyKVnHRLZRMyIw80xSi
# nL0m/9NTIMdgaZtYClT0Bef9Maz5yIUXx7gpGaQpL0bj3duRX58/Nj4OMGcrRrc1
# r5a+2kxgzKi7nw0U1BjEMJh0giHPYla1IXMSHv2qyghYh3ekFesZVf/QOVQtJu5F
# GjpvzdeE8NfwKMVPZIMC1Pvi3vG8Aij0bdonigbSlofe6GsO8Ft96XZpkyAcSpcs
# dxkrk5WYnJee647BeFbGRCXfBhKaBi2fA179g6JTZ8qx+o2hZMmIklnLqEbAyfKm
# /31X2xJ2+opBJNQb/HKlFKLUrUMcpEmLQTkUAx4p+hulIq6lw02C0I3aa7fb9xhA
# V3PwcaP7Sn1FNsH3jYL6uckNU4B9+rY5WDLvbxhQiddPnTO9GrWdod6VQXqngwID
# AQABo4IBWjCCAVYwHwYDVR0jBBgwFoAUU3m/WqorSs9UgOHYm8Cd8rIDZsswHQYD
# VR0OBBYEFBqh+GEZIA/DQXdFKI7RNV8GEgRVMA4GA1UdDwEB/wQEAwIBhjASBgNV
# HRMBAf8ECDAGAQH/AgEAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBEGA1UdIAQKMAgw
# BgYEVR0gADBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLnVzZXJ0cnVzdC5j
# b20vVVNFUlRydXN0UlNBQ2VydGlmaWNhdGlvbkF1dGhvcml0eS5jcmwwdgYIKwYB
# BQUHAQEEajBoMD8GCCsGAQUFBzAChjNodHRwOi8vY3J0LnVzZXJ0cnVzdC5jb20v
# VVNFUlRydXN0UlNBQWRkVHJ1c3RDQS5jcnQwJQYIKwYBBQUHMAGGGWh0dHA6Ly9v
# Y3NwLnVzZXJ0cnVzdC5jb20wDQYJKoZIhvcNAQEMBQADggIBAG1UgaUzXRbhtVOB
# kXXfA3oyCy0lhBGysNsqfSoF9bw7J/RaoLlJWZApbGHLtVDb4n35nwDvQMOt0+Lk
# VvlYQc/xQuUQff+wdB+PxlwJ+TNe6qAcJlhc87QRD9XVw+K81Vh4v0h24URnbY+w
# QxAPjeT5OGK/EwHFhaNMxcyyUzCVpNb0llYIuM1cfwGWvnJSajtCN3wWeDmTk5Sb
# sdyybUFtZ83Jb5A9f0VywRsj1sJVhGbks8VmBvbz1kteraMrQoohkv6ob1olcGKB
# c2NeoLvY3NdK0z2vgwY4Eh0khy3k/ALWPncEvAQ2ted3y5wujSMYuaPCRx3wXdah
# c1cFaJqnyTdlHb7qvNhCg0MFpYumCf/RoZSmTqo9CfUFbLfSZFrYKiLCS53xOV5M
# 3kg9mzSWmglfjv33sVKRzj+J9hyhtal1H3G/W0NdZT1QgW6r8NDT/LKzH7aZlib0
# PHmLXGTMze4nmuWgwAxyh8FuTVrTHurwROYybxzrF06Uw3hlIDsPQaof6aFBnf6x
# uKBlKjTg3qj5PObBMLvAoGMs/FwWAKjQxH/qEZ0eBsambTJdtDgJK0kHqv3sMNrx
# py/Pt/360KOE2See+wFmd7lWEOEgbsausfm2usg1XTN2jvF8IAwqd661ogKGuinu
# tFoAsYyr4/kKyVRd1LlqdJ69SK6YMIIHBzCCBO+gAwIBAgIRAIx3oACP9NGwxj2f
# OkiDjWswDQYJKoZIhvcNAQEMBQAwfTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdy
# ZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2Vj
# dGlnbyBMaW1pdGVkMSUwIwYDVQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0YW1waW5n
# IENBMB4XDTIwMTAyMzAwMDAwMFoXDTMyMDEyMjIzNTk1OVowgYQxCzAJBgNVBAYT
# AkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZv
# cmQxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UEAwwjU2VjdGlnbyBS
# U0EgVGltZSBTdGFtcGluZyBTaWduZXIgIzIwggIiMA0GCSqGSIb3DQEBAQUAA4IC
# DwAwggIKAoICAQCRh0ssi8HxHqCe0wfGAcpSsL55eV0JZgYtLzV9u8D7J9pCalkb
# JUzq70DWmn4yyGqBfbRcPlYQgTU6IjaM+/ggKYesdNAbYrw/ZIcCX+/FgO8GHNxe
# TpOHuJreTAdOhcxwxQ177MPZ45fpyxnbVkVs7ksgbMk+bP3wm/Eo+JGZqvxawZqC
# IDq37+fWuCVJwjkbh4E5y8O3Os2fUAQfGpmkgAJNHQWoVdNtUoCD5m5IpV/BiVhg
# iu/xrM2HYxiOdMuEh0FpY4G89h+qfNfBQc6tq3aLIIDULZUHjcf1CxcemuXWmWlR
# x06mnSlv53mTDTJjU67MximKIMFgxvICLMT5yCLf+SeCoYNRwrzJghohhLKXvNSv
# RByWgiKVKoVUrvH9Pkl0dPyOrj+lcvTDWgGqUKWLdpUbZuvv2t+ULtka60wnfUwF
# 9/gjXcRXyCYFevyBI19UCTgqYtWqyt/tz1OrH/ZEnNWZWcVWZFv3jlIPZvyYP0QG
# E2Ru6eEVYFClsezPuOjJC77FhPfdCp3avClsPVbtv3hntlvIXhQcua+ELXei9zmV
# N29OfxzGPATWMcV+7z3oUX5xrSR0Gyzc+Xyq78J2SWhi1Yv1A9++fY4PNnVGW5N2
# xIPugr4srjcS8bxWw+StQ8O3ZpZelDL6oPariVD6zqDzCIEa0USnzPe4MQIDAQAB
# o4IBeDCCAXQwHwYDVR0jBBgwFoAUGqH4YRkgD8NBd0UojtE1XwYSBFUwHQYDVR0O
# BBYEFGl1N3u7nTVCTr9X05rbnwHRrt7QMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMB
# Af8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMEAGA1UdIAQ5MDcwNQYMKwYB
# BAGyMQECAQMIMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2VjdGlnby5jb20vQ1BT
# MEQGA1UdHwQ9MDswOaA3oDWGM2h0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGln
# b1JTQVRpbWVTdGFtcGluZ0NBLmNybDB0BggrBgEFBQcBAQRoMGYwPwYIKwYBBQUH
# MAKGM2h0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb1JTQVRpbWVTdGFtcGlu
# Z0NBLmNydDAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wDQYJ
# KoZIhvcNAQEMBQADggIBAEoDeJBCM+x7GoMJNjOYVbudQAYwa0Vq8ZQOGVD/WyVe
# O+E5xFu66ZWQNze93/tk7OWCt5XMV1VwS070qIfdIoWmV7u4ISfUoCoxlIoHIZ6K
# vaca9QIVy0RQmYzsProDd6aCApDCLpOpviE0dWO54C0PzwE3y42i+rhamq6hep4T
# kxlVjwmQLt/qiBcW62nW4SW9RQiXgNdUIChPynuzs6XSALBgNGXE48XDpeS6hap6
# adt1pD55aJo2i0OuNtRhcjwOhWINoF5w22QvAcfBoccklKOyPG6yXqLQ+qjRuCUc
# FubA1X9oGsRlKTUqLYi86q501oLnwIi44U948FzKwEBcwp/VMhws2jysNvcGUpqj
# QDAXsCkWmcmqt4hJ9+gLJTO1P22vn18KVt8SscPuzpF36CAT6Vwkx+pEC0rmE4Qc
# TesNtbiGoDCni6GftCzMwBYjyZHlQgNLgM7kTeYqAT7AXoWgJKEXQNXb2+eYEKTx
# 6hkbgFT6R4nomIGpdcAO39BolHmhoJ6OtrdCZsvZ2WsvTdjePjIeIOTsnE1CjZ3H
# M5mCN0TUJikmQI54L7nu+i/x8Y/+ULh43RSW3hwOcLAqhWqxbGjpKuQQK24h/dN8
# nTfkKgbWw/HXaONPB3mBCBP+smRe6bE85tB4I7IJLOImYr87qZdRzMdEMoGyr8/f
# MYIFgjCCBX4CAQEwgZAwfDELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIg
# TWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBM
# aW1pdGVkMSQwIgYDVQQDExtTZWN0aWdvIFJTQSBDb2RlIFNpZ25pbmcgQ0ECED6K
# LmIeiUiglzQbLcGUdXwwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwxCjAIoAKA
# AKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFDffxhhYaG2svR4G8Pf/LBRk
# euJmMA0GCSqGSIb3DQEBAQUABIIBANPUr+oA/Cwam02evVxmhvXmR61K72Bto4gI
# uFeWKpeGmBPwm4vOH+peRb39Q7xwK5jGF/9HsbMahgnC2SrK4JuNwhAIDR6sNL/I
# 7/oKkpO/xPXXNfbHXK6cThULhnsJ2U5ETRGemyAh8vrnji1yS4Kf/RP7r2AgQdy8
# c0OU4GW+FHhiseOac4hH0oSFHj9FipxtbX0zTGF21NS5mQ07aHSspCzDxbJzt6U8
# pwaiNK594moTfeJgtaS7UkYIHl05KnY41wspLg0d3O+21nw1jhZ13NIfp3tw4zQG
# pym8AVfO/udWe+TTaY3/g3vS1+oCxZ8Jd7dlEEOuWGvoYp3GpfKhggNMMIIDSAYJ
# KoZIhvcNAQkGMYIDOTCCAzUCAQEwgZIwfTELMAkGA1UEBhMCR0IxGzAZBgNVBAgT
# EkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMP
# U2VjdGlnbyBMaW1pdGVkMSUwIwYDVQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0YW1w
# aW5nIENBAhEAjHegAI/00bDGPZ86SIONazANBglghkgBZQMEAgIFAKB5MBgGCSqG
# SIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIxMDkwMzEyMDQx
# M1owPwYJKoZIhvcNAQkEMTIEMBttxeV4e6Ui8hW8dRJAq5xiJyFYnacDQ0APqCV3
# Pr/YZZr1PUDhK/b20IffJ+VSEzANBgkqhkiG9w0BAQEFAASCAgA1UUtPcYS7k8a4
# noLd60KBlrsjxlWAyODGfuy/ARfSYbzU9hWod+/c2vPgeP/ZopydvrkoCb7kOeZv
# AXcXKRf92RdLgqpbDqK+YIIaTI/EvTSVoIYkY4ktxNgJyv3oRVagD4oVA5MHwJVV
# 2IYGDNbHDFO6cpjEmuFKm1xJZNkK6IrRwYtbe+W5YsYcPCXY+mG3g3d4YvKq9b45
# J+8Qe9Mqw6eLj84OVu0WwYjl45BsHhqNipL8FP3NxWu3kmuhtZUdYugfFj/PtPB0
# IoTxMXubRdWSxauW6QjEI+kxkO1rpYqZILNLuuZunEqnz1qvJeDgm2XcORBmE11R
# elkQyPPLcrFIPfw6NNAEGPb82y1rn6VA3dKXysaJFfC7PvCTXwTR4e7acmcXEigl
# t+5NLvJAwuPe+3h+zebyD1tRuGCJ07ZL48JVrmlgTJM9k6YM1IfVLqd1fHch3wEL
# QKBQKPGaSiC2aZucksIkxL7NOG1sghA0WA2Io3PSXfo7qq1xmOtYQ5/CK1GlGxgJ
# HYoza7NvblNcCJreYI44mfEyq3eYcyGilkRteZE1Gs0VKnDaIn2464mdng7B/AMZ
# D59ZJ0yOZcyZuL+NVeteTK20L7XyjjIp45HTay/j9jZq8pt2R3yCMlxniMy8l7w6
# GnwFwPreYbftXwTO8p7GcCrslo2DRw==
# SIG # End signature block
