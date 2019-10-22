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
	
	if ($TemplateConfig.ApplyTemplate)
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
	
	$i = 180
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
# MIIknAYJKoZIhvcNAQcCoIIkjTCCJIkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU3kJHurrDz+VZWsFxmLaE9pEc
# bwKggh+oMIIEhDCCA2ygAwIBAgIQQhrylAmEGR9SCkvGJCanSzANBgkqhkiG9w0B
# AQUFADBvMQswCQYDVQQGEwJTRTEUMBIGA1UEChMLQWRkVHJ1c3QgQUIxJjAkBgNV
# BAsTHUFkZFRydXN0IEV4dGVybmFsIFRUUCBOZXR3b3JrMSIwIAYDVQQDExlBZGRU
# cnVzdCBFeHRlcm5hbCBDQSBSb290MB4XDTA1MDYwNzA4MDkxMFoXDTIwMDUzMDEw
# NDgzOFowgZUxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJVVDEXMBUGA1UEBxMOU2Fs
# dCBMYWtlIENpdHkxHjAcBgNVBAoTFVRoZSBVU0VSVFJVU1QgTmV0d29yazEhMB8G
# A1UECxMYaHR0cDovL3d3dy51c2VydHJ1c3QuY29tMR0wGwYDVQQDExRVVE4tVVNF
# UkZpcnN0LU9iamVjdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM6q
# gT+jo2F4qjEAVZURnicPHxzfOpuCaDDASmEd8S8O+r5596Uj71VRloTN2+O5bj4x
# 2AogZ8f02b+U60cEPgLOKqJdhwQJ9jCdGIqXsqoc/EHSoTbL+z2RuufZcDX65OeQ
# w5ujm9M89RKZd7G3CeBo5hy485RjiGpq/gt2yb70IuRnuasaXnfBhQfdDWy/7gbH
# d2pBnqcP1/vulBe3/IW+pKvEHDHd17bR5PDv3xaPslKT16HUiaEHLr/hARJCHhrh
# 2JU022R5KP+6LhHC5ehbkkj7RwvCbNqtMoNB86XlQXD9ZZBt+vpRxPm9lisZBCzT
# bafc8H9vg2XiaquHhnUCAwEAAaOB9DCB8TAfBgNVHSMEGDAWgBStvZh6NLQm9/rE
# JlTvA73gJMtUGjAdBgNVHQ4EFgQU2u1kdBScFDyr3ZmpvVsoTYs8ydgwDgYDVR0P
# AQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wEQYDVR0gBAowCDAGBgRVHSAAMEQG
# A1UdHwQ9MDswOaA3oDWGM2h0dHA6Ly9jcmwudXNlcnRydXN0LmNvbS9BZGRUcnVz
# dEV4dGVybmFsQ0FSb290LmNybDA1BggrBgEFBQcBAQQpMCcwJQYIKwYBBQUHMAGG
# GWh0dHA6Ly9vY3NwLnVzZXJ0cnVzdC5jb20wDQYJKoZIhvcNAQEFBQADggEBAE1C
# L6bBiusHgJBYRoz4GTlmKjxaLG3P1NmHVY15CxKIe0CP1cf4S41VFmOtt1fcOyu9
# 08FPHgOHS0Sb4+JARSbzJkkraoTxVHrUQtr802q7Zn7Knurpu9wHx8OSToM8gUmf
# ktUyCepJLqERcZo20sVOaLbLDhslFq9s3l122B9ysZMmhhfbGN6vRenf+5ivFBjt
# pF72iZRF8FUESt3/J90GSkD2tLzx5A+ZArv9XQ4uKMG+O18aP5cQhLwWPtijnGMd
# ZstcX9o+8w8KCTUi29vAPwD55g1dZ9H9oB4DK9lA977Mh2ZUgKajuPUZYtXSJrGY
# Ju6ay0SnRVqBlRUa9VEwggTmMIIDzqADAgECAhBiXE2QjNVC+6supXM/8VQZMA0G
# CSqGSIb3DQEBBQUAMIGVMQswCQYDVQQGEwJVUzELMAkGA1UECBMCVVQxFzAVBgNV
# BAcTDlNhbHQgTGFrZSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdv
# cmsxITAfBgNVBAsTGGh0dHA6Ly93d3cudXNlcnRydXN0LmNvbTEdMBsGA1UEAxMU
# VVROLVVTRVJGaXJzdC1PYmplY3QwHhcNMTEwNDI3MDAwMDAwWhcNMjAwNTMwMTA0
# ODM4WjB6MQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVy
# MRAwDgYDVQQHEwdTYWxmb3JkMRowGAYDVQQKExFDT01PRE8gQ0EgTGltaXRlZDEg
# MB4GA1UEAxMXQ09NT0RPIFRpbWUgU3RhbXBpbmcgQ0EwggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQCqgvGEqVvYcbXSXSvt9BMgDPmb6dGPdF5u7uspSNjI
# vizrCmFgzL2SjXzddLsKnmhOqnUkcyeuN/MagqVtuMgJRkx+oYPp4gNgpCEQJ0Ca
# WeFtrz6CryFpWW1jzM6x9haaeYOXOh0Mr8l90U7Yw0ahpZiqYM5V1BIR8zsLbMaI
# upUu76BGRTl8rOnjrehXl1/++8IJjf6OmqU/WUb8xy1dhIfwb1gmw/BC/FXeZb5n
# OGOzEbGhJe2pm75I30x3wKoZC7b9So8seVWx/llaWm1VixxD9rFVcimJTUA/vn9J
# AV08m1wI+8ridRUFk50IYv+6Dduq+LW/EDLKcuoIJs0ZAgMBAAGjggFKMIIBRjAf
# BgNVHSMEGDAWgBTa7WR0FJwUPKvdmam9WyhNizzJ2DAdBgNVHQ4EFgQUZCKGtkqJ
# yQQP0ARYkiuzbj0eJ2wwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8C
# AQAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwEQYDVR0gBAowCDAGBgRVHSAAMEIGA1Ud
# HwQ7MDkwN6A1oDOGMWh0dHA6Ly9jcmwudXNlcnRydXN0LmNvbS9VVE4tVVNFUkZp
# cnN0LU9iamVjdC5jcmwwdAYIKwYBBQUHAQEEaDBmMD0GCCsGAQUFBzAChjFodHRw
# Oi8vY3J0LnVzZXJ0cnVzdC5jb20vVVROQWRkVHJ1c3RPYmplY3RfQ0EuY3J0MCUG
# CCsGAQUFBzABhhlodHRwOi8vb2NzcC51c2VydHJ1c3QuY29tMA0GCSqGSIb3DQEB
# BQUAA4IBAQARyT3hBeg7ZazJdDEDt9qDOMaSuv3N+Ntjm30ekKSYyNlYaDS18Ash
# U55ZRv1jhd/+R6pw5D9eCJUoXxTx/SKucOS38bC2Vp+xZ7hog16oYNuYOfbcSV4T
# p5BnS+Nu5+vwQ8fQL33/llqnA9abVKAj06XCoI75T9GyBiH+IV0njKCv2bBS7vzI
# 7bec8ckmONalMu1Il5RePeA9NbSwyVivx1j/YnQWkmRB2sqo64sDvcFOrh+RMrjh
# JDt77RRoCYaWKMk7yWwowiVp9UphreAn+FOndRWwUTGw8UH/PlomHmB+4uNqOZrE
# 6u4/5rITP1UDBE0LkHLU6/u8h5BRsjgZMIIE/jCCA+agAwIBAgIQK3PbdGMRTFpb
# MkryMFdySTANBgkqhkiG9w0BAQUFADB6MQswCQYDVQQGEwJHQjEbMBkGA1UECBMS
# R3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRowGAYDVQQKExFD
# T01PRE8gQ0EgTGltaXRlZDEgMB4GA1UEAxMXQ09NT0RPIFRpbWUgU3RhbXBpbmcg
# Q0EwHhcNMTkwNTAyMDAwMDAwWhcNMjAwNTMwMTA0ODM4WjCBgzELMAkGA1UEBhMC
# R0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBwwHU2FsZm9y
# ZDEYMBYGA1UECgwPU2VjdGlnbyBMaW1pdGVkMSswKQYDVQQDDCJTZWN0aWdvIFNI
# QS0xIFRpbWUgU3RhbXBpbmcgU2lnbmVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
# MIIBCgKCAQEAv1I2gjrcdDcNeNV/FlAZZu26GpnRYziaDGayQNungFC/aS42Lwpn
# P0ChSopjNZvQGcx0qhcZkSu1VSAZ+8AaOm3KOZuC8rqVoRrYNMe4iXtwiHBRZmns
# d/7GlHJ6zyWB7TSCmt8IFTcxtG2uHL8Y1Q3P/rXhxPuxR3Hp+u5jkezx7M5ZBBF8
# rgtgU+oq874vAg/QTF0xEy8eaQ+Fm0WWwo0Si2euH69pqwaWgQDfkXyVHOaeGWTf
# dshgRC9J449/YGpFORNEIaW6+5H6QUDtTQK0S3/f4uA9uKrzGthBg49/M+1BBuJ9
# nj9ThI0o2t12xr33jh44zcDLYCQD3npMqwIDAQABo4IBdDCCAXAwHwYDVR0jBBgw
# FoAUZCKGtkqJyQQP0ARYkiuzbj0eJ2wwHQYDVR0OBBYEFK7u2WC6XvUsARL9jo2y
# VXI1Rm/xMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQM
# MAoGCCsGAQUFBwMIMEAGA1UdIAQ5MDcwNQYMKwYBBAGyMQECAQMIMCUwIwYIKwYB
# BQUHAgEWF2h0dHBzOi8vc2VjdGlnby5jb20vQ1BTMEIGA1UdHwQ7MDkwN6A1oDOG
# MWh0dHA6Ly9jcmwuc2VjdGlnby5jb20vQ09NT0RPVGltZVN0YW1waW5nQ0FfMi5j
# cmwwcgYIKwYBBQUHAQEEZjBkMD0GCCsGAQUFBzAChjFodHRwOi8vY3J0LnNlY3Rp
# Z28uY29tL0NPTU9ET1RpbWVTdGFtcGluZ0NBXzIuY3J0MCMGCCsGAQUFBzABhhdo
# dHRwOi8vb2NzcC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQUFAAOCAQEAen+pStKw
# pBwdDZ0tXMauWt2PRR3wnlyQ9l6scP7T2c3kGaQKQ3VgaoOkw5mEIDG61v5MzxP4
# EPdUCX7q3NIuedcHTFS3tcmdsvDyHiQU0JzHyGeqC2K3tPEG5OfkIUsZMpk0uRlh
# dwozkGdswIhKkvWhQwHzrqJvyZW9ljj3g/etfCgf8zjfjiHIcWhTLcuuquIwF4Mi
# KRi14YyJ6274fji7kE+5Xwc0EmuX1eY7kb4AFyFu4m38UnnvgSW6zxPQ+90rzYG2
# V4lO8N3zC0o0yoX/CLmWX+sRE+DhxQOtVxzhXZIGvhvIPD+lIJ9p0GnBxcLJPufF
# cvfqG5bilK+GLjCCBVUwggQ9oAMCAQICEDYundkGUmnZYKGqqVRkDDgwDQYJKoZI
# hvcNAQELBQAwfDELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hl
# c3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MSQwIgYDVQQDExtTZWN0aWdvIFJTQSBDb2RlIFNpZ25pbmcgQ0EwHhcNMTkwMzE0
# MDAwMDAwWhcNMjEwMzEzMjM1OTU5WjCBpzELMAkGA1UEBhMCREUxDjAMBgNVBBEM
# BTY2NTcxMREwDwYDVQQIDAhTYWFybGFuZDESMBAGA1UEBwwJRXBwZWxib3JuMRkw
# FwYDVQQJDBBLb3NzbWFuc3RyYXNzZSA3MSIwIAYDVQQKDBlLcsOkbWVyIElUIFNv
# bHV0aW9ucyBHbWJIMSIwIAYDVQQDDBlLcsOkbWVyIElUIFNvbHV0aW9ucyBHbWJI
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs+f9rpEc+fjIZAYqOnrM
# kRYOoVtXoSya3uOqTtqdfXqQHuv4Ap40JTFyADNmHabJ7fGfCxFCq1axhjg0Ly0O
# n7KzReBQz4Y+M3OR+cByP0jjAbtbugzbVrySif1AX55JPQm60c5MxnklWfNU4l0/
# ieN/lTYV7SfY19fbXCxN1Z8mgkBZ+KbFcBes30D2DsoT/u4kb0oMxBjNL8+aIvUq
# eFKm8LLrNnuKGfn0++IghY/X2F3j/6NXyjoldohW5OHFTASMNYTQjZFvXfPAu8or
# 7R+BOepmGF5eUjpNpOCjgAmj46RCOCGX3KCf8iyhY88s8oNrvdKaBCe0mYpzUnBQ
# CQIDAQABo4IBpTCCAaEwHwYDVR0jBBgwFoAUDuE6qFM6MdWKvsG7rWcaA4WtNA4w
# HQYDVR0OBBYEFJIH3xQ1u7lnPAdIlJzhOJWhhIiXMA4GA1UdDwEB/wQEAwIHgDAM
# BgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMBEGCWCGSAGG+EIBAQQE
# AwIEEDBABgNVHSAEOTA3MDUGDCsGAQQBsjEBAgEDAjAlMCMGCCsGAQUFBwIBFhdo
# dHRwczovL3NlY3RpZ28uY29tL0NQUzBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8v
# Y3JsLnNlY3RpZ28uY29tL1NlY3RpZ29SU0FDb2RlU2lnbmluZ0NBLmNybDBzBggr
# BgEFBQcBAQRnMGUwPgYIKwYBBQUHMAKGMmh0dHA6Ly9jcnQuc2VjdGlnby5jb20v
# U2VjdGlnb1JTQUNvZGVTaWduaW5nQ0EuY3J0MCMGCCsGAQUFBzABhhdodHRwOi8v
# b2NzcC5zZWN0aWdvLmNvbTAdBgNVHREEFjAUgRJpbmZvQGtyYWVtZXItaXQuZGUw
# DQYJKoZIhvcNAQELBQADggEBAASLXBPt/BJ0qNRYiALS1Hw9aSynGBIxg6CJbIFr
# q7qNfmYIdPnYtLrm07y96eSSr8rMuG8ncyssS4gG1PtjNnOrdTSGmessr8ad2NUU
# H+9iCHA6qyKa85n2xCptlVtcAIKoIJd8M7CPYXRTScSHOvw5gd2flOt4PGleMoXq
# on6FxLUyi8usK+DpkjJ8add9wTjifksLIYMjgJFhDkuyNM8+sO6I0zDos8AT+xMV
# GD3PjSoqmzbYa2dzIrX1Z9gXQEK6u9/MnewGbyillPDCY0E+azWNd9VeC/O9xRO3
# nFIvNtXoFvEdcu/mPd+P0SAUTChQ/iqkBvfEDMhus8PdkWwwggXeMIIDxqADAgEC
# AhAB/W0w/KPKUagbvGQONQMtMA0GCSqGSIb3DQEBDAUAMIGIMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKTmV3IEplcnNleTEUMBIGA1UEBxMLSmVyc2V5IENpdHkxHjAc
# BgNVBAoTFVRoZSBVU0VSVFJVU1QgTmV0d29yazEuMCwGA1UEAxMlVVNFUlRydXN0
# IFJTQSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0xMDAyMDEwMDAwMDBaFw0z
# ODAxMTgyMzU5NTlaMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKTmV3IEplcnNl
# eTEUMBIGA1UEBxMLSmVyc2V5IENpdHkxHjAcBgNVBAoTFVRoZSBVU0VSVFJVU1Qg
# TmV0d29yazEuMCwGA1UEAxMlVVNFUlRydXN0IFJTQSBDZXJ0aWZpY2F0aW9uIEF1
# dGhvcml0eTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAIASZRc2DsPb
# CLPQrFcNdu3NJ9NMrVCDYeKqIE0JLWQJ3M6Jn8w9qez2z8Hc8dOx1ns3KBErR9o5
# xrw6GbRfpr19naNjQrZ28qk7K5H44m/Q7BYgkAk+4uh0yRi0kdRiZNt/owbxiBhq
# kCI8vP4T8IcUe/bkH47U5FHGEWdGCFHLhhRUP7wz/n5snP8WnRi9UY41pqdmyHJn
# 2yFmsdSbeAPAUDrozPDcvJ5M/q8FljUfV1q3/875PbcstvZU3cjnEjpNrkyKt1ya
# tLcgPcp/IjSufjtoZgFE5wFORlObM2D3lL5TN5BzQ/Myw1Pv26r+dE5px2uMYJPe
# xMcM3+EyrsyTO1F4lWeL7j1W/gzQaQ8bD/MlJmszbfduR/pzQ+V+DqVmsSl8MoRj
# VYnEDcGTVDAZE6zTfTen6106bDVc20HXEtqpSQvf2ICKCZNijrVmzyWIzYS4sT+k
# OQ/ZAp7rEkyVfPNrBaleFoPMuGfi6BOdzFuC00yz7Vv/3uVzrCM7LQC/NVV0CUnY
# SVgaf5I25lGSDvMmfRxNF7zJ7EMm0L9BX0CpRET0medXh55QH1dUqD79dGMvsVBl
# CeZYQi5DGky08CVHWfoEHpPUJkZKUIGy3r54t/xnFeHJV4QeD2PW6WK61l9VLupc
# xigIBCU5uA4rqfJMlxwHPw1S9e3vL4IPAgMBAAGjQjBAMB0GA1UdDgQWBBRTeb9a
# qitKz1SA4dibwJ3ysgNmyzAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB
# /zANBgkqhkiG9w0BAQwFAAOCAgEAXNR8Dc/3AX1BmWUMc8VSn8v4z5kGfxvaQxWf
# ngJVV5YU8VI8J4eUKO0fOgE3onb8U1DAhJvGa066jCFPoo5VYpHzaRXYvIjjxKoL
# /e+o6UtVKgYgbVV4KRnuXzBcSyQRVf8kmm5eKivuC02ff/cBOJQUlUMHCftgqe4c
# qxKMoJpep5hqWW2LPwj7yNFFrxgVZJASD3MoLsXiJE78WOzw9EX+IrPrL47S2UVh
# BcGXb6h2co+LjDavvw0FznGN5qZvH2ymcWLF2NCDcgzxZxGJDJwTTHI037zVcd+q
# cd3huWyMPBJdZdq9VxK2Q2v/5d5NZhFRz5mu7Be26HGRjN5J/t01caIVJ5Qcz2Hj
# Jrtvo2clIV3m3R0LLmgbO4Kv7INnhdSYUXSxuZmAif9/eBlceUpgLpJArkw3KizJ
# x2LIDl33NlvK4CUlAbTdGgecdwA/0NzV7D3U+rs/zIXWb3+pLd+5Avf1l5q1NdrD
# Z7CHSqkoniOO/1wna+GwT/MH7gAu1FmHy1JBler0R9fuZEFVfI1ZApXdYp3Cue5a
# KHSEpZu3kMcMB9/1iTZ0MtYowbCwC+CcTMMc1vzjabVHRoEvooKr02NEcMSN/y0z
# uq2Pe7VwiK4+Gc9AKNj8yJC7XZki9VLmWMUfiDFD7ogd18aOPENqHacY3n09FvFi
# +cqQqP0wggX1MIID3aADAgECAhAdokgwb5smGNCC4JZ9M9NqMA0GCSqGSIb3DQEB
# DAUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKTmV3IEplcnNleTEUMBIGA1UE
# BxMLSmVyc2V5IENpdHkxHjAcBgNVBAoTFVRoZSBVU0VSVFJVU1QgTmV0d29yazEu
# MCwGA1UEAxMlVVNFUlRydXN0IFJTQSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAe
# Fw0xODExMDIwMDAwMDBaFw0zMDEyMzEyMzU5NTlaMHwxCzAJBgNVBAYTAkdCMRsw
# GQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGDAW
# BgNVBAoTD1NlY3RpZ28gTGltaXRlZDEkMCIGA1UEAxMbU2VjdGlnbyBSU0EgQ29k
# ZSBTaWduaW5nIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhiKN
# MoV6GJ9J8JYvYwgeLdx8nxTP4ya2JWYpQIZURnQxYsUQ7bKHJ6aZy5UwwFb1pHXG
# qQ5QYqVRkRBq4Etirv3w+Bisp//uLjMg+gwZiahse60Aw2Gh3GllbR9uJ5bXl1GG
# pvQn5Xxqi5UeW2DVftcWkpwAL2j3l+1qcr44O2Pej79uTEFdEiAIWeg5zY/S1s8G
# tFcFtk6hPldrH5i8xGLWGwuNx2YbSp+dgcRyQLXiX+8LRf+jzhemLVWwt7C8VGqd
# vI1WU8bwunlQSSz3A7n+L2U18iLqLAevRtn5RhzcjHxxKPP+p8YU3VWRbooRDd8G
# JJV9D6ehfDrahjVh0wIDAQABo4IBZDCCAWAwHwYDVR0jBBgwFoAUU3m/WqorSs9U
# gOHYm8Cd8rIDZsswHQYDVR0OBBYEFA7hOqhTOjHVir7Bu61nGgOFrTQOMA4GA1Ud
# DwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdJQQWMBQGCCsGAQUF
# BwMDBggrBgEFBQcDCDARBgNVHSAECjAIMAYGBFUdIAAwUAYDVR0fBEkwRzBFoEOg
# QYY/aHR0cDovL2NybC51c2VydHJ1c3QuY29tL1VTRVJUcnVzdFJTQUNlcnRpZmlj
# YXRpb25BdXRob3JpdHkuY3JsMHYGCCsGAQUFBwEBBGowaDA/BggrBgEFBQcwAoYz
# aHR0cDovL2NydC51c2VydHJ1c3QuY29tL1VTRVJUcnVzdFJTQUFkZFRydXN0Q0Eu
# Y3J0MCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC51c2VydHJ1c3QuY29tMA0GCSqG
# SIb3DQEBDAUAA4ICAQBNY1DtRzRKYaTb3moqjJvxAAAeHWJ7Otcywvaz4GOz+2EA
# iJobbRAHBE++uOqJeCLrD0bs80ZeQEaJEvQLd1qcKkE6/Nb06+f3FZUzw6GDKLfe
# L+SU94Uzgy1KQEi/msJPSrGPJPSzgTfTt2SwpiNqWWhSQl//BOvhdGV5CPWpk95r
# cUCZlrp48bnI4sMIFrGrY1rIFYBtdF5KdX6luMNstc/fSnmHXMdATWM19jDTz7UK
# DgsEf6BLrrujpdCEAJM+U100pQA1aWy+nyAlEA0Z+1CQYb45j3qOTfafDh7+B1ES
# ZoMmGUiVzkrJwX/zOgWb+W/fiH/AI57SHkN6RTHBnE2p8FmyWRnoao0pBAJ3fEtL
# zXC+OrJVWng+vLtvAxAldxU0ivk2zEOS5LpP8WKTKCVXKftRGcehJUBqhFfGsp2x
# vBwK2nxnfn0u6ShMGH7EezFBcZpLKewLPVdQ0srd/Z4FUeVEeN0B3rF1mA1UJP3w
# TuPi+IO9crrLPTru8F4XkmhtyGH5pvEqCgulufSe7pgyBYWe6/mDKdPGLH29Oncu
# izdCoGqC7TtKqpQQpOEN+BfFtlp5MxiS47V1+KHpjgolHuQe8Z9ahyP/n6RRnvs5
# gBHN27XEp6iAb+VT1ODjosLSWxr6MiYtaldwHDykWC6j81tLB9wyWfOHpxptWDGC
# BF4wggRaAgEBMIGQMHwxCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1h
# bmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGDAWBgNVBAoTD1NlY3RpZ28gTGlt
# aXRlZDEkMCIGA1UEAxMbU2VjdGlnbyBSU0EgQ29kZSBTaWduaW5nIENBAhA2Lp3Z
# BlJp2WChqqlUZAw4MAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgACh
# AoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAM
# BgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBTAxQfQWdVh+53eqFVR1DwHK0LU
# JDANBgkqhkiG9w0BAQEFAASCAQByCh7L0HVQnRtqaBfLrGQturN2RNDRW8UDVRSQ
# 0qhR5TDmVStBVXc9SEmL5Zh7+2OjgmlLfwIlvfN/T8QLRTL17q+DWF0MxVwCowtq
# 5szzGIA6nKPlMEqOZASxjA5ObeFtc81F73erSBRP1tm5eV1UJ2IzCqDXIsqxSAcy
# aO56Ghu2vBPOuDMsL28T7NfoxW/c4pCUbUf5Pni8X3TJnU50dnuKfKp836fdV1B3
# 97cOCySoALHc27LnOH5a1vBXu29ZiCldYI/4/5wKRk6vWESMiVq169wbVlAi1ahN
# 6UZGCOguyH/zXS+U+BrGZLidOcLVQHT2+eC7twfNrniL7aC+oYICKDCCAiQGCSqG
# SIb3DQEJBjGCAhUwggIRAgEBMIGOMHoxCzAJBgNVBAYTAkdCMRswGQYDVQQIExJH
# cmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNP
# TU9ETyBDQSBMaW1pdGVkMSAwHgYDVQQDExdDT01PRE8gVGltZSBTdGFtcGluZyBD
# QQIQK3PbdGMRTFpbMkryMFdySTAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTkxMDIyMDczODAwWjAjBgkqhkiG
# 9w0BCQQxFgQUKTVTbbk37UGht1ho4h0W4hf4WmkwDQYJKoZIhvcNAQEBBQAEggEA
# XKSaIbQEFnjciuRGN++f9HEdO6FgFz/8Cc+fc1+2438vu5/qdCRXCcXmCUkHC54V
# wPnSthgg8CJyVprve6vlUmOTAvVamEAaaGCRPTGEU+VQxOJRcGujxgGnSjRvx1QZ
# XmISUsopsFCzxWnUdz8Vf7+dAgnZh6bemOfM3MSDrNUGp1mqI3W4yDzMn4YGfMYk
# Ws4wv1tcBWTv2XkUWAlUabFzbmhr2a0Bvi1mLhV5+1gB5FuH3+jHtkPkLGC5sVek
# 8IRbI6NTuFrkf/m3r49s2URKB/1kAS+k6GwxO8AWHbGyEHPK1VU5+by5K9zMuOMF
# xlSplo2vcZOqzr0jpyIi1A==
# SIG # End signature block
