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

	Write-Log "  downloading ServerEye.Setup... " -NoNewline
	Download-SEFile "$BaseDownloadUrl/$SE_cloudIdentifier/ServerEyeSetup.exe" "$Path\ServerEyeSetup.exe" -proxy $proxy
	
	Write-Log "  downloading ServerEye.Vendor... " -NoNewline
	Download-SEFile "$BaseDownloadUrl/vendor/$SE_vendor/Vendor.msi" "$Path\Vendor.msi" -proxy $proxy
	
	Write-Log "  downloading ServerEye.Core... " -NoNewline
	Download-SEFile "$BaseDownloadUrl/setup/ServerEye.msi" "$Path\ServerEye.msi" -proxy $proxy

	
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

	if ([System.IO.File]::Exists($TargetFile))
	{
		Write-Log "using local file" -ForegroundColor Green
	} else {	
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

			Write-Log "done" -ForegroundColor Green
			
		}
		catch
		{
			
			#Write-Log -Message "Error downloading: $Url - Interrupting execution - $($_.Exception.Message)" -EventID 666 -EntryType Error
			Stop-Execution
		}
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
# MIIeygYJKoZIhvcNAQcCoIIeuzCCHrcCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBkrZnpbwk4GFEJ
# 0I2Jq2shathcT0h5ArMW0wXsJE0tT6CCGLkwggVAMIIEKKADAgECAhA+ii5iHolI
# oJc0Gy3BlHV8MA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAkdCMRswGQYDVQQI
# ExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGDAWBgNVBAoT
# D1NlY3RpZ28gTGltaXRlZDEkMCIGA1UEAxMbU2VjdGlnbyBSU0EgQ29kZSBTaWdu
# aW5nIENBMB4XDTIxMDMxNTAwMDAwMFoXDTIzMDMxNTIzNTk1OVowgacxCzAJBgNV
# BAYTAkRFMQ4wDAYDVQQRDAU2NjU3MTERMA8GA1UECAwIU2FhcmxhbmQxEjAQBgNV
# BAcMCUVwcGVsYm9ybjEZMBcGA1UECQwQS29zc21hbnN0cmFzc2UgNzEiMCAGA1UE
# CgwZS3LDpG1lciBJVCBTb2x1dGlvbnMgR21iSDEiMCAGA1UEAwwZS3LDpG1lciBJ
# VCBTb2x1dGlvbnMgR21iSDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
# APZ99rk9dw3vm2ll7CstRVSY1Z4ZQowm7j0cN1jaFsKGMR/fnntgILwKHrP4nAfV
# DD5fnaZQW9U7GCJBddLNWNPiRJ/MGRbSJ3S1WHBJYbKzx+tqXmug/k/YwYNjG6wL
# V+wLCOMFaxa2wkFPcgdIjRF9mE5BT81QgB0ip32AH3TA9DYGX/ElSiw03qQpNz3k
# 1mwvtuv+pcr6vP4c/Zv0UMlKcKhheaVlDOc1pu4mYcqSDKW79CwbLlR4MtEfkcgR
# J5vhNhXPYUrx2Q11MA1jQtoprM9fkA8xx68jxMvvoJJW3OvcbnNU/obvMKKCNex/
# 6vQn5yrdfWdX5IFz03QNNCECAwEAAaOCAZAwggGMMB8GA1UdIwQYMBaAFA7hOqhT
# OjHVir7Bu61nGgOFrTQOMB0GA1UdDgQWBBS/o2hdxTj7XrAgvfi7QIWvYGQFezAO
# BgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcD
# AzARBglghkgBhvhCAQEEBAMCBBAwSgYDVR0gBEMwQTA1BgwrBgEEAbIxAQIBAwIw
# JTAjBggrBgEFBQcCARYXaHR0cHM6Ly9zZWN0aWdvLmNvbS9DUFMwCAYGZ4EMAQQB
# MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGln
# b1JTQUNvZGVTaWduaW5nQ0EuY3JsMHMGCCsGAQUFBwEBBGcwZTA+BggrBgEFBQcw
# AoYyaHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUlNBQ29kZVNpZ25pbmdD
# QS5jcnQwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMA0GCSqG
# SIb3DQEBCwUAA4IBAQAqIfS4ob0wDVC1CQV0qlo/mnO6yxubYVuCbBmIx6KZM8pE
# 2OZebVcVh1t82nqYdmulFHs878F35iCi2Vls8eTNhrptNLGp+JTAD5bhV1x9obDD
# 02TsqgSysmMoqav0sP8vIJdsHuR/12wzy9HDt8invvHWjBeIa8Yq7breoSepnAPn
# 99lt0q2QYCWHGef7uj3pRSMyD+Hef0zERRcCuORZJp+mJDctSRwMQ8MzWlNpg1oG
# M4qQqntIVEDRduegGO5IF1n3Dtx/lSoh2WWL+1PO8aNsmrvQK4Xw6S2VEWZvAipu
# 9MdCunys05wHRkG2QCSgCY4S/Z2jswLbA9ATGMxJMIIF9TCCA92gAwIBAgIQHaJI
# MG+bJhjQguCWfTPTajANBgkqhkiG9w0BAQwFADCBiDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQK
# ExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0Eg
# Q2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTgxMTAyMDAwMDAwWhcNMzAxMjMx
# MjM1OTU5WjB8MQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVz
# dGVyMRAwDgYDVQQHEwdTYWxmb3JkMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQx
# JDAiBgNVBAMTG1NlY3RpZ28gUlNBIENvZGUgU2lnbmluZyBDQTCCASIwDQYJKoZI
# hvcNAQEBBQADggEPADCCAQoCggEBAIYijTKFehifSfCWL2MIHi3cfJ8Uz+MmtiVm
# KUCGVEZ0MWLFEO2yhyemmcuVMMBW9aR1xqkOUGKlUZEQauBLYq798PgYrKf/7i4z
# IPoMGYmobHutAMNhodxpZW0fbieW15dRhqb0J+V8aouVHltg1X7XFpKcAC9o95ft
# anK+ODtj3o+/bkxBXRIgCFnoOc2P0tbPBrRXBbZOoT5Xax+YvMRi1hsLjcdmG0qf
# nYHEckC14l/vC0X/o84Xpi1VsLewvFRqnbyNVlPG8Lp5UEks9wO5/i9lNfIi6iwH
# r0bZ+UYc3Ix8cSjz/qfGFN1VkW6KEQ3fBiSVfQ+noXw62oY1YdMCAwEAAaOCAWQw
# ggFgMB8GA1UdIwQYMBaAFFN5v1qqK0rPVIDh2JvAnfKyA2bLMB0GA1UdDgQWBBQO
# 4TqoUzox1Yq+wbutZxoDha00DjAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgw
# BgEB/wIBADAdBgNVHSUEFjAUBggrBgEFBQcDAwYIKwYBBQUHAwgwEQYDVR0gBAow
# CDAGBgRVHSAAMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6Ly9jcmwudXNlcnRydXN0
# LmNvbS9VU0VSVHJ1c3RSU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDB2Bggr
# BgEFBQcBAQRqMGgwPwYIKwYBBQUHMAKGM2h0dHA6Ly9jcnQudXNlcnRydXN0LmNv
# bS9VU0VSVHJ1c3RSU0FBZGRUcnVzdENBLmNydDAlBggrBgEFBQcwAYYZaHR0cDov
# L29jc3AudXNlcnRydXN0LmNvbTANBgkqhkiG9w0BAQwFAAOCAgEATWNQ7Uc0SmGk
# 295qKoyb8QAAHh1iezrXMsL2s+Bjs/thAIiaG20QBwRPvrjqiXgi6w9G7PNGXkBG
# iRL0C3danCpBOvzW9Ovn9xWVM8Ohgyi33i/klPeFM4MtSkBIv5rCT0qxjyT0s4E3
# 07dksKYjalloUkJf/wTr4XRleQj1qZPea3FAmZa6ePG5yOLDCBaxq2NayBWAbXRe
# SnV+pbjDbLXP30p5h1zHQE1jNfYw08+1Cg4LBH+gS667o6XQhACTPlNdNKUANWls
# vp8gJRANGftQkGG+OY96jk32nw4e/gdREmaDJhlIlc5KycF/8zoFm/lv34h/wCOe
# 0h5DekUxwZxNqfBZslkZ6GqNKQQCd3xLS81wvjqyVVp4Pry7bwMQJXcVNIr5NsxD
# kuS6T/FikyglVyn7URnHoSVAaoRXxrKdsbwcCtp8Z359LukoTBh+xHsxQXGaSyns
# Cz1XUNLK3f2eBVHlRHjdAd6xdZgNVCT98E7j4viDvXK6yz067vBeF5Jobchh+abx
# KgoLpbn0nu6YMgWFnuv5gynTxix9vTp3Los3QqBqgu07SqqUEKThDfgXxbZaeTMY
# kuO1dfih6Y4KJR7kHvGfWocj/5+kUZ77OYARzdu1xKeogG/lU9Tg46LC0lsa+jIm
# LWpXcBw8pFguo/NbSwfcMlnzh6cabVgwggauMIIElqADAgECAhAHNje3JFR82Ees
# /ShmKl5bMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxE
# aWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMT
# GERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMjAzMjMwMDAwMDBaFw0zNzAz
# MjIyMzU5NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBU
# aW1lU3RhbXBpbmcgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDG
# hjUGSbPBPXJJUVXHJQPE8pE3qZdRodbSg9GeTKJtoLDMg/la9hGhRBVCX6SI82j6
# ffOciQt/nR+eDzMfUBMLJnOWbfhXqAJ9/UO0hNoR8XOxs+4rgISKIhjf69o9xBd/
# qxkrPkLcZ47qUT3w1lbU5ygt69OxtXXnHwZljZQp09nsad/ZkIdGAHvbREGJ3Hxq
# V3rwN3mfXazL6IRktFLydkf3YYMZ3V+0VAshaG43IbtArF+y3kp9zvU5EmfvDqVj
# bOSmxR3NNg1c1eYbqMFkdECnwHLFuk4fsbVYTXn+149zk6wsOeKlSNbwsDETqVcp
# licu9Yemj052FVUmcJgmf6AaRyBD40NjgHt1biclkJg6OBGz9vae5jtb7IHeIhTZ
# girHkr+g3uM+onP65x9abJTyUpURK1h0QCirc0PO30qhHGs4xSnzyqqWc0Jon7ZG
# s506o9UD4L/wojzKQtwYSH8UNM/STKvvmz3+DrhkKvp1KCRB7UK/BZxmSVJQ9FHz
# NklNiyDSLFc1eSuo80VgvCONWPfcYd6T/jnA+bIwpUzX6ZhKWD7TA4j+s4/TXkt2
# ElGTyYwMO1uKIqjBJgj5FBASA31fI7tk42PgpuE+9sJ0sj8eCXbsq11GdeJgo1gJ
# ASgADoRU7s7pXcheMBK9Rp6103a50g5rmQzSM7TNsQIDAQABo4IBXTCCAVkwEgYD
# VR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUuhbZbU2FL3MpdpovdYxqII+eyG8w
# HwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGG
# MBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcw
# AYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8v
# Y2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBD
# BgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNl
# cnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgB
# hv1sBwEwDQYJKoZIhvcNAQELBQADggIBAH1ZjsCTtm+YqUQiAX5m1tghQuGwGC4Q
# TRPPMFPOvxj7x1Bd4ksp+3CKDaopafxpwc8dB+k+YMjYC+VcW9dth/qEICU0MWfN
# thKWb8RQTGIdDAiCqBa9qVbPFXONASIlzpVpP0d3+3J0FNf/q0+KLHqrhc1DX+1g
# tqpPkWaeLJ7giqzl/Yy8ZCaHbJK9nXzQcAp876i8dU+6WvepELJd6f8oVInw1Ypx
# dmXazPByoyP6wCeCRK6ZJxurJB4mwbfeKuv2nrF5mYGjVoarCkXJ38SNoOeY+/um
# nXKvxMfBwWpx2cYTgAnEtp/Nh4cku0+jSbl3ZpHxcpzpSwJSpzd+k1OsOx0ISQ+U
# zTl63f8lY5knLD0/a6fxZsNBzU+2QJshIUDQtxMkzdwdeDrknq3lNHGS1yZr5Dhz
# q6YBT70/O3itTK37xJV77QpfMzmHQXh6OOmc4d0j/R0o08f56PGYX/sr2H7yRp11
# LB4nLCbbbxV7HhmLNriT1ObyF5lZynDwN7+YAN8gFk8n+2BnFqFmut1VwDophrCY
# oCvtlUG3OtUVmDG0YgkPCr2B2RP+v6TR81fZvAT6gt4y3wSJ8ADNXcL50CN/AAvk
# dgIm2fBldkKmKYcJRyvmfxqkhQ/8mJb2VVQrH4D6wPIOK+XW+6kvRBVK5xMOHds3
# OBqhK/bt1nz8MIIGxjCCBK6gAwIBAgIQCnpKiJ7JmUKQBmM4TYaXnTANBgkqhkiG
# 9w0BAQsFADBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4x
# OzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGlt
# ZVN0YW1waW5nIENBMB4XDTIyMDMyOTAwMDAwMFoXDTMzMDMxNDIzNTk1OVowTDEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMSQwIgYDVQQDExtE
# aWdpQ2VydCBUaW1lc3RhbXAgMjAyMiAtIDIwggIiMA0GCSqGSIb3DQEBAQUAA4IC
# DwAwggIKAoICAQC5KpYjply8X9ZJ8BWCGPQz7sxcbOPgJS7SMeQ8QK77q8TjeF1+
# XDbq9SWNQ6OB6zhj+TyIad480jBRDTEHukZu6aNLSOiJQX8Nstb5hPGYPgu/CoQS
# cWyhYiYB087DbP2sO37cKhypvTDGFtjavOuy8YPRn80JxblBakVCI0Fa+GDTZSw+
# fl69lqfw/LH09CjPQnkfO8eTB2ho5UQ0Ul8PUN7UWSxEdMAyRxlb4pguj9DKP//G
# Z888k5VOhOl2GJiZERTFKwygM9tNJIXogpThLwPuf4UCyYbh1RgUtwRF8+A4vaK9
# enGY7BXn/S7s0psAiqwdjTuAaP7QWZgmzuDtrn8oLsKe4AtLyAjRMruD+iM82f/S
# jLv3QyPf58NaBWJ+cCzlK7I9Y+rIroEga0OJyH5fsBrdGb2fdEEKr7mOCdN0oS+w
# VHbBkE+U7IZh/9sRL5IDMM4wt4sPXUSzQx0jUM2R1y+d+/zNscGnxA7E70A+GToC
# 1DGpaaBJ+XXhm+ho5GoMj+vksSF7hmdYfn8f6CvkFLIW1oGhytowkGvub3XAsDYm
# sgg7/72+f2wTGN/GbaR5Sa2Lf2GHBWj31HDjQpXonrubS7LitkE956+nGijJrWGw
# oEEYGU7tR5thle0+C2Fa6j56mJJRzT/JROeAiylCcvd5st2E6ifu/n16awIDAQAB
# o4IBizCCAYcwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/
# BAwwCgYIKwYBBQUHAwgwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MB8GA1UdIwQYMBaAFLoW2W1NhS9zKXaaL3WMaiCPnshvMB0GA1UdDgQWBBSNZLeJ
# If5WWESEYafqbxw2j92vDTBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0
# YW1waW5nQ0EuY3JsMIGQBggrBgEFBQcBAQSBgzCBgDAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMFgGCCsGAQUFBzAChkxodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGlt
# ZVN0YW1waW5nQ0EuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQANLSN0ptH1+OpLmT8B
# 5PYM5K8WndmzjJeCKZxDbwEtqzi1cBG/hBmLP13lhk++kzreKjlaOU7YhFmlvBuY
# quhs79FIaRk4W8+JOR1wcNlO3yMibNXf9lnLocLqTHbKodyhK5a4m1WpGmt90fUC
# CU+C1qVziMSYgN/uSZW3s8zFp+4O4e8eOIqf7xHJMUpYtt84fMv6XPfkU79uCnx+
# 196Y1SlliQ+inMBl9AEiZcfqXnSmWzWSUHz0F6aHZE8+RokWYyBry/J70DXjSnBI
# qbbnHWC9BCIVJXAGcqlEO2lHEdPu6cegPk8QuTA25POqaQmoi35komWUEftuMvH1
# uzitzcCTEdUyeEpLNypM81zctoXAu3AwVXjWmP5UbX9xqUgaeN1Gdy4besAzivhK
# KIwSqHPPLfnTI/KeGeANlCig69saUaCVgo4oa6TOnXbeqXOqSGpZQ65f6vgPBkKd
# 3wZolv4qoHRbY2beayy4eKpNcG3wLPEHFX41tOa1DKKZpdcVazUOhdbgLMzgDCS4
# fFILHpl878jIxYxYaa+rPeHPzH0VrhS/inHfypex2EfqHIXgRU4SHBQpWMxv03/L
# vsEOSm8gnK7ZczJZCOctkqEaEf4ymKZdK5fgi9OczG21Da5HYzhHF1tvE9pqEG4f
# SbdEW7QICodaWQR2EaGndwITHDGCBWcwggVjAgEBMIGQMHwxCzAJBgNVBAYTAkdC
# MRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQx
# GDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEkMCIGA1UEAxMbU2VjdGlnbyBSU0Eg
# Q29kZSBTaWduaW5nIENBAhA+ii5iHolIoJc0Gy3BlHV8MA0GCWCGSAFlAwQCAQUA
# oIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisG
# AQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcN
# AQkEMSIEIHyUmjL40E2HLJPgTpcM0oBCcovhh3uUoSDOSKq2RK+5MA0GCSqGSIb3
# DQEBAQUABIIBANoDvRkPMdaxt+RYO5d4H+jyfhDt/S8nXoeFyPgbvED7P1kDf2om
# af9tJDqT3/c1OO+WWd2LH99iAGsWFya7vfTLW1dyOGiBsxlc7A5j0MKKSwk4OZ4Y
# la/Z9CpHXwkcq8LjODvHsVL8ltkUw79y3DZheuTS3HrY7jHBAkN8bYdn1DDzgenY
# d54uJwr4f7FITMPJPZ/Hz3xq86zsPEkJo2z+YqwkFCaiK+dtSOblWU8ZVvAzCMiL
# FJ6x1PHNAxzqg2oQxz6LA9d9EEt8bmPFEjgn2QW5pG1Nn5mZ9n67S9IZQVCIU0uV
# tWVpSZeY/vqSXrAOWsoOIZ9XMibOduYFF/ihggMgMIIDHAYJKoZIhvcNAQkGMYID
# DTCCAwkCAQEwdzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIElu
# Yy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYg
# VGltZVN0YW1waW5nIENBAhAKekqInsmZQpAGYzhNhpedMA0GCWCGSAFlAwQCAQUA
# oGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjIw
# NDI1MTQ0NjI5WjAvBgkqhkiG9w0BCQQxIgQgvOkzEo1M94wTqHIUxSe502NnPH/H
# tIwdq7+fr2Z2YZUwDQYJKoZIhvcNAQEBBQAEggIAMYuQUHvoQ3x8uxPmFq/ztLJT
# 11uuCQEqh00DoAGZvQY4B1F+Vlu3ONtpM5N9UuKrxOHUXIzBNk47tgKBkqnFG8PW
# gglGY92xcHELuMg3JyZIBeXduhR7V7pwGnccn5orwyMNTB023NA/K6bHNvFmw5Ic
# kaZOuCnfFVfbtObLXJWIHQyv6hRG0v7E1KPDxTyABGRrti7/yt9k8vIHUuLylTvT
# HOwthLr1FEHD1p6dZIi2l0tJ1z0hN3G66E4f77bfJLDju1BDnA7if/F6PKrHqI/D
# xrNNWQsTvlcCalDLq0lSWePgvAl3f1k8rhF6uTBkcE74tRGEJcQfqF6PD2mSGhTm
# bTgr9kWzVeDBiL6ItmMe81vNfBtr+mR6i44wzxrtC/clU7HT/7w6Qr9qUCha/Afa
# SuuwqVl+48vgdmG8MWvCmDLSlPsx3sXAB21+F2FrrBSXFYgKhaqX9e7B0ix8oo9S
# jzxEPN0nrbrdR1MakHj2Sr/J4pyT4tDBWQpcpW76P9GUgkg7pIB8Twes3B5LIlcs
# qvT+E2MGsWsnDwB3rsVl1PAYfLfYjYGWMChcznQGJeyCDr9WOOAWELJ5hJTw09S6
# eKn4V3DiZ8YZ3hemJv/Wzqt1HP1GJucFH2mbocZBFDr9FoB23MME25nXtDFMeVh9
# pSPWsVY5xpmXs15Efm8=
# SIG # End signature block
