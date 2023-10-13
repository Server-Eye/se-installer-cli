# Server-Eye GPO Install
# Version 3.0
# Author: Thomas Krammes
# Author: Andreas Behr
# Author: Rene Thulke
#
# Weitere Informationen zu diesem Skript finden Sie hier:
# https://servereye.freshdesk.com/support/solutions/articles/14000113669

Param ( 
    [Parameter()] 
    [Switch]$OCCConnector
)


# Die folgenden Werte muessen angepasst werden
$customerID = ""
$templateid = ""
$apikey = ""
$parentGuid = ""
$cleanup = $false

# Wo sollen Remote Logs abgespeichert werden
$SharedFolder = ""

# Wird ein Proxy benötigt?
$proxyIP = ""
$proxyPort = ""
$proxyDomain = ""
$proxyUser = ""
$proxyPassword = ""

# Wenn eine Alarmierungen auf dem Sensorhub oder dem OCC-Connector gesetzt werden sollen
$UserId = $null
$Email = $false
$Phone = $false
$Ticket = $false
$DeferId = $null

#
# Aendern Sie bitte nichts unterhalb dieser Zeile
#

#region Internal Variables
$URL = "https://update.server-eye.de/download/se/ServerEyeSetup.exe"
$SetupPath = Join-Path -Path $env:TEMP -ChildPath "\ServerEyeSetup.exe"
$SEPath = "C:\Program Files (x86)\Server-Eye"
$CCConfig = Join-Path -Path $SEPath -ChildPath "config\se3_cc.conf"
$MACConfig = Join-Path -Path $SEPath -ChildPath "config\se3_mac.conf"
$ERSPath = Join-Path -Path $SEPath -ChildPath "ers\EmergencyAction.exe"
$SELogPath = Join-Path -Path $env:ProgramData -ChildPath "\ServerEye3\logs\"
$SEInstallLog = Join-Path -Path $SELogPath -ChildPath "installer.log"
$ErrorActionPreference = "Continue"
#endregion Internal Variables

Write-verbose $PSBoundParameters

#region Internal function
#region FindContainerID
Function Find-ContainerID {
    [cmdletbinding(
    )]
    Param (
        [Parameter(Mandatory = $true)]
        $Path
    )
    if (Test-Path $path ) {
        Write-Output (Get-Content $Path | Select-String -Pattern "\bguid=\b").ToString().Replace("guid=", "")
    }
}
#endregion FindContainerID
#region Add-Template
function Add-Template {
    [CmdletBinding()]
    Param (
        [string]
        $Guid,
		
        [string]
        $authtoken,
		
        [string]
        $TemplateId,

        [string]
        $proxyip,

        [string]
        $proxyport,

        [PSCredential]
        $ProxyCredential
    )
    
    $url = "https://api-ms.server-eye.de/3/container/$guid/template/$templateId"
    $exitcode = 0
    try {
        if ($proxyip) {
            [uri]$buildproxy = "http://{0}:{1}" -f $proxyip, $proxyport
            if ($ProxyCredential) {
                $Template = Invoke-RestMethod -Uri $url -Method Post -Headers @{"x-api-key" = $ApiKey } -Proxy $buildproxy -ProxyCredential $ProxyCredential
                Add-Content -Path $SEInstallLog -Value "$(Get-Date -Format "yy.MM.dd hh:mm:ss")  INFO ServerEye.Installer.Logic.PowerShell - Template with $($template.Count) Sensoren added"

            }
            else {
                $Template = Invoke-RestMethod -Uri $url -Method Post -Headers @{"x-api-key" = $ApiKey } -Proxy $buildproxy
                Add-Content -Path $SEInstallLog -Value "$(Get-Date -Format "yy.MM.dd hh:mm:ss")  INFO ServerEye.Installer.Logic.PowerShell - Template with $($template.Count) Sensoren added"
            }
            
        }
        else {
            $Template = Invoke-RestMethod -Uri $url -Method Post -Headers @{"x-api-key" = $ApiKey }
            Add-Content -Path $SEInstallLog -Value "$(Get-Date -Format "yy.MM.dd hh:mm:ss")  INFO ServerEye.Installer.Logic.PowerShell - Template with $($template.Count) Sensoren added"
        }
    }
    catch {
        Add-Content -Path $SEInstallLog -Value "$(Get-Date -Format "yy.MM.dd hh:mm:ss")  ERROR ServerEye.Installer.Logic.PowerShell - Template Error: $_"
        Write-Error -Message "Template Error: $_" -ErrorAction $ErrorActionPreference
        
    }
}
#endregion Add-Template
#Region Notification
#region helper Functions
function Remove-Null {

    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeline)]
        $obj
    )

    Process {
        $result = @{}
        foreach ($key in $_.Keys) {
            if ($_[$key] -ne $null) {
                $result.Add($key, $_[$key])
            }
        }
        $result
    }
}

function Intern-PostJson($url, $authtoken, $body) {
    $body = $body | Remove-Null | ConvertTo-Json
    if ($authtoken -is [string]) {
        return (Invoke-RestMethod -Uri $url -Method Post -Body $body -ContentType "application/json" -Headers @{"x-api-key" = $authtoken } );
    }
    else {
        return (Invoke-RestMethod -Uri $url -Method Post -Body $body -ContentType "application/json" -WebSession $authtoken );
    }
}
#endregion helper Functions
function New-ContainerNotification {
    [CmdletBinding()]
    Param(
        
        [Parameter(Mandatory = $true)]
        $CId,
        [Parameter(Mandatory = $true)]
        $UserId,
        [Parameter(Mandatory = $false)]
        $Email,
        [Parameter(Mandatory = $false)]
        $Phone,
        [Parameter(Mandatory = $false)]
        $Ticket,
        [Parameter(Mandatory = $false)]
        $DeferId,
        [Parameter(Mandatory = $true)]
        [alias("ApiKey", "Session")]
        $AuthToken
    )
    
    
    Process {
        $reqBody = @{
        
            'cId'     = $CId
            'userId'  = $UserId
            'email'   = $Email
            'phone'   = $Phone
            'ticket'  = $Ticket
            'deferId' = $DeferId
        }
        try {
            $Noti = Intern-PostJson -url "https://api.server-eye.de/2/container/$CId/notification" -authtoken $AuthToken -body $reqBody
            Add-Content -Path $SEInstallLog -Value "$(Get-Date -Format "yy.MM.dd hh:mm:ss") INFO  ServerEye.Installer.Logic.PowerShell - Notification created for user $($noti.usermail)" 
        }
        catch {
            Add-Content -Path $SEInstallLog -Value "$(Get-Date -Format "yy.MM.dd hh:mm:ss") ERROR  ServerEye.Installer.Logic.PowerShell - Notification Error: $_"
            Write-Error -Message "Notification Error: $_" -ErrorAction $ErrorActionPreference
        }

    }
}

function Save-SELog {
    param (
        [Parameter(Mandatory = $true)]
        $Path,
        [Parameter(Mandatory = $true)]
        [switch]$withError
    )

    if ($withError) {
        $MSIRemoteFolder = Join-Path -Path $Path -ChildPath "MSILogs"
        if (!(Test-Path $MSIRemoteFolder)) {
            New-Item -Path $MSIRemoteFolder -ItemType Directory
        }
    
        $MSILog = Get-ChildItem -Path $env:TEMP -Filter Server-Eye_*
        foreach ($log in $MSILog) {
            Copy-Item -Path $log.FullName -Destination $MSIRemoteFolder
        }
    }
    Copy-Item $SEInstallLog $Path 
}

#endregion Notification
#endregion Internal function

#region Build Proxy
if ($proxyIP) {
    Write-verbose "Proxy IP Detected" 
    $buildproxy = "{0}:{1}" -f $proxyIP, $proxyPort
    if ($proxyUser) {
        Write-verbose "Create Secure Password" 
        $PWord = ConvertTo-SecureString -String $proxyPassword -AsPlainText -Force
        if ($proxyDomain) {
            Write-verbose "Build User with Domain" 
            $proxyCred = "{0}\{1}" -f $proxyDomain, $proxyuser
        }
        else {
            Write-verbose "Build User without Domain" 
            $proxyCred = $proxyUser
        }
        Write-verbose "Build Secure Credential" 
        $Cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ProxyCred, $PWord
        
    }
}
#Endregion Build Proxy

#region Server-Eye Download
# Download der aktuellen Version
Write-verbose "Check if Setup Download is needed"
if (!(Test-Path $SetupPath)) {
    Write-verbose "Download is needed"
    try {
        Write-verbose "Start Downloading the Server-Eye Setup"
        if ($proxyIP) {
            Write-verbose "Proxy IP Detected" 
            if ($proxyUser) {
                Write-verbose "Start Download" 
                Start-BitsTransfer -Source $URL -Destination $SetupPath -Description "Server-Eye Setup" -ProxyUsage Override -ProxyList $buildproxy -ProxyAuthentication "Basic" -ProxyCredential $Cred
                Write-verbose "Finished Downloading the Server-Eye Setup" 
            }
            else {
                Start-BitsTransfer -Source $URL -Destination $SetupPath -Description "Server-Eye Setup" -ProxyUsage Override -ProxyList $buildproxy
                Write-verbose "Finished Downloading the Server-Eye Setup" 
            }

        }
        else {
            Start-BitsTransfer -Source $URl -Destination $SetupPath -Description "Server-Eye Setup"
            Write-verbose "Finished Downloading the Server-Eye Setup" 
        }
    }
    catch {
        Write-Error "Something went wrong $_"
        exit 2
    }

}
else {
    Write-verbose "No Download is needed"
}
#endregion Server-Eye Download

#Erstellen der Prozess Argument
#region Arguments

Write-verbose "Starting Argument"
if ($OCCConnector) {
    Write-verbose "Argument for OCC-Connector"
    $Install = "newConnector"
}
else {
    Write-verbose "Argument for Sensorhub"
    $Install = "install --cID={0}" -f $parentGuid
}
#WIP
#if ($templateid) {
#    $template = " --templateID={0}" -f $templateid
#}
#else {
$template = $null
#}
if ($proxyIP) {
    Write-verbose "Argument with Proxy URL"
    $Proxy = " --proxyUrl={0} --proxyPort={1}" -f $proxyIP, $proxyport
    if ($proxyUser) {
        Write-verbose "Argument with Authentication Proxy"
        $proxy = "{0} --proxyUser={1} --proxyPassword={2}" -f $Proxy, $proxyUser, $proxyPassword
    }
    if ($proxyDomain) {
        Write-verbose "Argument with Authentication Proxy with Domain"
        $proxy = "{0} --proxyDomain={1}" -f $Proxy, $proxyDomain
    }
}
else {
    $proxy = $null
}
$argument = '"ARGUMENTS={0} --customerID={1} --apiKey={2} --silent=true --cleanup={3}{4}{5}" "/quiet"' -f $Install, $customerID, $apikey, $cleanup.toString().ToLower(), $template, $Proxy
$startProcessParams = @{
    FilePath     = $SetupPath
    ArgumentList = $argument       
    Wait         = $true;
    NoNewWindow  = $true;
    Passthru     = $true;
} 
Write-verbose "Finished Argument construction"
#endregion Arguments


# Installation Server-Eye
#region CheckRemoteLog
Write-verbose "Setting RemoteLogs Folder"
if ($SharedFolder) {
    $remoteLog = Join-Path -Path $SharedFolder -ChildPath $env:computername
    if (!(Test-Path $remoteLog)) {
        New-Item -Path $remoteLog  -ItemType Directory
    }
}

#endregion CheckRemoteLog
Write-verbose "Check Server-Eye Installation State"

if (!(Test-Path $ERSPath)) {
    
    Write-verbose "Starting Server-Eye installation"
    $Setup = Start-Process @startProcessParams
    Write-verbose "Finished Server-Eye installation: $($Setup.ExitCode)"
    Write-verbose "Collecting Logs"

    if ($setup.ExitCode -ne 0) {
        Write-verbose "Collecting MSI Logs"
        if ($SharedFolder) {
        Save-SELog -Path $remoteLog -withError
        }
        exit 1
    }
    Write-verbose "Collecting Logs finished"
    $SensorhubID = Find-ContainerID -path $CCConfig
    $ConnectorID = Find-ContainerID -path $MACConfig
    if ($templateid) {
        foreach ($template in $templateid) {
            #Try Catch in Function not need here
            Add-Template -Guid $SensorhubID -authtoken $apikey -TemplateId $template -proxyip $proxyip -proxyPort $proxyport -ProxyCredential $Cred
        }
    }

    if ($userid) {
        if ($ConnectorID) {
            #Try Catch in Function not need here
            New-ContainerNotification -CId $ConnectorID -UserId $userid -Email $Email -Phone $Phone -Ticket $Ticket -DeferId $DeferId -AuthToken $apikey
            New-ContainerNotification -CId $SensorhubID -UserId $userid -Email $Email -Phone $Phone -Ticket $Ticket -DeferId $DeferId -AuthToken $apikey
        }
        else {
            New-ContainerNotification -CId $SensorhubID -UserId $userid -Email $Email -Phone $Phone -Ticket $Ticket -DeferId $DeferId -AuthToken $apikey
        } 
    }
    if ($SharedFolder) {
    Save-SELog -Path $remoteLog
    }
    exit 0
}
else {
    Write-verbose "Collecting Logs, Server-Eye inst installed"
    Write-verbose "Create new Loglinie Server-Eye installed"
    Add-Content -Path $SEInstallLog -Value "$(Get-Date -Format "yy.MM.dd hh:mm:ss") INFO  ServerEye.Installer.Logic.PowerShell Server-Eye already Installed, exit PowerShell Script"
    if ($SharedFolder) {
    Save-SELog -Path $remoteLog 
    }
    Write-verbose "Collecting Logs, Server-Eye inst finished"
    exit 0
}
