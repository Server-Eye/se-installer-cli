<#
    .SYNOPSIS
    Install Server-Eye via Commandline.
    
    .DESCRIPTION
    Install Server-Eye via Commandline with the Setup.
        
    .PARAMETER customerID
    ID of the Customer, where the System should be installed

    .PARAMETER apikey
    APIKey to install the System

    .PARAMETER parentGuid
    ID of the OCC-Connector where the Sensorhub should be installed

    .PARAMETER OCCConnector
    A OCC-Connector will be installed on the System

    .PARAMETER SharedFolder
    Path were the Logs should be stored in a central location

    .PARAMETER cleanup
    Should all old Server-Eye Data be deleted

    .PARAMETER proxyIP
    IP of the Proxy

    .PARAMETER proxyPort
    Port of the Proxy

    .PARAMETER proxyUser
    User to authenticate against the Proxy

    .PARAMETER proxyPassword
    Password for the Proxy User to authenticate against the Proxy

    .PARAMETER templateid
    IDs of the templates that should be added to the installed Sensorhub

    .PARAMETER UserId
    ID of the User that should be set to get a Notification for an alert of the Sensorhub or OCC-Connector

    .PARAMETER Email
    A Email should be send in the Notification
    
    .PARAMETER Phone
    A SMS should be send in the Notification

    .PARAMETER Ticket
    A Ticket should be send in the Notification

    .PARAMETER DeferId
    ID of the Defer to be set in the Notification

    .EXAMPLE
    Sensorhub 
    gpo_installV3Parameter.ps1 -customerID "CustomerID" -apikey "APIKey" -parentGuid "OCC-Connector ID" -SharedFolder "UNC Path"

    .EXAMPLE
    OCC-Connector
    gpo_installV3Parameter.ps1 -customerID "CustomerID" -apikey "APIKey" -OCCConnector -SharedFolder "UNC Path"

    .EXAMPLE
    Sensorhub with template
    gpo_installV3Parameter.ps1 -customerID "CustomerID" -apikey "APIKey" -parentGuid "OCC-Connector ID" -SharedFolder "UNC Path" -templateid "template ID"


    .LINK 
    https://servereye.freshdesk.com/support/solutions/articles/14000113669

    .NOTES
    Version 3.0
    Author: Server-Eye
    
#>


[CmdletBinding(DefaultParameterSetName = 'Sensorhub')]
Param(

    [Parameter(Mandatory = $true, ParameterSetName = 'Sensorhub')]
    [Parameter(Mandatory = $true, ParameterSetName = 'OCCConnector')]
    [ValidateNotNullOrEmpty()]
    [string]$customerID,

    [Parameter(Mandatory = $true, ParameterSetName = 'Sensorhub')]
    [Parameter(Mandatory = $true, ParameterSetName = 'OCCConnector')]
    [ValidateNotNullOrEmpty()]
    [string]$apikey,

    [Parameter(Mandatory = $true, ParameterSetName = 'Sensorhub')]
    [ValidateNotNullOrEmpty()]
    [string]$parentGuid,
    
    [Parameter(Mandatory = $true, ParameterSetName = 'OCCConnector')]
    [Switch]$OCCConnector,

    [Parameter(Mandatory = $false, ParameterSetName = 'Sensorhub')]
    [Parameter(Mandatory = $false, ParameterSetName = 'OCCConnector')]
    [ValidateScript({ Test-Path $_ })]
    [String]$SharedFolder,

    [Parameter(Mandatory = $false, ParameterSetName = 'Sensorhub')]
    [Parameter(Mandatory = $false, ParameterSetName = 'OCCConnector')]
    [switch]$cleanup,

    [Parameter(Mandatory = $false, ParameterSetName = 'Sensorhub')]
    [Parameter(Mandatory = $false, ParameterSetName = 'OCCConnector')]
    [string]$proxyIP,

    [Parameter(Mandatory = $false, ParameterSetName = 'Sensorhub')]
    [Parameter(Mandatory = $false, ParameterSetName = 'OCCConnector')]
    [string]$proxyPort,

    [Parameter(Mandatory = $false, ParameterSetName = 'Sensorhub')]
    [Parameter(Mandatory = $false, ParameterSetName = 'OCCConnector')]
    [string]$proxyUser,

    [Parameter(Mandatory = $false, ParameterSetName = 'Sensorhub')]
    [Parameter(Mandatory = $false, ParameterSetName = 'OCCConnector')]
    [string]$proxyPassword,

    [Parameter(Mandatory = $false, ParameterSetName = 'Sensorhub')]
    [Parameter(Mandatory = $false, ParameterSetName = 'OCCConnector')]
    [AllowNull()]
    [string[]]$templateid,

    [Parameter(Mandatory = $false, ParameterSetName = 'Sensorhub')]
    [Parameter(Mandatory = $false, ParameterSetName = 'OCCConnector')]
    [AllowNull()]
    [string]$UserId,

    [Parameter(Mandatory = $false, ParameterSetName = 'Sensorhub')]
    [Parameter(Mandatory = $false, ParameterSetName = 'OCCConnector')]
    [Switch]$Email,

    [Parameter(Mandatory = $false, ParameterSetName = 'Sensorhub')]
    [Parameter(Mandatory = $false, ParameterSetName = 'OCCConnector')]
    [Switch]$Phone,

    [Parameter(Mandatory = $false, ParameterSetName = 'Sensorhub')]
    [Parameter(Mandatory = $false, ParameterSetName = 'OCCConnector')]
    [Switch]$Ticket,

    [Parameter(Mandatory = $false, ParameterSetName = 'Sensorhub')]
    [Parameter(Mandatory = $false, ParameterSetName = 'OCCConnector')]
    [String]$DeferId

)

#region Internal Variables
$URL = "https://update.server-eye.de/download/se/ServerEyeSetup.exe"
$SetupPath = Join-Path -Path $env:TEMP -ChildPath "\ServerEyeSetup.exe"
$SEPath = "C:\Program Files (x86)\Server-Eye"
$CCConfig = Join-Path -Path $SEPath -ChildPath "config\se3_cc.conf"
$MACConfig = Join-Path -Path $SEPath -ChildPath "config\se3_mac.conf"
$ERSPath = Join-Path -Path $SEPath -ChildPath "ers\EmergencyAction.exe"
$SELogPath = Join-Path -Path $env:ProgramData -ChildPath "\ServerEye3\logs\"
$SEInstallLog = Join-Path -Path $SELogPath -ChildPath "installer.log"
$ErrorActionPreference ="Continue"  #to find errors use "Stop" here
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
# SIG # Begin signature block
# MIIlMgYJKoZIhvcNAQcCoIIlIzCCJR8CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU6csRbE4PG+9XlI+skK4yJ+UB
# K/Gggh8aMIIFQDCCBCigAwIBAgIQPoouYh6JSKCXNBstwZR1fDANBgkqhkiG9w0B
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
# MAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFAkai9vw971BZKk07U2jls/H
# q7/yMA0GCSqGSIb3DQEBAQUABIIBAN2DdUuwFdP/DhvOb7AYOfbSrT6tjyyk+WvD
# a25G0ksHedWHFX3/lC6fxAtfPlGQWh+OrrPYsdWBDy3JY1RsuLfbbtca8iIdSvol
# TEZfpmRH7SVnf/Ittdzli2FH//y0dgKhDfionlSU3kdkAfxOuHrbo+JIExLWgE5U
# RVSXky+O2+dLKRg6arxo+G3qKzzyetcoFFFUoKe6pwBX1TxFv3a0aMENR7z7T6B7
# g3449DGm8ttLlK1nWj1m6dh6XVatjcb5a2UgUM3l8Q/wqLEIj2+Ahfd/+a4P71Qq
# phZQqQRn2LqIhHKhyapRAyT/N1zJFVPYwdZmXs7/ajkMELtApRyhggNMMIIDSAYJ
# KoZIhvcNAQkGMYIDOTCCAzUCAQEwgZIwfTELMAkGA1UEBhMCR0IxGzAZBgNVBAgT
# EkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMP
# U2VjdGlnbyBMaW1pdGVkMSUwIwYDVQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0YW1w
# aW5nIENBAhEAjHegAI/00bDGPZ86SIONazANBglghkgBZQMEAgIFAKB5MBgGCSqG
# SIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIxMTExNTA3NTkw
# N1owPwYJKoZIhvcNAQkEMTIEMNbP8v2X+Unq1JBUxc6id5EXXVW3WVnc1mlapH3r
# 11uRLIgV2y26tUMld68MpC8QAzANBgkqhkiG9w0BAQEFAASCAgB1tniiezX2pKjC
# lF6IEqNd48h9DDPJPAE/etONr2ZUySbvbdyAI240kYF7rBCsNbcdNcV1500KhWRt
# boKfZBf7LI+PD10TZ/gZu6ugDjCJeanAR/r6NO3Bxi1UQ90mKYanj1lqSAijn4zq
# WesLQkR2IlmQDUNro8wYbILnNV9ctsQvCNXuYMBkrvDWU6SAeOlxijiybvVqesH3
# W2//fCWhF9xSAyrW+RN+SIUiIfnQ9/ctgNFyk3HzaWh/o+TyGO3sH4gN6y732fVs
# G57pdzt7rNUauyhELYg8VpcEHIBOsP9eyReEBK4FYBKf3FsIwSiBsclzJGkGnXLC
# QUwPDCnmb8ZNjkqnvv8P136kR+v1fmMvqQMja+2IOYbc0+wmTAauinnjncStFCoU
# KHATOMhFvVeSXRvGIHM+0wChevA9pGf+lYFNSP68RmTUzlcS2gnfI55z78SMj3ue
# 8H73pYSLOUAHsHplx8d0qEuJzBJ9Au7ViIJ9JF/CzRNuHgW+07X5fXoIoDyR1UY+
# 2iGyjLVE4qh6ZR+10qg2VMYgPCskMw8TBTQPAz557w9NYCCa32g1ezCeHUWhGw32
# 4idXUR+l3fG542QU9tHaZUC5PBsUGTzzJcA0EaDskt/Hkw2MWqwhLBrGJuV8EjiR
# 1+w9tZ/DZwYSa1Qm59NHzkfacUFPTw==
# SIG # End signature block
