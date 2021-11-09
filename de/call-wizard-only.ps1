<#
    .SYNOPSIS
    Install Server-Eye via Commandline.
    
    .DESCRIPTION
    Install Server-Eye via Commandline with the Wizard.
        
    .PARAMETER customerID
    ID of the Customer, where the System should be installed

    .PARAMETER apikey
    APIKey to install the System

    .PARAMETER parentGuid
    ID of the OCC-Connector where the Sensorhub should be installed

    .PARAMETER OCCConnector
    A OCC-Connector will be installed on the System

    .PARAMETER proxyIP
    IP of the Proxy

    .PARAMETER proxyPort
    Port of the Proxy

    .PARAMETER proxyUser
    User to authenticate against the Proxy

    .PARAMETER proxyPassword
    Password for the Proxy User to authenticate against the Proxy

    .EXAMPLE
    Sensorhub 
    call-wizard-only.ps1 -customerID "CustomerID" -apikey "APIKey" -parentGuid "OCC-Connector ID"

    .EXAMPLE
    OCC-Connector
    call-wizard-onlyps1 -customerID "CustomerID" -apikey "APIKey" -OCCConnector

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
    [string]$proxyIP,

    [Parameter(Mandatory = $false, ParameterSetName = 'Sensorhub')]
    [Parameter(Mandatory = $false, ParameterSetName = 'OCCConnector')]
    [string]$proxyPort,

    [Parameter(Mandatory = $false, ParameterSetName = 'Sensorhub')]
    [Parameter(Mandatory = $false, ParameterSetName = 'OCCConnector')]
    [string]$proxyUser,

    [Parameter(Mandatory = $false, ParameterSetName = 'Sensorhub')]
    [Parameter(Mandatory = $false, ParameterSetName = 'OCCConnector')]
    [string]$proxyPassword

)
#region Internal Variables

$SEPath = "C:\Program Files (x86)\Server-Eye"
$ExePath = Join-Path -Path $SEPath -ChildPath "\service\1\Wizard.exe"
$SELogPath = Join-Path -Path $env:ProgramData -ChildPath "\ServerEye3\logs\"
$SEInstallLog = Join-Path -Path $SELogPath -ChildPath "installer.log"
#endregion Internal Variables

#region Build Proxy
if ($proxyIP) {
    Write-Output "Proxy IP Detected" 
    $buildproxy = "{0}:{1}" -f $proxyIP, $proxyPort
    if ($proxyUser) {
        Write-Output "Create Secure Password" 
        $PWord = ConvertTo-SecureString -String $proxyPassword -AsPlainText -Force
        if ($proxyDomain) {
            Write-Output "Build User with Domain" 
            $proxyCred = "{0}\{1}" -f $proxyDomain, $proxyuser
        }
        else {
            Write-Output "Build User without Domain" 
            $proxyCred = $proxyUser
        }
        Write-Output "Build Secure Credential" 
        $Cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ProxyCred, $PWord
        
    }
}
#Endregion Build Proxy

#Erstellen der Prozess Argument
#region Arguments

Write-Output "Starting Argument"
if ($OCCConnector) {
    Write-Output "Argument for OCC-Connector"
    $Install = "newConnector"
}
else {
    Write-Output "Argument for Sensorhub"
    $Install = "install --cID={0}" -f $parentGuid
}
if ($proxyIP) {
    Write-Output "Argument with Proxy URL"
    $Proxy = " --proxyUrl={0} --proxyPort={1}" -f $proxyIP, $proxyport
    if ($proxyUser) {
        Write-Output "Argument with Authentication Proxy"
        $proxy = "{0} --proxyUser={1} --proxyPassword={2}" -f $Proxy, $proxyUser, $proxyPassword
    }
    if ($proxyDomain) {
        Write-Output "Argument with Authentication Proxy with Domain"
        $proxy = "{0} --proxyDomain={1}" -f $Proxy, $proxyDomain
    }
}
else {
    $proxy = $null
}
$argument = "{0} --customerID={1} --apiKey={2} --silent=true{3}{4}" -f $Install, $customerID, $apikey, $template, $Proxy
$startProcessParams = @{
    FilePath     = $ExePath
    ArgumentList = $argument       
    Wait         = $true;
    NoNewWindow  = $true;
    Passthru     = $true;
} 
Write-Output "Finished Argument construction"
#endregion Arguments

# Wizard Server-Eye
Write-Output "Check Server-Eye Wizard State"
Write-Output "Starting Server-Eye Wizard"
$Wizard = Start-Process @startProcessParams
Write-Output "Server-Eye Wizard finished with Exitcode: $($Wizard.ExitCode)"