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
$customer = ""
$templateid = ""
$apikey = ""
$parentGuid = ""
$SharedFolder = "" 
# Proxy if needed etc. "http://10.50.2.30:8080"
$proxy = ""

#
# Aendern Sie bitte nichts unterhalb dieser Zeile
#



# Download der aktuellen Version
if (!(Test-Path $env:TEMP\ServerEyeSetup.exe)) {
    $WebClient = New-Object System.Net.WebClient
    if ($proxy) {
        $WebProxy = New-Object System.Net.WebProxy($proxy, $true)
        $WebClient.Proxy = $WebProxy 
    }
    $WebClient.DownloadFile("https://update.server-eye.de/download/se/ServerEyeSetup.exe", "$env:TEMP\ServerEyeSetup.exe")
}
#Erstellen der Prozess Argument
#region Arguments
if ($OCCConnector) {
    $startProcessParams = @{
        FilePath               = "$env:TEMP\ServerEyeSetup.exe"
        ArgumentList           = '"ARGUMENTS=newConnector --customerID=' + $customer + ' --apiKey=' + $apikey + ' --silent=true"' + " /quiet"
        Wait                   = $true;
        NoNewWindow            = $true;
    } 
}
else {
    $startProcessParams = @{
        FilePath               = "$env:TEMP\ServerEyeSetup.exe"
        ArgumentList           = '"ARGUMENTS=install --cID=' + $parentGuid + ' --customerID=' + $customer + ' --apiKey=' + $apikey + ' --silent=true"' + " /quiet"
        Wait                   = $true;
        NoNewWindow            = $true;
    }
}
#endregion Arguments


# Installation Server-Eye
if (!(Test-Path 'C:\Program Files (x86)\Server-Eye\ers\EmergencyAction.exe')) {
    Start-Process @startProcessParams

    $SEInstallLog = Get-ChildItem -Path $env:ProgramData\ServerEye3\logs\ -Filter installer.log
    $MSILog = Get-ChildItem -Path $env:TEMP -Filter Server-Eye_*
    $remoteLog = "$SharedFolder\$env:computername.zip"
    
    Compress-Archive -Path $SEInstallLog -DestinationPath $remoteLog  -CompressionLevel Fastest -Update
    foreach ($log in $MSILog) {
        Compress-Archive -Path $log.FullName -DestinationPath $remoteLog  -CompressionLevel Fastest -Update
    } 
}
