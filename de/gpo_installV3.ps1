# Server-Eye GPO Install
# Version 3.0
# Author: Thomas Krammes
# Author: Andreas Behr
# Author: Rene Thulke
#
# Weitere Informationen zu diesem Skript finden Sie hier:
# https://servereye.freshdesk.com/support/solutions/articles/14000062437

# Die folgenden Werte muessen angepasst werden
$customer = ""
$templateid = ""
$apikey = ""
$parentGuid = ""
$ServerName = ""
$remoteLog = "\\$ServerName\se_install\$env:computername.txt" 
$logdatei = "C:\ProgramData\ServerEye3\logs\installer.log"
# Proxy if needed etc. "http://10.50.2.30:8080"
$proxy = $null

#
# Aendern Sie bitte nichts unterhalb dieser Zeile
#

# Download der aktuellen Version
$WebClient = New-Object System.Net.WebClient
$WebProxy = New-Object System.Net.WebProxy($proxy, $true)
$WebClient.Proxy = $WebProxy
$WebClient.DownloadFile("https://update.server-eye.de/download/se/ServerEyeSetup.exe", "$env:windir\temp\ServerEyeSetup.exe")

$arguments = "ARGUMENTS=install --cID $parentGuid --customerID $customer --apiKey $apikey --silent true"

# Installation Server-Eye
Set-Location "$env:windir\temp"

.\ServerEyeSetup.exe $arguments /quiet

Copy-Item $logdatei $remoteLog 
