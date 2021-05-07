# Server-Eye GPO Install
# Version 2.0
# Author: Thomas Krammes
# Author: Andreas Behr
#
# Weitere Informationen zu diesem Skript finden Sie hier:
# https://servereye.freshdesk.com/support/solutions/articles/14000062437

# Die folgenden Werte muessen angepasst werden
$customer=""
$secret=""
$templateid=""
$apikey=""
$parentGuid=""
$logdatei="c:\se_install_log.txt"
$remoteLog="\\fileserver\se_install\$env:computername.txt"
# Proxy if needed etc. "http://10.50.2.30:8080"
$proxy = $null
$proxyuser = $null
$proxyPassword = $null
$proxyDomain = $null
# Ändern auf $true wenn keine Log bei bestehender Installtion gewünscht sind
$noinstallLog = $false

#
# Aendern Sie bitte nichts unterhalb dieser Zeile
#

# Download der aktuellen Version
$WebClient = New-Object System.Net.WebClient
$WebProxy = New-Object System.Net.WebProxy($proxy,$true)
if ($proxyuser) {
    $WebProxy.Credentials = new-object System.Net.NetworkCredential($proxyuser, $proxyPassword)
}
$WebClient.Proxy = $WebProxy
$WebClient.DownloadFile("https://occ.server-eye.de/download/se/Deploy-ServerEye.ps1","$env:windir\temp\ServerEye.ps1")


# Installation Server-Eye
Set-Location "$env:windir\temp"

If ($noinstallLog -eq $true){
    .\ServerEye.ps1 -Download -Install -Deploy SensorhubOnly -ParentGuid $parentGuid -Customer $customer -Secret $secret -ApplyTemplate -TemplateId $templateid -ApiKey $apikey -DeployPath "$env:windir\temp" -LogFile $logdatei -Silent -proxy $WebProxy -SkipLogInstalledCheck
}
else {
    .\ServerEye.ps1 -Download -Install -Deploy SensorhubOnly -ParentGuid $parentGuid -Customer $customer -Secret $secret -ApplyTemplate -TemplateId $templateid -ApiKey $apikey -DeployPath "$env:windir\temp" -LogFile $logdatei -Silent -proxy $WebProxy
}


Copy-Item $logdatei $remoteLog 
