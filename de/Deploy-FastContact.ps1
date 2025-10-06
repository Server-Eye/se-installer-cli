#Requires -RunAsAdministrator
<#
    .SYNOPSIS
    Deploy Fast Contact on a system.

    .DESCRIPTION
    This script installs Fast Contact on the system it's executed on, either by downloading the installer from a provided URL or using a local file path.
    First, the script checks if Fast Contact is already installed on the system.
    If not, it downloads the installer from a provided URL or uses a local file path, installs Fast Contact silently, and verifies the installation.

    .PARAMETER CustomerID
    The Customer ID for the Fast Contact installation.

    .PARAMETER ApiKey
    The API key for authenticating with the servereye API.

    .EXAMPLE
    PS> .\Deploy-FastContact.ps1 -CustomerID "1c06477e-33b9-446e-8e4e-639e9c09b973" -ApiKey "5a8104cc-e09c-44c1-99aa-41f85aba59a8"
    Demonstrates how to run the script with a CustomerID and ApiKey.

    .NOTES
    Author  : servereye
    Version : 1.1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]
    $CustomerID,

    [Parameter(Mandatory = $true)]
    [string]
    $ApiKey
)

#region Variables
$LogPath = "$env:windir\Temp\Deploy-FastContact.log"
$InstallerPath = "$env:windir\Temp\FCInstaller.msi"
#endregion

#region Functions
function Log {
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]
        $LogMessage,

        [Parameter(Mandatory=$false)]
        [string]
        $LogPath = $LogPath,

        [Parameter(Mandatory=$false)]
        [switch]
        $ToScreen = $false,

        [Parameter(Mandatory=$false)]
        [switch]
        $ToFile = $false,

        [Parameter(Mandatory=$false)]
        [ValidateSet(
            "Black", "DarkBlue", "DarkGreen", "DarkCyan", "DarkRed", "DarkMagenta",
            "DarkYellow", "Gray", "DarkGray", "Blue", "Green", "Cyan", "Red",
            "Magenta", "Yellow", "White"
        )]
        [string]
        $ForegroundColor = "Gray",

        [Parameter(Mandatory=$false)]
        [ValidateSet(
            "Black", "DarkBlue", "DarkGreen", "DarkCyan", "DarkRed", "DarkMagenta",
            "DarkYellow", "Gray", "DarkGray", "Blue", "Green", "Cyan", "Red",
            "Magenta", "Yellow", "White"
        )]
        [string]
        $BackgroundColor = "Black"
    )

    $Stamp = (Get-Date).toString("dd/MM/yyyy HH:mm:ss")
    $LogMessage = "[$Stamp] $LogMessage"

    if ($ToScreen) {
        Write-Host -Object $LogMessage -ForegroundColor $ForegroundColor -BackgroundColor $BackgroundColor
    }
    if ($ToFile) {
        Add-Content -Path $LogPath -Value $LogMessage
    }
}

function Test-FastContactInstallation {
    $UninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    $IsFound = $false
    foreach ($Path in $UninstallPaths) {
        $Keys = Get-ChildItem -Path $Path -ErrorAction SilentlyContinue
        foreach ($Key in $Keys) {
            $DisplayName = (Get-ItemProperty -Path $Key.PSPath -ErrorAction SilentlyContinue).DisplayName
            if ($DisplayName -eq "Fast Contact") {
                $IsFound = $true
                break
            }
        }
        if ($IsFound) { break }
    }

    if ($IsFound) {
        return $true
    } else {
        return $false
    }
}
#endregion

#region Main execution
Log "Welcome to the Fast Contact deployment script v1.1" -ToFile -ToScreen
Log "Starting deployment..." -ToFile -ToScreen

if (Test-FastContactInstallation) {
    Log "Fast Contact is already installed on this system. Exiting deployment script." -ToFile -ToScreen -ForegroundColor Yellow
    exit
}

try {
    Log "Downloading Fast Contact installer..." -ToFile -ToScreen
    $ProgressPreference = "SilentlyContinue"
    $null = Invoke-WebRequest `
        -Uri "https://update.server-eye.de/download/FastContact/FCInstaller.msi" `
        -OutFile $InstallerPath `
        -UseBasicParsing `
        -ErrorAction Stop
    Log "Successfully downloaded Fast Contact installer to '$InstallerPath'." -ToFile -ToScreen
}
catch {
    Log "Failed to download Fast Contact installer:`n$_" -ForegroundColor Red -ToFile -ToScreen
    exit
}

try {
    Log "Getting token for customer from servereye API..." -ToFile -ToScreen
    $Headers = @{
        "x-api-key" = $ApiKey
    }
    $Response = Invoke-WebRequest -Uri "https://fc-ui-api.server-eye.de/customer/$CustomerID/token" -Headers $Headers -Method Get -ContentType "application/json" -UseBasicParsing -ErrorAction Stop
    $SecurityToken = ($Response.Content | ConvertFrom-Json).token
    Log "Successfully retrieved token from servereye API." -ToFile -ToScreen
}
catch {
    Log "Failed to get token from servereye API:`n$_" -ForegroundColor Red -ToFile -ToScreen
    exit
}

Log "Starting installation of Fast Contact..." -ToFile -ToScreen
try {
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$InstallerPath`" CustomerID=`"$CustomerID`" SecurityToken=`"$SecurityToken`" /l*v FCInstaller.log /qn /norestart" -Wait -NoNewWindow
}
catch {
    Log "Fast Contact installation failed:`n$_" -ForegroundColor Red -ToFile -ToScreen
    exit
}

try {
    Log "Cleaning up installer file..." -ToFile -ToScreen
    Remove-Item -Path $InstallerPath -Force -ErrorAction Stop
    Log "Successfully cleaned up installer file." -ToFile -ToScreen
}
catch {
    Log "Failed to clean up installer file at '$($InstallerPath)', please delete it manually:`n$_" -ForegroundColor Yellow -ToFile -ToScreen
}

Log "Verifying if installation was successful..." -ToFile -ToScreen
if (Test-FastContactInstallation) {
    Log "Fast Contact was installed successfully." -ToFile -ToScreen -ForegroundColor Green
} else {
    Log "The installation of Fast Contact has failed.`nPlease contact the servereye Helpdesk for further assistance, and include the following file in your request: '$env:windir\Temp\FCInstaller.log'" -ForegroundColor Red -ToFile -ToScreen
}
#endregion