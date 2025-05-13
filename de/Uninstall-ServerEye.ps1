#Requires -Version 5.0
#Requires -RunAsAdministrator

<# 
    .SYNOPSIS
    Uninstall Server-Eye

    .DESCRIPTION
    This Script will Uninstall Server-Eye and deletes all Server-Eye Data from the System.

    .PARAMETER Apikey
    To Remove Sensorhubs set this API Key

    .PARAMETER OCCConnector
    Set as Parameter if OCC-Connector should be removed if present

    
#>

Param ( 
    [Parameter(Mandatory = $false,
        HelpMessage = "To Remove Sensorhubs set this API Key")] 
    [String]$Apikey,

    [Parameter(Mandatory = $false,
        HelpMessage = "Set as Parameter if OCC-Connector should be removed if present, default is 0 for not.")] 
    [ValidateSet(0, 1)]
    [Int] $OCCConnector = 0  
)


#region Register Eventlog Source
try { New-EventLog -Source $EventSourceName -LogName $EventLogName -ErrorAction Stop | Out-Null }
catch { }
#endregion Register Eventlog Source

#region StopSEServices
$services = Get-Service -DisplayName Server-Eye* | Where-Object Status -EQ "Running"

if ($services) {
    Stop-Service $services
    $SECCService = Get-Service -Name CCService
    $SEMACService = Get-Service -Name MACService
    $SERecovery = Get-Service -Name SE3Recovery
    for ($i = 0; $i -le 20; $i++) {
        $SECCService = Get-Service -Name CCService
        $SEMACService = Get-Service -Name MACService
        $SERecovery = Get-Service -Name SE3Recovery
    
        if ($SECCService.Status -eq "Stopped" -and $SEMACService.Status -eq "Stopped" -and $SERecovery.Status -eq "Stopped") {
            break
        }
    
        Start-Sleep -Seconds 3
    }
}
#endregion StopSEServices

#region Internal Variables
$CCConf = "se3_cc.conf"
$MACConf = "se3_mac.conf"
$EventLogName = "Application"
$EventSourceName = "ServerEye-Custom"
$SEDataPath = "$env:ProgramData\ServerEye3"
if ($env:PROCESSOR_ARCHITECTURE -eq "x86") {
    $SEInstPath = "$env:ProgramFiles\Server-Eye"
}
else {
    $SEInstPath = "${env:ProgramFiles(x86)}\Server-Eye"
}
$SEConfigFolder = "config"
$ARRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
$AROn = "0"
$AROff = "262144"
$ARRegProperty = "DefaultLevel"
$SETasksName = "Server-Eye Tasks"
$WinTasksPath = "C:\Windows\System32\Tasks"
$SETasksPath = Join-Path -Path $WinTasksPath -ChildPath $SETasksName

$autoupdate = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate"

#endregion Internal Variables

#region Helper Function
#region RemoveOnReboot
Function Register-FileToDelete {
    <#
        .SYNOPSIS
            Registers a file/s or folder/s for deletion after a reboot.

        .DESCRIPTION
            Registers a file/s or folder/s for deletion after a reboot.

        .PARAMETER Source
            Collection of Files/Folders which will be marked for deletion after a reboot

        .NOTES
            Name: Register-FileToDelete
            Author: Boe Prox
            Created: 28 SEPT 2013

        .EXAMPLE
            Register-FileToDelete -Source 'C:\Users\Administrators\Desktop\Test.txt'
            True

            Description
            -----------
            Marks the file Test.txt for deletion after a reboot.

        .EXAMPLE
            Get-ChildItem -File -Filter *.txt | Register-FileToDelete -WhatIf
            What if: Performing operation "Mark for deletion" on Target "C:\Users\Administrator\Des
            ktop\SQLServerReport.ps1.txt".
            What if: Performing operation "Mark for deletion" on Target "C:\Users\Administrator\Des
            ktop\test.txt".


            Description
            -----------
            Uses a WhatIf switch to show what files would be marked for deletion.
    #>
    [cmdletbinding(
        SupportsShouldProcess = $True
    )]
    Param (
        [parameter(ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True)]
        [Alias('FullName', 'File', 'Folder')]
        $Source = 'C:\users\Administrator\desktop\test.txt'    
    )
    Begin {
        Try {
            $null = [File]
        }
        Catch { 
            Write-Verbose 'Compiling code to create type'   
            Add-Type @"
            using System;
            using System.Collections.Generic;
            using System.Linq;
            using System.Text;
            using System.Runtime.InteropServices;
        
            public class Posh
            {
                public enum MoveFileFlags
                {
                    MOVEFILE_REPLACE_EXISTING           = 0x00000001,
                    MOVEFILE_COPY_ALLOWED               = 0x00000002,
                    MOVEFILE_DELAY_UNTIL_REBOOT         = 0x00000004,
                    MOVEFILE_WRITE_THROUGH              = 0x00000008,
                    MOVEFILE_CREATE_HARDLINK            = 0x00000010,
                    MOVEFILE_FAIL_IF_NOT_TRACKABLE      = 0x00000020
                }

                [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
                static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, MoveFileFlags dwFlags);
                public static bool MarkFileDelete (string sourcefile)
                {
                    bool brc = false;
                    brc = MoveFileEx(sourcefile, null, MoveFileFlags.MOVEFILE_DELAY_UNTIL_REBOOT);          
                    return brc;
                }
            }
"@
        }
    }
    Process {
        ForEach ($item in $Source) {
            Write-Verbose ('Attempting to resolve {0} to full path if not already' -f $item)
            $item = (Resolve-Path -Path $item).ProviderPath
            If ($PSCmdlet.ShouldProcess($item, 'Mark for deletion')) {
                If (-NOT [Posh]::MarkFileDelete($item)) {
                    Try {
                        Throw (New-Object System.ComponentModel.Win32Exception)
                    }
                    Catch { Write-Warning $_.Exception.Message }
                }
            }
        }
    }
}
#endregion RemoveOnReboot

#region RemoveContainer
Function Remove-Container {
    [cmdletbinding(
    )]
    Param (
        [Parameter(Mandatory = $true)]
        [alias("ApiKey", "Session")]
        $AuthToken,
        [parameter(Mandatory = $true)]
        $ID
    )

    Invoke-RestMethod -Uri "https://api.server-eye.de/2/container/$Id" -Method Delete -Headers @{"x-api-key" = $AuthToken }

}
#endregion RemoveContainer

#region RemoveScheduledTask
Function Remove-ScheduledTask {
    [cmdletbinding(
    )]
    Param (
        [Parameter(Mandatory = $true)]
        $task
    )
    Unregister-ScheduledTask -Confirm:$false -InputObject $task
}
#endregion RemoveScheduledTask

#region RemoveScheduledTaskFolder
Function Remove-ScheduledTaskFolder {
    [cmdletbinding(
    )]
    Param (
        [Parameter(Mandatory = $true)]
        $Folder
    )
    Remove-Item -Path $Folder -Recurse -Force
}
#endregion RemoveScheduledTaskFolder

#region RemoveLocalFiles
Function Remove-LocalFiles {
    [cmdletbinding(
    )]
    Param (
        [Parameter(Mandatory = $true)]
        $Path
    )
    try {
        Write-Output "Server-Eye Data on the System, will be deleted."
        Remove-Item -Path $Path -Recurse -ErrorAction Stop
    }
    catch {
        if ($_.FullyQualifiedErrorId -like "InvalidOperation,Microsoft.PowerShell.Commands.RemoveItemCommand") {
            Write-Output "Error Removeing Files will add them to Remove on Reboot"
            $items = Get-ChildItem -Path $Path -Recurse
            $items | Foreach-object { Register-FileToDelete -Source $_.FullName }
            Register-FileToDelete -Source $Path
        }
        else {
            Write-Output $_
        }
            
    }
}
#endregion RemoveLocalFiles

#region RemoveSmartUpdates
Function Remove-SESU {
    [CmdletBinding()]
    Param(
    )
    
    $PSINIFilePAth = "C:\Windows\System32\GroupPolicy\Machine\Scripts"
    $PSINICMDFileName = "scripts.ini"
    $PSINIPSFileName = "psscripts.ini"
    $TriggerPatchRun = Join-Path -Path $SEInstPath -ChildPath "triggerPatchRun.*"
    $PSCMDINIPath = Join-Path -Path $PSINIFilePAth -ChildPath $PSINICMDFileName
    $PSPSINIPath = Join-Path -Path $PSINIFilePAth -ChildPath $PSINIPSFileName
    
    $PSINIRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Shutdown\0"
    $SURegKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    
    $Keys = Get-ChildItem -Path $PSINIRegPath -ErrorAction SilentlyContinue
    $KeyToRemove = Get-ItemProperty -Path $keys.PSPath -Name "Script" | Where-Object -Property Script -like -Value $TriggerPatchRun
    #region INI
    
    if (Test-Path $PSCMDINIPath) {
        Write-Verbose "Checking $PSINICMDFileName File for SU Script"
        $content = Get-Content $PSCMDINIPath
        $string = $content | Select-String -Pattern "triggerPatchRun.cmd"
        if ($string) {
            $SetNumber = ($string.ToString()).Substring(0, 1)
            Write-Verbose "Remove Lines form File"
            $content | Select-String -Pattern $SetNumber -NotMatch | Set-Content -Path $PSCMDINIPath 
        }
        else {
            Write-Verbose "No Lines in File"
        }
    }
    if (Test-Path $PSPSINIPath) {
        Write-Verbose "Checking $PSINIPSFileName File for SU Script"
        $content = Get-Content $PSPSINIPath
        $string = $content | Select-String -Pattern "triggerPatchRun.ps1"
        if ($string) {
            $SetNumber = ($string.ToString()).Substring(0, 1)
            Write-Verbose "Remove Lines form File"
            $content | Select-String -Pattern $SetNumber -NotMatch | Set-Content -Path $PSPSINIPath 
        }
        else {
            Write-Verbose "No Lines in File"
        }
    }
    #endregion INI
    
    #region Reg
    if ($KeyToRemove) {
        if (Test-Path $KeyToRemove.PSPath) {
            Write-Verbose "Remove Linies form Registry"
            Remove-Item $KeyToRemove.PSPath
        }
    }
    #endregion Reg
    if (Test-Path $SURegKey) {
        Remove-Item -Path $SURegKey -Recurse
    }
    Write-Verbose "Call GPUpdate"
    gpupdate.exe /force
}
#endregion RemoveSmartUpdates

#region FindContainerID
Function Find-ContainerID {
    [cmdletbinding(
    )]
    Param (
        [Parameter(Mandatory = $true)]
        $Path
    )

    Write-Output (Get-Content $Path | Select-String -Pattern "\bguid=\b").ToString().Replace("guid=", "")

}
#endregion FindContainerID

#region SEAntiRansom
Function Remove-SEAntiRansom {
    [cmdletbinding(
    )]
    Param (
        [Parameter(Mandatory = $true)]
        $Path,
        [Parameter(Mandatory = $true)]
        $On,
        [Parameter(Mandatory = $true)]
        $Off,
        [Parameter(Mandatory = $true)]
        $Property

    )
    $OS=Get-CimInstance -ClassName Win32_OperatingSystem
    If ($OS.BuildNumber -ge 22621 ){
            $keys =Get-Childitem hklm:SOFTWARE\Policies\Microsoft\Windows\SRPV2
            foreach($key in $keys.name){
                $Key=$key.Replace("HKEY_LOCAL_MACHINE\","HKLM:")
                set-ItemProperty -Path $key -Name "EnforcementMode" -Value 0
                Get-ChildItem "C:\Windows\System32\AppLocker\" | Remove-Item -Force
            }
        }
    else{

            If ((Get-ItemPropertyValue -Path $Path -Name DefaultLevel) -eq $On) {
                Write-EventLog -LogName $EventLogName -Source $EventSourceName -EventID 3004 -EntryType Information -Message "Remove Server-Eye Anti-Ransom"
                Set-ItemProperty -Path $ARRegPath -Name $Property -Value $Off
            }

    }

}
#endregion SEAntiRansom

#endregion Helper Function
#region Uninstall
if ((Test-Path $SEInstPath) -eq $true) {
    if (Test-Path $ARRegPath) {
        Remove-SEAntiRansom -Path $ARRegPath -On $AROn -Off $AROff -Property $ARRegProperty 
    }
    #region Remove Container via InstPath Config
    if ($Apikey) {
        try {
            If ((Test-Path "$SEInstPath\$SEConfigFolder\$MACConf") -and ($OCCConnector -ne 0)) {
                $MACId = Find-ContainerID -Path "$SEInstPath\$SEConfigFolder\$MACConf"
                Remove-Container -AuthToken $Apikey -id $MACId
                Write-EventLog -LogName $EventLogName -Source $EventSourceName -EventID 3001 -EntryType Information -Message "OCC-Connector was removed" 
                Write-Output "OCC-Connector was removed" 
            }
            elseIf (Test-Path "$SEInstPath\$SEConfigFolder\$CCConf") {
                $CId = Find-ContainerID -Path "$SEInstPath\$SEConfigFolder\$CCConf"
                Remove-Container -AuthToken $Apikey -id $CId
                Write-EventLog -LogName $EventLogName -Source $EventSourceName -EventID 3001 -EntryType Information -Message "Sensorhub was removed."
                Write-Output "Sensorhub was removed" 
            }


        }
        catch {
            Write-EventLog -LogName $EventLogName -Source $EventSourceName -EventID 3010 -EntryType Error -Message "Error: $_"
            Write-Output "Error: $_"
        }
        
    }
    #endregion Remove Container via InstPath Config
    try {
        Write-EventLog -LogName $EventLogName -Source $EventSourceName -EventID 3000 -EntryType Information -Message "Server-Eye Installation found." -ErrorAction SilentlyContinue
        $progs = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
        $sesetup = $progs | Where-Object { ($_.Displayname -eq "Server-Eye") -and ($_.QuietUninstallString -like '"C:\ProgramData\Package Cache\*\ServerEyeSetup.exe" /uninstall /quiet') }
        $sevendors = $progs | Where-Object { ($_.Displayname -eq "Server-Eye Vendor Package") }
        $seservereye = $progs | Where-Object { ($_.Displayname -eq "Server-Eye") }
        if ($sesetup) {
            Write-EventLog -LogName $EventLogName -Source $EventSourceName -EventID 3002 -EntryType Information -Message "Performing uninstallation of Server-Eye via Setup" -ErrorAction SilentlyContinue
            Write-Output "Performing uninstallation of Server-Eye via Setup"
            Start-Process -FilePath $sesetup.BundleCachePath -ArgumentList "/uninstall /quiet"
            
        }
        elseif ($sevendors) {
            Write-EventLog -LogName $EventLogName -Source $EventSourceName -EventID 3003 -EntryType Information -Message "Performing uninstallation of Server-Eye via MSI"
            Write-Output "Performing uninstallation of Server-Eye via MSI"
            foreach ($sevendor in $sevendors) {
                $sechildname = $sevendor.pschildname
                Start-Process msiexec.exe -Wait -ArgumentList "/x $sechildname /q"
            }  
            $sechildname = $seservereye.pschildname
            Start-Process msiexec.exe -Wait -ArgumentList "/x $sechildname /q"

        }
        Remove-LocalFiles -Path $SEDataPath
        $SETasks = Get-ScheduledTask -TaskPath "\Server-Eye Tasks\" -ErrorAction SilentlyContinue
        if ($SETasks) {
            Write-Output "Remove all Server-Eye Scheduled Tasks" 
            Unregister-ScheduledTask -InputObject $SETasks -Confirm:$false
            if ((Test-Path $SETasksPath) -eq $true) {
                Remove-ScheduledTaskFolder -Folder $SETasksPath
            }
        }
        Remove-SESU
    }
    catch {
        Write-Host "Eventlog nicht gefunden!"
    }

}
#endregion Uninstall
#region RemoveSEDataOnly
elseif (((Test-Path $SEDataPath) -eq $true)) {
    if (Test-Path $ARRegPat) {
    Remove-SEAntiRansom -Path $ARRegPath -On $AROn -Off $AROff -Property $ARRegProperty 
    }
    #region Remove Container via DataPath Config
    if ($Apikey) {
        try {
            if ((Test-Path "$SEDataPath\$MACConf") -and ($OCCConnector -ne 0)) {
                $MACId = Find-ContainerID "$SEDataPath\$MACConf"
                Remove-Container -AuthToken $Apikey -id $MACId
                Write-EventLog -LogName $EventLogName -Source $EventSourceName -EventID 3001 -EntryType Information -Message "OCC-Connector was removed" 
                Write-Output "OCC-Connector was removed"
            }
            elseif (Test-Path "$SEDataPath\$CCConf") {
                $CId = Find-ContainerID -Path "$SEDataPath\$CCConf"
                Remove-Container -AuthToken $Apikey -id $CId
                Write-EventLog -LogName $EventLogName -Source $EventSourceName -EventID 3001 -EntryType Information -Message "Sensorhub was removed."
                Write-Output "Sensorhub was removed"
            }


        }
        catch {
            Write-EventLog -LogName $EventLogName -Source $EventSourceName -EventID 3010 -EntryType Error -Message "Error: $_"
            Write-Output "Error: $_"
        }
        
    }
    #endregion Remove Container via DataPath Config
    try {
        Remove-LocalFiles -Path $SEDataPath
        $SETasks = Get-ScheduledTask -TaskPath "\Server-Eye Tasks\" -ErrorAction SilentlyContinue
        if ($SETasks) {
            Write-Output "Remove all Server-Eye Scheduled Tasks" 
            Unregister-ScheduledTask -InputObject $SETasks -Confirm:$false
            if ((Test-Path $SETasksPath) -eq $true) {
                Remove-ScheduledTaskFolder -Folder $SETasksPath
            }
        }
        Remove-SESU
    }
    catch {
        Write-EventLog -LogName $EventLogName -Source $EventSourceName -EventID 3010 -EntryType Error -Message "Error: $_"
        Write-Output "Error: $_" 
    }

}
#endregion RemoveSEDataOnly
else {
    Write-Output "No Server-Eye Installation was found"
}
# SIG # Begin signature block
# MIIq2QYJKoZIhvcNAQcCoIIqyjCCKsYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBNfWaUB5WOHurg
# FxFuM4KwnGoYyRs+7cNTZ6gHPzVH4qCCJHAwggVvMIIEV6ADAgECAhBI/JO0YFWU
# jTanyYqJ1pQWMA0GCSqGSIb3DQEBDAUAMHsxCzAJBgNVBAYTAkdCMRswGQYDVQQI
# DBJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcMB1NhbGZvcmQxGjAYBgNVBAoM
# EUNvbW9kbyBDQSBMaW1pdGVkMSEwHwYDVQQDDBhBQUEgQ2VydGlmaWNhdGUgU2Vy
# dmljZXMwHhcNMjEwNTI1MDAwMDAwWhcNMjgxMjMxMjM1OTU5WjBWMQswCQYDVQQG
# EwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS0wKwYDVQQDEyRTZWN0aWdv
# IFB1YmxpYyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQCN55QSIgQkdC7/FiMCkoq2rjaFrEfUI5ErPtx94jGgUW+s
# hJHjUoq14pbe0IdjJImK/+8Skzt9u7aKvb0Ffyeba2XTpQxpsbxJOZrxbW6q5KCD
# J9qaDStQ6Utbs7hkNqR+Sj2pcaths3OzPAsM79szV+W+NDfjlxtd/R8SPYIDdub7
# P2bSlDFp+m2zNKzBenjcklDyZMeqLQSrw2rq4C+np9xu1+j/2iGrQL+57g2extme
# me/G3h+pDHazJyCh1rr9gOcB0u/rgimVcI3/uxXP/tEPNqIuTzKQdEZrRzUTdwUz
# T2MuuC3hv2WnBGsY2HH6zAjybYmZELGt2z4s5KoYsMYHAXVn3m3pY2MeNn9pib6q
# RT5uWl+PoVvLnTCGMOgDs0DGDQ84zWeoU4j6uDBl+m/H5x2xg3RpPqzEaDux5mcz
# mrYI4IAFSEDu9oJkRqj1c7AGlfJsZZ+/VVscnFcax3hGfHCqlBuCF6yH6bbJDoEc
# QNYWFyn8XJwYK+pF9e+91WdPKF4F7pBMeufG9ND8+s0+MkYTIDaKBOq3qgdGnA2T
# OglmmVhcKaO5DKYwODzQRjY1fJy67sPV+Qp2+n4FG0DKkjXp1XrRtX8ArqmQqsV/
# AZwQsRb8zG4Y3G9i/qZQp7h7uJ0VP/4gDHXIIloTlRmQAOka1cKG8eOO7F/05QID
# AQABo4IBEjCCAQ4wHwYDVR0jBBgwFoAUoBEKIz6W8Qfs4q8p74Klf9AwpLQwHQYD
# VR0OBBYEFDLrkpr/NZZILyhAQnAgNpFcF4XmMA4GA1UdDwEB/wQEAwIBhjAPBgNV
# HRMBAf8EBTADAQH/MBMGA1UdJQQMMAoGCCsGAQUFBwMDMBsGA1UdIAQUMBIwBgYE
# VR0gADAIBgZngQwBBAEwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21v
# ZG9jYS5jb20vQUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNAYIKwYBBQUHAQEE
# KDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wDQYJKoZI
# hvcNAQEMBQADggEBABK/oe+LdJqYRLhpRrWrJAoMpIpnuDqBv0WKfVIHqI0fTiGF
# OaNrXi0ghr8QuK55O1PNtPvYRL4G2VxjZ9RAFodEhnIq1jIV9RKDwvnhXRFAZ/ZC
# J3LFI+ICOBpMIOLbAffNRk8monxmwFE2tokCVMf8WPtsAO7+mKYulaEMUykfb9gZ
# pk+e96wJ6l2CxouvgKe9gUhShDHaMuwV5KZMPWw5c9QLhTkg4IUaaOGnSDip0TYl
# d8GNGRbFiExmfS9jzpjoad+sPKhdnckcW67Y8y90z7h+9teDnRGWYpquRRPaf9xH
# +9/DUp/mBlXpnYzyOmJRvOwkDynUWICE5EV7WtgwggWNMIIEdaADAgECAhAOmxiO
# +dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYD
# VQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAi
# BgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAw
# MDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdp
# Q2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERp
# Z2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsb
# hA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iT
# cMKyunWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGb
# NOsFxl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclP
# XuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCr
# VYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFP
# ObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTv
# kpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWM
# cCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls
# 5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBR
# a2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6
# MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qY
# rhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8E
# BAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5k
# aWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDig
# NoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9v
# dENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCg
# v0NcVec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQT
# SnovLbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh
# 65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSw
# uKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAO
# QGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjD
# TZ9ztwGpn1eqXijiuZQwggXSMIIEOqADAgECAhEAt4SvG7AxI7MH8AJVKBjFCDAN
# BgkqhkiG9w0BAQwFADBUMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBM
# aW1pdGVkMSswKQYDVQQDEyJTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgQ0Eg
# UjM2MB4XDTIzMDMyMTAwMDAwMFoXDTI1MDMyMDIzNTk1OVowaDELMAkGA1UEBhMC
# REUxETAPBgNVBAgMCFNhYXJsYW5kMSIwIAYDVQQKDBlLcsOkbWVyIElUIFNvbHV0
# aW9ucyBHbWJIMSIwIAYDVQQDDBlLcsOkbWVyIElUIFNvbHV0aW9ucyBHbWJIMIIB
# ojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA0x/0zEp+K0pxzmY8FD9pBsw/
# d6ZMxeqsbQbqhyFx0VcqOvk9ZoRaxg9+ac4w5hmqo2u4XmWp9ckBeWPQ/5vXJHyR
# c23ktX/rBipFNWVf2BFLInDoChykOkkAUVjozJmX7T51ZEIhprQ3f88uzAWJnRQi
# RzL1qikEH7g1hSTt5wj30kNcDVhuhU38sKiBWiTTdcrRm9YnYi9N/UIV15xQ94iw
# kqIPopmmelo/RywDsgkPcO9gv3hzdYloVZ4daBZDYoPW9BBjmx4MWJoPHJcuiZ7a
# nOroabVccyzHoZm4Sfo8PdjaKIQBvV6xZW7TfBXO8Xta1LeF4L2Z1X2uHRIlqJYG
# yYQ0bKrRNcLJ4V2NqaxRNQKoQ8pH0/GhMd28rr92tiKcRe8dMM6aI91kXuPdivT5
# 9oCBA0yYNWCDWjn+NVgPGfJFr/v/yqfx6snNJRm9W1DO4JFV9GKMDO8vJVqLqjle
# 91VCPsHfeBExq5cWG/1DrnsfmaCc5npYXoHvC3O5AgMBAAGjggGJMIIBhTAfBgNV
# HSMEGDAWgBQPKssghyi47G9IritUpimqF6TNDDAdBgNVHQ4EFgQUJfYD1cPwKBBK
# OnOdQN2O+2K4rH4wDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwSgYDVR0gBEMwQTA1BgwrBgEEAbIxAQIBAwIwJTAjBggr
# BgEFBQcCARYXaHR0cHM6Ly9zZWN0aWdvLmNvbS9DUFMwCAYGZ4EMAQQBMEkGA1Ud
# HwRCMEAwPqA8oDqGOGh0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGlnb1B1Ymxp
# Y0NvZGVTaWduaW5nQ0FSMzYuY3JsMHkGCCsGAQUFBwEBBG0wazBEBggrBgEFBQcw
# AoY4aHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljQ29kZVNpZ25p
# bmdDQVIzNi5jcnQwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29t
# MA0GCSqGSIb3DQEBDAUAA4IBgQBTyTiSpjTIvy6OVDj1144EOz1XAcESkzYqknAy
# aPK1N/5nmCI2rfy0XsWBFou7M3JauCNNbfjEnYCWFKF5adkgML06dqMTBHrlIL+D
# oMRKVgfHuRDmMyY2CQ3Rhys02egMvHRZ+v/lj4w8y1WQ1KrG3W4oaP6Co5mDhcN6
# oS7eDOc523mh4BkUcKsbvJEFIqNQq6E+HU8qmKXh6HjyAltsxLGJfYdiydI11j8z
# 7+6l3+O241vxJ74KKeWaX+1PXS6cE+k6qJm8sqcDicwxm728RbdJQ2TfPS/xz8gs
# X7c39/lemAEVd9sGNdFPPHjMsvIYb5ed27BdwQjx53xB4reS80v+KA+fBPaUoSID
# t/s1RDDTiIRShNvQxdR8HCq3c15qSWprGZ0ivCzi52UrqmIjDpfyMDfX4WanbMwq
# 7iuFL2Kc9Mp6xzXgO1YWkWqh9dH5qj3tjEj1y+2W7SQyuEzzrcCUMk+iwlJLX5d5
# 2hNr3HnIM9KBulPlYeSQrpjVaA8wggYaMIIEAqADAgECAhBiHW0MUgGeO5B5FSCJ
# IRwKMA0GCSqGSIb3DQEBDAUAMFYxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0
# aWdvIExpbWl0ZWQxLTArBgNVBAMTJFNlY3RpZ28gUHVibGljIENvZGUgU2lnbmlu
# ZyBSb290IFI0NjAeFw0yMTAzMjIwMDAwMDBaFw0zNjAzMjEyMzU5NTlaMFQxCzAJ
# BgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxKzApBgNVBAMTIlNl
# Y3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYwggGiMA0GCSqGSIb3DQEB
# AQUAA4IBjwAwggGKAoIBgQCbK51T+jU/jmAGQ2rAz/V/9shTUxjIztNsfvxYB5UX
# eWUzCxEeAEZGbEN4QMgCsJLZUKhWThj/yPqy0iSZhXkZ6Pg2A2NVDgFigOMYzB2O
# KhdqfWGVoYW3haT29PSTahYkwmMv0b/83nbeECbiMXhSOtbam+/36F09fy1tsB8j
# e/RV0mIk8XL/tfCK6cPuYHE215wzrK0h1SWHTxPbPuYkRdkP05ZwmRmTnAO5/arn
# Y83jeNzhP06ShdnRqtZlV59+8yv+KIhE5ILMqgOZYAENHNX9SJDm+qxp4VqpB3MV
# /h53yl41aHU5pledi9lCBbH9JeIkNFICiVHNkRmq4TpxtwfvjsUedyz8rNyfQJy/
# aOs5b4s+ac7IH60B+Ja7TVM+EKv1WuTGwcLmoU3FpOFMbmPj8pz44MPZ1f9+YEQI
# Qty/NQd/2yGgW+ufflcZ/ZE9o1M7a5Jnqf2i2/uMSWymR8r2oQBMdlyh2n5HirY4
# jKnFH/9gRvd+QOfdRrJZb1sCAwEAAaOCAWQwggFgMB8GA1UdIwQYMBaAFDLrkpr/
# NZZILyhAQnAgNpFcF4XmMB0GA1UdDgQWBBQPKssghyi47G9IritUpimqF6TNDDAO
# BgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNVHSUEDDAKBggr
# BgEFBQcDAzAbBgNVHSAEFDASMAYGBFUdIAAwCAYGZ4EMAQQBMEsGA1UdHwREMEIw
# QKA+oDyGOmh0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY0NvZGVT
# aWduaW5nUm9vdFI0Ni5jcmwwewYIKwYBBQUHAQEEbzBtMEYGCCsGAQUFBzAChjpo
# dHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2lnbmluZ1Jv
# b3RSNDYucDdjMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTAN
# BgkqhkiG9w0BAQwFAAOCAgEABv+C4XdjNm57oRUgmxP/BP6YdURhw1aVcdGRP4Wh
# 60BAscjW4HL9hcpkOTz5jUug2oeunbYAowbFC2AKK+cMcXIBD0ZdOaWTsyNyBBsM
# LHqafvIhrCymlaS98+QpoBCyKppP0OcxYEdU0hpsaqBBIZOtBajjcw5+w/KeFvPY
# fLF/ldYpmlG+vd0xqlqd099iChnyIMvY5HexjO2AmtsbpVn0OhNcWbWDRF/3sBp6
# fWXhz7DcML4iTAWS+MVXeNLj1lJziVKEoroGs9Mlizg0bUMbOalOhOfCipnx8CaL
# ZeVme5yELg09Jlo8BMe80jO37PU8ejfkP9/uPak7VLwELKxAMcJszkyeiaerlphw
# oKx1uHRzNyE6bxuSKcutisqmKL5OTunAvtONEoteSiabkPVSZ2z76mKnzAfZxCl/
# 3dq3dUNw4rg3sTCggkHSRqTqlLMS7gjrhTqBmzu1L90Y1KWN/Y5JKdGvspbOrTfO
# XyXvmPL6E52z1NZJ6ctuMFBQZH3pwWvqURR8AgQdULUvrxjUYbHHj95Ejza63zdr
# EcxWLDX6xWls/GDnVNueKjWUH3fTv1Y8Wdho698YADR7TNx8X8z2Bev6SivBBOHY
# +uqiirZtg0y9ShQoPzmCcn63Syatatvx157YK9hlcPmVoa1oDE5/L9Uo2bC5a4CH
# 2RwwggauMIIElqADAgECAhAHNje3JFR82Ees/ShmKl5bMA0GCSqGSIb3DQEBCwUA
# MGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsT
# EHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9v
# dCBHNDAeFw0yMjAzMjMwMDAwMDBaFw0zNzAzMjIyMzU5NTlaMGMxCzAJBgNVBAYT
# AlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQg
# VHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDGhjUGSbPBPXJJUVXHJQPE8pE3qZdR
# odbSg9GeTKJtoLDMg/la9hGhRBVCX6SI82j6ffOciQt/nR+eDzMfUBMLJnOWbfhX
# qAJ9/UO0hNoR8XOxs+4rgISKIhjf69o9xBd/qxkrPkLcZ47qUT3w1lbU5ygt69Ox
# tXXnHwZljZQp09nsad/ZkIdGAHvbREGJ3HxqV3rwN3mfXazL6IRktFLydkf3YYMZ
# 3V+0VAshaG43IbtArF+y3kp9zvU5EmfvDqVjbOSmxR3NNg1c1eYbqMFkdECnwHLF
# uk4fsbVYTXn+149zk6wsOeKlSNbwsDETqVcplicu9Yemj052FVUmcJgmf6AaRyBD
# 40NjgHt1biclkJg6OBGz9vae5jtb7IHeIhTZgirHkr+g3uM+onP65x9abJTyUpUR
# K1h0QCirc0PO30qhHGs4xSnzyqqWc0Jon7ZGs506o9UD4L/wojzKQtwYSH8UNM/S
# TKvvmz3+DrhkKvp1KCRB7UK/BZxmSVJQ9FHzNklNiyDSLFc1eSuo80VgvCONWPfc
# Yd6T/jnA+bIwpUzX6ZhKWD7TA4j+s4/TXkt2ElGTyYwMO1uKIqjBJgj5FBASA31f
# I7tk42PgpuE+9sJ0sj8eCXbsq11GdeJgo1gJASgADoRU7s7pXcheMBK9Rp6103a5
# 0g5rmQzSM7TNsQIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNV
# HQ4EFgQUuhbZbU2FL3MpdpovdYxqII+eyG8wHwYDVR0jBBgwFoAU7NfjgtJxXWRM
# 3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNl
# cnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRw
# Oi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAg
# BgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQAD
# ggIBAH1ZjsCTtm+YqUQiAX5m1tghQuGwGC4QTRPPMFPOvxj7x1Bd4ksp+3CKDaop
# afxpwc8dB+k+YMjYC+VcW9dth/qEICU0MWfNthKWb8RQTGIdDAiCqBa9qVbPFXON
# ASIlzpVpP0d3+3J0FNf/q0+KLHqrhc1DX+1gtqpPkWaeLJ7giqzl/Yy8ZCaHbJK9
# nXzQcAp876i8dU+6WvepELJd6f8oVInw1YpxdmXazPByoyP6wCeCRK6ZJxurJB4m
# wbfeKuv2nrF5mYGjVoarCkXJ38SNoOeY+/umnXKvxMfBwWpx2cYTgAnEtp/Nh4ck
# u0+jSbl3ZpHxcpzpSwJSpzd+k1OsOx0ISQ+UzTl63f8lY5knLD0/a6fxZsNBzU+2
# QJshIUDQtxMkzdwdeDrknq3lNHGS1yZr5Dhzq6YBT70/O3itTK37xJV77QpfMzmH
# QXh6OOmc4d0j/R0o08f56PGYX/sr2H7yRp11LB4nLCbbbxV7HhmLNriT1ObyF5lZ
# ynDwN7+YAN8gFk8n+2BnFqFmut1VwDophrCYoCvtlUG3OtUVmDG0YgkPCr2B2RP+
# v6TR81fZvAT6gt4y3wSJ8ADNXcL50CN/AAvkdgIm2fBldkKmKYcJRyvmfxqkhQ/8
# mJb2VVQrH4D6wPIOK+XW+6kvRBVK5xMOHds3OBqhK/bt1nz8MIIGwjCCBKqgAwIB
# AgIQBUSv85SdCDmmv9s/X+VhFjANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMB4XDTIzMDcx
# NDAwMDAwMFoXDTM0MTAxMzIzNTk1OVowSDELMAkGA1UEBhMCVVMxFzAVBgNVBAoT
# DkRpZ2lDZXJ0LCBJbmMuMSAwHgYDVQQDExdEaWdpQ2VydCBUaW1lc3RhbXAgMjAy
# MzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKNTRYcdg45brD5UsyPg
# z5/X5dLnXaEOCdwvSKOXejsqnGfcYhVYwamTEafNqrJq3RApih5iY2nTWJw1cb86
# l+uUUI8cIOrHmjsvlmbjaedp/lvD1isgHMGXlLSlUIHyz8sHpjBoyoNC2vx/CSSU
# pIIa2mq62DvKXd4ZGIX7ReoNYWyd/nFexAaaPPDFLnkPG2ZS48jWPl/aQ9OE9dDH
# 9kgtXkV1lnX+3RChG4PBuOZSlbVH13gpOWvgeFmX40QrStWVzu8IF+qCZE3/I+PK
# hu60pCFkcOvV5aDaY7Mu6QXuqvYk9R28mxyyt1/f8O52fTGZZUdVnUokL6wrl76f
# 5P17cz4y7lI0+9S769SgLDSb495uZBkHNwGRDxy1Uc2qTGaDiGhiu7xBG3gZbeTZ
# D+BYQfvYsSzhUa+0rRUGFOpiCBPTaR58ZE2dD9/O0V6MqqtQFcmzyrzXxDtoRKOl
# O0L9c33u3Qr/eTQQfqZcClhMAD6FaXXHg2TWdc2PEnZWpST618RrIbroHzSYLzrq
# awGw9/sqhux7UjipmAmhcbJsca8+uG+W1eEQE/5hRwqM/vC2x9XH3mwk8L9Cgsqg
# cT2ckpMEtGlwJw1Pt7U20clfCKRwo+wK8REuZODLIivK8SgTIUlRfgZm0zu++uuR
# ONhRB8qUt+JQofM604qDy0B7AgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4Aw
# DAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAEGTAX
# MAgGBmeBDAEEAjALBglghkgBhv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3Mpdpov
# dYxqII+eyG8wHQYDVR0OBBYEFKW27xPn783QZKHVVqllMaPe1eNJMFoGA1UdHwRT
# MFEwT6BNoEuGSWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEB
# BIGDMIGAMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wWAYI
# KwYBBQUHMAKGTGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcN
# AQELBQADggIBAIEa1t6gqbWYF7xwjU+KPGic2CX/yyzkzepdIpLsjCICqbjPgKjZ
# 5+PF7SaCinEvGN1Ott5s1+FgnCvt7T1IjrhrunxdvcJhN2hJd6PrkKoS1yeF844e
# ktrCQDifXcigLiV4JZ0qBXqEKZi2V3mP2yZWK7Dzp703DNiYdk9WuVLCtp04qYHn
# bUFcjGnRuSvExnvPnPp44pMadqJpddNQ5EQSviANnqlE0PjlSXcIWiHFtM+YlRpU
# urm8wWkZus8W8oM3NG6wQSbd3lqXTzON1I13fXVFoaVYJmoDRd7ZULVQjK9WvUzF
# 4UbFKNOt50MAcN7MmJ4ZiQPq1JE3701S88lgIcRWR+3aEUuMMsOI5ljitts++V+w
# QtaP4xeR0arAVeOGv6wnLEHQmjNKqDbUuXKWfpd5OEhfysLcPTLfddY2Z1qJ+Pan
# x+VPNTwAvb6cKmx5AdzaROY63jg7B145WPR8czFVoIARyxQMfq68/qTreWWqaNYi
# yjvrmoI1VygWy2nyMpqy0tg6uLFGhmu6F/3Ed2wVbK6rr3M66ElGt9V/zLY4wNjs
# HPW2obhDLN9OTH0eaHDAdwrUAuBcYLso/zjlUlrWrBciI0707NMX+1Br/wd3H3GX
# REHJuEbTbDJ8WC9nR2XlG3O2mflrLAZG70Ee8PBf4NvZrZCARK+AEEGKMYIFvzCC
# BbsCAQEwaTBUMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MSswKQYDVQQDEyJTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgQ0EgUjM2AhEA
# t4SvG7AxI7MH8AJVKBjFCDANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEM
# MQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQB
# gjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDtcHsnsruMBzw2
# 0xdkXfWk4g+lx6d8fyTqe7AmiY2sXjANBgkqhkiG9w0BAQEFAASCAYAChxCXT3QT
# Lzh+dKRO5Ase5iuWVuEnynQxR2DNL40cgBlEGFIHmIGGTtxfXfoWeAMrs4xrYRBn
# kOUd487WBslzOr4op6Q2Evhfi/9ejAPcrWzih+vODDEMOe0XrQs5SUYjAlwaNRlh
# EjuH547J/h3Hqq2l5qZxg64IirV2lPMOwmkdyS5iMlCE5DL0Cyt3BL29gHTUF5aW
# UDlCJEf6r4t7xIf/jLJR9b1lMMjFhnWWJ9kDBNT95VoPEKnsngTvAuw+L2pl5n6M
# p59SJb+No3OsIYhqnmnsJBHId7Klj9tcBFrYzOYizf/bTDlpfHdQr4lEHpi43OWC
# lQj1BM6MAVO+C0F5thJDdOsbSrCaiu6IK6oaaypj1yG6M8oj35Jm2CUle70ppa+Q
# nvT+/3zKWCYXkFh0iwLzbYbMGa/fHAMxd3pEyvTrT1v4lNEhKs88FEaCbogxhD7O
# Ea8fvL7m8EnMrhHhdzLL2P9LmAF9RET5NxPz/OMuFi4ls3reeYWvFWuhggMgMIID
# HAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEwdzBjMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQg
# UlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBAhAFRK/zlJ0IOaa/2z9f5WEW
# MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkq
# hkiG9w0BCQUxDxcNMjQwMzA4MDkzNjAwWjAvBgkqhkiG9w0BCQQxIgQg252+mcdX
# 2eyYNSs3jhjP/EjNOlqBcgWG3NUopNHs288wDQYJKoZIhvcNAQEBBQAEggIAWsfD
# Xhox8YEqxzwQMjgvQyjK+AwQ5TITWjbjR5geBtbL3kuIdR/mUXjhxYNiEsN5uFLL
# nxMHhh4kt887/ouFoVdHA0vX9J0tvfH4ije/bcX4OK5iC6U9ySifwTE2/5KYMOk1
# ZT35PTOczv44kBFRgI2tV9Vc8q9c52WHnG7YxJW1MHMSH1Tohi6uNCsbHigKU75G
# ivIEJJZ6TalnPK2bdH9ZB7CFjXCDm29YUSbZQ89L5rbPMcAH/RgZNTR8U4DA8qSw
# EwmNfFmWEN7Y4yiLV89nwp1vhphOzwD8i49jSSTnHHlzMtBFP/XFCp/poHKp9sdU
# 0bQYWoL3gjxg1qUQ3I35N395/wvnZvd0QMAqPfYeMMqoN6joihbr87HJItduTTPe
# yrQ+Fk9VWeOl7nbr2ZBS6r43IN2E4MnwVxmp/9CnVX245NWkb6Ms7IFSsi3Ll7Rq
# s95NONRUgUdSgMQgnbsNsyPsRsMKtMUYfdODE00zmAt4PvFCcCcl4SgljFU4v55G
# 0It9uq23CxM7Kvp1zNAxwADYR1gqwR3wBL5jjM53w2kQEgLDPaQPAKdLUpfkN7is
# 5/BluYb6dE9+YijlxlqVsbLlkOwRvnF1p8/ToFPk+MW4rWS/8zh0oFkssyYTEKNg
# D1YNxSkmlhgNovixvTpA/7apsSNNMIb5gb+bXBQ=
# SIG # End signature block
