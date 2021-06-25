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
        HelpMessage = "Set as Parameter if OCC-Connector should be removed if present")] 
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
        Remove-Item -Path $Path -Recurse -ErrorAction stop
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
    $PSINIFileName = "scripts.ini"
    $TriggerPatchRun = "C:\Program Files (x86)\Server-Eye\triggerPatchRun.cmd"
    $PSINIPath = Join-Path -Path $PSINIFilePAth -ChildPath $PSINIFileName
    
    $PSINIRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Shutdown\0"
    
    $Keys = Get-ChildItem -Path $PSINIRegPath
    $KeyToRemove = Get-ItemProperty -Path $keys.PSPath -Name "Script" | Where-Object -Property Script -EQ -Value $TriggerPatchRun
    #region INI
    
    if (Test-Path $PSINIPath) {
        Write-Verbose "Checking $PSINIFileName File for SU Script"
        $content = Get-Content $PSINIPath
        $string = $content | Select-String -Pattern "triggerPatchRun.cmd"
        if ($string) {
            $SetNumber = ($string.ToString()).Substring(0, 1)
            Write-Verbose "Remove Lines form File"
            $content | Select-String -Pattern $SetNumber -NotMatch | Set-Content -Path $PSINIPath 
        }
        else {
            Write-Verbose "No Lines in File"
        }
    
        
    
    }
    #endregion INI
    
    #region Reg
    if (Test-Path $KeyToRemove.PSPath) {
        Write-Verbose "Remove Linies form Registry"
        Remove-Item $KeyToRemove.PSPath
    }
    #endregion Reg
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
    If ((Get-ItemPropertyValue -Path $Path -Name DefaultLevel) -eq $On) {
        Write-EventLog -LogName $EventLogName -Source $EventSourceName -EventID 3004 -EntryType Information -Message "Remove Server-Eye Anti-Ransom"
        Set-ItemProperty -Path $ARRegPath -Name $Property -Value $Off
    }

}
#endregion SEAntiRansom

#endregion Helper Function
#region Uninstall
if ((Test-Path $SEInstPath) -eq $true) {
    Remove-SEAntiRansom -Path $ARRegPath -On $AROn -Off $AROff -Property $ARRegProperty 
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
        Write-EventLog -LogName $EventLogName -Source $EventSourceName -EventID 3000 -EntryType Information -Message "Server-Eye Installation found."
        $progs = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
        $sesetup = $progs | Where-Object { ($_.Displayname -eq "Server-Eye") -and ($_.QuietUninstallString -like '"C:\ProgramData\Package Cache\*\ServerEyeSetup.exe" /uninstall /quiet') }
        $sevendors = $progs | Where-Object { ($_.Displayname -eq "Server-Eye Vendor Package") }
        $seservereye = $progs | Where-Object { ($_.Displayname -eq "Server-Eye") }
        if ($sesetup) {
            Write-EventLog -LogName $EventLogName -Source $EventSourceName -EventID 3002 -EntryType Information -Message "Performing uninstallation of Server-Eye via Setup"
            Write-Output "Performing uninstallation of Server-Eye via Setup"
            Start-Process -FilePath $sesetup.BundleCachePath -Wait -ArgumentList "/uninstall /quiet"
            
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
        Write-EventLog -LogName $EventLogName -Source $EventSourceName -EventID 3010 -EntryType Error -Message "Error: $_"
        Write-Output "Error: $_"
    }

}
#endregion Uninstall
#region RemoveSEDataOnly
elseif (((Test-Path $SEDataPath) -eq $true)) {
    Remove-SEAntiRansom -Path $ARRegPath -On $AROn -Off $AROff -Property $ARRegProperty 
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
# MIIlMgYJKoZIhvcNAQcCoIIlIzCCJR8CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUZq5MDMCGcHixSqakfNgvRja1
# utSggh8aMIIFQDCCBCigAwIBAgIQPoouYh6JSKCXNBstwZR1fDANBgkqhkiG9w0B
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
# MAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFHRvxhol6sfHHHPypz+yB1wr
# 4DzRMA0GCSqGSIb3DQEBAQUABIIBAH++z8LvwT2H0ekBjQZXZRshOLKXh7qg4gev
# emveJWlgExaB0xGrvcJufEUNNO1AePbkO55YQXZrmWJCS9Y7LWO3xLN4S+qev1Hm
# KGnXSOLV3jR4Ed60al4TbYnTxxp/d6QmiS2QZBlLlX3QVQCJbZfXBK1NgeKq3lB0
# urst82AMto9U0JJiTNhCZaWHPXH1q/9KP8wm459siQRee18EY7K8FvVQKtoJbSpO
# ouDViTmqO4J4RwCeFr7+sMLrQPOXa8belq3ue//GEqWAfR65NOGQsnBHUK0cihcE
# DZc7PsJOxGgTBceNltXJtRkYhpwj5z6ba0C+CfwxG5GRBKt7TsahggNMMIIDSAYJ
# KoZIhvcNAQkGMYIDOTCCAzUCAQEwgZIwfTELMAkGA1UEBhMCR0IxGzAZBgNVBAgT
# EkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMP
# U2VjdGlnbyBMaW1pdGVkMSUwIwYDVQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0YW1w
# aW5nIENBAhEAjHegAI/00bDGPZ86SIONazANBglghkgBZQMEAgIFAKB5MBgGCSqG
# SIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIxMDYyNTA2NDAy
# M1owPwYJKoZIhvcNAQkEMTIEMLXfwCbWO5lqAgHZ0CzdFD9UT6Wtmt8E7/tNy+iM
# P2lNTf318GPZEaL1a7XrGuA6sTANBgkqhkiG9w0BAQEFAASCAgAtDLbtb3pCqEd7
# 9NXI6o+wRgXA47FtikOHPvYrbaJqV1iiah5/iAawFfFUnYdNdPYfegi8xKtxEubC
# ubfcEyFwmwN2Vky6Va5FMrN2B9B8AeevnZlgscBVZH0WYn0xqta9o23nWkMbOfr/
# QT5WsL8uJLTXajhtV/zw2k3xX1pZ5ZBJQiVwXzNvPCj/0+K5G7jnkzxs8EWRYJ8h
# CsdKEzhputfaNPCQwCZhMaYReC9n7Os2oZURgHdzQMvIi8HEHv3HPXkJ4OYzg/dn
# UxCjCzhHMSU7f9Jo4ZJkfnWh4tlMz5Abatk5zSNTKgqICKqYGpGqzjsu40CoIi2u
# RoI8qDhrhMQR1sr0dPSXak+/YL6lzgO5/AriylpAtAxmccTVjcDsh1fJjhhTFgLU
# VMCooj8fkVYOT7MuLojpK4uqwwgjNXdXXQ3oh/NJb98Vbm/KDi0wzX2x1JEhfYOB
# CLrpDeDjqH5sRyLWALhzFxStzLmfJX7ywDztJ/0+NzwfwATh0QmSgCIA/law8b6y
# 5FwD0gtZqrExZV98rbdv9TYJYUP6+fn3MQGN2b47DfTRX/ibDZKPvxTmghYKX9x8
# I57IXC5tUw3ab+pB/bm7Nk2zUKtdJvTE41qCDQBDFAjuSp1l+y8DSyzDOzsInp4z
# t7UGLwmHmWbaNWvF9FjsBRFux4lCmQ==
# SIG # End signature block
