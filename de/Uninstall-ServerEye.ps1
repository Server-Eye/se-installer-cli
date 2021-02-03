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
$EventSourceName = "Server-Eye-Installation"
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
            Remove-LocalFiles -Path $SEDataPath
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
            Remove-LocalFiles -Path $SEDataPath
            $SETasks = Get-ScheduledTask -TaskPath "\Server-Eye Tasks\" -ErrorAction SilentlyContinue
            if ($SETasks) {
                Write-Output "Remove all Server-Eye Scheduled Tasks" 
                Unregister-ScheduledTask -InputObject $SETasks -Confirm:$false
            }
        }
    }
    catch {
        Write-EventLog -LogName $EventLogName -Source $EventSourceName -EventID 3010 -EntryType Error -Message "Error: $_"
        Write-Output "Error: $_"
    }

}
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
        }
    }
    catch {
        Write-EventLog -LogName $EventLogName -Source $EventSourceName -EventID 3010 -EntryType Error -Message "Error: $_"
        Write-Output "Error: $_" 
    }

} 
else {
    Write-Output "No Server-Eye Installation was found"
}