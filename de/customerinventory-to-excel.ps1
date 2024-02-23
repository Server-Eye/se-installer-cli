<# 
    .SYNOPSIS
    Export inventory data from all sensorhubs of a customer into an excel file

    .DESCRIPTION
    This script will read all inventory data of all sensorhubs of a customer and export it into an excel file

    .PARAMETER ApiKey
    The ApiKey of a user that is managing the customer, which inventory data should be extracted from

    .PARAMETER CustomerID
    The CustomerID of the customer (can be found in the URL bar behind /customer/ when selecting a customer via the customer list in the OCC)
    
    .PARAMETER Dest
    The path where the excel file should be saved. Note: A folder called "inventory" will be created in this path, which will contain the excel file

    .NOTES
    Author  : Thomas Krammes, Modified by Patrick Hissler and Leon Zewe - servereye
    Version : 1.1
    
    .EXAMPLE
    PS C:\> .\Inventory2.ps1 -ApiKey "e5e06dght-o924-4745-9407-4824ec3c5908" -CustomerID "3a8388cc-e09c-76c1-99aa-53f65acd59a8" -Dest "C:\Users\max.mustermann\Documents"
#>

Param (
    [Parameter(Mandatory=$true)][string]$ApiKey,
    [Parameter(Mandatory=$true)][string]$CustomerID,
    [Parameter(Mandatory=$true)][string]$Dest
)

function Status {
    Param (
        [Parameter(Mandatory=$true)][string]$Activity,
        [Parameter(Mandatory=$true)][int]$Counter,
        [Parameter(Mandatory=$true)][int]$Max,
        [Parameter(Mandatory=$true)][string]$Status,
        [Parameter(Mandatory=$true)][int]$Id,
        [Parameter(Mandatory=$false)][int]$ParentId
    )
    if ($Max) {
        $PercentComplete = (($Counter * 100) / $Max)
    } else {
        $PercentComplete = 100
    }

    if ($PercentComplete -gt 100) {
        $PercentComplete = 100
    }
    if ($ParentId) {
        try { Write-Progress -Activity $Activity -PercentComplete $PercentComplete -Status $Status -Id $Id -ParentId $ParentId } catch {}
    } else {
        Write-Progress -Activity $Activity -PercentComplete $PercentComplete -Status $Status -Id $Id
    }
}

function Inventory {
    Param (
        [Parameter(Mandatory=$true)]$Customer
    )

    $Hubs = Get-SeApiCustomerContainerList -AuthToken $ApiKey -CId $Customer.Cid | Where-Object { $_.Subtype -eq 2 }
    $XlsFile = $Dest + "\inventory\$($Customer.CompanyName).xlsx"

    $CountH = 0
    $HubCount = $Hubs.Count
    $InitFile = $true

    $InventoryAll = @()
    $HostStatusAll = @()

    foreach ($Hub in $Hubs) {
        $CountH++
        Status -Activity "$($CountH)/$($HubCount) Inventarisiere $($Customer.CompanyName)" -Max $HubCount -Counter $CountH -Status $Hub.Name -Id 2 -ParentId 1
        $HubStatus = '' | Select-Object Hub, MachineName, LastDate, Inventory, OsName, IsVM, IsServer, LastRebootUser, Cid
        $HubTemp = Get-SeApiContainer -AuthToken $ApiKey -CId $Hub.Id
        $HubStatus.Hub = $Hub.Name
        $HubStatus.OsName = $HubTemp.OsName
        $HubStatus.MachineName = $HubTemp.MachineName
        $HubStatus.IsVM = $HubTemp.IsVM
        $HubStatus.IsServer = $HubTemp.IsServer
        $HubStatus.Cid = $Hub.Id
        $HubStatus.LastRebootUser = $HubTemp.LastRebootInfo.User
        $State = (Get-SeApiContainerStateListbulk -AuthToken $ApiKey -CId $Hub.Id)
        $LastDate = [datetime]$State.LastDate
        $HubStatus.LastDate = $LastDate
        if ($LastDate -lt ((Get-Date).AddDays(-60)) -or $State.Message -eq 'OCC Connector hat die Verbindung zum Sensorhub verloren') {
            #Write-Host $Customer.Name '-' $Hub.Name': seit 60 Tagen nicht online'
            $HubStatus.Inventory = $false
            $HostStatusAll += $HubStatus
            continue
        } else {
            #-----------------------------------------------------------------------------------------
            $ScriptBlock = {
                try {
                    $Inv = (Get-SeApiContainerInventory -AuthToken $args[0] -CId $args[1])
                }
                catch {
                    $Inv = @()
                }
                return $Inv
            }

            $Inventory = Start-Job -ScriptBlock $ScriptBlock -ArgumentList @($ApiKey, $Hub.Id) | Wait-Job -Timeout 5 | Receive-Job
            Get-Job -State Running | Stop-Job
            Get-Job -State Stopped | Remove-Job
            Get-Job -State Completed | Remove-Job
            #------------------------------------------------------------------------------------------------------------------
            if ($Inventory.Count -eq 0) {
                $HubStatus.Inventory = $false
                $HostStatusAll += $HubStatus
                continue
            }
        }

        $HubStatus.Inventory = $true
        $HostStatusAll += $HubStatus

        if (!($InitObjects)) {
            $InventoryAll = @($Customer.CompanyName)
            $InventoryAll = $InventoryAll | Select-Object 'Hosts'
            $ObjectNames = (($Inventory | Get-Member) | Where-Object { $_.MemberType -eq 'NoteProperty' }).Name
            foreach ($ObjectName in $ObjectNames) {
                $InventoryAll = $InventoryAll | Select-Object *, $ObjectName
            }

            $InitObjects = $true
        }

        $Objects = (($Inventory | Get-Member) | Where-Object { $_.MemberType -eq 'NoteProperty' }).Name

        foreach ($Object in $Objects) {
            if ($Inventory.$Object.Host -ne $null) {
                $SubObject = $Inventory.$Object | Select-Object RealHost, *
            } else {
                $SubObject = $Inventory.$Object | Select-Object Host, *
            }

            if ($SubObject.Count -gt 1) {
                $Count = $SubObject.Count
                for ($A = 0; $A -le $Count - 1; $A++) {
                    $SubObject[$A].Host = $Hub.Name
                }
            } elseif (!$SubObject) {
            } else {
                $SubObject.Host = $Hub.Name
            }

            if ((Test-Path $XlsFile) -and $InitFile) {
                Export-Excel -Path $XlsFile -KillExcel
                Remove-Item $XlsFile
            }
            $InitFile = $false
            $ObjectWork = @()
            if ($InventoryAll.$Object) {
                $ObjectWork = $InventoryAll.$Object
            }

            $ObjectWork += $SubObject
            try { $InventoryAll.$Object = $ObjectWork } catch {}
            Clear-Variable SubObject
        }
    }

    if (!$InventoryAll) {
       

 $InventoryAll = @($Customer.CompanyName)
        $InventoryAll = $InventoryAll | Select-Object 'Hosts'
    }

    $InventoryAll.Hosts = $HostStatusAll
    $Worksheets = (($InventoryAll | Get-Member) | Where-Object { $_.MemberType -eq 'NoteProperty' }).Name
    $XlsCount = $Worksheets.Count
    $CountX = 0
    $Worksheets = $Worksheets | Where-Object { $_ -ne 'Hosts' }
    $InventoryAll.Hosts | Export-Excel -Path $XlsFile -WorksheetName 'Hosts' -Append -AutoFilter -AutoSize -FreezeTopRow -BoldTopRow -KillExcel
    foreach ($ObjectName in $Worksheets) {
        $CountX++
        Status -Activity "$($CountX)/$($XlsCount) schreibe Daten in Excel: $($Customer.CompanyName).xlsx" -Max $XlsCount -Counter $CountX -Status $ObjectName -Id 2 -ParentId 1
        $InventoryAll.$ObjectName | Export-Excel -Path $XlsFile -WorksheetName $ObjectName -Append -AutoFilter -AutoSize -FreezeTopRow -BoldTopRow -KillExcel
    }
}

Import-Module ServerEye.Powershell.Helper

if (!$CustomerID) {
    try {
        $Customers = Get-SeApiCustomerlist -AuthToken $ApiKey
    }
    catch {
        Write-Host 'ApiKey falsch'
        Exit
    }
    $CustomerCount = $Customers.Count
} else {
    try {
        $Customers = @((Get-SeApiCustomerlist -AuthToken $ApiKey | Where-Object { $_.CId -eq $CustomerID }))
    }
    catch {
        Write-Host 'ApiKey falsch'
        Exit
    }
    if (!$Customers) {
        Write-Host 'Customer nicht gefunden'
        Exit
    }
    $CustomerCount = 1
}

if (!(Test-Path $Dest)) {
    Write-Host "$Dest nicht gefunden"
}

$InventoryRoot = $Dest + '\inventory'
if (!(Test-Path $InventoryRoot)) {
    New-Item -Path $InventoryRoot -ItemType "directory" | Out-Null
}

$CountC = 0
$InitObjects = $false

foreach ($Customer in $Customers) {
    $CountC++
    Write-Host $Customer.CompanyName
    Status -Activity "$($CountC)/$($CustomerCount) Inventarisiere" -Max $CustomerCount -Counter $CountC -Status $Customer.CompanyName -Id 1
    Inventory $Customer
}