# Server-Eye Installer Script
Installs Server-Eye from the command line.
This is a Powershell script. Powershell in version 3 or higher is recommended.

## Introduction
This script will help to install Server-Eye on systems without a full UI or when a full interactive setup is not needed.
Right now this script can download the current version of the client, install the client, setup an OCC-Connector and setup a Sensorhub.

## Download
It is recommended to use the official download for production use. The official version is also signed with a valid codesigning certificate.

There are two version please make sure to pick the correct one.

Customers in the European Union please use:
```PowerShell
Invoke-WebRequest "https://occ.server-eye.de/download/se.silent/Deploy-ServerEye.ps1" -OutFile Deploy-ServerEye.ps1
```

Customers in the US and Canada please use:
```PowerShell
Invoke-WebRequest "https://occ.server-eye.com/download/se-usa.silent/Deploy-ServerEye.ps1" -OutFile Deploy-ServerEye.ps1
```

## Usage

The script can be controlled by using commandline parameters.

### Download Server-Eye Setup Files
```PowerShell
.\Deploy-ServerEye.ps1 -Download
```
Downloads the newest .msi files for Server-Eye.

### Install
```PowerShell
.\Deploy-ServerEye.ps1 -Install
```
Installs Server-Eye using the .msi files in the current directory.

### Deploy
```PowerShell
.\Deploy-ServerEye.ps1 -Deploy [All|SensorhubOnly] -Customer <CustomerID> -Secret <SecretKey> [-ParentGuid <OccConnectorId]
```
This will download the current version of ServerEye and install it on this computer.
This will also set up an OCC-Connector and a Sensorhub on this computer for the given customer.
The parameters Customer and Secret are required for this.

### Everything
```PowerShell
.\Deploy-ServerEye.ps1 -Download -Install -Deploy [All|SensorhubOnly] -Customer <CustomerID> -Secret <SecretKey> [-ParentGuid <OccConnectorId]
```
Does all of the above. Downloads, installs and sets up Server-Eye.
