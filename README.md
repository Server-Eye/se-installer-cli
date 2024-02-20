# Server-Eye Installer Script
Installs Server-Eye from the command line.
This is a Powershell script. Powershell in version 3 or higher is recommended.

Instructions on how to install the current Powershell can be found here: https://technet.microsoft.com/library/Hh847837.aspx


## Introduction
This script will help to install Server-Eye on systems without a full UI or when a full interactive setup is not needed.
This script can download the current version of the client, install the client, setup an OCC-Connector and setup a Sensorhub.

This script can also be used to apply a predefined template to the freshly installed Sensorhub.

## Download
It is recommended to use the official download for production use. The official version is also signed with a valid code-signing certificate.

```PowerShell
Invoke-WebRequest "https://occ.server-eye.de/download/se/Deploy-ServerEye.ps1" -OutFile Deploy-ServerEye.ps1
```

## Usage

The script can be controlled by using command line parameters.

The parameter _customerId_ and _secretKey_ must match the existing customer data. This is not your Server-Eye username or password! Please contact our support team if you do not know the correct customerId and secretKey.

##### customerId
This is the internal customer number created when you install a new customer. This script cannot create a new customer.

##### secretKey
The _secretKey_ authenticates the Server-Eye OCC-Connector Cloud connection. It is **NOT** your password.  


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

### Apply template
```PowerShell
.\Deploy-ServerEye.ps1 -ApplyTemplate -ApiKey <ApiKey> -TemplateId <TemplateId>
```
This will apply the template with the given ID to the freshly installed Sensorhub.

### Everything
```PowerShell
.\Deploy-ServerEye.ps1 -Download -Install -Deploy [All|SensorhubOnly] -Customer <CustomerID> -Secret <SecretKey> [-ParentGuid <OccConnectorId] [-ApplyTemplate -ApiKey <ApiKey> -TemplateId <TemplateId>]
```
Does all of the above. Downloads, installs and sets up Server-Eye.





