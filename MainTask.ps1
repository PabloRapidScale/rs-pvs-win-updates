#==========================================================================
#
# PVS Base Image Update
#
# AUTHOR: Pablo Murillo
# DATE  : 03/20/2020
#
# COMMENT: This script creates a new maintenance image, updates, optimizers,
# shutsdown the VM, and promotes the image to test.
#
#
#==========================================================================

# Get the script parameters if there are any
param
(
    # If no parameters are present or if the parameter is not
    #[string]$Installationtype
)

#Get variables currently defined in environment
$DefaultVariables = $(Get-Variable).Name
# define Error handling
# note: do not change these values
$global:ErrorActionPreference = "SilentlyContinue"
#Enable TLS 1.2 support for versions of PowerShell +5 which disable it by default
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

############################
# Functions                #
############################
#==========================================================================
# FUNCTION DS_WriteLog
#==========================================================================
function DS_WriteLog {
    <#
        .SYNOPSIS
        Write text to this script's log file
        .DESCRIPTION
        Write text to this script's log file
        .PARAMETER InformationType
        This parameter contains the information type prefix. Possible prefixes and information types are:
            I = Information
            S = Success
            W = Warning
            E = Error
            - = No status
        .PARAMETER Text
        This parameter contains the text (the line) you want to write to the log file. If text in the parameter is omitted, an empty line is written.
        .PARAMETER LogFile
        This parameter contains the full path, the file name and file extension to the log file (e.g. C:\Logs\MyApps\MylogFile.log)
        .EXAMPLE
        DS_WriteLog -InformationType "I" -Text "Copy files to C:\Temp" -LogFile "C:\Logs\MylogFile.log"
        Writes a line containing information to the log file
        .Example
        DS_WriteLog -InformationType "E" -Text "An error occurred trying to copy files to C:\Temp (error: $($Error[0]))" -LogFile "C:\Logs\MylogFile.log"
        Writes a line containing error information to the log file
        .Example
        DS_WriteLog -InformationType "-" -Text "" -LogFile "C:\Logs\MylogFile.log"
        Writes an empty line to the log file
    #>
    [CmdletBinding()]
    Param( 
        [Parameter(Mandatory = $true, Position = 0)][String]$InformationType,
        [Parameter(Mandatory = $true, Position = 1)][AllowEmptyString()][String]$Text,
        [Parameter(Mandatory = $true, Position = 2)][AllowEmptyString()][String]$LogFile
    )

    $DateTime = (Get-Date -format dd-MM-yyyy) + " " + (Get-Date -format HH:mm:ss)
	
    if ( $Text -eq "" ) {
        Add-Content $LogFile -value ("") # Write an empty line
    }
    Else {
        Add-Content $LogFile -value ($DateTime + " " + $InformationType + " - " + $Text)
        Write-Output ($DateTime + " " + $InformationType + " - " + $Text)
    }
}
#==========================================================================
# FUNCTION Test-RegistryValue & Get-RegistryValue
#==========================================================================
#Check if registry entry exists
function Test-RegistryValue($path, $name) {
    $key = Get-Item -LiteralPath $path -EA 0
    $key -and $Null -ne $key.GetValue($name, $Null)
}

# Gets the specified registry value or $Null if it is missing
function Get-RegistryValue($path, $name) {
    $key = Get-Item -LiteralPath $path -EA 0
    If ($key) {
        $key.GetValue($name, $Null)
    }
    Else {
        $Null
    }
}

#==========================================================================
# FUNCTION WaitForService
#==========================================================================
function WaitForService {
    [CmdletBinding()]
    Param( 
        [Parameter(Mandatory = $true, Position = 0)][String]$Name,
        [Parameter(Mandatory = $true, Position = 1)][String]$status
    )
    foreach ($service in (Get-Service -Name $Name)) {
        # Wait for the service to reach the $status or a maximum of 30 seconds
        $service.WaitForStatus($status, '00:00:30')
    }
}

#==========================================================================
# FUNCTION test-wsmanquiet & enable-winrm
#==========================================================================
#Test WINRM connectivity 
function test-wsmanquiet {
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]$computer)
    try {
        Test-WSMan -ComputerName $computer
    }
    catch {
        return $false
    }
    return $true
}

#Enable WinRM
function enable-winrm {
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]$computer
    )
    $ArgList = @(
        "powershell"
        "Start-Process powershell"
        "-Verb runAs"
        "-ArgumentList 'Enable-PSRemoting -force;"
        "Set-Item WSMan:localhost\client\trustedhosts -value *'"
    ) -join ' '
    $IWM_Params = @{
        ComputerName        = $computer
        Namespace           = 'root\cimv2'
        Class               = 'Win32_Process'
        Name                = 'Create'
        Credential          = $cred
        # the next value may need to be quoted if it needs to be [string] instead of [int]
        Impersonation       = 3
        EnableAllPrivileges = $True
        ArgumentList        = $ArgList
    }
    try {
        Invoke-WmiMethod @IWM_Params
    }
    catch {
        return $false
    }
    return $true
}
############################
# Preparation              #
############################

# Disable File Security
$env:SEE_MASK_NOZONECHECKS = 1

# Custom variables [edit]
$BaseLogDir = "C:\Logs"               # [edit] add the location of your log directory here
$PackageName = "Base Image Update"    # [edit] enter the display name of the software (e.g. 'Acrobat Reader' or 'Microsoft Office')

# Global variables
$StartDir = $PSScriptRoot # the directory path of the script currently being executed
if (!($Installationtype -eq "Uninstall")) { $Installationtype = "Install" }
$global:LogDir = (Join-Path $BaseLogDir $PackageName).Replace(" ", "_")
$LogFileName = "$($Installationtype)_$($PackageName).log"
$global:LogFile = Join-path $LogDir $LogFileName

# Create the log directory if it does not exist
if (!(Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType directory | Out-Null }

# Create new log file (overwrite existing one)
New-Item $LogFile -ItemType "file" -force | Out-Null

DS_WriteLog "I" "START SCRIPT - $Installationtype $PackageName" $LogFile
DS_WriteLog "-" "" $LogFile

#################################################
# Base Image Updates for Citrix PVS             #
#################################################

DS_WriteLog "I" "Base Image Updates for Citrix PVS" $LogFile
DS_WriteLog "-" "" $LogFile
# Define the variables needed in this script:
DS_WriteLog "I" "Define the variables needed in this script:" $LogFile

# -----------------------------------
# CUSTOMIZE THE FOLLOWING VARIABLES TO YOUR REQUIREMENTS
# -----------------------------------

$MaintServer = "*CTXMAINT*"                                                 #Set VM name for Maintenance VM, you can use wildcards. (Replace with $null to select VM in pop up using Out-GridView)
$versionname = Get-Date -Format "yyyy.MM.dd"                                #Version name format (2020.03.27)
$versiondescription = "Created via Windows update script"                   #Comment for PVS version properties
$scriptpath = "$StartDir\scripts\"                                          #PowerShell Scripts directory
$templatepath = "$StartDir\templates\"                                      #PowerShell template directory
$domainadminuser = ""                                                       #Local admin username for Maintenance VM
$domainadminpw = ""                                                         #Local admin password for Maintenance VM
$vcloud_url = ""                                                            #vCloud URL
$vcloud_user = ""                                                           #vCloud Username
$vcloud_pass = ""                                                           #vCloud Password
$vcloud_org = $null                                                         #vCloud Org (Replace $null with the Org Name or Select Org in pop up Out-GridView)

# If no variables are filled in, prompt user for input

if ([string]::IsNullOrWhiteSpace($domainadminuser)) {
    $domainadminuser = Read-Host -Prompt 'Domain Administrator Username [administrator]'
}
if ([string]::IsNullOrWhiteSpace($domainadminpw)) {
    $domainadminpw = Read-Host -AsSecureString -Prompt 'Domain Administrator Password [******]'
    $domainadminpw = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($domainadminpw))

}
if ([string]::IsNullOrWhiteSpace($vcloud_user)) {
    $vcloud_user = Read-Host -Prompt 'vCloud Username [first.last]'
}
if ([string]::IsNullOrWhiteSpace($vcloud_pass)) {
    $vcloud_pass = Read-Host -AsSecureString -Prompt 'vCloud Password [******]'
    $vcloud_pass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($vcloud_pass))
}
if ([string]::IsNullOrWhiteSpace($vcloud_url)) {
    $vcloud_selection = [ordered]@{
        IAD   = 'iad01vcd01.rsportal.net'
        SNA   = 'sna01vcd.rsportal.net'
        DAL   = 'dal01vcd.rsportal.net'
        ORD   = 'ord01vcd01.rsportal.net'
        LHR   = 'lhr01vcd.rsportal.net'
        DAL02 = 'dal02vcd.rsportal.net'
    }
    $vcloud_url = @($vcloud_selection | Out-GridView -Title 'Select a DataCenter' -OutputMode Single).Value
}
# Log Variables
DS_WriteLog "I" "-Maintenance Server = $MaintServer" $LogFile
DS_WriteLog "I" "-Maintenance version= $versionname" $LogFile
DS_WriteLog "I" "-Maintenance Description = $versiondescription" $LogFile
DS_WriteLog "I" "-Script location = $scriptpath" $LogFile
DS_WriteLog "I" "-Domain Admin User = $domainadminuser" $LogFile
DS_WriteLog "I" "-Domain Admin Password = ********" $LogFile
DS_WriteLog "I" "-vCloud URL = $vcloud_url" $LogFile
DS_WriteLog "I" "-vCloud User Name = $vcloud_user" $LogFile
DS_WriteLog "I" "-vCloud Password = *********" $LogFile

#Starts the timer
$StartDTM = (Get-Date)

# IMPORT MODULES AND SNAPINS
# --------------------------
If (-not(Get-PackageProvider -Name Nuget -ErrorAction silentlycontinue)) {
    Install-PackageProvider -Name Nuget -Confirm:$False -Force
}

# INSTALL PowerCLI


DS_WriteLog "I" "Install the PowerCLI VMWare Server modules" $LogFile
If (-not(Get-InstalledModule VMware.PowerCLI -ErrorAction silentlycontinue)) {
    try {
        Install-Module -Name VMware.PowerCLI -Confirm:$False -Force
        DS_WriteLog "S" "The PowerCLI VMWare Server modules were installed successfully" $LogFile
    }
    catch {
        DS_WriteLog "E" "An error occurred trying to install the PowerCLI VMWare Server modules (error: $($Error[0]))" $LogFile
        Exit 1
    }
}
DS_WriteLog "-" "" $LogFile

$powercli_config = Get-PowerCLIConfiguration
If ($powercli_config.InvalidCertificateAction -ne "Ignore") {
    Set-PowerCLIConfiguration -InvalidCertificateAction ignore -Confirm:$False | Out-Null
}
If ($powercli_config.ParticipateInCEIP -ne $false) {
    Set-PowerCLIConfiguration -ParticipateInCEIP $false -Confirm:$False | Out-Null
}

#Create vCloud Credential
$SecurePasswordvCloud = ConvertTo-SecureString $vcloud_pass -AsPlainText -Force
$CredentialvCloud = New-Object System.Management.Automation.PSCredential ($vcloud_user, $SecurePasswordvCloud)
#Connects to vCenter
DS_WriteLog "I" "Connecting to vCloud $vcloud_url" $LogFile
try {
    Connect-CIServer -Server $vcloud_url -Credential $CredentialvCloud | Out-Null
    DS_WriteLog "S" "Connected to $vcloud_url" $LogFile
}
catch {
    DS_WriteLog "E" "An error occurred trying to connect to $vcloud_url (error: $($Error[0]))" $LogFile
    Exit 1
}
DS_WriteLog "-" "" $LogFile


# INSTALL Citrix PVS PowerShell Modules
# For some reason, the Provisioning Server snapins are not installed by default. In order to use the command "Add-PSSnapin citrix*" (or abbreviated "asnp citrix*" ) to use these snapins, they first need to be installed.
# Note: interestingly, the XenDesktop snapins are installed by default (needed for the XenDesktop Setup Wizard).
# Reference: https://docs.citrix.com/content/dam/docs/en-us/provisioning-services/7-13/downloads/PvsSnapInCommands.pdf
DS_WriteLog "I" "Install the Provisioning Server snapins" $LogFile
try {
    &"$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319\installutil.exe" /LogFile="$LogDir\Install_PVS_Snapin.log" "$env:ProgramFiles\Citrix\Provisioning Services Console\Citrix.PVS.SnapIn.dll" | Out-Null
    DS_WriteLog "S" "The Provisioning Server snapins were installed successfully" $LogFile
}
catch {
    DS_WriteLog "E" "An error occurred trying to install the Provisioning Server snapins (error: $($Error[0]))" $LogFile
    Exit 1
}
DS_WriteLog "-" "" $LogFile

# Load the Citrix snap-ins
# ========================

DS_WriteLog "I" "Load the Citrix snap-ins" $LogFile
If (-not(Get-PSSnapin -Name Citrix.PVS.SnapIn -ErrorAction silentlycontinue)) {
    try {
        Add-PSSnapIn citrix*
        DS_WriteLog "S" "The Citrix snap-ins were loaded successfully" $LogFile
    }
    catch {
        DS_WriteLog "E" "An error occurred trying to load the Citrix snap-ins (error: $($Error[0]))" $LogFile
        Exit 1
    }
}
DS_WriteLog "-" "" $LogFile

#Select customer in vCloud to work with
DS_WriteLog "I" "Select Customer in vCloud (this can take a few seconds to generate)" $LogFile
if (!$vcloud_org) { 
    $vcloud_org = @(Get-Org | Sort-Object Name | Select-Object FullName, Name, Enabled, Description | Out-GridView -Title 'Select vCloud Customer' -OutputMode Single).Name
    DS_WriteLog "S" "Selected customer: $vcloud_org" $LogFile
}
elseif ($vcloud_org) {
    DS_WriteLog "S" "Customer: $vcloud_org already defined in variable" $LogFile
}
else {
    DS_WriteLog "E" "An error occurred trying to get the Org Name from vCloud (error: $($Error[0]))" $LogFile
    Exit 1
}
DS_WriteLog "-" "" $LogFile

#Select VMNAME
DS_WriteLog "I" "Select Maintenance VM for vCloud customer $vcloud_org" $LogFile
if (!$MaintServer) { 
    $vm = @(Get-CIVM -Org $vcloud_org | Sort-Object Name |  Out-GridView -Title 'Select Maintenance VM' -OutputMode Single)
    $VMNAME = $vm.Name
    DS_WriteLog "S" "Selected Maintenance Server: $VMNAME" $LogFile
}
else {
    $vm = @(Get-CIVM -Org $vcloud_org | Where-Object { $_.Name -like "$MaintServer" })
    $VMNAME = $vm.Name
    DS_WriteLog "S" "Maintenance Server $VMNAME selected based on search $MaintServer" $LogFile
}
DS_WriteLog "-" "" $LogFile

#Get some basic info on your PVS server to use as variables later in the script
$pvs_variables = Get-PvsDiskLocator
$pvs_site = $pvs_variables.SiteName
#TODO: Multiple Store Names will throw this off
$pvs_store = $pvs_variables.StoreName
#Create a pop-up window to select vDisk to modify
DS_WriteLog "I" "Select vDisk to modify" $LogFile
if ($(Get-PvsDiskInfo).count -eq 1) {
    $DiskInfo = Get-PvsDiskInfo -StoreName $pvs_store -SiteName $pvs_site | Select-Object Name, Description, SiteName, StoreName, Enabled, DiskLocatorId
}
else {
    $DiskInfo = @(Get-PvsDiskInfo -StoreName $pvs_store -SiteName $pvs_site | Select-Object Name, Description, SiteName, StoreName, Enabled, DiskLocatorId | Out-GridView -Title 'Select a vDisk' -OutputMode Single)
}
DS_WriteLog "-" "" $LogFile
DS_WriteLog "I" "User input is no longer required, rest of the steps will complete automatically." $LogFile
###### 01 Create Maintenance Image

#Check if a maintenance image already exists if one doesn't create it
if ( -not ( Get-PvsMaintenanceVersionExists -SiteName $DiskInfo.SiteName -StoreName $DiskInfo.StoreName -DiskLocatorName $DiskInfo.Name ) ) {
    #If Get-PvsMaintenanceVersionExists has returned false
    #Create a new Maintenance disk New-PvsDiskMaintenanceVersion
    $Maintenance_image = New-PvsDiskMaintenanceVersion -SiteName $DiskInfo.SiteName -StoreName $DiskInfo.StoreName -DiskLocatorName $DiskInfo.Name
    DS_WriteLog "S" "Maintenance Image created for $($Maintenance_image.Name) and the new version is $($Maintenance_image.Version)" $LogFile
}
else {
    DS_WriteLog "E" "A maintenance image already exist, please remove or promote that image" $LogFile
    Exit 1
}
DS_WriteLog "-" "" $LogFile

#Add description to Maintenance image to note when it was created and why

DS_WriteLog "I" "Comment Maintenance version" $LogFile
try {
    Get-PvsDiskVersion -SiteName $DiskInfo.SiteName -StoreName $DiskInfo.StoreName -DiskLocatorName $DiskInfo.Name -Version $Maintenance_image.Version -Fields Description | ForEach-Object { $o = $_; $o.Description = "$versiondescription created on $versionname by $vcloud_user"; $o } | Set-PvsDiskVersion -Version $Maintenance_image.Version | Out-Null
    DS_WriteLog "S" "Commented Maintenance image with $versiondescription - $versionname" $LogFile
}
catch {
    DS_WriteLog "E" "An error occurred commenting the maintenance image(error: $($Error[0]))" $LogFile
    Exit 1
}
DS_WriteLog "-" "" $LogFile

###### Force maintenance machine to boot to newly created vDisk maintenance version
#Skip Boot Menu (https://support.citrix.com/article/CTX135299)

#Get PVS Version
$psversion = Get-PvsVersion
$reg_key = $null
$reg_subkey = "SkipBootMenu"

if ($psversion.MapiVersion -ge '7') {
    $reg_key = "HKLM:\SOFTWARE\Citrix\ProvisioningServices\StreamProcess"
    DS_WriteLog "S" "PVS Version is $($psversion.MapiVersion)" $LogFile
}
elseif (($psversion).MapiVersion -lt '7') {
    $reg_key = "HKLM:\SOFTWARE\Citrix\ProvisioningServices"
    DS_WriteLog "S" "PVS Version is $($psversion.MapiVersion)" $LogFile
}
else { 
    DS_WriteLog "E" "The PVS version does not match the expected results: return value is $($psversion.MapiVersion)" $LogFile
    break
}

#Check if PVS is set to SkipBootMenu
if (-not (Test-RegistryValue $reg_key $reg_subkey)) {
    New-ItemProperty -Path $reg_key -Name $reg_subkey -Value 1 -PropertyType DWORD | Out-Null
    DS_WriteLog "S" "Enabling SkipBootMenu option in registry" $LogFile
    try {
        Restart-Service -Name StreamService -Force -Verbose | Out-Null
        DS_WriteLog "S" "Restarting PVS Stream Service" $LogFile
        #Wait for the StreamService to completely restart, otherwise target device may not boot properly
        WaitForService -Name "StreamService" -status "Running"
    }
    catch {
        DS_WriteLog "E" "An error occurred trying to restart the PVS Stream Service (error: $($Error[0]))" $LogFile
        Exit 1
    }
}
elseif ((Get-RegistryValue $reg_key $reg_subkey) -eq 1) {
    DS_WriteLog "S" "SkipBootMenu option is already set in registry" $LogFile
}
else {
    Set-ItemProperty -Path $reg_key -Name $reg_subkey -Value 1 | Out-Null
    DS_WriteLog "S" "Updating SkipBootMenu option in registry" $LogFile
    try {
        Restart-Service -Name StreamService -Force -Verbose | Out-Null
        DS_WriteLog "S" "Restarting PVS Stream Service" $LogFile
        #Wait for the StreamService to completely restart, otherwise target device may not boot properly
        WaitForService -Name "StreamService" -status "Running"
    }
    catch {
        DS_WriteLog "E" "An error occurred trying to restart the PVS Stream Service (error: $($Error[0]))" $LogFile
        Exit 1
    }
}
#Wait 30 seconds before booting the device
Start-Sleep -Seconds 30
###### 02 Turn On Maintenance Machine
#Turn on VM
DS_WriteLog "I" "Turning on $VMNAME" $LogFile
try {
    Get-CIVM -Org $vcloud_org | Where-Object { $_.Name -like "$MaintServer" } | Start-CIVM | Out-Null
    DS_WriteLog "S" "$VMNAME server has been powered on" $LogFile
}
catch {
    DS_WriteLog "E" "An error occurred trying to turn on $VMNAME (error: $($Error[0]))" $LogFile
    Exit 1
}
DS_WriteLog "-" "" $LogFile

#Waits for VM to become available over the network and grabs IP Address
$timer = [Diagnostics.Stopwatch]::StartNew()
#Operation timeout
$timeout = 2 #Hours
do {  
    if ($timer.Elapsed.TotalHours -ge $Timeout) {
        DS_WriteLog "E" "Timeout was exceeded (error: $($Error[0]))" $LogFile
        Exit 1
    }
    DS_WriteLog "I" "Waiting for $VMNAME to become available..." $LogFile
    Start-Sleep -Seconds 10
    $vmconn = $(Test-Connection -ComputerName $VMNAME -Count 1 -ErrorAction SilentlyContinue)
    $ip = $vmconn.IPV4Address
}
until ($ip)

DS_WriteLog "S" "$VMNAME is available on $ip" $LogFile
DS_WriteLog "-" "" $LogFile

######Compare MAC Address and ensure IP addresses in DNS and what is actually assigned match
$vcloud_mac = $($vm | Get-CINetworkAdapter).MACAddress -replace ":", "-"
$pvs_device = $(Get-PvsDevice | Where-Object { $_.DeviceMac -eq $vcloud_mac })

#TODO: Probably delete and not needed
if (-not ([string]::IsNullOrWhiteSpace($pvs_device.DeviceMac))) {
    $ip_from_mac = arp -a | select-string $pvs_device.DeviceMac | ForEach-Object { $_.ToString().Trim().Split(" ")[0] }
    DS_WriteLog "S" "$($pvs_device.DeviceMac) has an ip of $ip_from_mac" $LogFile
}
if ($ip -eq $ip_from_mac) {
    DS_WriteLog "S" "IP Address ($ip) in DNS for $VMNAME and IP Address ($ip_from_mac) assigned to VM MAC Address match. Proceeding..." $LogFile
}
else {
    DS_WriteLog "E" "IP Address ($ip) in DNS for $VMNAME and IP Address ($ip_from_mac) assigned to $VMNAME Virtual Machine in vCloud do not match. Troubleshoot DNS or DHCP issue and try again." $LogFile
    Exit 1
}

if ($VMNAME -eq $pvs_device.Name) {
    DS_WriteLog "S" "The VM Name in vCloud $VMNAME and name registered with the domain $($pvs_device.Name) match, proceeding" $LogFile
}
else {
    DS_WriteLog "E" "The VM Name in vCloud $VMNAME and name registered with the domain $($pvs_device.Name) do not match, adjusting variables and proceeding" $LogFile
    $VMNAME = $pvs_device.Name
}
#Create credential for WINRM
$domain = (Get-WmiObject Win32_ComputerSystem).Domain
$credname = ("$domain\$domainadminuser")
$secpasswd = ConvertTo-SecureString $domainadminpw -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($credname, $secpasswd)

###### 03 Ensure prerequisites for PSRemoting, WinRM, etc are enabled on Maintenance Machine

#Check WinRM is responding for the target computer (Replace with Function below)
DS_WriteLog "I" "Testing WinRM connectivity to $ip" $LogFile
try {
    test-wsmanquiet -Computer $ip
    DS_WriteLog "S" "$ip has WinRM Enabled" $LogFile
}
catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
    enable-winrm -computer $ip
    DS_WriteLog "E" "An error occurred trying to connect to $ip over WinRM trying to enable it (error: $($Error[0]))" $LogFile
    Continue
}
DS_WriteLog "-" "" $LogFile

$timer = [Diagnostics.Stopwatch]::StartNew()
$timeout = 120 #2 minutes
DS_WriteLog "I" "Testing WinRM connectivity to $VMNAME" $LogFile
#Tries to connect to WINRM and waits to become available
while (-not (test-wsmanquiet -Computer $VMNAME)) {
    DS_WriteLog "I" "Waiting for $VMNAME to become accessible WINRM..." $LogFile
    if ($timer.Elapsed.TotalSeconds -ge $Timeout) {
        DS_WriteLog "E" "Timeout exceeded. Giving up on $VMNAME" $LogFile
        Exit 1
    }
}
#Wait 30 seconds before starting the session
Start-Sleep -Seconds 30
#Start WINRM session
DS_WriteLog "I" "Start a PSSession with $VMNAME" $LogFile
try {
    #TODO: Delete, these are used for IP and local admin auth
    #$options=New-PSSessionOption -SkipCACheck -SkipCNCheck
    #$session = New-PSSession -ComputerName $ip -Credential $cred -UseSSL -SessionOption $options
    $session = New-PSSession -ComputerName $VMNAME -Credential $cred -ErrorAction Stop
    DS_WriteLog "S" "Succesfully connected a PSSession to $VMNAME" $LogFile
}
catch {
    DS_WriteLog "E" "An error occurred trying open a PSSession to $VMNAME (error: $($Error[0]))" $LogFile
    Exit 1
}
DS_WriteLog "-" "" $LogFile

#Enable more robust remoting once basic WinRM is enabled
DS_WriteLog "I" "Enabling Remoting on $VMNAME" $LogFile
Invoke-Command -Session $session -ScriptBlock {
    $(Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1' -UseBasicParsing).content | Out-File "$env:SystemDrive\Windows\temp\ConfigureRemotingForAnsible.ps1"
    powershell.exe -ExecutionPolicy ByPass -File "$env:SystemDrive\Windows\temp\ConfigureRemotingForAnsible.ps1"
}
DS_WriteLog "-" "" $LogFile

#TODO: Probably can delete
#Install Chocolatey
#Invoke-Command -Session $session -ScriptBlock {
#Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
#}

###### 05 Run Windows Updates
#Copies scripts needed for update process

DS_WriteLog "I" "Copying contents from $scriptpath to $VMNAME" $LogFile
try {
    Copy-Item -ToSession $session -path "$scriptpath\*" -Destination "$env:SystemDrive\Windows\temp" -Recurse -Force -PassThru
    DS_WriteLog "S" "Succesfully copied contents of $($scriptpath) to $VMNAME" $LogFile
}
catch {
    DS_WriteLog "E" "An error occurred trying to copy script files to $VMNAME (error: $($Error[0]))" $LogFile
    Exit 1
}
DS_WriteLog "-" "" $LogFile

#Copy templates directory for sealing

DS_WriteLog "I" "Copying contents from $templatepath to $VMNAME" $LogFile
try {
    Copy-Item -ToSession $session -path "$templatepath" -Destination "$env:SystemDrive\Windows\temp" -Recurse -Force -PassThru
    DS_WriteLog "S" "Succesfully copied contents of $($templatepath) to $VMNAME" $LogFile
}
catch {
    DS_WriteLog "E" "An error occurred trying to copy script files to $VMNAME (error: $($Error[0]))" $LogFile
    Exit 1
}
DS_WriteLog "-" "" $LogFile

#Scheduled tasks script block
$sbtask = {
    $action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument '-ExecutionPolicy Bypass -file "C:\Windows\temp\UpdateTask.ps1" -noexit'
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    Register-ScheduledTask -Action $action -Trigger $trigger -RunLevel Highest -TaskName "PSWindowsUpdate" -Force
}

#Creates scheduled tasks using script block
DS_WriteLog "I" "Setting up Windows Updates Scheduled task on $VMNAME" $LogFile
Invoke-Command -Session $session -ScriptBlock $sbtask | Out-Null

#Encrypt Password using script block
DS_WriteLog "I" "Encrypting password for reuse on $VMNAME" $LogFile
Invoke-Command -Session $session -ScriptBlock {
    Set-ExecutionPolicy Bypass
    . $env:SystemDrive\Windows\temp\New-StringEncryption.ps1
    #Encrypt credentials
    $win_pass = New-StringEncryption -StringToEncrypt "$using:domainadminpw"
    #Replace variables in script with encrypted credentials
    (Get-Content "$env:SystemDrive\Windows\temp\UpdateTask.ps1" -Raw) | Foreach-Object {
        $_ -replace '_UserName_', "$using:credname" `
            -replace '_SecurePassword_', "$win_pass"
    } | Set-Content "$env:SystemDrive\Windows\temp\UpdateTask.ps1"
}

#Enables autologon
#Install-Module -Name Autologon
DS_WriteLog "I" "Enabling AutoLogon after reboot on $VMNAME" $LogFile
try {
    Invoke-Command -Session $session -ScriptBlock { 
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Install-PackageProvider -Name Nuget -Confirm:$False -Force
        Install-Module Autologon -Confirm:$False -Force; Enable-AutoLogon -Username $using:domainadminuser -Password (ConvertTo-SecureString -String $using:domainadminpw -AsPlainText -Force) -LogonCount "1" 
    } | Out-Null
    DS_WriteLog "S" "Succesfully enabled AutoLogon on $VMNAME" $LogFile
}
catch {
    DS_WriteLog "E" "An error occurred trying to enable AutoLogon on $VMNAME (error: $($Error[0]))" $LogFile
    Exit 1
}
DS_WriteLog "-" "" $LogFile

#Restart to kick off the process
DS_WriteLog "I" "Rebooting $VMNAME to kick off Update process" $LogFile
try {
    Restart-Computer -Force -ComputerName $VMNAME -Credential $cred | Out-Null
    DS_WriteLog "S" "Succesfully rebooted $VMNAME and initiated Windows Update process" $LogFile
}
catch {
    DS_WriteLog "E" "An error occurred trying to reboot $VMNAME (error: $($Error[0]))" $LogFile
    Exit 1
}
DS_WriteLog "-" "" $LogFile

###### 09 Shutdown Maintenance Image
#Waits for VM to power down
$timer = [Diagnostics.Stopwatch]::StartNew()
#Operation timeout
$timeout = 2 #Hours
do {
    
    if ($timer.Elapsed.TotalHours -ge $Timeout) {
        DS_WriteLog "E" "Timeout was exceeded (error: $($Error[0]))" $LogFile
        Exit 1
    }
    DS_WriteLog "I" "Waiting for $VMNAME to complete Windows Update, Sealing, and Shutdown...." $LogFile
    Start-Sleep -Seconds 60
    $vmconn = $(Get-CIVM -Org $vcloud_org | Where-Object { $_.Name -eq $VMNAME })
    $vmstatus = $vmconn.Status
}
until ($vmstatus -eq "PoweredOff")
DS_WriteLog "S" "Succesfully powered down $VMNAME" $LogFile
DS_WriteLog "-" "" $LogFile

###### 10 Promote image to Test

#When done with updates promote image to Test
DS_WriteLog "I" "Promoting $($Maintenance_image.Name) to TEST" $LogFile
try {
    Invoke-PvsPromoteDiskVersion -SiteName $DiskInfo.SiteName -StoreName $DiskInfo.StoreName -DiskLocatorName $DiskInfo.Name -Test | Out-Null
    DS_WriteLog "S" "Succesfully promoted $($Maintenance_image.Name) to TEST" $LogFile
}
catch {
    DS_WriteLog "E" "An error occurred trying to promote $($Maintenance_image.Name) (error: $($Error[0]))" $LogFile
    Exit 1
}
DS_WriteLog "-" "" $LogFile

#End timer
$EndDTM = (Get-Date)
#Compare times
$time = ($EndDTM - $StartDTM)
DS_WriteLog "S" "Finished in $($time.TotalMinutes) minutes" $LogFile
DS_WriteLog "-" "" $LogFile
############################
# Finalize                 #
############################
#Cleanup Boot behaviour
#Reset SkipBootMenu back to normal
if ((Get-RegistryValue $reg_key $reg_subkey) -eq 1) {
    Set-ItemProperty -Path $reg_key -Name $reg_subkey -Value 0 | Out-Null
    DS_WriteLog "S" "Resetting SkipBootMenu option in registry to default" $LogFile
    try {
        Restart-Service -Name StreamService -Force | Out-Null
        DS_WriteLog "S" "Restarting PVS Stream Service" $LogFile
    }
    catch {
        DS_WriteLog "E" "An error occurred trying to restart the PVS Stream Service (error: $($Error[0]))" $LogFile
        Exit 1
    }
}
else {
    DS_WriteLog "S" "SkipBootMenu option in registry is set to $(Get-RegistryValue $reg_key $reg_subkey)" $LogFile
}
#Remove variales used in script
DS_WriteLog "I" "Clearing variables" $LogFile
try {
    ((Compare-Object -ReferenceObject (Get-Variable).Name -DifferenceObject $DefaultVariables).InputObject).foreach{ Remove-Variable -Name $_ -Force -ErrorAction SilentlyContinue } | Out-Null
    DS_WriteLog "S" "Succesfully cleared all variables used in script" $LogFile
}
catch {
    DS_WriteLog "E" "An error occurred trying to clear the session variables (error: $($Error[0]))" $LogFile
}
DS_WriteLog "-" "" $LogFile
Remove-Item env:\SEE_MASK_NOZONECHECKS
DS_WriteLog "I" "End of script" $LogFile
