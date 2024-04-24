# Loosely based on https://github.com/ryancbutler/UnideskSDK
$Username = "_UserName_"
$encryptedpw = "_SecurePassword_"
#TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#Load needed functions
. $env:SystemDrive\Windows\temp\New-StringDecryption.ps1
#Decrypt password
$securePassword = ConvertTo-SecureString -String (New-StringDecryption -EncryptedString $encryptedpw) -AsPlainText -Force
#Check if registry entry exists
function Test-RegistryValue($path, $name)
{
	$key = Get-Item -LiteralPath $path -EA 0
	$key -and $Null -ne $key.GetValue($name, $Null)
}

# Gets the specified registry value or $Null if it is missing
function Get-RegistryValue($path, $name)
{
	$key = Get-Item -LiteralPath $path -EA 0
	If($key)
	{
		$key.GetValue($name, $Null)
	}
	Else
	{
		$Null
	}
}
#Citrix Optimizer Settings
$downloadpath = "$env:SystemDrive\Windows\temp\CitrixOptimizer.zip"
$unzippath = "$env:SystemDrive\Windows\temp\CTX"
#Install WinUpdate Module
If(-not(Get-InstalledModule pswindowsupdate -ErrorAction silentlycontinue)){
    Install-Module pswindowsupdate -Confirm:$False -Force
}

If(-not(Get-InstalledModule Autologon -ErrorAction silentlycontinue)){
    Install-Module Autologon -Confirm:$False -Force
}

#### Script Starts Here ####
#wait for Windows update funciton
function Test-WUInstallerStatus {
    while ((Get-WUInstallerStatus).IsBusy) {
        Write-host -Message "Waiting for Windows update to become free..." -ForegroundColor Yellow
        Start-Sleep -Seconds 15
    }
}

#Enable Windows Update Service
write-host "Starting Windows Update Service"
Set-Service wuauserv -StartupType Automatic
Start-Service wuauserv

#Disable driver updates from Win Update channel
#reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v SearchOrderConfig /t REG_DWORD /d 1 /f
$reg_key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching"
$reg_subkey = "SearchOrderConfig"

#Check if Driver updates are disabled
if (-not (Test-RegistryValue $reg_key $reg_subkey)) {
    New-ItemProperty -Path $reg_key -Name $reg_subkey -Value 1 -PropertyType DWORD | Out-Null
    Write-Host "Disabling WinDrivers from update channel"
} elseif ((Get-RegistryValue $reg_key $reg_subkey) -eq 1) {
    Write-Host "SearchOrderConfig option is already set in registry"
} else {
    Set-ItemProperty -Path $reg_key -Name $reg_subkey -Value 1 | Out-Null
    Write-Host "Updating SearchOrderConfig option in registry"
}

#Make sure no other Windows update process is running
write-host "Checking Windows Update Process"
Test-WUInstallerStatus

#Get Updates
write-host "Getting Available Updates"
$updates = Get-WUList

#Download and install
if ($updates) {
    Write-Host "Installing Updates"
    Get-WUInstall -UpdateType Software -AcceptAll -install -IgnoreReboot -Verbose
}

#Wait for Windows Update to start if needed
Start-Sleep -Seconds 5

#Make sure no other Windows update process is running
Test-WUInstallerStatus

write-host "Checking for reboot"
if (Get-WURebootStatus -silent) {
    #Needs to reboot
    #Enabling autologon
    Enable-AutoLogon -Username "$Username" -Password $securePassword -LogonCount "1"
    Restart-Computer -Force
}
else {
    #WU Reboot not needed
    write-host "Initializing sealing and shutdown process"
    #Flag to use during seal process checks
    $good = $true
    #First Section of the "Shutdown for Finalize"
    #Unzip Optimizer
    Expand-Archive -Path "$downloadpath" -DestinationPath "$unzippath" -Force
    #Run RapidScale specific Citrix Optimize customizations
    $cust_templates = Get-ChildItem -Path "$env:SystemDrive\Windows\temp\templates\*.xml"
    foreach ($cust_template in $cust_templates) {
        & "$unzippath\CtxOptimizerEngine.ps1" -Source $cust_template -Mode Execute -OutputLogFolder "$PSScriptRoot"
    }
    #Check OS and run OS specific customizations
    $OSName = $(Get-CimInstance -ClassName Win32_OperatingSystem).caption
    if ($OSName -like '*Windows 10*') {
        $ReleaseID = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ReleaseID).ReleaseId
        $template = "Citrix_Windows_10_$($ReleaseID).xml"
    } elseif ($OSName -like '*Windows 7*') {
        $template = "Citrix_Windows_7.xml"
    } elseif ($OSName -like '*Windows 8*') {
        $template = "Citrix_Windows_8.xml"
    } elseif ($OSName -like '*Server 2008 R2*') {
        $template = "Citrix_Windows_Server_2008R2.xml"
    } elseif ($OSName -like '*Server 2012 R2*') {
        $template = "Citrix_Windows_Server_2012R2.xml"
    } elseif ($OSName -like '*Server 2016*') {
        $ReleaseID = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ReleaseID).ReleaseId
        $template = "Citrix_Windows_Server_2016_$($ReleaseID).xml"
    } elseif ($OSName -like '*Server 2019*') {
        $ReleaseID = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ReleaseID).ReleaseId
        $template = "Citrix_Windows_Server_2019_$($ReleaseID).xml"
    } else {
        $template = $null
    }
    if ($template) {
        & "$unzippath\CtxOptimizerEngine.ps1" -Source "$unzippath\Templates\$template" -Mode Execute -OutputLogFolder "$PSScriptRoot"
    }
    else {
        Write-Host "No appropriate template is available."
    }
    #If error with above
    if ($? -eq $false) {
        write-host "Issues with the optimize process. Rebooting Again"
        #Enable autologon to kick off scheduled task
        Enable-AutoLogon -Username "$Username" -Password $securePassword -LogonCount "1"
        #Set flag
        $good = $false
        #Reboot to initialize task
        Restart-Computer -Force
    }
    #If checks pass
    if ($good) {
        #Disable windows update services
        write-host "Disabling Windows Update Service"
        Set-Service wuauserv -StartupType Disabled
        Stop-Service wuauserv -Force
        #Remove Scheduled Task
        write-host "Removing Scheduled Task"
        Unregister-ScheduledTask -TaskName "PSWindowsUpdate" -Confirm:$false
        #Remove update script
		remove-item "$env:SystemDrive\Windows\temp\UpdateTask.ps1" -Force
		remove-item "$env:SystemDrive\Windows\temp\New-StringDecryption.ps1" -Force
		remove-item "$env:SystemDrive\Windows\temp\New-StringEncryption.ps1" -Force
		remove-item "$env:SystemDrive\Windows\temp\ConfigureRemotingForAnsible.ps1" -Force
		remove-item "$env:SystemDrive\Windows\temp\CitrixOptimizer.zip" -Force
        remove-item "$env:SystemDrive\Windows\temp\CTX" -Force -Recurse
        remove-item "$env:SystemDrive\Windows\temp\templates" -Force -Recurse
        #Shutdown system
        & "C:\Windows\System32\Shutdown.exe" /s /t 0 /d p:4:2 /c "Citrix image update finalization"
    }
}
