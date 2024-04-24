# Base Image Update Script
Script to update Windows on a PVS base image. Script follows steps outlined below.
# How to use
## With Input
Script can be ran as is without any edits or changes using the steps below.
1. Download Git Repository or git clone it
2. Launch Powershell as an admin and ensure that execution policy is set to bypass or permissive.
3. Navigate to the directory of the script and run ```$ .\MainTask.ps1```
4. Watch output, and fill in information for any prompts that come up. You will be told when user input is no longer required.
5. All information will be logged to "C:\Logs" if script fails check the log file.
## Without Input
If you want to do this as a scheduled task or some other automated fashion without any user interaction follow the steps below.
* Note that passwords and usernames are saved in plain text in the script if using the method below. 
1. Download Git Repository or git clone it
2. Navigate to the root of the project folder and open the MainTask.ps1 file in your preferred editor.
3. Fill in the variables below with the required information.

```
# -----------------------------------
# CUSTOMIZE THE FOLLOWING VARIABLES TO YOUR REQUIREMENTS
# -----------------------------------
...
$domainadminuser = "admin"          #Local admin username for Maintenance VM
$domainadminpw = "password"         #Local admin password for Maintenance VM
$vcloud_url = "vcloud.example.com"  #vCloud URL
$vcloud_user = "first.lastname"     #vCloud Username
$vcloud_pass = "password"           #vCloud Password
$vcloud_org = "ExampleOrg"          #vCloud Org (Replace $null with the Org Name or Select Org in pop up Out-GridView)
```

4. Launch Powershell as an admin and ensure that execution policy is set to bypass or permissive.
5. Navigate to the directory of the script and run ```$ .\MainTask.ps1```
6. All information will be logged to "C:\Logs" if script fails check the log file.

# Steps
Define defaults and functions
* Anything re-usable

Set or Get variables:
* Usernames, passwords, etc.

Create Maintenance Image:
* Install PowerShell PVS Module
* Add PowerShell SnapIn
* Identify Site, Store, and Disk Image
* Create the Maintenance image and add comment
* Configure boot option for maintenance images to autoboot devices

Turn On Maintenance Machine:
* Identify Datacenter and vCloud URL to connect to
* Connect to vCloud
* Select Tenant
* Select Machine to power on or find it based on provided input
* Power machine on and verify once powered on

Boot to Maintenance Machine:
* Ensure that this has booted to the appropriate image
* Confirm connectivity once booted up

Ensure prerequisites for PSRemoting, WinRM, etc are enabled on Maint Machine:
* Check if WinRM basics are enabled, if not enable them.
* Push AnsiblePSRemoting.ps1 script and run it to enable more advanced remoting.
* Copy over required scripts to maintenance machine and encrypt passwords for reuse
* Setup scheduled task to run Windows Update script at start up.
* Setup auto login on first run after reboot.

Run Windows Updates:
* After reboot initiate script and install windows updates. Reboot as many times as needed.

Run Optimizer:
* Run Citrix Optimizer with the configuration file to seal image

Shutdown Maintenance Image:
* Ensure complete shutdown of the device

Promote image to Test:
* Ensure image has been promoted

End