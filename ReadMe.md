# Windows Gold Disk Building

<details><summary>References</summary>https://www.elevenforum.com/tutorials/</br>
https://www.winos.me/</br>
https://github.com/Chuyu-Team/Dism-Multi-language</br>
https://www.elevenforum.com/tutorials/?prefix_id=7</br>
https://www.elevenforum.com/tutorials/?prefix_id=12</br>
https://www.tenforums.com/tutorials/id-Installation_Upgrade/</br>
https://www.tenforums.com/tutorials/id-Virtualization/</br>
nsnfrm topic/249660-disable-windows-10-telemetry-and-data-collection-collection-of-methods-tools</br>
https://devblogs.microsoft.com/scripting/automatically-enable-and-disable-trace-logs-using-powershell/</br>
https://duckduckgo.com/?q=windows+11+disable+logging+tracing&ia=web</br>
https://msfn.org/</br>
</details>


## 1. Set up an environment to perform the modifications.
<details><summary>References</summary>DevOps practices</details>

```powershell
# placeholder
# preferably download distribution files inside a VM
# bring up a VM
# automate the ISO build/ISO slim
```


### 1.2. Slim down the ISO
```powershell
# sysprep same way it's done for VDI - automate
# but add an full NTLite step before installing ISO and/or before sysprep
# automated testing
```
### References:
NTLite Windows11 Tuning PreSetupStage xml

## 2. Cloud


## 3. OS settings
Pre-configure OS settings  
+ Slimdown for all use cases  
+ Improve speed performance latency  
+ Improve reliability and reduce infosec risk  
+ Reduce energy footprint  
+ Empower the user correctly  
+ Reduce maintenaince risk and cost  

### 3.1 Power Management
<details><summary>References</summary>https://www.softpedia.com/get/System/Launchers-Shutdown-Tools/Power-Plan-Assistant.shtml<br/>
https://gist.github.com/raspi/203aef3694e34fefebf772c78c37ec2c#file-enable-all-advanced-power-settings-ps1-L5<br/>
https://gist.github.com/Nt-gm79sp/1f8ea2c2869b988e88b4fbc183731693<br/>
https://www.tenforums.com/performance-maintenance/149514-list-hidden-power-plan-attributes-maximize-cpu-performance.html<br/>
https://www.tenforums.com/tutorials/107613-add-remove-ultimate-performance-power-plan-windows-10-a.html<br/>
https://forums.guru3d.com/threads/windows-power-plan-settings-explorer-utility.416058<br/>
https://www.notebookcheck.net/Useful-Life-Hack-How-to-Disable-Modern-Standby-Connected-Standby.453125.0.html<br/>
https://www.dell.com/community/XPS/How-to-disable-modern-standby-in-Windows-21H1/td-p/7996308<br/>
</details>

```powershell

# get rid of hibernation
powercfg -h off

# use normal standby and not modern standby

powercfg /setdcvalueindex scheme_current sub_none F15576E8-98B7-4186-B944-EAFA664402D9 0
powercfg /setacvalueindex scheme_current sub_none F15576E8-98B7-4186-B944-EAFA664402D9 0
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\F15576E8-98B7-4186-B944-EAFA664402D9 /v Attributes /t REG_DWORD /d 2 /f

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "CsEnabled" -Value 0 -ErrorAction SilentlyContinue

# Coalescing IO - will introduce IO latency to save power

```
```powershell
# Get the list of devices that can wake the system
$wakeDevices = powercfg -devicequery wake_armed

# Disable wake functionality for mouse or touchpad devices
$wakeDevices | ForEach-Object {
    if ($_ -like "*Mouse*" -or $_ -like "*Touchpad*") {
        powercfg -devicedisablewake "$_"
        Write-Output "Disabled wake functionality for: $_"
    }
}
```

``` powershell
# Disable Wake Timers on AC
powercfg /SETACVALUEINDEX SCHEME_CURRENT 238c9fa8-0aad-41ed-83f4-97be242c8f20 bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 0
# Disable WoL at the OS level
powercfg -setacvalueindex SCHEME_CURRENT SUB_NONE F44E3DAE-CB3E-4D65-8A2A-7A5C5C6D3090 0
powercfg -setdcvalueindex SCHEME_CURRENT SUB_NONE F44E3DAE-CB3E-4D65-8A2A-7A5C5C6D3090 0

# Disable WoL for all network adapters
Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
    Write-Output "Processing $($_.Name)..."
    # Disable WoL features
    Disable-NetAdapterPowerManagement -Name $_.Name -WakeOnMagicPacket $false -WakeOnPattern $false -Confirm:$false
}

Write-Output "WoL has been disabled."


# Extreme Battery Saver on Idle (example not tested) (checks every 10min for idleness?)

# Define the power plan name
$powerPlanName = "Extreme Battery Saver"

# Check if the power plan exists
$existingPlan = Get-CimInstance -Namespace root/cimv2/power -ClassName Win32_PowerPlan | Where-Object { $_.ElementName -eq $powerPlanName }

if (-not $existingPlan) {
    # Create the power plan based on the Power saver
    $powerSaverGuid = (Get-CimInstance -Namespace root/cimv2/power -ClassName Win32_PowerPlan | Where-Object { $_.ElementName -eq "Power saver" }).InstanceID -replace ".*\{(.*)\}.*", '$1'
    $newPlanGuid = powercfg /duplicate $powerSaverGuid | Out-String | ForEach-Object { $_ -replace ".*\{(.*)\}.*", '$1' }
    powercfg /changename $newPlanGuid $powerPlanName
} else {
    $newPlanGuid = $existingPlan.InstanceID -replace ".*\{(.*)\}.*", '$1'
}

# Script to activate the power plan
$scriptContent = @"
# Activate the power plan
powercfg /setactive $newPlanGuid
"@
$scriptPath = "$env:USERPROFILE\setBatterySaver.ps1"
$scriptContent | Out-File -Path $scriptPath

# Create a scheduled task to run the script when the computer is idle
$taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File $scriptPath"
$taskTrigger = New-ScheduledTaskTrigger -AtStartup -RepetitionInterval ([TimeSpan]::FromMinutes(10)) -Idle
Register-ScheduledTask -Action $taskAction -Trigger $taskTrigger -TaskName "ActivateBatterySaver" -Description "Switches to battery saver plan when idle"


```


### 3.2 Disk Encryption
Delay encryption and present user choice:

```powershell
1. `fsutil behavior set disableencryption 1`: Disable encryption on the file system.
2. `cipher /d /s:C:\`: Decrypt all encrypted files on the C drive. Note that this command only works for files encrypted with the Encrypting File System (EFS). You should be logged in as the user who encrypted the files or an administrator who has the EFS recovery agent certificate. Otherwise, the command will fail, and the files will remain encrypted.
3. `reg add "HKLM\Software\Policies\Microsoft\Windows\EnhancedStorageDevices" /v "TCGSecurityActivationDisabled" /t REG_DWORD /d "1" /f`: Disable the Trusted Platform Module (TPM) security activation to prevent automatic encryption of new storage devices.
4. `sc config BDESVC start= disabled`: Disable the BitLocker Drive Encryption Service, which is responsible for managing BitLocker operations.
5. `sc config "EFS" start= disabled`: Disable the Encrypting File System (EFS) service, which manages EFS operations.

fsutil behavior set disableencryption 1
cipher /d /s:C:
reg add "HKLM\Software\Policies\Microsoft\Windows\EnhancedStorageDevices" /v "TCGSecurityActivationDisabled" /t REG_DWORD /d "1" /f
sc config BDESVC start= disabled
sc config "EFS" start= disabled

# Add dekstop icon to start Encryption upon user decision

```

## 3.3 IO Optimization
### 3.3.1 Eliminate everything log, performance counter, record keeping, temp files related
<details><summary>References</summary>https://yandex.com/search/?text=CrashControl+EnableLogFile&lr=10379 :: this search engine returns better results.</details>

```powershell


# Write Cache
# Ensure the script is running with administrative privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script needs to be run as an Administrator. Exiting..."
    exit
}

# Maximize write cache via registry (this sets the LargeSystemCache to 1, which maximizes cache)
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
Set-ItemProperty -Path $registryPath -Name "LargeSystemCache" -Value 1

Write-Host "Maximized write cache via registry."



# ADD RAMDISK AND INITIALIZE RAMDISK
# BELOW CODE IS EXAMPLE PLACEHOLDER NOT WORKING
# Ensure the script runs with administrative privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    exit
}

# Mount recovery.wim and extract ramdisk.sys
$mountPath = "C:\TempWIMMount"
$recoveryWIM = "C:\path_to_recovery.wim"
New-Item -Path $mountPath -ItemType Directory -Force | Out-Null
dism /Mount-Wim /WimFile:$recoveryWIM /index:1 /MountDir:$mountPath
Copy-Item "$mountPath\Windows\System32\drivers\ramdisk.sys" "C:\Windows\System32\drivers\ramdisk.sys"
dism /Unmount-Wim /MountDir:$mountPath /discard

# Registry setup for ramdisk.sys
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Ramdisk"
New-Item -Path $regPath -Force | Out-Null
Set-ItemProperty -Path $regPath -Name "Type" -Value 1
Set-ItemProperty -Path $regPath -Name "Start" -Value 0
Set-ItemProperty -Path $regPath -Name "ErrorControl" -Value 1
Set-ItemProperty -Path $regPath -Name "ImagePath" -Value "system32\drivers\ramdisk.sys"
Set-ItemProperty -Path $regPath -Name "Group" -Value "Base"

$regParamsPath = "$regPath\Parameters"
New-Item -Path $regParamsPath -Force | Out-Null
Set-ItemProperty -Path $regParamsPath -Name "UsePAE" -Value 0
Set-ItemProperty -Path $regParamsPath -Name "DiskSize" -Value 2147483648  # 2GB in bytes

# Notify the user
Write-Output "RAMDisk setup complete. Please restart your system."




- symlink logs and tempfiles to > NUL
(example)
@echo off

:: Disable unnecessary event logging
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "EnableLogFile" /t REG_DWORD /d "0" /f

:: Disable automatic memory dump creation
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "CrashDumpEnabled" /t REG_DWORD /d "0" /f

:: Disable DumpStack.log and DumpStack.log.tmp creation
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "StackTraceDatabaseLogEnable" /t REG_DWORD /d "0" /f

:: Disable Windows Error Reporting
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f


:: Delete existing DumpStack.log and DumpStack.log.tmp files
del /f /q C:\DumpStack.log
del /f /q C:\DumpStack.log.tmp

:: Create a RAM drive (adjust drive letter and size as needed)
imdisk -a -s 512M -m R: -p "/fs:ntfs /q /y"

:: preferably the winpe ramdrive will be more useful

:: Redirect event log files to the RAM drive (replace R: with the desired drive letter)
wevtutil el > event_logs.txt
for /f "tokens=*" %%A in (event_logs.txt) do (
    wevtutil sl %%A /lfn:"R:\%%A.evtx"
)

:: Clean up
del /f /q event_logs.txt

```


### 3.3.2 Add a button to reverse the above as needed

## 3.4 Drivers

Prevent out-of-date drivers from MS update

``` powershell

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" /v "DeviceInstallDisabled" /t REG_DWORD /d "1" /f

```

## 3.5 Updates
<details><summary>References</summary>https://techcommunity.microsoft.com/t5/windows-it-pro-blog/the-windows-update-policies-you-should-set-and-why/ba-p/3270914</details>

``` powershell
:: Set Windows Update policy to receive stable updates only
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "DeferFeatureUpdates" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "DeferFeatureUpdatesPeriodInDays" /t REG_DWORD /d "0" /f

:: Set Windows Update to check for updates frequently
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "ScheduledInstallDay" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "ScheduledInstallTime" /t REG_DWORD /d "1" /f


:: other Microsoft product updates through Windows Update
(example compatible with Windows 8, 8.1, 10, and 11.)
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "IncludeRecommendedUpdates" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\7971f918-a847-4430-9279-4a52d1efe18d" /v "RegisteredWithAU" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DoNotConnectToWindowsUpdateInternetLocations" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "IncludeRecommendedUpdates" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "Include_WSUS31" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "Include_MSUpdate" /t REG_DWORD /d "1" /f
```



## 3.6 Network
### 3.6.1. Turn off unused network protocols with a scheduled task
  client for ms net  
  file and pr sharing  
  register w dns  
  netbios  
  wi fi wake  
  eth fc  
  bluetooth

```powershell
Register-ScheduledTask -TaskName "DisableNetworkBindings" -Trigger (New-ScheduledTaskTrigger -OnEventID 4004 -User "NT AUTHORITY\SYSTEM") -Action (New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "Disable-NetAdapterBinding -Name * -ComponentID ms_msclient, ms_server, ms_serverdriver, ms_tcpip6, ms_wuguid, ms_wusnmp, ms_lltdio, ms_rspndr, ms_nwifi, ms_msclientio, ms_ndisuio, ms_rdma_ndk, ms_rdma_rspndr, ms_rdma_tcp, ms_rdma_udp, ms_tcpip -PassThru | Disable-NetAdapterBinding -Name * -ComponentID ms_netbt, ms_lldp, ms_wfplwf, ms_wfpcpl, ms_pacer | Set-NetAdapterAdvancedProperty -Name * -DisplayName 'Flow Control' -DisplayValue 'Disabled'") -Settings (New-ScheduledTaskSettingsSet -Priority 4 -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)) -Force

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v GlobalQueryBlockList /t REG_MULTI_SZ /d "local,localhost,localdomain,local.,*\nmdns,*.local" /f

netsh advfirewall firewall add rule name="Block UDP 5353" dir=in action=block protocol=UDP localport=5353
netsh advfirewall firewall add rule name="Block UDP 5353" dir=out action=block protocol=UDP localport=5353
netsh advfirewall firewall add rule name="Block UDP 1900" dir=in action=block protocol=UDP localport=1900
netsh advfirewall firewall add rule name="Block UDP 1900" dir=out action=block protocol=UDP localport=1900

netsh advfirewall firewall add rule name="Block IGMP" dir=in action=block protocol=IGMP
netsh advfirewall firewall add rule name="Block IGMP" dir=out action=block protocol=IGMP

sc config Bonjour Service start=disabled :: make this a scheduledtask
```


### Add button to enable per user need (the igmp upnp mdns and ssdp are used for multimedia stuff)
 - placeholder

## Turn off IPv6
(Prevent ipv6:: binding)
```powershell
netsh int ipv6 isatap set state disabled #set-Net6to4Configuration
netsh interface ipv6 set global randomizeidentifiers=disabled
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d "ffffffff" /f
netsh interface ipv6 set teredo disabled
netsh interface ipv6 set 6to4 disabled
netsh interface ipv6 set isatap disabled
netsh interface ipv6 set interface "Loopback Pseudo-Interface 1" routerdiscovery=disabled
netsh interface ipv6 set interface "Loopback Pseudo-Interface 1" dadtransmits=0 store=active
netsh interface ipv6 set interface "Loopback Pseudo-Interface 1" routeradvertise=disabled
netsh advfirewall firewall add rule name="Block all IPv6 traffic" protocol=icmpv6:255,any dir=in action=block
netsh advfirewall firewall add rule name="Block all IPv6 traffic" protocol=icmpv6:255,any dir=out action=block
netsh advfirewall firewall add rule name="Block all IPv6 TCP/UDP traffic" protocol=TCPv6,UDPv6 dir=in action=block
netsh advfirewall firewall add rule name="Block all IPv6 TCP/UDP traffic" protocol=TCPv6,UDPv6 dir=out action=block
(edge=yes)
netsh advfirewall firewall add rule name="Block all IPv6 traffic" protocol=any dir=in action=block edge=yes profile=any interface=any
netsh advfirewall firewall add rule name="Block all IPv6 traffic" protocol=any dir=out action=block edge=yes profile=any interface=any
```

### Firewall default disallow
fw dis inbound out- allj, cast teredo v6 cortana mDNS Narrator network discovery remote assist start wi-fi direct windows calc windows search wireless display
```powershell
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
```
## remove Wireless Display

### disallow allow remote assist because it's laggy
```powershell
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f
```

### SMB tuning
disable default admin and disk share server  
restrict access over anonymous connections  
prevent joining homegroup  
hide computer from browser list  
prevent network auto discovery  
hide entire network in network neighborhood
``` powershell
# Run this script with elevated privileges (as an administrator)

# 1. Disable default admin shares (like C$, D$, etc.)
# This will disable the administrative shares for the system root and system volume root directories
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Value 0

# 2. Restrict access over anonymous connections
# This will prevent anonymous access to the computer from the network
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 2

# 3. Hide the computer from the browser list
# This will prevent the computer from appearing in the list of networked devices
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" -Name "Hidden" -Value 1
Restart-Service "LanmanServer" -Force

# 4. WRONG Prevent network auto-discovery
# This will set the network profile to private and then disable network discovery for it
Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
Set-NetFirewallProfile -Profile Private -NetworkDiscovery Disabled

# 5. Hide entire network in Network Neighborhood 
# This will prevent the computer from displaying the entire network in the Network Neighborhood
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoEntireNetwork" -Type DWord -Value 1

# Notify that the script has completed
Write-Output "Script execution completed. Please note that some changes might require a user logoff or system restart to fully take effect."

```

### Hardening and tuning
dis UAC pw  
act  
uninst add remove onedrive  
dis msteams startup

## Edge
edge start withot data  
  privacy statement reject all  
  multilingual text suggestions

## Regional
add kbd remove kbd  
add language basic typing ocr (not lang pack)  
first day of week

## Tooling
add latest ps  
win event colletor service?  
office  
winpe setup  
run apps in containers  
11 KB5010474  
11 KB2267602  
11 KB4052623  
upd ms store apps  
prevent system volume information folder creation  
storage spaces not working  
+zip fldr  
-wrk fldr  
+rmdks crp  

MS Store:  
- turn off autoplay videos

## Graphics
Turn off GUI fx  
google.com/search?q=UserPreferencesMask+value+in+the+Registry+to+enable+the+Classic+graphics+mode ?

## Eliminate Smooth scrolling
@echo off
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "SmoothScroll" /t REG_SZ /d "0" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "MouseWheelRouting" /t REG_SZ /d "0" /f
echo Smooth scrolling has been disabled. Please restart your computer for the changes to take effect.
pause



