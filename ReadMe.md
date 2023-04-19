# Windows Gold Disk Building
_Inspired by the need for a reliable OS_

use case: every OS use case

ver 0.0001 a template

## 1. Set up an environment to perform the modifications.
```powershell
# placeholder
```
### References:

## 2. Slim down the ISO
```powershell
# placeholder
```
### References:

> - https://github.com/infr-automation/WindowsImageBuilding/blob/master/NTLiteFreeWindows11TuningPreSetupStagev01.xml.xml



## 3. OS settings

### 3.1 Power Management
```powershell
# placeholder
# Disable modern standby because it's creepy crashy and overheaty

powercfg /setdcvalueindex scheme_current sub_none F15576E8-98B7-4186-B944-EAFA664402D9 0
powercfg /setacvalueindex scheme_current sub_none F15576E8-98B7-4186-B944-EAFA664402D9 0
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\F15576E8-98B7-4186-B944-EAFA664402D9 /v Attributes /t REG_DWORD /d 2 /f

# Coalescing IO

```

#### References:
> https://www.softpedia.com/get/System/Launchers-Shutdown-Tools/Power-Plan-Assistant.shtml
> https://gist.github.com/raspi/203aef3694e34fefebf772c78c37ec2c#file-enable-all-advanced-power-settings-ps1-L5
> https://gist.github.com/Nt-gm79sp/1f8ea2c2869b988e88b4fbc183731693
> https://www.tenforums.com/performance-maintenance/149514-list-hidden-power-plan-attributes-maximize-cpu-performance.html
> https://www.tenforums.com/tutorials/107613-add-remove-ultimate-performance-power-plan-windows-10-a.html
> https://forums.guru3d.com/threads/windows-power-plan-settings-explorer-utility.416058/
>
> https://www.notebookcheck.net/Useful-Life-Hack-How-to-Disable-Modern-Standby-Connected-Standby.453125.0.html
> https://www.dell.com/community/XPS/How-to-disable-modern-standby-in-Windows-21H1/td-p/7996308



### 3.2 Disk Encryption
- Make Encryption user chouce, because it interferes with OS break-fix and performance.
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

## 3.3 Reduce IO
```powershell
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

:: Redirect event log files to the RAM drive (replace R: with the desired drive letter)
wevtutil el > event_logs.txt
for /f "tokens=*" %%A in (event_logs.txt) do (
    wevtutil sl %%A /lfn:"R:\%%A.evtx"
)

:: Clean up
del /f /q event_logs.txt

```

## 3.4 Drivers
``` powershell
-disable and prevent drivers from MS update because they are old
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" /v "DeviceInstallDisabled" /t REG_DWORD /d "1" /f

```

## 3.5 Updates
``` powershell
:: Set Windows Update policy to receive stable updates only
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "DeferFeatureUpdates" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "DeferFeatureUpdatesPeriodInDays" /t REG_DWORD /d "0" /f

:: Set Windows Update to check for updates frequently
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "ScheduledInstallDay" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "ScheduledInstallTime" /t REG_DWORD /d "1" /f


-other Microsoft product updates through Windows Update
(example compatible with Windows 8, 8.1, 10, and 11.)
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "IncludeRecommendedUpdates" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\7971f918-a847-4430-9279-4a52d1efe18d" /v "RegisteredWithAU" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DoNotConnectToWindowsUpdateInternetLocations" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "IncludeRecommendedUpdates" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "Include_WSUS31" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "Include_MSUpdate" /t REG_DWORD /d "1" /f
```
### References:
- https://techcommunity.microsoft.com/t5/windows-it-pro-blog/the-windows-update-policies-you-should-set-and-why/ba-p/3270914

- disallow allow remote assist because it's laggy
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f


- add scheduled task to disable unused network related stuff
  client for ms net
  file and pr sharing
  register w dns
  netbios
  wi fi wake
  eth fc
  bt off
(example oneliner needs fixing shortening and testing)
Register-ScheduledTask -TaskName "DisableNetworkBindings" -Trigger (New-ScheduledTaskTrigger -OnEventID 4004 -User "NT AUTHORITY\SYSTEM") -Action (New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "Disable-NetAdapterBinding -Name * -ComponentID ms_msclient, ms_server, ms_serverdriver, ms_tcpip6, ms_wuguid, ms_wusnmp, ms_lltdio, ms_rspndr, ms_nwifi, ms_msclientio, ms_ndisuio, ms_rdma_ndk, ms_rdma_rspndr, ms_rdma_tcp, ms_rdma_udp, ms_tcpip -PassThru | Disable-NetAdapterBinding -Name * -ComponentID ms_netbt, ms_lldp, ms_wfplwf, ms_wfpcpl, ms_pacer | Set-NetAdapterAdvancedProperty -Name * -DisplayName 'Flow Control' -DisplayValue 'Disabled'") -Settings (New-ScheduledTaskSettingsSet -Priority 4 -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)) -Force

netsh advfirewall firewall add rule name="Block UDP 5353" dir=in action=block protocol=UDP localport=5353
netsh advfirewall firewall add rule name="Block UDP 5353" dir=out action=block protocol=UDP localport=5353
netsh advfirewall firewall add rule name="Block UDP 1900" dir=in action=block protocol=UDP localport=1900
netsh advfirewall firewall add rule name="Block UDP 1900" dir=out action=block protocol=UDP localport=1900

netsh advfirewall firewall add rule name="Block IGMP" dir=in action=block protocol=IGMP
netsh advfirewall firewall add rule name="Block IGMP" dir=out action=block protocol=IGMP
sc config Bonjour Service start=disabled
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v GlobalQueryBlockList /t REG_MULTI_SZ /d "local,localhost,localdomain,local.,*\nmdns,*.local" /f



-- Add button to enable per user need
  

- Turn off IPv6
(Prevent ipv6:: binding)
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



- Firewall default disallow
fw dis inbound out- allj, cast teredo v6 cortana mDNS Narrator network discovery remote assist start wi-fi direct windows calc windows search wireless display
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound


-and so on:

disable default admin and disk share server
restrict access over anonymous connections
prevent joining homegroup
hide computer from browser list
prevent network auto discovery
hide entire network in network neighborhood

dis UAC pw
act
uninst add remove onedrive
dis msteams startup
first day of week

edge start withot data
  privacy statement reject all
  multilingual text suggestions
add language basic typing ocr (not lang pack)
add kbd remove kbd

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

Sources:
https://www.elevenforum.com/tutorials/
https://www.winos.me/
https://github.com/Chuyu-Team/Dism-Multi-language
https://www.elevenforum.com/tutorials/?prefix_id=7
https://www.elevenforum.com/tutorials/?prefix_id=12
https://www.tenforums.com/tutorials/id-Installation_Upgrade/
https://www.tenforums.com/tutorials/id-Virtualization/
nsanef topic/249660-disable-windows-10-telemetry-and-data-collection-collection-of-methods-tools
https://devblogs.microsoft.com/scripting/automatically-enable-and-disable-trace-logs-using-powershell/
https://duckduckgo.com/?q=windows+11+disable+logging+tracing&ia=web
