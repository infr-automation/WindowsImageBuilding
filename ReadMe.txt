Windows 11 Tuning

1. The NTLite XML file: Work in progress

2. Additional tuning to be added:

-Enable more Power settings Coalscing IO looks interesting I wonder if it affects performance
https://gist.github.com/raspi/203aef3694e34fefebf772c78c37ec2c#file-enable-all-advanced-power-settings-ps1-L5
https://www.tenforums.com/performance-maintenance/149514-list-hidden-power-plan-attributes-maximize-cpu-performance.html
https://www.tenforums.com/tutorials/107613-add-remove-ultimate-performance-power-plan-windows-10-a.html
https://forums.guru3d.com/threads/windows-power-plan-settings-explorer-utility.416058/

-Disable HDD encryption because it interferes with OS break-fix and performance.
fsutil behavior set disableencryption 1
  cipher /d /s:C:\
  reg add "HKLM\Software\Policies\Microsoft\Windows\EnhancedStorageDevices" /v "TCGSecurityActivationDisabled" /t REG_DWORD /d "1" /f
  sc config BDESVC start= disabled
  sc config "EFS" start= disabled


-Disable modern standby because it's creepy crashy and overheaty

powercfg /setdcvalueindex scheme_current sub_none F15576E8-98B7-4186-B944-EAFA664402D9 0
powercfg /setacvalueindex scheme_current sub_none F15576E8-98B7-4186-B944-EAFA664402D9 0
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\F15576E8-98B7-4186-B944-EAFA664402D9 /v Attributes /t REG_DWORD /d 2 /f
https://www.notebookcheck.net/Useful-Life-Hack-How-to-Disable-Modern-Standby-Connected-Standby.453125.0.html
https://www.dell.com/community/XPS/How-to-disable-modern-standby-in-Windows-21H1/td-p/7996308


-Reduce logging resource usage
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl]
"EnableLogFile"=dword:00000000


-disable drivers from MS update because they are old
..

-Update policies
https://techcommunity.microsoft.com/t5/windows-it-pro-blog/the-windows-update-policies-you-should-set-and-why/ba-p/3270914


upd other ms prod Add-WuServiceManager


- disallow allow remote assist because it's laggy

- add scheduled task to disable stuff
  client for ms net
  file and pr sharing
  register w dns
  netbios
  wi fi wake
  eth fc
  bt off

- Turn off IPv6
Prevent ipv6:: binding
dis set-Net6to4Configuration

- Firewall default disallow
fw dis inbound out- allj, cast teredo v6 cortana mDNS Narrator network discovery remote assist start wi-fi direct windows calc windows search wireless display

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
