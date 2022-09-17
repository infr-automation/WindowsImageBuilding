NTLite-based Windows pre-Setup customizations.

For the purpose of trying to correct Microsoft's critical mistakes.

1. Done: look inisde the XML.

2. To-Add:



powercfg /setdcvalueindex scheme_current sub_none F15576E8-98B7-4186-B944-EAFA664402D9 0
powercfg /setacvalueindex scheme_current sub_none F15576E8-98B7-4186-B944-EAFA664402D9 0
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\F15576E8-98B7-4186-B944-EAFA664402D9 /v Attributes /t REG_DWORD /d 2 /f
https://www.notebookcheck.net/Useful-Life-Hack-How-to-Disable-Modern-Standby-Connected-Standby.453125.0.html
https://www.dell.com/community/XPS/How-to-disable-modern-standby-in-Windows-21H1/td-p/7996308

#win upd drivers
check blog post 'The Windows Update policies you should set and why'
fsutil behavior set disableencryption 1
  cipher /d /s:C:\
  reg add "HKLM\Software\Policies\Microsoft\Windows\EnhancedStorageDevices" /v "TCGSecurityActivationDisabled" /t REG_DWORD /d "1" /f
  sc config BDESVC start= disabled
  sc config "EFS" start= disabled
upd other ms prod Add-WuServiceManager
dis allow remote assist
sched dis client for ms net
  file and pr sharing
  register w dns
  netbios
  wi fi wake
  eth fc
  bt off
  serviecs lstening on ipv6::?

fw dis inbound out- allj, cast teredo v6 cortana mDNS Narrator network discovery remote assist start wi-fi direct windows calc windows search wireless display
dis set-Net6to4Configuration
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
