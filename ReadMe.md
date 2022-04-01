NTLite-based Windows pre-Setup customizations.

1. Done: look inisde the XML.

2. To-Do:


disable-network-connectivity-modern-standby-windows-10
#win upd drivers
fsutil behavior set disableencryption 1
  cipher /d /s:C:\
  reg add "HKLM\Software\Policies\Microsoft\Windows\EnhancedStorageDevices" /v "TCGSecurityActivationDisabled" /t REG_DWORD /d "1" /f
  sc config BDESVC start= disabled
  sc config "EFS" start= disabled
upd other ms prod
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
