import "pe"
rule apt_ZZ_RedAlpha_2017Campaign_Dropper
{
 meta:
  desc = "RedAlpha 2017 Campaign, Dropper"
  author = "JAG-S, Insikt Group, RecordedFuture"
  TLP = "White"
  md5_x86 = "cb71f3b4f08eba58857532ac90bac77d"
  md5_x64 = "1412102eda0c2e5a5a85cb193dbb1524"
 
 strings:
  $drops1 = "http://doc.internetdocss.com/nethelp x86.dll" ascii wide
  $drops2 = "http://doc.internetdocss.com/audio x86.exe" ascii wide
  $drops3 = "http://doc.internetdocss.com/nethelp x64.dll" ascii widerr
  $drops4 = "http://doc.internetdocss.com/audio x64.exe" ascii wide
  $source1 = "http://doc.internetdocss.com/word x86.exe" ascii wide
  $source2 = "http://doc.internetdocss.com/word x64.exe" ascii wide
  $path1 = "\\Programs\\Startup\\audio.exe" ascii wide
  $path2 = "c:\\Windows\\nethelp.dll" ascii wide
  $persistence1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\svchost" ascii wide
  $persistence2 = "%SystemRoot%\\system32\\svchost.exe -k " ascii wide
  $persistence3 = "SYSTEM\\CurrentControlSet\\Services\\" ascii wide
  $persistence4 = "Parameters" ascii wide
  $persistence5 = "ServiceDll" ascii wide
  $persistence6 = "NetHelp" ascii wide
  $persistence7 = "Windows Internet Help" ascii wide
 
 condition:
  uint16(0)==0x5A4D
  and
  filesize < 500KB
  and
  (
  (pe.imphash() == "3697a1f9150de181026ce089c10657c3" or pe.imphash() ==
  "e6e566fc8a1dee3019821e84c5ad58cc")
  or
  (
    any of ($drops*)
    or
    any of ($source*)
    or
    any of ($path*)
    or
    6 of ($persistence*)
  )
 )
}
