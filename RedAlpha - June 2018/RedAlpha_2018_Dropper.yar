import "pe"
rule apt_ZZ_RedAlpha_Dropper
{
 meta:
  author = "JAG-S, Insikt Group, Recorded Future"
  tlp = "White"
  md5 = "e6c0ac26b473d1e0fa9f74fdf1d01af8"
  md5 = "e28db08b2326a34958f00d68dfb034b0"
  md5 = "c94a39d58450b81087b4f1f5fd304add"
  md5 = "3a2b1a98c0a31ed32759f48df34b4bc8"
  desc = "RedAlpha Dropper"
  version = "1.0"
 
 strings:
  $cnc = "http://doc.internetdocss.com/index?"
 
 condition:
  uint16(0) == 0x5A4D
  and filesize < 500KB
  and
  (pe.imphash() == "17030637d18335c7267d09ec0ebc637c" or pe.imphash() ==
  "617fd4619e215a00dae98de5980a4210")
  and
  all of them
}
