rule apt_ZZ_RedAlpha_njRat
{
 meta:
  author = "JAG-S, Insikt Group, Recorded Future"
  TLP = "White"
  md5 = "c74608c70a59371cbf016316bebfab06"
  date = "04-14-2018"
  desc = "Second-stage njRAT, RedAlpha config"
  version = "1.1"
 
 strings:
  $installName = "serverdo.exe" wide
  $port = "9527" wide
  $version = "0.7d" wide
  $c2 = "doc.internetdocss.com" wide
 
 condition:
  uint16(0) == 0x5A4D and filesize < 50KB
  and
  pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744"
  and
  all of them
}
