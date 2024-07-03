
rule crime_LockBit3_ransomware {

meta:

	reference = "https://www.bleepingcomputer.com/news/security/meet-brain-cipher-the-new-ransomware-behind-indonesia-data-center-attack/"
	hash = "eb82946fa0de261e92f8f60aa878c9fef9ebb34fdababa66995403b110118b12"
	hash = "6e07da23603fbe5b26755df5b8fec19cadf1f7001b1558ea4f12e20271263417"
	description = "Generic LockBit detection, also catches the version used in attacks in Indonesia."
	date = "2024-07-03"
	author = "Costin G. Raiu, TLPBLACK, craiu@noh.ro"
	version = "1.1"

strings:

	//detection is generic for LockBit 3
	$a1={C3 8BFF53 51 6A0158 0FA2F7C1000000400F95C0 84C074090FC7F0 0FC7F2 59 5B C3 }
	$a2={C3 6A0758 33C90FA2F7C3000004000F95C0 84C074090FC7F8 0FC7FA 59 5B C3 }
	$a3={C3 0F31 8BC8 C1C90D 0F31 8BD0 C1C20D 8BC1 59 5B C3 }
	$a4={55 8BEC 51 52 56 33C0 8B550C 8B7508 AC 33C9 B930000000 8D0C4D01000000 02F1 2AF1 33C9 B906000000 8D0C4D01000000 D3CA 03D0 90 85C0}
	$a5={E9 ?? ?? ?? ?? 6683F841 720C 6683F846 7706 6683E837 EB26 6683F861 720C 6683F866 7706 6683E857 EB14 6683F830 720C 6683F839 7706 6683E830 EB}
	$a6={5D 8BC3 5F 5E 5B 5D C20C00 90 55 8BEC 53 56 57 33C0 8B5D14 33C9 33D2 8B750C 8B7D08 85F6 }

condition:

	(filesize<1MB)
	and
	(uint16(0)==0x5a4d)
	and
	(2 of them)

}
