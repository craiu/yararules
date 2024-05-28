
rule crime_Chaos_Ransomware_gen {

meta:

	reference = "https://blog.sonicwall.com/en-us/2024/05/politically-charged-ransomware-weaponized-as-a-file-destroyer/"
	date = "2024-05-27"
	author = "Costin G. Raiu, Art of Noh, craiu@noh.ro"
	version = "1.0"
	hash = "524a898e18999ceac864dbac5b85fa2f14392e389b3c32f77d58e2a89cdf01c4"
	description = "Chaos ransomware generic strings"

strings:

	$a0="<Exponent>AQAB</Exponent>" ascii wide fullword
	$a2="<EncryptedKey>" ascii wide fullword
	$a15="vssadmin delete shadows /all /quiet & wmic shadowcopy delete" ascii wide fullword
	$a16="bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no" ascii wide fullword
	$a17="wbadmin delete catalog -quiet" ascii wide fullword
	$a18="C:\\Users\\" ascii wide fullword
	$a22="/9j/4AAQSkZJRgABAQAAAQABAAD/4gHYSUNDX1BST0ZJTEUAAQEAAAHIAAAAAAQwAABtbnRyUkdCIFhZWiAH4AABAAEAAAAAAABhY3NwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAA9tYAAQAAAADTLQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlkZXNjAAAA8AAAACRyWFlaAAABFAAAABRnWFlaAAABKAAAABRiWFlaAAABPAAAABR3dHB0AAABUAAAABRyVFJDAAABZAAAAChnVFJDAAABZAAAAChiVFJDAAABZAAAAChjcHJ0AAABjAAAADxtbHVjAAAAAAAAAAEAAAAMZW5VUwAAAAgAAAAcAHMAUgBHAEJYWVogAAAAAAAAb6IAADj1AAADkFhZWiAAAAAAAABimQAAt4UAABjaWFlaIAAAAAAAACSgAAAPhAAAts9YWVogAAAAAAAA9tYAAQAAAADTLXBhcmEAAAAAAAQAAAACZmYAAPKnAAANWQAAE9AAAApbAAAAAAAAAABtbHVjAAAAAAAAAAEAAAAMZW5VUwAAACAAAAAcAEcAbwBvAGcAbABlACAASQBuAGMALgAgADIAMAAxADb/2wBDAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/2wBDAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/wAARCAQ4B4ADAREAAhEBAxEB/8QAHwAAAAYDAQEBAAAAAAAAAAAABAUGBwgJAgMKAQAL/8QAgRAAAQIDBQQIAwcCAgQIAAI7AQIRAwQhAAUGMUEHElFhCBMicYGRofCxwdEJFCMyQuHxFVIzYhYkQ3IKFzRTY4KSshglRHOi0uIZJlRkg5PCJzU2RVZYdJaXo9PWGkZHVVeEprO1KDllZ3V2eIaHlJWktLbDxtTV1zd3xMVmp8f" ascii wide fullword
	$a24="17CqMQFeuB3NTzJ" ascii wide fullword
	$a25="(?:[13]{1}[a-km-zA-HJ-NP-Z1-9]{26,33}|bc1[a-z0-9]{39,59})" ascii wide fullword
	$a26="7z459ajrk722yn8c5j4fg" ascii wide
	$a27="2X28tfRmWaPyPQgvoHV" ascii wide
	$a28="1qw0ll8p9m8uezhqhyd" ascii wide
	$b11="\\Saved Games" ascii wide fullword

condition:

	(filesize<9MB)
	and
	(uint16(0)==0x5a4d)
	and
	(
	(3 of them)
	)

}
