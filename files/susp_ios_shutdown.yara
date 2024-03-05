
rule susp_iOS_shutdown {

meta:

	description = "Detect shutdown.log files from sysdiags with suspicious entries"
	author = "Costin G. Raiu, Art of Noh, craiu@noh.ro"
	date = "2023-12-28"
	version = "1.0"
	tlp = "TLP:CLEAR"
	reference = "https://securelist.com/shutdown-log-lightweight-ios-malware-detection-method/111734/"

strings:

	$a1="these clients are still here:"
	$b1="/private/var/db/"
	$b2="/private/var/tmp/"

	$c1="After "

condition:

	($c1 at 0) and $a1 and (any of ($b*))

}
