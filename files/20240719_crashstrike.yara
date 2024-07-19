
rule Crashstrike {

meta:

	description = "Crowdstrike C-00000???-*.sys files"
	author = "Costin G. Raiu, Art of Noh, craiu@noh.ro"
	date = "2024-07-19"
	version = "1.0"
	hash = "9d001ef3206fe2f955095244e6103ad7f8f318c7c5cbd91a0dd1f33e4217fcb2"
	reference = "https://en.wikipedia.org/wiki/July_2024_global_cyber_outages"

strings:

	$a1="000E0A000E0GHijklMNOPqRSTUVwX"
	$a2="AbCDEfghIjklMNoPqrstuV"

condition:

	(filesize<60KB)
	and
	(uint32(0)==0xaaaaaaaa)
	and
	(all of them)

}
