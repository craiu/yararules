rule unk_liblzma_backdoor {

meta:

	description = "liblzma backdoored"
	date = "2024-03-30"
	author = "Costin G. Raiu, Art of Noh, craiu@noh.ro"
	version = "1.1"
	hash = "8fa641c454c3e0f76de73b7cc3446096b9c8b9d33d406d38b8ac76090b0344fd"
	hash = "319feb5a9cddd81955d915b5632b4a5f8f9080281fb46e2f6d69d53f693c23ae"
	hash = "b418bfd34aa246b2e7b5cb5d263a640e5d080810f767370c4d2c24662a274963"
	hash = "cbeef92e67bf41ca9c015557d81f39adaba67ca9fb3574139754999030b83537"
	reference = "https://seclists.org/oss-sec/2024/q1/268"

strings:

	//prologue of the cpuid wrapper
	$a1={f3 0f 1e fa 55 48 89 f5 4c 89 ce 53 89 fb 81 e7 00 00 00 80 48 83 ec 28 48 89 54 24 18 48 89 4c 24 10}

	$a2={48 BF 30 30 30 30 30 30 30 30 8B F1 49 89 D1 89 43 28 48 89 3C 24 BF 3F FC FF 03}

condition:

	(uint32be(0)==0x7F454C46)
	and
	(filesize<10MB)
	and
	(any of them)

}
