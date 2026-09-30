rule Trojan_Hackers_Use_Maintain_8da300 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-09-30"
        description = "Detection for trojan: Hackers Use NeedyMantis to Maintain Long-Term Access in Breached Netwo"
        reference = "https://thehackernews.com/2026/09/hackers-use-needymantis-to-maintain.html"
        threat_level = 8
        malware_type = "trojan"
        confidence_score = 88
        source = "The Hacker News"
        version = "5.0"
    strings:

        // Hashes
        $hash1 = "c82520eb03c084226be4eafbff46f56dca0aa8804a2a7f23a085a96afe71ef77"
        $hash2 = "e842dd7642c8e04b5ec20b6393848a9c904e4832930950c16664fe7800ba382e"
        $hash3 = "9cb68f986043a576e19d32184c583b7d8f571c7219d8dc0065dced1c13f077ef"

        // Domains
        $domain1 = "thehackernews.uk" nocase

        // Files
        $file1 = "jli.dll" nocase

    condition:
        2 of ($hash*, $domain*, $file*)
